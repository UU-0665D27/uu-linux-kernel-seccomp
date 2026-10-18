use libc::{
    BPF_ABS, BPF_ALU, BPF_AND, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W,
    SECCOMP_RET_KILL_PROCESS, sock_filter,
};
use std::fmt;

use crate::libc::consts::{
    AUDIT_ARCH_X86_64, SECCOMP_DATA_ARCH_OFFSET, SECCOMP_DATA_ARG_COUNT, SECCOMP_DATA_ARGS_OFFSET,
    SECCOMP_DATA_NR_OFFSET, X32_SYSCALL_BIT,
};

/// Максимум инструкций в одном seccomp-фильтре.
///
/// Это `BPF_MAXINSNS` из ядра (`/usr/include/linux/bpf_common.h`). Ядро
/// отвергает фильтр длиннее — с `EINVAL` из `seccomp(2)`.
pub const BPF_MAXINSNS: usize = 4096;

/// Инструкций в заголовке программы (проверка арки и отсечение x32).
const HEADER_LEN: usize = 6;

/// Максимальная длина цепочки проверок аргументов в одном правиле.
///
/// `jt`/`jf` — 8-битные, поэтому любая цель прыжка внутри блока правила
/// (вход по `nr`, цепочка проверок, `RET` действия) должна быть не дальше
/// 255 инструкций. Проверки короче 254 инструкций это гарантируют.
pub const RULE_CHAIN_LIMIT: usize = 254;

/// Ошибки, возникающие при сборке BPF-программы для seccomp.
#[derive(Debug)]
pub enum BuildError {
    /// Номер системного вызова не помещается в 32-битное беззнаковое целое.
    SyscallNrOutOfRange { nr: i64 },
    /// BPF-опкод не помещается в 16-битное поле `code` структуры `sock_filter`.
    BpfCodeOutOfRange { code: u32 },
    /// Переданная константа имеет недопустимое значение для преобразования.
    InvalidConstant { name: &'static str, value: i64 },
    /// Программа превышает лимит ядра [`BPF_MAXINSNS`].
    ProgramTooLong { instructions: usize, limit: usize },
    /// Цепочка проверок аргументов в одном правиле длиннее, чем позволяет
    /// 8-битное поле перехода ([`RULE_CHAIN_LIMIT`]).
    RuleTooLong {
        rule: usize,
        instructions: usize,
        limit: usize,
    },
    /// Индекс проверяемого аргумента вне диапазона `0..SECCOMP_DATA_ARG_COUNT`.
    ArgIndexOutOfRange { arg: u32 },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SyscallNrOutOfRange { nr } => {
                write!(f, "номер сискола {nr} не влезает в u32")
            }
            Self::BpfCodeOutOfRange { code } => {
                write!(f, "BPF-опкод {code:#x} не влезает в u16")
            }
            Self::InvalidConstant { name, value } => {
                write!(f, "недопустимое значение константы {name}: {value}")
            }
            Self::ProgramTooLong {
                instructions,
                limit,
            } => write!(
                f,
                "программа из {instructions} инструкций превышает лимит ядра BPF_MAXINSNS ({limit})"
            ),
            Self::RuleTooLong {
                rule,
                instructions,
                limit,
            } => write!(
                f,
                "цепочка проверок правила {rule} заняла {instructions} инструкций, \
                 а 8-битный переход не тянет длиннее {limit}"
            ),
            Self::ArgIndexOutOfRange { arg } => {
                write!(
                    f,
                    "индекс аргумента {arg} вне диапазона 0..{SECCOMP_DATA_ARG_COUNT}"
                )
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// Создаёт стандартную (не переходную) инструкцию BPF.
///
/// # Аргументы
/// * `code` — битовая маска опкода (например, `BPF_LD | BPF_W | BPF_ABS`).
/// * `k` — аргумент инструкции (смещение в `seccomp_data` или константа).
///
/// # Возвращает
/// Структуру `sock_filter` с обнулёнными полями переходов (`jt` и `jf`).
///
/// # Ошибки
/// Возвращает `BuildError::BpfCodeOutOfRange`, если `code` не помещается в `u16`.
#[inline]
fn stmt(code: u32, k: u32) -> Result<sock_filter, BuildError> {
    u16::try_from(code).map_or(Err(BuildError::BpfCodeOutOfRange { code }), |c| {
        Ok(sock_filter {
            code: c,
            jt: 0,
            jf: 0,
            k,
        })
    })
}

/// Создаёт инструкцию условного перехода BPF.
///
/// # Аргументы
/// * `code` — битовая маска опкода перехода (например, `BPF_JMP | BPF_JEQ | BPF_K`).
/// * `k` — значение для сравнения с аккумулятором.
/// * `jt` — смещение для перехода, если условие истинно (true).
/// * `jf` — смещение для перехода, если условие ложно (false).
///
/// # Возвращает
/// Структуру `sock_filter`, готовую к использованию в BPF-программе.
///
/// # Ошибки
/// Возвращает `BuildError::BpfCodeOutOfRange`, если `code` не помещается в `u16`.
#[inline]
fn jump(code: u32, k: u32, jt: u8, jf: u8) -> Result<sock_filter, BuildError> {
    u16::try_from(code).map_or(Err(BuildError::BpfCodeOutOfRange { code }), |c| {
        Ok(sock_filter { code: c, jt, jf, k })
    })
}

/// Операция над значением одного аргумента сисколла.
///
/// Аргументы системных вызовов — беззнаковые `u64`, поэтому все сравнения
/// беззнаковые: «больше/меньше» трактуют аргумент и значение как `u64`,
/// как это делает и само ядро. `arg == -1` записывается через
/// [`Cmp::Eq`], но значение — `u64::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmp {
    /// `arg == val`.
    Eq(u64),
    /// `arg != val`.
    Ne(u64),
    /// `arg > val` (беззнаково).
    Gt(u64),
    /// `arg >= val` (беззнаково).
    Ge(u64),
    /// `arg < val` (беззнаково).
    Lt(u64),
    /// `arg <= val` (беззнаково).
    Le(u64),
    /// `(arg & mask) == (val & mask)` — маскированное равенство для проверки
    /// отдельных битов флагов (`SCMP_CMP_MASKED_EQ`).
    MaskedEq { mask: u64, val: u64 },
}

/// Число инструкций BPF, которые уйдут на одну проверку аргумента.
#[must_use]
pub const fn cmp_instructions(op: Cmp) -> usize {
    match op {
        // LD hi, JEQ hi, LD lo, JEQ lo — и для Eq, и для Ne.
        Cmp::Eq(_) | Cmp::Ne(_) => 4,
        // Lt вылезает за 5: младшее слово нужно проверить и на «>», и на «==»,
        // потому что `arg < val` запрещает оба исхода. Маскированному
        // равенству же нужны два `ALU|AND|K` — из-за этого тоже 6.
        Cmp::Lt(_) | Cmp::MaskedEq { .. } => 6,
        Cmp::Le(_) | Cmp::Gt(_) | Cmp::Ge(_) => 5,
    }
}

/// Проверка одного аргумента: индекс в `seccomp_data.args` + операция.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgCmp {
    /// Индекс аргумента (`0..6`: первый аргумент сисколла — 0).
    pub arg: u32,
    /// Что проверяем ([`Cmp`]).
    pub op: Cmp,
}

/// Правило фильтрации seccomp.
///
/// Определяет действие, которое должно быть выполнено при совпадении
/// номера системного вызова; если заданы [`Rule::args`] — при совпадении
/// номера **и** истинности всех проверок аргументов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Номер системного вызова (например, `libc::SYS_read`).
    pub nr: i64,
    /// Действие seccomp (например, `libc::SECCOMP_RET_ALLOW`).
    pub action: u32,
    /// Проверки аргументов; правило срабатывает, только если истинны все.
    pub args: Vec<ArgCmp>,
}

impl Rule {
    /// Новое правило без проверок аргументов: `nr` → `action`.
    #[must_use]
    pub const fn new(nr: i64, action: u32) -> Self {
        Self {
            nr,
            action,
            args: Vec::new(),
        }
    }

    /// Добавить проверку аргумента (builder).
    ///
    /// Проверки объединяются через «И»: правило срабатывает только когда
    /// номер сисколла совпал **и** выполнены все добавленные проверки.
    ///
    /// # Паники
    /// [`Cmp`] не проверяется здесь; недопустимый индекс `arg` (> 5)
    /// отработает в [`build_program`] как `BuildError::ArgIndexOutOfRange`.
    #[must_use]
    pub fn check(mut self, arg: u32, op: Cmp) -> Self {
        self.args.push(ArgCmp { arg, op });
        self
    }
}

/// Смещения младшего и старшего 32-битных слов аргумента в `seccomp_data`.
///
/// Раскладка little-endian x86_64: младшая половина `args[i]` — по
/// `16 + 8*i`, старшая — по `20 + 8*i`.
#[must_use]
const fn arg_offsets(arg: u32) -> (u32, u32) {
    let base = SECCOMP_DATA_ARGS_OFFSET + 8 * arg;
    (base, base + 4)
}

/// Разложить 64-битное значение на младшее и старшее 32-битные слова.
#[allow(clippy::cast_possible_truncation)] // срез верхних 32 бит и есть смысл этой функции
#[must_use]
const fn words(value: u64) -> (u32, u32) {
    (value as u32, (value >> 32) as u32)
}

/// Индекс последней инструкции в векторе.
const fn last(prog: &[sock_filter]) -> usize {
    prog.len() - 1
}

/// Куда прыгает условный переход, вылезающий за пределы своей проверки.
#[derive(Debug, Clone, Copy)]
enum Target {
    /// Следующее правило (или `default` после последнего правила).
    NextRule,
    /// `RET` действия самого правила — сюда прыгает «OK» последней проверки.
    Action,
    /// Начало проверки с индексом `usize` (порядок в `Rule::args`).
    Check(usize),
}

/// Какое поле перехода нужно залатать.
type Patch = (usize, bool, Target); // (индекс инструкции, true=jt / false=jf, цель)

/// Собрать блок BPF-инструкций одного правила: вход по номеру, цепочка
/// проверок аргументов, `RET` действия. Прыжки внутри блока расставляются
/// в конце, когда известны все цели.
///
/// Костяк любой проверки:
/// * цель «не совпало» (`FAIL`) — всегда следующее правило: несовпадение
///   аргументов обязано уронить и всё правило целиком;
/// * цель «совпало» (`OK`) — следующая проверка, а после последней —
///   «падение» на `RET` действия.
#[allow(clippy::too_many_lines)] // каждая строка — один-два push; расщеплять по вариантам смысла нет
fn compile_rule(rule_idx: usize, rule: &Rule) -> Result<Vec<sock_filter>, BuildError> {
    let nr = u32::try_from(rule.nr).map_err(|_| BuildError::SyscallNrOutOfRange { nr: rule.nr })?;

    // Каждый блок начинается с собственной перезагрузки номера сисколла:
    // предыдущее правило могло быть с проверками аргументов и забить
    // аккумулятор словом аргумента.
    let mut prog = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET)?,
        jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 0)?,
    ];
    let mut patches: Vec<Patch> = vec![(1, false, Target::NextRule)];
    let mut starts: Vec<usize> = Vec::with_capacity(rule.args.len());

    for (c, check) in rule.args.iter().enumerate() {
        starts.push(prog.len());
        let (lo, hi) = arg_offsets(check.arg);
        let ok = if c + 1 < rule.args.len() {
            Target::Check(c + 1)
        } else {
            Target::Action
        };

        match check.op {
            Cmp::Eq(v) => {
                let (vl, vh) = words(v);
                // hi == vh? не совпало → следующее правило.
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, hi)?);
                prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, vh, 0, 0)?);
                patches.push((last(&prog), false, Target::NextRule));
                // lo == vl? не совпало → следующее правило.
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, lo)?);
                prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, vl, 0, 0)?);
                patches.push((last(&prog), false, Target::NextRule));
            }
            Cmp::Ne(v) => {
                let (vl, vh) = words(v);
                // hi != vh → OK (jf); hi == vh → сравнить lo.
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, hi)?);
                prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, vh, 0, 0)?);
                patches.push((last(&prog), false, ok));
                // lo == vl → FAIL (jt); lo != vl → падаем на OK.
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, lo)?);
                prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, vl, 0, 0)?);
                patches.push((last(&prog), true, Target::NextRule));
            }
            Cmp::Lt(v) => {
                let (vl, vh) = words(v);
                // hi > vh → FAIL.
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, hi)?);
                prog.push(jump(BPF_JMP | BPF_JGT | BPF_K, vh, 0, 0)?);
                patches.push((last(&prog), true, Target::NextRule));
                // hi < vh → OK; hi == vh → проверить lo.
                prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, vh, 0, 0)?);
                patches.push((last(&prog), false, ok));
                // lo > vl → FAIL.
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, lo)?);
                prog.push(jump(BPF_JMP | BPF_JGT | BPF_K, vl, 0, 0)?);
                patches.push((last(&prog), true, Target::NextRule));
                // lo == vl → FAIL (это ровно `arg == val`); lo < vl → OK.
                prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, vl, 0, 0)?);
                patches.push((last(&prog), true, Target::NextRule));
            }
            Cmp::Le(v) => {
                let (vl, vh) = words(v);
                // hi > vh → FAIL.
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, hi)?);
                prog.push(jump(BPF_JMP | BPF_JGT | BPF_K, vh, 0, 0)?);
                patches.push((last(&prog), true, Target::NextRule));
                // hi < vh → OK; hi == vh → проверить lo.
                prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, vh, 0, 0)?);
                patches.push((last(&prog), false, ok));
                // lo > vl → FAIL (jt); lo <= vl → OK (jf).
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, lo)?);
                prog.push(jump(BPF_JMP | BPF_JGT | BPF_K, vl, 0, 0)?);
                patches.push((last(&prog), false, ok));
                patches.push((last(&prog), true, Target::NextRule));
            }
            Cmp::Gt(v) => {
                let (vl, vh) = words(v);
                // hi > vh → OK.
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, hi)?);
                prog.push(jump(BPF_JMP | BPF_JGT | BPF_K, vh, 0, 0)?);
                patches.push((last(&prog), true, ok));
                // hi == vh → проверить lo; hi < vh → FAIL.
                prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, vh, 0, 0)?);
                patches.push((last(&prog), false, Target::NextRule));
                // lo > vl → OK (jt); lo <= vl → FAIL (jf).
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, lo)?);
                prog.push(jump(BPF_JMP | BPF_JGT | BPF_K, vl, 0, 0)?);
                patches.push((last(&prog), true, ok));
                patches.push((last(&prog), false, Target::NextRule));
            }
            Cmp::Ge(v) => {
                let (vl, vh) = words(v);
                // hi > vh → OK.
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, hi)?);
                prog.push(jump(BPF_JMP | BPF_JGT | BPF_K, vh, 0, 0)?);
                patches.push((last(&prog), true, ok));
                // hi == vh → проверить lo; hi < vh → FAIL.
                prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, vh, 0, 0)?);
                patches.push((last(&prog), false, Target::NextRule));
                // lo >= vl → OK (jt); lo < vl → FAIL (jf).
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, lo)?);
                prog.push(jump(BPF_JMP | BPF_JGE | BPF_K, vl, 0, 0)?);
                patches.push((last(&prog), true, ok));
                patches.push((last(&prog), false, Target::NextRule));
            }
            Cmp::MaskedEq { mask, val } => {
                let (ml, mh) = words(mask);
                let (vl, vh) = words(val);
                // hi & mh == (val & mh)?
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, hi)?);
                prog.push(stmt(BPF_ALU | BPF_AND | BPF_K, mh)?);
                prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, vh & mh, 0, 0)?);
                patches.push((last(&prog), false, Target::NextRule));
                // lo & ml == (val & ml)?
                prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, lo)?);
                prog.push(stmt(BPF_ALU | BPF_AND | BPF_K, ml)?);
                prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, vl & ml, 0, 0)?);
                patches.push((last(&prog), false, Target::NextRule));
            }
        }
    }

    prog.push(stmt(BPF_RET | BPF_K, rule.action)?);

    // Латаем прыжки: теперь известны все цели.
    let total = prog.len();
    for (at, is_jt, target) in patches {
        let target_off = match target {
            Target::NextRule => total,
            Target::Action => total - 1,
            Target::Check(c) => starts[c],
        };
        let dist = target_off - (at + 1);
        let dist = u8::try_from(dist).map_err(|_| BuildError::RuleTooLong {
            rule: rule_idx,
            instructions: dist,
            limit: usize::from(u8::MAX),
        })?;
        if is_jt {
            prog[at].jt = dist;
        } else {
            prog[at].jf = dist;
        }
    }

    Ok(prog)
}

/// Компилирует набор правил seccomp в исполняемую BPF-программу.
///
/// Формирует валидный массив инструкций `sock_filter`, который последовательно проверяет:
/// 1. Архитектуру процесса (должна строго совпадать с `AUDIT_ARCH_X86_64`).
/// 2. Отсутствие флага `X32_SYSCALL_BIT` в номере системного вызова.
/// 3. Равенство номера системного вызова значениям из переданных `rules`
///    (и истинность проверок аргументов, если они заданы).
/// 4. Возврат `default_action`, если ни одно правило не совпало.
///
/// # Раскладка программы
///
/// Заголовок умирает сразу при несовпадении арки или x32-номера: оба
/// `RET KILL_PROCESS` стоят рядом с собственной проверкой, поэтому
/// «дальние» прыжки не нужны. Обычное правило (без аргументов) — тройка
/// с прыжками 0/1:
///
/// ```text
/// LD  [arch]
/// JEQ arch, jt=1, jf=0
/// RET KILL_PROCESS
/// LD  [nr]
/// JGE X32,  jt=0, jf=1
/// RET KILL_PROCESS
/// LD  [nr_i]                ; reload: аккумулятор мог быть затёрт
/// JEQ nr_i, jt=0, jf=1     ; правило i, первое совпадение выигрывает
/// RET act_i
/// ...
/// RET default_action
/// ```
///
/// Если у правила есть проверки аргументов, оно компилируется в блок из
/// входного `LD nr` + `JEQ nr`, цепочки проверок и `RET` действия.
/// Несовпадение аргумента уводит на следующее правило, совпадение ведёт по
/// цепочке дальше. Например, `Rule::new(nr, ACT).check(0, Cmp::Eq(v))`
/// собирается так (аргумент 0, разложение little-endian: старшее слово
/// по 20, младшее — по 16):
///
/// ```text
/// LD  [0],     k=0
/// JEQ nr,      jt=0, jf=5     ; nr не совпал → следующее правило
/// LD  [20],    k=5            ; старшее слово arg0
/// JEQ hi(v),   jt=0, jf=3     ; не совпало → следующее правило
/// LD  [16],    k=4            ; младшее слово arg0
/// JEQ lo(v),   jt=0, jf=1     ; не совпало → следующее правило
/// RET act                     ; все проверки прошли
/// ```
///
/// Соседство цели прыжка с его инструкцией гарантирует, что все `jt`/`jf`
/// влезают в 8 бит: длина цепочки проверок ограничена [`RULE_CHAIN_LIMIT`],
/// а всей программы — [`BPF_MAXINSNS`] ядра (4096).
///
/// # Аргументы
/// * `rules` — срез правил; проверяются по порядку, побеждает первое совпадение.
/// * `default_action` — действие, если ни одно правило не совпало.
///
/// # Возвращает
/// Вектор инструкций `sock_filter`, готовый для передачи в `prctl(PR_SET_SECCOMP, ...)`
/// или `seccomp(SECCOMP_SET_MODE_FILTER, ...)`.
///
/// # Errors
/// * `BuildError::SyscallNrOutOfRange` — если номер системного вызова в правиле отрицательный или > `u32::MAX`.
/// * `BuildError::ArgIndexOutOfRange` — если в проверке аргумента индекс >= 6.
/// * `BuildError::RuleTooLong` — если цепочка проверок одного правила не помещается в 8-битный переход.
/// * `BuildError::BpfCodeOutOfRange` — если внутренний опкод BPF не помещается в `u16`.
/// * `BuildError::ProgramTooLong` — если программа не влезает в [`BPF_MAXINSNS`].
pub fn build_program(rules: &[Rule], default_action: u32) -> Result<Vec<sock_filter>, BuildError> {
    // Предварительный проход: валидация правил и подсчёт длины программы.
    // Каждое правило — LD nr + вход + цепочка + RET (3 + chain).
    let mut total = HEADER_LEN + 1;
    for (i, rule) in rules.iter().enumerate() {
        u32::try_from(rule.nr).map_err(|_| BuildError::SyscallNrOutOfRange { nr: rule.nr })?;

        let mut chain = 0usize;
        for check in &rule.args {
            if check.arg >= SECCOMP_DATA_ARG_COUNT {
                return Err(BuildError::ArgIndexOutOfRange { arg: check.arg });
            }
            chain += cmp_instructions(check.op);
        }
        if chain > RULE_CHAIN_LIMIT {
            return Err(BuildError::RuleTooLong {
                rule: i,
                instructions: chain,
                limit: RULE_CHAIN_LIMIT,
            });
        }
        total += chain + 3;
    }

    if total > BPF_MAXINSNS {
        return Err(BuildError::ProgramTooLong {
            instructions: total,
            limit: BPF_MAXINSNS,
        });
    }

    let mut prog = Vec::with_capacity(total);

    // Заголовок: проверка архитектуры. Совпала — прыгаем через kill;
    // не совпала — падаем прямо на RET KILL_PROCESS.
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET)?);
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0)?);
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)?);

    // Заголовок: отсечение x32. nr >= X32_SYSCALL_BIT — падаем на kill;
    // иначе прыгаем через него.
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET)?);
    prog.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1)?);
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)?);

    // Правила: не совпало — прыжок на следующее; совпало — RET действия.
    for (i, rule) in rules.iter().enumerate() {
        prog.extend(compile_rule(i, rule)?);
    }

    // Действие по умолчанию.
    prog.push(stmt(BPF_RET | BPF_K, default_action)?);

    Ok(prog)
}
