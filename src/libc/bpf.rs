use libc::{
    BPF_ABS, BPF_JEQ, BPF_JGE, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, SECCOMP_RET_KILL_PROCESS,
    sock_filter,
};
use std::fmt;

use crate::libc::consts::{
    AUDIT_ARCH_X86_64, SECCOMP_DATA_ARCH_OFFSET, SECCOMP_DATA_NR_OFFSET, X32_SYSCALL_BIT,
};

/// Ошибки, возникающие при сборке BPF-программы для seccomp.
#[derive(Debug)]
pub enum BuildError {
    /// Превышен лимит относительного перехода BPF (jt/jf должны быть <= 255).
    TooManyRules { needed_offset: usize },
    /// Номер системного вызова не помещается в 32-битное беззнаковое целое.
    SyscallNrOutOfRange { nr: i64 },
    /// BPF-опкод не помещается в 16-битное поле `code` структуры `sock_filter`.
    BpfCodeOutOfRange { code: u32 },
    /// Переданная константа имеет недопустимое значение для преобразования.
    InvalidConstant { name: &'static str, value: i64 },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyRules { needed_offset } => write!(
                f,
                "слишком много правил: нужен переход на {needed_offset} инструкций вперёд, лимит BPF jt/jf — 255"
            ),
            Self::SyscallNrOutOfRange { nr } => {
                write!(f, "номер сискола {nr} не влезает в u32")
            }
            Self::BpfCodeOutOfRange { code } => {
                write!(f, "BPF-опкод {code:#x} не влезает в u16")
            }
            Self::InvalidConstant { name, value } => {
                write!(f, "недопустимое значение константы {name}: {value}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// Преобразует смещение в 8-битное значение для инструкций перехода BPF.
///
/// Инструкции перехода в классическом BPF (cBPF) используют 8-битные поля `jt` и `jf`,
/// что ограничивает максимальный относительный прыжок 255 инструкциями.
///
/// # Аргументы
/// * `offset` — целевое смещение в количестве инструкций.
///
/// # Ошибки
/// Возвращает `BuildError::TooManyRules`, если `offset` превышает `u8::MAX`.
fn offset_to_u8(offset: usize) -> Result<u8, BuildError> {
    u8::try_from(offset).map_err(|_| BuildError::TooManyRules {
        needed_offset: offset,
    })
}

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

/// Правило фильтрации seccomp.
///
/// Определяет действие, которое должно быть выполнено при совпадении
/// номера системного вызова.
pub struct Rule {
    /// Номер системного вызова (например, `libc::SYS_read`).
    pub nr: i64,
    /// Действие seccomp (например, `libc::SECCOMP_RET_ALLOW`).
    pub action: u32,
}

/// Компилирует набор правил seccomp в исполняемую BPF-программу.
///
/// Формирует валидный массив инструкций `sock_filter`, который последовательно проверяет:
/// 1. Архитектуру процесса (должна строго совпадать с `AUDIT_ARCH_X86_64`).
/// 2. Отсутствие флага `X32_SYSCALL_BIT` в номере системного вызова.
/// 3. Равенство номера системного вызова значениям из переданных `rules`.
/// 4. Возврат `default_action`, если ни одно правило не совпало.
/// 5. Принудительное завершение процесса (`SECCOMP_RET_KILL_PROCESS`) как абсолютный fallback.
///
/// После генерации базовых инструкций метод автоматически вычисляет и патчит
/// относительные смещения переходов (`jt` и `jf`).
///
/// # Аргументы
/// * `rules` — срез правил, определяющих разрешённые системные вызовы и действия.
/// * `default_action` — действие по умолчанию (обычно `SECCOMP_RET_ERRNO | код_ошибки`).
///
/// # Возвращает
/// Вектор инструкций `sock_filter`, готовый для передачи в `prctl(PR_SET_SECCOMP, ...)`
/// или `seccomp(SECCOMP_SET_MODE_FILTER, ...)`.
///
/// # Errors
/// * `BuildError::SyscallNrOutOfRange` — если номер системного вызова в правиле отрицательный или > `u32::MAX`.
/// * `BuildError::BpfCodeOutOfRange` — если внутренний опкод BPF не помещается в `u16`.
/// * `BuildError::TooManyRules` — если количество правил слишком велико, и относительный
///   переход к `default_action` или `kill` превышает лимит в 255 инструкций.
pub fn build_program(rules: &[Rule], default_action: u32) -> Result<Vec<sock_filter>, BuildError> {
    let mut prog = Vec::with_capacity(4 + rules.len() * 2 + 2);

    // Теперь все вызовы используют оператор ? для проброса ошибки
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET)?);
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 0)?);
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET)?);
    prog.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 0)?);

    let rules_start = prog.len();
    for r in rules {
        let nr = u32::try_from(r.nr).map_err(|_| BuildError::SyscallNrOutOfRange { nr: r.nr })?;
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 0)?);
        prog.push(stmt(BPF_RET | BPF_K, r.action)?);
    }

    let default_ret_idx = prog.len();
    prog.push(stmt(BPF_RET | BPF_K, default_action)?);

    let kill_idx = prog.len();
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)?);

    prog[1].jf = offset_to_u8(kill_idx - (1 + 1))?;
    prog[3].jt = offset_to_u8(kill_idx - (3 + 1))?;

    for (i, _) in rules.iter().enumerate() {
        let jump_idx = rules_start + i * 2;
        let is_last = i + 1 == rules.len();
        prog[jump_idx].jf = if is_last {
            offset_to_u8(default_ret_idx - (jump_idx + 1))?
        } else {
            1
        };
    }

    Ok(prog)
}
