//! Дизассемблер seccomp-BPF.
//!
//! Превращает готовую программу (`&[sock_filter]`) в текстовый листинг в
//! стиле `ceccomp dump` / `seccomp-tools dump`:
//!
//! ```text
//! #Label  CODE  JT   JF      K
//! #---------------------------------
//!  L0001: 0x20 0x00 0x00 0x00000004 $A = $arch
//!  L0002: 0x15 0x01 0x00 0xc000003e if ($A == x86_64) goto L0004
//!  ...
//! #---------------------------------
//! ```
//!
//! Два варианта вывода: [`dump`] — без цвета (для файлов, пайпов и тестов),
//! [`dump_colored`] — с ANSI-раскраской для терминала:
//!
//! * жёлтый — числовые/архитектурные операнды (`x86_64`, `0x40000000`, …);
//! * голубой — имена системных вызовов;
//! * красный — блокирующие действия (`KILL`, `ERRNO`, `TRAP`);
//! * зелёный — пропускающие (`ALLOW`, `LOG`).

use core::fmt::Write as _;

use libc::{
    BPF_ABS, BPF_ALU, BPF_AND, BPF_JA, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JMP, BPF_JSET, BPF_K, BPF_LD,
    BPF_RET, BPF_W, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
    SECCOMP_RET_KILL_THREAD, SECCOMP_RET_LOG, SECCOMP_RET_TRACE, SECCOMP_RET_TRAP,
    SECCOMP_RET_USER_NOTIF, c_long, sock_filter,
};

use crate::libc::consts::{AUDIT_ARCH_X86_64, SECCOMP_DATA_ARCH_OFFSET, SECCOMP_DATA_NR_OFFSET};
use crate::libc::name_of;

// Полные опкоды инструкций, которые понимает дизассемблер.
const CODE_LD_W_ABS: u32 = BPF_LD | BPF_W | BPF_ABS;
const CODE_RET_K: u32 = BPF_RET | BPF_K;
const CODE_JA: u32 = BPF_JMP | BPF_JA;
const CODE_JEQ: u32 = BPF_JMP | BPF_JEQ | BPF_K;
const CODE_JGT: u32 = BPF_JMP | BPF_JGT | BPF_K;
const CODE_JGE: u32 = BPF_JMP | BPF_JGE | BPF_K;
const CODE_JSET: u32 = BPF_JMP | BPF_JSET | BPF_K;
const CODE_ALU_AND_K: u32 = BPF_ALU | BPF_AND | BPF_K;

const HEADER: &str = "#Label  CODE  JT   JF      K\n";
const SEPARATOR: &str = "#---------------------------------\n";

// ANSI-цвета.
const RESET: &str = "\x1b[0m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";

/// Обернуть текст в ANSI-цвет (или вернуть как есть).
fn paint(color: bool, code: &str, text: &str) -> String {
    if color {
        format!("{code}{text}{RESET}")
    } else {
        text.to_owned()
    }
}

/// Действие `ERRNO`/`LOG`/… из `ret`-значения вместе с его цветом.
fn action_text(k: u32) -> (&'static str, String) {
    let action = k & 0xffff_0000;
    let data = k & 0x0000_ffff;

    match action {
        SECCOMP_RET_KILL_PROCESS => (RED, "KILL_PROCESS".to_owned()),
        SECCOMP_RET_KILL_THREAD => (RED, "KILL".to_owned()),
        SECCOMP_RET_TRAP => (RED, "TRAP".to_owned()),
        SECCOMP_RET_ERRNO => (RED, format!("ERRNO({data})")),
        SECCOMP_RET_ALLOW => (GREEN, "ALLOW".to_owned()),
        SECCOMP_RET_LOG => (GREEN, "LOG".to_owned()),
        SECCOMP_RET_TRACE => (YELLOW, "TRACE".to_owned()),
        SECCOMP_RET_USER_NOTIF => (YELLOW, "USER_NOTIF".to_owned()),
        _ => (YELLOW, format!("0x{k:08x}")),
    }
}

/// Операнд сравнения вместе с его цветом: константы — жёлтые, имена — голубые.
///
/// Имя сисколла выводится только для **входных** сравнений (когда
/// предыдущая инструкция загружала `$syscall_nr`): то же число в проверке
/// аргумента — это просто константа, а не номер сисколла.
fn operand_text(k: u32, nr_context: bool) -> (&'static str, String) {
    if k == AUDIT_ARCH_X86_64 {
        return (YELLOW, "x86_64".to_owned());
    }
    if nr_context && let Some(name) = name_of(c_long::from(k)) {
        return (CYAN, name.to_owned());
    }
    (YELLOW, format!("0x{k:08x}"))
}

/// Это входное сравнение? Предыдущая инструкция обязана загружать `nr`.
fn preceded_by_nr_load(prog: &[sock_filter], pc: usize) -> bool {
    pc > 0
        && prog[pc - 1].code == u16::try_from(CODE_LD_W_ABS).unwrap_or(0)
        && prog[pc - 1].k == SECCOMP_DATA_NR_OFFSET
}

/// Дизассемблировать одну инструкцию. `None` — неизвестный опкод.
fn disasm(prog: &[sock_filter], pc: usize, color: bool) -> Option<String> {
    let ins = &prog[pc];
    let code = u32::from(ins.code);
    let here = pc + 1; // 1-based метка текущей инструкции

    if code == CODE_LD_W_ABS {
        let text = match ins.k {
            k if k == SECCOMP_DATA_NR_OFFSET => "$A = $syscall_nr".to_owned(),
            k if k == SECCOMP_DATA_ARCH_OFFSET => "$A = $arch".to_owned(),
            k => format!("$A = [0x{k:08x}]"),
        };
        return Some(text);
    }

    if code == CODE_RET_K {
        let (color_code, text) = action_text(ins.k);
        return Some(format!("return {}", paint(color, color_code, &text)));
    }

    if code == CODE_ALU_AND_K {
        // `A &= k` — так компилируется маскированное равенство.
        let constant = paint(color, YELLOW, &format!("0x{:08x}", ins.k));
        return Some(format!("$A = $A & {constant}"));
    }

    if code == CODE_JA {
        let target = here + 1 + usize::try_from(ins.k).ok()?;
        return Some(format!("goto L{target:04}"));
    }

    let (op_true, op_false) = match code {
        CODE_JEQ => ("==", "!="),
        CODE_JGT => (">", "<="),
        CODE_JGE => (">=", "<"),
        CODE_JSET => ("&", "!&"),
        _ => return None,
    };

    let (color_code, operand) = operand_text(ins.k, preceded_by_nr_load(prog, pc));
    let operand = paint(color, color_code, &operand);

    // `goto` ставится в ту сторону, где смещение не равно нулю; если обе
    // ветви нулевые — печатаем условие без перехода.
    let body = if ins.jt != 0 {
        let target = here + 1 + usize::from(ins.jt);
        format!("{op_true} {operand}) goto L{target:04}")
    } else if ins.jf != 0 {
        let target = here + 1 + usize::from(ins.jf);
        format!("{op_false} {operand}) goto L{target:04}")
    } else {
        format!("{op_true} {operand})")
    };

    Some(format!("if ($A {body}"))
}

/// Отрисовать программу в листинг без цвета.
#[must_use]
pub fn dump(prog: &[sock_filter]) -> String {
    render(prog, false)
}

/// Отрисовать программу в листинг с ANSI-раскраской.
#[must_use]
pub fn dump_colored(prog: &[sock_filter]) -> String {
    render(prog, true)
}

/// Общий движок отрисовки.
fn render(prog: &[sock_filter], color: bool) -> String {
    let mut out = String::new();
    out.push_str(HEADER);
    out.push_str(SEPARATOR);

    for pc in 0..prog.len() {
        let ins = &prog[pc];
        let text = disasm(prog, pc, color).unwrap_or_else(|| "???".to_owned());
        let _ = writeln!(
            out,
            " L{:04}: 0x{:02x} 0x{:02x} 0x{:02x} 0x{:08x} {text}",
            pc + 1,
            ins.code,
            ins.jt,
            ins.jf,
            ins.k
        );
    }

    out.push_str(SEPARATOR);
    out
}
