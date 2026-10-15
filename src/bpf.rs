use crate::consts::{
    AUDIT_ARCH_X86_64, SECCOMP_DATA_ARCH_OFFSET, SECCOMP_DATA_NR_OFFSET, X32_SYSCALL_BIT,
};
use libc::{
    BPF_ABS, BPF_JEQ, BPF_JGE, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, SECCOMP_RET_KILL_PROCESS,
    sock_filter,
};
use std::fmt;

/// Ошибки сборки BPF-программы.
#[derive(Debug)]
pub enum BuildError {
    TooManyRules { needed_offset: usize },
    SyscallNrOutOfRange { nr: i64 },
    BpfCodeOutOfRange { code: u32 },
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

fn offset_to_u8(offset: usize) -> Result<u8, BuildError> {
    u8::try_from(offset).map_err(|_| BuildError::TooManyRules {
        needed_offset: offset,
    })
}

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

#[inline]
fn jump(code: u32, k: u32, jt: u8, jf: u8) -> Result<sock_filter, BuildError> {
    u16::try_from(code).map_or(Err(BuildError::BpfCodeOutOfRange { code }), |c| {
        Ok(sock_filter { code: c, jt, jf, k })
    })
}

pub struct Rule {
    pub nr: i64,
    pub action: u32,
}

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
