use libc::{
    BPF_ABS, BPF_JEQ, BPF_JGE, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, SECCOMP_RET_KILL_PROCESS,
    sock_filter,
};

use crate::consts::{
    AUDIT_ARCH_X86_64, SECCOMP_DATA_ARCH_OFFSET, SECCOMP_DATA_NR_OFFSET, X32_SYSCALL_BIT,
};

#[inline]
const fn stmt(code: u16, k: u32) -> sock_filter {
    // c
    //  struct sock_filter {	/* Filter block */
    //      __u16	code;   /* Actual filter code */
    //      __u8	jt;	/* Jump true */
    //      __u8	jf;	/* Jump false */
    //      __u32	k;      /* Generic multiuse field */
    //};

    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[inline]
const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

/// Одно правило: "если сискол == `nr`, вернуть `action`".
pub struct Rule {
    pub nr: i64,
    pub action: u32,
}

/// Собирает BPF-программу. Структура (индексы для N правил):
///
/// ```text
/// 0: LD  arch
/// 1: JEQ AUDIT_ARCH_X86_64   jt=0 (продолжить) jf=-> kill_idx
/// 2: LD  nr
/// 3: JGE X32_SYSCALL_BIT     jt=-> kill_idx    jf=0 (продолжить)
/// 4 .. 4+2N-1: пары [JEQ nr_i jt=0 (попал -> свой RET) jf=skip_to_next, RET action_i]
/// 4+2N:   RET default_action
/// 4+2N+1: RET KILL   <- общая цель для обоих проверок выше (kill_idx)
/// ```
pub fn build_program(rules: &[Rule], default_action: u32) -> Vec<sock_filter> {
    let mut prog = Vec::with_capacity(4 + rules.len() * 2 + 2);

    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 0));
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));
    prog.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 0));

    let rules_start = prog.len(); // = 4
    for r in rules {
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, r.nr as u32, 0, 0));
        prog.push(stmt(BPF_RET | BPF_K, r.action));
    }

    let default_ret_idx = prog.len();
    prog.push(stmt(BPF_RET | BPF_K, default_action));

    let kill_idx = prog.len();
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    prog[1].jf = (kill_idx - (1 + 1)) as u8;
    prog[3].jt = (kill_idx - (3 + 1)) as u8;

    for (i, _) in rules.iter().enumerate() {
        let jump_idx = rules_start + i * 2;
        let is_last = i + 1 == rules.len();
        prog[jump_idx].jf = if is_last {
            (default_ret_idx - (jump_idx + 1)) as u8
        } else {
            1
        };
    }

    prog
}
