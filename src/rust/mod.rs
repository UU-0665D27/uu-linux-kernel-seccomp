use crate::libc::{bpf::Rule, resolve_name};
use libc::{SECCOMP_RET_ALLOW, SECCOMP_RET_LOG, c_long, c_uint};

pub enum ACTION {
    ALLOW,
    LOG,
    TRACE,
    TRAP,
    DENY,
    ERRNO(u32),
}
#[must_use]
pub fn rule_nr(action: &ACTION, nr: c_long) -> Rule {
    if nr == -1 {
        //__NR_SCMP_ERROR
    }
    Rule {
        nr,
        action: action_name(action),
    }
}
#[must_use]
pub fn rule_name(action: &ACTION, name: &str) -> Rule {
    let nr = resolve_name(name);
    rule_nr(action, nr)
}
#[must_use]
pub fn action_name(action: &ACTION) -> c_uint {
    match action {
        ACTION::ALLOW => SECCOMP_RET_ALLOW,
        ACTION::LOG => SECCOMP_RET_LOG,
        ACTION::TRACE => todo!(),
        ACTION::TRAP => todo!(),
        ACTION::DENY => todo!(),
        ACTION::ERRNO(_) => todo!(),
    }
}
