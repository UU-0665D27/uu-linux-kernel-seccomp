mod bpf;
mod consts;

fn main() -> Result<(), bpf::BuildError> {
    let rules = vec![
        bpf::Rule {
            nr: libc::SYS_read,
            action: libc::SECCOMP_RET_ALLOW,
        },
        bpf::Rule {
            nr: libc::SYS_write,
            action: libc::SECCOMP_RET_ALLOW,
        },
        bpf::Rule {
            nr: libc::SYS_execve,
            action: libc::SECCOMP_RET_ALLOW,
        },
    ];

    #[allow(clippy::cast_sign_loss)] // ENOSYS=38 — заведомо положительная константа
    let enosys = libc::ENOSYS as u32;
    let prog = bpf::build_program(&rules, libc::SECCOMP_RET_ERRNO | enosys)?;

    for (i, f) in prog.iter().enumerate() {
        println!(
            "{i:3}: code={:#06x} jt={} jf={} k={:#x}",
            f.code, f.jt, f.jf, f.k
        );
    }
    Ok(())
}
