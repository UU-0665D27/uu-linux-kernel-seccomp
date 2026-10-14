mod bpf;
mod consts;

fn main() {
    let rules = vec![
        bpf::Rule {
            nr: libc::SYS_read,
            action: consts::SECCOMP_RET_ALLOW,
        },
        bpf::Rule {
            nr: libc::SYS_write,
            action: consts::SECCOMP_RET_ALLOW,
        },
        bpf::Rule {
            nr: libc::SYS_execve,
            action: consts::SECCOMP_RET_ALLOW,
        },
    ];

    let prog = bpf::build_program(&rules, libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32));

    for (i, f) in prog.iter().enumerate() {
        println!(
            "{i:3}: code={:#06x} jt={} jf={} k={:#x}",
            f.code, f.jt, f.jf, f.k
        );
    }
}
