use uu_linux_kernel_seccomp::bpf;

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

    let enosys = u32::try_from(libc::ENOSYS).map_err(|_| bpf::BuildError::InvalidConstant {
        name: "libc::ENOSYS",
        value: i64::from(libc::ENOSYS),
    })?;

    let prog = bpf::build_program(&rules, libc::SECCOMP_RET_ERRNO | enosys)?;

    for (i, f) in prog.iter().enumerate() {
        println!(
            "{i:3}: code={:#06x} jt={} jf={} k={:#x}",
            f.code, f.jt, f.jf, f.k
        );
    }

    let result = unsafe { libc::fork() };
    match result {
        -1 => {
            //ошибка fork
        }
        0 => {
            //код потомка
            unsafe { libc::exit(0) };
        }
        _ => {
            //родительский код
        }
    }
    Ok(())
}
