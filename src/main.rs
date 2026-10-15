use libc::sock_filter;
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
        bpf::Rule {
            nr: libc::SYS_exit,
            action: libc::SECCOMP_RET_ALLOW,
        },
        bpf::Rule {
            nr: libc::SYS_exit_group,
            action: libc::SECCOMP_RET_ALLOW,
        },
    ];

    let enosys = u32::try_from(libc::ENOSYS).map_err(|_| bpf::BuildError::InvalidConstant {
        name: "libc::ENOSYS",
        value: i64::from(libc::ENOSYS),
    })?;

    let default_action = libc::SECCOMP_RET_ERRNO | enosys;
    let mut prog = bpf::build_program(&rules, default_action)?;

    println!("Сгенерировано {} инструкций BPF:", prog.len());
    for (i, f) in prog.iter().enumerate() {
        println!(
            "  {i:3}: code={:#06x} jt={} jf={} k={:#x}",
            f.code, f.jt, f.jf, f.k
        );
    }
    println!("---");

    let pid = unsafe { libc::fork() };

    match pid {
        -1 => Err(bpf::BuildError::InvalidConstant {
            name: "fork",
            value: i64::from(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)),
        }),
        0 => {
            // Дочерний процесс никогда не возвращает управление в main
            run_child_process(&mut prog);
        }
        _ => {
            run_parent_process(pid);
            Ok(())
        }
    }
}

/// Выполняет применение seccomp и тестирование в изолированном дочернем процессе.
fn run_child_process(prog: &mut [sock_filter]) -> ! {
    // 1. Критически важно: разрешаем применение seccomp-фильтра
    let prctl_rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if prctl_rc != 0 {
        let msg = "[ОШИБКА] Не удалось установить PR_SET_NO_NEW_PRIVS\n".as_bytes();
        unsafe { libc::write(2, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        unsafe { libc::exit(1) };
    }

    // 2. Подготавливаем структуру sock_fprog
    let Ok(len) = u16::try_from(prog.len()) else {
        let msg = "[ОШИБКА] Слишком много правил BPF\n".as_bytes();
        unsafe { libc::write(2, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        unsafe { libc::exit(1) };
    };

    let sock_prog = libc::sock_fprog {
        len,
        filter: prog.as_mut_ptr(),
    };

    // 3. Применяем seccomp через прямой системный вызов
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::c_ulong::from(libc::SECCOMP_SET_MODE_FILTER),
            0 as libc::c_ulong,
            (&raw const sock_prog).cast::<libc::c_void>() as libc::c_ulong,
        )
    };

    if rc != 0 {
        let msg = "[ОШИБКА] Не удалось применить seccomp\n".as_bytes();
        unsafe { libc::write(2, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        unsafe { libc::exit(1) };
    }

    // 4. Тестируем запрещенный системный вызов
    // Используем прямой syscall, чтобы избежать кэширования PID
    // и особенностей обработки errno в glibc/musl.
    let test_pid = unsafe { libc::syscall(libc::SYS_getpid) };

    // В Linux syscall при ошибке возвращает -errno (в данном случае -38)
    if test_pid < 0 {
        let err_code = -test_pid;
        // Инфалибльное преобразование i32 (ENOSYS) в c_long через .into()
        if err_code == libc::ENOSYS.into() {
            let msg = "[УСПЕХ] Seccomp заблокировал getpid и вернул ENOSYS (38)\n".as_bytes();
            unsafe { libc::write(2, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
            unsafe { libc::exit(0) };
        }

        let msg = "[ОШИБКА] getpid вернул неожиданную ошибку\n".as_bytes();
        unsafe { libc::write(2, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
        unsafe { libc::exit(1) };
    }

    let msg = "[ПРОВАЛ] Seccomp НЕ сработал, getpid был разрешен!\n".as_bytes();
    unsafe { libc::write(2, msg.as_ptr().cast::<libc::c_void>(), msg.len()) };
    unsafe { libc::exit(1) };
}

/// Ожидает завершения дочернего процесса и выводит результат.
fn run_parent_process(pid: i32) {
    let mut status = 0;
    // Используем &raw mut вместо &mut status as *mut _
    let wait_result = unsafe { libc::waitpid(pid, &raw mut status, 0) };

    if wait_result == -1 {
        eprintln!("Ошибка waitpid: {}", std::io::Error::last_os_error());
    } else if libc::WIFEXITED(status) {
        let exit_code = libc::WEXITSTATUS(status);
        // Инлайнинг аргументов форматирования
        println!("Дочерний процесс завершился с кодом: {exit_code}");
    } else if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        println!("Дочерний процесс был убит сигналом: {signal}");
    }
}
