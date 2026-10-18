use libc::sock_filter;
use uu_linux_kernel_seccomp::libc::{bpf, dump};

fn main() -> Result<(), bpf::BuildError> {
    let rules = vec![
        bpf::Rule::new(libc::SYS_read, libc::SECCOMP_RET_ALLOW),
        bpf::Rule::new(libc::SYS_write, libc::SECCOMP_RET_ALLOW),
        bpf::Rule::new(libc::SYS_execve, libc::SECCOMP_RET_ALLOW),
        bpf::Rule::new(libc::SYS_exit, libc::SECCOMP_RET_ALLOW),
        bpf::Rule::new(libc::SYS_exit_group, libc::SECCOMP_RET_ALLOW),
        // Демонстрация проверки аргумента: open(...) только с пустыми
        // флагами (O_RDONLY == 0) — аргумент 1, младшая и старшая половины.
        bpf::Rule::new(libc::SYS_open, libc::SECCOMP_RET_ALLOW).check(1, bpf::Cmp::Eq(0)),
    ];

    let enosys = u32::try_from(libc::ENOSYS).map_err(|_| bpf::BuildError::InvalidConstant {
        name: "libc::ENOSYS",
        value: i64::from(libc::ENOSYS),
    })?;

    let default_action = libc::SECCOMP_RET_ERRNO | enosys;
    let mut prog = bpf::build_program(&rules, default_action)?;

    let colored = unsafe { libc::isatty(libc::STDOUT_FILENO) } == 1;
    let listing = if colored {
        dump::dump_colored(&prog)
    } else {
        dump::dump(&prog)
    };
    println!(
        "Сгенерировано {} инструкций BPF: {}",
        prog.len(),
        if colored {
            "(цвет)"
        } else {
            "(без цвета)"
        }
    );
    print!("{listing}");
    let _ = std::io::Write::flush(&mut std::io::stdout());
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

    // 4. Тестируем запрещенный системный вызов.
    // Обёртка `libc::syscall` транслирует сырое `-errno` от ядра в `-1`
    // и выставляет `errno`, поэтому ошибку читаем из `errno`, а не из знака.
    let test_pid = unsafe { libc::syscall(libc::SYS_getpid) };

    if test_pid == -1 {
        let errno = std::io::Error::last_os_error().raw_os_error();
        if errno == Some(libc::ENOSYS) {
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
