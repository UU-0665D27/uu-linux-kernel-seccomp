use uu_linux_kernel_seccomp::bpf;

fn main() -> Result<(), bpf::BuildError> {
    // 1. Определяем правила
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

    // 2. Безопасное преобразование константы без `as` и паники
    let enosys = u32::try_from(libc::ENOSYS).map_err(|_| bpf::BuildError::InvalidConstant {
        name: "libc::ENOSYS",
        value: i64::from(libc::ENOSYS),
    })?;

    let default_action = libc::SECCOMP_RET_ERRNO | enosys;
    let mut prog = bpf::build_program(&rules, default_action)?;

    // Выводим сгенерированную программу (до применения фильтра, чтобы std не мешал)
    println!("Сгенерировано {} инструкций BPF:", prog.len());
    for (i, f) in prog.iter().enumerate() {
        println!(
            "  {i:3}: code={:#06x} jt={} jf={} k={:#x}",
            f.code, f.jt, f.jf, f.k
        );
    }
    println!("---");

    // 3. Создаем дочерний процесс для безопасного тестирования
    let pid = unsafe { libc::fork() };

    match pid {
        -1 => {
            return Err(bpf::BuildError::InvalidConstant {
                name: "fork",
                value: i64::from(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)),
            });
        }
        0 => {
            // === КОД ПОТОМКА ===

            let len = u16::try_from(prog.len()).map_err(|_| bpf::BuildError::TooManyRules {
                needed_offset: prog.len(),
            })?;

            let sock_prog = libc::sock_fprog {
                len,
                filter: prog.as_mut_ptr(),
            };

            // Применяем seccomp через прямой системный вызов
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    // Инфалибльное расширение u32 -> c_ulong (u64) без `as`
                    libc::c_ulong::from(libc::SECCOMP_SET_MODE_FILTER),
                    // Явное приведение литерала к c_ulong обязательно для variadic функций
                    0 as libc::c_ulong,
                    // Приведение указателя к c_ulong (word-size) — стандарт для FFI
                    &sock_prog as *const _ as *const libc::c_void as libc::c_ulong,
                )
            };

            // syscall возвращает 0 при успехе и -1 при ошибке
            if rc != 0 {
                let err_msg = "[ОШИБКА] Не удалось применить seccomp\n".as_bytes();
                unsafe {
                    libc::write(2, err_msg.as_ptr() as *const libc::c_void, err_msg.len());
                }
                unsafe { libc::exit(1) };
            }

            // === ТЕСТ: Пытаемся вызвать ЗАПРЕЩЕННЫЙ системный вызов ===
            let test_pid = unsafe { libc::getpid() };

            if test_pid == -1 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOSYS) {
                    let msg =
                        "[УСПЕХ] Seccomp заблокировал getpid и вернул ENOSYS (38)\n".as_bytes();
                    unsafe {
                        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
                    }
                    unsafe { libc::exit(0) };
                } else {
                    let msg = "[ОШИБКА] getpid вернул неожиданную ошибку\n".as_bytes();
                    unsafe {
                        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
                    }
                    unsafe { libc::exit(1) };
                }
            } else {
                let msg = "[ПРОВАЛ] Seccomp НЕ сработал, getpid был разрешен!\n".as_bytes();
                unsafe {
                    libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
                }
                unsafe { libc::exit(1) };
            }
        }
        _ => {
            // === КОД РОДИТЕЛЯ ===
            // Ожидаем завершения дочернего процесса
            let mut status = 0;
            let wait_result = unsafe { libc::waitpid(pid, &mut status, 0) };

            if wait_result == -1 {
                eprintln!("Ошибка waitpid: {}", std::io::Error::last_os_error());
            } else {
                if libc::WIFEXITED(status) {
                    let exit_code = libc::WEXITSTATUS(status);
                    println!("Дочерний процесс завершился с кодом: {}", exit_code);
                } else if libc::WIFSIGNALED(status) {
                    let signal = libc::WTERMSIG(status);
                    println!("Дочерний процесс был убит сигналом: {}", signal);
                }
            }
        }
    }

    Ok(())
}
