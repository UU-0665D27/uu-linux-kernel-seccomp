//! Тесты чтения seccomp-фильтров через ptrace (`PTRACE_SECCOMP_GET_FILTER`).
//!
//! Сценарий: потомок ставит себе фильтр, родитель делает `PTRACE_ATTACH`,
//! вытаскивает инструкции и сравнивает с тем, что положили. Если у ядра
//! не хватает прав (`CAP_SYS_ADMIN` недоступен) — тест безобидно пропускаем.

use libc::sock_filter;
use uu_linux_kernel_seccomp::libc::bpf::{self, Rule};
use uu_linux_kernel_seccomp::libc::ptrace;
use uu_linux_kernel_seccomp::rust::{ACTION, Policy};

const EXIT_PRCTL: i32 = 90;
const EXIT_LEN: i32 = 91;
const EXIT_SECCOMP: i32 = 92;
const EXIT_IDLE: i32 = 93;

/// `Rule` с действием `ALLOW`.
const fn allow(nr: i64) -> Rule {
    Rule::new(nr, libc::SECCOMP_RET_ALLOW)
}

/// Применить фильтр к текущему процессу (внутри потомка).
fn apply_filter(prog: &[sock_filter]) {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        unsafe { libc::_exit(EXIT_PRCTL) };
    }
    let len = u16::try_from(prog.len()).unwrap_or_else(|_| unsafe { libc::_exit(EXIT_LEN) });
    let fprog = libc::sock_fprog {
        len,
        filter: prog.as_ptr().cast_mut(),
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::c_ulong::from(libc::SECCOMP_SET_MODE_FILTER),
            0 as libc::c_ulong,
            &raw const fprog,
        )
    };
    if rc != 0 {
        unsafe { libc::_exit(EXIT_SECCOMP) };
    }
}

/// Потомок: ставит фильтр и просто сидит в `pause()`.
fn child_task(prog: &[sock_filter]) -> ! {
    apply_filter(prog);
    unsafe { libc::pause() };
    unsafe { libc::_exit(EXIT_IDLE) };
}

#[test]
fn read_back_filters_of_child() {
    if !ptrace::readable_by_us() {
        // Нет `CAP_SYS_ADMIN` (или `scope` не позволяет attach).
        eprintln!("пропущено: PTRACE_SECCOMP_GET_FILTER недоступен без CAP_SYS_ADMIN");
        return;
    }

    let prog = bpf::build_program(
        &[allow(libc::SYS_pause), allow(libc::SYS_exit_group)],
        ACTION::KillThread.to_ret(),
    )
    .expect("сборка BPF-программы");

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork(): {}", std::io::Error::last_os_error());
    if pid == 0 {
        child_task(&prog);
    }

    match ptrace::seccomp_filters(pid) {
        Ok(filters) => {
            assert_eq!(filters.len(), 1, "ожидаем ровно один фильтр");
            let raw: &[sock_filter] = &filters[0];
            assert_eq!(raw.len(), prog.len());
            for (a, b) in raw.iter().zip(prog.iter()) {
                assert_eq!(
                    (a.code, a.jt, a.jf, a.k),
                    (b.code, b.jt, b.jf, b.k),
                    "филиль в ядре отличается от установленного"
                );
            }
        }
        Err(err) => {
            ptrace::kill_and_reap(pid);
            panic!("не получилось прочитать фильтры: {err}");
        }
    }

    ptrace::kill_and_reap(pid);
}

#[test]
fn policy_still_compiles_after_rework() {
    // Дымовой тест, чтобы `Policy` не имел регрессии вместе с ptrace-модулем.
    let prog = Policy::denylist()
        .allow("pause")
        .expect("pause")
        .compile()
        .expect("compile");
    assert!(prog.len() >= 2);
}
