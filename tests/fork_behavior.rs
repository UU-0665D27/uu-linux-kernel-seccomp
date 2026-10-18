//! Поведенческие тесты seccomp: фильтр применяется в дочернем процессе,
//! созданном через `fork`, и проверяется реальная реакция ядра.
//!
//! Почему именно `fork` и дочерний процесс:
//! * seccomp необратим — установив фильтр, «снять» его нельзя, поэтому
//!   грязный эксперимент уводим в потомка, а родитель остаётся чистым;
//! * после `fork` в многопоточном тест-раннере потомок обязан обходиться
//!   без выделения памяти, блокировок и ввода-вывода — иначе рискуем
//!   упереться в мьютекс, захваченный «потерянным» потоком. Поэтому
//!   BPF-программа собирается ДО `fork`, а результат передаётся через код
//!   выхода / факт смерти по сигналу (его читает `waitpid`).
//!
//! Про `errno`: glibc/musl-обёртка `syscall()` преобразует сырое `-errno`
//! от ядра в `-1` + `errno`. Поэтому «действие `ERRNO`» проверяем по
//! `errno`, а не по знаку возврата.

use core::sync::atomic::{AtomicBool, Ordering};

use libc::sock_filter;
use uu_linux_kernel_seccomp::libc::bpf::{self, Cmp, Rule};
use uu_linux_kernel_seccomp::rust::ACTION;

// Коды выхода для внутренних сбоев инфраструктуры (не должны появляться
// в успешных прогонах).
const EXIT_PRCTL: i32 = 90;
const EXIT_LEN: i32 = 91;
const EXIT_SECCOMP: i32 = 92;

/// Итог ожидания дочернего процесса.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Потомок завершился сам с данным кодом.
    Exited(i32),
    /// Потомка убило сигналом (номер сигнала).
    Signaled(i32),
}

/// `Rule` с действием `ALLOW`.
const fn allow(nr: i64) -> Rule {
    Rule::new(nr, libc::SECCOMP_RET_ALLOW)
}

/// Флаг `O_*` (в libc — `i32`) в беззнаковой 64-битной записи для BPF.
#[allow(clippy::cast_sign_loss)]
const fn flag(value: libc::c_int) -> u64 {
    value as u64
}

/// Действие `ERRNO` через высокоуровневый [`ACTION`].
fn errno_ret(errno: libc::c_int) -> u32 {
    ACTION::Errno(u16::try_from(errno).expect("errno влезает в u16")).to_ret()
}

/// Собрать BPF-программу в родителе (там выделение памяти безопасно).
fn program(rules: &[Rule], default_action: u32) -> Vec<sock_filter> {
    bpf::build_program(rules, default_action).expect("сборка BPF-программы")
}

/// Применить фильтр к текущему (дочернему) процессу.
///
/// Выделений, форматирования и `panic` здесь быть не должно: после `fork`
/// это может заклинить. Любой сбой выходим специальным кодом.
fn apply_filter(prog: &[sock_filter]) {
    let prctl_rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if prctl_rc != 0 {
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

/// Флаг срабатывания обработчика `SIGSYS` (для проверки `TRAP`).
static SIGSYS_SEEN: AtomicBool = AtomicBool::new(false);

/// Обработчик `SIGSYS`: только атомарная запись, никакого I/O.
extern "C" fn on_sigsys(_signal: libc::c_int) {
    SIGSYS_SEEN.store(true, Ordering::SeqCst);
}

// ── «Тела» потомков ──────────────────────────────────────────────────

/// Ожидает, что `getpid` вернёт настоящий pid (действия `ALLOW`/`LOG`).
fn child_expect_pid(prog: &[sock_filter], (): ()) -> i32 {
    apply_filter(prog);
    let ret = unsafe { libc::syscall(libc::SYS_getpid) };
    i32::from(ret <= 0)
}

/// Ожидает, что `getpid` вернёт `-errno` с заданным `errno`.
fn child_expect_errno(prog: &[sock_filter], want: libc::c_int) -> i32 {
    apply_filter(prog);
    let ret = unsafe { libc::syscall(libc::SYS_getpid) };
    if ret != -1 {
        return 2;
    }
    let errno = unsafe { *libc::__errno_location() };
    i32::from(errno != want)
}

/// Просто дёргает `getpid`; используется для фатальных действий.
fn child_probe_getpid(prog: &[sock_filter], (): ()) -> i32 {
    apply_filter(prog);
    unsafe { libc::syscall(libc::SYS_getpid) };
    0
}

/// Проверяет правило на `arg0` у `getpgid` (аргумент передаём сами, ноль).
///
/// 0 — `getpgid(0)` вернул pgid; 1 — вернул ошибку.
fn child_expect_pgid(prog: &[sock_filter], (): ()) -> i32 {
    apply_filter(prog);
    // 0 как c_long: важны именно 64 бита для сравнения в BPF.
    let ret = unsafe { libc::syscall(libc::SYS_getpgid, 0i64) };
    i32::from(ret == -1)
}

/// То же, но ожидает `errno == want` (правило не совпало, default — ERRNO).
///
/// 0 — совпадение; 2 — сисколл случайно разрешился; 1 — чужой errno.
fn child_expect_pgid_errno(prog: &[sock_filter], want: libc::c_int) -> i32 {
    apply_filter(prog);
    let ret = unsafe { libc::syscall(libc::SYS_getpgid, 0i64) };
    if ret != -1 {
        return 2;
    }
    i32::from(unsafe { *libc::__errno_location() } != want)
}

/// Открывает `/dev/null` двумя вызовами `open` и проверяет реакцию фильтра
/// на флаги (arg1). `wrong_flags` — флаги, обязанные упереться в `default`.
///
/// 0 — обе проверки сошлись; 1 — чтение не открылось;
/// 2 — «плохие» флаги случайно разрешились; 3 — не тот errno.
fn child_open_flags(prog: &[sock_filter], wrong_flags: libc::c_int) -> i32 {
    const PATH: &[u8] = b"/dev/null\0";

    apply_filter(prog);

    // Открытие на чтение обязано пройти (rule по arg1 = флаги).
    let ro = unsafe { libc::syscall(libc::SYS_open, PATH.as_ptr(), i64::from(libc::O_RDONLY), 0) };
    if ro < 0 {
        return 1;
    }

    // «Плохие» флаги обязаны урониться в default.
    let wo = unsafe { libc::syscall(libc::SYS_open, PATH.as_ptr(), i64::from(wrong_flags), 0) };
    if wo != -1 {
        return 2;
    }
    if unsafe { *libc::__errno_location() } != libc::EPERM {
        return 3;
    }

    0
}

/// Проверяет разбивку `Lt`/`Ge` по arg0 у `getpriority` (which).
///
/// 0 — обе ветки правильные; 1 — разрешённая ветка не прошла;
/// 2 — запрещённая разрешилась; 3 — не тот errno.
fn child_getpriority_range(prog: &[sock_filter], (): ()) -> i32 {
    apply_filter(prog);
    // PRIO_PROCESS (0): arg0 < 1 → ALLOW; возвращает nice (0 по умолчанию).
    let ours = unsafe { libc::syscall(libc::SYS_getpriority, i64::from(libc::PRIO_PROCESS), 0) };
    if ours == -1 {
        return 1;
    }
    // PRIO_USER (2): arg0 >= 1 → ERRNO(EPERM) из явного правила.
    let foreign = unsafe { libc::syscall(libc::SYS_getpriority, i64::from(libc::PRIO_USER), 0) };
    if foreign != -1 {
        return 2;
    }
    if unsafe { *libc::__errno_location() } != libc::EPERM {
        return 3;
    }

    0
}

/// Ставит обработчик `SIGSYS` и проверяет, что `TRAP` доставляется
/// именно как перехватываемый сигнал, а сисколл продолжается.
fn child_trap_getpid(prog: &[sock_filter], (): ()) -> i32 {
    SIGSYS_SEEN.store(false, Ordering::SeqCst);

    // Обработчик ставим ДО фильтра — тогда `rt_sigaction` можно не
    // разрешать внутри фильтра.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_sigsys as *const () as usize;
        action.sa_flags = 0;
        libc::sigemptyset(&raw mut action.sa_mask);
        libc::sigaction(libc::SIGSYS, &raw const action, std::ptr::null_mut());
    }

    apply_filter(prog);
    unsafe { libc::syscall(libc::SYS_getpid) };

    i32::from(!SIGSYS_SEEN.load(Ordering::SeqCst))
}

// ── Инфраструктура fork/wait ─────────────────────────────────────────

/// Создаёт потомка, прогоняет в нём `child` и возвращает итог.
///
/// `payload` — небольшой `Copy`-параметр, чтобы не захватывать окружение
/// в замыкании (замыкания потребовали бы аллокаций в потомке).
fn run_case<P: Copy>(
    prog: &[sock_filter],
    payload: P,
    child: fn(&[sock_filter], P) -> i32,
) -> Outcome {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork(): {}", std::io::Error::last_os_error());

    if pid == 0 {
        let code = child(prog, payload);
        unsafe { libc::_exit(code) };
    }

    wait_for(pid)
}

/// Дождаться потомка и нормализовать статус.
fn wait_for(pid: libc::pid_t) -> Outcome {
    let mut status: libc::c_int = 0;
    let rc = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert_eq!(rc, pid, "waitpid()");

    if libc::WIFEXITED(status) {
        Outcome::Exited(libc::WEXITSTATUS(status))
    } else {
        assert!(libc::WIFSIGNALED(status), "неожиданный статус {status:#x}");
        Outcome::Signaled(libc::WTERMSIG(status))
    }
}

// ── ALLOW ────────────────────────────────────────────────────────────

#[test]
fn allow_rule_permits_syscall() {
    // default — фатальный kill: если правило не сработает, потомок умрёт.
    let prog = program(
        &[allow(libc::SYS_getpid), allow(libc::SYS_exit_group)],
        libc::SECCOMP_RET_KILL_PROCESS,
    );

    assert_eq!(run_case(&prog, (), child_expect_pid), Outcome::Exited(0));
}

#[test]
fn allow_default_permits_everything() {
    let prog = program(&[], libc::SECCOMP_RET_ALLOW);
    assert_eq!(run_case(&prog, (), child_expect_pid), Outcome::Exited(0));
}

#[test]
fn large_allowlist_is_accepted_by_kernel() {
    // 300 «мёртвых» правил + нужные — это >255 инструкций, то есть за
    // старым 8-битным лимитом перехода. Раньше такой фильтр не собрался
    // бы вовсе; теперь ядро его принимает и он работает.
    let mut rules: Vec<Rule> = (0..300).map(|i| allow(i64::from(i) + 1000)).collect();
    rules.push(allow(libc::SYS_getpid));
    rules.push(allow(libc::SYS_exit_group));

    let prog = program(&rules, libc::SECCOMP_RET_KILL_PROCESS);
    assert!(
        prog.len() > 255,
        "программа должна перевалить за лимит перехода"
    );

    assert_eq!(run_case(&prog, (), child_expect_pid), Outcome::Exited(0));
}

// ── ERRNO ────────────────────────────────────────────────────────────

#[test]
fn default_errno_blocks_unlisted_syscall() {
    // Разрешён только выход, всё остальное (getpid) → ENOSYS.
    let prog = program(&[allow(libc::SYS_exit_group)], errno_ret(libc::ENOSYS));
    assert_eq!(
        run_case(&prog, libc::ENOSYS, child_expect_errno),
        Outcome::Exited(0)
    );
}

#[test]
fn errno_action_reports_configured_code() {
    let prog = program(&[allow(libc::SYS_exit_group)], errno_ret(libc::EPERM));
    assert_eq!(
        run_case(&prog, libc::EPERM, child_expect_errno),
        Outcome::Exited(0)
    );
}

#[test]
fn errno_differs_from_requested() {
    // Отрицательный контроль: на EACCES фильтр не должен отвечать EPERM.
    let prog = program(&[allow(libc::SYS_exit_group)], errno_ret(libc::EPERM));
    assert_eq!(
        run_case(&prog, libc::EACCES, child_expect_errno),
        Outcome::Exited(1)
    );
}

// ── KILL ─────────────────────────────────────────────────────────────

#[test]
fn kill_process_action_terminates_with_sigsys() {
    // Пустой список правил + фатальный default: первый же сисколл убивает.
    let prog = program(&[], libc::SECCOMP_RET_KILL_PROCESS);
    assert_eq!(
        run_case(&prog, (), child_probe_getpid),
        Outcome::Signaled(libc::SIGSYS)
    );
}

#[test]
fn kill_thread_action_terminates_with_sigsys() {
    // В одноthreadном потомке KILL_THREAD и KILL_PROCESS наблюдаются
    // одинаково — проверяем хотя бы сам сигнал.
    let prog = program(&[], ACTION::KillThread.to_ret());
    assert_eq!(
        run_case(&prog, (), child_probe_getpid),
        Outcome::Signaled(libc::SIGSYS)
    );
}

// ── TRAP ─────────────────────────────────────────────────────────────

#[test]
fn trap_action_reaches_sigsys_handler() {
    // Обязательно разрешаем `rt_sigreturn` — иначе возврат из обработчика
    // сигнала сам упрётся в фильтр. `exit_group` — чтобы потомок вышел.
    let prog = program(
        &[allow(libc::SYS_rt_sigreturn), allow(libc::SYS_exit_group)],
        ACTION::Trap.to_ret(),
    );
    assert_eq!(run_case(&prog, (), child_trap_getpid), Outcome::Exited(0));
}

// ── LOG / TRACE / USER_NOTIF ─────────────────────────────────────────

#[test]
fn log_action_allows_syscall() {
    let prog = program(&[allow(libc::SYS_exit_group)], ACTION::Log.to_ret());
    assert_eq!(run_case(&prog, (), child_expect_pid), Outcome::Exited(0));
}

#[test]
fn trace_action_without_tracer_returns_enosys() {
    // Трейсера нет, поэтому RET_TRACE вырождается в ошибку для сисколла.
    let prog = program(&[allow(libc::SYS_exit_group)], ACTION::Trace.to_ret());
    assert_eq!(
        run_case(&prog, libc::ENOSYS, child_expect_errno),
        Outcome::Exited(0)
    );
}

#[test]
fn user_notif_without_listener_returns_enosys() {
    // Слушателя нет — RET_USER_NOTIF тоже возвращает ошибку сисколла.
    let prog = program(&[allow(libc::SYS_exit_group)], ACTION::UserNotif.to_ret());
    assert_eq!(
        run_case(&prog, libc::ENOSYS, child_expect_errno),
        Outcome::Exited(0)
    );
}

// ── Проверки аргументов ──────────────────────────────────────────────

#[test]
fn arg_eq_allows_only_readonly_open() {
    // open(path, args=0) разрешён; open с O_WRONLY уходит в default EPERM.
    // Заодно проверяет слово arg1 (откуда младшая половина по 24).
    let prog = program(
        &[
            allow(libc::SYS_exit_group),
            Rule::new(libc::SYS_open, libc::SECCOMP_RET_ALLOW).check(1, Cmp::Eq(0)),
        ],
        errno_ret(libc::EPERM),
    );
    assert_eq!(
        run_case(&prog, libc::O_WRONLY, child_open_flags),
        Outcome::Exited(0)
    );
}

#[test]
fn arg_masked_eq_ignores_noise_flags() {
    // MaskedEq: (flags & O_ACCMODE) == O_RDONLY. Ядро принимает фильтр с
    // BPF_ALU|BPF_AND|BPF_K, маска отсекает «шумные» флаги.
    let prog = program(
        &[
            allow(libc::SYS_exit_group),
            Rule::new(libc::SYS_open, libc::SECCOMP_RET_ALLOW).check(
                1,
                Cmp::MaskedEq {
                    mask: flag(libc::O_ACCMODE),
                    val: 0,
                },
            ),
        ],
        errno_ret(libc::EPERM),
    );
    // O_RDWR != O_RDONLY по акцесс-моду → default.
    assert_eq!(
        run_case(&prog, libc::O_RDWR, child_open_flags),
        Outcome::Exited(0)
    );
}

#[test]
fn arg_lt_and_ge_split_getpriority() {
    // arg0 = 0 (PRIO_PROCESS) — правило Lt(1) пускает; arg0 = 2 (PRIO_USER)
    // — явное правило Ge(1) отвечает EPERM (default тут ENOSYS, чтобы
    // отличить сработавшее правило от промаха мимо всех).
    let prog = program(
        &[
            allow(libc::SYS_exit_group),
            Rule::new(libc::SYS_getpriority, libc::SECCOMP_RET_ALLOW).check(0, Cmp::Lt(1)),
            Rule::new(libc::SYS_getpriority, errno_ret(libc::EPERM)).check(0, Cmp::Ge(1)),
        ],
        errno_ret(libc::ENOSYS),
    );
    assert_eq!(
        run_case(&prog, (), child_getpriority_range),
        Outcome::Exited(0)
    );
}

#[test]
fn arg_ne_rule_passes_matching_args() {
    // arg0 = 0: Ne(1) истинно → ALLOW, default — фатальный kill.
    let prog = program(
        &[
            allow(libc::SYS_exit_group),
            Rule::new(libc::SYS_getpgid, libc::SECCOMP_RET_ALLOW).check(0, Cmp::Ne(1)),
        ],
        libc::SECCOMP_RET_KILL_PROCESS,
    );
    assert_eq!(run_case(&prog, (), child_expect_pgid), Outcome::Exited(0));
}

#[test]
fn arg_ne_rule_falls_to_default_on_exact_value() {
    // arg0 = 0: Ne(0) ложно → правило не совпало → default EPERM.
    let prog = program(
        &[
            allow(libc::SYS_exit_group),
            Rule::new(libc::SYS_getpgid, libc::SECCOMP_RET_ALLOW).check(0, Cmp::Ne(0)),
        ],
        errno_ret(libc::EPERM),
    );
    assert_eq!(
        run_case(&prog, libc::EPERM, child_expect_pgid_errno),
        Outcome::Exited(0)
    );
}
