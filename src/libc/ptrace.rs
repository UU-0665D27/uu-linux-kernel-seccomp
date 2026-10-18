//! Чтение seccomp-фильтров живого процесса через ptrace.
//!
//! Ядро экспортирует ровно один способ заглянуть в чужой seccomp —
//! `PTRACE_SECCOMP_GET_FILTER` (0x4204, Linux 4.4+). Открывается только
//! с действительным `CAP_SYS_ADMIN`: через него можно вытащить «сырые»
//! инструкции BPF-программы, иначе они недоступны.
//!
//! Протокол:
//! 1. `PTRACE_ATTACH` на pid → tracee получает `SIGSTOP` и заходит в ptrace-stop.
//! 2. `waitpid` — дождаться останова.
//! 3. Для `idx = 0, 1, 2, …`:
//!      - первый вызов без буфера → длина фильтра (число инструкций);
//!      - `ENOENT` — фильтров больше нет (idx перешёл границу);
//!      - второй вызов с буфером → сами инструкции.
//! 4. `PTRACE_DETACH` — процесс продолжает жить.
//!
//! Замечание: `PTRACE_ATTACH` на произвольный чужой процесс обычно
//! запрещён (Yama `ptrace_scope`, `CAP_SYS_PTRACE`, uid). Надёжно всегда
//! работает attach к прямому потомку — так и тестам, и примеру `dump -p`
//! проще показать результат.

use libc::{
    PTRACE_ATTACH, PTRACE_DETACH, SIGKILL, WUNTRACED, c_int, c_long, c_uint, pid_t, sock_filter,
};
use std::io::{self, Error};

// ── Константы ядра, которых нет в libc ───────────────────────────────

/// `PTRACE_SECCOMP_GET_FILTER` (Linux ≥ 4.4).
pub const PTRACE_SECCOMP_GET_FILTER: c_uint = 0x4204;

// ── Основной буфер обработки чужого фильтра ──────────────────────────

/// Читает фильтры `pid`, отпускает процесс после чтения.
///
/// `pid` должен быть нашим потомком либо мы должны иметь `CAP_SYS_PTRACE`
/// (в противном случае `PTRACE_ATTACH` вернёт `EPERM`).
///
/// # Errors
/// Возвращает `io::Error` c `errno` ядра напрямую (см. `waitpid`, `ptrace`):
/// * `EACCES` — нет `CAP_SYS_ADMIN` (его требует `seccomp_get_filter`);
/// * `EPERM` — Yama/права не позволяют `PTRACE_ATTACH`;
/// * `ESRCH` — процесс не найден или уже завершён;
/// * прочие ошибки ядра.
pub fn seccomp_filters(pid: pid_t) -> io::Result<Vec<Vec<sock_filter>>> {
    attach(pid)?;
    let read = read_filters(pid);
    if let Err(read) = read {
        detach(pid)?;
        return Err(read);
    }
    detach(pid)?;
    read
}

/// Читает фильтры tracee, к которому мы уже подключены как трассировщик.
///
/// Не делает `PTRACE_ATTACH`/`PTRACE_DETACH`: подходит для случая
/// `PTRACE_TRACEME` + `exec`, где родитель становится трассировщиком сам
/// (единственный путь в системах с Yama `ptrace_scope=1`).
///
/// # Errors
/// То же, что у [`seccomp_filters`], кроме ошибок attach/detach.
pub fn filters_of_tracee(pid: pid_t) -> io::Result<Vec<Vec<sock_filter>>> {
    read_filters(pid)
}

/// Читает фильтр, пока ядро продолжает их отдавать.
///
/// Ошибка `ENOENT` означает «это всё», её как ошибку не возвращаем.
fn read_filters(pid: pid_t) -> io::Result<Vec<Vec<sock_filter>>> {
    let mut out = Vec::new();
    for idx in 0..c_long::MAX {
        let Ok(len) = filter_len(pid, idx) else {
            break; // ENOENT или столько же
        };
        if len == 0 {
            break;
        }
        let len = usize::try_from(len).map_err(|_| io::Error::other("нелепая длина"))?;
        out.push(filter_body(pid, idx, len)?);
    }
    Ok(out)
}

/// Дозирует отдельный элемент из seq… ну, «n-й фильтр».
///
/// Возвращает только длину, `None` уже не различаем.
fn filter_len(pid: pid_t, idx: c_long) -> io::Result<c_long> {
    unsafe {
        let ret = libc::ptrace(
            PTRACE_SECCOMP_GET_FILTER,
            c_long::from(pid),
            idx,
            std::ptr::null_mut::<c_int>(),
        );
        if ret >= 0 {
            Ok(ret)
        } else {
            Err(Error::last_os_error())
        }
    }
}

/// Читает содержимое `idx`-го фильтра заданной длины.
fn filter_body(pid: pid_t, idx: c_long, len: usize) -> io::Result<Vec<sock_filter>> {
    let mut out: Vec<sock_filter> = Vec::with_capacity(len);
    unsafe {
        let ret = libc::ptrace(
            PTRACE_SECCOMP_GET_FILTER,
            c_long::from(pid),
            idx,
            out.as_mut_ptr().cast::<c_int>(),
        );
        if ret < 0 {
            return Err(Error::last_os_error());
        }
        // Смотрим содержимое. `ret` должно совпасть с `len`, иначе это уже не API.
        if usize::try_from(ret).map_err(|_e| io::Error::from(io::ErrorKind::InvalidData))? != len {
            return Err(io::Error::other("нестабильная длина фильтра"));
        }
        out.set_len(len);
    }
    Ok(out)
}

/// Присоединяемся к tracee и ждём его ptrace-stop.
fn attach(pid: pid_t) -> io::Result<()> {
    unsafe {
        if libc::ptrace(PTRACE_ATTACH, c_long::from(pid), 0, 0) < 0 {
            return Err(Error::last_os_error());
        }

        // Ждём останова (SIGSTOP, подсунутый PTRACE_ATTACH).
        let mut status: c_int = 0;
        let waited = libc::waitpid(pid, &raw mut status, WUNTRACED);
        if waited < 0 {
            return Err(Error::last_os_error());
        }
        if !libc::WIFSTOPPED(status) {
            return Err(io::Error::other("tracee не остановился"));
        }
    }
    Ok(())
}

/// Отпускаем tracee, продолжаем его.
fn detach(pid: pid_t) -> io::Result<()> {
    unsafe {
        if libc::ptrace(PTRACE_DETACH, c_long::from(pid), 0, 0) < 0 {
            return Err(Error::last_os_error());
        }
    }
    Ok(())
}

/// Умертвить (и дождаться) потомка, если тест помер раньше времени.
pub fn kill_and_reap(pid: pid_t) {
    unsafe {
        if libc::kill(pid, SIGKILL) == 0 {
            let mut status: c_int = 0;
            let _ = libc::waitpid(pid, &raw mut status, 0);
        }
    }
}

/// Берём `CAP_SYS_ADMIN` (бит 21) — без него ядро отдаст `EACCES`.
const CAP_SYS_ADMIN_BIT: u64 = 0x0020_0000;

// Кто-то считывает CapEff в /proc/self/status; проверим там.
fn cap_effective() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:\t") {
            return u64::from_str_radix(rest.trim(), 16).ok();
        }
    }
    None
}

/// Можно ли нам (в текущем процессе) подтянуть чужие seccomp-фильтры.
///
/// В основном совпадает с «есть ли `CAP_SYS_ADMIN`»; если `/proc` нечитаем,
/// консервативно считаем нет.
#[must_use]
pub fn readable_by_us() -> bool {
    cap_effective().is_some_and(|caps| (caps & CAP_SYS_ADMIN_BIT) != 0)
}
