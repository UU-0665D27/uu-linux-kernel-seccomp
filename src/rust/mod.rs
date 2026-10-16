use crate::libc::{bpf::Rule, resolve_name};
use libc::{
    SECCOMP_RET_ALLOW, SECCOMP_RET_DATA, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
    SECCOMP_RET_KILL_THREAD, SECCOMP_RET_LOG, SECCOMP_RET_TRACE, SECCOMP_RET_TRAP,
    SECCOMP_RET_USER_NOTIF, c_long, c_uint,
};

/// Действие фильтра seccomp.
///
/// Соответствует `SCMP_ACT_*` из libseccomp, но выражено как Rust-enum:
/// для `ERRNO` data (16 бит) лежит прямо в варианте, а не в отдельном
/// поле структуры.
///
/// Исторический `SCMP_ACT_KILL` == `SCMP_ACT_KILL_THREAD`; «DENY» в
/// современных реалиях — это `KILL_PROCESS` (убивает весь процесс, а
/// не только тред). Отдельного варианта `DENY` нет намеренно — пусть
/// вызывающий выбирает явно.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ACTION {
    /// `SECCOMP_RET_KILL_PROCESS` (0x80000000) — убить весь процесс.
    KillProcess,
    /// `SECCOMP_RET_KILL_THREAD` (0x00000000) == `SECCOMP_RET_KILL`.
    KillThread,
    /// `SECCOMP_RET_TRAP` (0x00030000) — SIGSYS в поток.
    Trap,
    /// `SECCOMP_RET_ERRNO | (errno & SECCOMP_RET_DATA)` (0x00050000).
    ///
    /// `errno` — значение из `<errno.h>` (EPERM, EACCES, …). Младшие
    /// 16 бит; всё, что выше, будет замаскировано при сборке.
    Errno(u16),
    /// `SECCOMP_RET_USER_NOTIF` (0x7fc00000) — отдать решение
    /// userspace-супервизору через `SECCOMP_IOCTL_NOTIF_*`.
    UserNotif,
    /// `SECCOMP_RET_TRACE` (0x7ff00000) — уведомить ptracer.
    Trace,
    /// `SECCOMP_RET_LOG` (0x7ffc0000) — залогировать и разрешить.
    Log,
    /// `SECCOMP_RET_ALLOW` (0x7fff0000) — пропустить.
    Allow,
}

impl ACTION {
    /// Собрать 32-битное `seccomp_data.ret`-значение для BPF-программы.
    ///
    /// Для `ERRNO(e)` выполняет `SECCOMP_RET_ERRNO | (e as u32 & SECCOMP_RET_DATA)`.
    /// Для остальных — просто константа действия.
    #[must_use]
    pub const fn to_ret(self) -> c_uint {
        match self {
            Self::KillProcess => SECCOMP_RET_KILL_PROCESS,
            Self::KillThread => SECCOMP_RET_KILL_THREAD,
            Self::Trap => SECCOMP_RET_TRAP,
            Self::Errno(e) => SECCOMP_RET_ERRNO | (e as c_uint & SECCOMP_RET_DATA),
            Self::UserNotif => SECCOMP_RET_USER_NOTIF,
            Self::Trace => SECCOMP_RET_TRACE,
            Self::Log => SECCOMP_RET_LOG,
            Self::Allow => SECCOMP_RET_ALLOW,
        }
    }

    /// Обратное разложение: вытащить действие из готового `ret`.
    ///
    /// Маскирует `SECCOMP_RET_ACTION_FULL` (0xffff0000) сверху и
    /// `SECCOMP_RET_DATA` (0x0000ffff) для `ERRNO`. Если action
    /// неизвестен — `None`.
    #[must_use]
    pub const fn from_ret(ret: c_uint) -> Option<Self> {
        let action = ret & 0xffff_0000;
        let data = (ret & SECCOMP_RET_DATA) as u16;

        match action {
            SECCOMP_RET_KILL_PROCESS => Some(Self::KillProcess),
            SECCOMP_RET_KILL_THREAD => Some(Self::KillThread),
            SECCOMP_RET_TRAP => Some(Self::Trap),
            SECCOMP_RET_ERRNO => Some(Self::Errno(data)),
            SECCOMP_RET_USER_NOTIF => Some(Self::UserNotif),
            SECCOMP_RET_TRACE => Some(Self::Trace),
            SECCOMP_RET_LOG => Some(Self::Log),
            SECCOMP_RET_ALLOW => Some(Self::Allow),
            _ => None,
        }
    }
}

// ── Совместимость со старым API ──────────────────────────────────────

/// Устаревший аксессор. Оставлен для совместимости; внутри просто
/// делегирует в [`ACTION::to_ret`].
#[must_use]
pub const fn action_name(action: &ACTION) -> c_uint {
    action.to_ret()
}

/// Собрать правило по номеру сисколла.
///
/// Возвращает `None`, если `nr == __NR_SCMP_ERROR` (-1) — это значит,
/// что вызывающий передал неразрешённое имя (см. [`resolve_name`]).
#[must_use]
pub const fn rule_nr(action: &ACTION, nr: c_long) -> Option<Rule> {
    if nr == -1 {
        return None; // __NR_SCMP_ERROR
    }
    Some(Rule {
        nr,
        action: action.to_ret(),
    })
}

/// Собрать правило по имени сисколла.
#[must_use]
pub fn rule_name(action: &ACTION, name: &str) -> Option<Rule> {
    rule_nr(action, resolve_name(name))
}
