use crate::libc::bpf::{self, BuildError, Rule};
use crate::libc::resolve_name;
use libc::{
    SECCOMP_RET_ALLOW, SECCOMP_RET_DATA, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
    SECCOMP_RET_KILL_THREAD, SECCOMP_RET_LOG, SECCOMP_RET_TRACE, SECCOMP_RET_TRAP,
    SECCOMP_RET_USER_NOTIF, c_long, c_uint, sock_filter,
};
use std::fmt;

// Реэкспорт примитивов проверок аргументов: на высоком уровне руками
// `Cmp::Eq(...)` пригождается постоянно, пусть лежит здесь же.
pub use crate::libc::bpf::{ArgCmp, Cmp};

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
    Some(Rule::new(nr, action.to_ret()))
}

/// Собрать правило по имени сисколла.
#[must_use]
pub fn rule_name(action: &ACTION, name: &str) -> Option<Rule> {
    rule_nr(action, resolve_name(name))
}

// ── Высокоуровневые политики ─────────────────────────────────────────

/// Ошибка конструирования политики [`Policy`].
#[derive(Debug)]
pub enum PolicyError {
    /// Имя системного вызова не найдено в таблице.
    UnknownSyscall(String),
    /// Не удалось собрать BPF-программу.
    Build(BuildError),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSyscall(name) => write!(f, "неизвестный системный вызов: {name}"),
            Self::Build(err) => write!(f, "ошибка сборки BPF-программы: {err}"),
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Build(err) => Some(err),
            Self::UnknownSyscall(_) => None,
        }
    }
}

impl From<BuildError> for PolicyError {
    fn from(err: BuildError) -> Self {
        Self::Build(err)
    }
}

/// Разрешить имя сисколла или вернуть [`PolicyError::UnknownSyscall`].
fn resolve(name: &str) -> Result<c_long, PolicyError> {
    match resolve_name(name) {
        -1 => Err(PolicyError::UnknownSyscall(name.to_owned())),
        nr => Ok(nr),
    }
}

/// Высокоуровневая политика seccomp.
///
/// Позволяет описывать фильтр именами сисколлов, а не номерами. Две модели:
///
/// * **allow-list** — [`Policy::allowlist`]: перечисляем разрешённое,
///   всё остальное получает `default`;
/// * **deny-list** — [`Policy::denylist`]: по умолчанию разрешено всё,
///   блокируем только явно указанное.
///
/// Правила проверяются в порядке добавления, побеждает первое совпадение.
/// Поэтому для deny-list `default` обязан быть `ALLOW`, а частные
/// блокировки стоит добавлять раньше общих.
///
/// Правило можно ограничить проверкой аргументов сисколла —
/// [`Policy::allow_args`] / [`Policy::deny_args`] (либо сырые
/// `allow_nr_args` / `deny_nr_args`). Набор операций — [`Cmp`].
///
/// # Пример
///
/// ```rust
/// use uu_linux_kernel_seccomp::rust::{ACTION, ArgCmp, Cmp, Policy};
///
/// // Разрешить только чтение/запись/выход, всё прочее — kill.
/// let prog = Policy::allowlist(ACTION::KillProcess)
///     .allow("read").unwrap()
///     .allow("write").unwrap()
///     .allow("exit_group").unwrap()
///     .compile().unwrap();
///
/// assert!(!prog.is_empty());
///
/// // Всё разрешено, кроме execve и ptrace.
/// let prog = Policy::denylist()
///     .deny("execve", ACTION::Errno(1)).unwrap()
///     .deny("ptrace", ACTION::KillProcess).unwrap()
///     .compile().unwrap();
///
/// assert!(!prog.is_empty());
///
/// // `mkdir` разрешаем только с правами 0o755: всем прочим режимам —
/// // EPERM, через проверку аргумента 1 (mode).
/// let prog = Policy::denylist()
///     .deny_args(
///         "mkdir",
///         &[ArgCmp { arg: 1, op: Cmp::Ne(0o755) }],
///         ACTION::Errno(1),
///     )
///     .unwrap()
///     .compile().unwrap();
///
/// assert!(!prog.is_empty());
/// ```
#[derive(Debug)]
pub struct Policy {
    default: ACTION,
    rules: Vec<Rule>,
}

impl Policy {
    /// Allow-list: разрешено только явно добавленное, остальное — `default`.
    ///
    /// Обычно в роли `default` выступает `ACTION::Errno(EPERM)` или
    /// `ACTION::KillProcess`.
    #[must_use]
    pub const fn allowlist(default: ACTION) -> Self {
        Self {
            default,
            rules: Vec::new(),
        }
    }

    /// Deny-list: по умолчанию разрешено всё, блокируем явно добавленное.
    #[must_use]
    pub const fn denylist() -> Self {
        Self {
            default: ACTION::Allow,
            rules: Vec::new(),
        }
    }

    /// Переопределить действие по умолчанию.
    #[must_use]
    pub const fn default_action(mut self, default: ACTION) -> Self {
        self.default = default;
        self
    }

    /// Разрешить системный вызов по имени (действие `ALLOW`).
    ///
    /// # Errors
    /// [`PolicyError::UnknownSyscall`] — если имя не найдено.
    pub fn allow(mut self, name: &str) -> Result<Self, PolicyError> {
        self.rules
            .push(Rule::new(resolve(name)?, ACTION::Allow.to_ret()));
        Ok(self)
    }

    /// Запретить системный вызов по имени, вернув указанное `action`.
    ///
    /// # Errors
    /// [`PolicyError::UnknownSyscall`] — если имя не найдено.
    pub fn deny(mut self, name: &str, action: ACTION) -> Result<Self, PolicyError> {
        self.rules.push(Rule::new(resolve(name)?, action.to_ret()));
        Ok(self)
    }

    /// Разрешить системный вызов по «сырому» номеру.
    #[must_use]
    pub fn allow_nr(mut self, nr: c_long) -> Self {
        self.rules.push(Rule::new(nr, ACTION::Allow.to_ret()));
        self
    }

    /// Запретить системный вызов по «сырому» номеру.
    #[must_use]
    pub fn deny_nr(mut self, nr: c_long, action: ACTION) -> Self {
        self.rules.push(Rule::new(nr, action.to_ret()));
        self
    }

    /// Разрешить сисколл по имени только при истинности проверок аргументов.
    ///
    /// Проверки (`ArgCmp`) объединяются через «И». Если сисколл вызван
    /// с другими аргументами, сработает `default` политики.
    ///
    /// # Errors
    /// [`PolicyError::UnknownSyscall`] — если имя не найдено.
    pub fn allow_args(mut self, name: &str, checks: &[ArgCmp]) -> Result<Self, PolicyError> {
        let mut rule = Rule::new(resolve(name)?, ACTION::Allow.to_ret());
        rule.args.extend_from_slice(checks);
        self.rules.push(rule);
        Ok(self)
    }

    /// Запретить сисколл по имени с указанным `action`, когда выполнены
    /// проверки аргументов.
    ///
    /// # Errors
    /// [`PolicyError::UnknownSyscall`] — если имя не найдено.
    pub fn deny_args(
        mut self,
        name: &str,
        checks: &[ArgCmp],
        action: ACTION,
    ) -> Result<Self, PolicyError> {
        let mut rule = Rule::new(resolve(name)?, action.to_ret());
        rule.args.extend_from_slice(checks);
        self.rules.push(rule);
        Ok(self)
    }

    /// Разрешить сисколл по «сырому» номеру только при истинности
    /// проверок аргументов.
    #[must_use]
    pub fn allow_nr_args(mut self, nr: c_long, checks: &[ArgCmp]) -> Self {
        let mut rule = Rule::new(nr, ACTION::Allow.to_ret());
        rule.args.extend_from_slice(checks);
        self.rules.push(rule);
        self
    }

    /// Запретить сисколл по «сырому» номеру с указанным `action`, когда
    /// выполнены проверки аргументов.
    #[must_use]
    pub fn deny_nr_args(mut self, nr: c_long, checks: &[ArgCmp], action: ACTION) -> Self {
        let mut rule = Rule::new(nr, action.to_ret());
        rule.args.extend_from_slice(checks);
        self.rules.push(rule);
        self
    }

    /// Скомпилировать политику в BPF-программу.
    ///
    /// # Errors
    /// [`PolicyError::Build`] — если правила не помещаются в лимиты BPF
    /// (см. `BuildError`).
    pub fn compile(&self) -> Result<Vec<sock_filter>, PolicyError> {
        Ok(bpf::build_program(&self.rules, self.default.to_ret())?)
    }
}
