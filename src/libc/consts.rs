//! Константы, которых в крейте `libc` для этой платформы нет вообще —
//! опкоды BPF, `SECCOMP_RET`_*, `SECCOMP_SET_MODE_FILTER` и т.д. берём
//! напрямую из `libc`, здесь остаётся только то, что он не экспортирует.
pub const SECCOMP_DATA_NR_OFFSET: u32 = 0;
pub const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
/// Смещение младшего слова `seccomp_data.args[0]` (само поле `args` —
/// массив из шести `u64`, идёт после `nr`, `arch` и `instruction_pointer`).
pub const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;
/// Сколько аргументов ядро отдаёт сисколлу в `seccomp_data` — ровно 6.
pub const SECCOMP_DATA_ARG_COUNT: u32 = 6;
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;
