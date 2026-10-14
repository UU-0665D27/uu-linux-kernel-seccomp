//! Константы BPF-опкодов и seccomp, которых нет (или нет под нужным
//! именем) в крейте `libc` для данной платформы.

// ---- классы инструкций / режимы (linux/bpf_common.h) ----
pub const BPF_LD: u16 = 0x00;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;

pub const BPF_W: u16 = 0x00; // 32-битное слово
pub const BPF_ABS: u16 = 0x20; // абсолютное смещение во входных данных

pub const BPF_JEQ: u16 = 0x10; // ==
pub const BPF_JGE: u16 = 0x30; // >=
pub const BPF_K: u16 = 0x00; // операнд — константа k

// ---- seccomp_data (linux/seccomp.h): смещения полей ----
pub const SECCOMP_DATA_NR_OFFSET: u32 = 0;
pub const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

// ---- AUDIT_ARCH_* (linux/audit.h) ----
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

// ---- SECCOMP_RET_* (linux/seccomp.h) ----
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_DATA_MASK: u32 = 0x0000_ffff;

// ---- seccomp(2): operation / flags ----
pub const SECCOMP_SET_MODE_FILTER: u32 = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;

// x86_64: ядро не фильтрует 32-битный (x86) ABI отдельной веткой —
// в seccomp_data.nr при вызове через int 0x80/x32 приходит номер
// с установленным битом __X32_SYSCALL_BIT (0x4000_0000). Отсекаем
// такие вызовы отдельной проверкой, как это делает libseccomp.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;
