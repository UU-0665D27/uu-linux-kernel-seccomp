pub mod bpf;
pub mod consts;
pub mod dump;
pub mod ptrace;

use libc::{
    SYS__sysctl, SYS_accept, SYS_accept4, SYS_access, SYS_acct, SYS_add_key, SYS_adjtimex,
    SYS_afs_syscall, SYS_alarm, SYS_arch_prctl, SYS_bind, SYS_bpf, SYS_brk, SYS_capget, SYS_capset,
    SYS_chdir, SYS_chmod, SYS_chown, SYS_chroot, SYS_clock_adjtime, SYS_clock_getres,
    SYS_clock_gettime, SYS_clock_nanosleep, SYS_clock_settime, SYS_clone, SYS_clone3, SYS_close,
    SYS_close_range, SYS_connect, SYS_copy_file_range, SYS_creat, SYS_delete_module, SYS_dup,
    SYS_dup2, SYS_dup3, SYS_epoll_create, SYS_epoll_create1, SYS_epoll_ctl, SYS_epoll_ctl_old,
    SYS_epoll_pwait, SYS_epoll_pwait2, SYS_epoll_wait, SYS_epoll_wait_old, SYS_eventfd,
    SYS_eventfd2, SYS_execve, SYS_execveat, SYS_exit, SYS_exit_group, SYS_faccessat,
    SYS_faccessat2, SYS_fadvise64, SYS_fallocate, SYS_fanotify_init, SYS_fanotify_mark, SYS_fchdir,
    SYS_fchmod, SYS_fchmodat, SYS_fchmodat2, SYS_fchown, SYS_fchownat, SYS_fcntl, SYS_fdatasync,
    SYS_fgetxattr, SYS_finit_module, SYS_flistxattr, SYS_flock, SYS_fork, SYS_fremovexattr,
    SYS_fsconfig, SYS_fsetxattr, SYS_fsmount, SYS_fsopen, SYS_fspick, SYS_fstat, SYS_fstatfs,
    SYS_fsync, SYS_ftruncate, SYS_futex, SYS_futex_waitv, SYS_futimesat, SYS_get_mempolicy,
    SYS_get_robust_list, SYS_get_thread_area, SYS_getcpu, SYS_getcwd, SYS_getdents, SYS_getdents64,
    SYS_getegid, SYS_geteuid, SYS_getgid, SYS_getgroups, SYS_getitimer, SYS_getpeername,
    SYS_getpgid, SYS_getpgrp, SYS_getpid, SYS_getpmsg, SYS_getppid, SYS_getpriority, SYS_getrandom,
    SYS_getresgid, SYS_getresuid, SYS_getrlimit, SYS_getrusage, SYS_getsid, SYS_getsockname,
    SYS_getsockopt, SYS_gettid, SYS_gettimeofday, SYS_getuid, SYS_getxattr, SYS_init_module,
    SYS_inotify_add_watch, SYS_inotify_init, SYS_inotify_init1, SYS_inotify_rm_watch,
    SYS_io_cancel, SYS_io_destroy, SYS_io_getevents, SYS_io_setup, SYS_io_submit,
    SYS_io_uring_enter, SYS_io_uring_register, SYS_io_uring_setup, SYS_ioctl, SYS_ioperm, SYS_iopl,
    SYS_ioprio_get, SYS_ioprio_set, SYS_kcmp, SYS_kexec_file_load, SYS_kexec_load, SYS_keyctl,
    SYS_kill, SYS_landlock_add_rule, SYS_landlock_create_ruleset, SYS_landlock_restrict_self,
    SYS_lchown, SYS_lgetxattr, SYS_link, SYS_linkat, SYS_listen, SYS_listxattr, SYS_llistxattr,
    SYS_lookup_dcookie, SYS_lremovexattr, SYS_lseek, SYS_lsetxattr, SYS_lstat, SYS_madvise,
    SYS_mbind, SYS_membarrier, SYS_memfd_create, SYS_memfd_secret, SYS_migrate_pages, SYS_mincore,
    SYS_mkdir, SYS_mkdirat, SYS_mknod, SYS_mknodat, SYS_mlock, SYS_mlock2, SYS_mlockall, SYS_mmap,
    SYS_modify_ldt, SYS_mount, SYS_mount_setattr, SYS_move_mount, SYS_move_pages, SYS_mprotect,
    SYS_mq_getsetattr, SYS_mq_notify, SYS_mq_open, SYS_mq_timedreceive, SYS_mq_timedsend,
    SYS_mq_unlink, SYS_mremap, SYS_mseal, SYS_msgctl, SYS_msgget, SYS_msgrcv, SYS_msgsnd,
    SYS_msync, SYS_munlock, SYS_munlockall, SYS_munmap, SYS_name_to_handle_at, SYS_nanosleep,
    SYS_newfstatat, SYS_nfsservctl, SYS_open, SYS_open_by_handle_at, SYS_open_tree, SYS_openat,
    SYS_openat2, SYS_pause, SYS_perf_event_open, SYS_personality, SYS_pidfd_getfd, SYS_pidfd_open,
    SYS_pidfd_send_signal, SYS_pipe, SYS_pipe2, SYS_pivot_root, SYS_pkey_alloc, SYS_pkey_free,
    SYS_pkey_mprotect, SYS_poll, SYS_ppoll, SYS_prctl, SYS_pread64, SYS_preadv, SYS_preadv2,
    SYS_prlimit64, SYS_process_madvise, SYS_process_mrelease, SYS_process_vm_readv,
    SYS_process_vm_writev, SYS_pselect6, SYS_ptrace, SYS_putpmsg, SYS_pwrite64, SYS_pwritev,
    SYS_pwritev2, SYS_quotactl, SYS_quotactl_fd, SYS_read, SYS_readahead, SYS_readlink,
    SYS_readlinkat, SYS_readv, SYS_reboot, SYS_recvfrom, SYS_recvmmsg, SYS_recvmsg,
    SYS_remap_file_pages, SYS_removexattr, SYS_rename, SYS_renameat, SYS_renameat2,
    SYS_request_key, SYS_restart_syscall, SYS_rmdir, SYS_rseq, SYS_rt_sigaction, SYS_rt_sigpending,
    SYS_rt_sigprocmask, SYS_rt_sigqueueinfo, SYS_rt_sigreturn, SYS_rt_sigsuspend,
    SYS_rt_sigtimedwait, SYS_rt_tgsigqueueinfo, SYS_sched_get_priority_max,
    SYS_sched_get_priority_min, SYS_sched_getaffinity, SYS_sched_getattr, SYS_sched_getparam,
    SYS_sched_getscheduler, SYS_sched_rr_get_interval, SYS_sched_setaffinity, SYS_sched_setattr,
    SYS_sched_setparam, SYS_sched_setscheduler, SYS_sched_yield, SYS_seccomp, SYS_security,
    SYS_select, SYS_semctl, SYS_semget, SYS_semop, SYS_semtimedop, SYS_sendfile, SYS_sendmmsg,
    SYS_sendmsg, SYS_sendto, SYS_set_mempolicy, SYS_set_mempolicy_home_node, SYS_set_robust_list,
    SYS_set_thread_area, SYS_set_tid_address, SYS_setdomainname, SYS_setfsgid, SYS_setfsuid,
    SYS_setgid, SYS_setgroups, SYS_sethostname, SYS_setitimer, SYS_setns, SYS_setpgid,
    SYS_setpriority, SYS_setregid, SYS_setresgid, SYS_setresuid, SYS_setreuid, SYS_setrlimit,
    SYS_setsid, SYS_setsockopt, SYS_settimeofday, SYS_setuid, SYS_setxattr, SYS_shmat, SYS_shmctl,
    SYS_shmdt, SYS_shmget, SYS_shutdown, SYS_sigaltstack, SYS_signalfd, SYS_signalfd4, SYS_socket,
    SYS_socketpair, SYS_splice, SYS_stat, SYS_statfs, SYS_statx, SYS_swapoff, SYS_swapon,
    SYS_symlink, SYS_symlinkat, SYS_sync, SYS_sync_file_range, SYS_syncfs, SYS_sysfs, SYS_sysinfo,
    SYS_syslog, SYS_tee, SYS_tgkill, SYS_time, SYS_timer_create, SYS_timer_delete,
    SYS_timer_getoverrun, SYS_timer_gettime, SYS_timer_settime, SYS_timerfd_create,
    SYS_timerfd_gettime, SYS_timerfd_settime, SYS_times, SYS_tkill, SYS_truncate, SYS_tuxcall,
    SYS_umask, SYS_umount2, SYS_uname, SYS_unlink, SYS_unlinkat, SYS_unshare, SYS_uselib,
    SYS_userfaultfd, SYS_ustat, SYS_utime, SYS_utimensat, SYS_utimes, SYS_vfork, SYS_vhangup,
    SYS_vmsplice, SYS_vserver, SYS_wait4, SYS_waitid, SYS_write, SYS_writev, c_long,
};

/// Резолвер имени системного вызова в его номер — чистый Rust-эквивалент
/// libseccomp-овской `seccomp_syscall_resolve_name`.
///
/// # Что делает
///
/// Принимает имя сисколла (`"read"`, `"openat"`, `"execve"`, …) и возвращает
/// его номер для **нативной** архитектуры (`SCMP_ARCH_NATIVE`, на x86_64 это
/// `0xc000003e`) — ровно то, что вернула бы C-функция из `libseccomp.so`.
///
/// # Оригинальный C-стек вызовов
///
/// Ниже — полный путь, который проходит вызов в libseccomp 2.5.x на x86_64.
/// Каждый уровень раскрыт: смещения полей `struct arch_def`, точки ветвления
/// и адреса из `.text` соответствуют сборке из Arch Linux (`libseccomp.so.2`).
///
/// ```text
/// seccomp_syscall_resolve_name(name)
///   └─ seccomp_syscall_resolve_name_arch(0, name)       ; 0 = SCMP_ARCH_NATIVE
///        └─ arch_def_lookup(0xc000003e) → &arch_def_native
///             ├─ arch->rewrite == NULL  (x86_64)
///             └─ arch->resolve_name(name)
///                  └─ syscall_resolve_name(name)         ; .text @ 0xdbe0
///                       ├─ strlen(name)
///                       ├─ gperf_lookup(name, len)       ; .text @ 0x5400
///                       │    ├─ hash по длине + байтам (gperf perfect hash)
///                       │    └─ strcmp для верификации кандидата
///                       └─ return entry->num (или -1)
/// ```
///
/// Разбор по уровням:
///
/// * **`seccomp_syscall_resolve_name`** (`.text @ 0xf780`, 15 байт) —
///   хвостовая обёртка. `xor edi,edi` выставляет arch-токен в 0
///   (`SCMP_ARCH_NATIVE`), имя переезжает из `rdi` в `rsi`, и управление
///   уходит через `jmp qword [reloc.seccomp_syscall_resolve_name_arch]`.
///
/// * **`seccomp_syscall_resolve_name_arch`** (`.text @ 0xf680`, 76 байт) —
///   проверяет `name != NULL`, затем `if (arch_token == 0) arch_token =
///   SCMP_ARCH_X86_64` (`cmove edi, 0xc000003e`), вызывает
///   `arch_def_lookup` (`fcn.000024e0`) и по результату читает указатель на
///   функцию из структуры:
///   ```text
///   [rax + 0x18]  →  syscall_resolve_name_rewrite   ; у x86_64 = NULL
///   [rax + 0x20]  →  syscall_resolve_name           ; собственно цель
///   ```
///   Если поле `+0x18` не NULL — прыгает туда (rewrite-вариант, нужен x32);
///   иначе — в `+0x20`. Любая ветка с NULL-аркой или NULL-name возвращает
///   `0xffffffff` (`__NR_SCMP_ERROR == -1`).
///
/// * **`arch_def_native`** — структура в `.data.rel.ro @ 0x2bc44`. Первые
///   поля после relocation: `token = 0xc000003e`, `size = 0x40`
///   (`ARCH_SIZE_64`), `endian = 0x01` (`ARCH_ENDIAN_LITTLE`), далее
///   `syscall_table`, `syscall_count`, два указателя на резолверы.
///
/// * **`syscall_resolve_name`** (`.text @ 0xdbe0`, 51 байт) — тонкая
///   функция с одним аргументом:
///   ```text
///   strlen(name)                     ; длина — заранее, для лукапа
///   entry = gperf_lookup(name, len)  ; sub.strcmp_5400
///   return entry ? *(int*)(entry + 0x10) : -1
///   ```
///   `[entry + 0x10]` — это поле `num` внутри `struct arch_syscall_def`.
///
/// * **`gperf_lookup`** (`.text @ 0x5400`) — сгенерированный `gperf`
///   perfect-hash. Отбрасывает длины `< 3` и `> 28`, хеширует несколько
///   байт имени (`name[0]`, `name[1]`, `name[3]`…`name[7]`, `name[len-1]`)
///   через таблицу `uint16[256]`, складывает с длиной, получает индекс в
///   массиве записей и верифицирует кандидат через `strcmp`. Для известных
///   сисколлов коллизий не бывает по построению.
///
/// # Почему в Rust это `match`
///
/// Все три уровня (`_name` → `_arch` → `syscall_resolve_name`) в Rust
/// вырождаются: арка всегда нативная, rewrite-ветка мертва, `strlen` не
/// нужен (у `&str` длина есть), `gperf`-таблица заменяется тем, что rustc
/// сам делает для `match` по строковым литералам:
///
/// 1. `switch` по длине — отсекает заведомо неподходящие имена;
/// 2. `switch` по первым 1/2/4/8 байтам (читаются как `u8`/`u16`/`u32`/`u64`);
/// 3. `memcmp` хвоста при совпадении префикса.
///
/// Это тот же perfect-hash по духу, но без indirection через две таблицы,
/// без `strcmp` и без вызова в libc — компилятор строит jump-таблицы
/// напрямую из литералов. На практике быстрее оригинала.
///
/// # Возвращаемое значение
///
/// * `>= 0` — номер сисколла для x86_64 (значения совпадают с
///   `libc::SYS_*` и с `/usr/include/asm/unistd_64.h`).
/// * `-1` — `__NR_SCMP_ERROR`: имя не найдено, либо `name` пуст.
///
/// Тип — `libc::c_long` (`i64` на x86_64), потому что именно этот тип
/// возвращает C-функция libseccomp; при вызове из Rust через FFI он
/// ложится в `rax` без конверсий.
///
/// # Отличия от libseccomp
///
/// * Не поддерживает x32 (`__X32_SYSCALL_BIT = 0x40000000`) — для обычного
///   x86_64-процесса эта ветка неактуальна. Если понадобится, добавь
///   `nr | 0x4000_0000` под `cfg(target_abi = "x32")` (nightly).
/// * Не поддерживает не-нативные арки (`SCMP_ARCH_ARM`, `SCMP_ARCH_MIPS`
///   и т.п.). Таблица — только для `SCMP_ARCH_X86_64`.
/// * Не вызывает `libseccomp.so` и не требует `CString`/`unsafe`.
///
/// # Пример
///
/// ```rust
/// use libc::c_long;
/// use uu_linux_kernel_seccomp::libc::resolve_name;
///
/// assert_eq!(resolve_name("read"),   libc::SYS_read   as c_long);
/// assert_eq!(resolve_name("write"),  libc::SYS_write  as c_long);
/// assert_eq!(resolve_name("openat"), libc::SYS_openat as c_long);
/// assert_eq!(resolve_name("execve"), libc::SYS_execve as c_long);
///
/// // неизвестное имя → __NR_SCMP_ERROR
/// assert_eq!(resolve_name("nope"), -1);
/// ```
///
/// # Как дополнить таблицу
///
/// Полный список сисколлов x86_64: `/usr/include/asm/unistd_64.h`
/// (или `/usr/include/asm-generic/unistd.h` для generic-ABI). Каждой
/// строке `#define __NR_<name> <num>` соответствует arm
/// `"<name>" => libc::SYS_<name>,`. Значения `libc::SYS_*` в крейте
/// `libc` уже сгенерированы из этих заголовков для целевой платформы,
/// так что руками номера вписывать не нужно.
///
/// Альтернатива — крейт [`syscalls`](https://crates.io/crates/syscalls),
/// где есть `Sysno::from_str(name) -> Result<Sysno, _>`:
///
/// ```rust,ignore
/// use syscalls::Sysno;
///
/// pub fn resolve_name(name: &str) -> c_long {
///     Sysno::from_str(name).map(|n| n as c_long).unwrap_or(-1)
/// }
/// ```
///
/// Это короче, но тянет зависимость; вариант с `match` + `libc::SYS_*`
/// собирается в идеальный jump-табличный код и не требует ничего, кроме
/// самого `libc`.
#[must_use]
pub fn resolve_name(name: &str) -> c_long {
    nr_by_name(name)
}

/// Обратный резолвинг: номер системного вызова → каноническое имя.
///
/// Тот же список, что и у [`resolve_name`], только в другую сторону. Нужен,
/// когда таблица известна лишь номером — например, при дизассемблировании
/// уже скомпилированной BPF-программы (см. [`dump`](crate::libc::dump::dump)).
///
/// Возвращает `None`, если номер не из таблицы x86_64. В частности, имени
/// нет у служебных значений вроде `0x4000_0000` или `0xffff_ffff`.
///
/// # Пример
///
/// ```rust
/// use uu_linux_kernel_seccomp::libc::name_of;
///
/// assert_eq!(name_of(libc::SYS_read), Some("read"));
/// assert_eq!(name_of(libc::SYS_openat), Some("openat"));
/// assert_eq!(name_of(0x4000_0000), None);
/// ```
#[must_use]
pub fn name_of(nr: c_long) -> Option<&'static str> {
    name_by_nr(nr)
}

/// Единый источник правды: из одного списка `"имя" => SYS_константа`
/// генерируются прямой (`nr_by_name`) и обратный (`name_by_nr`) резолверы.
///
/// Оба остаются обычными `match`, поэтому rustc строит для них jump-таблицы
/// так же, как раньше для одной `resolve_name`.
#[allow(non_upper_case_globals)]
macro_rules! define_syscall_table {
    ($($name:literal => $sys:path,)*) => {
        #[allow(clippy::too_many_lines)]
        #[allow(non_upper_case_globals)]
        fn nr_by_name(name: &str) -> c_long {
            match name {
                $($name => $sys,)*
                _ => -1,
            }
        }

        #[allow(clippy::too_many_lines)]
        #[allow(clippy::missing_const_for_fn)]
        #[allow(non_upper_case_globals)]
        fn name_by_nr(nr: c_long) -> Option<&'static str> {
            match nr {
                $($sys => Some($name),)*
                _ => None,
            }
        }
    };
}

define_syscall_table! {
        // 0..173
        "read" => SYS_read,
        "write" => SYS_write,
        "open" => SYS_open,
        "close" => SYS_close,
        "stat" => SYS_stat,
        "fstat" => SYS_fstat,
        "lstat" => SYS_lstat,
        "poll" => SYS_poll,
        "lseek" => SYS_lseek,
        "mmap" => SYS_mmap,
        "mprotect" => SYS_mprotect,
        "munmap" => SYS_munmap,
        "brk" => SYS_brk,
        "rt_sigaction" => SYS_rt_sigaction,
        "rt_sigprocmask" => SYS_rt_sigprocmask,
        "rt_sigreturn" => SYS_rt_sigreturn,
        "ioctl" => SYS_ioctl,
        "pread64" => SYS_pread64,
        "pwrite64" => SYS_pwrite64,
        "readv" => SYS_readv,
        "writev" => SYS_writev,
        "access" => SYS_access,
        "pipe" => SYS_pipe,
        "select" => SYS_select,
        "sched_yield" => SYS_sched_yield,
        "mremap" => SYS_mremap,
        "msync" => SYS_msync,
        "mincore" => SYS_mincore,
        "madvise" => SYS_madvise,
        "shmget" => SYS_shmget,
        "shmat" => SYS_shmat,
        "shmctl" => SYS_shmctl,
        "dup" => SYS_dup,
        "dup2" => SYS_dup2,
        "pause" => SYS_pause,
        "nanosleep" => SYS_nanosleep,
        "getitimer" => SYS_getitimer,
        "alarm" => SYS_alarm,
        "setitimer" => SYS_setitimer,
        "getpid" => SYS_getpid,
        "sendfile" => SYS_sendfile,
        "socket" => SYS_socket,
        "connect" => SYS_connect,
        "accept" => SYS_accept,
        "sendto" => SYS_sendto,
        "recvfrom" => SYS_recvfrom,
        "sendmsg" => SYS_sendmsg,
        "recvmsg" => SYS_recvmsg,
        "shutdown" => SYS_shutdown,
        "bind" => SYS_bind,
        "listen" => SYS_listen,
        "getsockname" => SYS_getsockname,
        "getpeername" => SYS_getpeername,
        "socketpair" => SYS_socketpair,
        "setsockopt" => SYS_setsockopt,
        "getsockopt" => SYS_getsockopt,
        "clone" => SYS_clone,
        "fork" => SYS_fork,
        "vfork" => SYS_vfork,
        "execve" => SYS_execve,
        "exit" => SYS_exit,
        "wait4" => SYS_wait4,
        "kill" => SYS_kill,
        "uname" => SYS_uname,
        "semget" => SYS_semget,
        "semop" => SYS_semop,
        "semctl" => SYS_semctl,
        "shmdt" => SYS_shmdt,
        "msgget" => SYS_msgget,
        "msgsnd" => SYS_msgsnd,
        "msgrcv" => SYS_msgrcv,
        "msgctl" => SYS_msgctl,
        "fcntl" => SYS_fcntl,
        "flock" => SYS_flock,
        "fsync" => SYS_fsync,
        "fdatasync" => SYS_fdatasync,
        "truncate" => SYS_truncate,
        "ftruncate" => SYS_ftruncate,
        "getdents" => SYS_getdents,
        "getcwd" => SYS_getcwd,
        "chdir" => SYS_chdir,
        "fchdir" => SYS_fchdir,
        "rename" => SYS_rename,
        "mkdir" => SYS_mkdir,
        "rmdir" => SYS_rmdir,
        "creat" => SYS_creat,
        "link" => SYS_link,
        "unlink" => SYS_unlink,
        "symlink" => SYS_symlink,
        "readlink" => SYS_readlink,
        "chmod" => SYS_chmod,
        "fchmod" => SYS_fchmod,
        "chown" => SYS_chown,
        "fchown" => SYS_fchown,
        "lchown" => SYS_lchown,
        "umask" => SYS_umask,
        "gettimeofday" => SYS_gettimeofday,
        "getrlimit" => SYS_getrlimit,
        "getrusage" => SYS_getrusage,
        "sysinfo" => SYS_sysinfo,
        "times" => SYS_times,
        "ptrace" => SYS_ptrace,
        "getuid" => SYS_getuid,
        "syslog" => SYS_syslog,
        "getgid" => SYS_getgid,
        "setuid" => SYS_setuid,
        "setgid" => SYS_setgid,
        "geteuid" => SYS_geteuid,
        "getegid" => SYS_getegid,
        "setpgid" => SYS_setpgid,
        "getppid" => SYS_getppid,
        "getpgrp" => SYS_getpgrp,
        "setsid" => SYS_setsid,
        "setreuid" => SYS_setreuid,
        "setregid" => SYS_setregid,
        "getgroups" => SYS_getgroups,
        "setgroups" => SYS_setgroups,
        "setresuid" => SYS_setresuid,
        "getresuid" => SYS_getresuid,
        "setresgid" => SYS_setresgid,
        "getresgid" => SYS_getresgid,
        "getpgid" => SYS_getpgid,
        "setfsuid" => SYS_setfsuid,
        "setfsgid" => SYS_setfsgid,
        "getsid" => SYS_getsid,
        "capget" => SYS_capget,
        "capset" => SYS_capset,
        "rt_sigpending" => SYS_rt_sigpending,
        "rt_sigtimedwait" => SYS_rt_sigtimedwait,
        "rt_sigqueueinfo" => SYS_rt_sigqueueinfo,
        "rt_sigsuspend" => SYS_rt_sigsuspend,
        "sigaltstack" => SYS_sigaltstack,
        "utime" => SYS_utime,
        "mknod" => SYS_mknod,
        "uselib" => SYS_uselib,
        "personality" => SYS_personality,
        "ustat" => SYS_ustat,
        "statfs" => SYS_statfs,
        "fstatfs" => SYS_fstatfs,
        "sysfs" => SYS_sysfs,
        "getpriority" => SYS_getpriority,
        "setpriority" => SYS_setpriority,
        "sched_setparam" => SYS_sched_setparam,
        "sched_getparam" => SYS_sched_getparam,
        "sched_setscheduler" => SYS_sched_setscheduler,
        "sched_getscheduler" => SYS_sched_getscheduler,
        "sched_get_priority_max" => SYS_sched_get_priority_max,
        "sched_get_priority_min" => SYS_sched_get_priority_min,
        "sched_rr_get_interval" => SYS_sched_rr_get_interval,
        "mlock" => SYS_mlock,
        "munlock" => SYS_munlock,
        "mlockall" => SYS_mlockall,
        "munlockall" => SYS_munlockall,
        "vhangup" => SYS_vhangup,
        "modify_ldt" => SYS_modify_ldt,
        "pivot_root" => SYS_pivot_root,
        "_sysctl" => SYS__sysctl,
        "prctl" => SYS_prctl,
        "arch_prctl" => SYS_arch_prctl,
        "adjtimex" => SYS_adjtimex,
        "setrlimit" => SYS_setrlimit,
        "chroot" => SYS_chroot,
        "sync" => SYS_sync,
        "acct" => SYS_acct,
        "settimeofday" => SYS_settimeofday,
        "mount" => SYS_mount,
        "umount2" => SYS_umount2,
        "swapon" => SYS_swapon,
        "swapoff" => SYS_swapoff,
        "reboot" => SYS_reboot,
        "sethostname" => SYS_sethostname,
        "setdomainname" => SYS_setdomainname,
        "iopl" => SYS_iopl,
        "ioperm" => SYS_ioperm,

        // 174: SYS_create_module — удалён, пропущен
        "init_module" => SYS_init_module,
        "delete_module" => SYS_delete_module,
        // 177: SYS_get_kernel_syms — удалён
        // 178: SYS_query_module     — удалён
        "quotactl" => SYS_quotactl,
        "nfsservctl" => SYS_nfsservctl,
        "getpmsg" => SYS_getpmsg,
        "putpmsg" => SYS_putpmsg,
        "afs_syscall" => SYS_afs_syscall,
        "tuxcall" => SYS_tuxcall,
        "security" => SYS_security,
        "gettid" => SYS_gettid,
        "readahead" => SYS_readahead,
        "setxattr" => SYS_setxattr,
        "lsetxattr" => SYS_lsetxattr,
        "fsetxattr" => SYS_fsetxattr,
        "getxattr" => SYS_getxattr,
        "lgetxattr" => SYS_lgetxattr,
        "fgetxattr" => SYS_fgetxattr,
        "listxattr" => SYS_listxattr,
        "llistxattr" => SYS_llistxattr,
        "flistxattr" => SYS_flistxattr,
        "removexattr" => SYS_removexattr,
        "lremovexattr" => SYS_lremovexattr,
        "fremovexattr" => SYS_fremovexattr,
        "tkill" => SYS_tkill,
        "time" => SYS_time,
        "futex" => SYS_futex,
        "sched_setaffinity" => SYS_sched_setaffinity,
        "sched_getaffinity" => SYS_sched_getaffinity,
        "set_thread_area" => SYS_set_thread_area,
        "io_setup" => SYS_io_setup,
        "io_destroy" => SYS_io_destroy,
        "io_getevents" => SYS_io_getevents,
        "io_submit" => SYS_io_submit,
        "io_cancel" => SYS_io_cancel,
        "get_thread_area" => SYS_get_thread_area,
        "lookup_dcookie" => SYS_lookup_dcookie,
        "epoll_create" => SYS_epoll_create,
        "epoll_ctl_old" => SYS_epoll_ctl_old,
        "epoll_wait_old" => SYS_epoll_wait_old,
        "remap_file_pages" => SYS_remap_file_pages,
        "getdents64" => SYS_getdents64,
        "set_tid_address" => SYS_set_tid_address,
        "restart_syscall" => SYS_restart_syscall,
        "semtimedop" => SYS_semtimedop,
        "fadvise64" => SYS_fadvise64,
        "timer_create" => SYS_timer_create,
        "timer_settime" => SYS_timer_settime,
        "timer_gettime" => SYS_timer_gettime,
        "timer_getoverrun" => SYS_timer_getoverrun,
        "timer_delete" => SYS_timer_delete,
        "clock_settime" => SYS_clock_settime,
        "clock_gettime" => SYS_clock_gettime,
        "clock_getres" => SYS_clock_getres,
        "clock_nanosleep" => SYS_clock_nanosleep,
        "exit_group" => SYS_exit_group,
        "epoll_wait" => SYS_epoll_wait,
        "epoll_ctl" => SYS_epoll_ctl,
        "tgkill" => SYS_tgkill,
        "utimes" => SYS_utimes,
        "vserver" => SYS_vserver,
        "mbind" => SYS_mbind,
        "set_mempolicy" => SYS_set_mempolicy,
        "get_mempolicy" => SYS_get_mempolicy,
        "mq_open" => SYS_mq_open,
        "mq_unlink" => SYS_mq_unlink,
        "mq_timedsend" => SYS_mq_timedsend,
        "mq_timedreceive" => SYS_mq_timedreceive,
        "mq_notify" => SYS_mq_notify,
        "mq_getsetattr" => SYS_mq_getsetattr,
        "kexec_load" => SYS_kexec_load,
        "waitid" => SYS_waitid,
        "add_key" => SYS_add_key,
        "request_key" => SYS_request_key,
        "keyctl" => SYS_keyctl,
        "ioprio_set" => SYS_ioprio_set,
        "ioprio_get" => SYS_ioprio_get,
        "inotify_init" => SYS_inotify_init,
        "inotify_add_watch" => SYS_inotify_add_watch,
        "inotify_rm_watch" => SYS_inotify_rm_watch,
        "migrate_pages" => SYS_migrate_pages,
        "openat" => SYS_openat,
        "mkdirat" => SYS_mkdirat,
        "mknodat" => SYS_mknodat,
        "fchownat" => SYS_fchownat,
        "futimesat" => SYS_futimesat,
        "newfstatat" => SYS_newfstatat,
        "unlinkat" => SYS_unlinkat,
        "renameat" => SYS_renameat,
        "linkat" => SYS_linkat,
        "symlinkat" => SYS_symlinkat,
        "readlinkat" => SYS_readlinkat,
        "fchmodat" => SYS_fchmodat,
        "faccessat" => SYS_faccessat,
        "pselect6" => SYS_pselect6,
        "ppoll" => SYS_ppoll,
        "unshare" => SYS_unshare,
        "set_robust_list" => SYS_set_robust_list,
        "get_robust_list" => SYS_get_robust_list,
        "splice" => SYS_splice,
        "tee" => SYS_tee,
        "sync_file_range" => SYS_sync_file_range,
        "vmsplice" => SYS_vmsplice,
        "move_pages" => SYS_move_pages,
        "utimensat" => SYS_utimensat,
        "epoll_pwait" => SYS_epoll_pwait,
        "signalfd" => SYS_signalfd,
        "timerfd_create" => SYS_timerfd_create,
        "eventfd" => SYS_eventfd,
        "fallocate" => SYS_fallocate,
        "timerfd_settime" => SYS_timerfd_settime,
        "timerfd_gettime" => SYS_timerfd_gettime,
        "accept4" => SYS_accept4,
        "signalfd4" => SYS_signalfd4,
        "eventfd2" => SYS_eventfd2,
        "epoll_create1" => SYS_epoll_create1,
        "dup3" => SYS_dup3,
        "pipe2" => SYS_pipe2,
        "inotify_init1" => SYS_inotify_init1,
        "preadv" => SYS_preadv,
        "pwritev" => SYS_pwritev,
        "rt_tgsigqueueinfo" => SYS_rt_tgsigqueueinfo,
        "perf_event_open" => SYS_perf_event_open,
        "recvmmsg" => SYS_recvmmsg,
        "fanotify_init" => SYS_fanotify_init,
        "fanotify_mark" => SYS_fanotify_mark,
        "prlimit64" => SYS_prlimit64,
        "name_to_handle_at" => SYS_name_to_handle_at,
        "open_by_handle_at" => SYS_open_by_handle_at,
        "clock_adjtime" => SYS_clock_adjtime,
        "syncfs" => SYS_syncfs,
        "sendmmsg" => SYS_sendmmsg,
        "setns" => SYS_setns,
        "getcpu" => SYS_getcpu,
        "process_vm_readv" => SYS_process_vm_readv,
        "process_vm_writev" => SYS_process_vm_writev,
        "kcmp" => SYS_kcmp,
        "finit_module" => SYS_finit_module,
        "sched_setattr" => SYS_sched_setattr,
        "sched_getattr" => SYS_sched_getattr,
        "renameat2" => SYS_renameat2,
        "seccomp" => SYS_seccomp,
        "getrandom" => SYS_getrandom,
        "memfd_create" => SYS_memfd_create,
        "kexec_file_load" => SYS_kexec_file_load,
        "bpf" => SYS_bpf,
        "execveat" => SYS_execveat,
        "userfaultfd" => SYS_userfaultfd,
        "membarrier" => SYS_membarrier,
        "mlock2" => SYS_mlock2,
        "copy_file_range" => SYS_copy_file_range,
        "preadv2" => SYS_preadv2,
        "pwritev2" => SYS_pwritev2,
        "pkey_mprotect" => SYS_pkey_mprotect,
        "pkey_alloc" => SYS_pkey_alloc,
        "pkey_free" => SYS_pkey_free,
        "statx" => SYS_statx,

        // 333: SYS_io_pgetevents — отсутствует в таблице
        "rseq" => SYS_rseq,
        // 335..423: SYS_pidfd_send_signal..SYS_io_uring_*  — там дыра,
        // но конкретно 424+ идут дальше; диапазон 335..423 в файле не
        // определён (это io_pgetevents / pkey_* / futex_waitv? — нет,
        // futex_waitv определён ниже под 449).
        "pidfd_send_signal" => SYS_pidfd_send_signal,
        "io_uring_setup" => SYS_io_uring_setup,
        "io_uring_enter" => SYS_io_uring_enter,
        "io_uring_register" => SYS_io_uring_register,
        "open_tree" => SYS_open_tree,
        "move_mount" => SYS_move_mount,
        "fsopen" => SYS_fsopen,
        "fsconfig" => SYS_fsconfig,
        "fsmount" => SYS_fsmount,
        "fspick" => SYS_fspick,
        "pidfd_open" => SYS_pidfd_open,
        "clone3" => SYS_clone3,
        "close_range" => SYS_close_range,
        "openat2" => SYS_openat2,
        "pidfd_getfd" => SYS_pidfd_getfd,
        "faccessat2" => SYS_faccessat2,
        "process_madvise" => SYS_process_madvise,
        "epoll_pwait2" => SYS_epoll_pwait2,
        "mount_setattr" => SYS_mount_setattr,
        "quotactl_fd" => SYS_quotactl_fd,
        "landlock_create_ruleset" => SYS_landlock_create_ruleset,
        "landlock_add_rule" => SYS_landlock_add_rule,
        "landlock_restrict_self" => SYS_landlock_restrict_self,
        "memfd_secret" => SYS_memfd_secret,
        "process_mrelease" => SYS_process_mrelease,
        "futex_waitv" => SYS_futex_waitv,
        "set_mempolicy_home_node" => SYS_set_mempolicy_home_node,

        // 451: отсутствует (SYS_cachestat не определён в этой таблице)
        "fchmodat2" => SYS_fchmodat2,
        // 453..461: не определены в этой таблице
        // 462:
        "mseal" => SYS_mseal,
}
