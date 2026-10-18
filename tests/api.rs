//! Тесты «чистой» части: резолвинг имён сисколлов, действия (`ACTION`)
//! и корректность сгенерированной BPF-программы.
//!
//! Здесь нет `fork` — программа не применяется к живому процессу, а
//! прогоняется через мини-интерпретатор классического BPF. Так проверяется
//! именно логика ветвлений (`jt`/`jf`) и раскладка `seccomp_data`.

use uu_linux_kernel_seccomp::libc::bpf::{self, ArgCmp, BuildError, Rule};
use uu_linux_kernel_seccomp::libc::resolve_name;
use uu_linux_kernel_seccomp::rust::{ACTION, Policy, PolicyError, rule_name, rule_nr};

/// Архитектура аудита для x86_64 (значение первого поля `seccomp_data`).
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// `__X32_SYSCALL_BIT` — старший бит, которым помечаются x32-вызовы.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Безопасно привести номер сисколла (`c_long`) к `u32`.
fn nr(value: i64) -> u32 {
    u32::try_from(value).expect("номер сисколла влезает в u32")
}

/// `AT_FDCWD` (−100) в беззнаковой 64-битной записи — как его видит BPF.
#[allow(clippy::cast_sign_loss)]
const AT_FD_CWD: u64 = libc::AT_FDCWD as i64 as u64;

/// Флаг `O_*` в беззнаковой 64-битной записи для BPF.
#[allow(clippy::cast_sign_loss)]
const fn flag(value: libc::c_int) -> u64 {
    value as u64
}

/// Собрать `Rule` с действием `ALLOW`.
const fn allow(nr: i64) -> Rule {
    Rule::new(nr, libc::SECCOMP_RET_ALLOW)
}

/// Собрать `ret`-значение `ERRNO | errno`, переиспользуя высокоуровневый
/// [`ACTION`] — так проверяется и он тоже.
fn errno_ret(errno: libc::c_int) -> u32 {
    ACTION::Errno(u16::try_from(errno).expect("errno влезает в u16")).to_ret()
}

/// Мини-интерпретатор классического BPF поверх `seccomp_data`.
///
/// Поддерживает ровно те инструкции, которые генерирует
/// [`bpf::build_program`]: загрузка `u32` из смещения, `JEQ`/`JGE`/`JGT`,
/// `ALU|AND|K` и `RET`. Возвращает итоговое `ret`-значение действия.
fn execute(prog: &[libc::sock_filter], arch: u32, syscall_nr: u32) -> u32 {
    execute_args(prog, arch, syscall_nr, [0; 6])
}

/// То же с ненулевыми аргументами сисколла — для проверок аргументов.
fn execute_args(prog: &[libc::sock_filter], arch: u32, syscall_nr: u32, args: [u64; 6]) -> u32 {
    let mut accumulator: u32 = 0;
    let mut pc: usize = 0;

    loop {
        let ins = &prog[pc];
        let code = u32::from(ins.code);

        if code == libc::BPF_LD | libc::BPF_W | libc::BPF_ABS {
            accumulator = load_word(ins.k, arch, syscall_nr, args);
        } else if code == libc::BPF_ALU | libc::BPF_AND | libc::BPF_K {
            accumulator &= ins.k;
        } else if code == libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K {
            pc += usize::from(if accumulator == ins.k { ins.jt } else { ins.jf });
        } else if code == libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K {
            pc += usize::from(if accumulator >= ins.k { ins.jt } else { ins.jf });
        } else if code == libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K {
            pc += usize::from(if accumulator > ins.k { ins.jt } else { ins.jf });
        } else if code == libc::BPF_RET | libc::BPF_K {
            return ins.k;
        } else {
            panic!("неизвестный опкод {code:#x}");
        }

        pc += 1;
    }
}

/// Прочитать слово `seccomp_data` по смещению (раскладка little-endian:
/// `nr`=0, `arch`=4, `ip`=8..16, `args[i]` — по `16+8*i`, старшая половина
/// по `16+8*i+4`).
#[allow(clippy::cast_possible_truncation)] // слово — это и есть обрезка u64
fn load_word(offset: u32, arch: u32, syscall_nr: u32, args: [u64; 6]) -> u32 {
    if offset == 0 {
        return syscall_nr;
    }
    if offset == 4 {
        return arch;
    }
    if offset == 8 || offset == 12 {
        return 0; // instruction_pointer в модели всегда нулевой
    }
    if (16..64).contains(&offset) {
        let index = ((offset - 16) / 8) as usize;
        let high = (offset - 16) % 8 == 4;
        return if high {
            (args[index] >> 32) as u32
        } else {
            args[index] as u32
        };
    }

    panic!("неизвестное смещение seccomp_data: {offset}");
}

// ── resolve_name ─────────────────────────────────────────────────────

#[test]
fn resolve_name_known_syscalls() {
    assert_eq!(resolve_name("read"), libc::SYS_read);
    assert_eq!(resolve_name("write"), libc::SYS_write);
    assert_eq!(resolve_name("openat"), libc::SYS_openat);
    assert_eq!(resolve_name("execve"), libc::SYS_execve);
    assert_eq!(resolve_name("seccomp"), libc::SYS_seccomp);
    assert_eq!(resolve_name("rt_sigreturn"), libc::SYS_rt_sigreturn);
}

#[test]
fn resolve_name_unknown_is_error() {
    assert_eq!(resolve_name(""), -1);
    assert_eq!(resolve_name("nope"), -1);
    assert_eq!(resolve_name("read "), -1);
}

// ── ACTION ───────────────────────────────────────────────────────────

#[test]
fn action_roundtrips_through_ret() {
    for action in [
        ACTION::KillProcess,
        ACTION::KillThread,
        ACTION::Trap,
        ACTION::Errno(1),
        ACTION::Errno(u16::try_from(libc::ENOSYS).unwrap()),
        ACTION::UserNotif,
        ACTION::Trace,
        ACTION::Log,
        ACTION::Allow,
    ] {
        assert_eq!(ACTION::from_ret(action.to_ret()), Some(action));
    }
}

#[test]
fn errno_action_keeps_16_bit_payload() {
    assert_eq!(
        ACTION::Errno(0x1234).to_ret(),
        libc::SECCOMP_RET_ERRNO | 0x1234
    );
    assert_eq!(
        ACTION::from_ret(libc::SECCOMP_RET_ERRNO | 0x1234),
        Some(ACTION::Errno(0x1234))
    );
}

#[test]
fn unknown_action_decodes_to_none() {
    assert_eq!(ACTION::from_ret(0x1234_0000), None);
}

// ── build_program: раскладка ─────────────────────────────────────────

#[test]
fn program_layout_for_single_rule() {
    let prog = bpf::build_program(&[allow(libc::SYS_read)], errno_ret(libc::ENOSYS)).unwrap();

    // 6 заголовка + (LD nr + JEQ + RET) на правило + завершающий default.
    assert_eq!(prog.len(), 10);

    // Архитектура: при несовпадении падаем на RET KILL ниже.
    assert_eq!(prog[0].k, 4);
    assert_eq!(prog[1].k, AUDIT_ARCH_X86_64);
    assert_eq!(prog[1].jt, 1);
    assert_eq!(prog[1].jf, 0);
    assert_eq!(prog[2].k, libc::SECCOMP_RET_KILL_PROCESS);

    // Отсечение x32: при nr >= X32 тоже падаем на RET KILL.
    assert_eq!(prog[3].k, 0);
    assert_eq!(prog[4].k, X32_SYSCALL_BIT);
    assert_eq!(prog[4].jt, 0);
    assert_eq!(prog[4].jf, 1);
    assert_eq!(prog[5].k, libc::SECCOMP_RET_KILL_PROCESS);

    // Правило: перезагрузка номера, вход и его действие.
    assert_eq!(prog[6].k, 0);
    assert_eq!(prog[7].k, nr(libc::SYS_read));
    assert_eq!(prog[8].k, libc::SECCOMP_RET_ALLOW);

    // Завершающий default.
    assert_eq!(prog[9].k, errno_ret(libc::ENOSYS));
}

#[test]
fn every_jump_is_local() {
    // Весь смысл переработки: ни один jt/jf не превышает 1, поэтому
    // 8-битный лимит перехода не наступает на сколь угодно длинной цепочке.
    let rules: Vec<Rule> = (0..1000).map(|i| allow(i64::from(i))).collect();
    let prog = bpf::build_program(&rules, errno_ret(libc::ENOSYS)).unwrap();

    for (i, ins) in prog.iter().enumerate() {
        assert!(ins.jt <= 1, "инструкция {i}: jt={}", ins.jt);
        assert!(ins.jf <= 1, "инструкция {i}: jf={}", ins.jf);
    }
}

// ── build_program: семантика ветвлений ───────────────────────────────

#[test]
fn listed_syscall_gets_its_action() {
    let default = errno_ret(libc::ENOSYS);
    let prog = bpf::build_program(
        &[
            allow(libc::SYS_read),
            Rule::new(libc::SYS_write, errno_ret(libc::EACCES)),
        ],
        default,
    )
    .unwrap();

    assert_eq!(
        execute(&prog, AUDIT_ARCH_X86_64, nr(libc::SYS_read)),
        libc::SECCOMP_RET_ALLOW
    );
    assert_eq!(
        execute(&prog, AUDIT_ARCH_X86_64, nr(libc::SYS_write)),
        errno_ret(libc::EACCES)
    );
}

#[test]
fn unlisted_syscall_falls_through_to_default() {
    let default = errno_ret(libc::EPERM);
    let prog = bpf::build_program(&[allow(libc::SYS_read)], default).unwrap();

    assert_eq!(
        execute(&prog, AUDIT_ARCH_X86_64, nr(libc::SYS_getpid)),
        default
    );
}

#[test]
fn foreign_arch_is_killed() {
    let prog = bpf::build_program(&[allow(libc::SYS_read)], errno_ret(libc::ENOSYS)).unwrap();

    assert_eq!(
        execute(&prog, AUDIT_ARCH_X86_64 ^ 0x1, nr(libc::SYS_read)),
        libc::SECCOMP_RET_KILL_PROCESS
    );
}

#[test]
fn x32_syscall_is_killed() {
    let prog = bpf::build_program(&[allow(libc::SYS_read)], errno_ret(libc::ENOSYS)).unwrap();

    assert_eq!(
        execute(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_read) | X32_SYSCALL_BIT
        ),
        libc::SECCOMP_RET_KILL_PROCESS
    );
}

// ── build_program: ошибки ────────────────────────────────────────────

#[test]
fn negative_syscall_number_is_rejected() {
    match bpf::build_program(&[allow(-1)], libc::SECCOMP_RET_ALLOW) {
        Err(BuildError::SyscallNrOutOfRange { nr: value }) => assert_eq!(value, -1),
        Err(other) => panic!("ожидали SyscallNrOutOfRange, получили {other}"),
        Ok(_) => panic!("ожидали SyscallNrOutOfRange"),
    }
}

#[test]
fn program_exceeding_kernel_limit_is_rejected() {
    // Потолок — не 8-битный переход, а BPF_MAXINSNS (4096). Правило
    // занимает LD nr + вход + RET = 3 инструкции, заголовок 6, плюс
    // default: 7 + 3N > 4096 наступает при N >= 1364.
    let rules: Vec<Rule> = (0..1364).map(|i| allow(i64::from(i))).collect();

    match bpf::build_program(&rules, libc::SECCOMP_RET_ALLOW) {
        Err(BuildError::ProgramTooLong {
            instructions,
            limit,
        }) => {
            assert_eq!(limit, bpf::BPF_MAXINSNS);
            assert!(instructions > limit);
        }
        Err(other) => panic!("ожидали ProgramTooLong, получили {other}"),
        Ok(_) => panic!("ожидали ProgramTooLong"),
    }
}

#[test]
fn large_allowlist_still_builds() {
    // То, что раньше падало на ~126 правилах, теперь собирается легко.
    let rules: Vec<Rule> = (0..1000).map(|i| allow(i64::from(i))).collect();
    assert!(bpf::build_program(&rules, libc::SECCOMP_RET_ALLOW).is_ok());
}

// ── build_program: проверки аргументов ───────────────────────────────

/// Аргументы для `execute_args`: `openat(dirfd, path, flags, ...)` на бумаге.
fn openat_args(dirfd: u64, flags: u64) -> [u64; 6] {
    [dirfd, 0, flags, 0, 0, 0]
}

#[test]
fn arg_eq_layout_uses_lo_hi_word_offsets() {
    // Правило с одной проверкой Eq(1) на arg0: LD nr, вход JEQ nr, LD
    // старшего слова (смещение 20), JEQ, LD младшего (16), JEQ, RET.
    let prog = bpf::build_program(
        &[Rule::new(libc::SYS_getpid, libc::SECCOMP_RET_ALLOW).check(0, bpf::Cmp::Eq(1))],
        errno_ret(libc::ENOSYS),
    )
    .unwrap();

    assert_eq!(prog.len(), 6 + 7 + 1);
    assert_eq!(prog[6].k, 0); // перезагрузка номера сисколла
    assert_eq!(prog[7].k, nr(libc::SYS_getpid)); // вход по nr
    assert_eq!(prog[8].k, 20); // старшее слово arg0
    assert_eq!(prog[9].k, 0); // старшая половина значения 1
    assert_eq!(prog[10].k, 16); // младшее слово arg0
    assert_eq!(prog[11].k, 1); // младшая половина
    assert_eq!(prog[12].k, libc::SECCOMP_RET_ALLOW); // RET действия
    assert_eq!(prog[13].k, errno_ret(libc::ENOSYS)); // default
}

#[test]
fn arg_eq_matches_only_exact_64bit_value() {
    let value = 0x1234_5678_9abc_def0;
    let prog = bpf::build_program(
        &[Rule::new(libc::SYS_getpid, libc::SECCOMP_RET_ALLOW).check(0, bpf::Cmp::Eq(value))],
        errno_ret(libc::EPERM),
    )
    .unwrap();

    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_getpid),
            [value, 0, 0, 0, 0, 0]
        ),
        libc::SECCOMP_RET_ALLOW
    );
    // Младшая половина совпала, старшая нет → default.
    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_getpid),
            [0x1234_5678, 0, 0, 0, 0, 0]
        ),
        errno_ret(libc::EPERM)
    );
    // Старшая совпала, младшая нет.
    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_getpid),
            [0x0000_0000_9abc_def0, 0, 0, 0, 0, 0]
        ),
        errno_ret(libc::EPERM)
    );
    // Граница: u64::MAX на обеих половинах.
    let max_prog = bpf::build_program(
        &[Rule::new(libc::SYS_getpid, libc::SECCOMP_RET_ALLOW).check(0, bpf::Cmp::Eq(u64::MAX))],
        errno_ret(libc::EPERM),
    )
    .unwrap();
    assert_eq!(
        execute_args(
            &max_prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_getpid),
            [u64::MAX, 0, 0, 0, 0, 0]
        ),
        libc::SECCOMP_RET_ALLOW
    );
    assert_eq!(
        execute_args(
            &max_prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_getpid),
            [u64::MAX - 1, 0, 0, 0, 0, 0]
        ),
        errno_ret(libc::EPERM)
    );
}

#[test]
fn arg_ne_falls_through_only_on_exact_value() {
    let prog = bpf::build_program(
        &[Rule::new(libc::SYS_getpid, libc::SECCOMP_RET_ALLOW).check(0, bpf::Cmp::Ne(12_345))],
        errno_ret(libc::EPERM),
    )
    .unwrap();

    // Любое другое значение проходит.
    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_getpid),
            [0, 0, 0, 0, 0, 0]
        ),
        libc::SECCOMP_RET_ALLOW
    );
    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_getpid),
            [u64::MAX, 0, 0, 0, 0, 0]
        ),
        libc::SECCOMP_RET_ALLOW
    );
    // Ровно 12_345 → default.
    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_getpid),
            [12_345, 0, 0, 0, 0, 0]
        ),
        errno_ret(libc::EPERM)
    );
}

#[test]
fn arg_lt_is_unsigned_and_strict() {
    let rule = Rule::new(libc::SYS_getpriority, libc::SECCOMP_RET_ALLOW).check(0, bpf::Cmp::Lt(1));
    let prog = bpf::build_program(&[rule], errno_ret(libc::EPERM)).unwrap();
    let run = |arg: u64| {
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_getpriority),
            [arg, 0, 0, 0, 0, 0],
        )
    };

    assert_eq!(run(0), libc::SECCOMP_RET_ALLOW);
    // Строгое «<»: 1 не проходит.
    assert_eq!(run(1), errno_ret(libc::EPERM));
    // Беззнаковое сравнение: «отрицательное» значение — огромное число.
    assert_eq!(run(u64::MAX), errno_ret(libc::EPERM));
}

#[test]
fn arg_le_allows_boundary() {
    let rule = Rule::new(libc::SYS_getpriority, libc::SECCOMP_RET_ALLOW).check(0, bpf::Cmp::Le(1));
    let prog = bpf::build_program(&[rule], errno_ret(libc::EPERM)).unwrap();
    let run = |arg: u64| {
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_getpriority),
            [arg, 0, 0, 0, 0, 0],
        )
    };

    assert_eq!(run(0), libc::SECCOMP_RET_ALLOW);
    assert_eq!(run(1), libc::SECCOMP_RET_ALLOW);
    assert_eq!(run(2), errno_ret(libc::EPERM));
    assert_eq!(run(u64::MAX), errno_ret(libc::EPERM));
}

#[test]
fn arg_gt_is_unsigned_and_strict() {
    let rule = Rule::new(libc::SYS_getpriority, libc::SECCOMP_RET_ALLOW).check(0, bpf::Cmp::Gt(0));
    let prog = bpf::build_program(&[rule], errno_ret(libc::EPERM)).unwrap();
    let run = |arg: u64| {
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_getpriority),
            [arg, 0, 0, 0, 0, 0],
        )
    };

    assert_eq!(run(0), errno_ret(libc::EPERM));
    assert_eq!(run(1), libc::SECCOMP_RET_ALLOW);
    // u64::MAX > 0 по беззнаковому сравнению.
    assert_eq!(run(u64::MAX), libc::SECCOMP_RET_ALLOW);
}

#[test]
fn arg_gt_compares_across_word_split() {
    // Сравнение должно работать и когда граница режется между словами.
    let boundary = 0x0000_00ff_8000_0000;
    let rule =
        Rule::new(libc::SYS_getpriority, libc::SECCOMP_RET_ALLOW).check(0, bpf::Cmp::Gt(boundary));
    let prog = bpf::build_program(&[rule], errno_ret(libc::EPERM)).unwrap();
    let run = |arg: u64| {
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_getpriority),
            [arg, 0, 0, 0, 0, 0],
        )
    };

    // Старшие слова одинаковые, младшее больше.
    assert_eq!(run(boundary + 1), libc::SECCOMP_RET_ALLOW);
    assert_eq!(run(boundary), errno_ret(libc::EPERM));
    assert_eq!(run(boundary - 1), errno_ret(libc::EPERM));
    // Старшее слово больше — само старшинство решает, младшие не смотрим.
    assert_eq!(run(0x0000_0100_0000_0000), libc::SECCOMP_RET_ALLOW);
    // А меньшее старшее слово — мимо, как ни крути младшее.
    assert_eq!(run(0x0000_00e0_0000_0000), errno_ret(libc::EPERM));
}

#[test]
fn arg_ge_allows_boundary() {
    let rule = Rule::new(libc::SYS_getpriority, libc::SECCOMP_RET_ALLOW).check(0, bpf::Cmp::Ge(1));
    let prog = bpf::build_program(&[rule], errno_ret(libc::EPERM)).unwrap();
    let run = |arg: u64| {
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_getpriority),
            [arg, 0, 0, 0, 0, 0],
        )
    };

    assert_eq!(run(0), errno_ret(libc::EPERM));
    assert_eq!(run(1), libc::SECCOMP_RET_ALLOW);
    assert_eq!(run(u64::MAX), libc::SECCOMP_RET_ALLOW);
}

#[test]
fn arg_masked_eq_ignores_noise_flags() {
    let rule = Rule::new(libc::SYS_openat, libc::SECCOMP_RET_ALLOW).check(
        2,
        bpf::Cmp::MaskedEq {
            mask: flag(libc::O_ACCMODE), // 0b11
            val: 0,                      // O_RDONLY
        },
    );
    let prog = bpf::build_program(&[rule], errno_ret(libc::EPERM)).unwrap();
    let run = |flags: u64| {
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_openat),
            openat_args(0, flags),
        )
    };

    assert_eq!(run(flag(libc::O_RDONLY)), libc::SECCOMP_RET_ALLOW);
    // «Шумные» флаги маска игнорирует.
    assert_eq!(
        run(flag(libc::O_RDONLY) | flag(libc::O_TRUNC)),
        libc::SECCOMP_RET_ALLOW
    );
    assert_eq!(
        run(flag(libc::O_RDONLY) | flag(libc::O_NONBLOCK) | flag(libc::O_APPEND)),
        libc::SECCOMP_RET_ALLOW
    );
    // Другой акцесс-мод — default.
    assert_eq!(run(flag(libc::O_WRONLY)), errno_ret(libc::EPERM));
    assert_eq!(run(flag(libc::O_RDWR)), errno_ret(libc::EPERM));
}

#[test]
fn arg_masked_eq_with_nonzero_value() {
    let rule = Rule::new(libc::SYS_openat, libc::SECCOMP_RET_ALLOW).check(
        2,
        bpf::Cmp::MaskedEq {
            mask: 0xff,
            val: 0x10f,
        },
    );
    let prog = bpf::build_program(&[rule], errno_ret(libc::EPERM)).unwrap();
    let run = |flags: u64| {
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_openat),
            openat_args(0, flags),
        )
    };

    // (arg & 0xff) == (0x10f & 0xff) == 0x0f
    assert_eq!(run(0x20f), libc::SECCOMP_RET_ALLOW);
    assert_eq!(run(0x90f), libc::SECCOMP_RET_ALLOW);
    assert_eq!(run(0x20e), errno_ret(libc::EPERM));
    assert_eq!(run(0x210), errno_ret(libc::EPERM));
}

#[test]
fn arg_all_checks_must_match() {
    // AT_FDCWD == -100 → в беззнаковой записи 0xFFFF_FFFF_FFFF_FF9C
    // (старшее слово имеет смысл только в 64-битной раскладке).
    let rule = Rule::new(libc::SYS_openat, libc::SECCOMP_RET_ALLOW)
        .check(0, bpf::Cmp::Eq(AT_FD_CWD))
        .check(2, bpf::Cmp::Eq(flag(libc::O_RDONLY)));
    let prog = bpf::build_program(&[rule], errno_ret(libc::EPERM)).unwrap();

    let both = execute_args(
        &prog,
        AUDIT_ARCH_X86_64,
        nr(libc::SYS_openat),
        openat_args(AT_FD_CWD, flag(libc::O_RDONLY)),
    );
    assert_eq!(both, libc::SECCOMP_RET_ALLOW);

    // Первая проверка совпала, вторая нет → default.
    let only_dirfd = execute_args(
        &prog,
        AUDIT_ARCH_X86_64,
        nr(libc::SYS_openat),
        openat_args(AT_FD_CWD, flag(libc::O_WRONLY)),
    );
    assert_eq!(only_dirfd, errno_ret(libc::EPERM));
}

#[test]
fn later_rule_still_sees_failed_args() {
    // Несовпадение проверок первого правила обязало уйти на второе.
    let prog = bpf::build_program(
        &[
            Rule::new(libc::SYS_openat, errno_ret(libc::EACCES))
                .check(2, bpf::Cmp::Eq(flag(libc::O_WRONLY))),
            Rule::new(libc::SYS_openat, libc::SECCOMP_RET_ALLOW),
        ],
        errno_ret(libc::EPERM),
    )
    .unwrap();

    // O_WRONLY попал в первое правило.
    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_openat),
            openat_args(0, flag(libc::O_WRONLY))
        ),
        errno_ret(libc::EACCES)
    );
    // O_RDONLY не совпал с проверкой первого правила и стал ALLOW второго.
    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_openat),
            openat_args(0, flag(libc::O_RDONLY))
        ),
        libc::SECCOMP_RET_ALLOW
    );
}

#[test]
fn arg_index_out_of_range_is_rejected() {
    let rule = Rule::new(libc::SYS_read, libc::SECCOMP_RET_ALLOW).check(6, bpf::Cmp::Eq(0));
    match bpf::build_program(&[rule], libc::SECCOMP_RET_ALLOW) {
        Err(BuildError::ArgIndexOutOfRange { arg }) => assert_eq!(arg, 6),
        Err(other) => panic!("ожидали ArgIndexOutOfRange, получили {other}"),
        Ok(_) => panic!("ожидали ArgIndexOutOfRange"),
    }
}

#[test]
fn rule_with_long_check_chain_is_rejected() {
    // 65 проверок Eq по 4 инструкции = 260 — уже за 8-битным лимитом.
    let mut rule = Rule::new(libc::SYS_read, libc::SECCOMP_RET_ALLOW);
    for _ in 0..65 {
        rule = rule.check(0, bpf::Cmp::Eq(0));
    }
    match bpf::build_program(&[rule], libc::SECCOMP_RET_ALLOW) {
        Err(BuildError::RuleTooLong {
            rule,
            instructions,
            limit,
        }) => {
            assert_eq!(rule, 0);
            assert_eq!(instructions, 260);
            assert_eq!(limit, bpf::RULE_CHAIN_LIMIT);
        }
        Err(other) => panic!("ожидали RuleTooLong, получили {other}"),
        Ok(_) => panic!("ожидали RuleTooLong"),
    }
}

#[test]
fn arg_checks_still_fit_jump_limit() {
    // Самая длинная из допустимых цепочек не вылезает за 8 бит перехода.
    let mut rule = Rule::new(libc::SYS_read, libc::SECCOMP_RET_ALLOW);
    for _ in 0..(bpf::RULE_CHAIN_LIMIT / bpf::cmp_instructions(bpf::Cmp::Eq(0))) {
        rule = rule.check(0, bpf::Cmp::Eq(0));
    }
    let prog = bpf::build_program(&[rule], libc::SECCOMP_RET_ALLOW).unwrap();
    // Самая длинная допустимая цепочка обязана собраться без ошибок (все
    // прыжки влезают в 8 бит — это гарантирует сама компиляция).
    // Причём аргумент, совпавший со всеми проверками, получает ALLOW.
    assert_eq!(
        execute_args(&prog, AUDIT_ARCH_X86_64, nr(libc::SYS_read), [0; 6]),
        libc::SECCOMP_RET_ALLOW
    );
}

// ── rust-надстройка ──────────────────────────────────────────────────

#[test]
fn rule_name_resolves_and_sets_action() {
    let rule = rule_name(&ACTION::Allow, "openat").expect("openat известен");
    assert_eq!(rule.nr, libc::SYS_openat);
    assert_eq!(rule.action, libc::SECCOMP_RET_ALLOW);
}

#[test]
fn rule_name_unknown_is_none() {
    assert!(rule_name(&ACTION::Allow, "definitely_not_a_syscall").is_none());
}

#[test]
fn rule_nr_rejects_scmp_error() {
    // -1 == __NR_SCMP_ERROR, приходит из resolve_name для неизвестных имён.
    assert!(rule_nr(&ACTION::Allow, -1).is_none());
    assert_eq!(
        rule_nr(&ACTION::Allow, libc::SYS_read).map(|r| r.nr),
        Some(libc::SYS_read)
    );
}

// ── Policy: allow-list / deny-list ───────────────────────────────────

#[test]
fn allowlist_permits_listed_and_blocks_others() {
    let prog = Policy::allowlist(ACTION::KillProcess)
        .allow("read")
        .expect("read")
        .allow("write")
        .expect("write")
        .compile()
        .expect("compile");

    assert_eq!(
        execute(&prog, AUDIT_ARCH_X86_64, nr(libc::SYS_read)),
        libc::SECCOMP_RET_ALLOW
    );
    assert_eq!(
        execute(&prog, AUDIT_ARCH_X86_64, nr(libc::SYS_write)),
        libc::SECCOMP_RET_ALLOW
    );
    assert_eq!(
        execute(&prog, AUDIT_ARCH_X86_64, nr(libc::SYS_getpid)),
        libc::SECCOMP_RET_KILL_PROCESS
    );
}

#[test]
fn denylist_blocks_listed_and_allows_others() {
    let prog = Policy::denylist()
        .deny("execve", ACTION::Errno(u16::try_from(libc::EPERM).unwrap()))
        .expect("execve")
        .deny("ptrace", ACTION::KillProcess)
        .expect("ptrace")
        .compile()
        .expect("compile");

    assert_eq!(
        execute(&prog, AUDIT_ARCH_X86_64, nr(libc::SYS_execve)),
        errno_ret(libc::EPERM)
    );
    assert_eq!(
        execute(&prog, AUDIT_ARCH_X86_64, nr(libc::SYS_ptrace)),
        libc::SECCOMP_RET_KILL_PROCESS
    );
    assert_eq!(
        execute(&prog, AUDIT_ARCH_X86_64, nr(libc::SYS_read)),
        libc::SECCOMP_RET_ALLOW
    );
}

#[test]
fn policy_accepts_raw_numbers() {
    let prog = Policy::allowlist(ACTION::Errno(u16::try_from(libc::EPERM).unwrap()))
        .allow_nr(libc::SYS_read)
        .compile()
        .expect("compile");

    assert_eq!(
        execute(&prog, AUDIT_ARCH_X86_64, nr(libc::SYS_read)),
        libc::SECCOMP_RET_ALLOW
    );
    assert_eq!(
        execute(&prog, AUDIT_ARCH_X86_64, nr(libc::SYS_getpid)),
        errno_ret(libc::EPERM)
    );
}

#[test]
fn policy_unknown_name_is_error() {
    let err = Policy::denylist()
        .deny("definitely_not_a_syscall", ACTION::Allow)
        .expect_err("ожидали ошибку");

    assert!(matches!(
        err,
        PolicyError::UnknownSyscall(name) if name == "definitely_not_a_syscall"
    ));
}

// ── Policy: проверки аргументов ───────────────────────────────────────

#[test]
fn policy_allow_args_passes_only_matching_args() {
    let prog = Policy::allowlist(ACTION::KillProcess)
        .allow("exit_group")
        .expect("exit_group")
        .allow_args(
            "openat",
            &[ArgCmp {
                arg: 0,
                op: bpf::Cmp::Eq(AT_FD_CWD),
            }],
        )
        .expect("openat")
        .compile()
        .expect("compile");

    // С нужным dirfd — разрешено.
    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_openat),
            openat_args(AT_FD_CWD, flag(libc::O_RDONLY))
        ),
        libc::SECCOMP_RET_ALLOW
    );
    // С чужим dirfd — default KILL.
    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_openat),
            openat_args(123, flag(libc::O_RDONLY))
        ),
        libc::SECCOMP_RET_KILL_PROCESS
    );
}

#[test]
fn policy_deny_args_blocks_only_matching_args() {
    let prog = Policy::denylist()
        .deny_args(
            "openat",
            &[ArgCmp {
                arg: 2,
                op: bpf::Cmp::Eq(flag(libc::O_WRONLY)),
            }],
            ACTION::Errno(u16::try_from(libc::EPERM).expect("errno влезает в u16")),
        )
        .expect("openat")
        .compile()
        .expect("compile");

    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_openat),
            openat_args(AT_FD_CWD, flag(libc::O_WRONLY))
        ),
        errno_ret(libc::EPERM)
    );
    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_openat),
            openat_args(AT_FD_CWD, flag(libc::O_RDONLY))
        ),
        libc::SECCOMP_RET_ALLOW
    );
}

#[test]
fn policy_nr_args_raw_variants_work() {
    let prog = Policy::allowlist(ACTION::Errno(
        u16::try_from(libc::ENOSYS).expect("errno влезает в u16"),
    ))
    .allow_nr_args(
        libc::SYS_getpid,
        &[ArgCmp {
            arg: 0,
            op: bpf::Cmp::Ge(0),
        }],
    )
    .deny_nr_args(
        libc::SYS_openat,
        &[ArgCmp {
            arg: 2,
            op: bpf::Cmp::Eq(flag(libc::O_WRONLY)),
        }],
        ACTION::Trap,
    )
    .compile()
    .expect("compile");

    assert_eq!(
        execute_args(&prog, AUDIT_ARCH_X86_64, nr(libc::SYS_getpid), [0; 6]),
        libc::SECCOMP_RET_ALLOW
    );
    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_openat),
            openat_args(AT_FD_CWD, flag(libc::O_WRONLY))
        ),
        libc::SECCOMP_RET_TRAP
    );
    assert_eq!(
        execute_args(
            &prog,
            AUDIT_ARCH_X86_64,
            nr(libc::SYS_openat),
            openat_args(AT_FD_CWD, flag(libc::O_RDONLY))
        ),
        errno_ret(libc::ENOSYS)
    );
}

#[test]
fn reexported_cmp_is_the_same_type_as_low_level() {
    // Реэкспорт из rust-слоя — это буквально типы из bpf: присваивание без
    // приведения должно компилироваться.
    let from_rust = uu_linux_kernel_seccomp::rust::ArgCmp {
        arg: 0,
        op: uu_linux_kernel_seccomp::rust::Cmp::Ne(1),
    };
    let from_low: bpf::ArgCmp = from_rust;
    assert_eq!(from_low.arg, 0);
    assert_eq!(from_low.op, bpf::Cmp::Ne(1));
}
