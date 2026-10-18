//! Тесты дизассемблера: формат листинга 1:1 как в `ceccomp dump`,
//! и корректная ANSI-раскраска.

use uu_linux_kernel_seccomp::libc::bpf::{self, Rule};
use uu_linux_kernel_seccomp::libc::dump::{dump, dump_colored};
use uu_linux_kernel_seccomp::rust::ACTION;

/// Действие `ERRNO` через высокоуровневый [`ACTION`].
fn errno_ret(errno: libc::c_int) -> u32 {
    ACTION::Errno(u16::try_from(errno).expect("errno влезает в u16")).to_ret()
}

/// `Rule` с действием `ALLOW`.
const fn allow(nr: i64) -> Rule {
    Rule::new(nr, libc::SECCOMP_RET_ALLOW)
}

// ── Без цвета: «золотой» вывод ───────────────────────────────────────

#[test]
fn dump_matches_ceccomp_layout() {
    // Одно правило (read → ALLOW), default = ERRNO(ENOSYS), фатальный
    // default для арки/x32.
    let prog = bpf::build_program(&[allow(libc::SYS_read)], errno_ret(libc::ENOSYS)).unwrap();

    let expected = "\
#Label  CODE  JT   JF      K
#---------------------------------
 L0001: 0x20 0x00 0x00 0x00000004 $A = $arch
 L0002: 0x15 0x01 0x00 0xc000003e if ($A == x86_64) goto L0004
 L0003: 0x06 0x00 0x00 0x80000000 return KILL_PROCESS
 L0004: 0x20 0x00 0x00 0x00000000 $A = $syscall_nr
 L0005: 0x35 0x00 0x01 0x40000000 if ($A < 0x40000000) goto L0007
 L0006: 0x06 0x00 0x00 0x80000000 return KILL_PROCESS
 L0007: 0x20 0x00 0x00 0x00000000 $A = $syscall_nr
 L0008: 0x15 0x00 0x01 0x00000000 if ($A != read) goto L0010
 L0009: 0x06 0x00 0x00 0x7fff0000 return ALLOW
 L0010: 0x06 0x00 0x00 0x00050026 return ERRNO(38)
#---------------------------------
";
    assert_eq!(dump(&prog), expected);
}

#[test]
fn dump_without_color_has_no_escape_code() {
    let prog = bpf::build_program(&[allow(libc::SYS_read)], errno_ret(libc::ENOSYS)).unwrap();
    let text = dump(&prog);
    assert!(!text.contains('\x1b'), "неожиданный ANSI-код в dump()");
}

// ── Операнды: syscall по имени, прочее по числу ──────────────────────

#[test]
fn unknown_operands_rendered_as_hex() {
    // nr = 0xffffffff не существует → печатается как число, а не имя.
    let rules = [Rule::new(0xffff_ffff, libc::SECCOMP_RET_ALLOW)];
    let prog = bpf::build_program(&rules, errno_ret(libc::ENOSYS)).unwrap();
    let text = dump(&prog);

    assert!(text.contains("if ($A != 0xffffffff)"));
}

#[test]
fn arg_compare_constants_rendered_as_hex_not_names() {
    // В проверке аргумента k — константа, а не номер сисколла: 0 и 1
    // обязаны печататься числами, а не `read`/`write`.
    let prog = bpf::build_program(
        &[Rule::new(libc::SYS_open, libc::SECCOMP_RET_ALLOW).check(1, bpf::Cmp::Eq(1))],
        errno_ret(libc::ENOSYS),
    )
    .unwrap();
    let text = dump(&prog);

    // Входное сравнение — по-прежнему по имени.
    assert!(text.contains("if ($A != open)"));
    // Константы проверок — hex.
    assert!(text.contains("if ($A != 0x00000000)"));
    assert!(text.contains("if ($A != 0x00000001)"));
    assert!(!text.contains("if ($A != read)"));
}

// ── Цвета ────────────────────────────────────────────────────────────

#[test]
fn dump_colored_marks_operands_and_actions() {
    let prog = bpf::build_program(&[allow(libc::SYS_read)], errno_ret(libc::ENOSYS)).unwrap();
    let text = dump_colored(&prog);

    // Жёлтый: константа арки и числовой операнд.
    assert!(text.contains("\x1b[33mx86_64\x1b[0m"));
    assert!(text.contains("\x1b[33m0x40000000\x1b[0m"));
    // Голубой: имя сисколла.
    assert!(text.contains("\x1b[36mread\x1b[0m"));
    // Красный: фатальные действия.
    assert!(text.contains("\x1b[31mKILL_PROCESS\x1b[0m"));
    assert!(text.contains("\x1b[31mERRNO(38)\x1b[0m"));
    // Зелёный: permitted.
    assert!(text.contains("\x1b[32mALLOW\x1b[0m"));
}

#[test]
fn log_action_is_green_like_allow() {
    let prog = bpf::build_program(&[], ACTION::Log.to_ret()).unwrap();
    assert!(dump_colored(&prog).contains("\x1b[32mLOG\x1b[0m"));
}
