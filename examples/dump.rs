//! Демо-код для вывода seccomp-фильтров **другой** программы — аналог
//! `ceccomp dump -p`.
//!
//! Читает через `PTRACE_SECCOMP_GET_FILTER` все seccomp-фильтры указанного
//! процесса и печатает их в том же формате листинга, что и обычный `dump`.
//!
//! Ограничение (в частности, при Yama `ptrace_scope=1`):
//! * наблюдать можно **только за потомками** — целевая программа должна
//!   быть порождена той же сессией/процессом (fork от вашего терминала);
//! * ядро требует `CAP_SYS_ADMIN` для `seccomp_get_filter`, иначе вернёт
//!   `EACCES`.
//!
//! Пример (pid получен от `pidof`, как в оригинальном случае):
//! ```
//! cargo run --example dump -q -- -p 12345
//! ```
//! Типичный сценарий «только потомки»: запустите в своём шелле целевую
//! программу, она поставит фильтр и укажет pid (e.g. `pidof`), затем
//! из того же шелла вызовите `dump -p <pid>`.
//! Для НЕ-потомков это не сработает — Yama вернёт `EPERM`.

use std::io::{self, IsTerminal};

use libc::pid_t;
use uu_linux_kernel_seccomp::libc::{dump, ptrace};

const USAGE: &str =
    "dump -p <pid>   # печатает seccomp-фильтры процесса (pid должен быть потомком)";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(pid) = parse_args(&args) else {
        eprintln!("{USAGE}");
        std::process::exit(2);
    };

    if let Err(err) = run(pid) {
        eprintln!("dump -p {pid}: {err}");
        if err.raw_os_error() == Some(libc::EPERM) {
            eprintln!("подсказка: Yama ptrace_scope=1 — наблюдать можно только за потомками;");
            eprintln!(
                "           запустите целевую программу под этим же шеллом, а затем `-p <pid>`"
            );
        } else if err.raw_os_error() == Some(libc::EACCES) {
            eprintln!("подсказка: seccomp_get_filter требует CAP_SYS_ADMIN (запустите как root)");
        }
        std::process::exit(1);
    }
}

/// `["-p", "12345"]` → `Some(12345)`.
fn parse_args(args: &[String]) -> Option<pid_t> {
    match args {
        [flag, value] if flag == "-p" => value.parse::<i32>().ok(),
        _ => None,
    }
}

fn run(pid: pid_t) -> io::Result<()> {
    let filters = ptrace::seccomp_filters(pid)?;
    if filters.is_empty() {
        println!("(нет seccomp-фильтров)");
        return Ok(());
    }

    let colored = io::stdout().is_terminal();
    for (index, filter) in filters.iter().enumerate() {
        println!("# filter #{index}: {} инструкций", filter.len());
        let listing = if colored {
            dump::dump_colored(filter)
        } else {
            dump::dump(filter)
        };
        print!("{listing}");
    }
    Ok(())
}
