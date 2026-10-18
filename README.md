# uu-linux-kernel-seccomp

Чистый Rust-крейс для построения seccomp-BPF фильтров на x86_64.
Единственная зависимость — [`libc`](https://crates.io/crates/libc): никаких
биндингов к `libseccomp` и высокоуровневых обёрток, только «как в C».

Код, комментарии и документация — на русском (это осознанный стиль проекта).

## Два слоя

| Слой | Путь | Что там |
|------|------|---------|
| Низкий | `libc` | Сырые числа и libc: генератор BPF (`bpf`), дизассемблер (`dump`), чтение чужих фильтров через ptrace (`ptrace`), константы ядра (`consts`) |
| Высокий | `rust` | `ACTION`, `Policy`, проверки аргументов `Cmp`/`ArgCmp` — надстройка над нижним слоем |

Результат компиляции политики — просто `Vec<sock_filter>`; накладывает его
на себя (или на потомка после `fork`) сам вызывающий, через
`prctl(PR_SET_NO_NEW_PRIVS, 1, …)` + `seccomp(SECCOMP_SET_MODE_FILTER, …)`.
Готовой `apply()` в крейсе нет намеренно: сценарии наложения фильтра разные.

## Быстрый старт

Whitelist-политика: из файловых операций — только чтение (у `openat` во
флагах запрещены `O_WRONLY`/`O_RDWR`/`O_CREAT`), а `read`/`write` остаются
открыты, чтобы код после установки фильтра мог сообщить об ошибке. Всё
прочее — `EPERM`.

```rust
use uu_linux_kernel_seccomp::rust::{ArgCmp, Cmp, Policy, ACTION};

fn main() {
    let mut prog = Policy::allowlist(ACTION::Errno(libc::EPERM))
        .allow("read").unwrap()
        .allow("write").unwrap()
        .allow("exit_group").unwrap()
        .allow_args("openat", &[ArgCmp {
            arg: 2,
            op: Cmp::MaskedEq {
                mask: (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT) as u64,
                val: 0,
            },
        }]).unwrap()
        .compile()
        .expect("политика слишком велика");

    // no_new_privs — без него unprivileged-фильтр не поставится
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

        let fprog = libc::sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_mut_ptr(),
        };

        let rc = libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            &fprog,
        );
        // rc < 0 + errno — фильтр не принят
    }
}
```

## Проверки аргументов

Каждому правилу можно сопоставить цепочку проверок аргументов (до 254
инструкций на правило — `jt`/`jf` у BPF восьмибитные):

```rust
use uu_linux_kernel_seccomp::rust::{ArgCmp, Cmp, Policy, ACTION};

// mkdir разрешаем только с mode == 0o755 (arg 1)
let prog = Policy::denylist()
    .deny_args(
        "mkdir",
        &[ArgCmp { arg: 1, op: Cmp::Ne(0o755) }],
        ACTION::Errno(1),
    ).unwrap()
    .compile().unwrap();
```

Сравнения беззнаковые (как их видит ядро): «аргумент == −1» записывается
как `Cmp::Eq(u64::MAX)`. Полный набор операций:
`Eq` · `Ne` · `Gt` · `Ge` · `Lt` · `Le` · `MaskedEq { mask, val }`.

## Дамп фильтров

```
cargo run --example dump -q -- prog        # фильтры этой программы
cargo run --example dump -q -- -p 12345    # seccomp-фильтры процесса 12345
```

`-p` читает через `PTRACE_SECCOMP_GET_FILTER`; при Yama `ptrace_scope=1`
наблюдать можно только за потомками, а для чтения фильтров ядру нужен
`CAP_SYS_ADMIN` (его отсутствие даёт `EACCES`).

## Ограничения

* архитектура — x86_64; таблица сисколлов зашита в `define_syscall_table!`,
  номера разрешаются один раз через `resolve_name(name)` / `name_of(nr)`;
* на правило — не более 254 слов проверок; на программу — не более 4096
  инструкций ядра (`BPF_MAXINSNS`, ≈1364 простых правила); превышение —
  ошибки `RuleTooLong`, `ProgramTooLong`, `ArgIndexOutOfRange`;
* без `no_new_privs` (или root с `CAP_SYS_ADMIN`) фильтр поставить нельзя —
  это ограничение ядра, не крейса.

## Лицензия

MIT — см. [LICENSE-MIT](LICENSE-MIT).
