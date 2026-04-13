# schedhint_ebpf

Standalone eBPF sampler for scheduler hints.

The eBPF side writes these maps:

- `SYSCALL_TOTAL`: per-syscall total
- `SYSCALL_BLOCKING_SCORE`: per-syscall blocking tendency score
- `SYSCALL_LAST_SEEN_NS`: per-syscall last seen timestamp
- `SYSCALL_CLASS_HIST`: global syscall class histogram

Note: this version intentionally avoids `bpf_get_current_pid_tgid` because some
StarryOS builds may not provide helper id `0x0e` yet.

The userspace side periodically reads these maps and prints snapshots that can
be consumed by a user-space scheduler.

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with the
target syscall entry symbol as argument:

```shell
cargo run --release -- <syscall_entry_symbol>
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package schedhint_ebpf --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/schedhint_ebpf` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, schedhint_ebpf is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
