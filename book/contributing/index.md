# Contributing

## Build

```bash
# Device build (release firmware, size-gate + defmt path) -> RP2350 ELF
cargo build --release --target thumbv8m.main-none-eabi

# Produce the UF2 image
./build.sh
```

The device build links an `arm-none-eabi` ELF gated at `text` ≤ 3.5 MiB (CI-enforced). The image is trimmed via cargo features, not code edits: `emulation` swaps the transports for host TCP sockets, and per-app features mean an app crate absent from the firmware's device list is absent from the ELF.

`./build.sh` produces `firmware/fapico2.uf2` through `firmware/uf2gen.py` (plain `elf2uf2` output silently does nothing on this bootrom).

## Test

```bash
# Host tests
cargo test --target x86_64-unknown-linux-gnu --exclude fapico2-firmware

# Emulation: CCID + HID over TCP sockets
cargo build -p fapico2-firmware --no-default-features --features emulation

# Lint
cargo clippy --target x86_64-unknown-linux-gnu --exclude fapico2-firmware --all-targets -- -D warnings
cargo clippy --target thumbv8m.main-none-eabi -- -D warnings

# Full test suite (clippy + gates + pytest)
./run_tests.sh
```

Testing is three layers: host unit tests; the *same* black-box pytest suites that gate the C build over the emulator; and the hardware matrix.

## Contribute

See [`CONTRIBUTING.md`](https://github.com/eddieoz/fapico2/blob/main/CONTRIBUTING.md) for the full contribution guide, including gate rules, size ceilings, and code conventions.

## License

GNU AGPLv3 — see [LICENSE](https://github.com/eddieoz/fapico2/blob/main/LICENSE) and [NOTICE](https://github.com/eddieoz/fapico2/blob/main/NOTICE).
