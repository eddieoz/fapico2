# Contributing

Thanks for looking at fapico2 — the F**king Authenticator. This is firmware for
a hardware credential, so the bar for a change is "it works **and** the gate is
green", not "it builds".

## Before you start

Read [`SECURITY.md`](SECURITY.md). If you are fixing a vulnerability, that file
describes how to report it privately — do not open a public issue.

## Build and test

You need the RP2350 Rust target and an ARM linker:

```bash
rustup target add thumbv8m.main-none-eabi
sudo apt-get install -y gcc-arm-none-eabi
```

The three checks CI runs, in the order it runs them:

```bash
# 1. host unit tests
cargo test --workspace --target x86_64-unknown-linux-gnu --exclude fapico2-firmware

# 2. clippy, host target, all targets, warnings are errors
cargo clippy --workspace --target x86_64-unknown-linux-gnu \
  --exclude fapico2-firmware --all-targets -- -D warnings

# 3. clippy, device target
cargo clippy --target thumbv8m.main-none-eabi -- -D warnings
```

To produce a flashable image locally:

```bash
./build.sh            # unsigned: firmware/fapico2.uf2 + .elf
./build-signed.sh     # signed secure-boot image (needs a signing key)
```

**No build output is committed.** The UF2 and ELF are gitignored; CI produces
the release artifact from source. Do not commit one, and do not add an
exception to `.gitignore` for them.

## The gates

CI runs ~20 gate scripts under `tests/scripts/`, most of which encode a
constraint that was learned the hard way. They are not decoration — a change
that breaks one will be red.

Two rules make them worth taking seriously:

- **If a gate blocks you, do not delete or weaken it to make your change
  merge.** Read what it protects, and either satisfy it or argue for the
  change in the PR. Every gate in this repo exists because something went
  wrong without it.
- **A gate that guards a documented constraint must be updated when you change
  the constraint**, and the docs and the gate must move together.

Run them all locally before opening a PR:

```bash
for g in tests/scripts/check_*.py; do python3 "$g" || echo "FAILED: $g"; done
```

Some gates need a built ELF or the device image; run `build.sh` first.

## Changing a size number

Two ceilings are enforced, and both will fail your PR if you cross them
without saying so on purpose:

- `text` ≤ 3.5 MiB — the absolute backstop.
- `bss` ≤ SRAM − the main-stack ceiling — the number that decides whether the
  board boots at all. The `bss`→`MSPLIM` stack distance scales with the entry
  count, so raising a static can dark-boot the device *without failing the
  link*. If you add static, say so in the PR.

If you must raise a ceiling, do it deliberately in the CI config and record
why in [`docs/size-report.md`](docs/size-report.md). A ratchet with generous
headroom is a number nobody reads.

## Code that is load-bearing

- **The AID dispatcher** (`platform/`) is shared by every app. Do not add a
  second dispatch path.
- **The random path is single** (`platform/src/drbg.rs`). A second source of
  randomness is a gate failure, and correctly so.
- **There is exactly one allocator**, and it is sanctioned in `platform/`.
- **No key material may reach the repository.** `secrets/` is ignored except
  its README; `build-signed.sh` generates your key locally. There is a test
  (`platform/tests/no_signing_key.rs`) that fails if that changes.

## Commit messages and PRs

Explain *why*. The gates encode decisions that are not obvious from the code;
a PR that changes one should say what it now protects instead.

If your change affects the hardware matrix, the size budget, or the security
posture, say so explicitly and say how you verified it — `docs/hardware-matrix.md`
and `docs/size-report.md` are the record.

## Licence

By contributing you agree your work is licensed under GPLv3, the same terms as
the rest of the repository. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
