# fapico2 fuzz targets (US-384)

`cargo-fuzz` targets for the **parsers** — the untrusted-input entry points that
receive attacker-controllable bytes straight off the wire. The property under
test: **malformed host input must not panic the device**. A `Result::Err` is a
*correct* response; a **panic** (which on the device is an undefined-behaviour /
reset vector) is the bug the fuzzer hunts for.

## Targets

| Target | File | What it fuzzes |
|---|---|---|
| `ctap_cbor` | `fuzz_targets/ctap_cbor.rs` | `fapico2_fido::cbor::decode` — the CTAP2 CBOR parser (command payloads). |
| `apdu_parse` | `fuzz_targets/apdu_parse.rs` | `iso7816::command::CommandView::try_from` (the ISO7816 APDU parser used by the OpenPGP + management apps) **and** `fapico2_fido::process_u2f_apdu` (the U2F / CTAP1 APDU parser). |
| `ccid_reasm` | `fuzz_targets/ccid_reasm.rs` | `fapico2_firmware::ccid_reasm::CcidReassembler` — the CCID bulk-OUT reassembler (US-920). Asserts the wedge-resync invariant, not only absence of panic. |
| `store_v3` | `fuzz_targets/store_v3.rs` | `fapico2_platform::store_v3` — the format-v3 secure-partition image (US-1050). Asserts round-trip identity, **image-nonce uniqueness across distinct plaintexts**, and fail-closed rejection of every truncation and every single-bit mutation. |
| `persist_sink` | `fuzz_targets/persist_sink.rs` | `fapico2_platform::persist_sink::FlashSlotSink` — the two-slot partition programmer (US-1051). Asserts that a matching slot is **skipped** (zero flash ops on the log), that a read-failing slot is always reprogrammed, and that a torn program leaves the previous good image bootable in the other slot. |
| `migration` | `fuzz_targets/migration.rs` | `fapico2_platform::migration::run` — the first-boot C→Rust record migration (US-1052). Asserts the C walker never reads outside the legal windows, no unbounded length reaches the store, and the destination store is left loadable with every migrated record stream framed exactly. |
| `attest_provision` | `fuzz_targets/attest_provision.rs` | `fapico2_fido::attestation::provision` — per-device attestation identity provisioning (US-1053). Asserts fail-closed: a present scalar slot is load-only, a corrupt one never regenerates. |
| `oath_tlv` | `fuzz_targets/oath_tlv.rs` | `fapico2_oath::oath_core` — the OATH TLV walker `nth_tlv` via the `PUT` APDU and the `oath.keystore.v1` restore (US-1054). Asserts every length is validated against the remaining buffer, a rejected PUT applies nothing, and a truncated persisted record is refused or canonical. |
| `fido_cred_state` | `fuzz_targets/fido_cred_state.rs` | `fapico2_fido::device_keystore` — the SOAK-FINDING-1 transactional commit (US-1055), driven through `vendor_state::with_keystore_ops` (the `grow_checked` seam) and `store_credential_checked`. Asserts a rejected commit latches nothing and the undo actually ran. |

The EPIC names these `fuzz/apdu_parse.rs` and `fuzz/ctap_cbor.rs`; they live one
level down in `fuzz/fuzz_targets/`, the directory `cargo-fuzz` requires. Each is
declared as a `[[bin]]` with `harness = false` and starts with `#![no_main]`
(libFuzzer's `-Zsanitizer=fuzzer` supplies `main`).

## Phase 6 — the six semantic targets (US-1050…US-1055)

The first three targets are *parsers*: for them, "does not panic" is the whole
property. The Phase-6 targets are not parsers. They sit at boundaries where a
wrong-but-quiet answer is worse than a crash — a repeated GCM nonce, a slot
that erases when it did not need to, a corrupt record that half-loads, an
attestation identity that silently rotates. For those, **absence of panic is
not a finding**: a sealer that returned a *constant* nonce round-trips
perfectly, and a `provision()` that regenerated on a corrupt certificate
returns `Ok`.

Each therefore asserts a named semantic invariant, and each has been shown to
go **red under a deliberately broken build of the code it covers** — that
mutation run is the deliverable, not a detail. The evidence (command and
output) is recorded in `.superpowers/sdd/report-P6.md`.

| Target | Story | Invariant(s) asserted | Mutation that makes it red |
|---|---|---|---|
| `store_v3` | US-1050 | seal/unseal identity; seal determinism; **distinct plaintexts never share an image nonce**; every truncation and every single-bit mutation refused; the boot decision never silently re-seeds damaged content | `store_v3::nonce_for` → a constant |
| `persist_sink` | US-1051 | a matching slot is **skipped** (zero flash ops); a read-failing slot is always reprogrammed; a torn program leaves the previous good image bootable in the other slot | drop the `slot_matches` skip (always erase); treat a read error as "matches" |
| `migration` | US-1052 | the walker never reads outside `[data_start, data_end+4)` or the rom-pool head words; no key/value exceeds the store bounds; the store stays a seal/unseal fixed point and every migrated `[fid][len][payload]` stream re-parses exactly | off-by-one in `push_tlv`'s length field; drop `Cfs::scan`'s `RecordOverflow` pool bound |
| `attest_provision` | US-1053 | with the scalar slot present, `provision` is **load-only** or refuses; the certificate slot is never rewritten; with it absent, a fresh identity is still minted (so the target cannot be satisfied by refusing everything) | route a corrupt scalar / wrong-size scalar / absent certificate back to the fresh-provision arm |
| `oath_tlv` | US-1054 | if a bounds-respecting walk cannot reach the KEY/NAME object, PUT must not answer `0x9000`; a non-`0x9000` PUT leaves `LIST` byte-identical; `0x9000` on a virgin app means a credential *was* stored; an unenforceable property bit (US-133) is refused; a truncated `oath.keystore.v1` either refuses to boot with the store untouched or is a persist/re-boot fixed point | clamp `nth_tlv`'s overrunning length instead of returning `None` |
| `fido_cred_state` | US-1055 | from a settled-clean keystore, a rejected commit leaves `persist_if_dirty` answering `false` (nothing latched) and the committed fields byte-identical; an accepted commit lands in the store and reloads | `dirty = true` instead of `dirty = dirty_before`, in `grow_checked` and in `store_credential_checked` |

These run on the same schedule as the parser targets (see the CI section
below), on their own matrix leg each so the job's wall time does not grow with
the target count.

## Why the host target is forced

The workspace `.cargo/config.toml` defaults the whole tree to the RP2350 device
target (`thumbv8m.main-none-eabi`). `cargo-fuzz` must build for a *hosted* target
(libFuzzer needs a C runtime), so `fuzz/.cargo/config.toml` overrides only
`[build].target` to `x86_64-unknown-linux-gnu`. The device-target `rustflags` /
`runner` stay scoped to `thumbv8m` and do not leak into host builds.

## Run locally

```sh
# One-time: nightly toolchain + cargo-fuzz.
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo +nightly install cargo-fuzz --locked

# From the repo root (the directory that contains fuzz/):
cargo +nightly fuzz build                    # build both targets
cargo +nightly fuzz run ctap_cbor -- -max_total_time=120
cargo +nightly fuzz run apdu_parse -- -max_total_time=120
```

A finding is written to `fuzz/crashes/<target>/`, and the CI workflow keys on
that directory being non-empty rather than on `cargo fuzz run`'s exit code
alone — cargo-fuzz exits non-zero both for a crash *and* for "no new coverage",
and a converged target should not turn the build red forever. `corpus/` and
`artifacts/` are gitignored build state.

## CI (`.github/workflows/fuzz-nightly.yml`)

Fuzzing no longer runs on every push. It runs on:

- **`schedule`** — nightly at `17 3 * * *` (UTC). The odd minute is deliberate:
  every other scheduled workflow on every other repository starts at `:00`,
  and that queue is measurably worse.
- **`workflow_dispatch`** — on demand, with optional `target` (single target)
  and `max_total_time` (default `900`) inputs.
- **`push`**, filtered to `fuzz/**` plus the eight source files the targets
  cover — so touching a parser gets you a run now rather than at 03:17.

All nine targets, `-max_total_time=900` each, one matrix leg per target so a red
target never hides the other eight. `fail-fast: false`, `timeout-minutes: 45`,
and `concurrency` with `cancel-in-progress: false` so a nightly never starts on
top of yesterday's still-running pass.

Crash reproducers (`fuzz/crashes/<target>/`) and the grown corpus are uploaded
as artifacts — 30-day and 14-day retention. A crash that exists only on a
runner that gets deleted in an hour is an anecdote, not a finding.

The run reports the reproducer directory explicitly and then honours
`cargo-fuzz`'s own exit code, so "converged" and "found something" stay
distinguishable in the log rather than collapsing into one non-zero exit. The
exit code stays authoritative because it also covers a build failure that never
reached the fuzzing loop at all, which no reproducer check can see.

### Why it moved

Measured over 2026-09-25..2026-10-02, the per-push smoke was 3,842 job-minutes
— 85% of every minute this repository spent in Actions. The section below this
one always described that smoke as a *regression* net rather than a
*discovery* engine, and said deeper runs were "intended to be scheduled (e.g.
nightly)". No scheduled workflow existed, so the regression smoke was doing
discovery work on every push at a budget too short to grow coverage across
runs anyway.

### What the schedule costs you, honestly

Fuzzing off the per-push path means a panic reachable from an untrusted
CTAP/APDU/CCID frame is no longer discovered before the change lands. It is
still discovered — nightly, or within minutes on a paths-filtered push — but
between nightly runs the tree is un-fuzzed with respect to that class of bug.
Two things keep the window bounded, and both are load-bearing:

1. `cargo test --workspace` and the pytest gate still run on **every** push.
   They are deterministic rather than exploratory, but they cover the parser
   unit cases — which is why the exposure is hours rather than days.
2. The semantic invariants the Phase-6 targets assert are **not** fuzz-only.
   Nonce uniqueness, fail-closed provisioning, and bootability after a torn
   program are each additionally covered by targeted unit tests, and the gates
   that police them — supply chain, attestation, persist, rng path — are
   untouched by this move and still run on every push.

If a target's code gets hot enough that "found within 24 h" is too slow,
restore it as a **short** per-push smoke rather than restoring the full 15
minutes. The 15-minute budget was never the load-bearing part; the
`cargo +nightly fuzz run <target>` invocation and the invariant set are.

## Scheduled full runs

The 15-min nightly run is a *regression* net, not a *discovery* engine. Longer
runs are the pass that seeds and mines the corpus — dispatch the workflow with
a larger `max_total_time`, or run locally:

```sh
# 8-hour run per target (overrides the 900s default):
cargo +nightly fuzz run ctap_cbor -- -max_total_time=28800
cargo +nightly fuzz run apdu_parse -- -max_total_time=28800

# …or a fixed number of executions regardless of wall time:
cargo +nightly fuzz run apdu_parse -- -runs=50000000
```

Run each target to a plateau (no new coverage across several hours) before
treating its corpus as a stable seed. `fuzz/corpus/<target>/` is seeded from
the committed corpora and the grown result is uploaded as an artifact, so
coverage can be carried forward deliberately instead of being rediscovered from
zero each night. A crash at any point still fails the run and drops the
reproducer into `fuzz/crashes/<target>/`, which the workflow uploads.
