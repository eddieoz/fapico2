# EPIC: US-413 — C-firmware data migration into fapico2 (Rust) v1.0.0

**Epic ID:** `RUST-MIGRATION-P6-413`
**Status:** Active — executed as stories S-413-1…S-413-7 of
[`EPIC-fapico2-phase6-acceptance-migration.md`](../../../docs/tasks/EPIC-fapico2-phase6-acceptance-migration.md)
(workspace-level, unversioned). This file is the separate US-413 epic the
parent epic's own rule requires ("write a separate epic before US-393").
**Created:** 2026-09-11
**Target repo:** `git/pico/fapico2/` (all story commits land here; unsigned).
**C reference tree:** `git/pico/pico-fido2/` — **frozen and read-only**;
analysis input only. Never modified, never referenced as a build dependency.

---

## Goal

An existing device that ran the C firmware (`pico-fido2`, USB identity
`20a0:42b2`) keeps its usable data when it is flashed with the Rust
firmware (`fapico2`, USB identity `fa20:0002`). On the **first Rust boot**
the firmware reads the C data partition on flash (strictly read-only),
re-derives the C key hierarchy where the C design exposes it without user
input, re-seeds the Rust SecureStore v2 slots, and sets a migration-complete
marker. Classes the C design seals behind a user passphrase (OpenPGP private
keys, PIN-wrapped FIDO keydev) migrate once, interactively, through a
**migration management APDU** (the single release-contract feature this epic
adds; no other new app features until after the US-393 cutover).

## Scope (story mapping)

All stories are defined verbatim in the Phase-6 epic; this epic owns their
scope:

| Story | Deliverable | Commit message (exact) |
|---|---|---|
| S-413-1 | This epic + `us413-migration-feasibility.md` + section gate script | `docs: US-413 migration epic + feasibility (US-413)` |
| S-413-2 | `platform/src/cflash.rs` runtime partition bounds + PICOBIN PT embed in `firmware/uf2gen.py` | `feat(device): RP2350 partition location + PT embed (US-413)` |
| S-413-3 | `platform/src/cfs.rs` read-only C flash FS walker | `feat(device): C flash FS reader (US-413)` |
| S-413-4 | `platform/src/ckey.rs` C key hierarchy derivation (kbase, keydev unwrap, PKOR/PKOC record crypto) | `feat(device): C key hierarchy derivation (US-413)` |
| S-413-5 | `platform/src/migration.rs` first-boot orchestrator + `main.rs` wiring | `feat(device): first-boot C data migration (US-413)` |
| S-413-6 | Migration passphrase APDU in the management app | `feat(device): migration passphrase APDU (US-413)` |
| S-413-7 | Hardware E2E on the real board with real C data; evidence in `us413-hardware-e2e.md` | `test(device): migration hardware E2E (US-413)` |

## Release contract (v1.0.0 delta)

> **v1.0.0 includes first-boot C→Rust data migration.** Migratable data is
> re-seeded automatically on the first Rust boot (silent classes). OpenPGP
> private keys and a PIN-wrapped FIDO keydev require the user's PW1/PIN once,
> supplied through the migration management APDU (S-413-6) with per-class
> status `MIGRATED | NEEDS_PASSPHRASE | NOT_MIGRATABLE | NONE | ERROR`.
> Devices whose keydev exists only in vendor-wrapped form
> (`EF_KEY_DEV_ENC 0xCC01`) are documented as **not migratable**.

This wording supersedes the pre-US-413 v1.0.0 scope in the parent epic and is
the contract the release notes (US-393) must restate.

## Out of scope

- **Vendor-wrapped keydev (`EF_KEY_DEV_ENC 0xCC01`)** — the wrapping key
  exists only in vendor custody; documented as not-migratable, no device-side
  recovery path.
- **C-region erase / reclaim** — the C data partition is never written,
  erased, or claimed by the Rust firmware in v1.0.0 (read-only guarantee is
  test-enforced in S-413-5). A later epic may reclaim the space.
- **TEE / CryptoCell gating of the Rust secure partition** — post-cutover
  hardening, out of this epic.
- **Any other new app feature** — the epic-level rule stands; the migration
  APDU is the sole exception, created by this contract.
- OpenPGP private-key *use* beyond migration completeness: OATH/OTP/OpenPGP
  **app-restore plumbing** (serving migrated data from the Rust apps) is
  post-cutover work; v1.0.0 preserves the data in keystore slots and
  documents that scope.

## Test strategy

- **Host TDD (every code story):** failing host test first with the exact
  named test; synthetic C-partition fixtures built by test utilities
  (record list incl. extended-length records, reversed order, all-0xFF,
  factory sentinels); known-answer vectors for every derived key (fixed UID +
  fixed OTP row, hand-checked against the C formulas before locking);
  wrong-key negative tests; read-only byte-identity assertion over the
  synthetic C region; idempotence (marker) test; malformed-APDU tests.
  Gates: `cargo test --workspace --target x86_64-unknown-linux-gnu --exclude
  fapico2-firmware`, clippy `-D warnings`, no-heap grep, device build +
  size gate (text ≤ 3,670,016 B).
- **Hardware BDD (S-413-7):** pre-registered Given/When/Then against the real
  board — C firmware first (`release/pico_fido2_pico2-1.0.uf2`,
  `20a0:42b2`), real data created (OpenPGP key with recorded passphrase, one
  FIDO credential, mgmt `EF_DEV_CONF` marker, OATH/OTP entries where tooling
  allows), then the Rust migration build (`fa20:0002`), migration APDU with
  the recorded PW1, and per-class assertions
  (`gpg --card-status`, sign operation, `fido2-token -I`, READ_CONFIG,
  OATH list, marker, second boot no-op). Verbatim evidence in
  `fapico2/docs/tasks/us413-hardware-e2e.md`.
- **Stop conditions / partial outcomes** per the Phase-6 epic (S-413-7:
  PIN-wrapped keydev with user unavailable ⇒ record `NEEDS_PASSPHRASE` path
  and mark the E2E partial; C tooling gap ⇒ fixture-backed substitute row).
