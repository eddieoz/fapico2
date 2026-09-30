# ADR 0001 — RSA in Rust for PIV / OpenPGP: ECC-only baseline, RSA deferred

- **Status:** Decided
- **Date:** 2026-09-05
- **Owner:** RUST-MIGRATION epic (Phase 2 → Phase 4 hand-off)
- **Supersedes:** —
- **Superseded by:** —
- **Governs:** Phase 4 (US-371…US-378), in particular US-376 ("PIV sign/decipher — RSA, 2 pts, *only if ADR chose RSA*").

---

## Context

Phase 4 (PIV) is gated by a single scoping decision: **does `fapico2` implement RSA
sign/decipher for PIV and OpenPGP, or is it ECC-only?** This decides whether Phase 4
carries one extra ~2-pt story (US-376) and a vendored crypto implementation, or stays
within the ECC surface the current stack already covers.

Facts established by the spike and the build:

1. **No heap on device.** The EPIC hard constraint is *no `#[global_allocator]`*; device
   code is `heapless` + trussed keystore only, and CI enforces this with a grep-gate
   (US-383). RSA-2048 sign/decipher is memory-hungry — the `rsa` crate and trussed's
   RSA stack both need sizable scratch buffers or dynamic allocation.
2. **`trussed-rsa-alloc` is host-only.** It is an *optional* opcard dependency pulled in
   by the `virt` feature (the emulation/host backend). It does **not** run on the
   `thumbv6m-none-eabi` device path, which uses a real Trussed platform over
   `embassy-rp`. There is therefore no device-side RSA primitive available today.
3. **Flash gate.** RP2040's 2 MB is the size gate (RP2350 rides free). A vendored
   pure-Rust RSA-2048 implementation adds on the order of 150–300 KB of flash and large
   static buffers — meaningful headroom against the C baseline (530,980 B text) once the
   FIDO/OATH/OTP/Management apps are integrated.
4. **No import-compat to preserve.** Per Q3 / US-413, device data does **not** migrate from
   the C firmware (`trussed` keystore ≠ `files.h` flash layout); fresh install is the
   default. So RSA key compatibility with keys already on a C-firmware card has no value —
   there is no existing-device fleet that would lose RSA support by going ECC-only.
5. **The current stack is ECC-complete for what the suites exercise.** `opcard` + trussed
   provide ECDSA (NIST P-256/384/521, brainpool) and X25519/Ed25519 signing/decipher, and
   the OpenPGP suite's non-RSA paths pass at or near the C baseline in isolation (see
   `docs/tasks/openpgp-suite-report.md`). PIV's modern signing/verification surface is fully
   coverable by ECDSA/ECDH.

## Decision

**`fapico2` is ECC-only for both OpenPGP 3.4 and PIV. RSA sign/decipher is deferred, not
permanently rejected.**

- OpenPGP (Phase 2): keep the current ECC surface; RSA suite paths (`rsa2k` keygen/import/
  sign/decipher) remain **skipped**, consistent with the emulation skip posture and an
  ECC-only device. No RSA code is added to `apps/openpgp` or `vendor/opcard`.
- PIV (Phase 4): implement slots 9a/9c/9d with **ECDSA + ECDH only** (US-375). US-376
  (RSA ops) is marked **"not in scope under this ADR"** and does not carry the ~2 pts.
- `NOTICE` / licensing: no new RSA crate is vendored, so no additional NOTICE entry is
  required today.

RSA is *deferred* rather than rejected so a future business need can be evaluated without
re-litigating the stack choice. Reopening it requires a **new ADR** (see Consequences),
because it changes the memory model and size budget, not just adds a feature.

## Consequences

### Makes easier
- Stays within the no-heap device contract; US-383's grep-gate stays trivially green.
- Keeps the 2 MB flash gate achievable with headroom after all apps are integrated.
- Lets Phase 4 ship PIV signing/verification on schedule without a ~2-pt RSA story or a
  vetted, audited RSA implementation (RSA is where crypto bugs are most costly).
- The OpenPGP suite's skip posture matches the C baseline; no suite edits needed.

### Makes harder / open items
- **Enterprise/RSA-only PIV** (some government, CAC, and corporate smartcard profiles that
  require RSA-2048 in slots 9a/9c) is **not supported**. If required, it must go through a
  follow-up ADR that also resolves:
  - *Memory model*: a heap allocator on device (would relax the no-heap gate — a deliberate,
    reviewed trade-off) **or** large static scratch buffers for a pure-Rust RSA.
  - *Flash cost*: vendored `rsa` crate impact on the 2 MB gate, measured in `US-382`'s size
    report.
  - *Audit*: any RSA implementation must be reviewed before shipping — this is the primary
    reason to decide explicitly *now* rather than silently.
- **Import-compat**: an ECC-only device cannot open RSA keys produced by the C firmware. This
  is acceptable because C-firmware data does not migrate (US-413); documented here so it is a
  known, accepted consequence rather than an oversight.

### Verification recorded here
- `trussed-rsa-alloc` confirmed optional and `virt`-feature-gated in `vendor/opcard/Cargo.toml`;
  absent from the `thumbv6m-none-eabi` device dependency closure.
- OpenPGP non-RSA suite paths pass at/near baseline (see the Phase 2 gate report).
- This ADR is the governing scope doc referenced by US-342; Phase 4 begins from it.
