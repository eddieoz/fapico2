# ADR 0002: Provisioning policy — profiles, deferred burns, and tag provenance

**Status:** Accepted (2026-10-03)
**Supersedes:** nothing
**Superseded by:** nothing
**Context docs:** [`docs/secure-storage-comparison.md`](../secure-storage-comparison.md) §6,
[`docs/tasks/EPIC-secure-storage.md`](../tasks/EPIC-secure-storage.md) Phase I,
[`docs/secureboot.md`](../secureboot.md).

## Decision

**fapico2 burns nothing irreversible into OTP in this phase of the project.** The
board-security controls the RP2350 offers — `CRIT1.SECURE_BOOT_ENABLE`, `CRIT1.DEBUG_DISABLE`,
`CRIT1.SECURE_DEBUG_DISABLE`, `CRIT1.GLITCH_DETECTOR_ENABLE` at max sensitivity, and durable
OTP page locks — are **defined, scheduled, and deferred** to a future provisioning epic. Until
that epic lands and is deliberately invoked, every board keeps its debug port available.

The posture is carried by **image provenance, not by build flags**:

| image class | debug port | irreversible OTP burns |
|---|---|---|
| alpha / beta images | **available** | **none** |
| `-release` tagged images | the boundary where the closure **will** apply — the mechanism is decided when the system is more mature | none today |

**Tag convention:** release tags carry a `-release` suffix (`vX.Y.Z-release`). The repository
currently carries no tags; the convention binds from the first tag. A `-release` tag asserts
"this image is the class the future provisioning epic targets", so a board's provenance is
readable from what flashed it.

## Why two different things must not be conflated

**Software debug is build state.** It is already stripped correctly: `dbg-log` is
release-forbidden by a `compile_error!` (`firmware/src/lib.rs:18-20`) and gated by
`tests/scripts/check_dbg_release_gate.py`; `apdu-trace` is capture-build-only. A release image
contains no software debug, and an automated build cannot change that.

**The debug port is device state.** `CRIT1.DEBUG_DISABLE` is an OTP fuse sampled by the
bootrom at reset (`pico-sdk/.../regs/otp_data.h:346-352`). CI cannot burn fuses, no build flag
reaches it, and once burned it is irreversible — a board that needs SWD afterwards cannot be
unlocked. Conflating the two would mean either burning fuses from a build script (wrong layer)
or believing a release build closes the port (it does not).

## What is deferred, with its prerequisites

The future provisioning epic inherits these recorded inputs; none of it is re-derived:

1. **`boot_key.rs` reconciliation — hard prerequisite.** `platform/src/boot_key.rs` is dead
   code (nothing calls it; the only `Otp` implementation is a test fake) whose row map does not
   match the bootrom: it models `rows: 48`, `first_key_row: 0x08`, 4 key slots,
   `OTP_ROW_BYTES: usize = 64` (`boot_key.rs:162, 318`), while the bootrom's key material lives
   at `BOOTKEY0 = rows 0x80–0x8F` and `BOOTKEY1 = 0x90–0x9B` — two slots, 16-bit ECC rows
   (`pico-sdk/.../regs/otp_data.h:1488-1760`), and `embassy-rp` reads ECC rows as `u16`
   (`otp.rs:50`). It must be reconciled or rewritten before any burn.
2. **A real `Otp` implementation** over `embassy_rp::otp` with ECC + raw write, blank-check,
   read-back verify, and a lock/raw-write surface (the current trait deliberately has none,
   `boot_key.rs:460-467`).
3. **Ordering constraint:** the signed image must be verified booting **before**
   `BOOT_FLAGS1.KEY_VALID` is set — the SDK header warns exactly this (`otp_data.h:742-748`).
4. **Durable page locks** for the key row (`0xE90`), closing the runtime-only `SW_LOCK` gap
   (D-14, `firmware/src/boot.rs:1157-1163`).
5. **Device-side provisioning command** on the rescue channel, presence-gated via the US-921
   grant model, one-shot, blank-row pre-flight.
6. **Host script** extending `build-signed.sh` / `otp_config.json` with the flag set, plus a
   gate that extracts the bootrom row constants from the SDK header and fails on drift.

**Revisit trigger:** system maturity — the signed-image flow proven end to end, the key-region
migration stable, and the per-record store landed. Until then, alpha/beta boards stay
diagnosable, which is the point: the boot-freeze investigation
(`docs/boot-freeze.md`) has one field diagnostic left — the LED rung ladder — and burning
debug shut before the storage refactor has even landed would make the known freeze class
permanently opaque on provisioned boards.

## What this decision does not change

- The **runtime-only** `SW_LOCK` on the key row still applies on every boot (`boot.rs:1565-1601`).
- Release **images** still ship with no software debug, by the existing gates.
- The refusal to boot without a usable OTP key row is untouched (`boot.rs:1191-1197`) — a
  missing root halts, it never falls back to a serial-derived key.
