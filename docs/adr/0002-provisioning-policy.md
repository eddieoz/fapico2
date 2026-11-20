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

**Tag convention:** release tags carry a `-release` suffix (`vX.Y.Z-release`). Tags exist
from `fapico2-release-alpha-v0.1.0` (2026-10-04) onward — all alpha-class, named
`fapico2-release-alpha-vX.Y.Z` — and **no `-release` boundary tag has been created yet**;
the convention binds from the first one. A `-release` tag asserts
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

## Amendment, 2026-11-20 — QC pre-warm is provisioning policy (FRESH-BOOT-SERVE, US-1922)

**Decision: every unit is powered once, to a completed boot, before sale.** The
2026-11-19 retail incident (two v0.7.0 units at Robocore parked dark on their
first boot — [`docs/audits/2026-11-19-retail-first-boot-dark-park.md`](../audits/2026-11-19-retail-first-boot-dark-park.md))
made this the cheapest control in the pipeline: one completed boot persists the
boot-entropy record and the identity material, and **permanently converts the
unit to the serve-while-warming path** — a board that has booted once never
again blocks enumeration on a stalled TRNG (firmware from 2026-11-20; ADR 0004
amendment 6). Zero firmware dependency on the QC step itself, no host needed:
power, watch, done.

**The completion instrument is the LED**, and it is pass/fail:

| what QC sees | verdict |
|---|---|
| boot ladder → warming blink (fast `.--.--.--.`, possibly with 5-second progress bursts) → **settles to a steady 1 Hz heartbeat** | **pass** — the unit has completed a boot; ship it |
| a **long-flash signature** (`0011`/`0100` — one ~1.2 s flash, pause, four bits) | **retry the power cycle** (off ≥ 5 s, replug). On v0.7.0's legacy path a stalled TRNG parks legibly here — at QC that is the desired outcome: the unit *selects against itself* instead of failing at a customer's desk. Two consecutive signatures = hold the unit back |
| ladder stops with no blink and no signature | infrastructure park (identity read) — hold back, do not ship |

The existing stock in the Robocore channel gets the same one-time power-on —
it can be done in the box, before the units reach a shelf. A board that fails
QC repeatedly (a TRNG that stalls across multiple power episodes) is a
hardware finding, exactly the thing QC exists to catch before sale.

**This is provisioning policy, not a firmware feature**: nothing in the image
changes, no gate runs on it, and the policy's whole content is "give each unit
one boot before it meets its owner". It sits in this ADR because it is a
pipeline decision about what a shipped unit has experienced, the same register
as the burn schedule the ADR already owns.
