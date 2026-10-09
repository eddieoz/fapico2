# ADR 0003: TrustZone — deferred

**Status:** Accepted (2026-10-03)
**Supersedes:** nothing
**Superseded by:** nothing
**Context docs:** [`docs/secure-storage-comparison.md`](../secure-storage-comparison.md) §6,
[`docs/tasks/EPIC-secure-storage.md`](../tasks/EPIC-secure-storage.md) Phase ADR (US-1576).

## Decision

**Do not adopt Arm TrustZone in this phase of fapico2.** Record the ceiling, the cost, and the
revisit conditions; build no story, gate, or scaffolding for it in the storage epic.

## The ceiling (what we are leaving on the table)

TrustZone is the only RP2350 feature with a higher security ceiling than everything else in the
storage epic: key material resident in **secure SRAM**, unreadable from non-secure code, with
peripheral access attribution via ACCESSCTRL. Today every secret — store key, DRBG seed,
credential keys during an operation — lives in ordinary SRAM that debug-privileged or
glitched code can read; `DEBUG_DISABLE` (ADR 0002) closes the debug path, but a code-execution
bug in the single image can still reach everything.

## The cost (why deferred)

1. **Two-state execution is required for the isolation to mean anything.** The SAU has 8
   regions (`pico-sdk/src/rp2350/hardware_structs/include/hardware/structs/sau.h:28-64`), but
   in a single-state image, marking SRAM or DMA secure changes nothing — all masters share the
   attribute. Real isolation needs a secure-world key service plus a non-secure application
   image, with an IPC boundary between them.
2. **No scaffolding exists.** The SDK ships registers and ROM hooks
   (`pico_bootrom.h:94, 214, 1026`) but no secure-world runtime, no non-secure linker script,
   no TrustZone build template; `embassy-rp` has no SAU/TrustZone support at all. The secure
   side would be hand-written.
3. **No incremental path.** Unlike the OTP controls (ADR 0002), TrustZone cannot be adopted
   story by story — the first useful step is already the full two-state split.
4. **The storage refactor does not need it.** The per-record AEAD design
   (`docs/tasks/EPIC-secure-storage.md`) assumes flash is plaintext-readable and seals
   accordingly; RAM residency is being reduced to single operations (US-1572), which shrinks —
   without eliminating — the window TrustZone would close.

## Revisit conditions

Reopen this ADR when (a) the per-record key store is landed and measured, (b) a concrete
threat requires key isolation from the main image itself (not merely from an off-board
attacker), and (c) engineering capacity for a two-state image and a secure/NS IPC boundary is
available. Until then, `docs/archive/SECURITY-ASSESSMENT-ROUND2.md`'s TrustZone notes remain the
honest statement: acknowledged, deferred.
