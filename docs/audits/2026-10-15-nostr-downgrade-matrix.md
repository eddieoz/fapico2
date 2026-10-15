# The Nostr custody downgrade matrix — hardware transcript (US-1718)

**Date:** 2026-10-15 (protocol written ahead of the hardware session; the
result slots below are filled only from the board — a PENDING slot is not
evidence)
**Board:** sacrificial RP2350 (Pico 2), ceremony-completed, **no SWD debugger
attached at any point** (reads and flashes over BOOTSEL only)
**Images:** `fapico2-release-alpha-v0.2.0` UF2 (the extraction leg) and a
v0.1.x UF2 (the destruction leg), against this branch's ceremony build
**Probe:** `scripts/nostr_probe.py` (CCID) for the extraction leg's
record-by-record verdict; the destruction leg is driven by flashing and
observing the identity set

## Protocol

1. Flash the ceremony build; set a PIN; import two test identities; run
   `CEREMONY_START` (vendor byte `0x4E`, consent recorded here — this is the
   sacrificial board). Confirm `GET_INFO` reports the pending bit **cleared**.
2. **Extraction leg** — flash `fapico2-release-alpha-v0.2.0` over the
   ceremony-completed board. On the v0.2.0 image, run `EXPORT_KEY` (INS
   `0x1A`) against every populated slot and attempt a `LIST_KEYS` open of
   each record under the legacy KDF. **Expected: every record
   `Undecodable` — extraction closed.** Record the status words and the
   open failures verbatim below.
3. **Destruction leg** — flash a v0.1.x image. Attempt the identity
   enumeration. **Expected: the range does not survive — the old firmware's
   ordinary write path overwrites/tombstones it; the residual is
   destruction, not extraction.** Record what the old image reports.
4. Re-flash the ceremony build and record what (if anything) survived —
   the destruction residual's endpoint.

## Results

### Extraction leg — v0.2.0 over a ceremony-completed board

**PENDING HARDWARE SESSION.**

### Destruction leg — v0.1.x over the same board

**PENDING HARDWARE SESSION.**

### Endpoint — ceremony build re-flash

**PENDING HARDWARE SESSION.**

## Where the residuals live

The review's residuals (Arbiter R6) are recorded once, in
[ADR 0006's downgrade section](../adr/0006-nostr-pin-custody.md): downgrade
restores PIN-less destruction; the custom-firmware adversary is covered only
by O5's secure boot at the `-release` boundary (and O5 alone does not stop
downgrade without this data sealing); FIDO/OATH and PIN-less boards are
outside this protection. This transcript is the matrix evidence those
sentences cite; the ceremony's measured duration bound (the extension's
`CEREMONY_BOUND_SECONDS`) is transcribed from the same session.
