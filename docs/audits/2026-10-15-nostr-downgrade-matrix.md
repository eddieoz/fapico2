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

### Leg 0 — the custody ceremony itself (this branch, `d63256d`)

The ceremony ran across three flashes of the ceremony build; the third
completed. The two failures before it were themselves US-1718 findings and are
recorded because they are the device path's signature of bugs the host suite
cannot see:

1. **PIN-cache desync** (`0cc8bec`): on device the applet boots with a lazily
   attached region, so the PIN cache GET_INFO reports stayed `pin_set=false`
   after every power cycle — the custody gate stood open on a PIN-set board.
   A refused `SET_PIN` healed it fail-closed (flags walked `0x00` → `0x05`
   across a reboot). Fixed in the `process` preamble; seen on this board.
2. **Provider exhaustion** (`d63256d`): the ceremony's re-entry asks its
   provider for the region a second time, and the device provider was
   take-once — the second call got `None`, the applet answered `6F00` and
   stayed store-dead until reboot. First run: `CEREMONY_START` burned the OTP
   page (28 ms; 8 secret words + lock + marker) then died at the re-entry —
   the flash reseat never ran, so `GET_INFO` kept the pending bit. Second run
   on the burned page: 7 ms, idempotent-`Complete`, same `6F00`. The host
   suite never caught it because the emulator's provider re-opens its file per
   call; the device one could not re-mint. Fixed by staging a spare `FLASH`
   singleton and minting fresh handles (`boot::nostr_key_region_fresh`),
   take-then-mint in `main.rs::nostr_region`.

**Completing run** (OTP page 59 already `Complete`; the run resumes at the
re-entry and reseat):

```
[state] GET_INFO sw=9000 caps=0x000F n_identities=1 flags=0x05   (pin_set | pending)
[pin]   PIN already set — skipping SET_PIN
[pre]   LIST_KEYS sw=9000 n_identities=1
[run]   CEREMONY_START sw=9000 body=00060000  migrated=6 already=0
[run]   DURATION: 0.620 s
[post]  GET_INFO sw=9000 flags=0x01            (pending bit CLEAR — the flash reseat marker landed)
[post]  LIST_KEYS sw=9000 n_identities=1         (equals the pre count)
[post]  GET_PUBKEY idx0 sw=9000 len=95
```

**Measured duration bound:** 0.62 s for the completing run, on a board whose
OTP page was already burned (the idempotent-`Complete` path). A virgin-page
ceremony adds the eight secret-word burns, the lock and the marker —
sub-millisecond ECC writes each, bounded by the same run's shape. The
extension's `CEREMONY_BOUND_SECONDS = 60` keeps ~96× headroom over the
measured run and stands.

Consent: the user approved this ceremony against the sacrificial board
(in session); the OTP burn is irreversible, page 59 now reads `Complete`.

### Extraction leg — v0.2.0 over a ceremony-completed board

`fapico2-release-alpha-v0.2.0` (commit `ddc3875`, built from a clean worktree
via `build.sh`) flashed over the ceremony-completed board — the flash-resident
records are the ceremony's, re-keyed to the custody secret; the v0.2.0 image
derives its region key the legacy way, with no custody rows.

Result: the v0.2.0 applet **cannot read a single record** — stronger than the
per-record `Undecodable` the protocol anticipated. The AEAD authentication of
every custody-keyed record fails under the legacy key, and the enumeration
paths (which must open each record to report it) answer the store-fault word:

```
SELECT  AID F0 00 00 00 02        -> 9000   (applet selects; the fault is below the SELECT)
GET_INFO (×3)                     -> 6F00  6F00  6F00
LIST_KEYS (×3)                    -> 6F00  6F00  6F00
GET_PUBKEY idx0 / idx1 / idx3     -> 6F00           EXPORT_KEY same indexes -> 6F00
GET_PUBKEY idx2  (empty slot)     -> 6A82           EXPORT_KEY idx2        -> 6A82
```

The one non-`6F00` answer is reproducible and is the discriminating
observation: `6A82` is the applet's own "no such identity at idx" word, and
idx2 is an empty slot — reading it needs no record authentication, so the
v0.2.0 store attaches and the in-band refusal answers. The same attach then
fails on every **populated** record: the AEAD open under the legacy key
refuses, the command ends `6F00`. No plaintext, no scalar, no enumeration.
**Extraction closed.** No `EXPORT_KEY` ever returned key material,
touch-gated or not.

(The empty-slot `6A82` also shows the fault is per-record AEAD failure, not a
wedged flash window: the old image's own refuse-empty path still answers in
band on the same region.)

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
