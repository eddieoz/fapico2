# fapico2 v0.7.0 — Release Notes

**Date:** 2026-11-13 · **Target:** Raspberry Pi Pico 2 (RP2350), USB-connected
**Theme:** the touch bypass stops being a silent, unbounded weakening
(EPICs `NOSTR-BYPASS-ACCOUNTING` + `NOSTR-BYPASS-USABILITY`, US-1837..1856).
v0.5.0 shipped the consented, session-bound bypass as a bare flag: arm it and
the three signing arms ran touch-free until LOCK or power. That was the known
gap — a deliberate weakening with no accounting — and this release closes it.

## The accounting

- **A budget**: `BYPASS_CAP = 255` exempt operations per session. The number
  is derived, not chosen — 255 is the largest count the 1-byte budget field
  can name — and it is sized from the owner's live measurement that one
  user-visible action costs ~8 exempt operations (each signature fans out to
  every relay; the NIP-44 encrypt/decrypt pair rides alongside), so one
  session ≈ 30 actions.
- **A deadline**: `BYPASS_SESSION_MS = 600_000` (10 minutes) from the arm
  press, measured by an injected monotonic clock (`with_now_provider` —
  `tasks::now_ms` on the device, an emulator seam in tests; unwired it reads
  0 and can only mean "never expires", the fido audit ring's convention).
- **A ledger**: every exempt operation appends one 22-byte `AuditRecord` to a
  16-deep RAM ring, readable through the new **`GET_AUDIT`** command
  (CCID INS `0x20`, HID vendor byte `0x50`; v0.3 body
  `budget(1) ‖ n(1) ‖ age_ms(4 BE) ‖ records`). The sampled `age_ms` is what
  makes a client-side countdown computable — a device-monotonic stamp can
  never be related to a host's wall clock. The read is the first one the
  PIN-session gate covers: a sessionless host learns nothing, not even the
  budget.
- **The advertisement**: `CAP_BYPASS_ACCOUNTING = 0x0020` (caps now
  `0x003F`); `APPLET_VERSION` bumps to 0.3 (the body-layout bump); GET_INFO's
  flags bit 3 derives from the guards' own predicate
  `touch_bypass && budget > 0` — a spent budget reads as not armed on the
  wire while the session is still open.

## The clearing matrix, completed

LOCK, a failed verify, **SET_PIN on an already-set board** (the verb refuses
`SW_PIN_ALREADY_SET` but closes the session — and the bypass now dies with
it; US-1856's fix for the resurrection path VERIFY used to reopen), the
factory wipe, every boot and the lazy expiry all clear the bypass, budget,
clock stamp and ring together. Deselect/re-select preserves. Over the cap or
past the deadline the guards fall back to the touch — **the press is the
fallback, never an error**.

## The companion extension

The [Nostr extension](https://github.com/eddieoz/fapico2-nostr-extension)
v0.7.0 renders the state honestly: the bypass checkbox checked = *Bypass
active — signatures run without a touch* (arming is the checked direction;
the consent press belongs to it), a status line with a live countdown
(*bypass armed — N operations left · expires in M:SS*), a ledger of the
exempted operations, and a plain-words notice on boards predating the
surface. Boards on older firmware show *the bypass status needs a firmware
update — this board predates it* instead of nothing.

## Verification

- Host suite (`apps/nostr`): 37 tests, including the full clearing matrix
  and the two US-1856 behavioral fixes proven RED-without/GREEN-with.
- CCID emulator suites: 96 passed / 0 failed.
- `scripts/nostr_probe.py --audit` carries the board-side walk (the
  sessionless gate, the 255-signature burst, the ring shape, the
  post-budget touch fallback, LOCK); its refusal-path crash was fixed this
  release. The interactive hardware transcript remains the one open DoD
  item — see `docs/audits/2026-11-13-nostr-bypass-accounting.md`.
- Fresh-context code review + security audit on both repos: the findings
  (SET_PIN resurrection, the flag's stale advertisement, four copies of the
  expiry leg, the probe tuple bug, the extension's mock fidelity) are fixed
  in-tree; no Critical remains.
- Workspace version bumps to 0.7.0 — getInfo key `0x0E` now renders "0.7".
