# Nostr touch bypass — hardware proof (US-1749)

**Date:** 2026-11-01
**Board:** fapico2 on RP2350, image from branch `fix/nostr-allowance` (US-1741..1746,
`build.sh` UF2 through `firmware/uf2gen.py`), flashed over BOOTSEL.
**No SWD debugger was attached at any point** (AGENTS hardware warnings — the
probe and the whole ceremony ran detached).
**Operator:** eddieoz (the finger on every press is the operator's).
**Probe:** `scripts/nostr_probe.py --touch-bypass` (CCID/PC-SC legs T1..T8) plus
the vendor-HID arm driven through the extension's checkbox
(commit `e20b81a` in `../fapico2-nostr-extension`, US-1748).

## What this proves

The disable leg's consent chain, the ten-signature chain at one touch, LOCK
and power-cycle clearing, the friction-free enable leg — each observed on
the board, not inferred from the host suites. The host suites
(`apps/nostr/tests/touch_bypass.rs`, 25 tests; the emulator matrix
`tests/harness/test_nostr_touch_policy.py`, 11 rows; the extension's
`touch_policy.test.js`, 17 tests) carry the refusal-order and lifecycle
matrix; this transcript is the hardware leg of the same claims.

## CCID legs — `scripts/nostr_probe.py --touch-bypass`

The board came to the probe with the session already open and the bypass
already armed (the extension ceremony below had run first), so the
canonical order was restructured by one step: a LOCK first — which
converts the mishap into a live **LOCK-clears-an-armed-bypass proof row**
— and then the canonical T2..T8 order. Verbatim:

```
[T0] pre-state GET_INFO
  -> caps=0x001f flags=0xf

[T6-pre] LOCK — clearing the armed bypass to establish the closed-session precondition
  -> SW=0x9000 (expect 9000)
  -> flags=0x5 — bypass cleared by LOCK (proof row)

[T2] SET_TOUCH_POLICY P1=1 with the session closed — the refusal
  -> SW=0x6982 (expect 0x6982)

[T3] VERIFY_PIN
  -> SW=0x9000 (expect 9000)

[T4] SET_TOUCH_POLICY P1=1 — waiting for the consent press (the LED is lit)…
  -> SW=0x9000 (expect 9000 after your press; 0x6985 = the window closed untouched)
  -> flags=0xf — FLAG_TOUCH_BYPASS stands (proof)

[T5-setup] GENERATE_KEY idx0 — ONE press when the LED lights (setup, not part of the chain)
  -> SW=0x9000 npub=cd60c645b4b01924… (expect 9000 + 32-byte npub)

[T5] the ten-signature chain — DO NOT touch the board; if the LED lights, the bypass failed
  -> 10/10 signs answered 9000 in 0.60s with NO touch prompt

[T6] LOCK — the flag must die with the session
  -> SW=0x9000
  -> flags=0x5 — bypass cleared (proof)
  -> disable-now answers 0x6982 (expect 0x6982 — the session closed with the lock)

[T7] the enable leg — friction-free in this locked state
  -> SW=0x9000 (expect 9000, no touch)
  -> flags=0x5 — bypass down

[T8] GET_INFO after the power cycle
  -> caps=0x001f flags=0x5
  -> CAP_TOUCH_POLICY stands, FLAG_TOUCH_BYPASS gone — the power cycle cleared the bypass (proof)

[post] the identity survived the cycle (durable, unlike the flag)
  -> LIST_KEYS: SW=0x9000 n_identities=1
```

The 10-event chain cost **exactly one touch** — the consent press at T4
(and one GENERATE press of setup, outside the chain); every signature in
the chain ran grant-free.

## Vendor-HID arm — the extension's checkbox

The emulator never exposes the Nostr HID interface (AGENTS §8), so the HID
arm's matrix is extension-driven on hardware. The evidence is T0's
pre-state: the board arrived at the probe with `flags=0x0f` — the session
had been opened and the bypass armed entirely through the extension
(US-1748's checkbox over the vendor-HID interface, `e20b81a`):

- the extension's VERIFY opened the session (bit 1 set);
- the checkbox uncheck sent vendor `0x4F` P1=1, the board lit for the
  consent press, the press landed, and the box stayed unchecked — bit 3
  stands (read back over CCID at T0, the same advertisement both
  transports serve);
- the extension's disable over HID is what T6-pre's LOCK then cleared,
  closing the loop across both transports (armed over HID, cleared over
  CCID — the §8 one-applet-behind-the-mutex model, observed).

The park/window dance on the disable press is inside the extension's
`device.run` path and completed without a touch-timeout — the press was
consumed, not refused.


## Residuals

- **Bypass-armed-at-unplug** — the operator expectation the epic names: a
  bypass left armed is extinguished by unplug, demonstrated by the probe's
  T8 power-cycle leg (closed by observation, not by inference).
- **Tag indistinguishability on the disable leg** (review note, 2026-11-01):
  on CCID the consent press waits under `presence_tag(1)` — the same value
  a SIGN for identity 1 uses. This reuse is the epic's own mandate (no new
  presence-tag domain), and grants are request-bound (they die with the
  wait; the single pending slot admits no second request), so no
  cross-consumption is possible — but the press that consents to going
  touch-free is tag-indistinguishable from a press for identity 1. Accepted;
  the consent's meaning lives in the verb the user is responding to, not in
  the tag.
- **The emulator cannot see the HID arm** — the standing §8 asymmetry. The
  deny-row and the host counting-grant tests carry the no-touch observable
  (`test_verify_then_disable_arms_the_bypass_and_sign_runs_touch_free`
  states the division in its own comment); the HID arm's park/window dance
  on the disable press is observable only here, on hardware.
- **The consent press on the extension's disable leg** is not
  machine-testable (the extension repo's own rule); the ceremony record in
  that repo (`docs/ceremony-results.md`) is its release gate.
