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

```
(PENDING — the transcript is appended verbatim by the hardware run)
```

## Vendor-HID arm — the extension's checkbox

The emulator never exposes the Nostr HID interface (AGENTS §8), so the HID
arm's matrix is extension-driven on hardware:

```
(PENDING — the transcript is appended by the hardware run)
```

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
