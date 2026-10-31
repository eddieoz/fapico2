# fapico2-release-alpha-v0.3.2 — Release Notes

**Date:** 2026-10-31 · **Target:** Raspberry Pi Pico 2 (RP2350), USB-connected
**Theme:** the boot-refusal release (PR
[#22](https://github.com/eddieoz/fapico2/pull/22)) — the intermittent dark
boot is root-caused from a board video, and the fragile verification behind
it is fixed without giving up the guarantee it enforced.

**This is an alpha.** Alpha/beta images keep the debug port available and burn
nothing irreversible into OTP ([ADR 0002](adr/0002-provisioning-policy.md)).

## The intermittent dark boot: root cause and fix

The failure: some power cycles produced a board that flashed **ten fast
blinks, one long flash, then four rhythm flashes** and went dark, never
enumerating — recoverable only by power-cycling many times, with no pattern
to when it would return.

The investigation ([docs/audits/2026-10-31-boot-dark-trng-refused.md](audits/2026-10-31-boot-dark-trng-refused.md))
decoded the LED pattern frame-by-frame from a phone video against the
firmware's own instruments: the ten blinks are the boot ladder crossing the
secure-store milestone, and the flashes after it are a **fatal signature
`0011` — `TrngRefused`** — from `ensure_boot_entropy`. The board was never
hanging; it was *refusing to boot on purpose*, and naming the reason.

The verification that refused: the boot guarantees the `boot.entropy.v1`
record — 32 bytes of hardware-TRNG entropy that seed every key the device
derives — by drawing from the TRNG under a **20 ms-per-block deadline, fatal
on a single miss**. That draw only runs on boots whose store starts empty
(first boot, or the first boot after a factory reset or nuke), which is why
failures clustered after reflashes and resets, and why healthy runs followed
once one draw succeeded: the record persists at the boot persist gate, which
a refused boot never reaches — so every power cycle re-rolled the dice.

Two things could miss the 20 ms budget: a generation tail beyond 10× the
datasheet's *average* (the budget was reasoned, never measured on silicon —
divergence D-8), and the RP2350's `AUTOCORR_ERR` health-test failure, which
the datasheet documents as dead "until next reset" — a wedge no amount of
waiting cures within one power episode.

The check itself is load-bearing and does not move: the record is the DRBG's
seed input, everything pre-USB derives from it, and the fail-closed posture
(ADR 0004) is unchanged. What changed is that a single missed window no
longer kills the boot:

- **the draw is retried** on a stepped budget (250 ms steps, 20 s) — the same
  treatment this board's flaky OTP reads already receive for the same class
  of settling fault. Each attempt is a full fresh peripheral cycle; a refused
  attempt scrubs its buffer. Only a source that refuses across the whole
  budget parks the board, with the same `TrngRefused` signature as before.
- **the record-absent path is now visible**: one ~0.4 s LED flash before the
  first draw attempt, on boots where the store started empty. On current
  firmware, a healthy fresh-store boot shows: pulse groups → 0.4 s flash →
  more pulses → the 1 Hz heartbeat. A ~20 s pause after the flash is the
  retry budget, not a hang. If the flash is followed (after ~20 s) by the
  `0011` signature, power-cycle with 5+ seconds off — and report it: that
  would be the hardware wedge surviving every retry.

## For users: the book now teaches the boot LED

The LED is the one diagnostic that works when the failure *is* "won't
enumerate". The new [troubleshooting chapter](../book/troubleshooting/index.md)
covers all four patterns (boot ladder, fatal signature, the 0.4 s draw
notice, the heartbeat), the ladder-count → milestone table, the signature
bit-reading rules (long gap = 0, short gap = 1, MSB first), the full reason
table with recovery actions, and the 5-second power-cycle discipline.
Writing it surfaced a documentation inversion in `fatal_sig.rs`'s module doc
(it described the bit encoding backwards against its own constants) — fixed.

## Upgrading from v0.3.1

Nothing to do. No data-format change, no storage migration, no new refusal a
conforming client reaches. The only visible differences: a fresh-store boot
now shows the 0.4 s draw notice (and may pause up to ~20 s while the draw is
retried), and a board that would previously have gone dark silently now
either boots or names its reason on the LED.

## Verification

All twelve CI checks green on the exact content this tag names, including
both clippy gates (`-D warnings`), 1,867 host tests, the full emulator suite,
the six structural gates and cargo-deny/cargo-vet. The device-integration
gate: boot chain 93,764 B ≤ 98,304 B (4.6 % margin — the fix grew no stack
frame), and the task-arena demand re-measured at 14,344 B with the stamp
refreshed after this release's documentation edits. Hardware validation: a
post-nuke first boot recorded on video decodes to all 45 ladder pulses, the
draw notice where designed, and a healthy heartbeat (audit doc §6).
