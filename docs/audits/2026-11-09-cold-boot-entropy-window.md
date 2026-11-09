# The cold-boot entropy window, decoded: a 20.4 s settle that *succeeded* at the deadline tail

**Date:** 2026-11-09 (incident recorded from video the same day).
**Recording:** `/home/eddieoz/Downloads/20261109_231111_1.mp4` (60 fps,
29.76 s), of a boot the owner filmed after the board had been unconnected
for a long time — the established trigger.
**Predecessor:** [`2026-10-31-boot-dark-trng-refused.md`](2026-10-31-boot-dark-trng-refused.md)
(its §5 table predicted the *fatal* shape for a full-budget window; this
recording is the variant that table had no row for).
**Method:** frame-by-frame LED decode, the same one as 2026-10-31 — ffmpeg
downscale + gray luminance of the bright-spot region where the LED glows
through the silicone case at the button hole (center ~(0.855, 0.273) of
frame, 11×9 box mean, threshold 162), no SWD ever.

**Outcome of this boot:** the board **booted** — the dark window ended in a
successful boot, heartbeat and all. That fact is the finding: it proves the
window is the `otp_retry` retry budget being *consumed*, not a fatal path,
and it is the first hardware measurement behind D-8.

## 1. The recording, decoded

| time (s) | LED | decoded |
|---|---|---|
| 0.00–2.50 | dark | pre-ladder (HAL init) |
| 2.50–3.30 | 10 pulses, ~80 ms period | ladder through `RUNG_STORE` (cumulative 1+2+3+4) |
| 3.30–23.67 | **dark 20.37 s** | the window — the `otp_retry` budget consumed in full |
| 23.67–24.03 | 5 pulses | `RUNG_DRBG` (cumulative 15) |
| 24.58–25.02 | 6 pulses | `RUNG_MIGRATION` (cumulative 21) |
| 25.25–27.17 | ~23 pulses | `RUNG_APPS`+`USB`+`SERVING` (cumulative 45) |
| 27.22 → | 500 ms on / 500 ms off | 1 Hz heartbeat — **serving** |

The decode table is stated in the **cumulative** terms of the flashed image
(the board's image predates `bootphase.rs`'s linear 9-pulse encoding; the two
instruments coexist — `bphase!` cumulative under `dbg-log`/`boot-timeline`
vs `mark!`/`boot_led` linear — and this board runs the cumulative one).

## 2. Which site

The window sits between `RUNG_STORE` and `RUNG_DRBG` — a boot region that
contains only `ensure_boot_entropy` (`main.rs:783`) and `init_drbg`
(`main.rs:807`). Two observations name it precisely:

1. **No 400 ms draw notice appears anywhere in the recording.**
   `ensure_boot_entropy` emits `entropy_draw_notice` (one 400 ms lit pulse)
   before its first attempt whenever the record is absent — the only path
   through it that can wait. The notice's absence means `ensure_boot_entropy`
   skipped: the `boot.entropy.v1` record was present, and the entire window
   is inside `init_drbg`.
2. **Within `init_drbg`, the identical OTP read had already succeeded
   without a pause** ~100 ms earlier (`derive_boot_store_key` runs
   `read_otp_key_1`; the 10-pulse group is uninterrupted). The only
   remaining consumer is `FuseSeedSource::seed`'s TRNG nonce draw —
   `probe_bytes`, two EHR blocks — the same marginal consumer as the
   2026-10-31 14:16 park (§7 of the predecessor audit).

So: **the window is `init_drbg`'s `otp_retry` budget being consumed by the
TRNG nonce draw.**

## 3. The budget is measured-marginal, and this is the success-tail variant

The window lasted **20.37 s ≈ `DEADLINE_MS` itself**: the draw succeeded on
the final attempts of the 20 s budget. That makes two readings at once:

- **First hardware measurement behind D-8.** The settling time of a cold
  power episode on this board is **≥ 20.4 s** — the budget was sized as a
  datasheet average × 10 (D-8's own caveat: "not a measured maximum"), and
  the measurement now says the *episode-level* settling exceeds it.
- **A reading the 2026-10-31 audit's §5 table did not have.** Its table
  predicted only the fatal shape for a full-budget window: consume the
  budget → emit a signature → park. This recording consumed the budget and
  **succeeded**. Three parked episodes (`0011` on 2026-10-31, `0100` on
  2026-10-31 14:16, plus the owner's repeated post-unplug failures) and one
  success-tail now bound the same phenomenon from both sides: the settle is
  sometimes < 20.4 s, sometimes > 20 s with the tail crossing the deadline.

## 4. The trigger correlation

The owner's operating observation, across episodes: the stall occurs **after
the board has been unconnected for a long time**; the first connection of
the episode shows either the fatal shape (blink > ~20 s dark > blink > dark)
or the success-tail shape (blink > ~20 s dark > blink > boots). Every
subsequent boot in the episode — and warm replugs generally — boots
normally. This matches the 2026-10-31 §7 incident ("after some time
unplugged") and the E16 settling precedent the OTP reads already established
on this board.

## 5. Fix landed and discriminating readings

The fix (EPIC `COLD-BOOT-ENTROPY-WINDOW`, US-1800…US-1814) changes only the
two boot-entropy sites:

- **`ENTROPY_DEADLINE_MS = 60_000`** — the entropy draws get their own
  budget, ≥ 2× the measured 20.4 s floor, separate from the OTP reads'
  20 s (which stay silent and park immediately, unchanged).
- **The wait-blink** — during an entropy wait the pin drives 80 ms lit /
  170 ms dark (`.--.--.--.`), so a 60 s window never reads as a dead board.
- **Bounded reboot-not-park** — a refusal after the whole budget reboots and
  re-rolls, a magic-guarded `.retain` counter bounding the loop at
  `MAX_REFUSED_BOOTS = 3`; only then does the board park, with the same
  `0011`/`0100` signature it would have emitted immediately.

### Reading a board with this build

| reading | meaning |
|---|---|
| ladder, then `.--.--.--.` for up to ~60 s | entropy settling — the board is **working**; do not unplug |
| ladder, blink window, board leaves the bus and re-runs the ladder | a window refused; the board is on attempt 2 or 3 of 3 (bounded reboot) |
| three refused windows, then `0011`/`0100` once | the bound expired; park, legible as before — power-cycle-5 s per `docs/boot-freeze.md` |
| ladder, dark ~20 s (blink-free), `0100`/`0011` once | an **OTP** read refused — unchanged behaviour, park immediate |

The hardware validation leg (US-1813) records the actual decode of the
fixed build in §6 below when it is run.

## 6. Hardware validation (fixed build)

*Not yet run* — this section carries the decode table of the fixed build
when the owner flashes it and records a cold episode (US-1813). The open
question it answers: does `SCB::sys_reset` clear the settling (so the
rebooted boot's window is short), or does only VBUS removal — in which case
the bound is what catches a hard wedge.
