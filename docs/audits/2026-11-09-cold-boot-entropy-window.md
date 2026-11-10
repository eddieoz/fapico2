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

The hardware validation leg (US-1813) is §6 below: the 1-minute-dwell
observation (warm path unchanged) and the long-dwell episode that answers
the epic's open question.

## 6. Hardware validation (fixed build)

**First observation — 2026-11-10 00:40, the board that reproduced the stall,
fixed build flashed over BOOTSEL** (rescue `REBOOT(BOOTSEL)` →
`fapico2.uf2` sha256 `9fc33491…`, re-enumerated `fa20:0002` and serving).
Episode: board unpowered for **1 minute**, then filmed from the replug
(`20261110_004056_1.mp4`, 60 fps, 9.29 s, macro framing — LED spot tracked
at ~(935, 200) of 1296×604).

| time (s) | LED | decoded |
|---|---|---|
| 0.00–2.32 | dark | pre-ladder (HAL init) |
| 2.32–3.50 | 15 pulses, 80 ms period | cumulative ladder through `RUNG_STORE`(10)+`RUNG_DRBG`(15) — **no window between them** |
| 3.50–4.08 | dark 0.58 s | inter-phase gap |
| 4.08–4.52 | 6 pulses | `RUNG_MIGRATION` (cumulative 21) |
| 4.52–4.75 | dark 0.23 s | inter-phase gap |
| 4.75–6.72 | 24 pulses | `RUNG_APPS`+`USB`+`SERVING` (cumulative 45) |
| 6.72 → | 0.52 s on / 0.48 s off | 1 Hz heartbeat — **serving, ~6.7 s after power-on** |

Pulse counts are duration arithmetic (span ÷ 80 ms period), which the frame
granularity makes exact where per-pulse counting is not (a 40 ms pulse reads
as 1–2 frames and flickers across the threshold).

**Findings:**

1. **The cold episode did not reproduce at a 1-minute dwell.** The draw was
   warm: no `.--.--.--.` window, no dark stretch, and no 400 ms draw notice
   (the `boot.entropy.v1` record was present; `ensure_boot_entropy` skipped
   and `init_drbg`'s seed draw succeeded on the first attempt). The settling
   trigger therefore needs a **longer unpowered dwell than 60 s** — the
   owner's established trigger is "unconnected for a long time", and one
   minute after a serving episode does not re-arm it. This bounds the
   phenomenon from below in a new dimension: the ≥ 20.4 s settle of §3
   belongs to *long*-dwell cold episodes, not to every power gap.
2. **The warm path is behaviourally unchanged.** The blink window, the
   bigger budget and the bounded reboot are invisible when the draw succeeds
   immediately — the boot completes in ~6.7 s, ladder and heartbeat
   identical to the pre-fix image's warm boots. No regression on the path
   every normal boot takes.

### The long-dwell episode (2026-11-10 09:05, US-1813 — the video that answers the epic)

The board unplugged overnight (~8 h), filmed from the replug
(`20261110_090552.mp4`, 60 fps, 284.4 s; owner-cropped LED view
`lv_0_20261110094401.mp4` decoded — green-dominance channel, the white
keyboard backlight rejected; the cropped video's framing put the LED under
30 fps, so ladder pulses read as 1-frame LITs and are distinguishable from
the blink's 3-frame LITs). The owner's account: it did not initialize on
the first try; the recording ends with the device going dark; after a few
power cycles it initialized correctly, the blinking window preceding the
successful boot.

| time (s) | LED | decoded |
|---|---|---|
| 0.00–1.27 | dark | power-on, pre-ladder |
| 1.27–2.07 | 10 pulses (1-frame LITs) | **boot 1 ladder** — cumulative through `RUNG_STORE`, no draw notice: record present, window is `init_drbg`'s |
| 2.13–~65 | `.--.--.--.` (3f LIT / 5f dark) | **window 1** — wait-blink 80/170, one pair per 250 ms step |
| 67.07–67.87 | 10 pulses | **boot 2 ladder** — refusal #1, bounded reboot, re-run from the top |
| ~67.9–~131 | `.--.--.--.` | **window 2** — same length as window 1 |
| 132.87–133.67 | 10 pulses | **boot 3 ladder** — refusal #2 |
| ~133.7–~197 | `.--.--.--.` | **window 3** |
| 198.43–199.47 | 10 pulses | **boot 4 ladder** — refusal #3, the bound |
| ~199.5–264.3 | `.--.--.--.` | **window 4** |
| 264.50–265.70 | LIT 1.20 s | fatal-signature preamble |
| 266.30, 267.10, 267.50, 268.30 | 4 × 200 ms bits, gaps 0.6 / 0.2 / 0.6 / ∞ | bits `0,1,0,+0` → **`0100` = id 4, `DrbgRefused`** |
| 268.50 → end | dark | **the park** — permanent until VBUS removal |

**Every US-1813 assertion is met, and the open question is answered:**

1. **The window blinks instead of sitting dark** — four windows, the exact
   80/170 rhythm, `.--.--.--.` from the first failed attempt of each boot
   to its last; the owner watched a working board for 4½ minutes instead
   of a dead one.
2. **A refusal reboots and re-runs the ladder** — three of them, decoded
   at 67.07, 132.87, 198.43; the board leaves the bus, the ladder runs
   from the top, the owner sees attempt 2, 3, 4.
3. **`SCB::sys_reset` does not clear the settling.** The rebooted boots'
   windows are all the same length (~63–65 s each — the 60 s sleep budget
   plus per-attempt wall time). Four consecutive boots spanning ~4.4
   minutes all refused their whole budgets; only the owner's VBUS power
   cycles cleared the episode. The reboot buys re-rolls, not warmth —
   the bound is not an optimization but the load-bearing half of the
   design, and this episode is exactly the wedge it exists for.
4. **The bound parks legibly** — signature `0100` (`DrbgRefused`), the
   same id the 2026-10-31 14:16 park emitted, emitted once, then dark.
   An operator with the pre-fix firmware would have seen one 20 s dark
   window and the same signature 3½ minutes sooner — but an operator
   *watching* the pre-fix firmware would have seen a dead board for 20 s
   and had to power-cycle blind. Here the board told the owner what it
   was doing the whole time, tried everything it could on its own, and
   then said precisely why it stopped.
5. **The settle can outlast minutes, not seconds** — this episode's
   settle exceeded four ~63 s windows (~4.4 min of episode time), far
   beyond the 2026-11-09 success-tail's ≥ 20.4 s. The D-8 note gains the
   data point; the upper bound remains unmeasured.

The window-vs-budget arithmetic: each window is ~63–65 s against the
60 s `ENTROPY_DEADLINE_MS` because `otp_retry::retry` counts *sleep* time,
and each attempt's own wall time (the DRBG construction's record read and
seed derivation, ~10–20 ms) rides on top — 240 attempts × overhead ≈ 3–5 s.
Recorded rather than "fixed": the deadline's unit is documented as a sleep
budget, and the blink's duty cycle makes the wall time legible on the pin.
