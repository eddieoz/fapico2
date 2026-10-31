# Dark boots decoded: `TrngRefused` from `ensure_boot_entropy`

- **Date:** 2026-10-31
- **Symptom:** intermittent dark boots — LED shows ~10 fast blinks, one long
  flash, then four rhythm flashes (two fast, two slow), then dark; no USB
  enumeration. Recovered only by repeated power cycles; after recovery, long
  runs of normal boots until it suddenly recurs.
- **Status:** root cause identified (video-decoded LED signature + call-order
  proof). **Fix landed** (`ensure_boot_entropy` retries the draw on the
  `otp_retry` budget before refusing, and pulses the LED once on the
  record-absent path); hardware validation pending.
- **Evidence:** `IMG_1354_1.mp4` (frame-by-frame green-dominance timeline) and
  `firmware/src/{bootphase.rs,fatal_sig.rs,main.rs,boot.rs}`,
  `platform/src/trng.rs`.

---

## 1. The LED recording, decoded

Frame-by-frame measurement of the recording (29 fps, green-dominance
sampling of the board LED):

| time (s) | LED | decoded meaning |
|---|---|---|
| 0.17 – 0.97 | 10 pulses, ~80 ms apart | boot ladder, cumulative 10 = through `RUNG_STORE` (1+2+3+4) |
| 1.03 – 2.21 | one continuous ~1.2 s lit | fatal-signature preamble (`PREAMBLE_US = 1_200_000`) |
| 2.83 – 2.97 | 200 ms lit, ~600 ms gap | bit `0` (`ZERO_GAP_US`) |
| 3.62 – 3.76 | 200 ms lit, ~600 ms gap | bit `0` |
| 4.41 – 4.59 | 200 ms lit, ~200 ms gap | bit `1` (`ONE_GAP_US`) |
| 4.79 – 5.00 | 200 ms lit, then dark | bit `1` |

Bits MSB-first: `0,0,1,1` = **0b0011 = 3 = `Reason::TrngRefused`**
(`fatal_sig.rs:127`). The eye reads the same four bits as "1 Hz, 1 Hz,
0.5 Hz, 0.5 Hz" with the order flipped; the 2:1 rhythm ratio is the
ONE_GAP/ZERO_GAP pair either way.

## 2. Which fatal site

`TrngRefused` has exactly three call sites:

| site | ladder position when it fires | pulses seen |
|---|---|---|
| `main.rs:527` (TIMER0 not counting) | before `RUNG_OTP` | 3 |
| `main.rs:682` (same, migration probe) | before `RUNG_OTP` | 3 |
| **`boot.rs:1847` (`ensure_boot_entropy`)** | **after `RUNG_STORE`, before `RUNG_DRBG`** | **10** |

The recording shows 10 pulses, and the boot ladder's cumulative count
(`signature(rung).pulses == rung + 1`) reaches 10 exactly at `RUNG_STORE`
(`main.rs:756`). The very next step in `main` is
`boot::ensure_boot_entropy(&mut seed_probe, store)` (`main.rs:783`). The
decoding and the call order agree with no remaining ambiguity:

**The board is refusing to boot inside `ensure_boot_entropy`, because the
bounded TRNG draw returned `Err` within the 20 ms per-block budget.**

## 3. The mechanism, end to end

`ensure_boot_entropy` (`boot.rs:1824-1851`) guarantees the
`boot.entropy.v1` secure-store record (32 TRNG bytes, the input to every
DRBG seed, consumed by `drbg_seed.rs`):

```rust
match store.read(migration::SLOT_BOOT_ENTROPY, &mut buf) {
    Ok(n) if n == ckey::BOOT_ENTROPY_LEN => return,   // record present: no draw, no risk
    Ok(_) | Err(NotFound) => {}                        // record absent: DRAW
    Err(_) => return,
}
if try_fresh_bytes(probe, &mut buf).is_err() {
    fatal_boot(..., Reason::TrngRefused);              // <-- the dark boot
}
```

Consequences that produce the observed behaviour exactly:

1. **The draw — and therefore the risk — exists only on boots where the
   record is absent**, i.e. a `BootSlot::Fresh` decision (both secure
   slots erased) or a wrong-length record. A reflash of a different image
   (US-919 foreign-image wipe / manifest mismatch) or a first-ever boot
   lands here; ordinary boots with the record present skip the TRNG at
   this site entirely.
2. **The refusal is a 20 ms-per-EHR-block wall-clock budget**
   (`MAX_ENTROPY_WAIT_MS`, `platform/src/trng.rs:220`). 32 bytes = two
   blocks, each budgeted 20 ms. The budget is a 10× safety factor on the
   datasheet's ~2 ms *average*, and the module's own doc records that it
   has **never been measured on silicon** (D-8) — the datasheet itself
   warns "results occasionally take an especially long time to generate".
3. **`AUTOCORR_ERR` is a hardware wedge.** The RP2350 documentation
   (quoted in `trng.rs:1288`) says the RNG "ceases functioning until next
   reset"; the probe's `rearm()` soft-reset does not revive it (the
   embassy-rp driver retries it forever in vain). One autocorrelation
   failure during the draw makes the remaining budget unwinnable, no
   matter how long the wait were.
4. **The record is persisted only at persist gate 1** (`main.rs:1058`),
   which a fatal boot never reaches. So a refused boot leaves the store
   without the record: **every power cycle redraws and re-rolls the
   dice.** That is precisely the "power cycle many, many times and
   eventually it works" experience.
5. **Once a draw succeeds**, gate 1 programs the sealed store image into
   *both* slots (`FlashSlotSink::program`, `persist_sink.rs:90`), so every
   subsequent boot finds the record and never touches the TRNG here
   again — the long runs of normal boots. The lottery re-opens when the
   store loses the record (reflash of a different image being the known
   route).

The board-level precedent is already in the tree: `main.rs:725-733`
records that an OTP-controller register write made subsequent OTP reads
fail ~80 consecutive times on this hardware until a power cycle. The TRNG
autocorrelation wedge is the same class of "controller state poisoned
until power-on reset" failure.

A secondary hazard in the same window: the boot sanity draw
(`main.rs:580`, non-fatal since US-1008) runs through the same probe
*before* `ensure_boot_entropy`. If its `status()` hits `autocorr_err`, the
`rearm()` soft-reset can leave the peripheral dead for the rest of the
power cycle — and US-1008's "continuing to init_drbg, which is the
authority" then hands the authority a corpse. The sanity draw must be
counted as part of the same per-boot dice roll.

## 4. Is the verification needed? Can it move later?

**The check is load-bearing and cannot simply move after boot.** The
`boot.entropy.v1` record is the entropy input to the DRBG seed
(`drbg_seed.rs`); every app boot and the bound device root derive from it,
all pre-USB. Deriving it later would mean the DRBG and every keystore
boot before it — the fail-closed policy (ADR 0004) is deliberate and
correct: without the record, bound derivations refuse, and a fallback key
would silently weaken every derived key.

**What is *not* load-bearing is the single-shot fatal.** The guarantee
"record exists before any derivation" survives unchanged if the draw is
retried; the current code converts one missed 20 ms window (or one
autocorrelation event) into a permanent park that a human must defeat by
hand with a USB cable. Three fixes preserve the security property and
remove the fragility, in rising order of invasiveness:

1. **Retry the draw before refusing.** Bounded loop with stepped delays —
   the exact pattern `otp_retry.rs` already ships for the flaky OTP reads
   on this board. A slow-tail block succeeds on attempt 2; only a wedged
   peripheral exhausts the retries. Cost is bounded and paid only on the
   Fresh path.
2. **Re-budget `MAX_ENTROPY_WAIT_MS` from a silicon measurement**
   (US-1007's outstanding hardware leg). 20 ms = 10× a datasheet average;
   the success path costs nothing if the number grows, because the wait
   ends at `Ready`.
3. **On final refusal, reboot instead of parking.** A bounded
   sys-reset loop with a retained-RAM attempt counter (park with the
   signature after N failures) automates exactly what the operator does
   by hand today. Note the open question: `fatal_sig.rs` records that the
   *OTP* wedge survives a plain system reset (VBUS-only recovery); whether
   the TRNG wedge clears on sys-reset or only on power-on reset needs one
   hardware A/B before this fix is trusted.

## 5. Fix landed and discriminating test

Two changes in `firmware/src/boot.rs` (both verified by the device release
build and the host suites; the boot path itself is arm-only and needs the
hardware leg):

1. **The draw is retried before refusing.** `ensure_boot_entropy` now runs
   the bounded draw through `otp_retry::retry` (`STEP_MS` 250 ms /
   `DEADLINE_MS` 20 s — the same budget the OTP reads use for the same
   class of settling fault). Each attempt is a full enable/wait/read
   cycle, so a retry is a fresh roll of the peripheral; a refused attempt
   scrubs the buffer, so no attempt inherits another's contents. Only a
   source that refuses across the whole budget parks the board, with the
   same `TrngRefused` signature as before. A slow-tail block (the D-8
   residual) now costs one extra attempt instead of a dark boot; a
   hardware wedge still parks, ~20 s later.
2. **The record-absent path is now visible on the LED.** Before the first
   draw attempt, `entropy_draw_notice()` emits one 400 ms lit pulse — a
   duration no other pre-release pin driver uses (ladder 25 ms, signature
   bit 200 ms, heartbeat 500 ms, preamble 1200 ms), and it is *not* a
   ladder rung, so the progress count stays truthful.

### Reading a board with this build

| LED reading | meaning |
|---|---|
| pulses, **400 ms flash**, more pulses, 1 Hz heartbeat | fresh-store boot; the draw ran (and succeeded). Never fatal-shaped. |
| pulses, **400 ms flash**, ~20 s pause, preamble + `0011` | drew across the whole retry budget and was refused — the wedge case; power-cycle (the sys-reset-clears-it question is now answerable by whether BOOTSEL-less reset also recovers) |
| pulses, preamble + `0011`, **no 400 ms flash** | refusal did not come from this site — the audit's decoding was wrong, report it |
| pulses, preamble + `0011`, 400 ms flash, **15 pulses** before the preamble | the post-wipe redraw (`ensure_fw_manifest`), i.e. a foreign-image boot, not a fresh mount |

The last two rows discriminate the remaining open question of §3: *which*
route left the store without the record on a boot that followed no reflash.

## 6. Hardware validation (2026-10-31, post-nuke boot)

The fix was flashed after a full nuke; the first boot was video-recorded
(`20261031_110655_1_1.mp4`, 60 fps) and decoded frame-by-frame. Every one of
the 45 ladder pulses is accounted for:

| time | LED | decoded |
|---|---|---|
| 5.40–6.15 s | 10 pulses | rungs 0–3 (`RUNG_HAL`..`RUNG_STORE`), cumulative 10 |
| 6.22–6.65 s | 433 ms lit | the 400 ms draw notice — fresh store, the draw ran |
| 6.70–6.97 s | 4 pulses (+1 merged into the notice tail) | `RUNG_DRBG` (5) |
| 7.0–7.55 s | dark 583 ms | `ensure_fw_manifest` stamp (first boot for the image) |
| 7.55–7.98 s | 6 pulses | `RUNG_MIGRATION` |
| 8.0–8.58 s | dark 600 ms | persist gate 1 (both slots programmed — record becomes durable) |
| 8.58–10.50 s | 24 pulses | `RUNG_APPS`+`RUNG_USB`+`RUNG_SERVING` (7+8+9) |
| 10.55 s → | 1 Hz heartbeat | serving |

The draw-path boot completed normally on the first power episode — the same
path that previously parked the board on a single missed 20 ms window. The
notice fired exactly where designed, which also confirms on hardware that a
nuked store reaches the draw (the §3 trigger condition). Still to observe on
hardware: a refused draw across the whole retry budget (400 ms flash → ~20 s
pause → `0011` signature), and whether a sys-reset clears the autocorrelation
wedge or only a VBUS power cycle does.
