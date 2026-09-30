# Boot freeze after a flash or a settings save

- **Epic:** `BOOT-FREEZE-POST-FLASH` (US-1301…US-1312)
- **Story doc:** [`docs/tasks/EPIC-boot-freeze-post-flash.md`](tasks/EPIC-boot-freeze-post-flash.md)
- **Status:** instrumentation shipped; **the trigger is not yet established**
- **Last updated:** 2026-10-01

---

## Read this first if you have a frozen board in front of you

1. **Unplug the USB cable, WAIT 5 SECONDS, then plug it back in.** That is the
   fix. The wait is not superstition — it is load-bearing. Replugging quickly
   leaves the board **still frozen**: the same board, the same firmware and the
   same state all recover reliably when power was off for 4-5 s and fail to
   recover when it was off for a moment. A reset-button press or a re-flash
   will *not* clear it either — see [why](#why-a-power-cycle-and-not-a-reset).
2. Watch the LED **from the moment you power it**. If it blinks a countable
   number of times and then goes dark and USB never appears, the device reached
   a named boot phase and stopped: [read the ladder](#1-the-boot-phase-ladder).
3. If instead you see **one long flash, a pause, then four short flashes**, the
   device is refusing to boot for a specific reason: [read the signature](#2-fatal-signatures).
4. Do **not** attach an SWD probe to investigate. On this hardware that alone is
   enough to cause the failure you are investigating — see
   [Do not attach a debugger](#do-not-attach-a-debugger).

## What this document is for

Before this epic, the failure had four accounts in this repository and **three
different conclusions**, none proven:

| Account | Claim |
|---|---|
| `SECURITY-ASSESSMENT-ROUND2.md` §20 | "the device is not frozen" |
| §22 (R2-26) | "attaching a debugger bricks it" |
| `docs/known-gate-divergences.md` D-12 | "came up dark", mechanism disputed |

The instrumentation below exists so the next account is a **measurement**. What
it can and cannot establish is stated in [What is not known](#what-is-not-known).

## Do not attach a debugger

[`AGENTS.md`:98-112](../../AGENTS.md) (the sibling repo root, one level above
`fapico2/`) records, from a prior investigation on this hardware, that **a
connected SWD debugger is sufficient on its own** to produce this exact failure
on a board whose OTP is perfectly healthy:

> with a debugger attached, `OTP_DATA_RAW` reads return `0xFFFFFFFF`.
> `read_raw_word` maps exactly that value to `Err(Error::InvalidPermissions)`.
> `read_otp_key_1()` treats any `Err` as "key absent" and returns `None`;
> `derive_boot_store_key()` then calls `fatal_boot`.

So "flash then reboot" and "debug then reboot" are the **same observational
event** until a run separates them. This confounded the reported trigger, and
separating it is the epic's pivot (US-1301) — which is **still open**: see
[What is not known](#what-is-not-known).

The house rules stand unchanged: *"Validate detached, over BOOTSEL (copy the
UF2, no probe connected)"* and *"Use the probe to READ, never to RUN."*

> **Citation note (2026-10-01, corrected later the same day).** An earlier
> revision of this document recorded that `AGENTS.md` did not exist. That was
> wrong, and the mistake was looking only inside the repository: the file lives
> at [`../../AGENTS.md`](../../AGENTS.md), one level above `fapico2/`, outside
> the git worktree. Lines 98-135 were then checked and match the epic's quotes
> exactly — including the register map (OTP controller `0x4012_0000`, ECC
> `OTP_DATA` at `0x4013_0000`, `OTP_DATA_RAW` at `0x4013_4000`) and the note that
> `0x400D_8100` is the **RP2040** map and reads all zeros on RP2350.
>
> The watchdog refusal below belongs in that file's hardware-validation section
> and is not yet there.

## 1. The boot phase ladder

Under the release-allowed `boot-timeline` feature (`./build-timeline.sh`), the
firmware blinks its progress on the board LED — the only channel that works on a
device that never enumerates.

**Read the count as a transition count, not a light level.** Phase `N` emits
`N` blink cycles, and every phase ends with the pin back at its resting level.
So counting *changes* gives an unambiguous answer whichever way the LED is
wired, and a board revision that inverts the pin cannot change the diagnosis.
This is deliberate (`firmware/src/boot_ladder.rs`).

| What you see | What it means |
|---|---|
| No blink at all | Froze before or during HAL init — before the LED could be driven |
| `n` cycles, then dark, no USB | Phases 1…`n` completed; phase `n`+1 did not |
| A count partway between phases | Froze **inside** a phase — see below |

Because phase boundaries sit at cumulative cycle counts `0, 1, 3, 6, 10, …`
(triangular numbers), a count that lands between two boundaries is a freeze
*inside* a phase. The classifier reports `UNKNOWN` for those rather than
rounding down, because rounding would name a boundary the device never
demonstrably reached.

Turn a recording into a verdict:

```bash
python3 tests/hardware/boot_time_probe.py --label arm-a --after-enter \
    --blinks blinks.txt
```

`blinks.txt` is one LED level per line or token (`1`/`on`/`true`,
`0`/`off`/`false`) — a human or a camera's transcription, not a live sample. The
probe cannot read a blink rate; it can classify one.

### The prediction that was made about this, and what happened to it

The epic predicted that an OTP key-row failure would produce **exactly three
ladder blinks and then a solid LED**, because `bphase!(P_STORE_KEY)` sits *after*
`derive_boot_store_key()` returns and that function calls `fatal_boot` from
inside on an unreadable row.

**The prediction's arithmetic was wrong, and the code was not even doing it.**
Two corrections, both recorded rather than quietly fixed:

- `P_STORE_KEY` is id **4**, not 3. More importantly, the ladder is
  *cumulative*: phase 1 emits 1 cycle, phase 2 emits 2, phase 3 emits 3. A board
  that dies before phase 4 has emitted `1 + 2 + 3 = 6` cycles, not 3.
- `phase_blinks` **had no call site anywhere in the tree**. `bphase!` expanded to
  `dlog!` alone, so the ladder was documented and implemented but never
  emitted. There was nothing to count, which is the mechanical reason the four
  prior accounts had no measurement to disagree about.

Both are fixed (US-1304). The corrected prediction — *an OTP key-row failure
shows 6 cycles, then the OTP signature* — has **not been tested on hardware**.

## 2. Fatal signatures

A pre-USB refusal used to be a `defmt` line and a `loop {}`. `defmt` needs a
probe; a probe causes the failure. So the device now says why on the LED
(US-1306).

A signature is **one long flash, a pause, then four short flashes**:

```text
    ████████████░░░░░     preamble: one 1200 ms pulse, 600 ms gap
    ██░░░  ██░░░  ██░░░  ████░░░░░  4 bits, most-significant first
    short  short  short  long          = 0b0001 = 1
```

Long gap = `1`, short gap = `0`. The whole signature takes ~4.6 s and is emitted
**once** before the device parks.

| id | Cause | Fix |
|---:|---|---|
| 1 | **OTP key row unreadable** | **Power cycle** — the only thing that clears it |
| 2 | Chip identity row unreadable | Investigate provisioning |
| 3 | TRNG refused / no entropy | Investigate silicon |
| 4 | DRBG could not be seeded | Investigate; usually follows 1 or 2 |
| 5 | Secure-partition image failed authentication | Investigate; may be a foreign image |
| 6 | Secure partition not writable | Investigate flash wear |
| 7 | Backend never mounted | Investigate; may follow 6 |
| 8 | A keystore could not be opened | Investigate store contents |
| 9 | A schema migration could not complete | Investigate; may need re-enrollment |
| 10 | **Panic** | A bug — report it, with the count |

**id 1 is the one that matters operationally**, and it gets its own id precisely
because its recovery is known and differs from everything else. A signature of
any other id that reads `0b0001` is a *different* cause with a *different* fix,
so do not power-cycle-and-hope on id 10.

A signature cannot be confused with the two other things that blink this pin: no
signature pulse is 40 ms (the ladder's period) or 500 ms (the heartbeat's), and
the 1200 ms preamble is three times longer than any other lit pulse the firmware
drives.

## Why the wait is part of the fix (measured 2026-10-01)

The freeze reproduces **with no debugger attached at all** — measured on
hardware on 2026-10-01, 2 of 2 flash-and-reboot cycles, each requiring a power
cycle to recover. So the "attach a probe and have a look" advice is not just
counterproductive, it manufactures the fault.

What makes it reproducible is a controlled comparison the operator ran during
that session:

> if I remove power and return it fast, the board stays frozen. If I wait 4-5
> seconds and replug, then it returns.

Same board, same image, same state; the only variable is how long power was off.

This is **not** a firmware race, a concurrency bug or a boot-ordering problem,
and nothing is to do with unloading memory — the device is not reading stale
RAM. The failing read is an OTP read that returns `0xFFFFFFFF`, which the
firmware maps to "key absent" and then refuses to boot without. That is a
hardware register result.

The likely mechanism is the supply rail. RP2350 **errata E16** records that the
OTP array's read voltage comes from an internal regulator whose power-good
"isn't sampled outside of the initial power-on reset startup sequence". Four or
five seconds of power-off is what it takes for that rail to discharge and for
the power-on sequence to sample it correctly. Replug too fast and the OTP array
comes back in the escalated state, so the board refuses to boot again.

**This is consistent with, and is the strongest evidence yet for, the
reset-property hypothesis (fact 8).** It also means the recovery procedure is
deterministic once you know the wait — which is a real improvement over "unplug
it and hope".

## Why a power cycle, and not a reset

Per `SECURITY-ASSESSMENT-ROUND2.md` §22 (R2-26, reproduced on hardware
2026-09-28), the OTP `SW_LOCK` registers after a debugger access:

| register | healthy | after SWD access, **system** reset | after **power** cycle |
|---|---|---|---|
| `SW_LOCK[0]` | `0x05` | `0x0D` | `0x05` |
| `SW_LOCK[1]` | `0x04` | `0x0C` | `0x04` |

Every ECC read of rows `0xE90`–`0xE9F` then returns the all-ones sentinel. **A
system reset does not clear the escalation; only removing VBUS does.** That is
why "power cycle fixes it" is a consequence of the hardware and not a clue about
what caused it.

## The watchdog decision: refused

**Decided 2026-10-01 (US-1311): no watchdog is added. The reasoning is recorded
here so this is not re-proposed on the next freeze.**

A watchdog is the obvious answer to "a hang should be recoverable", and for this
particular failure it is the **wrong** one:

- In the locked mode above, **a reset does not restore the key row**. Arming a
  watchdog converts a *legible* park — which US-1306 just made diagnosable —
  into an **illegible infinite reboot loop**. The signature, which is emitted
  once and then parks, would flash over and over with no operator able to catch
  a count. That is strictly worse: the signal US-1306 exists to deliver is
  destroyed by the fix someone would reach for next.
- The device has no watchdog today (there is no `embassy_rp::watchdog` in
  `firmware/`, `platform/` or `apps/`), so this is a "do not add" decision
  rather than a change.

A watchdog **would** be in scope for a *transient* hang mode — one a reset
actually clears. If a future measurement establishes that, the correct shape is a
watchdog fed by boot progress and armed only after boot reaches a known-good
phase, so it cannot reset-loop through the window it exists to protect, and its
arm point gets a host test.

## What is not known

Stated plainly, because the epic's whole point is that an unmeasured account is
the failure mode it is fixing.

**Not established: what triggers the freeze.** US-1301 (reproduce with zero SWD
involvement) is **BLOCKED** — no RP2350 board was attached when this epic was
executed. That number decides which branch is live:

- **If it reproduces with no probe:** the reset-property branch (RP2350 errata
  E16, an OTP-array regulator whose power-good is not sampled outside the
  initial power-on reset sequence) becomes the live hypothesis, and US-1307's
  reset-reason latch is the way to test it.
- **If it does not:** the debugger is the trigger, and US-1307 is **deleted, not
  deferred**.

Also unverified on hardware, and stated rather than assumed:

- that the boot ladder reaches the pin (the call site existed only from US-1304);
- that the fatal signature reaches the pin (US-1306's acceptance criterion);
- the corrected OTP prediction (6 ladder cycles, then signature id 1);
- the LED polarity correction, which is asserted by
  `tests/scripts/check_led_polarity.py` against the C reference
  (`pico-keys-sdk/src/led/led_pico.c:50`, `gpio_put(gpio, progress >= 0.5)` with
  no `PICO_DEFAULT_LED_PIN_INVERTED`) rather than by a measurement taken here.

### Status of the prior accounts

Each of the three earlier accounts gets an explicit line, because leaving them to
be reconciled by whoever reads them next is how the fourth account happened:

| Account | Status |
|---|---|
| §20 "the device is not frozen" | **Left open.** §20.6 declined to link §20 and §22; this epic does not link them either, and no measurement was available to settle it. |
| §22 (R2-26) "attaching a debugger bricks it" | **Left open as the trigger**, but its *recovery* finding — power cycle, not reset — is carried into this document and ADR 0002 as established. |
| D-12 "came up dark", mechanism disputed | **Left open**, for the same reason. |

None is confirmed or refuted, because the measurement that would do that
(US-1301) has not been taken. What *is* settled is the instrumentation that will
make that measurement possible without a probe.

## The recovery policy (ADR 0002)

The firmware refuses to serve when it cannot read its hardware identity, and
says so. There is no fallback key and no lock/absence distinction — both
rejected with their trade-offs recorded in
[`docs/adr/0002-fatal-boot-recovery-policy.md`](adr/0002-fatal-boot-recovery-policy.md).

## Operator procedure

1. Note what the LED does, counting from power-on (ladder cycles, or the
   signature).
2. Unplug the USB cable. Wait a few seconds. Replug.
3. If it enumerates, you have the ID above; the store content is not implicated
   (§20.3 bisected the store with forged variants and found the decisive
   measurement: **the store that hung past 300 s and the store that had just
   booted twice are byte-identical**).
4. If it does not, the device is not in the locked state — record the LED
   behaviour and escalate; ids 5–9 are not cleared by power cycling.
