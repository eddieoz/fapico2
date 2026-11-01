# Troubleshooting the boot

When a board refuses to boot, USB is exactly the thing that does not work — so the diagnostic tools that need enumeration (logs, `ykman`, PicoForge) are all unreachable. The board has one instrument that always works: **the LED**. It announces every boot milestone and, if boot is refused, names the reason. This chapter teaches you to read it.

Watch the LED **from the moment you plug power in**. Every pattern below happens in the first seconds.

## The four things the LED can say

| what you see | what it is |
|---|---|
| short pulses, ~80 ms apart, then more pulses | the **boot ladder** — a progress counter; count them to locate a freeze |
| one long flash (~1.2 s), a pause, then four shorter flashes | a **fatal signature** — the board refused to boot and is naming the reason |
| a single ~0.4 s flash, longer than any ladder pulse | the **entropy-draw notice** — a first/fresh boot drawing randomness (normal, see [below](#the-04-s-flash-a-fresh-store-drawing-entropy)) |
| steady 1 Hz blink, forever | the **heartbeat** — boot completed; the board is alive and serving |

These are separated by flash *length*, not just rhythm: a ladder pulse is lit for 25 ms, a signature bit for 200 ms, the draw notice for 400 ms, the heartbeat for 500 ms. You do not need a stopwatch — after one healthy boot you will recognize each by eye. A case over the board does not stop any of this being countable (all of the readings below were verified through a 3D-printed case on video).

## A healthy boot, end to end

A normal boot pulses the LED in groups and then settles into the 1 Hz heartbeat. You do not need to count every pulse to a healthy boot — **pulses, then steady 1 Hz heartbeat, means success**. But here is the full anatomy, measured on hardware, so a partial reading makes sense:

| pulses | milestone just crossed |
|---|---|
| 1, 2–3 | HAL up, clock and TRNG ready |
| 4–6 | the device's key row read; store key derived |
| 7–10 | secure store mounted |
| *(0.4 s flash on a fresh store — see below)* | drawing fresh entropy |
| 11–15 | DRBG seeded |
| 16–21 | firmware verified, first-boot migration done |
| 22–28 | applets built (FIDO, OATH, OpenPGP, ...) |
| 29–36 | store persisted, backend mounted |
| 37–45 | USB up, tasks serving |
| steady 1 Hz | serving |

The groups run together when the stages between them are fast, so in practice you will see one or two bursts of pulses rather than nine tidy groups. On a **first boot** (or the first boot after a factory reset), a **~0.4 s flash** appears in the middle, and the two longest pauses (up to ~1 s each) follow it — that is the entropy draw and the store being written durably for the first time.

## The boot ladder: *k* pulses, then dark

The ladder is cumulative: each milestone's pulses stack on the previous ones. A board that goes dark after **10** pulses crossed four milestones and died in the fifth stage. The count localizes the freeze:

| last count | froze in |
|---|---|
| never blinked | before the HAL — power cycle; if it never blinks at all, the firmware is not running (re-flash via BOOTSEL) |
| 1 | clock/TRNG bring-up |
| 3 | the OTP key-row read |
| 6 | mounting the secure store |
| 10 | the entropy draw / DRBG init |
| 15 | firmware-manifest check, first-boot migration |
| 21 | constructing the applets |
| 28 | persisting the store, mounting the backend |
| 36 | bringing USB up |
| 45 | just before serving |

## Fatal signatures: one long flash, then four bits

When boot is *refused* — not frozen, refused — the LED says why, once, and the board goes dark. The pattern: one long flash (1.2 s), a pause, then **four lit pulses of 200 ms each**. Each pulse is a *bit*; the **gap that follows** it names the bit:

- gap ≈ **0.2 s** (short) → bit **1**
- gap ≈ **0.6 s** (long) → bit **0**

Read the four bits left to right as a binary number, most-significant bit first. For example: long, long, short, short = `0,0,1,1` = 3. The number is the reason:

| id | bits | reason | what to do |
|---|---|---|---|
| 1 | `0001` | OTP key row unreadable | power cycle (off **≥ 5 s**) and retry; recovery is a power cycle, not a reset button |
| 2 | `0010` | chip identity row unreadable | power cycle as above |
| 3 | `0011` | TRNG refused within the retry budget | power cycle as above; see [the entropy draw](#the-04-s-flash-a-fresh-store-drawing-entropy) |
| 4 | `0100` | DRBG seed refused (same TRNG class, one step later) | power cycle as above; fixed by the same retry — if it recurs, report it |
| 4 | `0100` | DRBG could not be seeded | power cycle and retry |
| 5 | `0101` | store content failed verification | re-flash the firmware; if it recurs, the store was deliberately refused — report it |
| 6 | `0110` | store could not be written durably | power cycle; if it recurs, report |
| 7 | `0111` | backend failed to mount | power cycle and retry |
| 8 | `1000` | a keystore failed to open | power cycle and retry |
| 9 | `1001` | schema migration failed | power cycle and retry |
| 10 | `1010` | a firmware panic | power cycle; if it recurs on the latest firmware, report it with the signature |

After any signature, unplug, **wait at least 5 seconds**, and plug back in. The wait is load-bearing: several of these conditions clear on a real power cycle and not on a quick replug or a reset button.

## The 0.4 s flash: a fresh store drawing entropy

On the first boot after a factory reset — or any boot where the secure store starts empty — the LED gives one **~0.4 second** flash before the mid-boot pulse groups. That is the board announcing: *my store came up empty, I am drawing fresh randomness to seed it*. It is normal, it happens once, and the boot continues afterwards. On an ordinary boot (the store intact) the flash does **not** appear — nothing is drawn at that point.

Two things can follow it that are worth recognizing:

- **a pause of up to ~20 seconds** before the next pulses. That is the entropy draw being retried, not a hang — the board redraws on a stepped budget before it ever gives up. If the draw succeeds on any attempt, boot continues normally.
- if the draw exhausts the whole budget (~20 s), the board emits signature `0011` (reason 3, above) and goes dark. Power cycle with 5+ seconds off and try again — a fresh power episode gives the randomness generator a fresh chance, and after one success the record is stored permanently (the flash does not appear again until the next factory reset).

One more thing worth knowing: the seed for the board's randomness generator involves **one more** draw from the same hardware source after the store's entropy record is guaranteed — and it gets the same retry treatment. So on a cold boot after the board has been unplugged for a while, a signature `0100` (reason 4) means the same kind of marginal first-draw miss, one step later; power-cycling with 5+ seconds off recovers it, exactly like `0011`. If either signature repeats on consecutive boots, report it — that would mean the generator stays wedged across the whole retry budget, which is a hardware finding.

## A worked example

A real failure, decoded: **10 fast blinks, one long flash, then four rhythm flashes — two slow, two fast — then dark.**

The 10 blinks mean the store mounted. The long flash is a fatal signature's preamble. The four bits: the gaps after each lit pulse were long, long, short, short = `0,0,1,1` = reason **3** — the randomness generator missed its budget on a boot where the store was empty, and the firmware of the time refused to boot rather than continue without a seeded generator. Power-cycling eventually gave a power episode where the draw succeeded — and because the successful draw persists, the board then booted normally until the store was empty again (a reflash or reset).

Current firmware fixes the *fragility* (the single missed window no longer kills the boot — see the 0.4 s flash section), keeps the *guarantee* (the board still refuses rather than running on a generator that never produced), and adds the 0.4 s flash so the failure mode is visible instead of silent. The full investigation is recorded in [the audit](https://github.com/eddieoz/fapico2/blob/main/docs/audits/2026-10-31-boot-dark-trng-refused.md).

## Heartbeat running, but USB dead

If the LED blinks a steady 1 Hz and *stays* that way, boot completed — the board is alive and the fault is on the host side. Work through: another cable/port, [the USB identity](../how-to/usb-identity.md) (a pair your host's driver cannot bind looks exactly like "no device"), and the client quirks in [What it works with](../interop/index.md).

## If it repeats

1. Note the exact pattern (a phone video is ideal — pulse counts are readable from it).
2. Unplug, wait 5 seconds, plug back in. Repeat once or twice: a *consistent* signature is information, a one-off is usually a marginal power episode.
3. Re-flash the latest firmware over BOOTSEL — several past causes (this one included) were firmware, and the fix ships as an image.
4. If it still reproduces, report it with the LED sequence. The pattern is the bug report.
