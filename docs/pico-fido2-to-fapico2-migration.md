# Migrating a board from pico-fido2 to fapico2

**Status:** operator record, written 2026-10-11 from a live board
(`pico_fido2_pico2-1.0.uf2` history → fapico2). Facts about OTP state are
source-verified and hardware-confirmed; the boot-park mechanism is recorded at
the confidence stated inline, not higher.

**What this covers:** the durable hardware state a board carries after running
pico-fido2 1.0, what each piece means to fapico2, and the one failure mode that
looks like a brick during the switch but isn't. Data migration (credentials,
keys, OpenPGP capture) is a separate track — see
[`migration-epic.md`](migration-epic.md).

---

## Read this first if the board parks after a flash

**Unplug the USB cable, WAIT 5 SECONDS, plug it back in.** Do not nuke, do not
reflash, do not reach for a probe.

A board that ran pico-fido2 and is then flashed with fapico2 can park during
its first boots: a fast series of LED blinks, then the LED solid-on, no USB
enumeration. This was reproduced repeatedly on 2026-10-11 and looked permanent
— it survived several nuke-and-reflash cycles — and then stopped occurring
without any persistent state having changed. The mechanism and the evidence are
in [The post-flash park](#the-post-flash-park-that-looks-like-a-brick); the
short version is that it is a transient OTP-read condition, not flash content
and not a firmware/image mismatch, and **every recovery was a power cycle**.

Nuking was never the fix and never the harm: `nuke_universal.uf2` is Raspberry
Pi's official `flash_nuke` (auto-detects the chip, caps at 16 MiB, so it erases
the full 4 MiB and nothing in OTP). After it, fapico2 boots with a fresh store
(`Fresh`, the US-915 slot decision). If you have already nuked: fine — the
store was empty anyway, and the park, when it happens, comes back only until
one boot lands with the rail settled.

---

## What pico-fido2 1.0 leaves in OTP — and why fapico2 is fine with it

pico-fido2's `otp_platform_init` (`pico-keys-sdk/src/otp/otp_rp2350.c`) runs on
every boot and burns durably on first boot:

| OTP state | Where | What it is |
|---|---|---|
| MKEK key, 32 B ECC-written | row `0xE90`–`0xE9F` | pico-fido2's storage root key — **the same row fapico2 reads as its C-compat root** (`boot.rs::read_otp_key_1`) |
| DEVK key, 32 B ECC-written | row `0xE80`–`0xE8F` | pico-fido2's device key; unread by fapico2 |
| Chaff (key complement), raw-written | rows `0xEA0`–`0xEBF` | no ECC — ECC-mode reads of these rows fail; unread by fapico2 |
| Page lock, burned raw | row `0xFF5` (`PAGE58_LOCK1`), value `0x3C3C3C` | locks page 58 (rows `0xE80`–`0xEBF`) — **irreversible** |

The lock decodes from the RP2350 register map (`otp_data.h:2866-2956`) as:
`LOCK_S = 0b00` (Secure access fully open), `LOCK_NS = 0b11` (non-secure
inaccessible), `LOCK_BL = 0b11` (bootloader denies *user* OTP access).
`PAGE58_LOCK0` (`0xFF4`) reads `0x000000` — no hardware-key requirements.

Three operator-visible consequences, all expected:

1. **`picotool otp get` over rows `0xE80`–`0xEBF` fails with
   `permission failure`** — even in BOOTSEL, even in raw mode. That is the
   `LOCK_BL` anti-dump measure doing its job, on every board that ever ran
   pico-fido2. It is **not** evidence that fapico2 cannot read the row:
   fapico2 runs secure-state and reads through the memory-mapped views, which
   the lock leaves open (`LOCK_S = 0b00`). The lock rows themselves
   (`0xFF4`–`0xFF7`) remain readable and are the place to look when auditing a
   board.
2. **At every reset, `SW_LOCK[58]` loads as `0x0C`** (secure read/write,
   non-secure inaccessible) — measured in
   [`SECURITY-ASSESSMENT-ROUND2.md`](archive/SECURITY-ASSESSMENT-ROUND2.md)
   §22 on a board with this burn that booted fapico2 normally. See also
   D-13/D-14 in [`known-gate-divergences.md`](known-gate-divergences.md).
3. **The MKEK value differs from a factory board.** A factory board's row
   `0xE90` is unprogrammed (all-zero) — fapico2 never writes it — so the store
   key derives from zeros there and from pico's MKEK here. Both derive and
   boot; the value is not a boot factor. The row is shared **by design**
   (`platform/src/ckey.rs`, C-compat).

## The post-flash park that looks like a brick

**Symptom (observed 2026-10-11):** after flashing `fapico2.uf2` over BOOTSEL,
the board blinks a fast series and parks solid-on, no USB. Reproduced across
multiple nuke-and-reflash cycles. pico-fido2 1.0 re-flashed onto the same board
booted normally throughout.

**Why each piece behaved that way:**

- **fapico2 parks** because `read_otp_key_1()` (`boot.rs:1375`) fail-closes on
  an unreadable row — `fatal_boot` before USB, by design (US-918). The LED is
  lit from GPIO init and stays lit; the blink series is the boot ladder
  (`boot_led.rs`, one ~25 ms pulse per rung).
- **pico-fido2 does not park** on the same condition because it tolerates the
  all-ones read deterministically (consistent garbage keys) — a firmware
  difference in failure posture, not a difference in what the hardware returned.

**Mechanism — recorded at its actual confidence:** the strongest hypothesis is
the OTP power-rail transient of RP2350 errata **E16** (the OTP read voltage
comes from an internal regulator whose power-good "isn't sampled outside of the
initial power-on reset startup sequence"). A post-flash reboot is not a
power-on reset — the bootrom marks `FLASH_UPDATE` in the watchdog scratch — so
every flash lands in the risk window. The sibling investigation measured, with
no probe attached (2026-10-01,
`fapico2-bootfreeze/docs/boot-freeze.md`), that recovery depends on the
power-off dwell: replug fast → still frozen; wait 4–5 s → boots. On
2026-10-11 this board recovered on every attempt, including fast replugs, so
the transient is marginal and not reliably reproducible on demand. What is
certain from both sessions: **the recovery is always a power cycle, never a
nuke, never a reflash.**

**Reading the LED on the shipping image** (polarity per the pending US-1303:
GPIO25 is active-high): lit from reset; one brief dark pulse per boot rung;
solid-on = parked pre-USB. Rung map (`main.rs` mark sites): 1 HAL → 2 TRNG →
3 OTP/store-key → 4 store mount → 5 DRBG → 6 migration → 7 apps → 8 USB →
9 serving. A park after pulse *n* names the window between rung *n* and *n+1*;
a park after pulse 3 is the OTP/store-key window this page is about.

## House rules that apply on these boards

- **SWD probe: read, never run** (`AGENTS.md` hardware warnings). Attaching a
  probe to *run* manufactures this exact failure class (§22 R2-26).
- picotool OTP reads of page 58 will always fail on these boards (consequence
  1 above) — audit via the lock rows and §22's SWD *read* path instead.
- The burn is irreversible; there is no "un-pico-fido2" for a board. Nothing
  needs un-doing: fapico2 and pico-fido2 share the row and both boot on it.

## References

- [`archive/SECURITY-ASSESSMENT-ROUND2.md`](archive/SECURITY-ASSESSMENT-ROUND2.md)
  §22 (R2-26) — SW_LOCK register measurements, all-ones sentinel.
- [`known-gate-divergences.md`](known-gate-divergences.md) D-13 (lock-state
  precondition for provisioning), D-14 (the runtime-only write-lock).
- `fapico2-bootfreeze/docs/boot-freeze.md` (sibling worktree) — the Oct 1
  no-probe reproduction, the dwell measurement, fatal-signature and LED-polarity
  work (**not yet merged into this tree** — the shipping image parks silently
  where that tree says why).
- [`migration-epic.md`](migration-epic.md) — the data-migration track
  (C flash FS re-seeding, key hierarchy, passphrase APDU).
- [`bootsel.md`](bootsel.md) — BOOTSEL entry, re-enumeration timing.
