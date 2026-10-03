# Entering BOOTSEL mode

BOOTSEL is the RP2350 bootrom's USB mass-storage mode: the chip reboots, the
bootrom enumerates as a USB stick named `RP2350`, and the host copies a
`.uf2` to `/media/<user>/RP2350/` to flash it. There are two ways to get a
running device there, and **both work on both firmwares**.

| Firmware running | Programmatic (rescue APDU) | Button sequence |
|---|---|---|
| C firmware (`pico-fido2` build) | ✅ `scripts/bootsel.py --bootsel` | ✅ |
| fapico2 Rust build | ✅ **same AID, same APDU, same script** (`apps/rescue`) | ✅ |

> **Correction (2026-10-02).** This page used to claim the Rust build had
> **no rescue applet** and that `--bootsel` worked only on the C firmware.
> That was wrong, and wrong in the expensive direction: it told a maintainer
> planning a re-flash that the only route was physically holding BOOTSEL and
> RESET on a board they could not reach. `apps/rescue/src/lib.rs` implements
> the applet — same AID `A0 58 3F C1 9B 7E 4F 21`, same CLA `0x80`, same
> `INS 0x1F` — and it is registered on the **device** build, not only the
> emulator (`firmware/Cargo.toml` → `fapico2-rescue/device`; wired in
> `firmware/src/main.rs` into `boot::RESCUE_APP` and passed to
> `register_ccid_apps`). `AGENTS.md` documented the same thing correctly all
> along; this page did not.

## How the mechanism works

Both firmwares ship a **rescue app** on the CCID interface, selected by AID
and answering a small CLA=`0x80` command set. The Rust implementation is
`apps/rescue/src/lib.rs`; the C one is `pico-keys-sdk/src/rescue.c`.

| APDU | Effect |
|---|---|
| `00 A4 04 00 08 A0 58 3F C1 9B 7E 4F 21` | SELECT rescue app → returns MCU, product, SDK version, chip id |
| `80 1F 01 00 00` | **Reboot into BOOTSEL** |
| `80 1F 00 00 00` | Plain reboot into the running firmware |

### The one thing to get right: the mode byte is in **P1**

This is the single most common mistake on this APDU, on both firmwares,
because `P2` *is* the selector byte for the other CLA=`0x80` command in this
protocol (`SECURE` puts the lock byte in P2). For `REBOOT` it is not:

```text
80 1F 01 00 00     P1 = 0x01 → BOOTSEL
80 1F 00 00 00     P1 = 0x00 → plain reboot
```

`P2` must be `0x00` (`P2_UNUSED`, `apps/rescue/src/lib.rs:375`); any other
value is refused `0x6A86`. A `P1` outside `0x00`/`0x01` is refused as well
rather than clamped — `RebootMode::from_p1` (`:469`) returns `None`, because
answering `9000` to a mode that was not performed is a lie.

**`P1 = 0x00` is a plain reboot, not BOOTSEL.** If you follow this table and
the board just restarts and re-enumerates, you sent the wrong mode byte.

```python
from smartcard.System import readers
from smartcard.util import toBytes
r = readers()[0]; c = r.createConnection(); c.connect()
c.transmit([0x00,0xA4,0x04,0x00,8] + list(toBytes('A0 58 3F C1 9B 7E 4F 21')))
c.transmit([0x80, 0x1F, 0x01, 0x00, 0x00])   # SW=9000, board leaves the bus
```

### User presence

The C firmware's `rescue_require_user_presence()` documents P1=`0x01` as
blocking on the board button (default window 30 s), returning `SW 6985` on
timeout — **but hardware verification on 2026-09-08 showed the C firmware
entered BOOTSEL with no button press at all**, within a few seconds. Treat the
button as a fallback: press it *while* the APDU is in flight if the command
stalls.

The **Rust** applet does not gate `REBOOT` on presence at all.
`cmd_reboot` (`apps/rescue/src/lib.rs:1106`) validates `P2` and the mode byte
and hands off to the injected reboot handler; nothing on that path consults
the presence runtime. That is a deliberate, threat-modelled decision
(`docs/tasks/rescue-threat-model.md` §5 / R5 — an unauthenticated surface
that can put the device into its bootloader), not an oversight. If you are
auditing the surface, start with that document. If you are just re-flashing,
expect `9000` and a board that leaves the bus.

Notes from the C source:

- `INS_REBOOT_BOOTSEL` (0x1F) exists only on Pico builds (`PICO_PLATFORM`);
  it is not compiled for ESP32/emulation targets.
- Lc must be 0 (`SW 6700` otherwise).
- After the APDU returns `9000`, the C command queues `EV_RESET`; the USB task
  runs `usb_secure_reboot_now()` (`src/usb/usb.c`): interrupts off, core1
  reset, stacks + heap securely zeroed, then a chip reset. The bootrom then
  enters USB mass storage **without** the BOOTSEL pin being held — the
  "secure reboot" path.
- `80 1F 00 00 00` (plain reboot) is useful to restart the firmware without
  touching hardware.

## Using the helper script

`scripts/bootsel.py` talks CCID through pcscd (pyscard). Requirements:
`pcscd` running and your user able to open the reader (on Ubuntu:
`sudo usermod -aG lp $USER`, then re-login).

```sh
# What firmware is on the device? (SELECT rescue AID)
python3 scripts/bootsel.py --info

# Reboot the running firmware (no button)
python3 scripts/bootsel.py --reboot

# Enter BOOTSEL — completes with no button press on either firmware
python3 scripts/bootsel.py --bootsel

# Enter BOOTSEL and immediately flash the Rust build
python3 scripts/bootsel.py --bootsel --flash firmware/fapico2.uf2
```

`--bootsel --flash` waits for `/media/<user>/RP2350`, copies the `.uf2`
(size-verified), waits for the bootrom to restart the device, and waits for
the card to re-enumerate in app mode. `--tries N` retries the user-presence
window.

If SELECT fails with `SW 6A82` (file not found), the running firmware has no
rescue applet — on a stock fapico2 image that should not happen; on anything
older than US-161, or on a board still running the C firmware built before
the rescue port, it will.

### ⚠️ Auto-detect picks the wrong board on a two-board desk

`pick_reader` (`scripts/bootsel.py:63`) matches the substring **`pico`** in
the pcscd reader name and returns the first hit. That substring comes from
the **reference C board's** reader name (`Pol Henarejos …`, on the
`pico-fido2` control device) — it is not a property of *our* hardware, and a
fapico2 unit presents a different reader name entirely.

So, on a desk with **both** a reference `pico-fido2` and a fapico2 attached:

> `--bootsel` with no `--reader` targets the **reference board**. The fapico2
> is never touched, which then looks exactly like "the rescue APDU reported
> success and the board did nothing" — a very expensive way to spend an
> afternoon.

Always pass `--reader` when more than one board is attached:

```sh
pcsc-ls                                   # list the readers
python3 scripts/bootsel.py --bootsel --reader '<the fapico2 reader name>'
```

The single-reader fallback is fine; the bug only bites with more than one
reader present.

Close anything else holding the CCID reader first (Yubico Authenticator,
`ykman`): they take an exclusive pcscd connection and the APDU then fails with
`CardConnectionException: Sharing violation. (0x8010000B)`.

## Button sequence (always works, both firmwares)

1. Hold the **BOOTSEL** button.
2. Press and release the **RESET** button (while still holding BOOTSEL).
3. Keep holding BOOTSEL until the `RP2350` volume appears.
4. Release BOOTSEL; copy the `.uf2` to `/media/<user>/RP2350/`.
5. The device unmounts itself and reboots into the new firmware.

## If the board flashed but never came back

This is the failure this page is most likely to be opened for, because the
script above reports `done: firmware flashed, device in app mode` and then
the board simply never re-enumerates — no `lsusb` entry, no `2e8a:0003`
bootrom, no mass-storage volume, and only a physical power cycle clears it.

**Do not attach an SWD probe.** A probe makes `OTP_DATA_RAW` read
`0xFFFFFFFF`, which `read_otp_key_1()` reads as "no key", and `fatal_boot`
fires before USB is even constructed — the probe manufactures the exact
failure you are trying to diagnose. (`AGENTS.md`, "Hardware warnings".)

**Instead, watch the LED.** The board LED (GPIO25) runs a boot-phase ladder in
every image, every profile, with no feature and no rebuild: **one short pulse
(25 ms) per boot boundary crossed**, then the pin parked dark. After a
successful boot the 1 Hz heartbeat takes the pin over, which is
unmistakable next to a 25 ms pulse.

| what you see | what it means |
|---|---|
| never blinks | froze at or inside `embassy_rp::init` — before the LED exists |
| **k** short pulses, then dark | froze in the stage after boundary **k** |
| 9 short pulses, then dark | every boundary crossed (`serving` included); died between the last rung and the executor's first poll |
| 9 short pulses, then a steady 1 Hz blink | boot completed — **the fault is post-boot USB enumeration**, not the boot |

| pulses | last boundary crossed | the stage it died in |
|---:|---|---|
| 1 | `hal+led-mounted` | TRNG / clock bring-up |
| 2 | `trng-clock` | **the OTP key-row read** (`derive_boot_store_key`) — the leading suspect |
| 3 | `otp-key-row-read` | secure-store slot decision / image restore |
| 4 | `secure-store-mounted` | boot entropy, DRBG, firmware manifest |
| 5 | `drbg-live` | first-boot C→Rust migration |
| 6 | `migration-done` | applet keystore boots, trussed backend mount, dispatcher |
| 7 | `app-statics-registered` | final secure-partition persist |
| 8 | `app-statics-registered` | `Usb::new` / `usb_task` spawn |
| 9 | `usb-up` | the serve-task spawns |

The encoding, the rung order and the pin-handover rule live in
`firmware/src/bootphase.rs` (pure, host-tested); the GPIO driver is
`firmware/src/boot_led.rs`; the call sites are the `mark!` sites in
`firmware/src/main.rs`. `FAPICO2_BOOT_LED=0` compiles the whole thing out if
a deployment ever decides the boot latency is worth more than the
diagnosability (see `firmware/build.rs`).

**Caveat that is worth stating:** a board that freezes *inside* one 25 ms
pulse can be read one rung either way. The pulse is short relative to the
stages it separates (hundreds of milliseconds to seconds), so the error is
rare and never more than one rung.

## Status

The APDU contract above is verified against the C sources
(`pico-keys-sdk/src/rescue.c`, `src/apdu.c`, `src/usb/usb.c`,
`src/button.c`) and, for the Rust applet, against
`apps/rescue/src/lib.rs` (AID, `INS`, `P1`/`P2` placement and the
user-presence-free `REBOOT`). The rescue-APDU path has been **exercised on
the board** with the C firmware flashed: **verified 2026-09-08** —
`scripts/bootsel.py --bootsel` entered BOOTSEL with **no button press**
(automatic, within a few seconds).

The **Rust** rescue applet is host-verified (the emulator registers the same
applet and `tests/harness/test_rescue_*.py` drive it over CCID), and
**hardware-unverified** for the BOOTSEL reboot path — nothing in this repo has
put a Rust image into BOOTSEL through it. The LED ladder above is likewise
**entirely hardware-unverified**: its encoding, ordering and release rule are
host-tested, its GPIO behaviour is not.