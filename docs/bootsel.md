# Entering BOOTSEL mode

BOOTSEL is the RP2350 bootrom's USB mass-storage mode: the chip reboots, the
bootrom enumerates as a USB stick named `RP2350`, and the host copies a
`.uf2` to `/media/<user>/RP2350/` to flash it. There are two ways to get a
running device there, and **which one works depends on which firmware is
flashed** — read the gap note below before planning a re-flash.

| Firmware running | Programmatic (rescue APDU) | Button sequence |
|---|---|---|
| C firmware (`pico-fido2` build) | ✅ `scripts/bootsel.py --bootsel` | ✅ |
| fapico2 Rust build | ❌ **no rescue APDU in v1.0.0** — **physical BOOTSEL+RESET only** | ✅ (only way) |

## How the mechanism works (C firmware)

The pico-keys-sdk ships a **rescue app** (`pico-keys-sdk/src/rescue.c`)
registered on the CCID interface. It is selected by AID and answers a small
CLA=`0x80` command set:

| APDU | Effect |
|---|---|
| `00 A4 04 00 08 A0 58 3F C1 9B 7E 4F 21` | SELECT rescue app → returns MCU, product, version, 16-byte serial |
| `80 1F 01 00 00` | **Reboot into BOOTSEL** — requires user presence |
| `80 1F 00 00 00` | Plain reboot into the running firmware (100 ms watchdog) |

Notes from the C source:

- `INS_REBOOT_BOOTSEL` (0x1F) exists only on Pico builds (`PICO_PLATFORM`);
  it is not compiled for ESP32/emulation targets.
- **User presence**: P1=`0x01` is documented as blocking in
  `rescue_require_user_presence()` until the board button is pressed
  (default window 30 s, `button.c`), returning `SW 6985` on timeout.
  **Hardware-verified 2026-09-08:** the C firmware entered BOOTSEL with
  **no button press** — `scripts/bootsel.py --bootsel` completed
  automatically, within a few seconds, without touching the board button.
  Treat the button as a fallback only (press it *while* the APDU is in
  flight if the command stalls).
- Lc must be 0 (`SW 6700` otherwise); any other P1 → `SW 6B00`.
- After the APDU returns `9000`, the command queues `EV_RESET`; the USB task
  runs `usb_secure_reboot_now()` (`src/usb/usb.c`): interrupts off, core1
  reset, stacks + heap securely zeroed, then a chip reset. The bootrom then
  enters USB mass storage **without** the BOOTSEL pin being held — the
  "secure reboot" path.
- `80 1F 00 00 00` (plain reboot) needs no button and is useful to restart
  the firmware without touching hardware.

## Using the helper script

`scripts/bootsel.py` talks CCID through pcscd (pyscard). Requirements:
`pcscd` running and your user able to open the reader (on Ubuntu:
`sudo usermod -aG lp $USER`, then re-login).

```sh
# What firmware is on the device? (SELECT rescue AID)
python3 scripts/bootsel.py --info

# Reboot the running firmware (no button)
python3 scripts/bootsel.py --reboot

# Enter BOOTSEL — on the C firmware this completes with no button press
# (verified 2026-09-08); keep the button fallback in case the APDU stalls
python3 scripts/bootsel.py --bootsel

# Enter BOOTSEL and immediately flash the Rust build
python3 scripts/bootsel.py --bootsel --flash firmware/fapico2.uf2
```

`--bootsel --flash` waits for `/media/<user>/RP2350`, copies the `.uf2`
(size-verified), waits for the bootrom to restart the device, and waits for
the card to re-enumerate in app mode. `--reader NAME` overrides auto-detect
(it picks the reader whose name contains `pico`); `--tries N` retries the
user-presence window.

If SELECT fails with `SW 6A82` (file not found), the running firmware has no
rescue app — see the gap note.

## Button sequence (always works, both firmwares)

1. Hold the **BOOTSEL** button.
2. Press and release the **RESET** button (while still holding BOOTSEL).
3. Keep holding BOOTSEL until the `RP2350` volume appears.
4. Release BOOTSEL; copy the `.uf2` to `/media/<user>/RP2350/`.
5. The device unmounts itself and reboots into the new firmware.

## Gap: the fapico2 Rust build has no rescue app

The Rust firmware (`apps/`, `firmware/`) does **not** implement the rescue
app: no `A0 58 3F C1 9B 7E 4F 21` AID, no `INS 0x1F`. The mgmt app's
`INS_RESET` (0x1E) is a *factory config reset* of the management
configuration, not a reboot, and it wipes admin settings. Consequences:

- **Reflashing the Rust firmware requires physical BOOTSEL+RESET** — the
  button sequence (above) is the only way; there is **no rescue APDU in
  v1.0.0**.
- There is currently no programmatic reboot of the Rust build either; for
  the re-flash-persistence test, a USB unplug/replug is a full power cycle
  (the board is USB-powered) and is the supported substitute.
- Porting the rescue app is a *new feature*, which the migration epic
  prohibits until after the US-393 cutover — expect this page to change when
  the port lands.

## Status

The APDU contract above is verified against the C sources
(`pico-keys-sdk/src/rescue.c`, `src/apdu.c`, `src/usb/usb.c`,
`src/button.c`). The rescue-APDU path has been **exercised on the board**
with the C firmware flashed: **verified 2026-09-08** —
`scripts/bootsel.py --bootsel` entered BOOTSEL with **no button press**
(automatic, within a few seconds). The Rust build has no rescue app; on it,
only the physical BOOTSEL+RESET sequence works.
