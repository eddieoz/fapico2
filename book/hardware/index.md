# Compatible devices

fapico2 runs on the Raspberry Pi Pico 2, and today that is both the verified board and the definition of "the board": one board file ships, `firmware/boards/pico2.toml`, because one board exists.

## What a board needs

The firmware pins four things, and a board on the market must match all of them:

| Requirement | Why |
|---|---|
| **RP2350 microcontroller** | The whole security story — the OTP-derived store key, the bootrom's signed-boot support, the hardware TRNG — lives in the RP2350. An RP2040 (Pico 1, Pico 1 W) does not have any of it and cannot run this firmware. |
| **4 MiB QSPI flash** | The flash map — app, keystore partition, dual-slot store — is laid out for 4096 KiB and the linker script is generated from that number. A different flash size means a different board file, not a tweak. |
| **BOOTSEL wired the Pico 2 way** | Flashing happens through the bootrom's USB mass-storage bootloader; the button read as GPIO1 is what the device's own button input expects. |
| **Activity LED on GPIO25** | The Pico 2's default LED pin — the touch prompts and status blinks drive it. |

## What is verified

**Raspberry Pi Pico 2** — the board every hardware result in the [acceptance matrix](https://github.com/eddieoz/fapico2/blob/main/docs/hardware-matrix.md) was captured on: the full OpenPGP ceremony, FIDO2 over CTAP-HID, OATH, management, and flash persistence across power cycles.

**Raspberry Pi Pico 2 W** — the same RP2350 with the same 4 MiB flash, and the firmware has no network stack, so the radio simply stays unused. It is expected to work but has not been through the matrix; treat it as unverified until someone runs it.

## What about other boards?

Anything on the market with an RP2350 and 4 MiB flash is a candidate, not a promise — and we do not list verification we have not done. If you want to bring one up, the second board is a **data change, not a code change**: copy `firmware/boards/pico2.toml`, set the LED pin, button pin and flash size, and build with `FAPICO2_BOARD=<name>`. Unknown keys, pins above GPIO29, or a flash size outside the supported window are hard build failures, so a wrong board file fails loudly instead of flashing something broken. The procedure and the exact file contract are in [`docs/hardware-matrix.md`](https://github.com/eddieoz/fapico2/blob/main/docs/hardware-matrix.md)'s board section — and results from a second board belong back in the matrix.

## Buying checklist

- **RP2350**, not RP2040 — the Pico 2 family, or an RP2350 board from another maker that exposes BOOTSEL.
- **4 MiB flash** on board.
- A **BOOTSEL button** you can hold while plugging in.
- USB-C or micro-USB, whatever the board carries — the firmware is transport-agnostic.
