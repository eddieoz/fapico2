# Getting Started

## The hardware

One Raspberry Pi Pico 2 (RP2350) and a USB cable. That is all the hardware there is.

## Where the image comes from

Download the prebuilt [`fapico2.uf2`](https://github.com/eddieoz/fapico2/releases) from the release (sha256 in its release notes) or build from source — see [Contributing](../contributing/index.md) for build instructions. A first build takes tens of minutes on Linux/macOS/WSL.

## Putting it on the board

1. Hold **BOOTSEL** on the Pico 2.
2. Plug the board into your computer via USB.
3. A drive called `RP2350` will mount.
4. Copy `fapico2.uf2` onto the `RP2350` drive.
5. Wait — the board will re-enumerate. This can take up to a minute and is normal.

The Rust build supports **physical BOOTSEL** only: hold BOOTSEL while plugging in, or BOOTSEL + tap RESET. Full flashing and recovery reference: [`docs/bootsel.md`](https://github.com/eddieoz/fapico2/blob/main/docs/bootsel.md).

## Talking to it

The board enumerates as `fa20:0002` "fapico2", a composite CCID + CTAP-HID device.

**FIDO2 works everywhere, immediately.** Chrome, `ykman`, Yubico Authenticator — passkeys and WebAuthn just work. Set a PIN first (`ykman fido access change-pin` or the browser prompt): on a PIN-set board every operation requires the PIN and a touch.

**Linux/macOS only:** OpenPGP and OATH need a one-time libccid allowlist edit — without it your host sees *no smartcard reader at all*, which looks like broken hardware and is not. See [`docs/identity.md`](https://github.com/eddieoz/fapico2/blob/main/docs/identity.md#pcsc-allowlist-libccid) for the procedure.

## USB identity

The firmware enumerates as **`fa20:0002`** — manufacturer "The BLOCO Community", product "fapico2". `0xFA20` is not a USB-IF-registered vendor ID, so Linux and macOS need the libccid `Info.plist` allowlist edited before `pcscd` sees the CCID reader (CTAP-HID is unaffected everywhere). Production deployments need a registered VID — see the [USB identity how-to](../how-to/usb-identity.md) for changing it on a running board.

## First steps after flashing

- **Set the FIDO2 PIN** — every WebAuthn operation needs it and a touch.
- **Register a passkey** somewhere you actually log in — see the [SSH how-to](../how-to/ssh.md) and the [Linux login how-to](../how-to/linux-auth.md).
- **Enrol your TOTP codes** with `ykman oath` once the allowlist edit is done.
- **Generate your PGP key on the card** with `gpg --card-status` and `gpg --change-pin` for the card's own PIN.
