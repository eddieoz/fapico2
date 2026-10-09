# Getting Started

## The hardware

One Raspberry Pi Pico 2 (RP2350) and a USB cable. That is all the hardware there is. What "compatible" means and which boards on the market match: [Compatible devices](../hardware/index.md).

## Where the image comes from

Download the prebuilt [`fapico2.uf2`](https://github.com/eddieoz/fapico2/releases) from the release (sha256 in its release notes) or build from source — see [Contributing](../contributing/index.md) for build instructions. A first build takes tens of minutes on Linux/macOS/WSL.

## Putting it on the board

The same on every OS — the bootrom presents a USB mass-storage drive:

1. Hold **BOOTSEL** on the Pico 2.
2. Plug the board into your computer via USB.
3. A drive called `RP2350` will mount (Linux: `/media/$USER/RP2350`; Windows/macOS: the `RP2350` drive in Explorer/Finder).
4. Copy `fapico2.uf2` onto the drive.
5. Wait — the board will re-enumerate. This can take up to a minute and is normal.

Linux users who prefer the command line: [`scripts/bootsel.py`](https://github.com/eddieoz/fapico2/blob/main/scripts/bootsel.py) reboots a running board into BOOTSEL over the Rescue applet and flashes for you (`--bootsel --flash firmware/fapico2.uf2`). The Rust build supports **physical BOOTSEL** only otherwise: hold BOOTSEL while plugging in, or BOOTSEL + tap RESET. Full flashing and recovery reference: [`docs/bootsel.md`](https://github.com/eddieoz/fapico2/blob/main/docs/bootsel.md).

## Talking to it

The board enumerates as `fa20:0002` "fapico2", a composite CCID + CTAP-HID device. Set a FIDO2 PIN first (`ykman fido access change-pin` or the browser prompt): on a PIN-set board every operation requires the PIN and a touch. Then per host:

### Linux

- **FIDO2 — nothing to install.** The kernel's `usbhid` driver picks the board up; Chrome, `ykman`, and Yubico Authenticator work immediately.
- **Smartcard applets (OpenPGP, OATH, OTP) need a one-time libccid allowlist edit.** libccid has no wildcard, so the reader is invisible to `pcscd` until you append `0xFA20` / `0x0002` to the `ifdVendorID` / `ifdProductID` / `ifdFriendlyName` arrays in `/etc/libccid_Info.plist` (on Debian/Ubuntu, `ifd-ccid.bundle` is a symlink to that file) and run `sudo systemctl restart pcscd`. Without it your host sees *no smartcard reader at all* — that looks like broken hardware and is not. Full procedure: [`docs/identity.md`](https://github.com/eddieoz/fapico2/blob/main/docs/identity.md#pcsc-allowlist-libccid).
- **Building from source** is native — see [Contributing](../contributing/index.md).

### macOS

- **FIDO2 — works immediately**, in Safari, Chrome and libfido2-based tools; no driver step exists on macOS for the HID interface.
- **Smartcard applets need the same libccid allowlist edit** as Linux — the plist lives wherever libccid is installed on your system. Until then the CCID reader does not appear, which again looks like broken hardware and is not. See [`docs/identity.md`](https://github.com/eddieoz/fapico2/blob/main/docs/identity.md#pcsc-allowlist-libccid).
- **Building from source** is native — see [Contributing](../contributing/index.md).

### Windows

- **FIDO2 — works immediately**: browsers speak FIDO over HID natively, and no allowlist concept applies.
- **Smartcard applets over CCID are not verified on Windows yet** — flashing and FIDO2 are the paths we stand behind. If a smartcard client does not see the reader, that is why.
- **Building from source**: use WSL — a first build takes tens of minutes there. See [Contributing](../contributing/index.md).

## USB identity

The firmware enumerates as **`fa20:0002`** — manufacturer "The BLOCO Community", product "fapico2". `0xFA20` is not a USB-IF-registered vendor ID, so Linux and macOS need the libccid `Info.plist` allowlist edited before `pcscd` sees the CCID reader (CTAP-HID is unaffected everywhere). Production deployments need a registered VID — see the [USB identity how-to](../how-to/usb-identity.md) for changing it on a running board.

## First steps after flashing

- **Set the FIDO2 PIN** — every WebAuthn operation needs it and a touch.
- **Register a passkey** somewhere you actually log in — see the [SSH how-to](../how-to/ssh.md) and the [Linux login how-to](../how-to/linux-auth.md).
- **Enrol your TOTP codes** with `ykman oath` once the allowlist edit is done.
- **Generate your PGP key on the card** with `gpg --card-status` and `gpg --change-pin` for the card's own PIN.
