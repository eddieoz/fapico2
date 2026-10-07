# Getting Started

## What you need

One Raspberry Pi Pico 2 (RP2350). That is the whole shopping list.

## Get an image

Either download the prebuilt [`fapico2.uf2`](https://github.com/eddieoz/fapico2/releases) from the release (sha256 in its release notes) or build from source — see [Contributing](../contributing/index.md) for build instructions. A first build takes tens of minutes on Linux/macOS/WSL.

## Flash it

1. Hold **BOOTSEL** on the Pico 2.
2. Plug the board into your computer via USB.
3. A drive called `RP2350` will mount.
4. Copy `fapico2.uf2` onto the `RP2350` drive.
5. Wait — the board will re-enumerate. This can take up to a minute and is normal.

The Rust build supports **physical BOOTSEL** only (hold BOOTSEL while plugging in, or BOOTSEL + tap RESET). Full procedure, both firmwares, recovery paths: [`docs/bootsel.md`](https://github.com/eddieoz/fapico2/blob/main/docs/bootsel.md).

## Use it

The board enumerates as `fa20:0002` "fapico2", a composite CCID + CTAP-HID device.

**FIDO2 works everywhere, immediately.** Chrome, `ykman`, Yubico Authenticator — passkeys and WebAuthn just work.

**Linux/macOS only:** OpenPGP and OATH need a one-time libccid allowlist edit — without it your host sees *no smartcard reader at all*, which looks like broken hardware and is not. See [`docs/identity.md`](https://github.com/eddieoz/fapico2/blob/main/docs/identity.md#pcsc-allowlist-libccid) for the procedure.

## USB identity (provisional)

The firmware enumerates as **`fa20:0002`** — manufacturer "The BLOCO Community", product "fapico2". `0xFA20` is **not** a USB-IF-registered vendor ID, so this identity is provisional: production needs a registered VID, and until then Linux and macOS need the libccid `Info.plist` allowlist edited before `pcscd` sees the CCID reader (CTAP-HID is unaffected everywhere).

## Migration from the C firmware

On the first boot after cutover from the C `pico-fido2` firmware, the Rust image detects the C data partition and **re-seeds the Rust keystore from it** (read-only, idempotent).

- **Silent (no user input):** FIDO keydev + resident credentials, OATH credentials, OTP slots, Management config, PIV objects, OpenPGP public keys / certs / DOs / PIN hashes.
- **One-time PW1/PIN step:** OpenPGP **private keys** and PIN-wrapped FIDO keydevs need the passphrase **once**.
- **Not migratable:** the vendor ChaChaPoly keydev.
