# fapico2

**The F\*\*king Authenticator.** Your passkeys, PGP keys and 2FA tokens — on hardware you own.

fapico2 turns a ~$5 [Raspberry Pi Pico 2](https://www.raspberrypi.com/products/raspberry-pi-pico-2/) into a multi-applet hardware authenticator: FIDO2/U2F passkeys, OpenPGP 3.4, OATH (TOTP/HOTP) and YubiKey-protocol OTP served by **one firmware, one binary**, over one USB composite device. No vendor account, no cloud, no subscription. Written in Rust, licensed AGPLv3 — build it from source or download the prebuilt image.

## Read this first

**fapico2 is experimental.** It has had no external security audit. The RP2350 is not a secure element — it is a general-purpose microcontroller, and a stolen board is only as strong as the optional OTP / secure-boot hardening you have applied to it. Do not use it to guard credentials you cannot afford to lose or have stolen. Read the [threat model](./threat-model.md) and [limitations](./security/index.md) before trusting it with anything real.

## Keys never touch an online machine

- **Generated on the device, and they stay there.** Every key comes from the RP2350's hardware TRNG and every signature happens on the chip. Nothing crypto-related ever leaves the board.
- **Sealed at rest.** Everything is AEAD-encrypted under a root key derived from a one-way-fused OTP row plus the chip's own identity. A flash dump lifted off your board is inert somewhere else — recovering the root key from the chip itself takes physical possession and very sophisticated lab methods, not a USB cable. The same reasoning that keeps bitcoin keys off internet-connected machines applies to the keys that guard your email, your code and your accounts.
- **No network.** The device build has no network stack at all. There is no channel to exfiltrate through, because there is no channel.
- **No one else's copy.** A passkey synced to a phone vendor's cloud lives on every device signed into that account, and you trust the vendor's sync to keep it. A resident passkey on fapico2 exists on one board you own.

## What it does

| App | What you use it for | Transport | Verified with |
|---|---|---|---|
| FIDO2/U2F | passkeys, WebAuthn, SSH (`-sk`), Linux login | CTAP-HID | Chrome, python-fido2 2.2.1, ykman |
| OpenPGP 3.4 | PGP signing/encryption, SSH auth | CCID | gpg / scdaemon 2.4.4 |
| OATH (YKOATH) | TOTP/HOTP codes | CCID | ykman, Yubico Authenticator |
| OTP | YubiKey-slot OTP | CCID | ykman otp |
| Management | device config, rescue surface | CCID | ykman, PicoForge |

Works with the tooling you already have: the CTAP dialect targets Yubico's own client stack, the OpenPGP card speaks protocol 3.4 to GnuPG, and the OATH applet answers Yubico Authenticator. See the [how-tos](./how-to/index.md) for SSH and Linux login, end to end.

## Capacity

- **856 resident passkeys** — measured to refusal on hardware. For scale: a YubiKey 5 holds 100.
- **68 OATH credentials** reserved in the key store.

One board replaces a drawer of tokens.

## Getting started

**0. What you need:** one Raspberry Pi Pico 2 (RP2350). That is the whole shopping list.

**1. Get an image.** Download the prebuilt [`fapico2.uf2`](https://github.com/eddieoz/fapico2/releases) (sha256 in its release notes) or build from source.

**2. Flash it.** Hold **BOOTSEL**, plug the board in, copy the UF2 onto the `RP2350` drive that mounts, and wait — re-enumeration can take up to a minute and that is normal.

**3. Use it.** FIDO2 works everywhere, immediately. **Linux/macOS only:** OpenPGP and OATH need a one-time libccid allowlist edit.

See [Getting Started](./getting-started/index.md) for the full procedure.

## License

GNU AGPLv3 — see [LICENSE](https://github.com/eddieoz/fapico2/blob/main/LICENSE) and [NOTICE](https://github.com/eddieoz/fapico2/blob/main/NOTICE).
