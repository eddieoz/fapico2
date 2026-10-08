# fapico2

**The F\*\*king Authenticator.** Your passkeys, PGP keys and 2FA tokens — on hardware you own.

fapico2 turns a ~$5 [Raspberry Pi Pico 2](https://www.raspberrypi.com/products/raspberry-pi-pico-2/) into a multi-applet hardware authenticator: FIDO2/U2F passkeys, OpenPGP 3.4, OATH (TOTP/HOTP) and YubiKey-protocol OTP served by **one firmware, one binary**, over one USB composite device. No vendor account, no cloud, no subscription. Written in Rust, licensed AGPLv3, built from source — or download the prebuilt image.

## Why

- **Self-custody for credentials.** Keys are generated on the device and never leave it. Everything at rest is sealed under a root key derived from a chip-unique OTP row — a flash dump lifted off your board is inert somewhere else. The same reasoning that keeps bitcoin keys off internet-connected machines applies to the keys that guard your email, your code and your accounts.
- **The whole bill of materials is one Pico 2.** No proprietary secure element to trust, no sealed hardware to return to a vendor. If you can read this, you can rebuild the device from source.
- **No network.** The device build has no network stack at all — the only networked code in the tree is the host-side emulator used for testing.
- **Works with the tooling you already have.** Chrome, `ykman`, Yubico Authenticator and GnuPG are verified against real hardware; the CTAP dialect targets Yubico's own client stack.
- **Replaces a drawer of tokens.** One board carries your FIDO2 passkeys, your OpenPGP identity, your TOTP codes and your YubiKey-protocol OTP slots.
- **Its failures are published.** A red-team assessment of an earlier build ships in full in this repository — the findings are more useful than the reassurance would be.

## What it does

| App | What you use it for | Transport | Verified with |
|---|---|---|---|
| FIDO2/U2F | passkeys, WebAuthn; CTAP2.1 incl. credProtect, credMgmt, largeBlobs, hmac-secret | CTAP-HID | Chrome, python-fido2 2.2.1, ykman |
| OpenPGP 3.4 | PGP signing/encryption, SSH auth | CCID | gpg / scdaemon 2.4.4 (on-card ECC key generation) |
| OATH (YKOATH) | TOTP/HOTP codes | CCID | ykman, Yubico Authenticator |
| OTP | YubiKey-slot OTP | CCID | ykman otp |
| Management | device config, rescue surface | CCID | ykman, PicoForge |
| PIV | smartcard login | — | **deferred — post-v1.0.0** |

## Capacity

- **FIDO2 resident passkeys: 856** — measured to refusal on current builds. For scale: a YubiKey 5 holds 100.
- **OATH credentials: 68 slots reserved** in the key store.

## Security model, in plain terms

- **Keys are generated on the device** from the RP2350's hardware TRNG and used only there — signing happens on the chip.
- **At rest, everything is sealed.** Records are AEAD-encrypted under a root key derived from `otp_key_1` (a one-way-fused OTP row) plus the chip's own identity. The firmware **refuses to boot** if that row is unavailable — there is no public-constant fallback.
- **One bad record is not a bad day.** The per-record store commits a single credential per write, survives torn writes, and a FIDO reset cannot take OATH's credentials with it.
- **Signed secure boot is available** (`./build-signed.sh`): the bootrom refuses unsigned images. Opt-in, and off by default in the alpha.

## What this is not

1. **Not safe from someone who holds it.** Until the first `vX.Y.Z-release` tag, the SWD debug port is open on every published image. Anyone with brief physical access and a debug probe can extract every key the device holds.
2. **Not independently audited.** The published red-team assessment is of an earlier build; some of it has been addressed, not all. No warranty.
3. **Not certified and not ruggedized.** No FIPS/Common Criteria evaluation, and no NFC — a Pico 2 has no radio.
4. **Not anonymously attributable.** Default builds carry a public development attestation key, so their attestation proves nothing about key provenance.
5. **Not finished on every front.** PIV is deferred; Brainpool P-384r1 is absent from OpenPGP; CTAP1/U2F register attestation fails client-side verification (CTAP2 is unaffected).

## Getting started

**0. What you need:** one Raspberry Pi Pico 2 (RP2350). That is the whole shopping list.

**1. Get an image.** Either download the prebuilt [`fapico2.uf2`](https://github.com/eddieoz/fapico2/releases) from the release (sha256 in its release notes) or build from source.

**2. Flash it.** Hold **BOOTSEL**, plug the board in, copy the UF2 onto the `RP2350` drive that mounts, and wait — re-enumeration can take up to a minute and that is normal.

**3. Use it.** The board enumerates as `fa20:0002` "fapico2", a composite CCID + CTAP-HID device. FIDO2 works everywhere, immediately. **Linux/macOS only:** OpenPGP and OATH need a one-time libccid allowlist edit.

See [Getting Started](./getting-started/index.md) for the full procedure.

## License and security

GNU AGPLv3 — see [LICENSE](https://github.com/eddieoz/fapico2/blob/main/LICENSE) and [NOTICE](https://github.com/eddieoz/fapico2/blob/main/NOTICE).

**Not independently audited; no warranty is offered.** Read [Security](./security/index.md) before trusting this with anything you cannot afford to lose.
