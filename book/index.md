# fapico2

<div class="hero">

**The F\*\*king Authenticator.** Your passkeys, PGP keys and 2FA tokens — on hardware you own.

fapico2 turns a ~$5 [Raspberry Pi Pico 2](https://www.raspberrypi.com/products/raspberry-pi-pico-2/) into a multi-applet hardware authenticator: FIDO2 passkeys, OpenPGP 3.4, OATH (TOTP/HOTP) and YubiKey-protocol OTP served by **one firmware, one binary**, over one USB composite device. No vendor account, no cloud, no subscription. Written in Rust, licensed AGPLv3 — build it from source or download the prebuilt image.

</div>

## Read this first

**fapico2 is experimental.** No audit outside this project has looked at the code, the RP2350 carries no secure element, and what stands between a lab and your keys is the sealing design plus whatever hardening you have burned into the board. Do not put a credential on it whose loss you could not survive. The [threat model](./threat-model.md) and [security](./security/index.md) pages name what the chip cannot stop — read them before the first enrolment, not after the first incident.

## Keys never touch an online machine

- **Generated on the device, and they stay there.** Every key comes from the RP2350's hardware TRNG and every signature happens on the chip. Nothing crypto-related ever leaves the board.
- **Sealed at rest.** Everything is AEAD-encrypted under a root key derived from a one-way-fused OTP row plus the chip's own identity. A flash dump lifted off your board is inert somewhere else — recovering the root key from the chip itself takes physical possession and very sophisticated lab methods, not a USB cable. The same reasoning that keeps bitcoin keys off internet-connected machines applies to the keys that guard your email, your code and your accounts.
- **No network.** The device build has no network stack at all. There is no channel to exfiltrate through, because there is no channel.
- **No one else's copy.** A passkey synced to a phone vendor's cloud lives on every device signed into that account, and you trust the vendor's sync to keep it. A resident passkey on fapico2 exists on one board you own.
- **Nothing to revoke, no one to trust.** No account to suspend, no server to breach, subpoena or shut down. The board answers to you and works as long as the board does.

## What it is for

Each applet replaces a habit that leaks. Six of the everyday ones:

<div class="usecase-grid">
  <div class="usecase">
    <div class="uc-icon">🔑</div>
    <h3>Passkey logins</h3>
    <p>Register once in any browser; from then on, login is a touch and the PIN. Room for <strong>856 resident passkeys</strong> — a YubiKey 5 holds 100.</p>
  </div>
  <div class="usecase">
    <div class="uc-icon">⌨️</div>
    <h3>Passwordless SSH</h3>
    <p>Resident <code>-sk</code> keys with <code>verify-required</code>: the private half never touches a disk. <a href="./how-to/ssh.md">Walkthrough.</a></p>
  </div>
  <div class="usecase">
    <div class="uc-icon">🔒</div>
    <h3>Linux login</h3>
    <p>The board answers PAM at the login prompt — a stolen password alone gets nobody in. <a href="./how-to/linux-auth.md">Walkthrough.</a></p>
  </div>
  <div class="usecase">
    <div class="uc-icon">✉️</div>
    <h3>Encrypted to the recipient</h3>
    <p>OpenPGP 3.4 signs and decrypts from the card: mail and files sealed for one reader, not for the channel.</p>
  </div>
  <div class="usecase">
    <div class="uc-icon">💾</div>
    <h3>Disk encryption gate</h3>
    <p>The <code>hmac-secret</code> extension hands LUKS its unlock secret only while the board is present and touched.</p>
  </div>
  <div class="usecase">
    <div class="uc-icon">⏱️</div>
    <h3>Second factor, in your pocket</h3>
    <p>TOTP and HOTP codes computed on the board, read through Yubico Authenticator — the phone holds none of them.</p>
  </div>
</div>

## What it does

| App | What you use it for | Transport | Verified with |
|---|---|---|---|
| FIDO2 | passkeys, WebAuthn, SSH (`-sk`), Linux login | CTAP-HID | Chrome, python-fido2 2.2.1, ykman |
| OpenPGP 3.4 | PGP signing/encryption, SSH auth | CCID | gpg / scdaemon 2.4.4 |
| OATH (YKOATH) | TOTP/HOTP codes | CCID | ykman, Yubico Authenticator |
| OTP | YubiKey-slot OTP | CCID | ykman otp |
| Management | device config, rescue surface | CCID | ykman, PicoForge |

The board speaks dialects your machine already knows: browsers and `ykman` over CTAP-HID, GnuPG and Yubico Authenticator over CCID. See the [how-tos](./how-to/index.md) for SSH and Linux login, end to end.

## Capacity

- **856 resident passkeys** — measured to refusal on hardware. For scale: a YubiKey 5 holds 100.
- **68 OATH credentials** reserved in the key store.

One board replaces a drawer of tokens.

## Getting started

**The board:** one Raspberry Pi Pico 2 (RP2350) — nothing else on the shopping list. [What makes a board compatible.](./hardware/index.md)

**The image:** download the prebuilt [`fapico2.uf2`](https://github.com/eddieoz/fapico2/releases) (sha256 in its release notes) or build from source.

**The flash:** hold **BOOTSEL**, plug the board in, copy the UF2 onto the `RP2350` drive that mounts, and wait — re-enumeration can take up to a minute and that is normal.

**The first login:** FIDO2 works in any browser straight away. **Linux/macOS only:** OpenPGP and OATH need a one-time libccid allowlist edit.

See [Getting Started](./getting-started/index.md) for the full procedure.

## Buy me a coffee

fapico2 is free software, built in the open. If it earned its keep, send sats: ⚡ **eddieoz@sats4.life**

## License

GNU AGPLv3 — see [LICENSE](https://github.com/eddieoz/fapico2/blob/main/LICENSE) and [NOTICE](https://github.com/eddieoz/fapico2/blob/main/NOTICE).
