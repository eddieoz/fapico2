# Features

## FIDO2/U2F

Passkeys and WebAuthn over CTAP2.1, including credProtect, credMgmt, largeBlobs, and hmac-secret. Works with Chrome, python-fido2 2.2.1, ykman, and Yubico Authenticator.

- **856 resident passkeys** — measured to refusal on current builds
- CTAP-HID transport (works everywhere, no drivers needed)

## OpenPGP 3.4

PGP signing/encryption and SSH auth via the OpenPGP card protocol. On-card ECC key generation. Works with gpg / scdaemon 2.4.4.

- CCID transport
- Needs libccid allowlist on Linux/macOS (see [Getting Started](../getting-started/index.md))

## OATH (YKOATH)

TOTP/HOTP codes, compatible with Yubico Authenticator and ykman.

- **68 slots reserved** in the key store
- CCID transport
- Needs libccid allowlist on Linux/macOS

## OTP

YubiKey-slot OTP, compatible with ykman otp.

- CCID transport
- Needs libccid allowlist on Linux/macOS

## Management

Device configuration and rescue surface, compatible with ykman and PicoForge.

- CCID transport
- Runtime VID/PID configuration
- Rescue applet for BOOTSEL recovery

## PIV

Smartcard login — **deferred to post-v1.0.0**.

## Capacity

| Resource | Capacity | Notes |
|---|---|---|
| FIDO2 resident passkeys | 856 | Measured to refusal |
| OATH credentials | 68 | Reserved in key store |
| OTP slots | — | YubiKey-protocol |

For scale: a YubiKey 5 holds 100 resident passkeys.
