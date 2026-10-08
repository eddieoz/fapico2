# Features

## FIDO2/U2F

Passkeys and WebAuthn over CTAP-HID — works everywhere, no drivers needed. CTAP2.1 including credProtect, credMgmt, largeBlobs and hmac-secret. Verified with Chrome, python-fido2 2.2.1, ykman and Yubico Authenticator.

- **856 resident passkeys** — measured to refusal on hardware
- Resident-key recovery with `ssh-keygen -K` for [SSH](../how-to/ssh.md)
- [Linux login with PAM](../how-to/linux-auth.md)

## OpenPGP 3.4

PGP signing/encryption and SSH auth via the OpenPGP card protocol, spoken directly to GnuPG. On-card ECC key generation — the private key is generated on the chip and never exported. Verified with gpg / scdaemon 2.4.4.

- Algorithms as shipped: RSA 2048/3072/4096, NIST P-256/384/521, Ed25519, X25519, secp256k1, Brainpool P-256r1
- Symmetric at-rest: AES-256-CBC, ChaCha20-Poly1305
- CCID transport, needs the libccid allowlist on Linux/macOS

## OATH (YKOATH)

TOTP/HOTP codes, compatible with Yubico Authenticator and ykman.

- **68 credentials** reserved in the key store
- CCID transport, needs the libccid allowlist on Linux/macOS

## OTP

YubiKey-slot OTP, compatible with `ykman otp`.

- CCID transport, needs the libccid allowlist on Linux/macOS
- Touch-gated challenge supported

## Management

Device configuration and the rescue surface, compatible with ykman and PicoForge.

- Runtime VID/PID configuration
- Rescue applet: reboot a running board into the mass-storage bootloader without auth or a button — the way into BOOTSEL without touching the board

## Capacity

| Resource | Capacity | Notes |
|---|---|---|
| FIDO2 resident passkeys | 856 | Measured to refusal on hardware |
| OATH credentials | 68 | Reserved in the key store |

For scale: a YubiKey 5 holds 100 resident passkeys.
