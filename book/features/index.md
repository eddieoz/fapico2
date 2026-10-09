# Features

What the device does, and proof that it does it. Everything listed here is implemented and verified against real clients; nothing on this page is a promise. Every term is explained on the [FAQ](../faq/index.md).

## The device at a glance

| App | What you use it for | Transport | Verified with |
|---|---|---|---|
| FIDO2 | passkeys, WebAuthn, SSH (`-sk`), Linux login | CTAP-HID | Chrome, python-fido2 2.2.1, ykman |
| OpenPGP 3.4 | PGP signing/encryption, SSH auth | CCID | gpg / scdaemon 2.4.4 |
| OATH (YKOATH) | TOTP/HOTP codes | CCID | ykman, Yubico Authenticator |
| OTP | YubiKey-slot OTP, challenge-response | CCID | ykman otp |
| Management | device config, rescue surface | CCID | ykman, PicoForge |

## FIDO2 / WebAuthn

- Passkeys (WebAuthn) over **CTAP 2.1** — verified with Chrome, python-fido2 2.2.1, ykman and Yubico Authenticator
- **856 discoverable credentials (resident keys)** — measured to refusal on hardware
- Credential management: enumerate, rename, delete — via ykman or PicoForge
- Extensions: **hmac-secret, credProtect, credBlob, largeBlobKey, minPinLength**
- Large blobs (`authenticatorLargeBlobs`)
- User presence enforcement through the physical button; user verification with PIN
- **ES256** (ECDSA over P-256) — the algorithm every client requests first, and the one the device path signs with
- Permissions enforced on every token: **MC, GA, CM, ACFG, LBW**
- Authenticator configuration; vendor configuration
- **Seed backup**: the vendor seed — the soft-lock key — exports once, as a 24-word phrase, and installs on any board; passkeys themselves are non-exportable by design — [the procedure](../how-to/seed-backup.md)
- **Enterprise attestation** (`enterpriseAttestation`): a listed enterprise RP can request identifying attestation
- **Signature counters**: a persistent per-credential counter increments on every assertion
- Sealed store: credentials survive a reflash, and a flash dump alone is inert

## OATH (YKOATH)

- **TOTP and HOTP** — 68 credentials reserved in the key store
- **Access-code locking** — until the correct access code is presented, the applet answers "locked"; it persists across power cycles (hardware-verified)
- Challenge-response generation, touch-gated
- Yubico Authenticator and ykman compatible

## OTP

- **YubiKey-slot OTP** — the YubiKey one-time-password protocol over CCID
- Challenge-response generation, touch-gated challenge
- `ykman otp` compatible

## OpenPGP 3.4

- **OpenPGP card specification v3.4** — 3 key slots (Signature, Encryption, Authentication)
- RSA (2048, 3072, 4096), Ed25519, Curve25519, ECDSA (NIST P-256, P-384, P-521), secp256k1, Brainpool P-256r1
- **Key generation on device**; key import; public-key and certificate export
- PIN and Admin PIN protection; reset and unblock — via the admin PIN or a dedicated reset code
- Works with GnuPG, SSH and compatible tools over CCID

## Platform

- **Signed secure boot** (opt-in, `./build-signed.sh`): the bootrom refuses unsigned images
- **Master key in OTP**: the store key derives from a one-way-fused OTP row — nothing that seals the device lives in flash
- **Rescue interface**: reboot a running board into the mass-storage bootloader without auth or a button
- LED slot configuration via PicoForge

## Capacity

| Resource | Capacity | Notes |
|---|---|---|
| FIDO2 resident passkeys | 856 | Measured to refusal on hardware |
| OATH credentials | 68 | Reserved in the key store |

For scale: a YubiKey 5 holds 100 resident passkeys.
