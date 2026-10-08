# Features

What the device does, then what each of these terms means. Everything listed here is implemented and verified against real clients; nothing on this page is a promise.

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
- ECDSA (P-256, P-384, P-521) and EdDSA (Ed25519) authentication
- Permissions enforced on every token: **MC, GA, CM, ACFG, LBW**
- Authenticator configuration; vendor configuration
- Sealed store: credentials survive a reflash, and a flash dump alone is inert

## OATH (YKOATH)

- **TOTP and HOTP** — 68 credentials reserved in the key store
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
- PIN and Admin PIN protection; reset and unblock functions
- Works with GnuPG, SSH and compatible tools over CCID

## Platform

- **Signed secure boot** (opt-in, `./build-signed.sh`): the bootrom refuses unsigned images
- **Master key in OTP**: the store key derives from a one-way-fused OTP row — nothing that seals the device lives in flash
- **Rescue interface**: reboot a running board into the mass-storage bootloader without auth or a button
- LED slot configuration via PicoForge

## What each term means

**What is a passkey (discoverable credential, resident key)?**
A login credential whose private key is generated on the device and never leaves it. The site stores only the public half. "Discoverable" means the device remembers which sites you registered, so you plug in, touch, and the site knows it is you — no username typing on the key.

**What is hmac-secret?**
A CTAP2.1 extension that lets a site or a tool derive a secret on the device — the mechanism behind FIDO2 disk encryption (LUKS / `systemd-cryptenroll`) and part of what the [SSH how-to](../how-to/ssh.md) relies on.

**What is credProtect?**
A policy extension that tells the device when a credential may be used without user verification. This firmware requires the PIN and the touch on every operation of a PIN-set board regardless — credProtect cannot weaken that.

**What are credBlob and largeBlobKey / large blobs?**
Two ways a site can store data alongside a credential: credBlob carries a small blob (32 bytes) readable without unlocking; largeBlobKey points at a large blob stored via `authenticatorLargeBlobs`.

**What is minPinLength?**
An extension that lets a site learn the device's minimum PIN length, so it can enforce the same floor when the PIN is created or changed from a web page.

**What do the permission bits (MC, GA, CM, ACFG, LBW) mean?**
Every PIN-derived token carries a set of permission bits — makeCredential, getAssertion, credential management, authenticator configuration, large-blob write. A token minted for one operation is refused for another; the firmware enforces this.

**What is TOTP / HOTP?**
Time-based and counter-based one-time passwords — the 6-digit codes an authenticator app shows. HOTP counts events instead of time. The codes are computed on the device; the phone never holds them.

**What is YKOATH?**
The protocol Yubico Authenticator and ykman speak to manage and read those codes over CCID. This applet answers it directly.

**What is challenge-response?**
Instead of a password, the verifier sends a challenge and the device answers with an HMAC computed from a secret in a slot — used by `ykman otp` and YubiKey-slot tooling. A touch-gated challenge waits for the button first.

**What is OpenPGP card 3.4?**
The smartcard standard GnuPG speaks. Your PGP identity lives on the chip: three key slots (signing, encryption, authentication), keys generated on the device, guarded by a PIN and an Admin PIN.

**What are CTAP-HID and CCID?**
The two USB transports: CTAP-HID is what browsers and FIDO2 tools speak (FIDO2/WebAuthn); CCID is the smartcard protocol (OpenPGP, OATH, OTP, management). U2F/CTAP1 is not the supported path on this firmware — FIDO2/CTAP2 is what every modern browser and tool uses.

**What is the sealed store (secure lock)?**
Every record at rest is AEAD-encrypted under a root key derived from a one-way-fused OTP row plus the chip's identity. A flash dump lifted off the board is inert somewhere else — the store key is not in the dump. See the [threat model](../threat-model.md) for what a lab-level attacker can and cannot do.

**What is secure boot?**
The RP2350's bootrom refuses to run an image that is not signed with your key. Opt-in (`./build-signed.sh`), burned into a one-way fuse once — irreversible, at your decision.

## Capacity

| Resource | Capacity | Notes |
|---|---|---|
| FIDO2 resident passkeys | 856 | Measured to refusal on hardware |
| OATH credentials | 68 | Reserved in the key store |

For scale: a YubiKey 5 holds 100 resident passkeys.
