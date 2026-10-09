# FAQ

The practical questions first, then every term this site uses, explained.

## The practical questions

**What do I need on my computer to use it?**
For FIDO2, nothing — browsers and libfido2 clients speak CTAP-HID natively. OpenPGP, OATH and OTP go over CCID, and on Linux/macOS that means a one-time libccid allowlist edit before your host sees the smartcard reader (see [Getting Started](../getting-started/index.md)). Tools worth having: `ykman` and PicoForge for management, GnuPG for the OpenPGP card. What each tool can and cannot do, quirks included: [What it works with](../interop/index.md).

**What happens if I forget the PIN?**
Nothing recovers it — that is the design, not an oversight. A factory reset issued from any FIDO2 client clears the PIN and takes every FIDO credential on the board with it; the OATH, OTP and OpenPGP applets keep their records. If a reset is your recovery plan, the credentials were never backed up anywhere — plan for that before you need it.

**What happens if I lose the board?**
A resident passkey exists on that one board and nowhere else — there is no cloud copy to fall back on, and no export either: passkeys are non-exportable by design. For accounts you cannot afford to be locked out of, register a second authenticator of any kind and store its recovery codes with your emergency documents. The [seed backup](../how-to/seed-backup.md) does not carry passkeys — it carries the vendor seed behind the soft lock, which is why a lost board means re-enrolling and a lost phrase for an *exported* seed means a key loose in the world.

**Why not just buy a YubiKey?**
Capacity and source. This holds 856 resident passkeys to a YubiKey 5's 100, and the firmware is AGPLv3 — you can build it, read it and change it instead of trusting a vendor's black box. What you give up is on the [threat model](../threat-model.md) page: no secure element (a lab with the board can do things a lab with a YubiKey cannot), no NFC, no certifications.

**Can I sync my passkeys across devices?**
No. Passkey sync means a vendor's cloud holds a usable copy of your credential and you hold an account with that vendor. A resident passkey here exists on one board you control — that is the whole trade.

**Why does everything ask for the PIN and a touch once the PIN is set?**
Deliberate. The firmware requires both on every operation of a PIN-set board, and no WebAuthn option can switch either off — a board that leaves your pocket opens nothing by itself. The reasoning is on the [Security](../security/index.md) page.

**Is U2F supported?**
No — FIDO2/CTAP2 only. Every browser and FIDO tool in current use speaks CTAP2; the legacy U2F path was left out on purpose, and nothing modern misses it.

**Is it certified?**
No FIPS, no Common Criteria, and no external audit — three red-team rounds are published in full instead, with every finding marked [FIXED, accepted or open](https://github.com/eddieoz/fapico2/blob/main/docs/archive/SECURITY-ASSESSMENT-ROUND3-REMEDIATION.md). Certification and honesty are different products; this project sells the second.

## The terms

**What is a passkey (discoverable credential, resident key)?**
A login credential whose private key is generated on the device and never leaves it; the site stores only the public half. "Discoverable" means the device remembers which sites you registered — plug in, touch, and the site knows it is you. No username is stored on the key.

**What is hmac-secret?**
A CTAP2.1 extension that lets a site or a tool derive a secret on the device — the mechanism behind FIDO2 disk encryption (LUKS / `systemd-cryptenroll`) and part of what the [SSH how-to](../how-to/ssh.md) relies on.

**What is credProtect?**
A policy extension that tells the device when a credential may be used without user verification. This firmware requires the PIN and the touch on every operation of a PIN-set board regardless, so credProtect cannot weaken anything here.

**What are credBlob and largeBlobKey / large blobs?**
Two ways a site can store data alongside a credential: credBlob carries a small blob (32 bytes) readable without unlocking; largeBlobKey points at a large blob stored through `authenticatorLargeBlobs`. The store behind it is deliberately small on this board — about 960 bytes — so it carries protocol payloads, not files.

**What is minPinLength?**
An extension that lets a site learn the device's minimum PIN length, so it can enforce the same floor when the PIN is created or changed from a web page.

**What do the permission bits (MC, GA, CM, ACFG, LBW) mean?**
Every PIN-derived token carries a set of permission bits — makeCredential, getAssertion, credential management, authenticator configuration, large-blob write. A token minted for one operation is refused for another, and the firmware enforces that itself.

**What is TOTP / HOTP?**
Time-based and counter-based one-time passwords — the 6-digit codes an authenticator app shows. HOTP counts events instead of time. The codes are computed on the device; the phone never holds them.

**What is YKOATH?**
The protocol Yubico Authenticator and ykman speak to manage and read those codes over CCID. This applet answers it directly.

**What is challenge-response?**
Instead of a password, the verifier sends a challenge and the device answers with an HMAC computed from a secret in a slot — used by `ykman otp` and YubiKey-slot tooling. A touch-gated challenge waits for the button first.

**What is OpenPGP card 3.4?**
The smartcard standard GnuPG speaks. Your PGP identity lives on the chip: three key slots (signing, encryption, authentication), keys generated on the device, guarded by a PIN and an Admin PIN.

**What are CTAP-HID and CCID?**
The two USB transports: CTAP-HID is what browsers and FIDO2 tools speak (FIDO2/WebAuthn); CCID is the smartcard protocol (OpenPGP, OATH, OTP, management). See "Is U2F supported?" above for the legacy path.

**What is the sealed store?**
Every record at rest is AEAD-encrypted under a root key derived from a one-way-fused OTP row plus the chip's identity. A flash dump lifted off the board is inert somewhere else — the store key is not in the dump. The [threat model](../threat-model.md) covers what a lab-level attacker can and cannot do.

**What is secure boot?**
The RP2350's bootrom refuses to run an image that is not signed with your key. Opt-in (`./build-signed.sh`), burned into a one-way fuse once — irreversible, at your decision.
