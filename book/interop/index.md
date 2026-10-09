# What it works with

Every tool below has been driven against real hardware; the [hardware matrix](https://github.com/eddieoz/fapico2/blob/main/docs/hardware-matrix.md) holds the verbatim evidence. The interesting part is not the green rows — it is the quirks, because those are what you hit on a Tuesday.

| Tool | What it does | Status |
|---|---|---|
| Chrome / WebAuthn | passkeys, PIN prompts, credential management | verified |
| python-fido2 2.2.1 | the full CTAP2.1 surface (this is what `ykman` and Yubico Authenticator are built on) | verified |
| `ykman` | FIDO2, OATH, OTP, device config | verified |
| Yubico Authenticator | OATH codes over CCID | verified |
| GnuPG 2.4.4 (scdaemon) | OpenPGP card: on-card generation, sign, encrypt, PIN changes | verified |
| OpenSSH (`-sk` keys via libfido2) | resident SSH keys, `verify-required` | verified |
| PicoForge | device config, credential manager, USB identity | verified |
| Yubico Authenticator (Android) | OATH codes on a phone, over a USB OTG cable | verified — set a Yubico USB identity first |
| PGPony (Android) | OpenPGP card on a phone: slots, sign, decrypt | verified — pair the public key first |
| OpenKeychain (Android) | OpenPGP card on a phone, over the same OTG path | compatible |

Not served: **U2F/CTAP1** (every current client speaks CTAP2), **PIV** (deferred out of v1.0.0), and there is **no NFC** — a Pico 2 has no radio, so phone use always means a USB OTG cable.

## On a phone

The board has no radio. Everything a phone sees arrives over a USB OTG cable, and it is the same CCID and CTAP2 surfaces the desktop uses — no separate phone firmware, nothing to install on the board. What the phone apps *do* care about is who the board claims to be: Android clients in this space are built around YubiKeys, and several filter on the USB identity. **Switch the identity to a Yubico pair (`1050:0407`) before reaching for a phone** — the [USB identity how-to](../how-to/usb-identity.md#phones-need-a-yubico-identity) is the five-minute version, and the change survives a reflash.

## The quirks worth knowing

These are facts about the *clients*, not defects in the board, and none of them are fixable in firmware. Full detail: [`docs/client-compatibility.md`](https://github.com/eddieoz/fapico2/blob/main/docs/client-compatibility.md).

**`ssh-keygen -K` says "invalid format" on the sign path — that means "no touch".** OpenSSH maps several different failures to the same string. The download path genuinely failed on older firmware builds; the sign path failing this way is the device waiting for the button. Touch the board and the same command succeeds.

**`ssh-keygen -K` on Ubuntu's libfido2 1.14.0 speaks a preview dialect (`0x41`).** This firmware answers it deliberately — the credential-management route serves both that and the `0x0A` modern form. A wiped board also returns "invalid format" from the download path, because libfido2 1.14.0 has no empty-success form; enroll something first and the same command reads it fine.

**gpg's scdaemon and pcscd fight over the board.** For a full OpenPGP ceremony, stop `pcscd` or set `disable-ccid` in `scdaemon.conf` — two readers claiming one device is a client-side collision, and scdaemon's internal CCID driver is the path the verified ceremony ran on.

**The OpenPGP card serial is drawn from the hardware TRNG and changes on factory reset.** Host keyring stubs (`~/.gnupg/private-keys-v1.d/`) still point at the old serial; delete the stale stubs and re-generate the association. The keys on the card are untouched.

**On-card RSA generation is slow, and gpg's reader deadline will look like a fault.** The card generates an RSA-2048 key in about 90 seconds against gpg's ~14.5-second PC/SC timeout. The ECC defaults (Ed25519 / cv25519) generate in a normal timeframe — use them.

**A factory-reset helper that waits for the classic `6983` exhaustion will wait forever.** This card's retry counter is a fixed 3 that no command can raise, so it answers `63Cx` on exhaustion and never the "locked" status some client loops wait for. The count is deliberate: it is the brute-force resistance, and no client convenience gets to weaken it.

**PGPony: importing the card is not enough — pair the public key.** When you import a card key, PGPony's keyring row carries the identity and fingerprints but **no public key**, and a card contact without one attached is invisible as a signer. The card looks fine in the slot list while every sign or encrypt attempt just doesn't offer the device. The fix is in the app: open the keyring and use **"Pair with Hardware Key"** to attach the public half (import it, or fetch it from a keyserver). The app stores no secret material on the phone either way — the card stays the only signer.

**PGPony signs Ed25519 and cv25519 card keys, not ECDSA ones.** The card returns raw `r‖s` from a signature operation — what GnuPG expects — but PGPony's BouncyCastle layer expects DER, so an ECDSA key (P-256, secp256k1, Brainpool) will be offered and then produce a malformed signature. Generate Ed25519/cv25519 on the card and the question never comes up. Documented in the [PGPony/Kleopatra investigation](https://github.com/eddieoz/fapico2/blob/main/docs/archive/openpgp-kleopatra-pgpony-investigation.md).
