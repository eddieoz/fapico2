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

Not served: **U2F/CTAP1** (every current client speaks CTAP2), **PIV** (deferred out of v1.0.0), and there is **no NFC** — a Pico 2 has no radio.

## The quirks worth knowing

These are facts about the *clients*, not defects in the board, and none of them are fixable in firmware. Full detail: [`docs/client-compatibility.md`](https://github.com/eddieoz/fapico2/blob/main/docs/client-compatibility.md).

**`ssh-keygen -K` says "invalid format" on the sign path — that means "no touch".** OpenSSH maps several different failures to the same string. The download path genuinely failed on older firmware builds; the sign path failing this way is the device waiting for the button. Touch the board and the same command succeeds.

**`ssh-keygen -K` on Ubuntu's libfido2 1.14.0 speaks a preview dialect (`0x41`).** This firmware answers it deliberately — the credential-management route serves both that and the `0x0A` modern form. A wiped board also returns "invalid format" from the download path, because libfido2 1.14.0 has no empty-success form; enroll something first and the same command reads it fine.

**gpg's scdaemon and pcscd fight over the board.** For a full OpenPGP ceremony, stop `pcscd` or set `disable-ccid` in `scdaemon.conf` — two readers claiming one device is a client-side collision, and scdaemon's internal CCID driver is the path the verified ceremony ran on.

**The OpenPGP card serial is drawn from the hardware TRNG and changes on factory reset.** Host keyring stubs (`~/.gnupg/private-keys-v1.d/`) still point at the old serial; delete the stale stubs and re-generate the association. The keys on the card are untouched.

**On-card RSA generation is slow, and gpg's reader deadline will look like a fault.** The card generates an RSA-2048 key in about 90 seconds against gpg's ~14.5-second PC/SC timeout. The ECC defaults (Ed25519 / cv25519) generate in a normal timeframe — use them.

**A factory-reset helper that waits for the classic `6983` exhaustion will wait forever.** This card's retry counter is a fixed 3 that no command can raise, so it answers `63Cx` on exhaustion and never the "locked" status some client loops wait for. The count is deliberate: it is the brute-force resistance, and no client convenience gets to weaken it.
