# Client compatibility notes

Firmware-side constraints and known client-side gaps that show up when a
specific host application talks to the token. Everything here is a fact about
the *client* or a deliberate firmware choice the client must live with — none
of it is fixable by editing the firmware image, and each item says which side
has to absorb it.

(The largest of these, PicoForge's single-reader PC/SC behaviour, is kept in
the README's *PicoForge compatibility* section, where a gate
(`tests/scripts/check_picoforge_compat_docs.py`) pins it; this file carries
the items that gate does not cover.)

## OpenSSH `ssh-keygen -K`: libfido2 1.14.0 sends credMgmt on `0x41`

libfido2 1.14.0's `credman_tx` transmits **every** credential-management
operation under the hard-coded command byte `CTAP_CBOR_CRED_MGMT_PRE` (`0x41`)
— there is no `0x0A` fallback in that release. This firmware serves `0x0A` for
PicoForge and python-fido2 and, since US-1618, also routes `0x41` to the
credential manager when the request's `pinUvAuthParam` verifies in the
credMgmt **preview** scope (`subCommand ‖ params`), which is what libfido2
signs. The RS-Key vendor channel keeps `0x41` for its own (vendor-scope)
requests, so the two coexist.

Consequence for the user: `ssh-keygen -K` on a board running firmware before
US-1618 fails with *"Unable to load resident keys: invalid format"* — the
vendor channel answered `0x14` and OpenSSH mapped it to
`SSH_ERR_INVALID_FORMAT` (not a PIN error; see
[`docs/known-gate-divergences.md`](known-gate-divergences.md)'s US-121
addendum). On a **wiped** board the same string appears from a correct device:
`read_rks` gets `0x2E NO_CREDENTIALS` from `enumerateRPsBegin` and libfido2
1.14.0 treats it as a hard failure — there is no empty-success form for a
Begin. **Newer libfido2 that honours the `credMgmt` getInfo option sends
`0x0A`**, which this firmware has always served, so the `0x41` path is only
reached by 1.14.x-era clients (Ubuntu's OpenSSH links it).

**Triage note — "invalid format" is not always the routing defect.** With the
fix in place, `ssh-keygen -K` succeeds (PIN; no touch). But `ssh-keygen -Y
sign` / `ssh -O verify-required` require a **touch**, and without it the device
answers `0x2D KEEPALIVE_CANCEL`, which OpenSSH maps to the *same*
`SSH_ERR_INVALID_FORMAT` string as the pre-fix routing failure. So "invalid
format" on the *sign* path means "no touch", not "misrouted credMgmt" — the
download path is the one the `0x41` routing defect broke.

## OpenPGP factory reset: the client's retry loop is shorter than this card's counter

Ten wrong VERIFYs of `00000000` then `00 E6 00 00` + `00 44 00 00`, breaking on
`6983`. It works because the counter is a hardcoded `3` that **no APDU can
raise** (the client's bound of ten can never bind) and the card answers `63Cx`,
never `6983`, on exhaustion. Do not cap it at ten or raise it — both weaken
brute-force resistance to fit one app's loop. Same class: a **touch-gated** OTP
slot (`CHAL_BTN_TRIG`) is refused `6985` at challenge time. Details in
[`docs/hardware-matrix.md`](hardware-matrix.md).

## OpenPGP serial change vs host key stubs

The OpenPGP card serial is drawn from the hardware TRNG and **changes on
factory reset / nuke**, so host keyring stubs recording the old serial
(`~/.gnupg/private-keys-v1.d/`) point at a card that no longer matches and
gnupg/Kleopatra ask for a serial that is gone. Delete the stale shadowed stubs
(back them up first); the live card's keys are unaffected — details in
[`docs/token2-hardware-validation.md`](token2-hardware-validation.md).

The **manufacturer** (AID bytes 8–9) is a different field and is fixed at
`FF FE` — the spec's range for cards that generate their own serial, matching
`../pico-fido2` and `../RS-Key`. It is deliberately *not* `00 00`, which the spec
reserves for test cards and which gpg **and** PGPOpony both render as the literal
string "test card". gpg prints the two halves on separate lines (`Manufacturer`
/ `Serial number`) but joins them in key listings, so an older board shows up as
`card-no: 0000 …` there. Unlike the serial, this field is not persisted and does
not change on reset — it is re-derived every boot. Full analysis:
[`openpgp-kleopatra-pgpony-investigation.md`](archive/openpgp-kleopatra-pgpony-investigation.md).

## OpenPGP algorithms — as shipped (hardware-verified)

`GET DATA FA` advertises **27 records, 9 each in C1/C2/C3**: RSA-2048/3072/4096,
NIST P-256/384/521, Ed25519 + X25519, secp256k1, Brainpool **P-256r1**; symmetric
is AES-256-CBC (ENC/DEC) and ChaCha20-Poly1305 (at-rest KEK). **Brainpool P-384r1
is *not* available** — deferred in `f09bc02`, refused `6A80` at PUT DATA and
absent from FA; P-512r1 was never implemented.

**gpg-proven on the part** (signature checked against the card's own public
key): Ed25519 sign/verify, cv25519 encrypt/decrypt, secp256k1 and Brainpool
P-256r1 generate/sign/verify, and the P-384r1 refusal. **RSA import, decipher
and signing are hardware-proven**; on-card *generation* works but is slow
(RSA-2048 90.5 s) against the host's ~14.5 s PC/SC deadline, which is what made
it look broken. Two client-side traps (`kdf-setup on` fails because the host
derives the KDF; `PSO:CDS` returns raw `r||s`, not DER) are documented in
[`docs/known-gate-divergences.md`](known-gate-divergences.md), as is the gpg
`disable-ccid` requirement when a pcscd-served reader is in use
(`docs/hardware-matrix.md` row 1).
