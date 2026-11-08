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

## Rescue `WRITE` presence: the first attempt waits for you (US-1762)

A rescue `WRITE PhyConfig` (`80 1C 01 00 …`) is touch-gated (US-1536): the
APDU is refused `6985` unless the operator presses the device button. Since
US-1762 the gate is a **blocking wait**: the first `WRITE` APDU holds the
T=1 transaction open for up to **10 s** (the D-5 bound — under the observed
~14.5 s libccid T=1 abort ceiling, the same budget the OpenPGP PSO and Nostr
CCID waits use), lighting the LED solid while it waits. A press inside that
window completes **inside the same APDU** — one attempt, no retry logic, no
timing discipline for the client. Without a press the APDU answers `6985`
byte-exactly after the 10 s, never as a host-side transport abort.

Two contracts, stated apart, because both ship:

* **Rescue `WRITE` — blocking ("the first attempt waits for you").** Press
  when the LED goes solid; the save completes in that same request. A client
  that retries anyway is harmless (the second APDU finds the grant already
  consumed and is refused `6985` if no new press arms it — a press held
  *before* the request is not consent: anti-harvest, US-921).
* **The other CCID consumers (management `WRITE_CONFIG`/`RESET`, OATH,
  OTP) — retry semantics ("retry within 10 s of your press").** Their gate
  is unchanged (US-1762's D-6: `window_grant` byte-identical): the first
  APDU answers `6985` immediately and opens a 15 s cross-call window; a
  press while it is open arms a grant that lives 10 s from the press and is
  consumed by the next APDU that arrives inside that life.

The wire shape and status words are unchanged from the RS-Key reference:
pico-keys-sdk gates the same APDU on `rescue_require_user_presence()` and
answers the same `6985`; a client built for the reference needs no new error
handling here. **PicoForge needs no change for the flow** — its config-save
cue ("Press the device button to confirm") is accurate under both contracts.
Two PicoForge-side items are recorded as named follow-ups, deliberately out
of the firmware's scope: (1) the rescue write path renders the raw
`[69, 85]` instead of its own APDU SW table's "Conditions of use not
satisfied" (`picoforge/src/hal/apdu/mod.rs:131` vs `hal/rescue/ops.rs:620`);
(2) the "Authentication Required" dialog gives no hint when no PIN exists.

### What the operator sees

`Failed to apply configuration: Write failed: [69, 85]` means **the touch
was not registered in time for that attempt** — the press landed before the
write started, after its 10 s window closed, or the button was already held
when the request arrived (a held press is deliberately not consent). The LED
is solid while the device is waiting: press while it is solid and save
again; under the blocking contract the very next save completes inside its
own request. The raw-hex rendering is PicoForge's own bypass of its SW table
(follow-up 1 above), not a firmware status word this firmware invented.

### PIN-less first-run config-save matrix (US-1765, hardware-verified 2026-11-08)

On a fresh board with **no PIN set**, the configuration-save matrix against
the D4 tiers (`apps/fido/src/vendor41.rs`), verified by driving both
transports deliberately (CCID is always enumerated; the "FIDO route" means
the client driving config over the HID transport):

| route | tier | result, no PIN | what the operator does |
|---|---|---|---|
| Rescue (CCID) | benign — LED GPIO/brightness/options | `9000` via touch | press when the LED goes solid ("Press the device button to confirm"); the blocking wait holds ≤10 s |
| Rescue (CCID) | identity — VID/PID, USB strings | `9000` via touch | the same — the rescue applet is the **recovery** surface; a forgotten PIN must not forfeit the identity repair, so no tier exists there |
| FIDO (`0x41`) | benign | `9000` via touch | "Touch your device if it flashes" — the vendor command opens a keepalive window under the HID channel tag; the press arms it (trace: `Window(0x8000_0013) → Press → Armed → Grant`, 84 ms latency) |
| FIDO (`0x41`) | identity | **`0x36` instantly, no touch asked** | PicoForge's "Authentication Required" dialog is the correct UX — the strongest gate in the `0x41` dialect is not downgraded for first-run convenience |

The coherent PIN-less path for identity writes: set a PIN on the Passkeys
screen, then retry — the client mints an `acfg` `pinUvAuthToken` and the
write succeeds (the token handshake is what `scripts/fix_usb_identity.py
write` performs; the matrix run verified the refusal side live and left the
token side to that tooling, since the board under test was PIN-less by
precondition).
