# The backup seed: make, retrieve, and hand over

How to back up the board's vendor master seed as a 24-word BIP-39 phrase, and
how to put that phrase — or a new seed — onto a board. The tool is
[`scripts/backup_fido.py`](../scripts/backup_fido.py); the firmware side needs
no flashing beyond any build that carries US-171/US-172 (every image since the
`0x41` vendor channel grew the backup sub-commands).

**Read §[Scope](#scope) before promising anything to a user: this backs up the
*vendor* seed, and it does not bring passkeys back.**

---

## Scope

| claim | status |
|---|---|
| Backs up the **vendor master seed** — the `0x41` channel's seed: the soft-lock key material and PicoForge's Backup screen | **yes** |
| Backs up **FIDO passkeys / resident credentials** | **no — non-exportable by design.** Credentials derive from `device_random` (`stateless::master_from_device_random`), not from this seed. No tool can export them. |
| Survives on the board through a CTAP2 reset | **yes** — `reset_from_seed` (`device_keystore.rs:2860`) clears pin_state/credentials/vault_state but never touches the vendor seed |
| Restoring replaces the previous seed | **yes, permanently** — unless you hold the *previous* seed's own phrase, it is gone |
| The phrase alone opens a locked board | **yes** — `UNLOCK` accepts the phrase's 32 bytes with no PIN and no button (the second factor *is* the phrase) |

The honest one-liner for a user: *this phrase is the master seed of the
PicoForge/RS-Key side of the board — the lock key and the Backup screen. Your
passkeys are not in it and cannot be exported by anything.*

## The four commands

```bash
python3 scripts/backup_fido.py status            # no touch, no PIN — read the flags
python3 scripts/backup_fido.py export            # seed → 24 words on stdout (touch)
python3 scripts/backup_fido.py export --out fido-seed.txt   # …or to a 0600 file
python3 scripts/backup_fido.py restore --generate   # draw a fresh seed, install, print phrase
python3 scripts/backup_fido.py restore --file fido-seed.txt
python3 scripts/backup_fido.py finalize          # close the export window forever (touch)
```

All prose goes to **stderr**; the phrase itself goes to **stdout**, so
`backup_fido.py export | pass insert fido/seed` stores exactly the words.

### status

```
board at /dev/hidraw1 (product: The BLOCO Community fapico2):
  seed:          present
  export window: open
  lock:          not engaged
```

* `seed: absent` — nothing to export; provision one with `restore --generate`.
* `export window: open` — anyone holding the board can run `export`. Close it
  with `finalize` when you are done.
* `lock: engaged` — release from PicoForge's Lock screen; this tool
  deliberately cannot unlock (the phrase-holder unlocks with PicoForge, and a
  CLI that pastes phrases into unlock prompts is a worse idea than the lock).

### export → the paper phrase

1. `backup_fido.py export` — the board asks for a **button press**; the
   terminal says "Touch the button … now".
2. Twenty-four words print. Write them on **paper**. The `--out` file is a
   convenience copy at `0600` that refuses to overwrite; paper is the backup,
   the file is a drafting aid.
3. **`finalize` when done.** Export stays possible until you do.

The phrase is plain BIP-39 (`from_entropy`, no passphrase), rendered from the
same wordlist the `bip39` crate picoforge uses — so PicoForge's Backup screen
and this tool print the *same* words for the same seed. Any BIP-39 tool that
accepts 24 words without a passphrase can re-derive the seed from the phrase;
`backup_fido.py` does it offline.

### restore → put a seed on a board

```bash
python3 scripts/backup_fido.py restore --generate   # new seed (recommended)
python3 scripts/backup_fido.py restore --file fido-seed.txt
```

* The phrase enters by hidden prompt, stdin, or `--file` — **never argv**,
  so it stays out of shell history and `/proc/*/cmdline`.
* The BIP-39 checksum is validated **before any wire traffic**.
* If the board already has a seed, the tool says so and asks for
  confirmation before replacing it. Replacing is permanent.
* `--generate` draws 32 bytes from the OS random generator, **installs
  first**, and prints the phrase only after the board confirms — no phrase on
  screen that is not already on the board. Touch required.
* Works even on a **sealed** board (window closed) — restore is exactly the
  recovery path finalize exists to protect.

### finalize → close the one-time export window

```bash
python3 scripts/backup_fido.py finalize
```

On a terminal it asks you to type `FINALIZE`; piped scripts must pass
`--yes`. Nothing is erased: the seed, the lock and every passkey stay. What
changes is monotonic and durable — **the seed can never be exported from this
board again**. A copy of the phrase written down before finalize remains a
fully working key forever; finalize protects the *board*, not the phrase.

## Recipes

### A. Provision a fresh board (the normal path)

```bash
python3 scripts/backup_fido.py restore --generate    # prints the phrase once
# write the 24 words on paper, check them by typing them back:
python3 scripts/backup_fido.py status                # seed: present, window open
python3 scripts/backup_fido.py finalize              # window closed forever
```

### B. Back up an already-provisioned board

```bash
python3 scripts/backup_fido.py status                # window must be open
python3 scripts/backup_fido.py export --out /dev/shm/fido-seed.txt
# copy to paper; shred the shm file; then:
python3 scripts/backup_fido.py finalize
```

If `status` says the window is already CLOSED, the seed was either never
exportable or already taken — a board whose window is closed has no
exportable seed, and `export` says so instead of pretending.

### C. Migrate to a replacement board

```bash
# on the OLD board (window still open):
python3 scripts/backup_fido.py export --out seed.txt
# on the NEW board:
python3 scripts/backup_fido.py restore --file seed.txt
python3 scripts/backup_fido.py finalize
rm seed.txt   # the paper copy is the backup now
```

### D. Hand a board over (deprovision the seed door)

CTAP2 reset does **not** close the export window — a factory-reset board still
exports whatever vendor seed it holds to the next person to press the button.
Before handing a board away:

```bash
python3 scripts/backup_fido.py finalize      # or: restore --generate && finalize
```

### E. Recover a locked board with the phrase

The soft lock is released from **PicoForge's Lock screen** (Unlock), using the
24-word phrase. This tool cannot do it on purpose; the phrase is the second
factor and PicoForge is the intended operator.

## PIN-set boards — read this before promising a backup flow

The tool is **touch-only by design**: it never asks for a PIN, never mints a
pinUvAuthToken, and never charges the three-strike latch. The firmware's own
policy (AGENTS.md §4 — on a PIN-set board every gated operation wants a token
*and* a button) means the gated sub-commands answer `0x36` (`PuatRequired`) on
a PIN-set board, and no amount of button-pressing changes that. Observed, not
theorized: the same suite that passes on a PIN-free store answers `0x36` once
an earlier test has set a PIN.

So:

* **PIN-free board** — the tool works as described above.
* **PIN-set board** — use PicoForge (it mints the token via ClientPin), or
  clear the PIN first. A CTAP2 reset clears the PIN and the credentials but
  **not** the vendor seed, so `reset` → tool flow → re-set the PIN in
  PicoForge is lossless for the seed; it is *not* lossless for passkeys, which
  a reset destroys.

## Device selection, and what can go wrong with it

The board answers CTAPHID on VID/PID `1050:0407` — the Yubico identity,
**deliberately** (see [identity.md](identity.md)). Consequences for this tool:

* VID/PID cannot discriminate anything; the HID product string ("The BLOCO
  Community fapico2") is shown for every candidate and a missing "pico" earns
  a caution, not a refusal.
* The **authoritative check is the MSE handshake**: on a device that reads
  `0x41` as the CTAP 2.0 preview credentialManagement command — a YubiKey's
  reading — the MSE sub-command demands pinUvAuth, so an unauthenticated MSE
  there answers an error status where a board answers `0x00` plus a COSE key.
  Every mutating command stops there with a "does not look like a fapico2
  board" message. (Reasoned from the client dialects; not measured against a
  YubiKey — none was on the bus when this was written.)
* When several devices answer the ungated `STATE` probe at all, the tool
  refuses to guess and demands `--device PATH`.

A stock Ubuntu host binds only `2E8A:10FF`; if the board is invisible at all,
that is the USB identity problem, not this tool's —
[identity.md](identity.md) and `scripts/fix_usb_identity.py` cover it.

## What the tests cover, and what they cannot

`tests/pico-fido/test_093_backup.py` drives the tool's library over the
emulator: restore→export round-trip, a **byte-exact transcription** of the
LOAD request (the test recomputes the channel key and AEAD independently and
the firmware accepts exactly those bytes), finalize→sealed→`0x30`→load-still-
works, the BIP-39 vectors cross-checked against the `bip39` 2.2.2 crate in
both directions, and the client-side phrase gates.

It does **not** cover the touch gate (the emulator auto-acks presence; the
gate's teeth are pinned in `apps/fido/tests/vendor_backup.rs`), and it is not
hardware. Interpreter matrix verified: the test venv (fido2 2.2.1 /
cryptography 50.0.1) and system python3 (fido2 1.2.0 / cryptography 44.0.3).

## Wire notes (for the next person debugging this)

* Channel: MSE sub-command `1` — P-256 ECDH, response COSE key parsed **by
  label** (`-2`/`-3`), key = `HKDF-SHA256(salt=b"", ikm=z, info=device_point)`,
  AAD = the device's uncompressed 65-byte point.
* Blobs: `nonce(12) ‖ ct ‖ tag(16)`, ChaCha20-Poly1305, **sender-chosen
  nonce both directions**, 32-byte plaintext exactly.
* Touch-fallback (`TokenOptional` + presence) is what the tool rides on: no
  PIN is ever sent, so no token, no MAC, and the three-strike latch is never
  charged. The MAC'd request shape is kept in `backup_fido.py` as executable
  dialect documentation and pinned by the transcription test.
* **Compatibility with PicoForge** (verified line-for-line against
  `../picoforge/src/hal/fido/{backup.rs,mod.rs,constants.rs,ops.rs}`): same
  vendor byte `0x41`, same sub-commands `MSE=1/EXPORT=2/LOAD=3/FINALIZE=4/
  STATE=5`, same MSE COSE key `{1:2, 3:-25, -1:1, -2:x, -3:y}` wrapped as
  `{1: cose}`, same HKDF/AAD derivation, same blob framing, same STATE keys,
  same BIP-39 rendering (the wordlist is vendored from the `bip39` crate
  PicoForge depends on). PicoForge's tokenless path (`pin: None`) emits
  exactly this tool's request shape. Two intentional differences: PicoForge
  can mint a PERM_ACFG token from a PIN (this tool is touch-only), and the
  MSE COSE map's key *order* on the wire differs (PicoForge's BTreeMap
  emits `-3,-2,-1,1,3`; the tool's `fido2.cbor` preserves insertion order
  `1,3,-1,-2,-3`) — semantically identical maps, and the firmware parses by
  key, which the e2e suite proves for the tool's order.
* Statuses worth reading on a napkin: `0x30` export refused (window closed /
  no seed), `0x3D` unlock-target-not-locked, `0x27` tag failure.
