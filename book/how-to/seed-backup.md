# The seed backup

The board holds a 32-byte **vendor master seed** — since the seed-root work it is the **FIDO derivation root**: the key material your resident passkeys derive from, as well as the [soft lock](../using/index.md#factory-reset) and PicoForge's Backup screen. The firmware can export it **once**, as a 24-word BIP-39 phrase, and install a phrase (or a fresh seed) on any board running this firmware — restoring the phrase restores the wallet for every credential created while the seed governs. Two drivers speak the same channel and print the same words for the same seed: [`scripts/backup_fido.py`](https://github.com/eddieoz/fapico2/blob/main/scripts/backup_fido.py) on the command line, and PicoForge's Backup screen.

The full record — wire notes, test coverage, failure statuses — is [`docs/backup-seed.md`](https://github.com/eddieoz/fapico2/blob/main/docs/backup-seed.md). This page is what you need to use it.

<div class="security-callout">

**The phrase is your passkey wallet — treat it like one.** The seed is the FIDO derivation root: a board wiped to bare silicon, flashed fresh and restored from the phrase alone re-derives the **same passkey private keys** for the same accounts (proven on hardware — a nuked board reproduced the byte-identical key). The blast radius matches: **anyone holding the phrase holds every passkey key it governs**, no board, no PIN, no touch. It also opens a locked board. Paper, offline, never a photo or a cloud note.

</div>

## What it is for, exactly

| Claim | Status |
|---|---|
| Backs up the vendor master seed — the soft-lock key | **yes** |
| Backs up passkeys / resident credentials | **yes, for credentials created while the seed governs** (this firmware generation and forward) |
| Restores credentials created **before** the seed was installed | **no — their keys died with the board that made them.** Re-register once on the seed-governed board; from then on the phrase carries them |
| Restores U2F/stateless registrations, hmac-secret secrets, OATH/PIV/OpenPGP/Nostr keys | **no** — device-sealed, unexportable by construction. The phrase is the FIDO wallet, nothing else |
| Carries the signature counter on restore | **no** — a restored credential starts at 1 where the old board was at *N*; some RPs warn or reject on the regression. Re-register with any RP that complains |
| Survives a CTAP2 factory reset on the board | **yes** — reset clears PIN, credentials and vault state, never the seed |
| Restoring replaces the previous seed | **yes, permanently** — unless you hold the previous seed's phrase, it is gone |
| The phrase alone opens a locked board | **yes** — no PIN, no button; the phrase *is* the second factor |

## The four commands

```bash
python3 scripts/backup_fido.py status              # read the flags — no touch, no PIN
python3 scripts/backup_fido.py export              # seed → 24 words on stdout (touch)
python3 scripts/backup_fido.py restore --generate  # draw a fresh seed, install, print phrase
python3 scripts/backup_fido.py finalize            # close the export window forever
```

`export --out file.txt` writes the phrase to a `0600` file that refuses to overwrite — a drafting aid; paper is the backup. Prose goes to stderr and the phrase to stdout, so piping into a secret store captures exactly the words. `restore` takes a phrase by hidden prompt, stdin or `--file` — never argv — and validates the BIP-39 checksum before any wire traffic.

## The export window is one-shot

Export stays possible until you run `finalize` — and the closing is **monotonic and durable**: the seed can never be exported from that board again. Nothing is erased; a phrase written down before finalize remains a fully working key forever. Finalize protects the *board*, not the phrase.

One hazard deserves its own warning: **a CTAP2 factory reset does not close the window.** A reset board still exports whatever vendor seed it holds to the next person to press the button. Never hand a board over without finalizing first.

## The procedures

**Provision a fresh board** (the normal path — no seed yet):

```bash
python3 scripts/backup_fido.py restore --generate   # prints the phrase once; write it on paper
python3 scripts/backup_fido.py status              # seed: present, window open
python3 scripts/backup_fido.py finalize            # window closed forever
```

**Back up an already-provisioned board:**

```bash
python3 scripts/backup_fido.py status              # the window must be open — if it says CLOSED, export has already been taken or refused
python3 scripts/backup_fido.py export --out /dev/shm/fido-seed.txt
# copy to paper, shred the file, then:
python3 scripts/backup_fido.py finalize
```

**Migrate to a replacement board:** export on the old board, then on the new one **reset first** (see below — the firmware refuses a seed that would orphan existing passkeys), `restore --file`, finalize the new board, delete the file. Credentials the old board created *before* its seed was installed do not migrate — re-register those once.

**Restore a wallet onto a wiped or replacement board** (reset-first — the firmware enforces it):

```bash
ykman fido reset                                # wipes board B's passkeys AND its PIN; the vendor seed it keeps
python3 scripts/backup_fido.py restore --file seed.txt
python3 scripts/backup_fido.py finalize
# register the same accounts again — the same (site, account) now derives the
# SAME key the old board had. Expect some sites to warn about the signature
# counter going backwards; re-register with any that refuse.
```

The firmware refuses the install (`0x30`) while the board holds resident passkeys and the incoming seed differs from the installed one — installing a different derivation root over existing passkeys would orphan their keys, so the tool tells you to reset first. A **same-seed** reinstall is always allowed: it cannot orphan anything. The end-to-end proof this page's claim rests on — a board nuked to bare silicon, reflashed, restored from the phrase alone, re-registering the same identity under the byte-identical key — is [`docs/audits/2026-10-31-seed-restore-proof.md`](https://github.com/eddieoz/fapico2/blob/main/docs/audits/2026-10-31-seed-restore-proof.md).

**Hand a board over:** `finalize` first — or `restore --generate && finalize` to provision it with a seed nobody holds. Do this every time a board leaves your possession, because the reset does not do it for you.

**Recover a locked board:** release the soft lock from **PicoForge's Lock screen**, using the 24-word phrase. The CLI deliberately cannot unlock — the phrase is the second factor, and PicoForge is the intended operator.

## On a PIN-set board: use PicoForge

The CLI is **touch-only by design** — it never asks for a PIN, never mints a token, never charges the three-strike latch. The firmware's own rule (a PIN-set board wants a token *and* a button) means its gated commands answer `0x36` on a PIN-set board, and no amount of button-pressing changes that. So: PIN-free board, use the CLI as written; PIN-set board, use PicoForge's Backup screen, which mints the token from the PIN. Clearing the PIN with a CTAP2 reset is lossless *for the seed* — it is not lossless for passkeys, which a reset destroys.

## Finding the right board

The tool talks CTAPHID and proves it is a fapico2 board with the MSE handshake — a device that answers the vendor channel's MSE sub-command with a pinUvAuth demand (a YubiKey's reading of `0x41`) is refused with a "does not look like a fapico2 board" message instead of proceeding. If the board is invisible altogether, that is the [USB identity](./usb-identity.md) problem, not the tool's.
