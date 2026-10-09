# The seed backup

The board holds a 32-byte **vendor master seed** — the key material behind the [soft lock](../using/index.md#factory-reset) and PicoForge's Backup screen. The firmware can export it **once**, as a 24-word BIP-39 phrase, and install a phrase (or a fresh seed) on any board running this firmware. Two drivers speak the same channel and print the same words for the same seed: [`scripts/backup_fido.py`](https://github.com/eddieoz/fapico2/blob/feat/backup/scripts/backup_fido.py) on the command line, and PicoForge's Backup screen.

The full record — wire notes, test coverage, failure statuses — is [`docs/backup-seed.md`](https://github.com/eddieoz/fapico2/blob/feat/backup/docs/backup-seed.md). This page is what you need to use it.

<div class="security-callout">

**Your passkeys are not in the phrase, and no tool can export them.** Resident credentials derive from different key material (`device_random`), non-exportable by design. The phrase carries the vendor seed: the lock key. Treat that as a wallet phrase in its own right — anyone holding it can install your seed on their board and, worse, it is the key that opens a locked board. Paper, offline, never a photo or a cloud note.

</div>

## What it is for, exactly

| Claim | Status |
|---|---|
| Backs up the vendor master seed — the soft-lock key | **yes** |
| Backs up passkeys / resident credentials | **no — non-exportable by design** |
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

**Migrate to a replacement board:** export on the old board, `restore --file` on the new one, finalize the new board, delete the file.

**Hand a board over:** `finalize` first — or `restore --generate && finalize` to provision it with a seed nobody holds. Do this every time a board leaves your possession, because the reset does not do it for you.

**Recover a locked board:** release the soft lock from **PicoForge's Lock screen**, using the 24-word phrase. The CLI deliberately cannot unlock — the phrase is the second factor, and PicoForge is the intended operator.

## On a PIN-set board: use PicoForge

The CLI is **touch-only by design** — it never asks for a PIN, never mints a token, never charges the three-strike latch. The firmware's own rule (a PIN-set board wants a token *and* a button) means its gated commands answer `0x36` on a PIN-set board, and no amount of button-pressing changes that. So: PIN-free board, use the CLI as written; PIN-set board, use PicoForge's Backup screen, which mints the token from the PIN. Clearing the PIN with a CTAP2 reset is lossless *for the seed* — it is not lossless for passkeys, which a reset destroys.

## Finding the right board

The tool talks CTAPHID and proves it is a fapico2 board with the MSE handshake — a device that answers the vendor channel's MSE sub-command with a pinUvAuth demand (a YubiKey's reading of `0x41`) is refused with a "does not look like a fapico2 board" message instead of proceeding. If the board is invisible altogether, that is the [USB identity](./usb-identity.md) problem, not the tool's.
