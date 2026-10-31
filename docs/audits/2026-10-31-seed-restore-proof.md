# The seed-restore proof: one board, one phrase, one wallet — `SAME-KEY` on silicon

**Date:** 2026-10-31
**EPIC:** [FIDO-SEED-ROOT](../tasks/EPIC-fido-seed-root.md) (US-1733 live leg + US-1740)
**ADR:** [0008-seed-rooted-fido-derivation.md](../adr/0008-seed-rooted-fido-derivation.md)
**Firmware under test:** `feat/seed` at `6795c32` (US-1732..US-1739 landed), built by
`./build.sh` → `firmware/fapico2.uf2` (sha256 `45f738a0…d6`), flashed over BOOTSEL.
**Board:** one RP2350 board, USB identity `fa20:0002` ("The BLOCO Community fapico2").

## What this closes

The 2026-10-31 field report (`docs/audits/2026-10-30-wrong-key-assertion-drift.md`'s
neighbour): a seed exported from board A and imported into board B, then
re-registering the same passkey, produced a **different wallet** on B. The root
cause (EPIC §1): the resident credential ID was device-independent but the
signing scalar was keyed by a per-device TRNG `hkey`, and the exported "master
seed" was inert. This epic made the seed the FIDO derivation root (`froot`);
this transcript is the hardware proof that **restoring the phrase reproduces
the wallet**.

## The protocol — one board, because only one was on the bench

The EPIC's original scenario is two boards. One board proves the same
property with a strictly harsher wipe between the two registrations: a full
**nuke** (secure partition destroyed — seed, records, device root, PIN, all
gone) followed by a reflash of the same UF2. The board that registers passkey
#2 is not "the same device with its state intact"; it is a fresh device whose
**only** carried-over knowledge is the 24-word phrase. If the seed were still
inert, the post-nuke registration would derive under a fresh TRNG root and
the keys would differ — that is precisely the pre-epic failure, and what the
host-twin RED suite (`seed_root_restore.rs`, US-1732) reproduced before the
fix.

The cycle:

| step | action | touch |
|---|---|---|
| 0 | nuke + reflash epic HEAD → fresh device (`backup_fido.py status`: `seed: absent`) | — |
| 1 | `restore --generate` — install a fresh seed, phrase printed once | yes |
| 2 | register passkey #1 — rp `fapico2-probe.local`, user `probe`, rk=true | yes |
| 3 | `export --out` — the exported phrase is **byte-identical** to step 1's | yes |
| 4 | nuke + reflash again → fresh device (`seed: absent`) | — |
| 5 | `restore --file` — import the phrase | yes |
| 6 | register passkey #2 — same rp, same user | yes |
| 7 | compare | — |

## The transcript

**Step 0** — after the first nuke + reflash:

```
$ python3 scripts/backup_fido.py status
board at /dev/hidraw1 (product: The BLOCO Community fapico2):
  seed:          absent
  export window: open
  lock:          not engaged
```

**Step 1** — install the seed (`/dev/shm/fapico2-proof-phrase.txt`, 0600):

```
$ python3 scripts/backup_fido.py restore --generate > /dev/shm/fapico2-proof-phrase.txt
A fresh phrase was drawn from the OS random generator.
Note: this seed's entropy came from the HOST machine, not the board's TRNG —
the board only stores what this install gave it.
Seed installed. Board now reports:
  seed:          present
```

(The entropy-provenance warning is US-1738's line, live.)

**Step 2** — passkey #1 (python-fido2 2.2.1, `make_credential` rk=true, then a
sanity `get_assertion`):

```
passkey #1 cred: d752bea896f91b9d2fc26829eefa837b4b912ad57826069966b091efb0f00728
pubkey x: efbf9538feeed2ef3f765550478571c5f6d49422656c443c3e97912343d7fe5c
pubkey y: 1d30fa35274f82dea0d5187dd62dec99db126a40c4f74b7960c69b8514b515c6
assertion signed after registration: True
```

**Step 3** — export round-trips the exact phrase:

```
$ diff /dev/shm/fapico2-proof-phrase.txt /dev/shm/fapico2-proof-export.txt
PHRASES IDENTICAL — export round-trips the --generate seed
```

**Step 4** — second nuke + reflash. The board answers `seed: absent` again;
the phrase is now the only copy of the seed **anywhere**.

**Step 5** — import:

```
$ python3 scripts/backup_fido.py restore --file /dev/shm/fapico2-proof-export.txt
Touch the button on the fapico2 board at /dev/hidraw1 now…
Seed installed. Board now reports:
  seed:          present
```

(Two earlier attempts of this step and of step 1 answered `0x2D`
KEEPALIVE_CANCEL — the touch window closed before the press; retried and
succeeded. A slow human is not a defect, but the window is worth noting.)

**Steps 6–7** — passkey #2 on the restored board, compared:

```
passkey #1 cred: d752bea896f91b9d2fc26829eefa837b4b912ad57826069966b091efb0f00728
passkey #2 cred: d752bea896f91b9d2fc26829eefa837b4b912ad57826069966b091efb0f00728
passkey #1 x: efbf9538feeed2ef3f765550478571c5f6d49422656c443c3e97912343d7fe5c
passkey #2 x: efbf9538feeed2ef3f765550478571c5f6d49422656c443c3e97912343d7fe5c
passkey #1 y: 1d30fa35274f82dea0d5187dd62dec99db126a40c4f74b7960c69b8514b515c6
passkey #2 y: 1d30fa35274f82dea0d5187dd62dec99db126a40c4f74b7960c69b8514b515c6

credential IDs : EQUAL
public keys    : SAME-KEY
assertion #2 signed: True
```

**Verdict: `SAME-KEY` (exit 0).** The nuked board, carrying nothing but the
phrase, re-registered the same identity under the **byte-identical P-256
key** — and served a signature under it. The same cycle on pre-epic firmware
ends `DIFFERENT-KEY` with equal credential IDs (the field report; reproduced
as the RED run of `apps/fido/tests/seed_root_restore.rs::
two_boards_with_the_same_seed_derive_the_same_credential_key` before
US-1735 flipped it).

## The host-side gate (US-1740 step 4)

`./run_tests.sh` green on the commit under test: clippy `-D warnings` clean
(`--all-targets`), host suites **311 passed / 6 skipped**, gate scripts
**13 passed / 17 xfailed**, bootloader suites **4 passed**, emulator suites
**70 passed / 8 skipped / 1 xfailed** (including the two `test_restart`
scenarios the orphan gate had exposed — fixed by the host twin's durable
`hkey`, US-1737).

## The release-notes artifact (getInfo after the restore)

US-1740 step 3's `ykman fido info` could not run against this board: `ykman`
filters devices by VID/PID and the board enumerates under its stored
`fa20:0002` identity, not the Yubico `1050:0407` ykman binds — the documented
USB-identity condition (`docs/identity.md`, `scripts/fix_usb_identity.py`).
The equivalent artifact, read over the same CTAPHID path with the fido2
library ykman wraps, from the board **in its post-restore state**:

```
versions:       ['U2F_V2', 'FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']
aaguid:         66617069-636f-3200-0000-000000000002
options:        {'rk': True, 'alwaysUv': False, 'credMgmt': True,
                 'authnrCfg': True, 'clientPin': False, 'largeBlobs': True,
                 'pinUvAuthToken': True, 'setMinPINLength': True,
                 'makeCredUvNotRqd': True, 'enterpriseAttestation': True}
max_msg_size:   7609
algos:          [-7, -8, -35, -36]
```

PIN-less (`clientPin: false`, `makeCredUvNotRqd: true`), resident keys and
credMgmt advertised — the wire claim is exactly what the command paths honour
(AGENTS.md §4's derive-from-state rule), on a board whose derivation root is
the restored seed.

## Residuals, stated honestly

* **US-1733's pre-fix `DIFFERENT-KEY` hardware artifact was never captured on
  two boards** — the fix landed before the bench session, and only one board
  was available. The defect is instead evidenced by the host-twin RED run
  (same seed ⇒ different keys, US-1732) and by the field report itself;
  `scripts/probe_seed_restore.py` remains two-board-capable for the next time
  two boards are on the bus.
* **The seedless back-compat claim (EPIC C5) is proven by the host suites**
  (byte-identical KAT vectors, all 83 test binaries green) but not on
  silicon: proving it on a board would require clearing the installed seed,
  and the seed is monotonic by design (short of another nuke). A pre-epic
  board flashed with this HEAD and used seedlessly is the remaining informal
  check — every seedless device in the field is exactly that check.
* **`../safe-passkeys-tutorial` cross-reference not landed** — the checkout
  is not present in this workspace. The in-tree neighbour is
  [2026-10-30-wrong-key-assertion-drift.md](2026-10-30-wrong-key-assertion-drift.md):
  that audit fixed same-device drift (US-1719..US-1731); this one fixed
  cross-device restore.
* The counter-regression caveat (ADR 0008) is untestable in this cycle by
  construction: the nuke also destroyed the counter, so a fresh restored
  credential starting at 1 is indistinguishable from a fresh registration.
  The caveat stands as documented for phrase-restore onto a board that
  *keeps* its records.
* The board was left with the export window **open** and one resident
  passkey — it is a test board; `finalize` before field use.
