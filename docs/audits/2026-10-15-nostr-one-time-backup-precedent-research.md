# Research round 4: the "one-time backup at creation" precedent, fact-checked

Date: 2026-10-15 · Follow-up to
[2026-10-15-nostr-import-only-pin-session-research.md](2026-10-15-nostr-import-only-pin-session-research.md)
(round 3, H4: import-only + single PIN + power-cycle session). This round
fact-checks the two precedents behind the round-4 proposal — "the user gets
one chance to save the key at creation, then it never leaves the device" —
and re-evaluates a GENERATE-with-one-time-reveal mode (H5) against them.

## Fact-check 1: what Kleopatra/gpg actually do

The user's observation was real, but the mechanism is not what it looks like:

- **Kleopatra** ("Generate new card keys and a certificate") offers a
  "Backup encryption key" checkbox — but it covers **only the encryption
  subkey**, and only when the card reports the `LocalKeyBackup` capability
  (`GenCardKeyDialog`, KDE/kleopatra `src/dialogs/gencardkeydialog.cpp`).
- **gpg** (`--card-edit` → `generate`) asks "Make off-card backup of
  encryption key? (Y/n)" (`g10/card-util.c`).
- **How the backup is possible at all** (GnuPG advisory, 2024-01-25,
  gnupg.org/blog/20240125-smartcard-backup-key.html): *"the gpg-agent creates
  the key and stores it as usual on disk. After the key has been moved to the
  smartcard and the protected backup has been written, the original on-disk
  key is replaced by a shadow-key."* **The key is host-generated; the card
  never had a non-exportable secret in the backup path.** Genuinely
  card-generated keys have no backup, ever — the spec forbids reading them
  ("Private keys and passwords shall not be readable from the card with any
  command or function", OpenPGP card 3.4 §4.4).
- The move (`keytocard`) is a move: Yubico's guidance is "create a backup of
  your key" *before* it, because the keyring copy is replaced by a stub
  (developers.yubico.com/PGP/Importing_keys.html).

**So the OpenPGP precedent is: the backup is taken while the key is still
host-held.** The "one chance" exists because afterwards the host copy is
deliberately destroyed — the backup moment and the move are the same
ceremony. This is exactly round 3's import posture.

### Precision after owner observation (Kleopatra card ceremony, 2026-10-15)

The owner ran the ceremony and confirmed the backup prompt appears inside
"generate keys on card". Decomposed, the ceremony splits the three keys:

- **Sign and authentication keys: genuinely card-generated** (GENKEY returns
  the public key only; opcard's `gen.rs:378,401` serializes public only) and
  **never backed up**.
- **Encryption subkey: host-generated when backup is taken.** The backup
  prompt in `card-util.c` is gated on the card's **key-import capability**
  (`info.extcap.ki` — the Extended Capabilities "key import" bit), which is
  the tell: a backup of an imported key needs import support, not on-card
  generation. The advisory's mechanism sentence covers this key: gpg-agent
  creates it on disk, writes the encrypted `sk_<keyid>.gpg`, moves it to the
  card, shadows the on-disk copy.

The user-visible shape — "device creates my keys, I get one chance to save a
backup, then the gate closes" — is therefore **implemented by gpg as
host-generation of the backed-up key**. Two consequences for this design:

1. The ecosystem-faithful way to give Nostr users "one chance to save at
   creation" is the extension generating + showing once + importing (round 3's
   import posture). GnuPG gets the backup by *not* generating the backed-up
   key on the card.
2. A device-generated-then-revealed key (H5) is a capability **neither
   ecosystem offers**: the card spec forbids reading card-generated keys, and
   the wallets keep the reveal on-device-screen. H5's only license is this
   repo's own backup-seed window (Decision 3 below).

Side observation from the same ceremony: on-card **RSA** key generation on
opcard/trussed is slow enough to blow the ceremony timeout (RSA2048 fails,
curve25519 succeeds) — a separate applet-performance issue, unrelated to
backup mechanics.

## Fact-check 2: the wallet/Nostr precedents

- **Hardware wallets** — the real "shown once, never again": Ledger and
  Trezor generate on-device and display the seed **on the device's own
  screen**; the secret never crosses USB at creation; no firmware export
  command exists. Trezor verbatim: "Your Trezor device will only show you
  your wallet backup once" (trezor.io support). **The load-bearing element is
  the trusted device screen.** A screenless token cannot implement this
  ceremony: every surface that could render the reveal is the host.
- **Software wallets and Nostr clients re-reveal freely** — Electrum (Wallet
  → Seed), Sparrow (View Seed), BlueWallet, Phoenix, Amethyst (Backup keys
  screen), Damus (Settings → Key, behind Face ID), nos2x (nsec show/hide
  toggle). "Shown once" is false for all of them because the app holds the
  key.
- **Gossip is the closest middle precedent**: the You page shows the
  *encrypted* key (ncryptsec) freely; a raw export is an explicit one-way
  act that permanently downgrades a tracked `KeySecurity` from `Medium`
  ("locally generated and never exported") to `Weak` ("either imported or
  has been exported"). The ecosystem's own taxonomy says a revealed
  device-generated key **is an exported key**, not a hardware-wallet key.

## The precedent that actually applies to this repo

**`docs/backup-seed.md` — the vendor master seed.** The repo already operates
a one-time-reveal window for a device-held secret: export behind a touch,
printed once, closed forever by `finalize`. That is the true precedent class
for a screenless device: not the wallet screen, not the software wallet, but
a **deliberate, one-way, host-crossing export window with an explicit
finalize**. H5 is that pattern applied to Nostr identities — a pattern this
repo ships today for the seed.

## Analysis: is a one-time reveal of a device-generated Nostr key (H5) self-defeating?

Round-4 draft claim: "once revealed, the key is host-held and
custody-identical to an imported key." Skeptic verdict: **direction holds,
framing was overconfident**. The honest accounting:

**What H5 genuinely buys over import-only:**
1. **Post-ceremony host compromise finds nothing.** Import-only leaves the
   nsec in client storage indefinitely (every audited client re-reveals);
   H5 crosses the host exactly once and is gone. For users who store keys in
   clients, this is a real, permanent difference.
2. **TRNG provenance.** A compromised host can shape webcrypto randomness;
   device-generated keys have unforgeable origin (the PIV-attestation
   argument). Small but real.
3. **No persistent client custody.** The extension holds nothing before,
   during (after capture), or after.

**What H5 costs:**
1. **The capture trap** (round 2, unchanged): a dismissed MV3 popup mid-ceremony
   silently degrades the identity to "on-device only, no backup" — which is
   precisely the hardened posture the user did not choose. Mitigation remains
   the round-2 ceremony conditions (echo-back proof-of-copy, commit-before-
   reveal, persistent unbacked nag).
2. **It breaks the import-only property the model advertises.** A reveal
   opcode for generated keys is, on the wire, the export door round 3
   deleted — restricted to the creation instant, but it exists. If shipped,
   it must be labeled honestly in the Gossip sense: this key has left the
   device once; it is not a hardware-wallet key.
3. **A rejected analogy must not be used to sell it.** The Ledger/Trezor
   ceremony cannot occur on this hardware (no screen); the OpenPGP rule
   ("shall not be readable") is the rule a reveal violates. H5's license is
   the repo's own backup-seed window, not either ecosystem's wallet model.

**Rejected alternative (skeptic verdict: reject):** passphrase-wrapped
encrypted backup for generated keys (Gossip ncryptsec style). The device
would have to wrap, so the passphrase and the blob cross USB in the same
ceremony — any host that captures one captures both; zero improvement over
the bare reveal at the cost of real firmware surface (a KDF on RP2350, a new
opcode, a passphrase dialect over two transports). AGENTS.md §5: no named
attack stopped.

## Design resolution

Round 3's H4 **holds as the model**; the one-time backup re-enters as an
**opt-in creation-time posture**, not a change to it:

```
Creating an identity (extension, after PIN session unlock + touch):

  IMPORT path   — paste your nsec (you already hold it; nothing new to save)
  GENERATE path — choose:
     [ ] Hardened  : the scalar never leaves the board. No backup is possible;
                     if this board dies or the PIN is forgotten+reset, the
                     identity is gone. (OpenPGP on-card semantics)
     [x] Backup once: the scalar is shown exactly once, now, then the gate
                     closes forever. (backup-seed semantics)
```

- Both GENERATE postures are PIN-session-gated and touch-gated; the reveal is
  a response-shape change to GENERATE plus a GET_INFO capability bit (round
  2's engineering notes carry over verbatim, including extension-first
  sequencing and the CCID-only emulator trap).
- The wire truth stays honest: a backup-once key is, by the ecosystem's own
  taxonomy, an exported key. The extension should say so in the ceremony.
- IMPORT keys need no ceremony: the user is pasting a key they already hold —
  "one chance to save it" is vacuous there.

## Decision Log

| # | decision | rationale |
|---|---|---|
| 1 | The OpenPGP "backup at device-key creation" precedent is a **host-held-moment backup** (gpg-agent generates, moves, backs up) — it supports import-only, not device-generated reveal | GnuPG advisory T6944 mechanism; spec §4.4 non-readability |
| 2 | The "shown once, never again" precedent is a **device-screen** ceremony, unimplementable on a screenless token | Ledger/Trezor: secret never crosses USB; no screen here |
| 3 | The applicable in-repo precedent is the **vendor master seed one-time window** (`backup-seed.md`) | same shape: device-held secret, deliberate host-crossing export, finalize forever |
| 4 | H5 is admissible **only as an opt-in GENERATE posture** with round-2 ceremony conditions and honest labeling ("this key has left the device once") | genuine deltas (post-ceremony compromise, TRNG provenance) vs capture trap; ecosystem taxonomy calls it Weak |
| 5 | Encrypted passphrase-wrapped backup: **rejected** | passphrase and blob on the same bus in the same ceremony; new firmware surface; §5 violation |
| 6 | IMPORT keys never need a backup ceremony | the user is pasting a key they already hold |

## Open decision for the owner

Ship the one-time-backup GENERATE mode, or keep GENERATE hardened-only?
- If the target population routinely creates identities in the extension and
  values a recoverable backup over maximum hardening, ship it as the
  **default** GENERATE posture with hardened as the opt-out (the ecosystem
  expectation the user cited), with the round-2 verified-capture ceremony as
  a hard gate.
- If hardening is the product statement, keep round 3's H4 verbatim: GENERATE
  warns and never reveals; users who want backups use IMPORT.

Both variants leave round 3's custody model (import-only, PIN session,
power-cycle expiry, EXPORT_KEY deleted) intact; the only question is whether
GENERATE has one response shape or two.
