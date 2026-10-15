# ADR 0006: Nostr PIN custody — import-only custody, the PIN session gate, and the forgotten-PIN inversion

**Status:** Accepted (2026-10-15)
**Supersedes:** nothing (amends ADR 0005's "no PIN-derived input anywhere in the
derivation" — the amendment is a clarification, not a reversal: the *keys* stay
device-bound; the PIN is an access gate in front of them)
**Context docs:** the research rounds' Decision Logs —
[`docs/audits/2026-10-15-nostr-pin-reuse-research.md`](../audits/2026-10-15-nostr-pin-reuse-research.md)
(whose candidate D, "narrow the export path", was superseded),
[`docs/audits/2026-10-15-nostr-one-chance-export-research.md`](../audits/2026-10-15-nostr-one-chance-export-research.md),
[`docs/audits/2026-10-15-nostr-import-only-pin-session-research.md`](../audits/2026-10-15-nostr-import-only-pin-session-research.md)
(the settled H4 design — the authority for this ADR),
[`docs/audits/2026-10-15-nostr-one-time-backup-precedent-research.md`](../audits/2026-10-15-nostr-one-time-backup-precedent-research.md)
(H5 device-reveal **not** adopted — owner decision, 2026-10-15); the EPIC
[`docs/tasks/EPIC-nostr-pin-custody.md`](../tasks/EPIC-nostr-pin-custody.md).

## Decision

Four decisions, recorded together because the third is only admissible on the
first:

1. **Import-only custody: `EXPORT_KEY` is deleted outright** — the CCID INS
   `0x1A` and the vendor byte `0x48` both retire to an in-band `6D00`
   (US-1699). *No export command is no extraction path.* The in-tree precedent
   is the applet we already ship: `vendor/opcard` implements the OpenPGP card
   3.4 command set, whose APDU table contains **no export-of-private-key
   command at all**, and the standard it serves states the custody rule
   verbatim — *"Private keys and passwords shall not be readable from the card
   with any command or function"* (OpenPGP card 3.4.1, §access rules). PIV and
   HSM are the same shape. The one-chance export (research round 2's H1,
   accepted in principle there) is superseded by this round: its capture trap
   — the reveal window is exactly when a compromised host gets its chance —
   and the User Advocate's one-chance analysis decided it.
2. **The PIN is an access gate, not key custody.** The PinRecord is an
   OATH-`PinRecord`-weight record sealed device-bound in the Nostr keyregion
   (keyed under `derive_payload_key(otp_key_1, chipid, NOSTR_PAYLOAD_SECRET)`
   — no PIN-derived input, exactly as ADR 0005 rule 1 recorded; changing the
   PIN re-keys nothing). A successful verify sets one RAM-only session flag
   behind `NostrViaMutex` — applet-global, so a CCID unlock covers the vendor
   HID arm, and a power cycle clears it. Every identity-touching command
   (`SIGN`, `NIP44 ENC/DEC`, `IMPORT`, `GENERATE`, `DELETE`, `SET_LABEL`)
   refuses `6982` while `pin_set && !pin_unlocked`; the three touch-free reads
   stay open, and the touch layer is unchanged.
3. **The forgotten-PIN inversion: import-only custody is what makes PIN-bound
   signing admissible.** Research round 1 rejected PIN-bound signing on one
   ground — forgotten PIN = destroyed non-revocable identities. That objection
   was true under device-only custody and dissolves under import-only: an
   imported key *necessarily* has a host-held copy (the user just typed the
   nsec in to import it), so a forgotten PIN costs **reset + re-import**, not
   identity loss. The device copy is a hardened signing oracle, not the backup
   — the taxonomy `docs/backup-seed.md` already documents for the vendor master
   seed. Import-only and the PIN are complementary: import-only makes the PIN
   safe (nothing irrecoverable behind it); the PIN makes the device copy
   worthless to a thief (they may press the button; they cannot sign, import,
   delete, or generate without it). Round 1's constraint ranking
   ("narrowed-export > any PIN") was derived under device-only custody and does
   not survive the inversion.
4. **The torn-record policy fails closed.** A pin slot that reads back
   undecodable is not treated as "no PIN": the applet answers `SW_PIN_LOCKED`
   to every verify and `SW_STORE_FAULT` to set/change, the state bit reads
   `Undecodable`, and only `factory_wipe` clears it. Refusing to guess is the
   whole point — an honest answer does not exist, so the only safe one is the
   refusal (`apps/nostr/tests/pin.rs::torn_pin_record_fails_closed`).

### The four rejected alternatives

- **FIDO-PIN reuse (research round 1, candidate A) — REJECT.** The CTAP2
  clientPIN is bound to pinUvAuth protocols and a per-protocol retry counter
  the FIDO applet owns; reusing it couples two applets' lockout policies and
  makes the Nostr gate reachable through CTAP2 client machinery fapico2 does
  not implement. The Nostr PIN is applet-local (candidate B, "the least-bad
  PIN"), with no expiry beyond the power cycle.
- **PIN-wrapped record encryption (round 1, candidate E) — REJECT**, reaffirming
  ADR 0005 rule 3: re-keying every record on PIN change, and a KDF whose salt
  handling must be re-derived per ceremony, buys nothing the session gate does
  not. The records stay device-bound; the PIN gates the *use*, not the bytes.
- **One-chance export at creation (round 2's H1) — superseded**, its capture
  trap and the alpha population (~zero users) deciding against it; the
  transition warning ("EXPORT_KEY is gone — export before flashing") lives in
  the release notes instead of a grandfathered flags bit.
- **One-time backup of a device-generated key (round 4's H5) — declined by the
  owner (2026-10-15).** The Kleopatra card ceremony's own sequence (backup
  *before* the import, never after) is the precedent that applies; a
  device-reveal window would reintroduce exactly the extraction path decision 1
  deletes. GENERATE keeps its no-backup warning instead.

### The residual ceiling, stated honestly

- **A host-controlling adversary keylogs PIN entry.** The PIN is typed on the
  host; custody against a compromised host ends at the keystroke. The device
  defends the keys against *physical* possession, not against the machine the
  PIN was typed on.
- **Generated keys have no backup.** `GENERATE_KEY` produces a key that exists
  only on the board; a forgotten PIN destroys it. The extension warns in the
  generate flow; the warning is all there is.
- **A PIN-knowing possessor can still delete.** The gate is uniform: anyone
  with the PIN can sign — and delete. Delete has no separate admin credential
  (the OpenPGP PW1/PW3 split was considered and deferred, Decision Log #3).

### The downgrade section

Deferred by design: it records the custody-migration ceremony's Decision Log
(the downgrade review's R1–R7 dispositions) when the ceremony lands
(US-1716..1718). The threat is named here so the deferral is visible: an old
firmware image re-enables EXPORT; the migration marker and its refusal rules
are Phase 10–11 work gated on US-1711.
