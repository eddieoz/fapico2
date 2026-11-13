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
   stay open, and the touch layer is unchanged
   (amended — see **the touch-bypass amendment** at the end of this ADR; the
   thief sentence in decision 2 carries the same carve-out).
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
   delete, or generate without it — and, since US-1741, a thief who knows the
   PIN can arm the three signing arms only by spending the bypass's own
   consent press, which the accounting then bounds; see the amendment below).
   Round 1's constraint ranking
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

**Status:** recorded 2026-10-15 (US-1718); the matrix transcript lives in
[`docs/audits/2026-10-15-nostr-downgrade-matrix.md`](../audits/2026-10-15-nostr-downgrade-matrix.md)
and **is now complete** — the ceremony, extraction, destruction and endpoint
legs all ran on the sacrificial board that day. One amendment the session
earned: the destruction residual is **narrower than "downgrade restores
PIN-less destruction" reads** — the v0.1.2 image's ordinary destructive
command (factory `RESET`) and its compaction never touch the range, and its
ordinary writes cannot reach it at real occupancy; destruction by downgrade
requires the store deliberately filled to the top sector or an out-of-band
erase. The threat sentence below stands for exactly those two paths.

The threat: OTP burning is a firmware-level act, not an OTP-controller
guarantee — an old image carries the old KDF and the old, retired
`EXPORT_KEY`, so downgrade is an extraction attempt, and the ceremony's
answer is **data sealing**, not image signing: after the ceremony, every
record is sealed under a key derived from the burned custody page's
read-back contents, and the legacy constant-KDF opens nothing. The
ceremony itself is consent-gated (decision: the burn runs only on the
explicit `CEREMONY_START` verb, never as a side effect — a declined
migration leaves the board legacy-sealed and pending by the user's own
recorded choice).

#### The Decision Log of the downgrade review (R1–R7, binding on Phases 9–11)

The multi-agent review of the downgrade-and-custody design closed
**APPROVED-WITH-REVISIONS**; the dispositions, with the story that
discharged each:

| # | Revision | Discharged by |
|---|---|---|
| R1 | The OTP primitive must classify rows three-way — erased, valid, faulted — and a **faulted row is never classified as erased**, in either direction; a faulted read feeding the KDF fails closed before any record is touched. | US-1710 (`row_classifies_erased_valid_faulted`, `faulted_row_never_derives_a_key`) |
| R2 | **No page constant is committed and no burn-capable code ships** until the two-population OTP probe closes: occupancy and lock rows dumped on both a pico-fido2-migrated board and a factory board, the register model reconciled, the page constant recorded with the transcript. | US-1711 (probe transcript; custody page 59) |
| R3 | The one true brick vector — a burn word that verifies against neither intended nor erased — is **spent on nothing user-visible**: the ceremony aborts with no marker, and the torn burn resumes by refilling erased-class words only. | US-1712 (`verify_mismatch_aborts_with_no_marker`) |
| R4 | **Consent precedes every irreversible operation**: VERIFY and every other command never trigger a burn or a re-seat; the ceremony runs only on the explicit start verb, refused without a PIN, without legacy records, or with the marker standing. | US-1715 (host tests) |
| R5 | The legacy constant-KDF branch is **permanent behind one named seam** — no time-bombed expiry; the fleet-horizon question is a standing review item at the `-release` provisioning epic, not a timer. | `platform/src/keyregion/crypto.rs` `NostrKeySource::LegacyConstant` (single seam) |
| R6 | The review's **residuals are recorded once each** in the docs, by the downgrade matrix (below). | US-1718 |
| R7 | The completeness assertion — **after the marker, no record, including the PIN record, opens under the legacy KDF** — is host-tested and re-checked at every boot attach. | US-1713 (`no_record_opens_under_legacy_after_marker`), `nostr_custody_region` |

#### The residuals (R6), stated once and only here

- **Downgrade restores PIN-less destruction.** A v0.1.x image has neither the
  PIN gate nor custody: flashing one over a ceremony-completed board destroys
  the identity set by the *old* firmware's own ordinary write path (the range
  is overwritten/tombstoned, not read). The matrix's second leg demonstrates
  exactly this — destruction, not extraction — and that asymmetry is the
  whole protection story: the sealed set is worthless to the old image, so
  the old image cannot preserve it.
- **The custom-firmware adversary is covered only by O5's secure boot** at
  the `-release` boundary ([ADR 0002](0002-provisioning-policy.md)). The
  custody seal stops an old *shipped* image, not a crafted one: code that
  ignores the KDF entirely and reads the AEAD records as raw bytes stops
  nothing, because it stops being an authenticator. O5 alone does not stop
  downgrade; this data sealing alone does not stop a crafted image; the pair
  is the boundary where the residual closes.
- **FIDO, OATH, OpenPGP/PIV and PIN-less Nostr boards are outside this
  protection.** The custody domain is Nostr's keyregion only; PIN-less
  boards never migrate (nothing to protect — the gate does not exist), and
  no other applet's records are re-seated by the ceremony.

## Amendment (US-1741..1749/1855/1856, 2026-11-13): the touch bypass is a carve-out of this gate, accounted and bounded

US-1741..1749 (EPIC `NOSTR-TOUCH-BYPASS`) carved one deliberate exception into
decision 2's "the touch layer is unchanged", and US-1837..1856
(EPICs `NOSTR-BYPASS-ACCOUNTING` / `NOSTR-BYPASS-USABILITY`) bounded it. This
amendment is the decision's versioned home; AGENTS.md §8 carries the
implementer's trap list.

**What is carved out.** `SET_TOUCH_POLICY` (INS `0x1F`, vendor `0x4F`) lets an
open PIN session plus a physical consent press exempt exactly **`SIGN` and the
NIP-44 encrypt/decrypt pair** from the touch. The four key-management commands
(generate, import, label, delete) never skip the touch; the PIN gate itself is
untouched; the press consents to the identity, not the opcode.

**What bounds the carve-out — the accounting decision.**

- **`BYPASS_CAP = 255` exempt operations per session.** Not 256: the budget
  rides a 1-byte wire field, and 255 is the largest count it can name — the
  cap is derived from the wire, not chosen. Sizing came from the owner's
  live measurement that one user-visible action costs ~8 exempt operations
  (each signature fans out to every relay; the NIP-44 pair rides alongside),
  so one session ≈ 30 actions. Still fixed, not configurable: a configurable
  bypass is a bypass whose weakest configuration someone else gets to choose.
- **`BYPASS_SESSION_MS = 600_000` (10 minutes)** from the arm press, by a
  caller-supplied monotonic clock (`with_now_provider`; unwired it reads 0
  and can only mean "never expires" — the fido audit ring's convention).
  Past either bound the guards fall back to the touch — **the press is the
  fallback, never an error**.
- **Every exempt operation appends one 22-byte `AuditRecord`** to a 16-deep
  RAM ring, readable through `GET_AUDIT` (INS `0x20`, vendor `0x50`; v0.3
  body `budget(1) ‖ n(1) ‖ age_ms(4 BE) ‖ records` — the sampled age, not a
  raw device-monotonic stamp, because only an age anchors a client-side
  countdown). It is the first *read* the PIN-session gate covers: a
  sessionless host learns nothing, not even the budget. Advertised as caps
  bit 5 (`CAP_BYPASS_ACCOUNTING = 0x0020`); `APPLET_VERSION` bumped to 0.3
  for the body layout.
- **The RAM-only rule is inherited unchanged**: the bypass, budget, clock
  stamp and ring die with the session — LOCK, a failed verify, SET_PIN on an
  already-set board (the verb refuses `SW_PIN_ALREADY_SET` but closes the
  session, and the bypass dies with it; US-1856's clearing-matrix fix), the
  factory wipe, every boot, and the expiry; deselect preserves. GET_INFO's
  flags bit 3 derives from the guards' own predicate
  `touch_bypass && budget > 0` — a spent budget reads as not armed on the
  wire while the session is still open, so the cheap check every client
  reads cannot claim armed over a guard about to demand the press.

**Why this is admissible under this ADR's own logic.** Decision 3 made
PIN-bound signing admissible by removing what a forgotten PIN destroys; the
bypass does not reopen that objection — it is a session privilege anchored in
the same PIN session, it cannot be armed without the PIN *and* a physical
press, it cannot survive unplug, and the accounting bounds what a distracted
"armed and forgot" costs to at most 255 signing operations inside 10 minutes,
each of them recorded where the session's own host can read them. The threat
the accounting answers is the one decision 2 already named: not the thief
with the board, but the user who armed and walked away.
