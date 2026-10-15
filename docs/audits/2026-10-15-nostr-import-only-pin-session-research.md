# Research round 3: the OpenPGP pattern — import-only custody + PIN-locked session for Nostr

Date: 2026-10-15 · Follow-up to
[2026-10-15-nostr-pin-reuse-research.md](2026-10-15-nostr-pin-reuse-research.md)
and [2026-10-15-nostr-one-chance-export-research.md](2026-10-15-nostr-one-chance-export-research.md).
Method: designer draft → code/standard exploration (opcard internals; OpenPGP
card 3.4.1 and Yubico documentation) → owner decisions → arbitration. This
round supersedes round 2's H1 (one-chance export).

## The pattern, from the standard

**OpenPGP card 3.4.1** (§access rules for DOs) states the custody rule
verbatim: *"Private keys and passwords shall not be readable from the card
with any command or function."* The access table gives the cardholder private
key template (5F48) `READ = Never, WRITE = Verify PW3`. The only uses of a
stored key are the crypto commands (PSO:CDS sign, PSO:DEC, INTERNAL
AUTHENTICATE); GENERATE ASYMMETRIC KEY PAIR (§7.2.14) returns the **public**
key only.

**PIV is the same shape**: private keys are imported or generated on-device,
and no Yubico tool has an export action; PIV attestation exists precisely to
cryptographically *prove* that a key was generated on that device and never
left.

**opcard implements it** (`vendor/opcard`): the complete APDU dispatch table
(`command.rs:246-323`) contains no command that returns private key material
— verified negatively across every `serialize_key` call site; the only
serialization of a key handle is the public half of the GENERATE response
(`gen.rs:378,401`). Keys are wrapped with ChaCha8-Poly1305 under a user-KEK
derived from PW1 and unwrapped only at use (`state.rs:2080-2119`); in-memory
handles are cleared on deselect/reset (`state.rs:596`, `card.rs:273-292`).

## The PIN model (what "bounded to PIN" means concretely)

| OpenPGP | gates | our firmware |
|---|---|---|
| PW1 (user, min 6) | PSO:CDS (sign), PSO:DEC (decrypt), INTERNAL AUTH | would gate SIGN / NIP-44 |
| PW3 (admin, min 8) | PUT DATA (**import**), GENERATE, RESET RETRY COUNTER, TERMINATE DF | would gate IMPORT / DELETE / GENERATE |
| UIF per key | touch per op — **stacked on top of PIN**, not instead of it | already exists (`presence_grant`) |
| Retry counter = 3, RESET RETRY COUNTER via PW3 or optional Reset Code | recovery path | OATH counter analog |

Two implementation facts worth stealing:

- **PIN × touch stacking** (`pso.rs:42-59`): PIN establishes the session, the
  touch is per-operation on top, bound to the operation tag. Nostr already
  has the touch half (`nostr_wait_grant`).
- **Session discipline**: the verified-PIN state is volatile; the KEK is
  loaded for the session and cleared on deselect/reset. "Cached PIN" is the
  standard's own answer to session UX (PW-status `pw1_valid_multiple`, and
  Yubico's UIF `CACHED`/`CACHED_FIXED` modes in the spec-reserved bytes
  03/04).

## The core finding: the forgotten-PIN inversion

Round 1 rejected PIN-bound signing on one ground: **forgotten PIN = destroyed
non-revocable identities**. That objection was true for device-held-only
custody, and it dissolves under import-only custody:

- An imported key **necessarily has a host-held copy** — the user just typed
  the nsec into the client to import it. Yubico's own keytocard guide says
  exactly this: back up *before* the import, because the import is a move.
- So a forgotten PIN costs **reset + re-import**, not identity loss. The
  device copy is a hardened signing oracle, not the backup — the same
  taxonomy our own repo already documents for the vendor master seed
  (`docs/backup-seed.md`: passkeys non-exportable by design, seed
  exportable behind a deliberate window).
- Import-only and the PIN are **complementary, not alternatives**: import-only
  makes the PIN safe (nothing irrecoverable behind it); the PIN makes the
  device copy worthless to a thief (they can press the button, but they
  cannot sign, import, delete, or generate without it).

Round 1's constraint ranking ordered "narrowed-export > any PIN" — that
ordering was derived under device-only custody and does not survive this
inversion.

## The design (H4): import-only + single PIN + power-cycle session

Per owner decisions of this round:

1. **`EXPORT_KEY` deleted outright** (CCID `0x1A`, vendor HID `0x48` →
   in-band refusal like any unknown command). The v0.2.0 alpha population is
   near-zero; release notes carry the transition: **export your identities
   before flashing** if you want them movable. No reveal ceremony, no
   flags-bit grandfathering — round 2's capture trap is eliminated by
   construction: there is no export ceremony at all.
2. **`GENERATE_KEY` kept, with a no-backup warning.** An on-device generated
   scalar exists nowhere else; if the PIN is forgotten and the slot reset, or
   the board dies, that identity is unrecoverable. This is the accepted,
   spec-blessed hazard of on-card generation (§7.2.14); the warning is an
   extension-side ceremony, same weight as the old export "I understand"
   gate. Candidates: "for testing/throwaway identities".
3. **Single PIN for everything** (user decision; not the PW1/PW3 split).
   OATH `PinRecord` weight, not the opcard KEK machinery: `PinRecord {
   counter, salt[16], verifier[32] }` (`apps/oath/src/oath_core.rs:797-823`)
   — salted SHA-256 verifier, durable retry budget decrementing on failure,
   resetting on success. No KEK: the record seal key stays device-bound
   (round 1's PIN-wrapped-encryption option stays rejected); the PIN is an
   access gate, not key custody.
4. **Session = RAM-only unlock flag, power cycle is the expiry.** PIN verify
   sets `unlocked: bool` on `NostrApp`; it is never persisted; power cycle,
   `factory_wipe`, and applet reset clear it. This resolves round 1's
   hardest problem (expiry with no wall clock, two transports) by choosing
   the one anchor that needs no clock and no transport semantics: **reboot**.
   Both transports share the applet behind the mutex, so an unlock over CCID
   is visible to the HID arm — for one physical device that is the honest
   semantics, and it must be stated in the docs rather than discovered. The
   touch stays exactly as today for every gated operation: PIN → session →
   per-op press (the OpenPGP stacked model).
5. **Gate matrix**:

   | command | today | H4 |
   |---|---|---|
   | GET_INFO / LIST_KEYS / GET_PUBKEY | touch-free | touch-free (public reads) |
   | SIGN / NIP-44 | touch | **PIN session + touch** |
   | IMPORT / GENERATE / DELETE / SET_LABEL | touch | **PIN session + touch** |
   | VERIFY_PIN / SET/CHANGE_PIN | — | new: PIN commands themselves |
   | EXPORT_KEY | touch | **deleted** |

6. **New wire surface**: APDUs in the applet's INS range (0x1B VERIFY,
   0x1C SET/CHANGE) and vendor-HID bytes (0x4B/0x4C class), following the
   §8 dialect rules (unsupported byte answers `6D00` in band; read the
   extension's `ctaphid.js` before touching shapes). Retry-counter feedback
   in the OpenPGP `63CX` vocabulary (`63C1` = 1 try remaining, …) so the
   extension can render attempts remaining with a dialect clients already
   know. `GET_INFO` gains a capability/state bit (PIN set / session
   unlocked) — touch-free, so the extension can show lock state.

## Threat coverage after H4

| adversary | round 0 (today) | H4 |
|---|---|---|
| Remote attacker (web page) | public outputs only | unchanged (public outputs only) |
| Possessor, no host configured | blocked at the button | blocked at PIN **and** button |
| Possessor with host + extension | **one press extracts the scalar** | **extraction impossible; signing/import/delete/generate blocked by unknown PIN** |
| Attacker on host, owner nearby | touch consents, attacker interleaves | session already unlocked is the residual window (bounded by power cycle; the owner's own unlock is the only path) |
| Flash-dump attacker | nothing (device-bound seal) | unchanged |

Honest ceiling: a host-controlling adversary can keylog PIN entry (the popup
is browser chrome, same as any pinentry); a PIN-knowing possessor can still
sign, delete, and fill slots (squatting — no duplicate-npub check); and
generated-key identities are lost if the PIN is forgotten. None of these has
a cheaper fix inside this custody model.

## Why H4 supersedes round 2's H1 (one-chance export)

- **Ceremony**: H1 required a verified-capture ceremony (echo-back, unbacked
  nag, commit-before-reveal) to avoid manufacturing permanent losses at
  3–8%/creation. H4 has no ceremony at all — the user's existing nsec copy
  *is* the backup, made before the device is involved.
- **Coverage**: H1 closed extraction only. H4 closes extraction *and* the
  casual signing oracle (round 2's explicitly open flank).
- **Cost**: H1 needed an inverted legacy flags bit + capability bit +
  response-shape versioning. H4 deletes a command and adds two PIN verbs.
- **Recovery**: H1's lost-backup case was unrecoverable; H4's lost-backup
  case (generated keys only) is warned at creation.

## Decision Log

| # | decision | alternatives | rationale |
|---|---|---|---|
| 1 | Import-only custody: EXPORT_KEY deleted outright | one-chance (r2 H1); grandfathered flags bit | no export command = no extraction path; alpha population ~zero, release notes carry the transition |
| 2 | GENERATE_KEY kept with a no-backup warning | remove (pure import-only) | on-device generation matches spec §7.2.14 precedent; warning is extension-side |
| 3 | Single PIN (OATH PinRecord weight), not PW1/PW3 | PW1/PW3 split; per-sign PIN | simplest cognitive model; per-sign PIN kills burst-signing UX; admin/user split is deferrable |
| 4 | Session = RAM-only flag, power-cycle expiry, per-op touch unchanged | transport teardown anchors; command-count expiry; wall clock | only anchor with no clock and no cross-transport ambiguity; touch layer stays exactly as audited |
| 5 | PIN is an access gate, not key custody | PIN-wrapped KEK (round 1 option E) | re-keying on PIN change stays rejected (ADR 0005 rule 3); records remain device-bound |
| 6 | `63CX` retry vocabulary + GET_INFO state bit | bespoke status words | known dialect, renders in clients with existing conventions |

## Work items (for the follow-up implementation request)

1. **Firmware / applet**: PinRecord (home: spare keyregion space vs 1 of 8
   slots vs re-tiling — decide during design), VERIFY/SET/CHANGE handlers,
   `unlocked` flag on `NostrApp`, gate in `sign`/`nip44_*`/`import`/
   `generate`/`delete`/`set_label`, EXPORT removal, GET_INFO bits, `63CX`
   words, `factory_wipe` clears PinRecord + flag.
2. **Proxy discipline**: every new `App` trait method forwarded through
   `NostrViaMutex` (`firmware/src/nostr_shared.rs`) — the F-A3
   silent-no-op-on-hardware class. Host tests green ≠ hardware works.
3. **Extension** (`../fapico2-nostr-extension`): PIN dialog with attempts-
   remaining rendering, first-use set-PIN flow, GENERATED-key no-backup
   warning, GET_INFO lock-state indicator, power-cycle note ("unlocks until
   the board restarts"), release-note transition warning for v0.2.0 users.
4. **Tests**: host gate-matrix tests over both twins (`app.rs` AND
   `device_core.rs` — the twin trap), retry/lockout semantics, harness
   updates (`tests/harness/test_nostr_keymgmt.py` will fail until it does
   the PIN dance), CCID hardware probe, and **vendor-HID arm on hardware**
   (emulator is CCID-only, the standing §8 trap).
5. **Docs**: ADR (supersedes the round-2 recommendation; references OpenPGP
   card 3.4.1 §access rules and §7.2.14), AGENTS.md §8 amendment when the
   dialect lands, release notes for the alpha population.

## What a real design must still decide

1. **PinRecord storage home** — spare keyregion space (cleanest: no identity
   slot burned), 1 of 8 slots (simple, costs capacity), or re-tiling (cuts
   `FIDO_CAPACITY` again — round 1's constraint guardian's least-favourite).
2. **Retry exhaustion** — OATH's model is permanent until applet reset (which
   now costs only re-import, so permanence is finally affordable); or an
   admin-style unblock with a second secret (deferred PW3 complexity).
3. **LOCK verb at v1** — an explicit session lock is cheap (clears the RAM
   flag) and gives unattended-socket users a real answer; optional.
4. **Whether GET_INFO leaks unlock state** — a touch-free read that says
   "session unlocked" is convenient for UI and a minor privacy leak (an
   attacker with host access learns the board is open); decide with the
   extension's needs in view.
