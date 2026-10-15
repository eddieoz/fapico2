# Research: reusing the FIDO PIN to gate Nostr applet access

Date: 2026-10-15 · Method: structured multi-agent review (designer → skeptic →
constraint guardian → user advocate → arbiter). Every factual claim below was
verified against source with file:line citations at review time.

## The threat model, precisely

Four adversaries, and what stops each today:

| adversary | what they can do today | does a PIN help? |
|---|---|---|
| Remote attacker (web page) | gets pubkeys, signatures, ciphertexts only — never key material | **No** (no touch or PIN is needed for what they already get) |
| Possessor without a configured host | blocked at the button on every secret command | redundant — touch already stops them |
| Possessor **with** host + configured extension (the stated threat) | one press on `EXPORT_KEY` (`apps/nostr/src/lib.rs:1067-1100`) exfiltrates the raw BIP-340 scalar | **Yes — but only against a casual possessor.** A host-controlling adversary can keylog the PIN at entry. The PIN raises the bar from "press the button" to "press the button *and* steal the PIN", not to "impossible". |
| Flash-dump attacker | nothing — records are sealed under `derive_payload_key(otp_key_1, chipid, …)` (ADR 0005); OTP row is not flash | no (already stopped) |

Two structural facts dominate everything else:

1. **Touch is worthless against the stated threat.** A device possessor is
   physically present; every touch gate is satisfied by pressing. The PIN is
   the only factor that distinguishes owner from possessor — which is why the
   idea is worth researching at all.
2. **`EXPORT_KEY` is the single secret-returning command** on both transports
   (CCID 0x1A, vendor HID 0x48). IMPORT injects, GENERATE returns only the
   npub, SIGN/NIP-44 never reveal the scalar. The export path *is* the
   exfiltration path.

## Candidate designs and verdicts

### A. Reuse the FIDO CTAP2 clientPIN — REJECT

**Pros:** one PIN to remember; the CTAP2 token machinery (pinUvAuthToken,
retry latch, 3-strike power-cycle latch) already exists and is battle-tested.

**Cons (each independently disqualifying):**
- The PIN machinery lives entirely inside the two `FidoApp` twins
  (`pin.rs`, `device_core.rs`); reuse means a `fapico2-nostr → fapico2-fido`
  crate edge that ADR 0005's deny-graph explicitly refuses.
- **`authenticatorReset` incoherence:** CTAP2 reset clears `pin_hash` and
  rotates `device_random` while Nostr records survive by design. After any
  reset, a Nostr gate keyed on FIDO state either *silently opens* (a browser
  "reset key" flow defeats it) or leaves 8 non-revocable identities
  permanently locked. Both branches are wrong.
- **It silently changes FIDO's wire behaviour:** `pin_set` drives the §4
  accessors (`U2F_V2 = !pin_set`, `alwaysUv`, `makeCredUvNotRqd` —
  `apps/fido/src/ctap2.rs:664,696,757`). A Nostr-motivated PIN would flip
  FIDO's advertisements; that class of misadvertising broke real Yubico
  clients before (AGENTS.md §4).
- Setup requires a CTAP2 clientPIN ceremony (ykman/browser) on the FIDO
  interface — a foreign ritual for a Nostr/social-media user.
- Shared retry latch couples failures across applets invisibly.

### B. Nostr-local PIN + session expiry — CONDITIONAL (the least-bad PIN)

A verifier inside the Nostr applet following the OATH `PinRecord` pattern
(`apps/oath/src/oath_core.rs:811`: salted SHA-256 verifier + attempts budget,
~50 B), with a session-unlock flag on `NostrApp`.

**Pros:**
- Transport-blind by construction (one applet, two transports).
- Extension-native setup ("set a PIN" in the dialog the user already trusts).
- No FIDO coupling; §4 advertisements untouched.
- A stretched KDF is unnecessary: the verifier is sealed under the
  device-bound key and never leaves flash, so offline brute-force already
  requires the OTP row (excluded by the threat model).
- OATH, PIV, and OpenPGP all own independent PINs — this is the repo's
  established per-applet precedent, not a new architecture.

**Cons / conditions:**
- **Costs one of eight identity slots** (the keyregion has no stream store),
  or a re-tiling that cuts `FIDO_CAPACITY` again.
- **Session expiry is the hardest engineering problem**: no wall clock; CCID's
  honest anchor is `deselect`, the HID arm's is CID teardown, but the mutex
  makes state applet-global — an unlock on one interface is visible to the
  other. Whatever anchor is chosen must be stated on the wire and testable on
  hardware (the emulator exposes CCID only).
- A session is an armed grant that does **not** die with its request — a
  standing amendment to the presence-audit invariant that must be argued in
  writing, not slipped in as a flag.
- New applet state must be forwarded through `NostrViaMutex` — the known
  silent-no-op-on-hardware failure class (management RESET, audit F-A3).
- Torn-write semantics must be fail-closed, with recovery = announced
  `factory_wipe` (US-1650) = total identity loss.
- **Forgotten-PIN semantics are the make-or-break decision:** destructive
  reset manufactures permanent identity loss; non-destructive reset means a
  possessor can also reset, and the protection is one press. Either answer
  loses users.

**Condition of admissibility:** the PIN gates **key management only**
(EXPORT/IMPORT/GENERATE/DELETE) and never signing. If the proposal means
gating all key access, B inherits the permanent-loss failure mode.

### C. Platform-level shared PIN facility — REJECT for now

Architecturally cleanest in principle (one source of truth), but it refactors
the most wire-sensitive code in the firmware to serve one consumer (YAGNI per
AGENTS.md §5), requires a written argument for a new storage facility, and
buys nothing for Nostr that B's scoped record doesn't. Not wrong — unaffordable
today. Revisit only if a third applet needs a PIN.

### D. No PIN; narrow the export path — PASS on constraints, with a real hole

**Pros:** zero new mechanism (§5-aligned); strongest against the stated threat
because there is no extraction window at all — a session-with-expiry *is*
itself the window; all wire invariants preserved; the record's `flags(1)` byte
supports a per-record opt-in atomically; refusal is in-band `6985`/`6A80` that
the extension already handles.

**Cons:**
- Does not stop the **signing oracle**: impersonation from this board and
  extraction-elsewhere are the same harm for a publishing identity.
- **Removes the product's only backup/migration path** for a non-revocable
  identity on consumable flash — the export ceremony is currently doubling as
  the backup ritual (the extension renders nsec once with an "I understand"
  gate). "Board dies in a drawer, account gone" is the more likely loss.
- Breaking wire change to a client (the extension) that defines the dialect.

### E. PIN-wrapped record encryption — REJECT

**Pros:** cryptographically strongest claim — the device cannot even read its
own records without the PIN.

**Cons:** ADR 0005 rule 3 is a written wall: a PIN-derived key requires
solving whole-region re-keying on reset first — the transaction
`device_keystore.rs` declined to ship for FIDO. A power cut mid-rekey seals
all 8 identities under a key with no usable derivation. `authenticatorReset`
becomes an identity destroyer instead of a harmless scoped reset. The
keyregion's own invariant (`crypto.rs:42`: the index key is not a function of
any pin_secret) fights it. Forgotten PIN = mathematically destroyed
identities, unrecoverable, "indistinguishable from valid data".

## Constraint ranking

**D > B (conditional, export-scoped) > C > A > E**

## Decision Log

| # | decision | alternatives | objections | resolution |
|---|---|---|---|---|
| 1 | The threat model selects a PIN only for the casual-possessor variant; the session widens the attacker-on-host window | — | Skeptic O1: "the threat model does not select a PIN" | **Accepted** — the report states the protection ceiling honestly: PIN defeats press-only possessors, not host-controlling adversaries |
| 2 | Reuse of the FIDO PIN (A) is rejected | B, D | Skeptic/Constraint: reset incoherence, §4 advertisement coupling, forbidden crate edge | **Accepted** — both branches of the reset interaction are wrong; advertisement coupling already broke real clients |
| 3 | PIN-wrapped encryption (E) is rejected | — | ADR 0005 rule 3; power-cut brick; identity loss | **Accepted** — adjudicated by ADR already; not re-litigated without solving region re-keying |
| 4 | A Nostr-local PIN (B) is conditionally admissible, gated to key-management (minimally export) commands only, never signing | D alone | User Advocate: forgotten-PIN stakes; User Advocate: habituation/phishing from PIN-in-popup | **Accepted with conditions** — export-only scope bounds the forgotten-PIN cost to a convenience, not the identities; the phishing surface exists but the PIN is never the highest-stakes secret on the device (the scalar is, and stays behind the press) |
| 5 | Export-path hardening (D) must be discussed in the same decision as B | — | User Advocate: export is the only backup path today | **Accepted** — any B proposal must state where backup/migration lives |
| 6 | Any accepted design requires hardware verification of the HID arm and the proxy forwarding, not host tests | — | Skeptic O3: failure modes land where host tests are blind | **Accepted** — emulator is CCID-only (AGENTS.md §8 trap) |

**Disposition: REVISE.** The original proposal (reuse the FIDO PIN) is
rejected. The salvageable core is a **Nostr-local, export-scoped PIN with
session expiry**, designed together with an answer to the backup question —
or, if the threat is taken at its narrowest, simply hardening the export path
with no PIN at all.

## What a real design must still decide

1. Session anchor without a clock (command count? transport teardown? explicit
   lock command from the extension?) — and its wire-visible semantics.
2. Forgotten-PIN semantics, stated before implementation: what does the user
   lose, and what does the possessor gain.
3. Whether EXPORT_KEY remains (D vs B trade), and where backup lives.
4. Slot accounting for the PinRecord (1 of 8 identities, or re-tiling).
5. Hardware test plan for: proxy forwarding of new applet methods, the HID arm
   (emulator-blind), and FIDO advertisement invariance after any PIN work.
