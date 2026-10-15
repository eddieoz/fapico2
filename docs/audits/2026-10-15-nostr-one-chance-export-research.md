# Research round 2: one-chance export at creation (API-token model)

Date: 2026-10-15 · Follow-up to
[2026-10-15-nostr-pin-reuse-research.md](2026-10-15-nostr-pin-reuse-research.md).
Same method: designer draft → skeptic → constraint guardian → user advocate →
arbiter. Facts re-verified in source (`apps/nostr/src/lib.rs`,
`platform/src/keyregion/nostr_store.rs`, the extension under
`../fapico2-nostr-extension`).

## The two options, formalized

**H1 — one-chance export at creation.** `GENERATE_KEY`'s response gains the
scalar exactly once (or a paired reveal opcode); storage stays atomic with the
creation; `EXPORT_KEY` refuses for keys created after the change. Legacy
pre-change keys are grandfathered exportable via the record's reserved `flags`
byte. `IMPORT_KEY` is retained as the recovery path — the property "if the
person has the backup, they can always recover" is exactly what makes
one-chance survivable.

**H2 — device-only generator, opt-in adoption.** The device TRNG generates and
reveals the scalar once but does **not** store; the user then explicitly opts
to keep it on the device (re-import/commit) or takes the nsec to a software
Nostr client. Custody is chosen explicitly; the scalar crosses the host in
both branches of the common path.

## What each option actually closes — and what neither closes

- **Closed (the real gain):** recurring extraction exposure. A compromise of
  the extension or the host **after creation** can no longer extract
  identities created before it. Today every key is one press away from
  exfiltration forever; under H1 the window is a single ceremony.
- **NOT closed — the signing oracle.** A possessor (or compromised host with
  the owner nearby) still signs as you with zero exports. Impersonation via
  `SIGN` is the harm users actually suffer, and both options leave it
  untouched. No export policy fixes this; only a use-gating mechanism (the
  round-1 PIN discussion, rated expensive) addresses it.
- **NOT closed — deletion and squatting.** A possessor can still `DELETE_KEY`
  your identities (destructive, not exfiltrative) and fill slots with garbage
  via `IMPORT_KEY` (no duplicate-npub check). Recovery from squatting is
  DELETE-only; a real identity lost to DELETE is gone regardless of export
  policy.
- **NOT closed — compromise at creation.** The reveal crosses the host bus at
  exactly the moment a new setup is most likely to be compromised. A
  malicious extension at creation captures the scalar without ever needing
  `EXPORT_KEY`. The honest claim is **"the key leaves less often"**, not
  "never leaves the device."

## Constraint Guardian: H1 conditional pass, H2 weaker

- **H1 — CONDITIONAL PASS.** Binding constraint: the legacy fork. The flags
  byte is reserved-zero, so the bit must be defined **inverted** (bit0 =
  export-restricted; reserved-zero stays legacy-exportable) or every existing
  key loses its only export path. The bit is write-once at creation, never
  cleared, pinned by test. No new write path: the reveal rides the existing
  atomic sealed `write_identity`, response appended after.
- **H2 — CONDITIONAL PASS, weaker.** The durable-pending branch FAILS: pending
  state in RAM dies with the ~30s MV3 worker; pending state in flash is a new
  torn-write surface that stops no attack. Only the "reveal + re-IMPORT"
  branch passes — and it reuses existing opcodes. Its headline property
  ("the device TRNG is the only origin") is **unenforceable**: adoption *is*
  `IMPORT_KEY`, and the device cannot distinguish a re-imported TRNG draw
  from a host-made key once the scalar has left.
- **Status quo + hardened export UX** passes only as a stopgap.

**Wire skew (four combinations of old/new firmware and extension):** H1's
response grows `npub(32)` → `npub(32) ‖ scalar(32)`; an old extension
misparses the frame. Mitigation must be in-band and touch-free: a capability
bit in `GET_INFO` (`INFO_FLAGS` is reserved-zero today), **extension ships
first**, firmware second — firmware cannot be pushed to users (BOOTSEL only).
H2 skews cleaner (unknown opcode = the in-band 6D00-in-CBOR refusal both
clients parse) but a semantics-changed GENERATE silently fails to store, so a
new opcode, not a changed one, is mandatory.

**Surface accounting:** H1 = one response shape, one gate, one flags bit, no
new `App` trait method (no proxy-forward hazard), transport-agnostic so it is
host-testable. H2 = new opcode, extension dialect addition, presence semantics
for the new command, adoption UX state machine.

## User Advocate: the one-chance trap decides it

- **H1's dominant failure mode:** silent unbacked identity. Popup dismissed
  before saving, MV3 worker death mid-ceremony, "I understand" clicked
  through without saving, npub saved instead of nsec — all land in the same
  terminal state: slot occupied, scalar gone forever, no overwrite. Estimated
  **3–8 lost identities per 100 creations** without capture verification, all
  discovered when the $15 dongle dies. Today the same mistake is free (re-export
  later); H1 arms it. H2's pre-commit crash is categorically better —
  nothing stored, retryable.
- **Ceremony invariants a one-chance promise requires (extension-side):**
  echo-back proof-of-copy (re-enter a fragment of the nsec before Done
  enables) instead of "I understand"; commit before reveal; a persistent
  **unbacked-key flag** in extension storage (no key material, just
  "identity X has no verified backup") that nags until resolved; clipboard
  scrub delayed or user-initiated; one screen, above the fold; honest copy —
  never "never leaves the device."
- **H2's custody choice** helps only if device-custody is the
  consequence-framed default and save-verification precedes it. The
  software-client branch as a coequal option is dishonest: plaintext nsec in
  a browser profile is the weakest custody on offer for a years-long
  publishing identity; demote it to a clearly-labeled throwaway/testing
  option.
- **Split-brain legacy UX:** a user who just exported key 3 will assume key 5
  behaves the same and read the refusal as a malfunction. The refusal message
  must name the reason in band.

## Decision Log

| # | decision | alternatives | objections | resolution |
|---|---|---|---|---|
| 1 | One-chance export (H1) is the right extraction hardening, shipped behind a verified-capture ceremony | H2, status quo | Skeptic: capture trap converts UI fumbles into permanent loss; claim "never leaves" is false | **Accepted with conditions** — the ceremony invariants above are a hard gate; the marketing claim is "you can export exactly once, now" |
| 2 | Legacy keys are grandfathered via an **inverted** export-restricted bit, write-once, never cleared | Non-inverted bit; forced migration | Constraint: reserved-zero forces the direction or existing keys are stranded | **Accepted** |
| 3 | H2 rejected as the primary model | H1 | Skeptic: TRNG-exclusivity unenforceable; double host transit on the common path; needs a new opcode + state machine; User Advocate: custody click-through at maximum ignorance | **Rejected** — its genuinely better crash property (retryable pre-commit loss) is noted but does not outweigh the surface and the exposure on the default path |
| 4 | Adoption of H1 largely dissolves the round-1 PIN rationale for the extraction threat | Scoped PIN for legacy EXPORT/IMPORT | Constraint (r1) had ranked narrowed-export above any PIN | **Accepted** — the PIN's only residual role would be gating the grandfathered legacy export; judged not worth its forgotten-PIN cost. Revisit only if use-gating (sign) is ever wanted |
| 5 | Extension ships its capability check before any firmware flash | Firmware-first | Skeptic: old ext + new fw misparses the grown frame | **Accepted** — sequencing constraint of the option |
| 6 | Signing-oracle and deletion threats are explicitly out of scope of this hardening | — | Skeptic O1 | **Accepted** — recorded so the property sold is extraction, not impersonation |

**Disposition: REVISE-and-PROCEED.** H1 is accepted in principle with three
hard conditions (verified-capture ceremony, inverted legacy bit, extension-first
sequencing). H2 is rejected. The signing oracle remains the open flank of the
possessor threat and is unchanged by any export policy.

## Engineering notes for a real design

1. `GENERATE_KEY` response: append `scalar(32)` after `npub(32)`; the length
   change is the version signal — but the `GET_INFO` capability bit is the
   authoritative detection for the extension.
2. Flags bit: define bit0 = `EXPORT_RESTRICTED`, set at creation for
   post-change GENERATE and IMPORT records (imported keys are one-way doors —
   document that recovering an imported key means its original backup);
   reserved-zero records keep today's exportable behaviour.
3. `EXPORT_KEY` on a restricted record answers an in-band status word
   (`6A86`-class) that the extension maps to a sentence naming the policy.
4. Torn reveal (crash between store and capture): recovery is DELETE-only;
   the unbacked-flag nag in the extension is the safety net. Document it.
5. Tests: the emulator is CCID-only, so the vendor-HID arm of the new
   response needs a host test through `process_vendor_through` plus hardware
   verification (the standing §8 trap).
