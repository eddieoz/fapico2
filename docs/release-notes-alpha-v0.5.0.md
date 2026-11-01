# fapico2-release-alpha-v0.5.0 — Release Notes

**Date:** 2026-11-01 · **Target:** Raspberry Pi Pico 2 (RP2350), USB-connected
**Theme:** the button learns to stand down (PR
[#27](https://github.com/eddieoz/fapico2/pull/27), EPIC
`NOSTR-TOUCH-BYPASS` — with the client side in
[fapico2-nostr-extension #3](https://github.com/eddieoz/fapico2-nostr-extension/pull/3)):
Nostr signing chains stop costing one press per signature, behind a consent
ceremony that borrows every load-bearing property the PIN session already
proved.

**This is an alpha.** Alpha/beta images keep the debug port available and burn
nothing irreversible into OTP ([ADR 0002](adr/0002-provisioning-policy.md)).

## The feature: a consented, session-bound touch bypass

Nostr platforms send chains of events; a touch per signature made a 10-event
chain 10 presses. `SET_TOUCH_POLICY` (INS `0x1F`, vendor byte `0x4F`) is the
touch analogue of the PIN session:

- **Arming is the consented direction**: an open PIN session **and** a
  physical press — the extension can only ask; the firmware enforces both.
  Every refusal eats an armed grant, so a refusal can never leak a signature.
- **The safe direction stays friction-free**: re-enabling the touch answers
  `9000` in every board state, so the button can always be had back.
- **The exemption is signing-only**: exactly SIGN, NIP-44 ENC and NIP-44 DEC.
  GENERATE, IMPORT, SET_LABEL and DELETE press unconditionally, on every
  board, in every state — byte-identical to before.
- **RAM-only, dies with its session**: LOCK, a failed verify, the factory
  wipe and every boot clear it; deselect/re-select preserves it. A bypass
  that survives unplug is a bypass the user forgot they owned.
- **The advertisement cannot lie**: GET_INFO advertises the verb
  unconditionally (caps `0x0010`) and the live state (flags `0x08`) from the
  same field the gate reads.

Verified on hardware: the [transcript](docs/audits/2026-11-01-nostr-touch-bypass-proof.md)
closes the matrix on both transports — the consent press, **ten signatures in
0.60 s with zero touch prompts**, LOCK clearing, the friction-free enable,
and the power cycle extinguishing the flag while the identity survives it.
The extension's checkbox and its ceremony record ride the sibling repo.

## Also in this release

- **The boot-chain gate self-heals** (US-956/US-964): the task-arena stamp is
  byte-exact over the source closure and cannot tell a comment from code, so
  documentation edits kept blocking the device job on a manual nightly run.
  The gate now runs the sanctioned re-measurement itself — re-stamps and
  passes when the demand did not move, hard-fails naming old → new when a
  future genuinely grew.
- **The book tells users both halves**: a [Nostr troubleshooting
  chapter](https://github.com/eddieoz/fapico2/tree/main/book/troubleshooting)
  (every refusal as symptom → status word → remedy, the bypass's error rows
  and its two misuse patterns) and the how-to walkthrough of the checkbox,
  the consent press, and what a chain costs. The stale "no config bit"
  claims now name the one deliberate exception.

## Review record

Two independent full reviews (a 12-point invariant review plus a 10-agent
code review across both repos) found no functional defect in the device
implementation; the follow-ups they did find are fixed in the series — a
failed verify now clears an armed bypass beside the session it closed, and
the extension's read-back ping cannot leave the checkbox rendering a stale
policy. Residuals are recorded in the audit, not re-argued: the disable
leg's consent press is tag-indistinguishable from a SIGN press for identity
1 (the epic mandates no new tag domain; grants are request-bound, so no
cross-consumption is possible).

**Full Changelog**: https://github.com/eddieoz/fapico2/compare/fapico2-release-alpha-v0.4.0...fapico2-release-alpha-v0.5.0
