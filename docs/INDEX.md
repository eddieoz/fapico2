# Documentation index

Manually maintained — when you add, move or archive a document, add its line
here. Historical investigations live in [`archive/`](archive/README.md) with
one-line verdicts; working plans under `tasks/` and `superpowers/` are
deliberately **not in git**.

## Start here (first-time setup and the things that look like dead hardware)

- [bootsel.md](bootsel.md) — flashing over BOOTSEL, recovery paths, why re-enumeration can take a minute.
- [boot-freeze.md](boot-freeze.md) — a frozen board says why: the boot ladder, the fatal-signature decoder (long gap = 0, short gap = 1), and why a probe makes it worse.
- [audits/2026-10-31-boot-dark-trng-refused.md](audits/2026-10-31-boot-dark-trng-refused.md) — the intermittent dark boot decoded from a video: `TrngRefused` from `ensure_boot_entropy`, why power-cycling re-rolls the dice, and the retry + LED draw-notice fix.
- [pico-fido2-to-fapico2-migration.md](pico-fido2-to-fapico2-migration.md) — the durable OTP state a board carries after pico-fido2 1.0 (page-58 lock, picotool `permission failure`), the post-flash park and its root cause (the runtime `sw_lock` write, removed 2026-10-11), and the boot OTP retry.
- [identity.md](identity.md) — USB identity (AAGUID, VID:PID), the **PC/SC allowlist step Linux/macOS need before OpenPGP/OATH work**, and the runtime VID/PID silent-lockout hazard.
- [capacity.md](capacity.md) — hardware-verified ceilings: 856 FIDO2 resident credentials (measured to refusal), 68 OATH slots (reservation), and which constants are *not* capacities.
- [client-compatibility.md](client-compatibility.md) — client-side quirks no firmware change can fix.

## Using and trusting the device

- [backup-seed.md](backup-seed.md) — the vendor master seed as a 24-word phrase: export / restore / finalize with `scripts/backup_fido.py`, and the honest scope (passkeys are NOT in it).
- [hardware-matrix.md](hardware-matrix.md) — hardware acceptance matrix: USB IDs, algorithms, per-applet results.
- [release-notes-v1.0.0.md](release-notes-v1.0.0.md) — the published release: image hash, verification procedure.
- [secureboot.md](secureboot.md) — RP2350 signed secure boot procedure (opt-in, not yet burned on any board).
- [debug-access-risk.md](debug-access-risk.md) — accepted-risk record: the open debug port until the first `-release` tag.
- [supply-chain.md](supply-chain.md) — dependency vetting, SBOM, accepted RustSec advisories (CI-gated).
- [SECURITY.md](../SECURITY.md) — vulnerability reporting (not a docs file, but the entry point).

## Security and design records

- [secure-storage-comparison.md](secure-storage-comparison.md) — adversarial comparison of key-at-rest against pico-fido/pico-openpgp/pico-hsm/RS-Key.
- [secure-storage-story-matrix.md](secure-storage-story-matrix.md) — tracked evidence index for the secure-storage epic.
- [adr/](adr/README.md) — architecture decision records (PIV/RSA, provisioning policy, TrustZone).
- [nostr-presence-audit.md](nostr-presence-audit.md) — the Nostr presence-gate adversarial audit
  (2026-10-12): the CANCEL-repark orphaned-grant replay (Critical, PoC-confirmed), the folded-FIDO-tag
  mask check, the proxy-swallowed mgmt-RESET wipe, the CCID arm that can never grant — arbitration,
  decision log D1–D10, the red-then-green fix series, and the hardware acceptance
  ([evidence](evidence/nostr-presence-audit/hardware.md): D7/D6 verified live, two new
  prompt-visibility findings F-A15 fixed / F-A16 recorded).
- [adr/0005-nostr-key-storage.md](adr/0005-nostr-key-storage.md) — the Nostr records' device-bound
  key derivation, the FIDO-range carve and occupancy guard, the deliberate second secp256k1
  implementation, and the scalar RAM-lifetime amendment.
- [adr/0008-seed-rooted-fido-derivation.md](adr/0008-seed-rooted-fido-derivation.md) — the vendor
  master seed governs the FIDO derivation root (`froot`) so restoring the phrase restores the
  resident passkey wallet; the seedless byte-compat freeze, serving-time derivation with the
  fail-closed orphan gate, the reset-first LOAD contract, and what stays device-bound.

The three round-based red-team security assessments live in
[`archive/`](archive/README.md): [round 2](archive/SECURITY-ASSESSMENT-ROUND2.md)
(the deep record), [round 3](archive/SECURITY-ASSESSMENT-ROUND3.md) (the
same-day report) and the [round-3 remediation
record](archive/SECURITY-ASSESSMENT-ROUND3-REMEDIATION.md) (what is fixed, with
the hardware evidence). The Nostr arc's own red-team pass is
[archive/SECURITY-ASSESSMENT-NOSTR.md](archive/SECURITY-ASSESSMENT-NOSTR.md)
(2026-10-10, firmware + extension).

## Living budgets and gates (CI reads these — do not move)

- [size-report.md](size-report.md) — flash/RAM budget ledger, CI-gated.
- [erase-budget.md](erase-budget.md) — flash erase budget, CI-gated.
- [known-gate-divergences.md](known-gate-divergences.md) — register of CI gate divergences and the standing waiver.
- [supply-chain.md](supply-chain.md) — also CI-gated (listed above).

## Protocol references

- [ctap2-hid-framing.md](ctap2-hid-framing.md) — CTAPHID wire-format reference for driving CTAP2 by hand.
- [webauthn-discovery-baseline.md](webauthn-discovery-baseline.md) / [webauthn-discovery-ab.md](webauthn-discovery-ab.md) — repeatable getInfo probes and the US-1529 A/B transcript.
- [token2-hardware-validation.md](token2-hardware-validation.md) — post-flash acceptance against a real WebAuthn flow.
- [fido2-canonical-cbor-fix.md](fido2-canonical-cbor-fix.md) — the Chrome canonical-CBOR failure and its fix.
- [provenance.md](provenance.md) — AGPL provenance audit against the C reference trees.

## Migration

- [migration-feasibility.md](migration-feasibility.md) — US-413: C-firmware data formats and what migrates (CI-gated; do not move).
- [migration-epic.md](migration-epic.md) — the epic stub pointing at the workspace-level plan (CI-gated; do not move).

## Archive (historical investigations, verdicts summarized)

[archive/README.md](archive/README.md) — the WebAuthn browser-discovery evidence set, the OpenPGP client investigations, and the round-3 remediation record.
