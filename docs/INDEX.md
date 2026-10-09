# Documentation index

Manually maintained — when you add, move or archive a document, add its line
here. Historical investigations live in [`archive/`](archive/README.md) with
one-line verdicts; working plans under `tasks/` and `superpowers/` are
deliberately **not in git**.

## Start here (first-time setup and the things that look like dead hardware)

- [bootsel.md](bootsel.md) — flashing over BOOTSEL, recovery paths, why re-enumeration can take a minute.
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

- [SECURITY-ASSESSMENT-ROUND2.md](SECURITY-ASSESSMENT-ROUND2.md) — published red-team assessment of an earlier build, in full.
- [secure-storage-comparison.md](secure-storage-comparison.md) — adversarial comparison of key-at-rest against pico-fido/pico-openpgp/pico-hsm/RS-Key.
- [secure-storage-story-matrix.md](secure-storage-story-matrix.md) — tracked evidence index for the secure-storage epic.
- [adr/](adr/README.md) — architecture decision records (PIV/RSA, provisioning policy, TrustZone).

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
