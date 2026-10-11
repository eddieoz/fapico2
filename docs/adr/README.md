# Architecture Decision Records

Governing scope decisions for the `fapico2` Rust rewrite. Each ADR records a
load-bearing architectural choice and its consequences; see the linked story in
the `RUST-MIGRATION` EPIC (`docs/tasks/EPIC-rust-migration-fapico2.md`).

| ID | Title | Status | Driven by |
|---|---|---|---|
| [0001](0001-piv-rsa.md) | RSA in Rust for PIV / OpenPGP: ECC-only baseline, RSA deferred | Decided | US-342 (blocks Phase 4) |
| [0002](0002-provisioning-policy.md) | Provisioning policy — profiles, deferred burns, and tag provenance | Accepted | US-1567, US-1568 (`FIDO-SECURE-STORE` Phase I) |
| [0003](0003-trustzone.md) | TrustZone — deferred | Accepted | US-1576 (`FIDO-SECURE-STORE` Phase ADR) |
| [0004](0004-fatal-boot-recovery-policy.md) | The recovery policy for a fatal boot: refuse, and say so — reason signatures, no watchdog, deadline-bounded OTP reads | Decided (+ amendments 2026-10-11) | US-1309/US-1310; boot-freeze follow-up |

Format: title, status, date, owner, context → decision → consequences. New ADRs
should append a row here and pick the next free number.
