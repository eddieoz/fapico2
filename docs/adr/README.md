# Architecture Decision Records

Governing scope decisions for the `fapico2` Rust rewrite. Each ADR records a
load-bearing architectural choice and its consequences; see the linked story in
the `RUST-MIGRATION` EPIC (`docs/tasks/EPIC-rust-migration-fapico2.md`).

| ID | Title | Status | Driven by |
|---|---|---|---|
| [0001](0001-piv-rsa.md) | RSA in Rust for PIV / OpenPGP: ECC-only baseline, RSA deferred | Decided | US-342 (blocks Phase 4) |
| [0002](0002-provisioning-policy.md) | Provisioning policy — profiles, deferred burns, and tag provenance | Accepted | US-1567, US-1568 (`FIDO-SECURE-STORE` Phase I) |
| [0003](0003-trustzone.md) | TrustZone — deferred | Accepted | US-1576 (`FIDO-SECURE-STORE` Phase ADR) |

Format: title, status, date, owner, context → decision → consequences. New ADRs
should append a row here and pick the next free number.
