# Changelog

Release notes and per-version scope live in
[`docs/release-notes-v1.0.0.md`](docs/release-notes-v1.0.0.md). This file is the
short index of what changed and when, newest first.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

### Added — the Nostr applet (branch `feat/nostr`)

- **Nostr identities on the device**: up to 8 BIP-340 identities with on-chip
  signing and NIP-44 v2 encryption, served over CCID (AID `F0 00 00 00 02`,
  plain APDUs) and over a third USB HID interface (usage page `0xFF00`,
  CTAPHID vendor commands `0x40`–`0x4A`). Keys are device-bound (ADR 0005),
  sealed per-record in the keyregion's new Nostr domain; every command that
  uses or changes the private set is touch-gated, with per-transport presence
  tags that survived a dedicated adversarial audit
  (`docs/nostr-presence-audit.md`, hardware-verified 2026-10-12).
- **The fapico2 Nostr browser extension** (Chrome 116+, WebHID) exposes the
  NIP-07 `window.nostr` API — sign, NIP-44 encrypt/decrypt, key management —
  with a per-site, per-action approval prompt and the physical touch as final
  consent. Verified end-to-end against hardware.
- **Capacity change**: FIDO2 resident passkeys move 856 → 848 (8 slots carved
  from the top of FIDO's range for Nostr, existing records untouched and
  guarded by the occupancy rule); measured to refusal at the carved geometry.
- **Reset semantics**: the management applet's `RESET` now wipes Nostr with
  everything else; CTAP2 `authenticatorReset` still spares it.
- **Docs**: [ADR 0005](docs/adr/0005-nostr-key-storage.md) (key storage, the
  second secp256k1 implementation, the scalar RAM-lifetime amendment), the
  presence-gate audit, the red-team assessment of the arc
  (`docs/archive/SECURITY-ASSESSMENT-NOSTR.md`), and the user/implementation
  pages in `book/` (`book/how-to/nostr.md`, `book/features/nostr.md`).

## [1.0.0] — 2026-10-01

First **published** release of the Rust firmware, and the cutover point from
the C `pico-fido2` tree. Full notes, including the per-app scope table and the
migration contract, are in
[`docs/release-notes-v1.0.0.md`](docs/release-notes-v1.0.0.md).

The date is the day the release was cut and published, not the day the scope
was first written down: this version sat unannounced from 2026-09-11 through
2026-09-30 while the OpenPGP applet, the Yubico OTP HID transport and the
FIDO2 credential-management work landed. The shipping image is recorded in
[`docs/size-report.md`](docs/size-report.md), which re-measures it and fails
CI on any disagreement — the number in the release notes is not the authority.

### Added

- **OpenPGP 3.4** over CCID — full command set served on device, accepted by
  `gpg` on hardware. Serves 27 algorithm records (9 each in C1/C2/C3): RSA
  2048/3072/4096, NIST P-256/384/521, Ed25519, X25519, secp256k1, Brainpool
  P-256r1, AES-256-CBC and ChaCha20-Poly1305.
- **OATH (YKOATH)** over CCID — full command set served on device.
- **FIDO2/U2F** over CTAP HID — full CTAP2.1 command set, including
  credProtect/credBlob/hmac-secret, credMgmt, largeBlobs and a vendor vault.
- **OTP** over CCID, served inside the management app crate.
- **Management** over CCID — device config, rescue surface, and the migration
  passphrase APDU.
- **Migration from the C firmware** — the first Rust boot detects the C data
  partition and re-seeds the Rust keystore from it. Most classes migrate
  silently; OpenPGP private keys and PIN-wrapped FIDO keydevs need the
  passphrase once. The vendor ChaChaPoly keydev is not migratable.
- **Signed secure boot** — `build-signed.sh` produces a signed image and
  refuses to sign with an unsupported key type.
- **Supply-chain tooling** — `cargo-deny`, an SBOM, and a release chain of
  custody with cosign signing and build-provenance attestation.

### Known limitations

- **PIV is not served** by the Rust firmware; it remains on the C firmware post
  cutover. PIV *data* still migrates silently.
- **Brainpool P-384r1 is not available.** Deferred; refused `6A80` at PUT DATA
  and absent from `GET DATA FA`. P-512r1 was never implemented.
- **RSA key generation is slow on the part** (RSA-2048 ~90 s) against a host
  PC/SC deadline of roughly 14.5 s, so on-card generation times out for some
  hosts. RSA import, signing and decipher are proven.
- **The USB vendor ID `0xFA20` is not USB-IF-registered.** See the README for
  the `libccid` allowlist step Linux and macOS need.
- **The firmware is not independently audited.** See [`SECURITY.md`](SECURITY.md)
  and [`docs/archive/SECURITY-ASSESSMENT-ROUND2.md`](docs/archive/SECURITY-ASSESSMENT-ROUND2.md).

[Unreleased]: https://github.com/eddieoz/fapico2/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/eddieoz/fapico2/releases/tag/v1.0.0
