# Changelog

Release notes and per-version scope live in
[`docs/release-notes-v1.0.0.md`](docs/release-notes-v1.0.0.md). This file is the
short index of what changed and when, newest first.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

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
  and [`docs/SECURITY-ASSESSMENT-ROUND2.md`](docs/SECURITY-ASSESSMENT-ROUND2.md).

[Unreleased]: https://github.com/eddieoz/fapico2/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/eddieoz/fapico2/releases/tag/v1.0.0
