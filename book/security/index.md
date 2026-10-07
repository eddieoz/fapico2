# Security

## Security model, in plain terms

- **Keys are generated on the device** from the RP2350's hardware TRNG and used only there — signing happens on the chip.
- **At rest, everything is sealed.** Records are AEAD-encrypted under a root key derived from `otp_key_1` (a one-way-fused OTP row) plus the chip's own identity. The firmware **refuses to boot** if that row is unavailable — there is no public-constant fallback. A flash dump alone does not open the store; the store key is not in it.
- **One bad record is not a bad day.** The per-record store commits a single credential per write, survives torn writes, and a FIDO reset cannot take OATH's credentials with it.
- **Signed secure boot is available** (`./build-signed.sh`): the bootrom refuses unsigned images. Opt-in, and off by default in the alpha.

## What this is not

1. **Not safe from someone who holds it.** Until the first `vX.Y.Z-release` tag, the SWD debug port is open on every published image — deliberate, so alpha boards stay recoverable ([ADR 0002](https://github.com/eddieoz/fapico2/blob/main/docs/adr/0002-provisioning-policy.md)). Anyone with brief physical access and a debug probe can extract every key the device holds; while that port is open, every other control is a delay, not a barrier. Until it closes, this is evaluation hardware: do not make it the only key to anything.

2. **Not independently audited.** The published [red-team assessment](https://github.com/eddieoz/fapico2/blob/main/docs/SECURITY-ASSESSMENT-ROUND2.md) is of an earlier build; some of it has been addressed, not all. No warranty.

3. **Not certified and not ruggedized.** No FIPS/Common Criteria evaluation, and no NFC — a Pico 2 has no radio.

4. **Not anonymously attributable.** Default builds carry a public development attestation key, so their attestation proves nothing about key provenance.

5. **Not finished on every front.** PIV is deferred; Brainpool P-384r1 is absent from OpenPGP; CTAP1/U2F register attestation fails client-side verification (CTAP2 is unaffected); a known RSA timing advisory (RUSTSEC-2023-0071) has no upstream fix.

## Red-team assessment

A red-team assessment of an earlier build is published in full in the repository: [`docs/SECURITY-ASSESSMENT-ROUND2.md`](https://github.com/eddieoz/fapico2/blob/main/docs/SECURITY-ASSESSMENT-ROUND2.md). The findings are more useful than the reassurance would be.

## Supply chain

Dependency vetting, SBOM, and accepted RustSec advisories are CI-gated. See [`docs/supply-chain.md`](https://github.com/eddieoz/fapico2/blob/main/docs/supply-chain.md).

## Reporting vulnerabilities

Report vulnerabilities privately — see [`SECURITY.md`](https://github.com/eddieoz/fapico2/blob/main/SECURITY.md). Do not open public issues for security reports.
