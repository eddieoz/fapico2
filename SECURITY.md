# Security Policy

## Status: not audited

**This firmware has not been independently audited, and no warranty is
offered.** It is a hardware credential — a device that holds private keys and
will be used to authenticate you. Treat it as development/evaluation hardware
unless you have independently verified it. Do not make it the only key to
anything you cannot afford to lose.

## Known weaknesses

[`docs/SECURITY-ASSESSMENT-ROUND2.md`](docs/SECURITY-ASSESSMENT-ROUND2.md) is a
red-team assessment of an earlier build. It is published, in full, because the
findings are more useful than the reassurance would be. Read it before
deploying.

The headline result: an attacker with brief physical access and an unsigned
firmware image could substitute firmware, read the device's OTP row, derive the
secure-store key, and decrypt the stored credentials. The literal key values
recovered during that assessment are redacted from the published document (the
board used is permanently burned — `otp_key_1` is a one-way-fuse row that cannot
be rotated), but the attack chain and the derivation are reproduced completely,
so the vulnerability is fully described.

Some of that has since been addressed; not all of it has. The document records
what was true of the build it assessed, not a current guarantee.

### Practical consequences

- **Physical access to an unlocked or freshly-bootsel'd device is assumed to be
  an attack.** Signed secure boot (`build-signed.sh`) is the mitigation and is
  opt-in; an unsigned build accepts whatever image it is handed.
- **The USB vendor ID `0xFA20` is not USB-IF-registered.** Treat the identity as
  provisional.
- **The compiled-in FIDO attestation key is a public development key.** A
  default build's attestation proves nothing about key provenance.
- **A default build keeps its secure store across a reflash.** Build with
  `FAPICO2_FOREIGN_IMAGE_WIPE=1` for a device that must destroy its store when
  flashed with an unrecognised image.

## A note on the one key-shaped value in the tree

`tests/scripts/check_attestation_gate.py` contains a 32-byte hex value, and it
is a **private key scalar**. It is there on purpose: the gate is a blocklist
that fails the build if those bytes — or their hex spelling — ever reappear
anywhere in the tree, and a blocklist has to contain what it forbids.

It is not live key material. It was compiled into a firmware image anyone could
download (so it has been public for longer than this repository existed), the
red-team round that extracted it rotated it out of the build, and the current
firmware generates per-device attestation keys from the TRNG. Everything ever
attested under it is forgeable by anyone, which is a fact about the past that
cannot be un-published.

## Reporting a vulnerability

Report privately. **Do not open a public issue for a vulnerability.**

Use GitHub's private vulnerability reporting for this repository
("Security" → "Report a vulnerability"), or open a security advisory. If that
is unavailable to you, open a regular issue that says only that you would like
to discuss a security matter privately, with no technical detail.

Please include: the firmware version or commit, the hardware (RP2350 board), the
threat model you are assuming, and a reproduction. A `firmware/fapico2.uf2`
reproduces a build exactly, so include one if you can.

What to expect: acknowledgement, an assessment of severity, and a fix or a
statement that the report is accepted as a known limitation. There is no bounty
programme and no SLA.

## Scope

In scope: the firmware in this repository, the bootloader/signing scripts, and
the vendored `vendor/opcard` code as built into the image.

Out of scope: the host-side `pcscd`/`libccid` stack, `gpg` and other PC/SC
clients, and any third-party app whose behaviour is documented in the README as
client-side and not fixable from the firmware.
