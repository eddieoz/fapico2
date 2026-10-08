# Reference

The repository's [`docs/`](https://github.com/eddieoz/fapico2/blob/main/docs/INDEX.md) directory carries the deep technical record. These are the ones most people need, with the key facts inline.

## Using the device

- [**identity.md**](https://github.com/eddieoz/fapico2/blob/main/docs/identity.md) — what the device claims to be: AAGUID `66617069636F3200…0002`, USB `FA20:0002`, and the **PC/SC allowlist step Linux/macOS need before OpenPGP and OATH work**.
- [**bootsel.md**](https://github.com/eddieoz/fapico2/blob/main/docs/bootsel.md) — flashing over BOOTSEL, recovery paths, and why re-enumeration can take a minute.
- [**capacity.md**](https://github.com/eddieoz/fapico2/blob/main/docs/capacity.md) — hardware-verified ceilings: 856 FIDO2 resident credentials **measured to refusal** on hardware, 68 OATH slots reserved.
- [**hardware-matrix.md**](https://github.com/eddieoz/fapico2/blob/main/docs/hardware-matrix.md) — the acceptance matrix: USB IDs, algorithms, per-applet results against real clients.

## Trusting the device

- [**secureboot.md**](https://github.com/eddieoz/fapico2/blob/main/docs/secureboot.md) — the RP2350 signed secure boot procedure: opt-in, burned once, irreversible.
- [**debug-access-risk.md**](https://github.com/eddieoz/fapico2/blob/main/docs/debug-access-risk.md) — the accepted-risk record for the open debug port until the first `-release` tag.
- [**supply-chain.md**](https://github.com/eddieoz/fapico2/blob/main/docs/supply-chain.md) — dependency vetting, SBOM and accepted RustSec advisories, CI-gated.
- [**SECURITY.md**](https://github.com/eddieoz/fapico2/blob/main/SECURITY.md) — how to report a vulnerability privately.

## Design records

- [**SECURITY-ASSESSMENT-ROUND2.md**](https://github.com/eddieoz/fapico2/blob/main/docs/SECURITY-ASSESSMENT-ROUND2.md) — the published red-team assessment, in full.
- [**secure-storage-comparison.md**](https://github.com/eddieoz/fapico2/blob/main/docs/secure-storage-comparison.md) — the adversarial comparison of the key-at-rest design against per-record flash stores.
- [**ADRs**](https://github.com/eddieoz/fapico2/blob/main/docs/adr/README.md) — architecture decision records: provisioning policy, TrustZone, PIV/RSA.

## Protocol references

- [**ctap2-hid-framing.md**](https://github.com/eddieoz/fapico2/blob/main/docs/ctap2-hid-framing.md) — the CTAPHID wire format, for driving CTAP2 by hand.
- [**client-compatibility.md**](https://github.com/eddieoz/fapico2/blob/main/docs/client-compatibility.md) — client-side quirks no firmware change can fix, and which side has to absorb each one.
