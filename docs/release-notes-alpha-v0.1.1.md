# fapico2-release-alpha-v0.1.1 — Release Notes

**Date:** 2026-10-07 · **Target:** Raspberry Pi Pico 2 (RP2350), USB-connected
**Shipping image:** `fapico2.uf2` — the Release carries the image and GitHub's
own "Source code" archives, and nothing else. The SHA-256 of the image is
recorded per-build, not here: it is stamped in the release SBOM and named in
the `release-manifest.json` attached to the release workflow run, and it is
what the build-provenance attestation covers.

**This is an alpha.** Alpha/beta images keep the debug port available and burn
nothing irreversible into OTP ([ADR 0002](adr/0002-provisioning-policy.md)).

## What changed since v0.1.0

- **`libfido2` resident keys work** (PR #14): the credential-management
  operation arrives on the `0x41` byte libfido2 1.14.0 hard-codes, not the
  `0x0A` the other clients send. `ssh-keygen -K` now downloads resident keys.
  Two defects in the preview dialect were fixed alongside it — the
  `enumerateRPs` response had a chimera `totalRPs` key value, and the
  sub-command numbering was inverted (US-1625/US-1626).
- **Presence-gated destruction** (PR #10, US-1600–1614): `authenticatorReset`
  now opens a consent window on the transport and requires user presence in
  both twins — a management factory reset costs exactly one touch — and the
  getInfo ciphertext is bound to the IV it advertises.
- **CI and gates** (PRs #11, #13, #15): the pinned toolchain is installed
  where `cargo` actually uses it, the boot-chain gate the 1.99.0 pin made
  reproducibly red was fixed, and pull requests are no longer failed for
  paperwork a change did not cause.
- **README** rebranded as the project's front door (PR #12).

## Verifying the download

1. Check out the tag and confirm it names the commit the Release shows.
2. Verify the image against the provenance GitHub minted for it:

   ```bash
   gh attestation verify fapico2.uf2 --repo eddieoz/fapico2
   ```

3. The same digest is in the `release-manifest.json` workflow artifact of the
   release run, cross-checked against the digest stamped into the attached
   SBOM.

The SBOM (`supply-chain/sbom.cdx.json`), the provenance statement and the
release manifest are workflow artifacts, not Release assets — the Release
itself carries the image and the auto-generated source archives.

## Scope and caveats unchanged from v0.1.0

The single UF2 serves one USB composite device (CCID + CTAP HID); applets are
selected by AID. The app-by-app scope, the hardware-acceptance matrix and the
provisional-VID (`fa20:0002`, not USB-IF-registered) note are in
[`docs/release-notes-v1.0.0.md`](release-notes-v1.0.0.md) and
[`docs/hardware-matrix.md`](hardware-matrix.md); nothing in them changed here.