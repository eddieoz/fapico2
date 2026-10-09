# fapico2-release-alpha-v0.1.2 — Release Notes

**Date:** 2026-10-09 · **Target:** Raspberry Pi Pico 2 (RP2350), USB-connected
**Shipping image:** `fapico2.uf2` — the Release carries the image and GitHub's
own "Source code" archives, and nothing else. The SHA-256 of the image is
recorded per-build, not here: it is stamped in the release SBOM and named in
the `release-manifest.json` attached to the release workflow run, and it is
what the build-provenance attestation covers.

**This is an alpha.** Alpha/beta images keep the debug port available and burn
nothing irreversible into OTP ([ADR 0002](adr/0002-provisioning-policy.md)).

## What changed since v0.1.1

The firmware image is functionally unchanged — the only touch in the
firmware tree is a stale documentation path inside one test comment. This
release is the tooling and the documentation around the device:

- **Seed backup export/restore** (PR #16): `scripts/backup_fido.py` exports
  and restores the vendor seed as a 24-word BIP-39 phrase, speaking the
  `0x41` backup dialect (MSE / EXPORT / LOAD / FINALIZE / STATE) over a
  touch-only session. The phrase never enters argv or the environment;
  `--out` writes `0600` and refuses to overwrite; finalize refuses a
  non-terminal state without `--yes`. The dialect is pinned byte-exactly by
  `tests/pico-fido/test_093_backup.py`. The honest scope is in
  [`docs/backup-seed.md`](backup-seed.md): passkeys are **not** in this
  backup, CTAP2 reset does not clear the seed, and a PIN-set board answers
  `0x36` to this touch-only tool by design (AGENTS.md §4) — use PicoForge
  there, or reset the PIN away.
- **Documentation site** (PR #17): the mdBook in `book/` now serves at
  <https://eddieoz.github.io/fapico2/>, deployed by `pages.yml` — product
  landing, how-tos (disk encryption, git signing, encrypt-to-recipient,
  changing the USB identity), a threat model and a FAQ, all reviewed against
  the device's actual behaviour.
- **Release workflow** (8d5aaa6): the Release is titled with the tag itself,
  not "fapico2 <tag>".

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
