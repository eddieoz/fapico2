# fapico2 v1.0.0 — Release Notes

**Date:** 2026-10-01 · **Target:** Raspberry Pi Pico 2 (RP2350), USB-connected
**Shipping image:** `fapico2.uf2`, sha256
`0f4e6189e4ea0c744ec556b4cf0b74c849b776ac1a25a085d5461175a898142c`
(3061 blocks = 1 absolute preamble + 3060 ARM_S payload; 1,567,232 bytes;
byte-reproducible from the tag via `firmware/uf2gen.py` — see
[docs/size-report.md](size-report.md), which re-measures every figure here
and fails CI on any disagreement).

**This is the first published release.** Earlier drafts of this file recorded
`b9bc12f8…` and `53ba915e…` (198 and 2,046-block images from 2026-09-11 and
2026-09-20). Both predate the OpenPGP applet, the Yubico OTP HID transport,
and the FIDO2 credential-management work, and neither is what a clone of the
tag builds. The numbers above are the image the release workflow builds and
publishes; `docs/size-report.md` is the authority and is enforced on every
push.

**Verifying a download.** The tag is **GPG-signed** by a maintainer, and
that is the trust anchor for this release. The Release carries the UF2, the
SBOM, the build-provenance attestation, and a `release-manifest.json` naming
the tag, the commit and the digest of each asset. So the check is: confirm
the tag's signature, read the manifest, and every asset is pinned to that one
version.

**What this release is not.** The artefacts are **not** cosign-signed. The
keyless signing path is deferred: cosign reports writing a Fulcio
certificate and writes something the verification gates cannot read, and a
keyless signature cannot be reproduced outside GitHub Actions to diagnose
it. Shipping a signature check that had never passed was the worse option,
so the signing steps were removed and the omission recorded in the workflow.
Restoring them is a small, deliberate change, and the gates are unchanged —
they will enforce the signature again the moment they can.

Note the two are different questions, and only the first is answered here.
The tag signature says **a person decided this is v1.0.0**. A cosign
signature would have said **GitHub Actions built these bytes from this
repository**. The build half is covered for now by CI's reproducibility
check and the provenance attestation, not by a signature over the artefact.

## Cutover decision

The C tree (`pico-fido2/`) is **frozen but shippable**. v1.0.0 of the Rust
`fapico2` firmware is the release point of the cutover: existing users can
move to the Rust build, and the C build remains available and supported for
what it still serves better — specifically, **PIV keeps being served by the C
firmware post-cutover** (PIV serving is out of the Rust v1.0.0 scope; PIV
*data* still migrates silently, below). The C tree receives no new features;
all Rust-side development happens in `fapico2/`.

## v1.0.0 scope

One firmware, one binary — a single UF2 serving one USB composite device
(CCID + CTAP HID), apps selected by AID:

| App | State in v1.0.0 |
|---|---|
| **OpenPGP 3.4** (CCID, AID `D2 76 00 01 24 01`) | **Phase-7 addendum:** full opcard command set served on device (S-721-1…5), hardware-accepted P7-C7 (gpg generate + clearsign/verify on device); private keys migrate via PW1 (below) |
| **Management** (CCID, `A0 00 00 05 27 47 11 17`) | config (incl. `EF_DEV_CONF` persistence), migration passphrase APDU |
| **OATH** (CCID, `A0 00 00 05 27 21 01`) | **v1.0.0 capability note (SUPERSEDED by the Phase-7 OATH addendum below):** a YKOATH **wiring shell** — SELECT→FCI only, command set not served; **app-restore is post-cutover**, no store restore (`OathApp::new()`); migrated OATH data was preserved in the keystore and serves once the restore lands |
| **OTP** (CCID, `A0 00 00 05 27 20 01`) | served inside the management app crate; slots persisted + restored (`otp.slots.v2`) |
| **FIDO2/U2F** (CTAP HID) | **v1.0.0 capability note (SUPERSEDED by the Phase-7 addendum below):** a CTAP-HID **shell** — `getInfo` + vendor vault + error responses; the only durable secret is the persisted hkey (keydev). Resident-credential CTAP2 serving is post-cutover; migrated FIDO credentials are preserved in `fido.keystore.v1` |
| **PIV** | **deferred — post-v1.0.0**; use the C firmware for PIV (see cutover decision) |

## Migration from the C firmware (first Rust boot)

On the first boot on a board that ran the C `pico-fido2` firmware, the Rust
image re-seeds its keystore from the C data partition (read-only on the C
region; idempotent — a second boot changes nothing).

- **Silent (no user input):** FIDO keydev (32/33 B records) + resident
  credentials, OATH credentials, OTP slots, Management `EF_DEV_CONF`, PIV
  objects (re-seeded into `piv.keystore.v1`; serving deferred), OpenPGP
  public keys / certificates / DOs / PIN hashes.
- **PW1/PIN classes (one-time):** OpenPGP **private keys** and 61 B
  PIN-wrapped FIDO keydevs need the user's passphrase **once**, via the
  migration management APDU (P1 selects the class, data carries the
  PIN/passphrase). Wrong passphrase ⇒ `NEEDS_PASSPHRASE` (constant-time
  compare; C retry counters untouched).
- **Not migratable:** the vendor ChaChaPoly keydev (`EF_KEY_DEV_ENC 0xCC01`
  only) — no device-side unwrap exists.

Full byte formats, key-derivation formulas, and per-class verdicts with C
source evidence: [us413-migration-feasibility.md](tasks/us413-migration-feasibility.md).
On-hardware proof with real C data: [us413-hardware-e2e.md](tasks/us413-hardware-e2e.md)
(cutover executed 2026-09-11 — C release flashed, real data created, Rust
migration image flashed, cutover assertions recorded verbatim).

## Hardware acceptance

The US-213 hardware matrix was executed on the RP2350 with verbatim evidence
per row (rows 1–5 recorded, row 6 PIV **DEFERRED**): see
[hardware-matrix.md](hardware-matrix.md). The boot bring-up saga and its
reconciled root cause (task-frame overflow chain: store-in-async-frame →
store by-value copy → app objects/Dispatcher in the task param frame; MSPLIM
exonerated; entry = VT[1]) are recorded in the matrix's
boot bring-up section.

## USB identity (provisional VID)

The device enumerates as **`fa20:0002` "The BLOCO Community" "fapico2"`**.
**Note:** `0xFA20` is **not** a USB-IF-registered vendor ID — this identity is
provisional. Production requires a registered VID or a picoforge re-brand.
Host implications and the libccid `Info.plist` allowlist workaround
(macOS/OpenSC; Linux pcscd matches by CCID class) are documented in the
[README](../README.md#usb-identity-provisional).

The manufacturer was `"EddieOz"` until 2026-09-28. **v1.0.0 ships
`"The BLOCO Community"`** — this section said otherwise for a while after
that rename, which is why `check_release_notes.py` now compares the identity
in these notes against `firmware/boards/pico2.toml` rather than trusting
either to be remembered in step with the other. A board flashed with an
image older than the rename still enumerates as "EddieOz"; that is the only
case where the old string is correct.


---

## Phase-7 capability addendum (S-701-4/-5/-6, 2026-09-12 — supersedes the FIDO shell note above)

The FIDO2/U2F app now serves the **full CTAP2.1 command set on the RP2350**
(no-heap): getInfo (maxMsgSize 7609, canonical CBOR), makeCredential (ES256,
rk, credProtect / credBlob / hmac-secret(-mc) / largeBlobKey extensions),
getAssertion + getNextAssertion, clientPin (protocols v1+v2, permissioned
tokens), credMgmt, largeBlobs (fragmented get/set), authenticatorConfig,
U2F/CTAP1 and the vendor vault. Durable state persists in the chunked
`fido.keystore.v1` snapshot (credentials, PIN state, large-blob array, vault
state). Evidence: Phase-7 ladder (P7-C1/P7-C2 hardware
ceremonies via python-fido2) and `apps/fido/tests/device_*.rs`.

## Phase-7 OATH addendum (S-711-1…3, 2026-09-12 — supersedes the OATH wiring-shell note above)

The OATH (YKOATH) app now serves the **full YKOATH command set on the RP2350**
(no-heap, the device-path `oath_core`): PUT / DELETE / RENAME / LIST,
CALCULATE (HOTP counter + TOTP), CALC_ALL, SET_CODE + access-code challenge
on SELECT with VALIDATE, RESET, and the OTP PIN lifecycle (set / verify /
change with retry budget). Durable state persists in the chunked
`oath.keystore.v1` stream (credentials, HOTP moving factors, access code);
the OTP PIN record is session state (S-711-1 scope note — the C firmware
persisted it as `EF_OTP_PIN`, so PIN *persistence* parity is an open
follow-up; PIN ops pass). Evidence: Phase-7 ladder P7-B1 —
a 45-check hardware ceremony over real CCID including a user power cycle
(`tests/scripts/p7_b1_oath.py`) — and `docs/hardware-matrix.md` row 3.
Re-confirmed verbatim in P7-D1 (S-731-1, 2026-09-19): the same 39-check
ceremony re-run over pyusb raw-CCID (`tests/scripts/ccid_usb.py`) on the
final S-723 image `f8d92bd5…` — and re-pinned
in P7-D2 (S-731-1, 2026-09-20): 39/39 PASS again on the final Phase-7 image
`53ba915e…` on a factory-fresh (nuked) keystore, with the post-replug
persistence corroboration (VALIDATE + LIST + HOTP counter continued).

## Phase-7 OpenPGP addendum (S-721-1…5, 2026-09-18 — supersedes the OpenPGP shell scope note above)

The OpenPGP 3.4 app now serves the **full opcard command set on the RP2350**
(no-heap): SELECT, VERIFY / CHANGE-REF-DATA / RESET-RETRY, GET DATA / PUT DATA,
SELECT DATA / GET NEXT, PSO:SIGN / DECIPHER / ENCIPHER (ECC only: P-256,
Ed25519, Cv25519), INTERNAL AUTHENTICATE, GENKEY, MSE, GET CHALLENGE, TERMINATE
DF. Durable state persists in the chunked `openpgp.keystore.v1` stream (DO
records, PIN hashes) plus `openpgp.dek.v1` (IV+key for private key unwrap after
PW1 migration APDU). Hardware-accepted P7-C7 (`docs/hardware-matrix.md`
row 1): `gpg --card-edit generate` (three-key ECC generated on-card in the
secure store, TRNG entropy), `gpg --clearsign` / `--verify` returns
"Good signature", PIN change + reset-retry-counter, GET CHALLENGE
non-constant, and unplug/replug persistence. Evidence:
Phase-7 ladder P7-C7, S-721-5 acceptance, and `docs/hardware-matrix.md` row 1.
Re-pinned in P7-D2 (S-731-1, 2026-09-20) on the final Phase-7 image
`53ba915e…`: the OpenPGP identity was regenerated on-card (three-key ECC,
new fingerprint set, full gpg ceremony incl. PIN change + reset-retry +
non-constant GET CHALLENGE), and the identity persisted the row-5 power
cycle.
