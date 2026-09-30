# FIDO2 hardware sign-in failure — CTAP2 canonical CBOR root cause & fix

**Date:** 2026-09-12 · **Scope:** `apps/fido/src/device_core.rs` (device/no-heap
serializer) · **Status:** fixed, verified on RP2350 hardware

## Symptom

Signing in at Token2 (`www.token2.com`) with the **physical fapico2 token**
failed in Chrome with a JS error whose CTAP2 layer reported
`kCtap2ErrInvalidCBOR`, produced by Chromium's CBOR decoder error
`DecoderError::OUT_OF_ORDER_KEY`. The **same flow against the emulation
binary passed all tests** (282 pytest cases + the Rust device-path suites).

## Root cause

CTAP2 §6.5.1 ("CTAP2 Canonical CBOR Encoding Form") requires every CBOR map
to carry its keys sorted ascending by *encoded bytes*: integer keys first,
then text strings by header byte (`0x60|len`) then UTF-8 content. Chromium
parses **every authenticator response** with its own strict canonical decoder
(`components/cbor/reader.{h,cc}`, invoked from
`device/fido/ctap2_device_operation.h`) and has done so since CTAP2 support
shipped — there is no leniency opt-out. Lenient decoders (python-fido2's bare
`cbor.decode`, Firefox, most server-side validators) accept the same bytes,
which is why only Chrome failed. This is a documented interop failure class:
SoloKeys solo1 #499 (makeCredential extensions map) and Yubico
python-fido2 #93 (GoTrust getInfo options map) hit the identical wall.

### Why only the hardware failed

The FIDO2 app has two CBOR writers:

- **Host/emulation path** (`app.rs`): builds responses as a `cbor::Value`
  tree; `cbor::encode` (cbor.rs:440-453) **sorts every map recursively**
  before writing. Wire output is always canonical regardless of insertion
  order.
- **Device path** (`device_core.rs`, `device_keystore.rs`, `ctap2.rs`):
  the zero-alloc `no_heap` writer (cbor.rs:21+) is a pure streaming writer
  with **no sorting and no validation** — wire order equals the caller's
  insertion order.

The device code copied key insertion order from host code that relies on the
encoder's sort. Result: every device-path response containing the offending
maps was non-canonical, invisible to the emulation test suites.

### Violations found (device path, full audit)

| # | Site | Map | Actual → canonical |
|---|------|-----|--------------------|
| 1 | `device_core.rs` `build_assertion` (~L1149) | getAssertion/getNextAssertion credential descriptor (response key 1) | `type` before `id` → **`id` first** (0x62 < 0x64). Fired on **every** sign-in — the Token2 failure |
| 2 | `device_core.rs` `cm_cred_response` user entity (~L2162) | credMgmt enumerateCreds user submap (key 6) | `displayName` first → **`id`, `name`, then `displayName`** (0x62 < 0x64 < 0x6B) |
| 3 | `device_core.rs` makeCredential extensions (~L853) | authData extensions map | `hmac-secret-mc` (0x6E) before `largeBlobKey`/`minPinLength` (0x6C) → **moved after** |
| 4 | `device_core.rs` makeCredential response (~L932) | top-level response map | map header hardcoded to **3** pairs while a 4th (`5: largeBlobKey`) was appended when requested — a structural defect any strict decoder rejects. Header count now includes the optional pair |

Everything else audited canonical: getInfo + options map (explicitly sorted
in `ctap2.rs`), COSE keys, clientPIN, largeBlobs, credMgmt top-level maps.

## Fix

Key reorder at the four sites above (commit
`fix(fido): canonical CBOR map ordering on the device path`).

## Regression guard

`apps/fido/tests/canonical_device.rs` — drives `FidoApp::process_ctap2`
(the exact handler code the RP2350 serve loop runs) through:

- makeCredential with the `hmac-secret-mc` + `largeBlobKey` +
  `minPinLength` extension set and a user entity with name + displayName,
- getAssertion (the browser sign-in command),
- credMgmt `enumerateCredsBegin`,

and walks **every raw response byte** with a strict canonical-order checker
(recursive over the `no_heap` `Parser`, comparing each map key's minimal
encoding lexicographically). Verified to **fail against the unfixed code**
and pass with the fix — closing the host/device divergence that let the bug
ship: the emulation suite can never catch this class of bug, because the
host writer sorts.

## Verification

1. `cargo test -p fapico2-fido --target x86_64-unknown-linux-gnu` — all
   green (incl. the 2 new regression tests).
2. Clippy gate (`-D warnings`) clean.
3. Full emulation pytest suite — no new failures vs. baseline (OpenPGP/PIV
   failures in the first run were transport/state pollution from a stale
   relay; see suite reports).
4. **Hardware:** release firmware rebuilt, UF2 flashed to the RP2350 in
   BOOTSEL, device re-enumerated as `fa20:0002 EddieOz fapico2`, then a full
   makeCredential → getAssertion ceremony for `www.token2.com` over USB HID,
   parsed with python-fido2 `Ctap2` (**strict_cbor=True** — the mode that
   re-encodes each response and rejects non-canonical bytes, i.e. the same
   property Chromium enforces): both commands returned canonical responses.

## Note on the JS error text

In current Chromium, `kCtap2ErrInvalidCBOR` maps to `NotAllowedError`
(`authenticator_common_impl.cc`, case `kAuthenticatorResponseInvalid`);
`SecurityError` is reserved for rpID/origin checks. The exact error text
observed depends on the Chrome version / Windows platform-authenticator
path in the middle; the underlying CBOR rejection is unaffected.

## References

- CTAP2 spec §6.5.1 canonical form:
  <https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html>
- Chromium strict reader: `components/cbor/reader.h` ("This decoder only
  accepts canonical CBOR…", `OUT_OF_ORDER_KEY = 8`)
- Analogous real-world cases: <https://github.com/solokeys/solo1/issues/499>,
  <https://github.com/Yubico/python-fido2/issues/93>,
  <https://github.com/w3c/webauthn/issues/1624>
