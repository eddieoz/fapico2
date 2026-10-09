# Round-3 Red-Team Remediation Record — fapico2 (1050:0407)

**Date:** 2026-10-05 · **Branch:** `fix/3rd-security-assessment`
**Source report:** [`SECURITY-ASSESSMENT-ROUND3.md`](SECURITY-ASSESSMENT-ROUND3.md)
(round 3, same-day remediation). **Epic:** `docs/tasks/EPIC-presence-gated-destruction-and-getinfo-leak.md`
(local, gitignored) — US-1600…US-1614, all executed.
**Verification probe:** `scripts/verify_getinfo_oracle.py` (commit `cb9dcdd`).

Round 3 found three control-plane defects. This record is the post-fix
hardware evidence for the two remediated ones (F1, F3) and the release-gate
story for the accepted one (F2).

## Status of every round-3 finding (as of 2026-10-08)

| Finding | Severity | Status | Where |
|---|---|---|---|
| F1 — unauthenticated `authenticatorReset` | CRITICAL | **FIXED** (touch gate, both twins + transport) | evidence below |
| F2 — open debug interface | HIGH | **ACCEPTED** — release gate, must be re-verified on hardware at the first `-release` tag | evidence below; [`../debug-access-risk.md`](../debug-access-risk.md) |
| F3 — `encCredStoreState` equality oracle | MEDIUM | **FIXED, verified on hardware** | evidence below |
| F4 — OATH default access code; PUT/DELETE/RENAME ungated; no validate retry counter | HIGH (latent) | **OPEN** — unchanged: `DEFAULT_ACCESS_CODE` still auto-provisioned (`apps/oath/src/oath_core.rs:396`, `:1089`), presence gates cover SET_CODE/CALC/CALC_ALL/RESET only | report F4 |
| F5 — normal REBOOT leaves the board non-enumerating | MEDIUM | **OPEN** — `cmd_reboot` unchanged (`apps/rescue/src/lib.rs:1335`); BOOTSEL replacement remains accepted by design | report F5 |
| F6 — `INS_MIGRATION` unauthenticated passphrase oracle | MEDIUM | **OPEN** — no presence grant on the migration dispatch (`apps/mgmt/src/lib.rs:464`) | report F6 |
| F7 — full firmware extractable over BOOTSEL | LOW | **ACCEPTED BY DESIGN** — documented in the threat model | report F7 |
| F8 — deprecated pinUvAuth protocol 1 advertised | LOW | **OPEN** — `pin_protocols` still pushes 1 and 2 (`apps/fido/src/ctap2.rs:839`) | report F8 |
| F9 — `apdu-trace` release-allowed, fixed drain CID, cleartext PINs | INFORMATIONAL | **PARTIALLY FIXED** — the drain channel is per-boot random (US-922, `firmware/src/dbg_cid.rs`); the feature remains release-allowed as a documented capture-build-only surface | report F9 |
| F10 — unassigned CLA returns success with no data | INFORMATIONAL | **OPEN** — `// TODO: check CLA` (`vendor/opcard/src/command.rs:244`) | report F10 |

## F1 — CRITICAL unauthenticated `authenticatorReset` — FIXED

The two-layer fix (command-boundary gate in `device_app.rs`/`app.rs` twins,
`0x07` added to the transport's `presence_windowed` set) landed in commits
`0349ef6` and `505f5a2`, with the US-1606 tripwire (`db5f173`) proving the
management factory reset still costs exactly one touch and US-1607 (`af81283`)
proving the device build fails closed. Covered by `apps/fido/tests/
reset_presence_gate.rs` (both twins) and the transport tests; the host suite is
green.

## F3 — MEDIUM `encCredStoreState`/`encIdentifier` equality oracle — FIXED, VERIFIED ON HARDWARE

The fix (commit `f1e5566`) encrypts under the advertised random IV instead of
discarding it for a zero IV. The probe was run before and after flashing the
fixed build (`firmware/fapico2.uf2` sha256 `7f1d6df0…`), same PIN-set board
(`clientPin=true, alwaysUv=true, makeCredUvNotRqd=false`):

| capture | `encCredStoreState` 0x1E | `encIdentifier` 0x19 |
|---|---|---|
| pre-flash | 10/10 distinct IVs, **1/10 distinct ciphertexts** | 10/10 IVs, **1/10 ciphertexts** |
| post-flash | 10/10 distinct IVs, **10/10 distinct ciphertexts** | 10/10 IVs, **10/10 ciphertexts** |

The pre-flash repeating ciphertext is byte-identical to the report's recorded
`f317bb1c8bee39979eb696e0df504295` — F3 reproduced on the same board it was
filed from, then closed on it.

**Counter-increment proof — the "not reached" item of the report, now reached.**
Full sequence on the flashed board: 10 getInfo polls (10/10 distinct) →
registration on `us1612-assertion-test.local` (PIN + touch, counter 100) →
**one real `getAssertion`** (UV required, touch, counter advanced to 134,
71-byte ES256 signature) → 10 getInfo polls (10/10 distinct) → **all 20
ciphertexts distinct across the assertion boundary**. An unauthenticated poller
can no longer distinguish "no assertion happened" from "an assertion happened".
The test credential was deleted afterwards (`enumerateRps` confirms zero
resident RPs; the PIN and the registered demo-site passkeys remain).

**Client regression (US-1611):** `ykman list` / `ykman fido info` /
`ykman otp info` clean; CCID `READ_CONFIG` and FIDO `0x42` return
byte-identical DeviceInfo bodies; getInfo is 464 bytes with the key set
unchanged, 0x19/0x1E still 32 bytes, no integer wider than 32 bits (AGENTS.md
§6). PicoForge 0.9.0: PIN unlock succeeded on both the **Passkeys and OATH**
screens, and full registration + authentication ceremonies succeeded in a real
browser on `token2.com/tools/fido2-demo` and
`demo.yubico.com/webauthn-technical`.

## F2 — HIGH open debug interface — ACCEPTED, RELEASE GATE PROVED

Per ADR 0002 the `DEBUG_DISABLE` closure applies at the first `-release` tag
(repository carries no tags yet). US-1613 (`22758c2`) produced
`scripts/check_release_debug_state.sh` — it exits non-zero on the current
pre-release image (`secure boot: 0 / debug enable: 1 / secure debug enable: 1`)
— and US-1614 recorded the window in `docs/debug-access-risk.md`. **The closure
itself still fires only at that first tag and must be re-verified on hardware
then.**

## Side observation, resolved

Post-flash, `ykman list` reported serial `42794857` while the CCID reader name
carries `94746395`. Both are the same SHA-256 prefix of the chipid
(`n = 0xF28CFF69`) in the two documented encodings of `platform/src/usb_ident.rs`:
the USB string is the scaled 8-digit rendering, the management `TAG_SERIAL` is
the raw prefix with the top six bits of its first byte masked. CCID and FIDO
DeviceInfo bodies are byte-identical. Not a drift.
