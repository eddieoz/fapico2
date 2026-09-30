# PIV pytest harness — US-378 (the PIV suite gate)

Behavioural-verification suite for the **PIV** applet of the merged `fapico2`
firmware, driven over CCID against the single Rust emulation binary. It is the
acceptance gate for Phase 4 PIV (US-371…US-378) on the emulation transport.

This directory is self-contained: one `conftest.py` brings up a fresh
`fapico2-emulation` + `ccid_relay` session per run and the seven `test_piv_*.py`
files assert the wire protocol. It does **not** touch any Rust source.

---

## What is tested

| File | Story | Status now |
|---|---|---|
| `test_piv_status.py` | US-371/372/373 — SELECT/FCI, version, serial, PIN lifecycle, mgm AUTHENTICATE, missing-object 6A82 | **GREEN** |
| `test_piv_objects.py` | US-373 — GET/PUT DATA (roundtrip, `81 xx`/`82 hi lo` long forms, clear, unknown fid 6581, oversize 6700, no-mgm 6982) | **GREEN** |
| `test_piv_keygen.py` | US-374 — GEN KEY (0x47) P-256/9A + P-384/9C, attestation cert, GET METADATA (0xF7), negatives | **RED** |
| `test_piv_import.py` | US-374 — IMPORT (0xFE) known-scalar, metadata pubkey == d·G, negatives | **RED** |
| `test_piv_sign.py` | US-375 — slot sign (0x87) P-256/9C + P-384/9D, Python-side ECDSA verify, no-key 6581, algo mismatch 6700 | **RED** |
| `test_piv_ecdh.py` | US-375 — ECDH (0x3C) shared secret vs Python x-coordinate | **RED** |
| `test_piv_persistence.py` | US-374 — key + object survive an emulator restart (same keystore); mgm session does not | **RED** |

The RED tests are a **TDD record**: they assert the US-374/375 contract and fail
on plain protocol assertions (an `assert sw == 0x9000` that sees `0x6D00`/`0x6A81`).
They are deliberately **not** `@pytest.mark.skip`/`xfail` — they turn GREEN the
moment the Rust stories land, and they never crash on a fixture/timeout.

---

## How to run

Prereqs: the Rust emulation binary is built and the Python deps
(`cryptography`, `pytest`) are available. The project `.venv` has both:

```bash
cd fapico2

# 1. build the firmware under test (host emulation target)
cargo build --bin fapico2-emulation --no-default-features --features emulation \
    --target x86_64-unknown-linux-gnu

# 2. run the PIV suite (the conftest starts the relay + emulator itself)
./.venv/bin/python -m pytest tests/piv/ -v
```

The `conftest.py` `piv` fixture:
1. `pkill`s any stray `fapico2-emulation` / `ccid_relay.py`.
2. Starts `tests/harness/ccid_relay.py` (binds 35963 dial-in + 35970 client).
3. Starts `fapico2-emulation` with `FAPICO2_PIV_KEYSTORE` pointed at a fresh
   per-session temp file (factory defaults: PIN `123456`, 3 retries, AES-192
   mgm key `01…08×3`).
4. Connects the client, powers on (ATR), and SELECTs the PIV AID `A0 00 00 03 08`.

Ports 35963/35970 are **fixed** by the harness. The whole suite shares ONE
emulator session; the autouse fixture re-SELECTs PIV before each test so session
state (mgm/PIN) is clean, while persistent state (objects, keys, PIN retries)
survives. `test_piv_persistence.py` restarts the same emulator mid-session.

To run just the currently-green surface:
```bash
./.venv/bin/python -m pytest tests/piv/test_piv_status.py tests/piv/test_piv_objects.py -v
```

> Wiring `tests/piv/` into `run_all_tests.sh` / CI is a **later** story and is
> intentionally not done here.

---

## Actual pass/RED split (recorded 2026-09-07)

Run against `target/x86_64-unknown-linux-gnu/debug/fapico2-emulation`
(US-371/372/373 landed; US-374/375 in flight):

```
13 passed, 17 failed in 1.96s
```

**GREEN (13):**
```
tests/piv/test_piv_status.py::test_select_returns_fci               PASSED
tests/piv/test_piv_status.py::test_get_version_is_5_7_0             PASSED
tests/piv/test_piv_status.py::test_get_serial_is_dev_serial         PASSED
tests/piv/test_piv_status.py::test_pin_lifecycle                    PASSED
tests/piv/test_piv_status.py::test_mgm_authenticate                 PASSED
tests/piv/test_piv_status.py::test_missing_object_returns_6a82      PASSED
tests/piv/test_piv_objects.py::test_put_get_roundtrip               PASSED
tests/piv/test_piv_objects.py::test_get_200byte_uses_81xx_length_form  PASSED
tests/piv/test_piv_objects.py::test_get_2048byte_uses_82xx_length_form PASSED
tests/piv/test_piv_objects.py::test_put_empty_clears_object         PASSED
tests/piv/test_piv_objects.py::test_put_unknown_fid_rejected_6581   PASSED
tests/piv/test_piv_objects.py::test_put_oversize_rejected_6700      PASSED
tests/piv/test_piv_objects.py::test_put_requires_mgm_session        PASSED
```

**RED (17)** — each fails on a protocol assertion; the current emulator answers
`0x47`/`0xFE`/`0xF7`/`0x3C` with `6D00` (INS not implemented) and slot `0x87`
with `6A81` (function not yet supported):
```
test_piv_keygen.py::test_genkey_p256_slot_9a        "GEN KEY must answer 9000 (got 6D00)"
test_piv_keygen.py::test_genkey_p384_slot_9c        "GEN KEY must answer 9000 (got 6D00)"
test_piv_keygen.py::test_genkey_requires_mgm_session got 6D00, want 6982
test_piv_keygen.py::test_genkey_bad_slot_rejected    got 6D00, want 6B00
test_piv_keygen.py::test_genkey_bad_alg_rejected     got 6D00, want 6984
test_piv_import.py::test_import_known_scalar_p256   "IMPORT ... must answer 9000" (got 6D00)
test_piv_import.py::test_import_known_scalar_p384   "IMPORT ... must answer 9000" (got 6D00)
test_piv_import.py::test_import_bad_scalar_length_rejected got 6D00, want 6984
test_piv_import.py::test_import_requires_mgm_session got 6D00, want 6982
test_piv_import.py::test_import_bad_alg_rejected     got 6D00, want 6700
test_piv_sign.py::test_sign_p256_slot_9c             import setup: got 6D00, want 9000
test_piv_sign.py::test_sign_p384_slot_9d             import setup: got 6D00, want 9000
test_piv_sign.py::test_sign_no_key_returns_6581      "got 6A81"
test_piv_sign.py::test_sign_algo_mismatch_returns_6700 import setup: got 6D00, want 9000
test_piv_ecdh.py::test_ecdh_p256_slot_9e             import setup: got 6D00, want 9000
test_piv_ecdh.py::test_ecdh_p384_slot_9e             import setup: got 6D00, want 9000
test_piv_persistence.py::test_key_and_object_persist_mgm_session_does_not import: got 6D00, want 9000
```

---

## APDU / response contract (cross-check for the Rust agents)

All APDUs use CLA `00`. `SW_OK` = `9000`.

### GEN KEY — INS `0x47` (US-374)
```
00 47 00 <slot>  Lc  AC <n>  80 01 <alg>  [AA 01 <pinpolicy>]  [AB 01 <touch>]
```
- `slot` P2 ∈ {`9A`,`9C`,`9D`,`9E`}; `alg` = `11` (P-256) / `14` (P-384); P1 must be `00`.
- Success response (ECC) — C `make_ecdsa_response`:
  - P-256: `7F 49 43 86 41 <04||X||Y (65B)>` + `9000`
  - P-384: `7F 49 63 86 61 <04||X||Y (97B)>` + `9000`
- The matching **cert** is stored: 9A→`C105`, 9C→`C10A`, 9D→`C10B`, 9E→`C101`
  (readable via GET DATA, parses as X.509, public key == response point).
- **GET METADATA** (0xF7, see below) reports `origin = 01` (GENERATED).
- Negatives: no mgm → `6982` (checked first); bad slot → `6B00` (see ambiguity note);
  unknown alg → `6984`.

### IMPORT key — INS `0xFE` (US-374)
```
00 FE <alg> <slot>  Lc  06 <32|48> <scalar>  [AA 01 <pinpolicy>]  [AB 01 <touch>]
```
- P1 = `alg` (`11`/`14`), P2 = `slot`; `06` carries the raw private scalar
  (32 B P-256 / 48 B P-384). Empty response + `9000`.
- **GET METADATA** then reports the public key == `d·G` and `origin = 02` (IMPORTED).
- Negatives: no mgm → `6982`; scalar length ≠ 32/48 → `6984`; unsupported alg → `6700`.

### GET METADATA — INS `0xF7` (US-374)
```
00 F7 00 <slot>   ->   01 01 <alg>  02 02 <pinpolicy> <touch>  03 01 <origin>
                       04 <len> 86 <ptlen> <04||X||Y>   + 9000
```
- Tag `04` value = `86 <ptlen> <uncompressed point>` (ptlen `41`/`61`).
- Empty slot (no key) → C answers `6A88`.

### Slot sign — INS `0x87` to a key slot (US-375)
```
00 87 <alg> <slot>  Lc  7C <n>  81 <msg>   ->   7C <olen+2>  82 <olen>  <DER sig>  + 9000
```
- **C-parity: signing uses `0x87`, NOT Yubico's `0x32` SIGN.**
- The card hashes `msg` with SHA-256 (P-256) / SHA-384 (P-384), then ECDSA-signs
  the hash (DER). `olen` is the DER length.
- Pin policy: a slot whose policy is not `NEVER` requires a verified PIN
  (`has_pwpiv`) else `6982`. The tests import with `AA 01 01` (NEVER) so no PIN
  is needed.
- No key in the slot → `6581`; signing alg ≠ stored meta alg → `6700`.

### ECDH — INS `0x3C` (US-375, ADR-0001 addition — not in the C reference)
```
00 3C <alg> <slot>  Lc  7C <n>  81 <E>   ->   7C <m>  82 <Z>   + 9000
```
- `E` = host ephemeral uncompressed public key (`04||X||Y`); `Z` = the raw
  shared-secret **x-coordinate** (32 B P-256 / 48 B P-384).
- `m` = `1 + len(Z)` (the `82` tag wraps `Z` with the length implied by `m`).

---

## C-reference ambiguities and the choice made

The Rust port is a *parity* port of `pico-openpgp/src/openpgp/piv.c`, but the
US-374/375 task states specific status words that differ from the C reference in
three places. The tests assert the **task-stated** values (the contract the Rust
agent is implementing to) and flag the C value:

| Case | Test asserts (task) | C reference `piv.c` | Note |
|---|---|---|---|
| GEN KEY, bad slot | `6B00` (`SW_WRONG_P1P2`) | `6A86` (`SW_INCORRECT_P1P2`, `cmd_asym_keygen`) | Followed the task's explicit `6B00`. |
| Slot sign, no key | `6581` (`SW_MEMORY_FAILURE`) | `6A88` (`SW_REFERENCE_NOT_FOUND`) when the slot has no metadata; `6581` only when metadata exists but the key file is empty | Followed the task's `6581` (Rust checks key-file presence). |
| Default pin policy (no `AA`) | not asserted | 9C→`ALWAYS`(3), 9E→`NEVER`(1), else `ONCE`(2) (`piv_default_pin_policy`) | Tests import with an explicit `AA 01 01` (NEVER) to stay independent of the default, and the GEN KEY metadata assertions check only algo/origin/pubkey (not pin policy). |

Everything else (FCI blob, version `05 07 00`, serial `31 32 33 34`, PIN
lifecycle, mgm single-challenge AES-192-ECB, GET/PUT DATA TLV long forms,
`53 <len>` shape, cert fid mapping, ORIGIN values) matches the C reference
exactly and is exercised by the GREEN tests.
