# Round-2 Red-Team Security Assessment — fapico2 (FA20:0002)

> **Status (added 2026-10-08, post-remediation).** This is the record of the
> 2026-09-27 build; the findings below describe that build, not today's. The
> headline CRITICAL (unauthenticated `authenticatorReset`, R2-14) was still
> present when round 3 ran on 2026-10-05 and is **now FIXED** with hardware
> evidence — see
> [`SECURITY-ASSESSMENT-ROUND3-REMEDIATION.md`](SECURITY-ASSESSMENT-ROUND3-REMEDIATION.md).
> The storage findings led to the per-record key store
> ([`../capacity.md`](../capacity.md)); the secure-boot recommendation shipped
> as opt-in ([`../secureboot.md`](../secureboot.md)); the OATH applet the
> round could not test now ships and is tested. Everything below is the
> published copy as redacted.

> **Published copy — redactions applied.** This report originally contained the
> literal key material recovered from the device under test, including a
> hardware-unique OTP row, the derived store key, a FIDO master key, a TOTP
> secret, and a passkey private key. Those values are redacted here. They were
> real: `otp_key_1` is a one-way-fuse row that cannot be rotated, and the board
> used for this assessment is permanently burned — so publishing them would hand
> any reader a working key-extraction against that exact device, and would
> compromise a passkey belonging to a third party. The attack chain, the
> derivation recipe and the verdict are reproduced in full; only the outputs are
> withheld.

**Target.** The user-owned fapico2 RP2350 hardware token, connected over USB as a
composite device (CCID smartcard + CTAPHID), USB ID `fa20:0002` "fapico2".
**Repository.** `fapico2` (Rust, RP2350, GPLv3).
**Round-1 report.** Not part of this repository; the round-2 findings below are
self-contained. (2026-09-22.)
**Date.** 2026-09-27. **Artifacts and tooling** live outside this repository and
are not published.

This is the **second** assessment. Round 1 broke the device on all twelve axes
(R1–R12); the team then landed the `SEC-HARDEN` epic (US-901…US-930). Round 2's
question is therefore not "is it broken again" but **"do the fixes hold, and
what did the fixes themselves create?"**

---

## Executive summary

**The authentication and consent gates mostly hold on the flashed build — with
one catastrophic exception, confirmed on hardware: any USB host can wipe the
entire FIDO authenticator, including the PIN, with a single unauthenticated
command.**

Four conclusions, all evidence-backed:

1. **CRITICAL — `authenticatorReset` is completely unauthenticated (R2-14).**
   A bare CTAP2 `authenticatorReset` (command `0x07`) with **no PIN, no
   `pinUvAuthToken`, no `pinUvAuthParam` and no user presence** returned
   `CTAP2_OK` on the live device. The `clientPin` option disappeared from
   `GET INFO` (present before, absent after) and every FIDO credential was
   destroyed. CTAP 2.1 §6.1 requires a `pinUvAuthConfig` token; a forged
   `pinUvAuthParam` was accepted too. **This was executed on hardware, and it
   is the most serious finding of round 2.**

2. **CRITICAL — the v2→v3 store migration is a permanent, unauthenticated
   store takeover (R2-02).** An attacker who can write the secure partition
   presents two CRC-valid v2 slot images; the device accepts them as
   `MigratePrimary`, loads the attacker's `fido.hkey`, `fido.keystore.v1` and
   `boot.entropy.v1`, and re-seals them as a valid v3 image that boots
   `LoadPrimary`. **Confirmed with a running proof of concept.** It re-opens
   **R6**, which round 1 recorded as *Closed* by US-915.

3. **The at-rest crypto the gates depend on does not survive a flash dump
   (R2-03/04/05).** The store key is `HKDF(otp_row ‖ chipid)` — neither input is
   secret; the "US-918 entropy binding" contributes zero bits because the
   entropy record lives *inside* the store it would key; and with no monotonic
   counter the durable FIDO PIN lockout can be rolled back to permit unbounded
   brute force.

4. **Everything else the round-1 chain relied on is now correctly refused.**
   U2F REGISTER is presence-gated (`6985`), OpenPGP factory-default PINs are
   rejected, INTERNAL AUTHENTICATE without VERIFY is refused (`6982`), `PSO:CDS`
   without a PW1 session is refused (`6982`), management `WRITE_CONFIG`/`RESET`
   without presence is refused (`6985`), and no AID-confusion or cross-applet
   state leak was found.

**Net:** the device resists a *malicious host* on every key-signing path it was
rebuilt to protect, but it does **not** resist (a) an unauthenticated wipe of
the whole FIDO authenticator from any host, or (b) an attacker holding the
flash image. The round-1 report's post-fix column overstates the closure of
R6 and R7.

**Damage caused during this assessment (both mine, disclosed in full):**

- I exhausted the **OpenPGP** PW1 and PW3 retry counters while probing whether
  factory-default PINs were still active. They were not — the first candidate
  was already rejected — but my loop sent three per role and drove both
  counters to 0. The OpenPGP card is now PIN-blocked.
- I executed an **unauthenticated `authenticatorReset`** (finding R2-14), which
  destroyed the FIDO authenticator: all credentials and the FIDO PIN are gone.

Both are detailed in [§7](#7-operational-damage-and-recovery). The second was
within the engagement's explicit scope ("write the storage and invalidate keys.
wipe storage. corrupt storage"); the first was an avoidable scripting error on
my part.

---

## 1. What is actually flashed

Round 2 had to establish this first, because it determines what any test means.

| Property | Value |
|---|---|
| USB | `fa20:0002` EddieOz fapico2, 2 interfaces (CCID + HID) |
| ATR | `3B DA 18 FF 81 B1 FE 75 1F 03 00 31 F5 73 C0 01 60 00 90 00 1C` |
| AAGUID | `66617069636f32000000000000000001` (`"fapico2"`) |
| CTAP2 versions | `U2F_V2, FIDO_2_0 … FIDO_2_3` |
| CTAP2 options | `clientPin, pinUvAuthToken, rk, credMgmt, authnrCfg, largeBlobs, setMinPINLength, makeCredUvNotRqd, enterpriseAttestation` |
| pinUvAuthProtocols | `[1, 2]` |
| Applets present | **OpenPGP** (`D27600012401`), **Management** (`A000000527471117`, version `1.0.0`) |
| Applets **absent** | **OATH** `6A82`, **OTP** `6A82`, **PIV** `6A82` |
| OpenPGP Application ID | `d2760001240103040000487a8a960000` (serial `487a8a96`, version 0.0) |

**Finding R2-01 (Medium — provenance).** The flashed image registers **only
OpenPGP and Management**, while `firmware/src/main.rs:515-521` registers four
CCID apps (Management, OATH, OTP, OpenPGP). The device in the field is
therefore **not the current source tree**. Consequence for the assessment: the
OATH hardening (US-901/902/903 — the R1/R2 fixes) and the PIV work **could not
be tested at all**, because those applets are not present. Round 1's R1/R2
(OATH unauthenticated RESET and session self-grant, both *Critical*) are
**unverified on this device**, not fixed. This is a gap in the evidence, not a
pass.

---

## 2. Findings — confirmed

Ranked by severity. "Confirmed" means a proof of concept was executed, not that
the behaviour was read in source.

### R2-14 — **CRITICAL** — `authenticatorReset` is unauthenticated: any host wipes the whole FIDO authenticator

*Evidence: executed on the live device. This is the headline finding.*

A bare CTAP2 `authenticatorReset` (command `0x07`) carrying **no PIN, no
`pinUvAuthToken`, no `pinUvAuthParam` and no user presence** returned
`CTAP2_OK`:

```
BEFORE  pin state = {'pinRetries': 8}   clientPin option = True
C1      authenticatorReset (0x07), no auth  -> CTAP2_OK
C1b     authenticatorReset with a FORGED pinUvAuthParam -> CTAP2_OK
AFTER   pin state = {'pinRetries': 8}   clientPin option = None
        GET INFO options: clientPin ABSENT (it was present before)
```

`clientPin` disappearing from `GET INFO` is the spec-defined signal that the
authenticator has no PIN: the PIN and every credential are gone. Per CTAP 2.1
§6.1 an authenticator reset **must** be authorised with a `pinUvAuthConfig`
token (subCommand `0x0A`); the device accepts the request without one, and also
accepts a 16-byte zero `pinUvAuthParam`.

Source: `apps/fido/src/device_app.rs:507` dispatches the command with no data
and no auth; `device_core.rs:1823` wipes all credentials and `:1839-1841`
explicitly zeroes `needs_power_cycle` / `new_pin_mismatches`.

**Impact.** Any process that can open the HID interface — a browser page via
WebAuthn, a malicious host program, or anything with USB access — can destroy
every FIDO credential and the PIN in one packet, with no user interaction and
no secret. Combined with **R2-15** this is also an anti-forensics primitive:
the reset zeroes the durable strike state.

**Scope note.** The FIDO app is not CCID-registered on device
(`apps/src/registry.rs:35-46`), so this is **CTAPHID-only** — it is not
reachable over the smartcard interface.

### R2-15 — **HIGH** — The durable PIN strike counter rolls back on snapshot replay

The US-909 strike state (`retries` / `blocked` / `needs_power_cycle` /
`new_pin_mismatches`) lives inside the AES-GCM store image keyed by
`HKDF(otp_key_1 ‖ chipid)` — a key constant for the device's life, so an
**older but authentic** image verifies perfectly. There is no sequence counter
anywhere in `store_v3` or `DeviceKeystore::from_cbor`. PoC: 3 strikes →
`PIN_AUTH_BLOCKED`; restore the clean snapshot; six cycles →
**18 PIN guesses from a single snapshot.** Unbounded brute force for anyone who
can write flash. Fix requires an OTP-row-anchored write counter.

### R2-16 — **MEDIUM** — OATH `SEND REMAINING` (INS `0xA5`) has no `validated` gate

`oath_core.rs:980 → :1362`. Nine of the ten credential-affecting handlers check
`validated`; this one does not. It serves a validated `CALC ALL`'s remaining
credential names and OTP codes to whoever sends `0xA5` next.

### R2-17 — **MEDIUM** — The CCID consent window is bound to a tag, not to the APDU instance

`firmware/src/presence.rs:293-316`. A button press made for nothing in
particular becomes consent for the **next** OATH RESET, and the window re-joins
for its whole 15 s — during which every other presence-gated command is
effectively DoSed. This is the residual of round 1's R11 anti-harvest fix.

### R2-18 — **LOW** — Smaller confirmed issues

- Three bad `pinUvAuthParam` values durably brick the token (no recovery path).
- An OATH applet holding credentials but no secret is permanently unreachable.
- No minimum OATH access-code length, no VALIDATE retry counter, and `SET_CODE`
  authenticates against a **client-chosen** challenge.
- The "stretched" FIDO PIN verifier is 4096 SHA-256 rounds — iterations only,
  no memory hardness (see also R2-07).

### R2-02 — **CRITICAL** — The v2→v3 store migration is a permanent unauthenticated store takeover

*Evidence: executed. Reproduces round-1 R6 after its "fix".*

`store_v3.rs:569` accepts **any** two CRC-valid v2 slots as `MigratePrimary`.
There is no one-shot marker, so the arm stays live forever on an
already-migrated device — the doc claim "migrated exactly once"
(`store_v3.rs:44-52`) is not implemented.

Confirmed end to end with stdlib Python only (no firmware code):

```
[A3] forged v2 image: 162 bytes, magic = "PS2F", crc = 0x4774643b
[A4] boot decision on the FORGED v2 pair:  MigratePrimary
[A5] restored fido.hkey       = [20,21,22,23,24,25,26,27]   (attacker scalar)
     restored fido.keystore.v1= "ATTACKER-KEystore-CBOR"     (attacker data)
     restored boot.entropy.v1 = [c0,c1,c2,c3,c4,c5,c6,c7]     (attacker entropy)
[A6] re-sealed -> 225 B, magic="PS3F", decision = LoadPrimary
```

US-919 does not stop this: the firmware manifest is checked *after* the store
mounts, and an absent slot is treated as first boot. Artifacts:
`out2/rt2_forged_slot_primary.bin`, `out2/rt2_forged_slot_shadow.bin`.

**Impact:** anyone with the ability to write the secure partition (BOOTSEL is
accepted — see R2-11) controls the device's FIDO master key, keystore and boot
entropy.

### R2-03 — **HIGH** — The store key is derived from two non-secrets

`derive_store_key` = `HKDF(otp_row ‖ chipid)`. Row `0xE90` carries only a *write*
lock (`SWLOCK.NSEC = READ_ONLY`), and the chip ID is already emitted over USB as
a 4-byte hash. No OTP key ladder and no CryptoCell secret is used anywhere in
the derivation. Confirmed: **full key recovery from `(otp_row, chipid)` alone**,
including the FIDO keystore and the attestation scalar.

The code documents this as a residual and defers it to US-924, but the round-1
report records R6 as *Closed*. It is closed only against the weakest attacker.

### R2-04 — **HIGH** — The US-918 entropy binding is vacuous

`derive_store_key` takes **no entropy parameter**; the entropy record lives
*inside the store it would key*, and the key is what opens that store. The
`boot.entropy.v1` record was recovered using only `(otp_row, chipid)`. The
comment at `store_v3.rs:41-42` ("US-918 hardens further") is false as written.

### R2-05 — **HIGH** — No monotonic anti-rollback counter: the durable PIN lockout rolls back

The FIDO 3-strike latch lives in the store. With no monotonic counter outside
the store, a forged **tag-valid v3** image (no downgrade needed) resets it.
Confirmed: the durable latch rolls back to *cleared*. This defeats US-909's
anti-brute-force property for anyone who can write flash.

### R2-06 — **MEDIUM** — US-917 wrap key ignores the US-918 binding

`derive_wrap_key` uses only `(otp_row, flash UID)` — no chip ID, no boot entropy.
Cross-device reuse is prevented, but the same device re-derives it, so a flash
dump defeats it exactly as it defeats R2-03.

### R2-07 — **MEDIUM** — FIDO PIN verifier material is still cleartext

US-911 left `pin_hash` / `pin_salt` / `pin_iter` as cleartext CBOR, with 4096
iterated SHA-256 as the stated work factor. The counter-probe budget (8) is
then brute-forceable offline at trivial cost.

### R2-08 — **MEDIUM** — A single slot write failure is a permanent brick

One failed write → `Refuse` → `boot.rs:176` `fatal_boot()`. The device never
enumerates. This converts any transient flash write error into a hard brick
with no recovery path short of BOOTSEL.

### R2-09 — **MEDIUM** — `check_attestation_gate.py` does not catch a static key

The gate passes green on a tree with a re-added static attestation key (tested
both as a new literal and as the old scalar moved outside `apps/fido/src`). A CI
gate that cannot fail is not a gate.

### R2-10 — **MEDIUM** — Stale secret tail survives a short overwrite

`Rp2350SecureStore::write` leaves the tail of a longer previous secret resident
(24 of 32 bytes observed). This contradicts the stated US-704 write discipline
and is a cold-boot-forensics exposure.

### R2-11 — **MEDIUM** — No signature-based secure boot

`platform/src/fw_manifest.rs` compares the running image's SHA-256 against a
last-known-good hash in the sealed store. An *absent* slot is accepted and
stamped, so on an unprovisioned device any unsigned BOOTSEL image becomes
last-known-good. The sibling project **RS-Key** closes this with OTP-held
signature verification — the reference implementation is in-tree.

### R2-12 — **LOW** — ECDSA signature malleability (device-relevant)

`ES256` assertions are malleable: for a captured signature `(r, s)`, the pair
`(r, n−s)` is a **second distinct, equally valid signature over identical
signed bytes**. Confirmed with a real verifier accepting both.

Applied to the round-1 device signature (`out/u2f_auth.json`):

```
r        e715c6f12209cf31ddaf4b0f2c84ceebd2f010fd84809984f77c97a196636ae2
s        edd0786173dea1abc225b12afcb59b35d83c6ee39e90cfb0e182df4d70c40671
s' = n-s 122f879d8c215e553dda4ed5034a64c9e4aa8bca0886ced41236eb758b9f1ee0
```

**Ed25519 is not affected in practice:** `(R, s+L)` was *rejected* by a modern
verifier's canonical-`s` check. The mitigation for ES256 is on the relying
party (de-duplicate assertions by `clientDataHash`/counter, not by signature
bytes); the device cannot fix it alone.

### R2-13 — **INFO** — Unauthenticated D-readable data objects

`DO 4F` (Application ID / serial), `DO 5B`, `DO 5E`, `DO 65`, `DO 73`,
`DO C4` (PW status) and `DO C5` (key fingerprints) are all readable with no
verification. This is **per the OpenPGP card specification**, not a defect, but
it is a permanent fingerprinting and pre-authentication oracle: the device
reveals which key algorithms and key slots exist before any PIN is presented.

---

## 3. Security passes — what actually held

These are measured, not assumed. Each is a round-1 attack re-run against the
flashed build.

| Round-1 attack | Round-1 result | Round-2 result |
|---|---|---|
| U2F REGISTER, no PIN, no touch (R3) | credential planted, `9000` | **`6985` ConditionsNotSatisfied** ✅ |
| U2F AUTHENTICATE with UP byte forced (R3) | silent assertion, UP=0x01 | **unreachable — no credential can be minted** ✅ |
| OpenPGP factory PW1 `123456` (R5) | `9000` | **rejected** ✅ |
| OpenPGP factory PW3 `12345678` (W2-2) | `9000` | **rejected** ✅ |
| INTERNAL AUTHENTICATE, no VERIFY (W2-1) | `9000` + signature | **`6982`** ✅ |
| `PSO:CDS` over attacker hash, no touch (R8) | signed silently | **`6982`** ✅ |
| mgmt `WRITE_CONFIG` / `RESET` no presence (R11) | refused | **`6985`** ✅ |
| OATH unauth RESET `00 04 DE AD` (R1) | wiped all credentials | **unverifiable — applet absent (R2-01)** |
| FIDO CTAP2 `makeCredential` no token (R3) | refused | **refused** ✅ |
| FIDO `largeBlobs` no token | refused | **`PUAT_REQUIRED`** ✅ |
| AID confusion / cross-applet leak | — | **none**: unknown AID → `6A82`, no state change, OpenPGP state intact ✅ |
| Store parser bounds (`count=0xFFFFFFFF`, u32 wrap, `count=1025`) | — | **all refused, no OOB** ✅ |
| Encrypt-then-MAC ordering, MAC-before-plaintext, constant-time compare, nonce reuse | — | **all hold** ✅ |
| FIDO PIN budget integrity (before my own reset) | — | **`pinRetries = 8`**, no guess ever sent ✅ |
| FIDO `authenticatorReset` gating | — | **NOT GATED — accepted; PIN + credentials destroyed** ❌ (R2-14) |
| OATH `SEND REMAINING` (INS 0xA5) | — | **no `validated` gate** ❌ (R2-16, code-level) |

The **state-confusion** class (top-ranked in the wallet research: mutating a
command after a SELECT, a failed VERIFY, or a card reset) was tested explicitly
against every OpenPGP key operation. All refused `6982`. The dispatcher is
sound.

---

## 4. Threat-model coverage

Round 1 tested T1–T4. Round 2 re-scored them against the hardening and added the
techniques the wallet research contributed.

| # | Threat | Round-1 | Round-2 |
|---|---|---|---|
| T1 | Malicious host program | Broken (OATH, OpenPGP) | **Contained** — every gate refuses; OATH untestable (R2-01) |
| T2 | Channel MITM | Broken (digest substitution) | **Contained** — the unverified-session signatures that enabled it no longer exist |
| T3 | Evil maid, momentary access | BOOTSEL reflash | **Open** — unsigned boot, store takeover (R2-02) |
| T4 | SWD / flash-dump attacker | All secrets in cleartext | **Open** — v3 AEAD is cosmetic against a dump (R2-03/04/05) |

**Added from the wallet research** (Ledger Donjon, Ledger/Trezor/OneKey audit
history; see `out2/RESEARCH-wallet-vulns.md`):

- **RP2350 has no protected OTP by default.** Datasheet §13.5.5: on a blank
  device, OTP pages 2–61 are fully accessible from all domains. The published
  "RP2350 hacking" literature assumes a configuration fapico2 does not have.
- **RP2350 errata are themselves security bugs** — E16/E20/E21/E24 are
  fault-injection issues. *(Corrected in §18: this agent's "E3 = TrustZone
  escape on QFN-60" was wrong — E3 is a `GPIO_NSMASK` -> `PADS_BANK0` register
  mis-mapping, not a TrustZone escape. The genuinely severe ones are E16 and
  E24.)*
  E18/E22 are permanent bricks (bears on R2-08).
- **Donjon RP2350 laser fault injection (2026-09-18):** `DEBUGEN` overrides
  `CRIT1.DEBUG_DISABLE`, and a rescue reset halts before firmware re-applies its
  *soft* OTP lock. Relevant to any future claim that the OTP lock is a
  hardware boundary.
- The research agent explicitly **refused to assert** several widely-cited
  claims it could not verify (notably a `CVE-2024-4937` that does not exist in
  the CVE database, and unreachable Ledger/Trezor/OneKey audit pages). Those
  are not repeated here.

**Claims deliberately NOT made.** No fault injection, laser FI, power tearing or
QFN-60 TrustZone escape was performed — those need bench equipment and a
reprogrammable second stage. Their absence is a limitation, not a pass.

---

## 5. Exploit chain

The end-to-end chain an attacker would actually run, given one window of
physical access:

0. **Wipe first, with no access at all (R2-14).** One unauthenticated
   `authenticatorReset` from any host destroys the FIDO authenticator and its
   PIN. No physical access, no secret, no user interaction. Confirmed live.
1. **Dump.** Read the QSPI image over BOOTSEL (unauthenticated). Obtain the OTP
   row `0xE90` and the chip ID (the latter is also served over USB).
2. **Derive.** `HKDF(otp_row ‖ chipid)` → the v3 store key. No secret is
   required. *(R2-03)*
3. **Read.** Decrypt the v3 store. The FIDO keystore, the FIDO PIN verifier and
   the attestation scalar are all in cleartext after this step. *(R2-03)*
4. **Roll back.** Re-seal a store whose FIDO PIN 3-strike counter is zeroed, or
   simply present two forged CRC-valid **v2** slots and let the device migrate
   the attacker's data in. *(R2-02, R2-05)*
5. **Own.** Boot with attacker-chosen `fido.hkey`, `boot.entropy.v1` and
   keystore. FIDO assertions and the OpenPGP session are then under attacker
   control, with the owner's credentials silently replaced.
6. **Persist.** Because there is no signature-based boot (R2-11), the implant
   survives the victim's next reflash; and because the store MAC is
   self-keyed, the owner cannot detect the substitution by reading the store.

**Chain is confirmed through step 5** by execution against the shipped
`boot_decision_sealed` and `from_partition_image_reader` code paths.

---

## 6. Tooling notes (including two of my own bugs)

Recording these because both initially looked exactly like device faults, and
the same trap will bite the next assessor:

1. **pyscard returns `(data, sw1, sw2)`** on this host. An early version of
   `rt2lib.Ccid.raw()` unpacked two values; its blanket `except` converted the
   resulting `ValueError` into a fabricated `6F00`. That fabricated status was
   indistinguishable from a dead device and cost a long false-diagnosis detour
   — including the belief that pcscd was broken. **Never let an exception
   masquerade as a status word.**
2. **CTAPHID init packets set `TYPE_INIT` (0x80)**, CTAP opcodes ride inside a
   `CTAPHID_CBOR` (0x10) envelope, and on Linux `python-fido2` prepends a report
   ID byte to every hidraw write. Missing any of the three yields a device that
   looks mute. The U2F (CTAP1) path additionally takes a full APDU
   (`00 01 00 00 40 …`) and returns a **2-byte** SW, not a 1-byte CTAP status.

The final U2F results were cross-checked against `python-fido2`, an independent
implementation, precisely because the hand-rolled transport had already lied
once.

---

## 7. Operational damage and recovery

Two destructive events during this assessment, both disclosed in full.

### 7a. OpenPGP PIN1 and PIN3 are blocked (my scripting error)

**What I did wrong.** To test whether OpenPGP factory-default PINs were still
live, `attack1_pgp.py` looped over three PIN candidates for PW1 and three for
PW3. The *first* candidate was already rejected — the defaults are genuinely
dead — but the loop consumed the retry counter regardless. Both counters went
`3 → 2 → 1 → 0`.

**Current state.** `GET DATA 00C4` returns `007f7f7f000000`: **PW1 and PW3 are
blocked** (`00` = invalid). Key operations correctly refuse `6982`, so nothing
is exposed — but the OpenPGP card is unusable until it is reset.

**Fix applied.** `attack1_pgp.py` now sends exactly **one** candidate per role.
Additional guessing requires `RT2_ALLOW_PIN_GUESSING=1` and is intended for the
emulator only. A warning is in the file's docstring.

### 7b. The FIDO authenticator was wiped (in scope, hardware-confirmed)

`attack5_fido_reset.py` sent an unauthenticated `authenticatorReset` to confirm
finding R2-14. The device accepted it, and **all FIDO credentials and the FIDO
PIN are destroyed**. This was within the engagement's stated scope ("write the
storage and invalidate keys. wipe storage. corrupt storage"), and round 1 had
already wiped the OATH store with operator authorisation — but it is a real,
irreversible loss of device state and is recorded as such.

Post-reset `GET INFO` confirms it: `clientPin` is absent from the options map.

### Recovery

Both recover with the same operation, which is the operator's decision because
it destroys state:

- **Nuke + reflash**: `nuke_universal.uf2`, then the current
  `firmware/fapico2.uf2`. This clears the flash-resident store — a plain `.uf2`
  reflash does **not**, and would leave the OpenPGP card still blocked. Note
  the flashable artifact must be a `firmware/uf2gen.py` product; plain
  `elf2uf2-rs` output silently does nothing on RP2350 (US-924 D-phase finding).
- The current build additionally registers **OATH, OTP and PIV**, which is the
  only way to test the US-901/902/903 OATH fixes that round 1's Critical R1/R2
  left unverified (R2-01).

**pcscd was not at fault and does not need restarting.** `opensc-tool`
succeeded at the exact moment `pyscard` appeared to fail, which is what exposed
the arity bug in §6.

---

## 8. Remediation priorities

1. **Gate `authenticatorReset` (R2-14) — today, before anything else.** Require
   a valid `pinUvAuthParam` over a `pinUvAuthConfig` token (subCommand `0x0A`)
   per CTAP2.1 §6.1, and refuse when `clientPin` is set but unauthenticated.
   This is a small gate on a path that currently destroys the device's entire
   FIDO state from an unprivileged host.
2. **Close the migration window (R2-02).** Add a one-shot "already migrated"
   marker that is *itself* authenticated, or refuse `MigratePrimary` unless a
   provisioner-set bit says this device has never had a v3 store. Until then
   every fielded device is permanently attackable.
3. **Get a real secret into the key derivation (R2-03/04/06).** Either cut over
   to the CryptoCell-backed path, or use the RP2350 OTP key ladder to derive a
   wrapping key that requires write-lock enforcement the device cannot bypass.
   `chipid` is not a secret; entropy stored inside the sealed store is not a
   secret. Both current "hardenings" must be corrected in the comments as well
   as the code — they are currently documented as stronger than they are.
4. **Add a monotonic anti-rollback counter (R2-05, R2-15)** in an OTP row, and bind the
   FIDO PIN strike count to it.
5. **Add signature-based secure boot (R2-11)**, using RS-Key's in-tree approach.
6. **Make `check_attestation_gate.py` fail** on a re-added static key (R2-09);
   a gate that cannot fail should be treated as absent.
7. **Encrypt the PIN verifier (R2-07)** and bind the strike count to the monotonic counter. and raise the KDF cost.
8. **Zeroize on overwrite (R2-10)** and **recover rather than `fatal_boot` on a
   transient slot-write error (R2-08)**.
9. **Flash the current build and re-run the OATH suite**, closing the R2-01
   evidence gap.

---

## 9. Limitations

- **OATH and PIV were not testable** — the applets are absent from the flashed
  image (R2-01). Round-1 R1/R2 remain *unverified*, not fixed.
- **No bench-level physical attack was performed**: no voltage/clock glitching,
  laser fault injection, power tearing, or decapsulation. R2-11 and the
  errata-driven TrustZone and OTP findings are therefore *open risk*, not
  measured passes.
- **OpenPGP key operations could not be re-tested post-PIN-block.** The gates
  refused, which is the result that matters, but no successful signing path was
  exercised in round 2.
- **R2-14 is confirmed on hardware; R2-15/16/17 are not.** R2-15 (strike-counter
  rollback) was demonstrated in a proof of concept against the store code, not
  by reflashing the board. R2-16 and R2-17 are OATH-path findings that could
  not be exercised on hardware because the OATH applet is absent from this
  build (R2-01).
- **Attestation keys could not be re-extracted** from the current build; the
  R2-09 gate finding is a code-level result.

---

## 10. Reproduction

```
redteam/rt2lib.py                  CTAPHID + CCID transports (pyscard)
redteam/recon3.py                  full device fingerprint
redteam/attack1_pgp.py             OpenPGP auth boundary
redteam/attack2_fido.py            FIDO2 / U2F   (U2F leg cross-checked via python-fido2)
redteam/attack3_malleability.py    signature malleability, verified
redteam/attack4_state.py           applet / state confusion
redteam/attack5_fido_reset.py      DESTRUCTIVE: unauthenticated authenticatorReset
redteam/out2/                      all captured evidence + forged slot images
redteam/out2/scratch/forge_slots.py  the store-forgery proof of concept
```

Supporting analysis: `out2/AUDIT-store-crypto.md` (store crypto),
`out2/RESEARCH-wallet-vulns.md` (hardware-wallet attack research),
`out2/AUDIT-auth-gates.md` (authentication and consent gates, 20 PoCs),
`out2/RESEARCH-sibling-repos.md` (`pico-fido`, `pico-fido2`, `RS-Key`, `pico-hsm`).

**Warnings.**

- `attack1_pgp.py` — **fixed** to send one PIN candidate per role. Further
  guessing needs `RT2_ALLOW_PIN_GUESSING=1` and must stay on the emulator.
- `attack5_fido_reset.py` — **destroys the FIDO authenticator every time it
  runs.** It is the proof for R2-14; do not re-run it against a device holding
  real passkeys.

---

## 11. Post-reflash validation (2026-09-27, after operator nuke + reflash)

The device was nuked, reflashed with `firmware/fapico2.uf2`, and repopulated by
the operator: a FIDO PIN plus a real passkey on `token2.com`, new OpenPGP PW1/
PW2/PW3, and OpenPGP sign/encrypt/auth keys. Everything below was measured on
that live, populated device with **selection state verified before every
command**.

### 11.1 Round-1 Critical R1/R2 are CLOSED — first hardware proof

Round 1 rated the OATH session self-grant and the unauthenticated wipe
**Critical** and exploited both live. US-901/902/903 claimed them closed, but
the applet was absent from the build flashed during the first half of this
assessment, so the claim was untested. With OATH reachable:

| Probe (fresh unvalidated session) | SW | Verdict |
|---|---|---|
| `LIST` (INS A1 P1=00) | `6982` | gated |
| `PUT` credential | `6982` | gated |
| `CALC_ALL` (INS A4) | `6982` | gated |
| `CALCULATE` (INS A2) | `6982` | gated |
| **`RESET` 00 04 DE AD** (round 1 R1) | **`6982`** | **closed — no unauthenticated wipe** |
| `SEND REMAINING` (INS A5) | `6985` | presence-gated, no data leak (R2-16 not reproduced) |

The R2 measurement is the one that mattered and it is unambiguous: **40
consecutive (SELECT OATH → LIST) cycles on one session returned `6982` in
40/40 cases.** The session is never pre-validated and a failed VALIDATE never
grants it.

> **Correction to an earlier artifact.** `attack10_oath.py` printed
> "R2 REGRESSED". That verdict was a false positive from two of my own errors:
> the post-nuke store is empty, so `LIST` answers `9000` trivially, and an
> intermittent `6A82` on SELECT left the *wrong applet* selected, so I was
> measuring OpenPGP's response to OATH opcodes. `attack10b_oath_verify.py`
> fixes both confounds and is the authoritative result. The lesson is the one
> from §6: never conclude a gate is open from a success code alone — prove the
> applet was selected and that the data existed.

### 11.2 Applet inventory (post-reflash, corrected)

My first post-reflash sweep reported OATH/OTP/PIV as absent (`6A82`). That was
**wrong**. Re-tested in isolation and in every ordering, all three were in fact
reachable; the `6A82` observations were a transient window right after the
nuke, while OATH's keystore was being re-seeded. Steady-state, 45/45 selects
succeed.

| Applet | AID | Status |
|---|---|---|
| OpenPGP | `D27600012401` | present — `9000` |
| Management | `A000000527471117` | present — `9000`, version 1.0.0 |
| OATH | `A000000527210101` | present — `9000`, FCI reports 3.4.3 / "fapico2!" |
| OTP | `A000000527200101` | present — `9000` |
| **PIV** | `A000000308` | **absent — never registered** |

**R2-19 (Medium — feature gap).** `apps/piv` exists and compiles, but
`register_ccid_apps` (`apps/src/registry.rs:35-46`) only ever receives
`management, oath, otp, openpgp`. **PIV is never registered on the device**, so
it is unreachable at runtime despite the AID being defined
(`apps/piv/src/lib.rs:30`). Any PIV-dependent plan — including the cross-applet
`EF_VAULT_KEY 0xCE03` collision the sibling-repo audit flagged — is untestable
until this is wired up.

**R2-20 (Low — availability).** Immediately after a nuke/reflash, `SELECT OATH`
answers `6A82` for a short window while the OATH keystore is re-seeded, and a
host that does not retry sees an applet that is not really absent. The
dispatcher correctly leaves the previous applet selected, so commands in that
window are routed to the wrong applet.

### 11.3 Other surfaces on the populated device

- **FIDO2:** every unauthenticated probe refused — `getAssertion` without a
  token, with a forged token, `hmac-secret`, `credMgmt` enumerate, `credBlob`,
  `authenticatorConfig`, `getPinUvAuthTokenUsingPinWithPermissions`
  (all `PUAT_REQUIRED` / `NOT_ALLOWED` / `INVALID_PARAMETER`). CTAP1 assertion
  `0x01`. `pinRetries` read as **8**, untouched.
- **OpenPGP:** every key operation refused `6982` (`PSO:CDS`, `PSO:ENC`,
  `INTERNAL AUTHENTICATE`), `PUT DATA`/`GENERATE` `6D00`, `CHANGE REFERENCE`
  `6A86`. No data object leaks key-shaped material. All DOs readable pre-auth is
  per specification.
- **Vendor surfaces:** the vendor vault (0x41) is live but every subcommand
  except `STATUS` demands a `pinUvAuthParam` carrying `PERM_ACFG`/`PERM_CM`.
  The `dbg-log` drain channel (`0x42`) is **absent** — this is a release
  build, so the diagnostic ring US-922 added is not compiled in. No debug leak.
- **R2-14 still live.** The unauthenticated `authenticatorReset` was *not*
  re-triggered against the operator's new passkey, because doing so destroys
  it. The gate is unchanged in source and was confirmed on hardware earlier
  this session (§R2-14).

### 11.4 Why key exfiltration is blocked, precisely

The store key is `HKDF(otp_row_0xE90 ‖ chipid)` (`firmware/src/boot.rs:541`).
**Both inputs live in the RP2350 OTP peripheral, not in XIP flash.** Therefore:

- A **BOOTSEL flash dump** yields the *encrypted* v3 store and the firmware —
  enough for "retrieve the flashed firmware", but **not** enough to open it.
- Reading OTP row `0xE90` needs either an **SWD probe** (none attached; the
  project is explicitly SWD-less by constraint) or **code executing on the
  chip** that prints the row.
- Consequently, with only USB access, the FIDO PIN, the passkey private key,
  the OpenPGP private keys and the secure-store contents are **not
  exfiltrable** — not because the gates are strong, but because the last link
  (the OTP row) is not reachable from a host.

This is the honest boundary of round 2. Closing it needs a debug probe or a
one-shot on-device key-dump build, both of which are the operator's call.

---

## 12. SWD exfiltration chain — built and validated, awaiting the probe

The USB surface is exhausted: every gate refuses (§11). Key exfiltration
therefore reduces to the offline path, and the offline path is
**`flash image + OTP row 0xE90 + chip ID`**. The chain is now implemented and
**cryptographically validated**; only the two memory reads remain, and those
need the physical probe.

### 12.1 Why a flash dump alone is not enough

`derive_store_key` (`platform/src/store_v3.rs:98`) is
`HKDF-SHA256(salt="PS3F", ikm=otp_key_1‖chipid_be, info="store")`, and
`read_otp_key_1` (`firmware/src/boot.rs:516`) reads OTP rows **0xE90–0xE9F**
while `get_chipid()` reads rows **0x000–0x003**. On the RP2350 those live in
the **OTP peripheral** (`OTP_DATA_BASE = 0x40130000`, `rp235x-hal/src/otp.rs`),
**not in XIP flash**. A BOOTSEL `cp` of the flash yields the firmware and the
*encrypted* store; it cannot yield the key. This is the precise reason the
exfiltration objective cannot be met from a host alone.

### 12.2 The chain (redteam/swd_exfil.py)

1. `probe-rs` attaches to RP2350 and halts core 0.
2. Read the chip ID — OTP ECC rows 0–3, `0x40130000`, one 32-bit read per
   **two** rows (even→low 16, odd→high 16).
3. Read `otp_key_1` — rows 0xE90–0xE9F (eight 32-bit reads from
   `0x40130748`).
4. Read the secure partition — XIP `0x103F0000`, 256 KiB.
5. Derive `store_key` with the exact firmware schedule.
6. Parse the sealed v3 image
   (`[magic "PS3F"][count][nonce 12B]`, per entry `[kl][vl][ct][tag 16B]`,
   trailing CRC-32) and AES-256-GCM-decrypt each entry with
   `nonce_i = image_nonce[0:8] ‖ u32le(i)` and
   `AAD = magic ‖ count ‖ i ‖ kl ‖ vl ‖ image_nonce`.
7. Hand back `fido.keystore.v1`, `fido.hkey`, the PIN verifier, the boot
   entropy and the OpenPGP DEKs.

### 12.3 Validation — the decryptor is proven, not assumed

A *real* sealed v3 image was produced by the shipped firmware code
(`out2/scratch/poc/src/bin/dump_sealed.rs`, using `Rp2350SecureStore` and
`derive_store_key` directly), containing five records shaped like the ones the
device persists. The independent pure-Python decryptor in §12.2 recovered it
exactly:

```
key   = <redacted: PoC store key>
image = 458 B, magic b'PS3F', count = 5
  fido.keystore.v1   64 B   FAKE-FIDO-KEYSTORE-CBOR:credential-privk…
  fido.hkey          32 B
  boot.entropy.v1    32 B
  pin.state          89 B   verifier=deadbeef…|salt=0011…|iter=4096
  openpgp.deks       36 B   FAKE-OPENPGP-DEK-BLOB-ED25519-X25519
RECOVERED 5/5 entries — GROUND-TRUTH MATCH: True
```

So everything downstream of the two OTP reads is proven working. When the
probe is attached, the remaining work is two `probe-rs read` calls and the
derivation — not a debugging session.

### 12.4 What is still needed from the operator

`probe-rs` 0.32.0 is installed and `probe-rs list` runs; **it reports no probe
on USB**. Physical attach is required: SWCLK→GP2, SWDIO→GP3, GND→GND, and
NRST held or connected. No debug/diagnostic build is required — and none
exists, so the SWD path is the only route.

One caveat worth stating up front: the RP2350's OTP is in the secure domain,
and the wallet research flagged several RP2350 errata as relevant. *(Corrected
in §18: the specific "E3 = TrustZone escape on QFN-60" claim was wrong. If the
probe path ever needs it, the relevant risk is E24 — QSPI flash-swap plus a
glitch — not E3.)* `swd_exfil.py` detects that case explicitly and reports it
rather than silently producing a wrong key.

---

## 13. Fuzzing and protocol-level results

### 13.1 Parser fuzzing (cargo-fuzz 0.13.2) — clean

| Target | Runs | Crashes |
|---|---|---|
| `apdu_parse` (ISO7816 + U2F APDU parsers) | 37,681 | 0 |
| `ctap_cbor` | 2,290,093 | 0 |
| `ccid_reasm` (CCID message reassembly) | 11,606,743 | 0 |

No panic, no OOB, no new artifacts. The untrusted-input parsers that the
dispatcher, the OpenPGP app and the CTAPHID path all depend on survived
~13.9 M executions. Caveat: the `apdu_parse` target passes `|| true` as the
user-presence callback, so it exercises parsing only — it is **not** evidence
about the presence gate (which §3 tests directly on hardware).

### 13.2 CCID / ISO-7816 framing attacks — no divergence, no hang

`attack11_ccid_protocol.py` sent SELECT length and P1/P2 abuse, 3-byte
extended-length framing, Lc larger and smaller than the data actually sent,
`61xx`/GET RESPONSE abuse, unknown CLA/INS across the live selection, every
OpenPGP INS with a 255-byte body, and OATH length confusion. The whole batch
completed in **0.3 s** against a 90 s budget — no hang, no parser crash, no
time-based oracle. All rejections were clean (`6A86`, `6A80`, `6D00`, `6982`).
The device answered normally afterwards.

**R2-20 (Low — availability, corrected characterisation).** `SELECT OATH`
*can* transiently answer `6A82`, and when it does the dispatcher correctly
leaves the previous applet selected — so a host that does not check the
SELECT status will send OATH opcodes that get executed against **OpenPGP**.
Trigger characterised as **connection churn**: 50 back-to-back PC/SC connects
with no delay made the stack raise `SCARD_E_CONNECTION_RESET` (card was reset).
Under normal rates it does not reproduce — 30/30 interleaved selects, 24/24
fresh connects, 45/45 in an earlier sweep. The practical risk is a client that
assumes `6A82` means "OATH is absent" and then mis-routes.

---

## 14. Shipped-binary secret sweep + the OpenPGP default-PIN posture

### 14.1 Round-1 R4 (static attestation identity) — CONFIRMED FIXED

Round 1 extracted the attestation private key `<redacted: round-1 attestation scalar>` from the shipped
image. Against the **current** build:

* the round-1 scalar has **0 byte occurrences** in `firmware/fapico2.elf`;
* there is no `include_bytes!` of an attestation key or cert
  (`apps/fido/src/attestation.rs` documents the removal in prose only).

A full sweep of the 1.46 MB image found **no ASN.1/DER structures, no PEM
markers, and no other high-entropy key-sized blob**. The only `private_key` /
`secret_key` strings are Rust symbol names from `p256`, `elliptic_curve`,
`pkcs1` and `trussed` — no material. R4 and R2-09 are closed on the shipped
artifact. (R2-09's *CI gate* weakness — `check_attestation_gate.py` passing on
a tree with a re-added static key — remains open as a process finding; the
shipped binary is clean even though the gate would not catch a regression.)

### 14.2 R2-21 (Medium) — factory-default OpenPGP PINs are still in every image

`vendor/opcard/src/state.rs:34,36` still define
`DEFAULT_USER_PIN = "123456"` and `DEFAULT_ADMIN_PIN = "12345678"`, and both
literal strings are present in the shipped ELF. A factory-fresh fapico2
therefore has **working, publicly-known PINs**; the entire defence is US-912's
gate:

```rust
pub fn factory_defaults_in_force(&self) -> bool {
    self.pw1_changed != Some(true) || self.pw3_changed != Some(true)
}
```

which is consulted at **five** call sites — `command.rs:500,521` and
`pso.rs:79,292,379` (PSO:CMS / CDS / ENC and the terminate path) — and
**fails closed** when a flag is `None`.

Assessment: the gate is correctly designed and broadly placed, and the
personalised card under test had both PINs changed, so key operations behaved
normally. But the *security argument* rests entirely on this one predicate.
A single missing call site anywhere in the PSO / GENERATE / PUT-DATA surface
re-opens round 1's R5 wholesale. Two cheap hardening steps would remove the
dependence: (a) refuse to leave the factory PINs live — force a change during
provisioning rather than at first use; (b) add a gate test that asserts *every*
key-operating handler consults `factory_defaults_in_force()`.

I could not test the gate's behaviour on a genuinely factory-fresh card
without destroying the operator's newly provisioned keys, so the gate is
**verified by construction and code reading, not by execution**.

### 14.3 R2-22 (Low) — boot-time default-PIN VERIFY, with a destructive side effect

`probe_default_pin` (`state.rs:1251-1275`) runs during `load()` on snapshots
that predate the changed-flags, to derive them. It:

1. refuses unless `pin_retries >= 2` (fails closed);
2. sends a **live `VERIFY` with the factory default PIN** for PW1 and again for
   PW3;
3. on success, if a PIN key object exists, calls `client.delete(key)` —
   **silently destroying that key at every boot** — and records
   `changed = false`; if no key exists it records `changed = true`.

Impact is bounded (legacy snapshots only, retries guarded, fails closed on
error), but it means a card that is *still on the default PIN and holding a
key* loses that key automatically, and that the default PIN is exercised on
the wire at boot. Worth making the `delete()` explicit and logged rather than
a silent side effect of a probe.

### 14.4 SWD probe status

`probe-rs` 0.32.0 is installed and working; `probe-rs list` reports **no probe
on the host USB** (checked repeatedly — no new USB, serial or hidraw node).
`redteam/60-probe-rs.rules` is written and ready for
`sudo cp 60-probe-rs.rules /etc/udev/rules.d/ && sudo udevadm control
--reload-rules`, should the probe enumerate but be permission-blocked. The
user is already in `plugdev` and `dialout`. The exfiltration chain itself is
built and **validated 5/5 against a real firmware-sealed v3 image** (§12.3);
attaching the probe reduces the task to two memory reads.

---

## 15. BOOTSEL flash read-back — firmware recovered, and a correction to R2-03

The operator put the board in BOOTSEL. The RP2350 mass-storage interface
exposes no block files, but `picotool` (already present at
`~/.pico-sdk/picotool/2.3.0/`) reads flash and OTP over PICOBOOT. No probe was
needed.

### 15.1 The flashed firmware is recovered and verified

```
picotool save -a flash_all.bin
  size   : 4,194,304 bytes (0x400000)
  sha256 : 959e17987ef0bd0a656b98ae4e7e4d4ef75f35a7b900252e63c478967b48001a
```

Re-extracting the payload from `firmware/fapico2.uf2` (the file the operator
flashed) and content-matching it against the dump: **364/364 distinct 512-byte
chunks matched (100.0%)**. The device is running exactly the shipped build.
*Objective item "retrieve the flashed firmware" — done, and verified rather
than assumed.*

### 15.2 The chip ID — public, recovered in one command

```
picotool otp get -e -n OTP_DATA_CHIPID0 ... OTP_DATA_CHIPID3
  0x0000 CHIPID0 = 0xce05
  0x0001 CHIPID1 = 0x8aa9
  0x0002 CHIPID2 = 0x2f52
  0x0003 CHIPID3 = 0x60da
  => chip ID = 0xCE058AA92F5260DA
```

Consistent with the datasheet: this is a *public* identifier, explicitly
readable from the USB bootloader. Its exposure is by design.

### 15.3 **R2-03 is materially mis-stated — CORRECTION**

The store-crypto audit rated this **High**: "Row `0xE90` gets only a *write*
lock (`SWLOCK.NSEC = READ_ONLY`); the chipid is already emitted over USB...
No OTP key-ladder / CryptoCell secret is used anywhere. PoC recovers every
secret." `firmware/src/boot.rs:534-536` repeats it: the row "is still
**readable from any code** (only the software write lock is applied — no
read-protect)".

Measured on the real part, that is wrong about the external case:

```
picotool otp get -e -n 0xe80   -> ERROR: permission failure
picotool otp get -e -n 0xe88   -> ERROR: permission failure
picotool otp get -e -n 0xe8f   -> ERROR: permission failure
picotool otp get -e -n 0xe90   -> ERROR: permission failure
picotool otp get -e -n 0x004   -> VALUE 0x800f      (control: readable)
picotool otp get -e -n 0x100   -> VALUE 0x0000      (control: readable)
picotool otp get -e -n 0xf00   -> VALUE 0x0000      (control: readable)
```

**OTP page 58 (rows `0xE80`–`0xEBF`), which contains the fapico2 key row
`0xE90`, is hardware read-protected**, and the RP2350 bootrom enforces it over
PICOBOOT. Surrounding pages read normally, so this is a deliberate per-page
lock, not a blanket one.

Consequences:

* **An attacker holding only a flash dump cannot open the store.** The
  `HKDF(otp_row ‖ chipid)` key is out of reach: one input is public by design,
  the other is denied by the silicon. The audit's "PoC recovers every secret
  from `(otp_row, chipid)`" was demonstrated against *synthetic* inputs, not a
  real part.
* **R2-03 drops from High to Low** as a standalone finding.
* **The residual is R2-11, not R2-03.** The row *is* readable by code running
  on the chip — the firmware's own `read_otp_key_1` does precisely that at
  every boot. And unsigned BOOTSEL boot (R2-11) lets an attacker put such code
  there. So the real chain is **flash dump + malicious reflash → read the row →
  derive the key → decrypt**, which is materially harder than a dump alone, and
  is bounded by the secure partition's own read protection only for the
  *dumping* half.
* The code comment at `boot.rs:534-536` is now actively misleading and should
  be corrected — it describes the on-chip case while sitting in a document that
  justifies the crypto against a physical attacker.

### 15.4 The sealed store, as read from the device

```
offset 0x3F0000 : magic "PS3F", count = 7, image nonce = 89893a6878d75703c72b058d
entries         : 7, 1,100 bytes of AES-256-GCM ciphertext
key lengths     : 15, 18, 29, 23, 9, 21, 21
value lengths   : 32, 32, 308, 32, 32, 490, 38
trailing CRC-32 : stored 0x7C8AC0CB, recomputed 0x7C8AC0CB -> MATCH
```

Candidate keys tested and **rejected** (AES-256-GCM tag mismatch on entry 0):
`otp_key_1 = 00×32` (the "never provisioned" case — worth testing, since
`derive_store_key` has no all-zero guard while `derive_kbase` does),
`0xA5×32`, `0xFF×32`. The store is genuinely sealed against everything
reachable from the host.

**R2-23 (Low — metadata disclosure).** The sealed image leaks its *shape*
without decryption: the number of records, and each record's **key-name length
and value length**, are in cleartext in the header. The lengths above imply a
32-byte key record (3 of them), a ~308-byte and a ~490-byte blob (the FIDO
keystore and the OpenPGP application state), and a 38-byte record. That is
enough to tell an attacker which key generations succeeded and roughly how much
data is held, before they hold any key. Storing lengths in the clear is a
deliberate trade for a streaming parser, but it should be acknowledged.

### 15.5 What was and was not achieved by the BOOTSEL session

| Objective | Result |
|---|---|
| Retrieve the flashed firmware | **Achieved** — 4 MB, sha256 recorded, 100% match to the shipped UF2 |
| Retrieve the keys from the secure store | **Not achieved** — store retrieved as ciphertext; key blocked by OTP read protection |
| Exfiltrate FIDO PIN / keys | **Not achieved** — see §11.3, §12.1 |
| Exfiltrate OpenPGP PIN / keys | **Not achieved** — same |
| Exfiltrate secure-storage information | **Partially** — record shapes and counts (§15.4) |
| Write / wipe / invalidate | **Achieved** (R2-14, §2 R2-14) |
| Malleability | **Achieved** for ES256 (§2 R2-12) |

---

## 16. Full key exfiltration — the store opened, 7/7 records

**This closes the exfiltration objective.** The chain in §12, executed end to
end against the live device.

### 16.1 The chain

1. **BOOTSEL read** — `picotool save -a` → the full 4 MB flash image, verified
   100% against the shipped UF2 (§15.1).
2. **OTP key row** — PICOBOOT refuses it ("permission failure", §15.3), so the
   read was performed **by code the attacker supplies**.
3. **Firmware substitution** — no signature check, so the board accepted an
   arbitrary 9.7 KB ARM-Secure image (`redteam/keydump-rs/`, packaged with
   fapico2's own `uf2gen.py`). It reads OTP rows `0xE90..0xE9F` and the chip
   ID, and writes 48 bytes to a scratch sector at XIP `0x10008000`. It never
   writes the OTP and never touches `0x103F0000`.
4. **BOOTSEL read-back** — `picotool save -r 0x10008000 0x10008200` → the key.
5. **Key derivation** — `HKDF-SHA256(salt="PS3F", ikm=otp_key_1‖chipid, info="store")`.
6. **Store decrypted** — 7/7 entries, every AES-256-GCM tag verified.

### 16.2 What came out

```
otp_key_1  <redacted: OTP key row>
chipid     <redacted: chip id>
store_key  <redacted: derived store key>
```

| Store record | Size | Extracted |
|---|---|---|
| `boot.entropy.v1` | 32 B | boot entropy seed |
| `boot.fwmanifest.v1` | 32 B | firmware-manifest hash (the US-919 anchor) |
| `fido.hkey` | 32 B | **FIDO master key** |
| `fido.attestation.v1.key` | 32 B | **Ed25519 attestation private scalar** |
| `fido.attestation.v1.cert.p000` | 308 B | attestation certificate |
| `fido.keystore.v1.p000` | 490 B | **FIDO keystore** (below) |
| `oath.keystore.v1.p100` | 38 B | **OATH keystore** — TOTP secret `<redacted: TOTP secret>` for `rt2probe` |

From the FIDO keystore, after unsealing the US-911 field encryption:

| Secret | Value |
|---|---|
| `device_random` | `<redacted: device_random>` |
| **passkey private key (ES256 scalar)** | `<redacted: passkey private scalar>` |
| credential_id | `<redacted: credential id>` |
| RP ID / user | `www.token2.com` / <redacted: user handle> |
| `pin_salt` | `<redacted: pin_salt>` |
| `pin_verifier` | `<redacted: pin_verifier>` |
| `pin_iter` / retries | 4096 / **8 (full budget)** |

### 16.3 The private key is verified, not asserted

Deriving the public point from the extracted scalar reproduces **both**
coordinates stored in the credential record, byte for byte:

```
private  <redacted>
  -> x   805ebf835a1dd6f0f82afae87e89eb42cc6360d9400cb91b9dc819bc5430ba4d
  -> y   64c0ad8aa540b9354b8405a651625894dee399986ddd4e9564d2f53878fe8563
  x present verbatim in the keystore at +0xDB
  y present verbatim in the keystore at +0xFE
```

**The `token2.com` passkey can now be asserted without the device, without
the PIN, and without a touch.** The same applies to every U2F/CTAP1 credential
the device can derive, because `device_random` is the root that
`stateless::master_from_device_random` expands.

### 16.4 R2-24 (Medium) — the field subkey derivation is not what the code documents

`snapshot_crypt::field_key()` documents
`HKDF(ikm = store_key, info = "fapico2 fido snapshot fields v1")` and the
module doc calls it "Derived OUTSIDE the snapshot … so sealing is not
circular." The device's stored fields did **not** open with that derivation —
they open with **`store_key` used directly as the AES-256-GCM key**, with the
documented AAD. Observed on the live artefact, not inferred.

Consequence: the intended domain separation between the store layer and the
snapshot-field layer is not in force, so a single recovered key opens both.
`store_key` and the field key are the same secret. Either the call site passes
the store key where the subkey is expected, or the device path bypasses
`field_key()`; either way the comment at `snapshot_crypt.rs:180-187` does not
describe the shipped behaviour and should be corrected.

### 16.5 FIDO PIN

The PIN is **offline-crackable** — the salt, the stretched verifier and the
iteration count are all in the exfiltrated keystore, and the construction
(`crypto.rs:442-457`) is 4096 iterated SHA-256 with no memory hardness. The
8-strike on-device budget is irrelevant once the store is in hand. A crack run
is in progress; a PIN of ≤6 digits is exhausted in minutes on 20 cores, and
the practical statement is that any PIN the owner chose is recoverable.

### 16.6 Revised scorecard

| Objective item | Result |
|---|---|
| Exfiltrate the FIDO **keys** | **Achieved** — `device_random`, `fido.hkey`, the passkey private key, the attestation key |
| Exfiltrate the FIDO **PIN** | **Achieved as a capability** — verifier + salt + iterations recovered; cracking is a compute problem, not a barrier |
| Exfiltrate OpenPGP PIN / keys | **Partial** — the store held no OpenPGP record in this build; OpenPGP keys live in the trussed backend, whose DEK is not in this partition |
| Exfiltrate secure-storage information | **Achieved** — 7/7 records decrypted |
| Retrieve the flashed firmware | **Achieved** — 4 MB, 100% verified |
| Retrieve keys from the secure store | **Achieved** — see §16.2 |
| Write / wipe / invalidate | **Achieved** — R2-14 unauthenticated `authenticatorReset` |
| Malleability | **Achieved** — ES256 (§R2-12); the private key above also makes a *better* malleability demo possible |

---

## 17. Hardware analysis — there is no CryptoCell, and why the store is not one

Follow-up research after §16. The premise behind the project's own remediation
plan is **wrong for this part**, and the correction is load-bearing.

### 17.1 The RP2350 has no CryptoCell

`pico-sdk/src/rp2350/hardware_regs/include/hardware/regs/addressmap.h:71-75`
is the whole peripheral list that matters here:

```
BOOTRAM_BASE  0x400e0000      <- NOT a CryptoCell; this is boot scratch RAM
ROSC_BASE     0x400e8000
TRNG_BASE     0x400f0000      <- randomness only, stores nothing
SHA256_BASE   0x400f8000      <- accelerator only, stores nothing
```

The RP2350's crypto hardware is a **TRNG** and a **SHA-256 accelerator**.
Neither holds key material. **The OTP is the only silicon secret store on the
chip.**

This invalidates:
* fapico2's documented mitigation — `boot.rs:760` and
  `security-residual-risk.md` R2 both name a "CryptoCell secure-arena key"
  (US-924) as the fix. That hardware does not exist on the RP2350.
* the suggestion in §16 that a vault could be "encrypted to a CryptoCell key
  that never leaves the silicon."

The `crypto_se` / `psa_crypto_se` symbols in the C trees
(`pico-fido`, `pico-fido2`, `pico-openpgp`) are mbedTLS's generic,
vendor-neutral Secure Element interface **with no RP2350 backend** — referenced,
not implemented.

### 17.2 Why fapico2's key row was readable — the exact mechanism

`SWLOCK` (`rp-pac-7.0.0/src/rp235x/otp/regs.rs:1063-1090`) is a 32-bit
register with **two independent 2-bit fields**:

| bits | field | governs |
|---|---|---|
| 1:0 | `sec` | the **Secure** domain — *"read-only to Non-secure code"* |
| 3:2 | `nsec` | the **Non-secure** domain |

Each takes `READ_WRITE` / `READ_ONLY` / `_RESERVED_2` / `INACCESSIBLE`, and
**writes are OR'd with the current value** — locks can only strengthen, never
weaken. That part of the design is sound.

`firmware/src/boot.rs:1040-1046` does:

```rust
if swlock.read().nsec() == SwLockNsec::READ_ONLY { return; }
swlock.modify(|v| v.set_nsec(SwLockNsec::READ_ONLY));
```

It sets **`nsec` only, and never touches `sec`** — so the Secure-domain lock on
the key row stays at its default `READ_WRITE`. The row is write-locked against
non-secure code and fully open to secure code.

**Measured, not inferred:** the keydump image built in §16 is an
`rp2350-arm-s` binary — it runs in the **Secure** domain — and it read rows
0xE90–0xE9F without difficulty. That is a direct demonstration that `sec` is
not `INACCESSIBLE` on this board.

### 17.3 The consequence — and why `INACCESSIBLE` is not the fix either

It is tempting to read §17.2 as "just set `sec = INACCESSIBLE`". That does
not work, and the reason is the whole point:

> **A secret that running firmware must read can never be protected, by any
> OTP permission bit, from a different piece of firmware running in the same
> security domain.**

The RP2350 permission model has two software domains (Secure, Non-secure) plus
the bootrom. There is no software-writable bit meaning "CRTM only" — `SWLOCK`
carries only `sec` and `nsec`. So:

| fapico2 runs as | key row lock | can fapico2 read it? | can a substituted image read it? |
|---|---|---|---|
| Secure | `sec=INACCESSIBLE` | **no** | no — but the firmware is broken |
| Secure | `sec=READ_ONLY` (today) | yes | **yes — §16** |
| Non-secure | `nsec=INACCESSIBLE` | **no** | no — but the firmware is broken |
| Non-secure | `nsec=READ_ONLY` (today) | yes | yes, if it can also run non-secure |

Every configuration either breaks the product or leaves it open. **The
permission model cannot express the security property the product needs**, so
the fix has to come from somewhere other than the OTP access bits.

### 17.4 What actually can close it: bootrom-enforced boot encryption

`picotool encrypt` (present at `~/.pico-sdk/picotool/2.3.0/`) encrypts the
program with an AES key held in an OTP page:

```
picotool encrypt ... <aes_key> <iv_salt> [<signing_key>]
                     --otp-key-page <page>     (default 29; IV salt on the next page)
                     --sign
```

This is qualitatively different from the v3 store sealing, because the attacker
cannot produce a bootable image at all. An unsigned image loads today; an
*unencrypted* one will not load once boot encryption is enabled, because the
bootrom holds the decryption key in an OTP page the attacker cannot read. That
converts firmware substitution from trivial into infeasible **without needing
the OTP permission bits to protect a runtime secret** — the key is never given
to firmware at all; only the bootrom uses it.

The related signed path, if signature verification is wanted:

```
picotool seal --sign <key.pem> <otp.json>        # sign the image, emit OTP config
picotool otp permissions <otp.json> --sign <key>  # program the access-control map
```

Note the second command **signs the permission map itself**, so the trust
anchor and the permissions that protect it are covered by the same signature.

**On this board, none of it is provisioned:** the OTP dump shows 24 non-zero
rows out of 4096, with the default boot-key page (29) and its IV salt (28)
both empty.

### 17.5 Revised remediation for this part

1. **Stop planning around a CryptoCell.** It is not on the RP2350. Re-scope
   US-924 against boot encryption + signed boot, or move to a part that has a
   real key store.
2. **Enable bootrom boot encryption**, with the key in a page the bootrom
   reads. This is the only control on this silicon that survives a flash dump
   plus unsigned firmware.
3. **Adopt signed boot** if the bootrom verifies signatures natively — research
   in flight; RS-Key carries a provisioning ritual but the C trees' signed
   boot uses one hardcoded vendor-wide key, so neither is a clean model.
4. **Keep the OTP page at `sec = READ_ONLY` (not READ_WRITE)** as defence in
   depth against a firmware bug that writes it — but document clearly that
   this is *not* a confidentiality control.
5. **Correct the documentation.** `boot.rs:760` and
   `security-residual-risk.md` R2 currently name nonexistent hardware as the
   remediation, which will keep producing plans against a part that cannot
   deliver them.

---

## 18. Errata and boot-chain — corrections and what is actually provisionable

Follow-up to §17, cross-checking the RP2350 datasheet (Appendix E) rather than
the secondary research. **Two claims in earlier sections were wrong and are
corrected here.**

### 18.1 CORRECTION — E3 is not a TrustZone escape

Sections 4 and 12.4 repeated "E3 is a TrustZone escape specific to QFN-60
(the Pico 2)". Verified against the datasheet: **E3 is a `GPIO_NSMASK` →
`PADS_BANK0` register mis-mapping** — a GPIO aliasing bug, not a TrustZone
escape and not specific to that package for security purposes. The claim
should not have been carried from secondary research without checking.

### 18.2 The errata that actually matter here

| Erratum | What it is | Workaround |
|---|---|---|
| **E16** | `USB_OTP_VDD` corruption can **revert the effects of `CRIT1.SECURE_BOOT_ENABLE` and `DEBUG_DISABLE`** | **None** |
| **E24** | QSPI flash-swap plus a glitch achieves **unsigned code execution on a secured device** | **None** (A2 + A3) |
| E18 | affects A2 and A3 | — |
| E17, E28 | **never fixed in silicon**; E28: *"Software shouldn't rely on OTP access keys for protection of lock words"* | n/a |

E16 is the most uncomfortable entry: a fault can undo secure-boot enablement
and debug disablement. Both E16 and E24 have **no workaround**, so any
boot-security story on this part is probabilistic, not absolute. That is a
reason to prefer the bootrom's signed check over anything software-side, and a
reason not to over-claim what boot hardening can deliver.

### 18.3 Signed secure boot IS a bootrom primitive — but encrypted boot is not

This corrects §17.4, which was too strong.

* **Signed secure boot is native to the bootrom** — SHA-256 + secp256k1, with
  the signing-key fingerprint in **OTP page 2** and anti-rollback support. This
  is the control that matters and it is a real one.
* **Encrypted boot is not.** The bootrom verifies a *signed, cleartext software
  decryption stage* which then holds the key. RPi's own datasheet is explicit:
  *"The bootrom handles only public key cryptography… this reasoning does not
  apply to the decryption stage."* The reference stage uses `OTP_KEY_PAGE 29`,
  AES-256-CTR (**unauthenticated**), and documents itself as not secure
  against side channels.

So the correct statement is narrower than §17.4's: **boot encryption is only
as strong as the signature on its decryption stage**, and the key's protection
is the signature chain, not the OTP page. Encrypted boot is a confidentiality
feature, not a substitute for signed boot.

### 18.4 What is actually provisioned on this board

From the OTP image captured in §15:

```
non-zero OTP rows : 24 of 4096, confined to pages 0, 62, 63
page 2  (signed-boot key fingerprint) : all zero   <- signed boot NOT enabled
page 28 (boot-enc IV salt)              : all zero
page 29 (boot-enc AES key)              : all zero
```

Pages 0/62/63 are the device's own identity and lock-word region. **Nothing
security-relevant is provisioned**: no signed boot, no boot encryption, no
glitch-detector enablement. Every hardware control discussed above is
currently inert on this device.

### 18.5 Revised, honest remediation order

1. **Read the silicon revision from the device first.** E24 is open on A2/A3 and
   fixed in A4; nothing above can be finalised without knowing which you have.
   *(The dump has no SYSINFO block, so this could not be determined offline.)*
2. **Enable signed secure boot.** It is the one control the bootrom enforces
   natively. It is a **one-way fuse** — test on a spare board first.
3. **Do not treat encrypted boot as a substitute.** Per §18.3 it inherits the
   decryption stage's signature as its only real strength.
4. **Boot to SRAM, not XIP.** RPi explicitly declines to recommend signed XIP
   because the check-then-execute window is what E24 abuses.
5. **Disable BOOTSEL** (E20/E21) to remove the cheap path to the OTP.
6. **Keep the key row at `sec = READ_ONLY`** as defence in depth, and document
   that it is *not* a confidentiality control (§17.3).
7. **Enable the glitch detector** and use the recommended countermeasures —
   while remembering E16 can revert `CRIT1` anyway.
8. **Keep the signing key fleet-wide with a public fingerprint in page 2** (4
   slots, revocable), but treat one leak as fleet-wide compromise and batch
   provisioning accordingly. Do **not** make the *root data* key fleet-wide:
   the OTP is imageable, so a shared root would make per-device chaff pointless.
9. **Drop CryptoCell from the plan entirely** (§17.1) and re-scope US-924.

### 18.6 Net position

The hardening story on this part is: **one strong control (bootrom signed
boot), several inert-by-default ones, and a documented set of silicon faults
with no workaround.** That is a defensible design if signed boot is enabled and
BOOTSEL is closed — but it is a *hardware* boundary, and the software layers
above it (the v3 store, the OTP row, the field encryption) are, as §16 proved,
defences that an attacker with a substituted image walks straight through.

---

## 19. Silicon revision measured — and two honest caveats

The gating item from §18.5(1), resolved on the device by extending the
keydump image to read the bootrom's SYSINFO block at `0x40000000`.

### 19.1 The read

```
SYSINFO chip_id   = 0x20004927   (JEP-106)
  REVISION    [31:28] = 2
  PART        [27:12] = 0x0004   -> RP2350
  MANUFACTURER[11:1]  = 0x493    -> Raspberry Pi
  STOP_BIT    [0]     = 1        -> identifier defined
package_sel         = 0
platform            = 0
gitref_rp2350       = 0x5A09D5A2
```

The bit-field layout decodes exactly as the datasheet documents, and
`PART=0x004` / `MANUFACTURER=0x493` independently confirm this is a real
RP2350 rather than a garbage read. The chip ID and the OTP key row came back
byte-identical to the first run, so the capture is self-consistent.

**The part reports JEDEC REVISION = 2.**

### 19.2 Caveat 1 — revision 2 is not, by itself, an A2/A3 verdict

The SDK's `sysinfo.h` documents the JEP-106 layout with `REVISION (0x3)` as its
worked example, and this part reports `2`. **I am not going to assert that
"2 = A2 silicon"** — the JEDEC revision field and the A2/A3/A4 silicon
revision numbering are different counters, and I have not verified the mapping
against the datasheet's revision table. What is established:

* the bootrom reports REVISION 2 on this board;
* the E24 "QSPI flash-swap achieves unsigned code execution" erratum applies
  to silicon revisions A2 and A3 and is fixed in A4;
* **so the open question — whether E24 is live on *this* part — is narrowed
  but not closed by this reading.** It needs the datasheet revision table to
  map REVISION 2 onto A2/A3/A4.

I flagged this as item (1) precisely because it had to be read off the part
rather than inferred; I should not now paper over the second half of the
inference.

### 19.3 Caveat 2 — a package disagreement worth resolving

SYSINFO `package_sel = 0`, which the datasheet defines as **QFN80**.
`picotool info -d` on the same device reports **QFN60**.

One of the two is reading a field the other ignores. The likely reading is
that picotool derives the package from a different source (OTP
`USER_PACKAGE_SEL`, or the part number) while SYSINFO carries a
manufacturing-time field that may be unset. I did not chase it, because it
does not change the security conclusion. It is recorded because the
**E3 erratum is package-specific to QFN-60**, so if this board is genuinely
QFN80 the erratum set that applies to it is smaller — and that should be
settled before the erratum list in §18.2 is treated as complete.

### 19.4 The CRC line in the capture — a false alarm, stated as such

The reader reports `crc stored = 0xFD97CCC0 calc = 0x0268333F -> MISMATCH`.
That is **not** a capture failure. The record layout has a 10-byte magic
followed by a 6-byte pad (`o += 16` in the image vs `o += 10` in the parser),
so the two compute the CRC over different prefixes. The authoritative
integrity evidence is that **all 7 store records decrypted with valid
AES-256-GCM tags** — a 128-bit authentication check, not a 32-bit CRC. The
CRC field is a redundant, mis-offset check and should be treated as
disregarded, not as a warning.

### 19.5 Position after this measurement

Unchanged by the revision reading, and worth restating plainly:

* **Nothing is provisioned.** CRIT0/CRIT1/BOOT_FLAGS0/BOOT_FLAGS1 all read
  zero; page 2 (signed-boot fingerprint), 28 (IV salt) and 29 (boot key) are
  all zero; `picotool info -m` independently says `extra security: not
  enabled`. The board runs with no boot chain at all.
* **The exfiltration chain of §16 still works** — this run re-derives the same
  store key and opens the same 7 records, which is a useful reproducibility
  check on the whole result.
* The remaining decisions — enable signed secure boot, close BOOTSEL, decide
  whether E24's exposure changes your risk tolerance — do not depend on the
  revision number. The single most valuable action, provisioning signed boot,
  is the same either way.

---

## 20. The "permanent freeze" — RESOLVED: a TRNG start/wait ordering defect

**Status: root cause FOUND and FIXED. It was a TRNG wedge, as suspected below —
and it is now proven rather than merely the best-supported cause.** Fixed on
`feat/rskey-adopt` in commits `7e6ffd1` (the red test) and `4d9746b` (the fix).

**The defect.** `Rp2350Probe::probe_bytes()` called `await_ready()` — the bounded
wait for a validated entropy block — *before* anything enabled the TRNG ring
oscillator. The enable (`RND_SOURCE_ENABLE.RND_SRC_EN = 1`) lived only inside
`read_into()`, which is by construction reached only *after* the wait succeeds.
So the very first wait could never succeed: with the source disabled the
peripheral reports `InvalidEhr` indefinitely, the 20 ms budget expires, and the
draw returns `Err(TrngError::Stalled)`. `init_drbg()` treats that refusal as
fatal by design, so the device halted at `fatal_boot("drbg: seed refused")`
**before USB is ever constructed** — solid LED, no enumeration, unrecoverable by
reflash because the failure is in the boot path, not the store.

**The register evidence** (read over SWD with the core parked), which is what
makes it proven rather than plausible:

| register | address | value | meaning |
|---|---|---|---|
| `RND_SOURCE_ENABLE` | `0x400F_012C` | `0x00000000` | **the source was never enabled** |
| `TRNG_CONFIG` | `0x400F_010C` | `0x00000001` | configured correctly (health tests on) |
| `SAMPLE_CNT1` | `0x400F_0130` | `0x00000019` | 25 — the budget's calibration, correctly applied |
| `TRNG_VALID` (EHR) | `0x400F_0110` | `0x00000000` | no entropy block was ever produced |
| `RNG_ISR` | `0x400F_0104` | `0x00000001` | bit 0, **not** `AUTOCORR_ERR` (bit 2) — no health-test failure |
| `TRNG_BUSY` | `0x400F_01B8` | `0x00000000` | not generating |

The configuration was right and the oscillator was simply never switched on.
That is an ordering defect, not a tolerance problem — which is why it survived a
host suite of 1244 tests, 22 gates, and a 23/23 mutation harness. All of those
exercise the *host* seam, where the device `Rp2350Probe` does not exist.

**The fix** enables the source before the first wait, and the regression test
asserts the *ordering* of register operations (first `SourceEnable` precedes
first `Status`) rather than only the outcome. It was red on the pre-fix tree:
9 failing assertions.

**Verification on hardware.** The tip flashes over BOOTSEL and enumerates in
**4 s** as `fa20:0002`; `getInfo` passes strict canonical CBOR; `getAssertion`
returns `0x3B UP_REQUIRED` with no touch, which is correct fail-closed behaviour.

### 20.0 A measurement trap that cost most of this investigation

**A connected debug probe breaks OTP reads on this board, and the resulting
failure looks exactly like the hang being hunted.** With `probe-rs` attached,
`OTP_DATA_RAW` reads return `0xFFFFFFFF`; `embassy_rp::otp::read_raw_word` maps
exactly that value to `Err(InvalidPermissions)`; `read_otp_key_1()` treats any
`Err` as "key absent"; `derive_boot_store_key()` then calls
`fatal_boot("secure partition: OTP key row unavailable")` — again before USB.
Detached, the same row reads fine and the firmware boots in 4 s.

So **every** hardware measurement taken through `probe-rs run` during this
investigation — *including measurements of the known-good baseline commit, which
boots perfectly* — produced a false "the OTP key row is unreadable" failure.
Validate fapico2 **detached**; use the probe to read, never to run. This is
recorded in the workbench `AGENTS.md`.

Related, and worth stating because it is easy to mistake for a cause:
`SW_LOCK[58]` reads `0x0000000F` (INACCESSIBLE in both domains) for the page
holding the C key row, and that value comes from the OTP lock pages at reset.
`otp_hw_write_lock_key_row()` is **runtime-only** and does not survive a reset,
so it neither burns anything nor protects anything (see D-14).

### 20.0.1 The history below is kept because the method is the lesson

The first version of this section blamed a slow boot; the second blamed a
corrupt OATH keystore stream; **both were wrong**, and both were concluded from a
single observation of an intermittent failure. The retractions stay.

### 20.1 The symptom

Reported as: the device stops booting, solid LED, no USB, no recovery by
reflash, and — the detail that drove the whole investigation — it appeared to
start after OATH was used and to persist through nukes.

### 20.2 What was actually happening

The device is not frozen. Boot times measured on this board:

| condition | time |
|---|---|
| steady state, warm power cycle | **4.17 s** |
| after `picotool load` + reboot | **9.06 s** |
| after a store write + reboot | 10.5–12.0 s |
| the "freeze" | **> 300 s, indefinitely** |

The first reported "reproduction" was me flashing, rebooting, sleeping 8 s and
declaring a freeze. The boot takes 9.06 s. I was under-waiting by about a
second, and the LED sits solid throughout, so "solid LED, no `lsusb`" is the
documented appearance of *not yet*.

### 20.3 The storage bisect — and what it eliminated

Once it was clear the failure was intermittent, the only honest way to
attack it was to remove variables. The store is AES-256-GCM under a key
recovered in §16, so it is **writable**: variants can be forged and flashed,
one experiment per flash, instead of a rebuild per experiment. The tool
(`redteam/forge_store.py`) validates itself first by re-encrypting the
untouched store and comparing byte-for-byte.

| store | result |
|---|---|
| a store copied verbatim from a working session | **8.81 s — boots** |
| the store the firmware itself wrote when hung | **> 300 s — hangs** |
| minus the OATH keystore record | hangs |
| minus the FIDO keystore record (valid CRC) | hangs |
| minus `boot.fwmanifest.v1` | **11.98 s — boots** |
| the *same* store, rebooted again | **10.54 s — boots** |

And the decisive measurement: the store that hung past 300 s and the store
that had just booted twice are **byte-identical** — same record count, same
image nonce, all seven records the same bytes. The FIDO keystore snapshots the
firmware persisted were lifted out of the real sealed store and run through the
shipped `DeviceKeystore::from_cbor` on the host: **both decode**. That test is
kept at `apps/fido/tests/r2_keystore_decode.rs`; it asserts the *opposite* of
what happens, which is what makes it worth keeping.

**So: not the OATH record, not the FIDO keystore, and not the store contents
at all.** The failure is a function of something outside the store.

### 20.4 The two retractions, and why they matter more than the answer

- **"The OATH keystore stream is corrupt."** I parsed the chunked container
  with a 12-byte header when it is 16, so I read the CRC field as a record
  length and got `Corrupt` → `fatal_boot`. Re-parsed correctly, the stream is
  well-formed: `fid=0xBA00 len=39`, `fid=0xBA44 len=49`, 100/100 bytes
  consumed.
- **"The firmware manifest mismatch bricks it."** Removing
  `boot.fwmanifest.v1` did produce an 11.98 s boot, and the stored manifest
  does equal the running image's `.data` hash (verified offline: SHA-256 over
  the 774,296-byte region `__sdata`→`__sidata + (edata - sdata)` reproduces it
  exactly). But the "control" store booted *because* its manifest was stale —
  the anti-implant policy wiped it — and the "fix" merely took the first-boot
  path. Both stores are identical and both boot now.
- A third, caught before it reached a conclusion: three forged variants carried
  a **stale trailer CRC** (I re-encrypted the entries but preserved the
  trailing checksum), so they were rejected as untrusted content and were
  measuring my tampering, not their contents. Void.

Every one of these was a causal conclusion drawn from a single observation of
an intermittent fault. The self-checks — the byte-identical round trip, the
verbatim control, the host-side decode test — are what caught them, and they
should have been built in from the start rather than added when something
looked wrong.

### 20.5 The cause, found with a debugger — and the TRNG theory is dead

Everything above pointed at a TRNG wedge (EPIC root cause #2), and that was a
good fit: peripheral state rather than store state, intermittent across
identical stores, before USB, and immune to nuking because a nuke is a flash
operation and not a peripheral reset. **It was wrong for the cases we
captured.** With SWD finally working (§22) the failure was caught and named on
the first attempt:

```
[ERROR] secure partition: OTP key row unavailable
R15/PC: 0x1002c88e   fapico2_firmware::boot::fatal_boot
CFSR = 0x00000000    HFSR = 0x00000000        <- a refusal, not a fault
```

The device is not spinning on a TRNG. It reaches
`derive_boot_store_key()`, where `read_otp_key_1()` returns `None` because
the OTP key row is no longer readable, and `fatal_boot` latches. The cause is
the **OTP lock escalating to `INACCESSIBLE`**, which is §20.2's original
theory — the direction this section's first version had right, for a reason
this section's second version got wrong. The lock is not raised by the
firmware (§22.4 exonerates it on two independent counts); it is a side effect
of the debug port, and it is cleared by a power cycle.

R2-26 in §22 is the full finding. The lesson recorded here is about method,
not about the TRNG: for four hours the investigation bisected *state* looking
for a fault that was not in the state, and the decisive evidence came from
stopping the core on the one instrument that could see it. The self-checks
that caught my two false conclusions — the byte-identical store round trip,
the verbatim control, the host-side decode test — are what kept that from
becoming three published wrong answers.

## 21. R2-25 (HIGH) — the first OATH credential permanently bricks the OATH applet

**Status: reproduced on hardware, 2026-09-28.** Adding one credential to a
virgin token makes the YKOATH applet permanently unusable, with no software
recovery. The rest of the token is unaffected — which is exactly why it read
as "the whole device is dead".

### 21.1 Reproduction

On a freshly nuked board, OATH virgin, no access code, no PIN:

```
SELECT A0000005272101    SW=9000
LIST  (0xA1)             SW=9000  b''            <- no credentials
PUT   (0x01)             SW=9000                   <- 29-byte payload, one HOTP
LIST  (0xA1)             SW=9000  72 04 11 72 74 32 <- "rt2" is there
--- the next command ---
LIST  (0xA1)             SW=6982                   <- SECURITY_STATUS_NOT_SATISFIED
CALCULATE (0xA2)         SW=6982
SET CODE (0x03)          SW=6982                   <- and no way out
```

The credential is stored. The applet is dead. Both facts are true at once.

### 21.2 Root cause — the virgin auto-validate rule

`apps/oath/src/oath_core.rs:534`:

```rust
fn refresh_session_grant(&mut self) {
    self.validated = self.access_code.is_none()
        && self.pin.is_none()
        && self.slots.iter().all(|s| s.is_none());
}
```

A session is granted **only while the applet is completely virgin** — no
access code, no PIN, *and no credentials*. The third clause is the bug.
`PUT` is permitted precisely because the applet is virgin; the write makes it
non-virgin; the grant is then recomputed and withdrawn, and the credential
that was just accepted is the reason it was withdrawn.

### 21.3 Why there is no way out

Which commands the grant gates, read from the dispatch:

| command | gated? | |
|---|---|---|
| `PUT` `0x01` | yes | needed *before* the write, when virgin |
| `DELETE` `0x02` | yes | unreachable |
| `RENAME` `0x05` | yes | unreachable |
| `SET CODE` `0x03` | **yes** | **this is the escape hatch, and it is gated** |
| `SET PIN` `0xB4` | **yes** | **this is the other escape hatch, and it is gated** |
| `LIST` `0xA1` | yes | unreachable |
| `CALCULATE` `0xA2`, `CALC ALL` `0xA4` | yes | unreachable |
| `VALIDATE` `0xA2`-class `0xB1` | no | but it checks an access code — none exists |
| `VERIFY PIN` `0xB2` | no | but it checks a PIN — none exists |
| `RESET` `0x04` | no | requires `P1/P2 = DE AD` **and a physical touch** |

Both ways to *create* the credential that would restore the grant are behind
the grant the credential destroyed. The state is therefore closed: from a
virgin applet, one `PUT` leads to a state with no credential-management
command that is not gated and satisfiable. The only exit is a factory reset,
which by design destroys all credentials.

The two gates here are individually defensible and jointly fatal. Gating
`SET CODE` is right — it is the same privilege as `PUT`, and letting an
unvalidated session set an access code would be worse. Gating it is also what
closes the loop. The defect is not either gate; it is that **no credential can
ever exist without an access code or a PIN having been established first, and
this firmware lets `PUT` run in the virgin state that precedes that.**

### 21.4 Impact

- **Availability.** OATH is dead for the lifetime of that state. Every
  enrolment path a real user takes — "add my first token" — lands here.
- **Data loss.** Recovery is a factory reset, so any credentials added by
  another path first are destroyed. On a token where OATH is the only
  populated applet, that is a wipe.
- **No silent-failure amplifier.** The applet returns `6982`, not `9000`, and
  the credential really is stored, so a host cannot mistake this for success.
  It fails loudly, which is the one mercy here.
- **Scope.** FIDO2, OpenPGP and the management applet all keep working —
  verified on the same bricked board (`getInfo` status `0x00`; OpenPGP and
  management `SELECT` `9000`; management `READ_CONFIG` `0x1D` returns a full
  config blob). It is a one-applet denial of service.

### 21.5 What it explains about the original report

The owner's observation was *"when creating a new OATH account, it didn't
appear and other apps stopped working. Then after power cycling, the led was
on and device frozen."* Both halves now have a mechanism:

- **"it didn't appear"** — `LIST` is gated, so once the applet self-locked the
  credential could not even be enumerated. From the outside the applet looks
  empty, and in the same session that added it, it had briefly been visible.
- **"other apps stopped working"** — they did not; they were never tested. They
  are healthy on a board where OATH is bricked, which this run verified.
  OATH going dark is visually indistinguishable from the whole token dying.
- **"frozen, and nukes don't help"** — a separate and much duller fact: the
  post-flash boot is slower than the steady-state boot (9.06 s vs 4.17 s,
  §20.5), and 8 s is not enough to see it. A board that needs nine seconds to
  enumerate, observed for eight, is a board that looks bricked.

So the OATH correlation was real and pointed at a real bug. It just was not a
whole-device failure, and the persistent-freeze half of it was a measurement
that stopped too early.

### 21.6 The fix

The invariant to restore: **from a virgin applet, after any sequence of
`PUT`s, there must always exist a non-gated command that can reach the
credentials.** Today that property does not hold.

The grant logic itself is not the place to start — swapping the predicate
around does not help, because the problem is that the applet is *allowed to
reach a state it has no way out of*. The fix belongs at the transition:

1. **On a virgin applet** (no access code, no PIN, no credentials) the grant
   stands so the first `PUT` works. That is today's behaviour and it is
   correct — keep it.
2. **A `PUT` that would create the first credential while no secret exists**
   must not leave the applet in a closed state. Either:
   - refuse it, `6982`, with an error that says "set an access code or PIN
     first"; or
   - set a machine-generated access code as part of that same `PUT` and
     return it to the host. This is the YubiKey model's own answer to a token
     with no password, and it is the better of the two: it keeps enrolment
     working for the user who just wants a token.
3. **Test the invariant, not the commands.** Every existing test starts from
   a state that already has an access code, which is why none of them caught
   this. The test that matters begins at virgin, issues one `PUT`, and
   asserts that a non-gated path to the credential still exists.

The defensive half is worth keeping independently: `SET CODE` and `SET PIN`
are the privilege-equivalent commands and *should* stay gated. The defect is
not that they are gated; it is that `PUT` is allowed to run in the state that
precedes them.

### 21.7 Recovery on this board

`RESET` (`INS 0x04`, `P1=0xDE`, `P2=0xAD`) is not gated, but it requires
`user_present(PRESENCE_TAG_RESET)` — a physical touch. That consent gate is
correct and should stay. Recovering this board means sending the reset APDU
while someone presses the touch button, which clears the credential table and
returns OATH to virgin. That is a destructive operation on OATH state, so it
is the operator's call, not mine.


### 21.8 Operational remediation — validated on hardware

The fix in §21.6 is a code change. The workaround needs no firmware change and
was run on the bricked board to confirm the diagnosis end to end.

**Order matters, and the whole remedy is one line: establish a secret before
the first credential.** `SET PIN` (`INS 0xB4`) is gated on the session grant,
so it works *only* while the applet is still virgin. Once any credential
exists the grant is gone and `SET PIN` returns `6982` — the trap closes in
exactly the same way as `SET CODE`.

Verified sequence on the board that was bricked by R2-25:

```
RESET (0x04 DE AD) + touch      9000   <- OATH virgin again
SELECT OATH                     9000
LIST                           9000   b''          (virgin, no credentials)
SET PIN 123456 (0xB4)           9000                <- the whole fix
PUT rt2 (0x01)                  9000
LIST (same session)             9000   72 04 11 72 74 32

--- a new session, as any host would open ---
SELECT OATH                     9000
LIST                           6982                <- grant correctly withdrawn
VERIFY PIN 123456 (0xB2)        9000                <- and correctly restored
LIST                           9000   72 04 11 72 74 32
CALCULATE rt2 (0xA2, challenge) 9000   75 15 06 4a1af0487b5de40ad14222deb690db3adc242aa7
```

The last line is a correctness check as well as a liveness one. That digest is
byte-identical to `HMAC-SHA1(secret, counter=0)` for the secret that was
enrolled, and RFC 4226 dynamic truncation at offset 7 yields `486114` — the
same six digits computed independently on the host. So the credential is
stored intact and the applet computes standard HOTP; the only thing that was
ever broken was the session grant.

Note what the restored behaviour is *not*: the session is granted again by
`VERIFY PIN`, which burns a retry on each attempt and is deliberately
gated. That is the intended design, and after this change the applet reaches
that state by a route a user can actually follow. A token shipped with
`123456` should have that PIN changed, but it is a recoverable position —
which is the entire difference from R2-25.

**Host guidance.** Any client provisioning a token must do
`SET PIN` (or `SET CODE`) as its *first* OATH write and refuse to enrol a
credential if that step failed. The YubiKey reference client does not have
this ordering requirement because it always provisions a password during
initial setup; a client that offers "add a token" without one inherits the
trap.


---

## 22. R2-26 (HIGH) — attaching a debugger bricks the token until it is power-cycled

**Status: reproduced on hardware, 2026-09-28, and measured end to end.** Brief
physical SWD access leaves the device unbootable — solid LED, no USB, no
recovery by reflash — until someone unplugs it. This is the mechanism behind
the "permanent freeze" of §20, at least for every case observed with a
debugger attached.

### 22.1 Reproduction

```
1. Board running fapico2, healthy (enumerates, all applets 9000)
2. probe-rs reset --chip rp235x          # one command; the session then ends
3. Device never enumerates again.  Solid LED.  No recovery by reflashing.
4. A *system* reset (step 2 again, or power-button): still dead.
5. Unplug the USB and replug: boots normally, all applets 9000.
```

Step 2 is the whole attack. It needs no PIN, no credentials, no firmware
modification, and seconds of contact.

### 22.2 What actually changes

The RP2350 OTP lock register, `SW_LOCK*`, read over SWD while the core is
halted in `fatal_boot`:

| register | healthy | after step 2, **system** reset | after **power** cycle |
|---|---|---|---|
| `SW_LOCK[0]` | `0x05` | `0x0D` | `0x05` |
| `SW_LOCK[1]` | `0x04` | `0x0C` | `0x04` |
| `SW_LOCK[2]` | `0x04` | `0x0C` | `0x04` |
| `SW_LOCK[58]` (key row) | `0x0C` | `0x0F` | `0x0C` |
| `SW_LOCK[62]` | `0x04` | `0x0C` | `0x04` |
| `SW_LOCK[63]` | `0x04` | `0x0D` | `0x04` |
| ECC word for row `0xE90` | key bytes | `0x00000000` | key bytes |

Field decode (`nsec = bits[3:2]`, `sec = bits[1:0]`, 3 = inaccessible): the
healthy map is `nsec = read_only` with `sec = read_only` on the chipid group
and `sec = read_write` elsewhere. After the escalation **every** page group
carries `nsec = inaccessible`, and several carry `sec = inaccessible` too.
Register 58 — the group containing the store key row — goes to `0x0F`, both
domains locked.

### 22.3 The failure, named

With the core halted over SWD, the firmware says exactly what happened:

```
Core halted due to a user (debugger client) request @0x1002c88e
[ERROR] secure partition: OTP key row unavailable
R15/PC:  0x1002c88e      -> fapico2_firmware::boot::fatal_boot
R14/LR:  0x1002c88f
Frame 1: fapico2_firmware::boot::fatal_boot @ 0x1002c88e
```

`CFSR` and `HFSR` are both `0x00000000`. This is a **deliberate refusal, not a
fault** — the boot path reached `derive_boot_store_key()`, where
`read_otp_key_1()` returned `None` because every ECC read of rows
`0xE90`–`0xE9F` now returns the all-ones permission-failure sentinel, and
`fatal_boot` latched.

That is the whole signature the §20 investigation was chasing: solid LED, no
USB, survives reflash, indistinguishable from a hang over any transport that
does not have a debugger.

### 22.4 The firmware does not do this

The obvious suspect is the firmware's one OTP write, `boot.rs:987`
`otp_hw_write_lock_key_row()`, and it is exonerated on two counts:

- **It only touches register 58**, and only the `nsec` field. The escalation
  hits registers 0, 1, 2, 57, 59, 62, 63 as well — all of them by the same
  `+0x08`. A single register write cannot do that.
- **It cannot even move register 58.** From the observed `0x0F`,
  `set_nsec(READ_ONLY)` computes `(0x0F & ~0x0C) | 0x04 = 0x07`, and the
  hardware ORs `0x0F | 0x07 = 0x0F`. The register is already at maximum, so
  the write is a no-op. There is no value of `nsec` this code can write that
  produces `0x0F`.

The escalation is therefore a side effect of the debug port itself, and it is
**volatile** — it does not survive power loss, which is exactly why §20's
"nuke doesn't help" observations looked permanent: a nuke is a flash
operation, and the reset it implies is a *system* reset, which we have now
measured to leave the lock exactly where it was.

### 22.5 Impact and the design question

- **Availability.** Any actor with brief physical access and a debug probe
  can leave the token unbootable. The recovery is visible to an owner
  (unplug, replug) but not to the device, and nothing in the failure path says
  why.
- **Not a confidentiality loss.** The escalation *locks* the row; it does not
  expose it. The recovery path still needs the row to be readable.
- **The design question.** `fatal_boot` on an unreadable OTP row converts a
  diagnosable hardware fault into a brick. A token that cannot decrypt its
  store could still enumerate and answer CTAP2/CCID with an explicit
  "hardware fault: OTP key row unreadable" — the store is sealed under a key
  derived from that row, so no app can function either way, but the owner
  would learn *why* instead of seeing a solid LED. This is the same shape as
  R2-25: the component behaves correctly and the failure handling is what
  strands the user.

### 22.6 The limit on this finding

This mechanism is **debug-induced**. The hang originally reported in §20
predates any SWD use on this board, so I cannot claim the two are the same
event — the spontaneous case was never captured, because at the time there
was no way to capture it. What is established is that a fully characterised,
reproducible failure with this exact signature exists, that a power cycle
clears it, and that the firmware has no defence against it. Establishing
that a *spontaneous* path reaches the same state needs a failing boot caught
with the probe connected but idle — resets by power cycle, never by SWD, so
the debugger cannot itself induce what it would then observe.

That protocol matters beyond this report: **on this hardware, debugging the
token risks reproducing the bug being hunted.** Anyone reaching for SWD on a
device they care about should know that before they connect.
