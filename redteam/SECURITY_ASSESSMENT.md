# fapico2 Security Assessment — Red Team Report (final)

**Target:** fapico2 (RP2350) — YubiKey-class authenticator
**Identity:** USB `1050:0407`, "The BLOCO Community fapico2", serial `94746395`, chipid `0x60da2f528aa9ce05`, CTAPHID fw 5.4.0
**Date:** 2026-10-05
**Attacker model:** USB access (physical or compromised host), **no PIN / no access code / no touch**, brief or indefinite possession. No lab equipment (no EM probe, no glitch rig, no SWD).

**Applets:** FIDO2/U2F (CTAPHID), OpenPGP 3.4 (CCID), OATH/YKOATH (CCID), YubiOTP (HID), Management (CCID), Rescue (CCID).

---

## Executive summary

The **cryptographic core is genuinely well built.** Across five applets and three transports I could not forge a signature, read a private key, steal an OTP code, or produce a decrypt oracle. The PIN retry counter is flash-resident (defeating the 8-guesses-per-replug brute force that works against stock YubiKeys). OpenPGP returns one identical error for every malformed decryption input — no Minerva-class oracle. OATH, YubiOTP and the RS-Key vendor channel all refuse every operation without their secret. The CTAPHID assembler survived INIT floods, CID abuse, seq attacks, preemption races and hostile CBOR without a hang or a reset.

Three real defects, all in the **control plane** rather than the crypto:

1. **CRITICAL — one unauthenticated CTAP2 frame destroys every credential and the PIN** (`authenticatorReset`, 498 ms, no touch). Confirmed by wiping the device.
2. **HIGH — the RP2350 debug interface is enabled** (`picotool info`: `debug enable: 1`, `secure debug enable: 1`), which is the precondition for RAM/key extraction via SWD. Tied to ADR 0002's `-release` closure, so it is an alpha-image defect — but it must not ship.
3. **MEDIUM — getInfo's `encCredStoreState` (0x1E) is a deterministic, unauthenticated encryption of the signature counter**, so anyone polling getInfo can observe when the owner used the key.

The full firmware **is** extractable by an unauthenticated attacker (4 MiB flash image pulled over BOOTSEL). The secure store inside it stayed encrypted: the key is OTP-derived and the bootrom **refuses** to release OTP row `0xE90`. That boundary held.

---

## Findings

### F1 — CRITICAL · Unauthenticated factory reset destroys all credentials and the PIN

**`apps/fido/src/device_core.rs:2558` (`handle_reset`) — no `user_present`, no token check.**

One frame on a normal CTAPHID channel, empty CBOR body, no pinUvAuthToken:

```
CTAPHID frame cmd 0x90 (CBOR), payload = 0x07   →   status 0x00 in 498 ms
```

Measured before → after on the live device:

| | before | after |
|---|---|---|
| `clientPin` | true | **false** |
| `alwaysUv` | true | **false** |
| `makeCredUvNotRqd` | false | **true** |
| pin retries | 2 | 8 (fresh) |
| credentials | user set | **destroyed** |
| `versions` | no `U2F_V2` | **`U2F_V2` present** |

The reference requires a button (`pico-fido2/src/fido/cbor_reset.c:78-84`). The transport already has the mechanism — `hid_serve.rs:773` sets `up_request` only for opcodes `0x01`/`0x02`, and `0x07` is absent from `presence_windowed`. 498 ms confirms no consent window opened (a gated command parks for the 30 s window).

Aggravating: the reset also **re-advertises `U2F_V2`**, dropping the key into the degraded U2F posture AGENTS.md §4 names as the failure mode Chrome reacts to by abandoning CTAP2. And `apps/fido/src/app.rs:698-702` is identically ungated — the AGENTS.md §1 twin trap in its second form, so the host suite stays green through a fix unless both twins *and* the transport change.

**Fix:** add `user_present()` to `handle_reset`, add `0x07` to `presence_windowed` in `hid_serve.rs`, mirror in `app.rs`, add a host test asserting reset parks for the touch window.

### F2 — HIGH · RP2350 debug interface enabled (RAM/key-extraction precondition)

`picotool info -a` over BOOTSEL reports:

```
secure boot:            0
debug enable:           1
secure debug enable:    1
```

With the debug interface open, an attacker with brief physical possession can attach SWD and dump RAM — where `derive_store_key`'s output, the ECDH `hkey`, `device_random` and per-applet keys are resident. That is **complete key exfiltration**, and it bypasses every gate this assessment otherwise found holding.

AGENTS.md's hardware warning ("never run this firmware with a SWD debugger attached") is an *operational* rule; it is not a property of the shipped image. ADR 0002 states the `DEBUG_DISABLE` closure applies at `-release` tags, and the repository carries no tags yet — so this image is pre-release and the finding is consistent with that. **It must be verified closed before the first tag.** I did not attach a debugger (it would also have bricked OTP reads and violated the AGENTS.md rule).

### F3 — MEDIUM · getInfo leaks assertion activity (deterministic counter encryption)

`device_core.rs:2686-2711` builds key `0x1E` (`encCredStoreState`) as:

```
IV(16) = fresh random per call
ct     = AES-256-CBC( HMAC-SHA256("fapico2-encStateKey", device_random),
                      HMAC-SHA256("fapico2-credStoreState", device_random ‖ cred_counter),
                      IV = 0 )        ← pin_cbc_encrypt_zero_iv, crypto.rs:1482
```

Measured over 6 consecutive unauthenticated getInfo calls: the **IV changes every call, the ciphertext is byte-identical every call** (`f317bb1c8bee39979eb696e0df504295`). That confirms zero-IV CBC over a plaintext that is a pure function of `device_random` and the **signature counter**.

Consequences: (a) the advertised IV is decorative — any consumer that trusts it decrypts wrongly; (b) **an unauthenticated poller can detect exactly when the counter moves, i.e. when the owner performed an assertion and how many**, with no PIN, touch or credential. (c) It is a plaintext-equality oracle over a counter, which is the shape a chosen-ciphertext attack needs.

I could not demonstrate a counter *increment* (that needs a completed assertion), so the leak is proven by mechanism + determinism, not by an observed change.

### F4 — HIGH (latent) · OATH auto-provisions a publicly-known access code

**`apps/oath/src/oath_core.rs:396` `DEFAULT_ACCESS_CODE = "123456"`, installed at boot by `provision_default_access_code` (`:1089`) when the owner has set none.** The PBKDF2 salt is the device_id, **published in the SELECT response** — I read it live (`0x71` = `f28cff69f7f10453`).

So on a unit where the owner never set a code, `PBKDF2-HMAC-SHA1("123456", device_id, 1000, 16)` is computable by anyone who SELECTs, and VALIDATE then unlocks LIST, CALC, PUT, DELETE and RENAME — none of which check user presence (`grep user_present apps/oath/src/oath_core.rs` returns only SET_CODE, conditional CALC, and RESET).

**Not exploitable on this board**: my VALIDATE with `123456` was refused `6984`, meaning a real access code is set here. Latent HIGH, not an active compromise. The module's comment at `:1062-1065` claims PUT/DELETE/RENAME "each gate on `user_present`" — false for three of five. Also: `cmd_validate` (`:2715`) has **no retry counter**, giving unlimited online guessing with a clean oracle.

### F5 — MEDIUM · Unauthenticated REBOOT takes the board off the bus until power-cycled

`apps/rescue/src/lib.rs:1335` — `cmd_reboot` checks only `P2 == 0x00` and the mode byte; no auth, no touch. `80 1F 00 00 00` (normal reboot) left the board **non-enumerating**: kernel logged repeated `device descriptor read/64, error -71` → "device not accepting address" → host power-cycled → "unable to enumerate USB device". Recovery required a physical unplug. Reproduced twice (once each reboot path). BOOTSEL (`P1=0x01`) is the documented recovery path and additionally permits arbitrary firmware replacement — accepted by design, but it means brief possession includes full firmware replacement.

### F6 — MEDIUM · Management `INS_MIGRATION` is an unauthenticated passphrase oracle

`apps/mgmt/src/lib.rs:464-473` — `INS_MIGRATION` (0x1F) has **no presence grant**, unlike `WRITE_CONFIG` and `RESET` on the same applet. `firmware/src/boot.rs:870` returns a **distinguishable status byte** (`Migrated=0 / NeedsPassphrase=1 / NotMigratable=2 / None=3 / Error=4`). Class 0 (`platform/src/migration.rs:1269-1296`) feeds an attacker-supplied passphrase into `ckey::unwrap_keydev` — an **unbounded** correct-FIDO-PIN oracle. Class 1 (OpenPGP PW1) is bounded by the card's counter.

### F7 — LOW · Full firmware is extractable by an unauthenticated attacker

Rescue REBOOT(BOOTSEL) → `picotool save -a` returned the **complete 4 MiB flash image** (SHA-256 `e9429e1b758eda677c8533a46d51dada020c9f3c793e8ef8e94217332c62a402`), including the firmware at offset `0x031000` and the sealed credential store at `0x20B001` (0x567 bytes, **7.87 bits/byte entropy** = genuine ciphertext).

**The encryption boundary held.** `store_v3::derive_store_key(otp_key_1, chipid)` needs OTP row `0xE90` (`boot.rs:1375-1384`), and the bootrom refuses it: `picotool otp get 0xE90` → *"permission failure"*, and rows `0xE80`–`0xEAF` dump as `XXXXXXXX`. I had chipid (`0x60da2f528aa9ce05`) and the full ciphertext, and could not decrypt — **the chain stops exactly where it should.**

This is inherent to the RP2350 (no read-protect on OTP from *running* firmware, as US-918 already documents) and is an accepted risk of an unauthenticated recovery path. Its practical severity is F2: with debug enabled, SWD beats this defence entirely.

### F8 — LOW · getInfo advertises deprecated pinUvAuth protocol 1

Key `0x06` = `[1, 2]`. Protocol 1 is the pre-2.1 HMAC construction without domain separation, deprecated by CTAP 2.1 (Barbosa et al., ePrint 2025/459). Both v1 and v2 `getKeyAgreement` returned the **same** device point within a session. Dropping v1 closes a downgrade window on a device whose whole posture is PIN-gated.

### F9 — INFORMATIONAL · `apdu-trace` is release-allowed with a fixed drain CID and cleartext PINs

`firmware/Cargo.toml` marks `apdu-trace`/`boot-timeline` release-allowed (unlike `dbg-log`, release-forbidden via `compile_error!`). Both reuse CTAPHID vendor command `0x42` with a **compile-time constant drain CID** (`main.rs:519-535`: `a5 5a a5 5a` / `7b 07 b0 07`), and `apdu_trace.rs:16-18` states the ring "records full APDU bytes: the VERIFY / CHANGE REFERENCE DATA commands carry PIN material in the clear." Dispatch matches **channel only, no auth** (`tasks.rs:565`). Unreachable in the shipping build (`build.sh` runs plain `--release`); a process risk for any capture image flashed and not reflashed.

### F10 — INFORMATIONAL · Unassigned CLA (0x90) returns success with no data

On the OpenPGP applet, `CLA=0x90` returns `9000` with zero-length data for many INS values, where `CLA=0x00` correctly returns `6A88`. I verified it **executes nothing**: after `90 E2` write attempts against DOs `0xCE` and `0x5B`, both still read `6A88` — no state mutation, no data leak, no PW bypass. An empty-success fallback for unhandled class bytes; the card should return `6D00`.

---

## What held — verified attacks that failed

**Key exfiltration: blocked on every store.**
- FIDO: no credential, resident key or largeBlob readable without a verified token carrying the right permission bit. All 17 credMgmt subcommands and all 4 largeBlob shapes → bounded errors. `authenticatorConfig` subcommands 0x04/0x05/0x07/0x09/0x0A/0x0B → `0x36` (token required).
- OpenPGP: `PSO:CDS` without PW1 → `6982`; `INTERNAL AUTHENTICATE` → `6982`; `PUT DO` template import pre-PW3 → `6A88`; `RESET RETRY COUNTER` without code → refused. Every GET DATA DO including PW-status `00C4` → `6A88`.
- OATH: `LIST`, `CALC` ×2, `PUT` (seed poisoning), `VALIDATE`, `SET CODE` → all `6982`. **40/40 flood PUTs rejected**, malformed PUTs rejected, applet healthy afterwards, `RESET 0xDE 0xAD` correctly demands a touch (`6985`).
- YubiOTP (cracked the 10-chunk YK4 framing): `CAPABILITIES` returns the same device-info TLV as mgmt/CCID; all challenge-response slots `0x11`–`0x18` → no data; **configure with a known secret rejected and the programming sequence stayed 0** — no slot was written.
- RS-Key vendor41: every token-gated subcommand refused; ungated `STATE` returns only `{1:false,2:false,3:false,4:false}` — booleans, no key material.

**Authentication bypass: none.** PIN retries persist across power cycle (7 before, 7 after). Token-less makeCredential/getAssertion never signed. CTAP1 `REGISTER` → `6985`. Flag coercion (`up=false`, `uv=false`, `uv=discouraged`, `rk=true`) → uniformly refused.

**Malleability: none found.**
- OpenPGP PSO:DECIPHER: 12 point mutations (zero, all-FF, bit-flips, truncation, concatenation, P-256 group order, small-order) → **one identical response** `6A86`, timing spread **0.2 ms**. No invalid-curve oracle.
- OpenPGP PSO:CDS: the only variation is empty-vs-non-empty input (`6D00` vs `6A86`); `P2=0x9A` correctly returns `6982` (PW1 required). No algorithm confusion.
- FIDO getInfo: all keys stable across calls except the two documented per-call IVs.

**Timing: no leak.** Five wrong PINs (three 6-digit, one 4-digit, one 9-digit) at 1191.5–1200.0 ms — **8 ms** spread at constant length, **0.7 ms** between lengths. The ~1192 ms ECDH handshake dominates completely.

**Transport fuzzing: survived.** 60 rapid INITs → 60 unique monotonic CIDs. Oversized/zero BCNT, reserved CID `0`, bridge CID `[0,0,0,1]`, broadcast non-INIT, wrong seq bits, INIT-preemption race → every input a defined error; never hung, never dropped. Spec-correct continuation reassembly echoes byte-for-byte.

**CBOR parser: no crashes.** 64-bit heads (`0x1B`), 32-deep nesting, indefinite-length maps, truncated maps, duplicate keys, `0x7B` huge-string claims, opaque tags → bounded errors. The §6 32-bit width rule holds.

**Reset blast radius correctly scoped.** Post-reset, OATH stayed locked, OpenPGP selected cleanly, mgmt config byte-identical.

---

## Attack chain (as executed)

1. **Enumerate** — `lsusb` → `1050:0407`; CTAPHID INIT (65-byte report framing, CID allocation, tolerant continuation parsing) → getInfo → capabilities, PIN state, identity blobs.
2. **Establish posture** — `getPinRetries` → 8; one wrong PIN → 7; CTAP1 register refused.
3. **Retry oracle** — wrong PIN → unauthenticated Rescue REBOOT → enumeration failure → power cycle → retries still 7. **Chain dead.**
4. **Fuzz** — transport and CBOR; all survived.
5. **Probe every read path** — CTAP2, vendor41, OATH, OpenPGP, mgmt, Rescue, YubiOTP. All gated.
6. **Malleability sweep** — ECDH point mutations, PSO shapes, CTAP2 flag coercion. Uniform.
7. **Break it (destruction)** — one frame `0x07` → `0x00` in 498 ms → credentials and PIN gone, `U2F_V2` re-advertised.
8. **Break it (extraction)** — Rescue REBOOT(BOOTSEL) → `picotool save -a` → full 4 MiB image; OTP row `0xE90` **refused**; sealed store (7.87 bits/byte) not decryptable. Restored via `picotool reboot`.

---

## Recommendations, in order

1. **Gate `authenticatorReset` on user presence** (F1) — `device_core.rs`, `hid_serve.rs`, `app.rs`, plus a host test.
2. **Verify the `DEBUG_DISABLE` closure actually fires before the first `-release` tag** (F2), and confirm on hardware with `picotool info -a` that both `debug enable` and `secure debug enable` read 0. Add that check to the release checklist.
3. **Remove or bound the OATH default access code** (F4); add `user_present()` to `cmd_put`/`cmd_delete`/`cmd_rename`; add a retry counter to `cmd_validate`.
4. **Make `encCredStoreState` honest** (F3): either stop advertising the unused IV, or re-encrypt under the advertised random IV, and consider removing a deterministic counter-derivative from an unauthenticated response entirely.
5. **Add a presence grant to `INS_MIGRATION`** and remove the distinguishable status byte on the unbounded class-0 path (F6).
6. **Investigate the reboot enumeration failure** (F5) — normal reboot should not require a physical unplug.
7. **Drop pinUvAuthProtocols v1** (F8), **make `apdu-trace` release-forbidden or per-build the CID** (F9).

**Accepted by design, document in the threat model:** Rescue REBOOT→BOOTSEL without auth or touch (unauthenticated firmware replacement + full flash extraction); flash images being extractable when the sealed store cannot be decrypted; OATH RESET without an access code.

---

## Coverage and limits

**Tested live on hardware:** CTAPHID (INIT/PING/WINK/CBOR/MSG), all unauthenticated CTAP2 opcodes, clientPIN state machine, CBOR and CTAPHID framing fuzzing, vendor41, management applet, Rescue applet (including BOOTSEL), OATH applet, OpenPGP applet (incl. malformed ECDH sweep), YubiOTP HID (correct 10-chunk framing), power-cycle persistence, flash extraction, OTP read attempts, and the reset attack.

**Not reached, and why:**
- **SWD / debug-port key extraction** (F2) — would violate the AGENTS.md hardware warning and make OTP unreadable; reported from `picotool info -a` evidence instead.
- **FIDO signature malleability on a completed ceremony** — needs a registered credential and the physical touch the device correctly demands; flag-coercion was tested instead (uniformly refused).
- **Counter-increment proof for F3** — needs a real assertion.
- **EM/flash-fault/EUCLEAK class** — no lab equipment. The RP2350 is not a certified secure element; treat "the key cannot leave the chip" as unproven.
- **Clone-detection / counter monotonicity** (NDSS attack 7) — needs a credential and a real assertion.

**Artifacts:** `redteam/` — `ctaphid.py`, `ccid.py`, `ccid_raw.py`, plus `recon.py`, `ctap2_probe.py`, `pin_attack.py`, `pin_recover.py`, `reboot_retry.py`, `hid_fuzz.py`, `hid_framing.py`, `hid_reassembly.py`, `vendor41_probe.py`, `oath_probe.py`, `oath_exploit.py`, `pgp_probe.py`, `pgp_malleability.py`, `fido_malleability.py`, `otp_probe.py`, `otp_exploit.py`, `timing.py`. Flash/OTP dumps in `/tmp/fapico2-dump/` (`flash_all.bin`, sha256 `e9429e1b…`, `otp.txt`). **This board's PIN and all its credentials were destroyed by finding F1 and remain unenrolled.**