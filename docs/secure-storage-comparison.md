# Secure storage: the four references, adversarially reviewed

**Date:** 2026-10-03
**Scope:** how `../pico-fido`, `../pico-openpgp`, `../pico-hsm` and `../RS-Key` protect keys at
rest, per applet/feature — strengths worth copying, weaknesses worth avoiding — measured against
what the RP2350 board actually offers and what fapico2 does today.
**Method:** five parallel adversarial source reviews (one per reference, one board-feature
inventory), targeted at weaknesses rather than mechanism surveys. Load-bearing claims about
fapico2's own code were re-verified by hand afterwards (§9); claims sourced only from the
sub-reviews are marked. This document feeds `docs/tasks/EPIC-secure-storage.md`, which holds the
implementation plan; this document holds the evidence and the verdict.

---

## 1. Executive summary

1. **Every reference has the same floor, and it is low.** All four protect key material with a
   PIN verifier that costs a handful of hash operations per guess (§5.2), and three of the four
   can fall back to a root key derived from a *public* constant plus the board serial
   (§5.1). fapico2 is already stronger on both axes: it refuses to boot without a real OTP root,
   and it stretches its PIN verifier with clamped iteration counts.
2. **The board is barely used by anyone.** No reference uses TrustZone; none uses the hardware
   SHA-256 accelerator; glitch detectors and debug-disable are enabled only by pico-hsm's
   opt-in secure lock. The cheapest unadopted controls on our board are one OTP row
   (`CRIT1`) wide (§6).
3. **The best architecture is shared by all four** — per-record AEAD whose key binds the
   record's full identity (slot, generation, domain, policy) — and fapico2's planned per-record
   store already adopts it. The differentiators between references are *enforcement*, not
   design: fail-closed fault semantics (RS-Key), policy-as-data checked at one choke point
   (pico-hsm), and manifest/payload root separation (pico-openpgp).
4. **fapico2 has genuine leads of its own** (§7): transactional checked mutations that cannot
   wedge the device, capacity that is measured rather than asserted, a gate culture that pins
   RAM/flash/erase budgets, and a host/device twin test discipline none of the C references
   can match.
5. **One new defect found in fapico2 during this review** (§6.2): `platform/src/boot_key.rs`
   implements secure-boot provisioning against a row map that does not match the RP2350
   bootrom (rows `0x08–0x0C`, 4 slots, 64-byte rows — versus the real `0x80–0x8F`, 2 slots,
   16-bit ECC rows), and nothing calls it. It is dead code whose layout would be wrong if
   anyone wired it up.

---

## 2. The comparison in one table

| Property | pico-fido | pico-openpgp | pico-hsm | RS-Key | fapico2 today |
|---|---|---|---|---|---|
| Root of trust | `keydev` (flash, wrapped) | DEK (flash, PIN-wrapped) | MKEK (OTP row 0xE90) | MKEK (OTP row 0xE90) | store key = HKDF(OTP 0xE90 ‖ chipid) |
| Root when OTP unprovisioned | **serial-derived fallback is the default on Pico** | serial-derived fallback | refuses (requires provisioning) | serial-derived "pre-OTP arm" | **refuses to boot** |
| Record sealing | AES-256-GCM, 55-byte identity AAD | AES-256-GCM, 55-byte AAD | AES-256-GCM, 55-byte AAD incl. policy hash | ChaCha20-Poly1305, AAD = serial hash | per-field GCM, AAD = slot‖scope‖cred_id (no generation) |
| Nonces | deterministic = `record_id‖generation`, safe because key co-varies | same scheme | same scheme | deterministic HMAC-based, documented equality leak | deterministic `SHA-256(key ‖ SHA-256(aad ‖ pt))` |
| Manifest vs payload roots | split | **split — the model** | split | single root | single store key |
| PIN KDF | ~3 hash ops | ~5 hash ops | ~3 hash ops | ~3 hash ops | **stretched, clamped rounds** |
| Retry counter | durable, decrement-before-verify | durable, verified write-back | plain flash byte | warm-reset only, unauthenticated scratch | persisted in snapshot |
| Record identity binding | full (slot/gen/type/flags/record-id) | full | full + policy hash | partial (rpId hash) | cred_id only |
| A/B commit + rollback | yes, commit-timeout | yes, equal-generation rejection | yes, allocator markers | journal-based (sequential-storage) | whole-snapshot chunked generations |
| Metadata at rest | **plaintext** RP/user names | plaintext descriptors | plaintext descriptors | sealed rpId box, plaintext nicknames | plaintext names |
| Anti-dump of a fresh device | weak (serial-derived root) | weak on RP2040, OK on RP2350 | strong (needs provisioning) | weak until OTP burnt | strong (no fallback root) |
| Rust type-level enforcement | n/a | n/a | n/a | **KeyFid/Sealed/FusedKey** | partial |

---

## 3. Per-reference findings

### 3.1 pico-fido

**The fact that colours everything** [agent-verified; `otp_rp2040.c` re-confirmed by hand]:
on the Pico platform `otp_platform_init()` returns NULL for both key slots
(`pico-keys-sdk/src/otp/otp_rp2040.c:36-38`), so `derive_kbase()` takes the fallback branch
(`crypto_utils.c:34-42`): `kbase = HKDF(salt="NO-OTP", ikm=SHA256(board-id))`. The board id is
the USB serial-number descriptor (`usb_descriptors.c:396`) — **broadcast to every host**. On a
shipped pico-fido, the root of the key hierarchy is a public constant given the serial number.

**Strengths**
- Record keys bound to a 55-byte identity AAD mixed into the HKDF `info` and re-verified
  against the parsed identity on every unseal
  (`object_crypto_provider.c:78-133`): transplant and rollback fail by construction.
- Deterministic nonces (`record_id‖generation`, `:132`) are safe *because* the key derivation
  includes the same values — an elegant invariant worth copying **with the invariant asserted**.
- A/B manifests with generation, `previous_generation`, candidate validation and commit-timeout
  rollback (`object_container_store.c:96-99, 387-402, 449-472`).
- Durable PIN-retry burn: decremented and synchronously committed **before** the verifier is
  compared, with an honest "did the commit drain" check (`cbor_client_pin.c:62-71, 596-609`).
- Dual-core flash isolation via `multicore_lockout` during erase/program
  (`low_flash.c:108-173`).

**Weaknesses**
- **Anti-dump fails on a fresh device**: `keydev` wraps under `kbase` with AES-256-CBC
  (`fido.c:376-391`), and `kbase` is public given the serial. Flash dump + USB serial decrypts
  all resident credential private blobs offline, no PIN. The PIN wrap (format `0x03`) exists
  only after a PIN is set.
- **Unstretched PIN verifier** (`crypto_utils.c:44-56`): one SHA-256 plus two HMACs per guess.
  A 6-digit PIN falls in seconds against a stolen dump.
- **`uint8_t existing` overflow** in credMgmt metadata (`cbor_cred_mgmt.c:175-185`): at 256
  resident credentials the metadata reports `existing = 0, remaining = 256`. [agent-verified]
- **Plaintext metadata at rest**: RP IDs, client data hashes and user names are
  `AUTHENTICATED_PUBLIC` (`resident_container.c:326-335`) — the full account inventory is
  readable from a dump without breaking any crypto. Anti-harvest: weak.
- **Silent root regeneration**: `scan_files_fido()` regenerates `keydev` if its file is empty
  (`fido.c:397-422`) — and the flash layer's sector erase can empty it on a torn write
  (`low_flash.c:122-123, 307`). Losing the sector silently rekeys the device.
- **One key wears five hats**: `keydev` is simultaneously the attestation key, the U2F
  keyhandle root, the record-seal root, the hmac-secret root and the vendor-export root
  (`cbor_make_credential.c:733-736`, `fido.c:325-374, 842-879`). Zero compartmentalization.
- The pinUvAuthToken is persisted to flash (`fido.c:475-483`) and only rotated at the first
  clientPIN command of a boot.

### 3.2 pico-openpgp

**Strengths**
- **The manifest/payload root split is the best idea in the family**: descriptors are
  HMAC'd under a kbase-derived public root, payloads sealed under the PIN-gated DEK
  (`object_crypto_provider.c:63-102`). A flash dump is structurally auditable — which slots
  exist, which generation — with confidentiality still PIN-gated.
- Exhaustive identity AAD with constant-time tag compare (`:104-141`).
- Two-slot A/B where **equal generation in both slots is a hard error** (`:96-98`), and new
  records are validated by full unseal before selection (`:207-219`).
- Retry-spend-before-verify with verified write-back (`openpgp.c:1023-1068`), and staged
  PIN-change transactions applied only against the current verifier (`:582-635`).

**Weaknesses**
- **Zero-work-factor PIN KDF**: the v2 verifier costs ~5 SHA-256 compressions per guess
  (`crypto_utils.c:44-56`); no PBKDF2/Argon2/scrypt anywhere in the tree.
- **NO-OTP is catastrophic on RP2040**: the serial is the *flash chip's* unique ID
  (`pico-sdk/src/rp2_common/pico_unique_id/unique_id.c:30`), queryable off-board with SPI
  command `0x4B`. Stolen flash ⇒ attacker computes `kbase` ⇒ brute-forces the verifier and
  decrypts kbase-protected blobs. On RP2350 the story silently depends on which board shipped.
- **PIV containers are sealed under the public root, not the DEK**
  (`object_provider.c:75-90` wires the PIV domain's `load_root` to `derive_kbase` for both
  roots): PIV private keys are recoverable from flash with only `kbase` — no PIN, no retries.
  Worse, PIN-change staging uses the same provider, so a torn change leaves an offline PIN
  oracle against the *new* PIN.
- **Retry counters are plaintext bytes**, and an erased counter file is re-initialised to
  `3,3,3` on next boot (`openpgp.c:448-452, 503-526`).
- **TERMINATE DF wipes without user presence** when PW3 is merely unusable
  (`cmd_terminate_df.c:21-24, 110-131`).
- `MBEDTLS_SHA256_ALT` is commented out (`mbedtls_config.h:333`) — the RP2350 hardware SHA-256
  driver ships in the SDK and is dead code.
- Secure boot uses a **hardcoded public BOOTKEY** (`otp_rp2350.c:155-160`): it authenticates
  "an image built with the public key", not a vendor.

### 3.3 pico-hsm

The most board-engaged of the four — and the one whose *architecture* is best matched by weak
*enforcement*.

**Strengths**
- OTP-rooted hierarchy where a flash dump alone is cryptographically inert
  (`crypto_utils.c:34-42`; `object_provider.c:29-38`).
- **Declarative, fact-based authorization policy in one choke point** — 14-byte rules of
  {operations, required facts, forbidden facts, namespace} (`object_policy.c:23-46, 91-114`),
  with the **policy hash sealed into the record AEAD** (`object_crypto_provider.c:125`), so
  downgrading a policy breaks the records that reference it.
- Session-epoch binding: authorization contexts are invalidated on every login/unload
  (`object_authorization.c:34-44`; `sc_hsm.c:248, 263`).
- The most complete RP2350 secure-boot provisioning in the family: CRIT1 + BOOT_FLAGS written
  to a primary row **and 7 replicas**, `KEY_INVALID` one-shot semantics, `DEBUG_DISABLE`,
  glitch detectors at max sensitivity, page locks, chaffed and invalidated legacy rows
  (`otp_rp2350.c:88-148, 200-247`).
- DKEK domain shred zero-fills flash payloads (`cmd_key_domain.c:136-147`).

**Weaknesses**
- **Derived PIN tokens live in static BSS for the whole power cycle and are never zeroized** —
  `session_pin`/`session_sopin` (`sc_hsm.c:47-48`); the clear paths only reset *boolean flags*
  (`sc_hsm.c:249, 264, 407`). They are the actual GCM key material for the MKEK records.
- **Legacy MKEK is integrity theater**: AES-256-CFB under the session token with an *unkeyed*
  CRC32C as the "checksum" (`kek.c:77-93`) — malleable and forgeable. Migration to GCM is
  self-heal on successful login, not forced (`kek.c:118-123, 419-424`).
- **The secure-lock third factor is inconsistently applied**: the XOR mask is applied on load
  only for legacy records (`kek.c:80-82`) while `store_mkek` always writes unmasked
  (`kek.c:172-201`) — enabling secure lock on a new-format device corrupts the records (DoS),
  and any re-init silently strips the factor.
- **The button gate auto-accepts by default**: it applies only if `HSM_OPT_BOOTSEL_BUTTON` is
  set, and the button layer auto-completes as pressed when no timeout is configured
  (`button.c:112-121`). `FORCE_BUTTON_WAIT` is not defined in any build file. The policy
  vocabulary has the facts to express presence (`object_policy.h:45, 52`) but the context
  builder never sets them (`object_authorization.c:54-83`).
- **OTP 0xE80 holds a raw secp256k1 private key**, readable in OTP, and the rescue applet
  serves a signing oracle over any 32-byte digest gated only by that auto-accepting button
  (`rescue.c:459-474`).
- DKEK shares are stored **unencrypted** (`kek.c:231-247`), and the flash relocate path leaves
  superseded records un-scrubbed (`flash.c:266-340`) — plaintext remnants in slack space.
- Secure messaging is GP-legacy: SHA-1-derived keys, AES-CBC, CMAC truncated to 8 bytes
  (`eac.c:45-58, 320`).

### 3.4 RS-Key

The youngest codebase, the only one in Rust, and the one with the best *engineering* controls.

**Strengths**
- **Type-level key-slot enforcement**: `KeyFid`/`Sealed` newtypes make writing plaintext into a
  key slot a *compile error*, with compile-fail doctests proving it
  (`crates/rsk-fs/src/sealed.rs:11-35, 53-96`). The C references structurally cannot have this.
- **No resident root key**: the MKEK is a `FusedKey = fn() -> Option<[u8; 32]>` read per
  operation into a `Zeroizing` local (`kdf.rs:41-53`) — the exposure window is one operation.
- **Fail-closed fault semantics**: `Storage::last_error` separates "absent" from "read failed",
  so a transient flash fault cannot be memoized as absence — the concrete attack it closes is
  re-seeding PIV factory PIN/PUK over the owner's on a faulted probe
  (`storage.rs:28-46`; `fs.rs:243-341`).
- **A formalized power-cut oracle**: atomicity/durability predicates (`powercut.rs:33-48`) run
  under Kani and a fuzz target against the *real* backend, with a documented torn-header
  argument (`rsk-store/src/lib.rs:246-260`).
- Hot-path partitioning: counters isolated from credential pages (`flash_storage.rs:36-45`).

**Weaknesses**
- **`get_chipid().unwrap_or(0)`** (`main.rs:541` — verified by hand): a transient OTP read
  fault at first boot yields `serial_hash = SHA256(0)` — a constant across all devices — for
  the *entire life of the device*. Should be a fatal boot stop.
- **The pre-OTP arm is paper armor** (`kdf.rs:84-86`), and the chipid is displayed on-device
  (`main.rs:1127-1130`) while the USB serial is a fixed constant — anyone with the board plus a
  dump recomputes `kbase`.
- Unstretched PIN verifier; lockout is warm-reset-only in an **unauthenticated** watchdog
  scratch tag (`pin_lock.rs:36-40, 77-98`).
- Truncated flash enumeration is recorded but `remaining_rk` does not consult it, so getInfo
  `0x14` can over-promise after a read fault (`fs.rs:268-300, 429-431`).
- No automatic compaction for ordinary credential updates: superseded sealed bodies stay
  dump-readable until the ring naturally sweeps (`rsk-store/src/lib.rs:200-235`).
- Vendor `0x41` UNLOCK is deliberately ungated — a host that captured the lock key once owns
  the device until power-off (`vendor.rs:583-590`).

---

## 4. Per-applet verdicts

| Applet/feature | Best reference | Why | Worst gap anywhere |
|---|---|---|---|
| FIDO2 resident credentials | pico-fido (design) | full identity AAD, A/B manifests | plaintext RP/user metadata at rest (pico-fido) |
| U2F | pico-fido | stateless handles, constant-time MAC | shares the single `keydev` root |
| OATH | pico-fido | transactional containers | worst anti-dump: secrets wrap under `kbase` alone |
| Yubico OTP | pico-fido | per-slot FID-separated keys, zeroize after use | session counter persists only on wrap |
| OpenPGP | pico-openpgp | manifest/payload root split | PIV-domain shortcut puts keys under the public root |
| PIV / HSM keys | pico-hsm | policy-as-data sealed into records | session tokens in BSS, never zeroized |
| Vault / backup | pico-fido | domain-separated layer keys, double-wrapping, best zeroize | bottoms out in `keydev` anyway |
| PIN / authorization | pico-hsm | declarative facts + session epoch | **all four: unstretched KDF** |
| Vendor/management channel | RS-Key | FIPS-profile refusals, PQ hybrid MSE, journal events | ungated UNLOCK |
| Board security provisioning | pico-hsm | replica rows, chaff, page locks, KEY_INVALID | hardcoded BOOTKEY (pico-openpgp, pico-hsm) |

---

## 5. The weaknesses every reference shares

These are the industry-of-references floor. fapico2 should be judged against them, and should
beat them categorically rather than match them.

### 5.1 The serial-derived fallback root

pico-fido ships it as the default (`otp_rp2040.c:36-38` + `"NO-OTP"` salt); pico-openpgp has
the same fallback and the RP2040 serial is the flash chip's own ID, readable off-board;
RS-Key has the "pre-OTP arm" and shows the chipid on screen. Only pico-hsm refuses to derive a
root without provisioning. **fapico2 already refuses to boot** (`boot.rs:1191-1197`) — which is
why the board can freeze, but also why a stolen fapico2 flash dump is inert in a way no
reference's is. The correct target is *both*: refuse on a missing root (as today) and
**provision the OTP root at manufacture** so the refusal never fires in the field.

### 5.2 The unstretched PIN verifier

~3–5 hash operations per guess in all four (`crypto_utils.c:44-56` in the shared SDK;
`kdf.rs:92-106` in RS-Key). Once the root is out of the way — via §5.1 or a chip-level OTP
extraction — a 4–8 digit PIN falls in seconds to hours, offline, with no rate limit that
survives a flash write rig. fapico2 stretches its verifier with clamped rounds
(`device_keystore.rs` `pin_iter`/`PIN_VERIFIER_ROUNDS`), which is a lead worth extending to a
modern memory-hard KDF *bounded* so an attacker-crafted iteration count cannot wedge the PIN
path — the clamp is what makes raising the floor safe.

### 5.3 Metadata harvest

Plaintext RP IDs / user names at rest (pico-fido `resident_container.c:326-335`, plaintext
descriptors in the others' manifests). CTAP2.1 legitimately requires enumerating RP IDs *after*
PIN authentication — which does not force storing them in plaintext *at rest*. The stronger
design is the one already in the EPIC: an index of truncated `HMAC(k_index, rp_id_hash)` tags
in plaintext, names sealed in the record body, so a dump yields pseudonymous site tags rather
than an account list.

### 5.4 Soft, tamperable lockout state

Retry counters in plain flash bytes (re-initialised when erased — pico-openpgp `openpgp.c:448`),
power-cycle latches in RAM (pico-fido), unauthenticated scratch registers (RS-Key). The durable
counter is only as strong as the flash write rig the attacker holds. The fix is monotonic,
MACed, or OTP-backed attempt state — see §8.

---

## 6. What the RP2350 board offers, and who uses it

Full inventory in the sub-review; the verified highlights:

| Feature | Available | pico-fido | pico-openpgp | pico-hsm | RS-Key | fapico2 |
|---|---|---|---|---|---|---|
| TrustZone / SAU (8 regions) | yes | ignored | ignored | ignored | image marked secure, no split | **ignored** (documented risk only) |
| Signed secure boot | yes | stubbed on Pico | hardcoded BOOTKEY | **best**: replicas, KEY_INVALID, page locks | reported, host ritual | host side done; **device side dead code with a wrong row map** |
| OTP durable page locks | yes | no | runtime only | **yes** | **yes** (SW_LOCK + LOCK1 burn) | runtime-only (D-14) |
| Hardware SHA-256 | yes (`pico_sha256`) | ignored (`MBEDTLS_SHA256_ALT` off) | ignored | ignored | ignored | ignored (software `sha2`) |
| Hardware TRNG | yes | via `pico_rand` | via SDK | via `pico_rand` | **used** + HMAC-DRBG whitening | **used, sole entropy source**, incl. an embassy config-restore workaround |
| Glitch detectors (×4) | yes | ignored | opt-in via secure lock | enabled at max sensitivity under secure lock | reported only | **ignored** |
| Debug disable | yes (irreversible OTP) | no | opt-in | under secure lock | reported only | **opposite: SWD/RTT is the diagnostic channel** |
| Flash encryption | **no** — verified absent from `xip.h`/`qmi.h` | — | — | — | — | AEAD sealing is the only defense, and fapico2 already does it |

### 6.1 Read this table as the roadmap

The board's cheap, unadopted controls are all OTP rows: `CRIT1` carries
`SECURE_BOOT_ENABLE`, `DEBUG_DISABLE`, `SECURE_DEBUG_DISABLE` and `GLITCH_DETECTOR_ENABLE`
with a 2-bit sensitivity field (`otp_data.h:314-369`); durable page locks for the key row live
at `0xF80–0xFFF`. Burning them is provisioning-time work measured in bytes, and fapico2 already
has the device-side scaffolding (`platform/src/boot_key.rs`, the rescue applet's provisioning
path, the US-921 edge-latch button gate).

### 6.2 New defect found in fapico2 during this review

`platform/src/boot_key.rs` (758 lines) implements secure-boot provisioning against a layout of
`rows: 48`, `first_key_row: 0x08`, 4 key slots and `OTP_ROW_BYTES: usize = 64`
(`boot_key.rs:162, 285-289, 318`). The RP2350 bootrom's real key material lives at
`BOOTKEY0 = rows 0x80–0x8F` and `BOOTKEY1 = 0x90–0x9B` — two slots, 16-bit ECC rows
(`pico-sdk/.../regs/otp_data.h:1488-1760`), and `embassy-rp` reads ECC rows as `u16`
(`otp.rs:50`). Nothing calls `boot_key.rs` — the only `Otp` implementation is a test fake, and
the module docs admit the divergence (`boot_key.rs:138-146`). **It is a parallel,
bootrom-incompatible encoding of a bootrom mechanism, dead in the tree.** It must be either
reconciled to the real row map or deleted before US-1534's provisioning work can build on it.

---

## 7. Where fapico2 already leads

Honest scoring requires this section. fapico2 is not behind the references on everything:

1. **No fallback root.** The references that ship a serial-derived fallback are *recoverable*
   off-board by design; fapico2 halts. (The halt is also the freeze — the answer is
   provisioning, not degradation.)
2. **Stretched, clamped PIN verifier.** All four references fail §5.2; fapico2 does not.
3. **Transactional mutations that cannot wedge.** SOAK-FINDING-1's dirty-latch failure mode —
   accepted-then-unpersistable state answering every command with `INVALID_COMMAND` — is
   prevented structurally by `store_credential_checked`/`grow_checked` serialize-ahead-rollback.
   pico-fido needed a 24-hour soak to find the same class of bug.
4. **Measured capacity.** `docs/capacity.md`'s discipline ("measured, not derived"; OATH's
   `MAX_CREDS = 68` is "a heapless table bound, never a capacity claim") has no equivalent in
   any reference — pico-fido's credMgmt metadata reports `remaining = 256` when full, because
   of an unchecked `uint8_t`.
5. **Gate culture.** bss ceiling, async-frame bound, erase budget read back out of source,
   flash ratchet, reproducible UF2 — none of the four references pin their resource budgets at
   all.
6. **Host/device twin testing.** `device_core.rs` is no_std-but-host-compiled and driven
   through the real command path (`credmgmt_ctap2_spec.rs::device_twin`). The C references
   test on hardware or not at all.

---

## 8. What makes fapico2 categorically stronger

Ranked by security value per unit of cost. Items 1–4 are the "use every spec the board makes
available" answer; item 5 is the storage refactor already planned in
`docs/tasks/EPIC-secure-storage.md`.

1. **Burn the four cheap OTP controls at provisioning** *(decided, then deferred — see
   `docs/adr/0002-provisioning-policy.md`: alpha/beta images keep the debug port; `-release`
   tags mark the closure boundary; the burn epic waits for system maturity).*
   `CRIT1.SECURE_BOOT_ENABLE`,
   `DEBUG_DISABLE`/`SECURE_DEBUG_DISABLE`, `GLITCH_DETECTOR_ENABLE` at max sensitivity, and
   durable page locks for the 0xE90 key row (closing the runtime-only D-14 gap). This is the
   E24 fault-injection and SWD-exfil class from the round-2 assessment, closed for the cost of
   a few OTP rows — and it is *more* than pico-fido, pico-openpgp or RS-Key do. The
   prerequisite is §6.2: reconcile or delete `boot_key.rs` first.
2. **Provision the OTP root at manufacture.** Converts §5.1 from "the device halts" into "the
   device never needs the halt", which also disarms the boot freeze: a provisioned board never
   reaches the `read_otp_key_1 → None` path that parks it.
3. **Make the PIN the last line, not the only line.** Extend the stretched verifier toward a
   memory-hard KDF (bounded, so the clamp story survives), and move retry state to a MACed
   monotonic counter. Every reference fails here; this is where fapico2 is categorically
   stronger, and it costs software only.
4. **Adopt the enforcement patterns, not just the AEAD.** From RS-Key: fail-closed fault
   semantics (fault ≠ absent), `FusedKey` per-operation key reads, and type-level key-slot
   chokepoints — the last is where being Rust is a real advantage over all three C references.
   From pico-hsm: policy-as-data sealed into the record AAD, and session-epoch binding. From
   pico-openpgp: the manifest/payload root split, so a dump is auditable without the PIN.
5. **The per-record store** (EPIC §4 Phases B–E) adopts the shared best architecture — identity-
   bound per-record AEAD, two-slot A/B with equal-generation rejection, HMAC-tag index — on top
   of which 1–4 make fapico2 the strongest of the five implementations rather than the best
   architected of the weakest.
6. **TrustZone is the one feature with a higher ceiling than all of the above** — keys in
   secure SRAM, non-secure isolation — and an order-of-magnitude higher cost: no embassy or SDK
   scaffolding, a two-state image to write, and no incremental adoption path. It should be an
   ADR decision, not a story in this epic.

---

## 9. Verification status

Claims in this document come from five adversarial source reviews. Re-verified by hand in this
session: the `NO-OTP`-as-default mechanism (`otp_rp2040.c` returns NULL), the OpenPGP
storage-location override (`device_shell.rs:123` — and the associated withdrawn defect, §1.3 of
the EPIC), the `boot_key.rs` row-map mismatch against `pico-sdk`'s `otp_data.h` and
embassy-rp's OTP geometry, RS-Key's `chipid().unwrap_or(0)` and its `NO-OTP` arm, and the
RP2350 flash-encryption absence (no `encrypt` in `xip.h`/`qmi.h`). The remaining
reference-internals claims — pico-hsm's `session_pin` zeroize gap, pico-fido's
`uint8_t existing` overflow, the relocation-path scrub gap — are cited from the sub-reviews
with file:line and were not independently re-executed; they are consistent with the earlier
mechanism surveys in this session and are flagged here so a reader knows which claims to
re-check first if one of them matters to a decision.
