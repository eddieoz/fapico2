# US-413 migration feasibility — C firmware data formats (verified against the frozen C tree)

**Status:** Verified 2026-09-11 against `git/pico/pico-fido2/` (frozen, read-only,
SDK subtree `pico-keys-sdk/`). Every claim carries `file:line` evidence. All
paths below are relative to `pico-fido2/`.

**Corrections vs the Phase-6 epic baseline facts (15–16), marked per the
superseded-claims rule:**

1. `pico_serial_hash` is **32 bytes**, not 16 (`serial.h:37`,
   `serial.c:250-271`). It is the full `SHA-256(pico_serial.id)` where
   `pico_serial.id` is the 8-byte flash UID on RP2 (`pico_get_unique_board_id`).
   The HKDF salt length is therefore 32.
2. There are **no `0xB0–0xB4` OATH or `0xB6–0xB9` OTP FIDs** in the C tree.
   OATH credentials live at `0xBA00–0xBAFE` (+ `0xBAFF` code), OTP slots at
   `0xBB00–0xBB03` (`src/fido/files.h:23-48`; verified by tree-wide grep).
3. *(Found while implementing S-413-3.)* The C FS record `fid` and length
   fields are **little-endian**, not big-endian: the C reader decodes
   `v |= p[i] << (8 * i)` (`low_flash.c:433-441` `flash_read_uint16`, same
   shape for `flash_read_uint32`) and the writer programs the fid/length
   with raw `flash_program_halfword`/`flash_program_word`
   (`flash.c:228-231,248`). The record *pointers* (`next`/`prev`) are also
   native LE `uintptr_t`. (The PKOR/PKOC object-container fields are
   big-endian — `put_uint*_be` — but that is a separate layer.) The reader
   in `platform/src/cfs.rs` decodes LE accordingly.

---

## 1. C flash FS record format

### 1.1 Record layout (backward linked list)

`pico-keys-sdk/src/fs/flash.c:42-49`:

```
| next_addr | prev_addr | fid | len16 | payload      | legacy
| next_addr | prev_addr | fid | FFFF  | len32 | data | extended
```

- `next` points to the **older** record (written first); `prev` points to the
  **newer** record / head address. Both are 4-byte absolute XIP addresses
  (native LE).
- `fid`: `uint16_t` **little-endian** at record offset 8; length: `uint16_t`
  LE at offset 10, or the escape value `FLASH_FILE_EXTENDED_LENGTH 0xffff`
  (`flash.h:26-28`) followed by a `uint32_t` LE length at offset 12 (extended
  format; payload then starts at offset 16 instead of 12).
- Records grow **downward** from `end_data_pool`; a new record's `next` = old
  head target, `prev` = head address, and the old record's `prev` is patched to
  the new record before the head is published (`flash.c:85-142`, publish at
  `flash.c:249`). In-place overwrite when the payload fits
  (`flash.c:196-208`); otherwise allocate + unlink old via `flash_clear_file`
  (`flash.c:255`, `file.c:663-697`).
- The walk (`file.c:327-364`): `base = flash_read_uintptr(endp)`, loop while
  `base >= startp`; `fid = read_u16(base+8)`; `stored = read_u16(base+10)`;
  `len = stored == 0xffff ? read_u32(base+12) : stored`; payload pointer =
  `base+8+2+2` (legacy) / `base+16` (extended).

### 1.2 Pool bounds (`flash.c:60-68`, `flash_set_bounds`)

```
end_flash      = end                       (partition end after the 8 KB reservation)
end_rom_pool   = end_flash - 8 - 4         (FLASH_DATA_HEADER_SIZE = uintptr+u32)
start_rom_pool = end_rom_pool - 16384      (FLASH_PERMANENT_REGION = 4 sectors)
end_data_pool  = start_rom_pool - 8
start_data_pool = start
```

The file-list head pointer is the `uintptr_t` at `end_data_pool`. Hard init
writes 8 zero bytes there (`file.c:310-315`); the scan then sees `base == 0`
⇒ empty list.

### 1.3 State discrimination (reader requirements → S-413-3)

- **FactoryFresh** — `file_scan_flash` (`file.c:365-380`) reads two words at
  `end_rom_pool`; if both are `0xFFFFFFFF` or `0xEFEFEFEF` the partition was
  never initialized. This includes an all-`0xFF` (never touched) partition —
  the C boot path treats erased flash as "first initialization".
  *(Implemented verbatim in `platform/src/cfs.rs`; the S-413-3 story text's
  "all-0xFF ⇒ Empty" case therefore classifies as `FactoryFresh` — the
  migration outcome is identical: no records, no store writes. `Empty` is
  the hard-initialized-but-file-less state: head word = 0.)*
- **Empty** — head at `end_data_pool` is 0 after the hard-init zero block
  (`file.c:310-315`) ⇒ no records.
- **Used** — otherwise follow the `next` chain down to `start_data_pool`.

### 1.4 Addressing

`flash_read`/`flash_program_*` take absolute XIP addresses
(`low_flash.c:365-420`); erase is `flash_range_erase(addr - XIP_BASE, …)`
(`low_flash.c:122-123`). The Rust reader maps a C-record address to a
partition offset as `addr - 0x10000000 - data_start_addr`.

## 2. C data partition (RP2350)

- **pt.json** (`pico-keys-sdk/config/rp2350/pt.json`): partition 1
  "PicoKeys Data", **start "1032K" = 0x102000, size "3064K"** ⇒ range
  `[0x102000, 0x400000)`; family "data", not booted. Partition 0 = firmware
  (0–1024 K), partition 2 = "PicoKeys Binding" (1024 K, 8 K).
- **Runtime resolution** (`low_flash.c:200-222`): `rom_load_partition_table`
  into a 4 KiB-aligned workarea, then
  `rom_get_partition_table_info(workarea, 0x8, PT_INFO_PARTITION_LOCATION_AND_FLAGS | PT_INFO_SINGLE_PARTITION | (1<<24))`
  (`boot_partition = 1`). Sector decode:
  `first = w & 0x1fff` (FIRST_SECTOR_LSB 0),
  `last = (w >> 13) & 0x3ffe`-shaped field (LAST_SECTOR_LSB 13; pico-sdk 2.3.0
  `PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS = 0x03ffe000`);
  `data_start_addr = first * 4096`, `data_end_addr = (last+1) * 4096`, then
  **`data_end_addr -= 2 * FLASH_SECTOR_SIZE` (8 KB reservation)** at
  `low_flash.c:222`. Fallback when the ROM table is unavailable:
  `data_start_addr = FLASH_SIZE/2; data_end_addr = FLASH_SIZE`
  (`low_flash.c:210-212`).
- **PICOBIN partition-table block**: the table exists only inside the C
  *image* (embedded by `pico_embed_pt_in_binary`,
  `picokeys_sdk_import.cmake:678`) — flashing the Rust image removes it, so
  S-413-2 must embed an equivalent block in the Rust UF2. Block marker
  `0xffffded3` (pico-sdk `boot/picobin.h:25`
  `PICOBIN_BLOCK_MARKER_START`), partition-table item id `0x0a`
  (`boot/picobin.h:42`).

## 3. C key hierarchy (→ S-413-4 `ckey.rs`)

### 3.1 Serial hash

- `pico_serial_hash[32]` (`serial.h:37`); computed once in `serial_init`:
  `mbedtls_sha256(pico_serial.id, sizeof(pico_serial.id), pico_serial_hash, false)`
  (`serial.c:250-271`). On RP2, `pico_serial.id` = 8-byte flash UID. Rust:
  `SHA256(flash_uid)` via embassy-rp; salt = all 32 bytes.

### 3.2 otp_key_1 (OTP_MKEK_ROW)

- `#define OTP_MKEK_ROW 0xE90` (`otp/otp_rp2350.c:33`); `otp_key_2` =
  `OTP_DEVK_ROW 0xE80` (line 34; not needed for migration).
- Read: `otp_buffer(row)` = memory-mapped `OTP_DATA_BASE + (row*2)`
  (`otp_rp2350.c:69-72`) — ECC mode, 2 bytes per row; a 32-byte key occupies
  rows `0xE90..0xE9F`. Protection is **software write-lock only**
  (`otp_hw->sw_lock[page]`, `otp_rp2350.c:94`) — **no read protection, no
  CryptoCell**; a non-secure Rust app can read it identically.
- Provisioned at first boot by `otp_platform_init` (`otp_rp2350.c:257-301`);
  migration aborts with `CState::NeverBootC` when the row is all-zero
  (C never initialized).

### 3.3 kbase

`crypto_utils.c:34-42`:

```
kbase = HKDF-SHA256(salt = pico_serial_hash [32],
                    IKM  = otp_key_1 [32, OTP row 0xE90],
                    info = "DEVICE/ROOT", L = 32)
```

No-OTP fallback (`otp_key_1 == NULL`): salt = `"NO-OTP"`, IKM =
`pico_serial_hash` (`crypto_utils.c:35,40`). The migration path uses the
primary formula only (OTP row present on any C-used device).

### 3.4 FIDO keydev (`EF_KEY_DEV 0xCC00`) unwrap — `src/fido/fido.c:227-287`

| Stored size | Format byte | Unwrap |
|---|---|---|
| 32 B | — (raw) | `AES-256-CBC(otp_key_1, IV = 0)` decrypt (`fido.c:239-243`) |
| 33 B | `0x01` | payload = bytes 1..33; `AES-256-CBC(kbase, IV = pico_serial_hash)` (`fido.c:275-278`); write path `encrypt_keydev_f1` `fido.c:374-389` |
| 61 B | `0x02` / `0x03` | **PIN-wrapped**: `decrypt_with_aad(session_pin, bytes 1..61 [12 B nonce ‖ 32 B ct ‖ 16 B tag], version = 3?2:1)` then `AES-256-CBC(kbase, IV = pico_serial_hash)` on the 32-B result (`fido.c:245-274`) ⇒ **NeedsPin** (S-413-6) |

`decrypt_with_aad` / `encrypt_with_aad` (`crypto_utils.c:81-148`): AES-256-GCM,
key = `pin_derive_kenc(pin_token)` (v1) / `pin_derive_kenc2` (v2) — both
HKDF-SHA256 chains salted with `pico_serial_hash` (`crypto_utils.c:58-75`),
AAD = `pico_serial_hash`, layout `[12 B nonce | ct | 16 B tag]`
(`12 + 32 + 16 = 60`).

- `EF_KEY_DEV_ENC 0xCC01` present without a usable `0xCC00` ⇒ **NotMigratable**
  (vendor ChaChaPoly-wrapped key; vendor-only key material).

## 4. PKOR / PKOC object-container record crypto

Files: `pico-keys-sdk/src/fs/object_container.c/h`,
`object_crypto_provider.c/h`, `object_store.h`.

- **Magics** (`object_container.c:74-76`): manifest `"PKOC"`, record `"PKOR"`,
  record-id state `"PKRI"`.
- **Sizes** (`object_container.h:23-34`): manifest format version 1, header
  32 B, descriptor 36 B, max 8 objects/manifest; record format version 1,
  header 40 B, nonce 12 B, AAD 55 B, policy hash 16 B. Tag 16 B
  (`object_store.h:31` `FILE_OBJECT_AUTH_TAG_SIZE`).
- **Manifest header (all BE)** — encode `object_container.c:258-270`:
  `magic[4] | version@4 | header_size@5 | flags u16@6 | namespace_id u16@8 |
  container_kind u16@10 | container_id u32@12 | generation u32@16 |
  previous_generation u32@20 | object_count u16@24 | reserved@27(=0) |
  extensions_size u16@28 | total_size u16@30` then N × 36-B descriptors,
  extensions, trailing 16-B HMAC tag.
- **Descriptor (36 B, BE)** — `object_container.c:33-45,182-196`:
  `object_type u16@0 | object_tag u16@2 | generation u32@4 | logical_size u32@8 |
  record_id u64@12 | stored_size u32@20 | policy_id u16@24 | key_domain u8@26 |
  protection u8@27 | flags u16@28 | extension_offset u16@30 | extension_size u16@32 |
  transaction_group u16@34`.
- **Record header (40 B, BE)** — `object_container.c:357-377`: `PKOR` magic,
  version@4, protection@5, header_size u16@6, `record_id u64@8`,
  `stored_size u32@16`, `logical_size u32@20`, `generation u32@24`,
  **nonce @28 = `record_id u64 BE ‖ generation u32 BE`** (cross-checked at
  `object_crypto_provider.c:132`).
- **AAD (55 B)** — `object_container.c:420-459`: `PKOR` + version + ns u16@5 +
  kind u16@7 + container_id u32@9 + type u16@13 + tag u16@15 + generation u32@17
  + logical_size u32@21 + policy_id u16@25 + policy_hash 16 B@27 + key_domain@43
  + protection@44 + flags u16@45 + record_id u64@47.
- **Key derivation** (`object_crypto_provider.c:42-44,63-102`):
  - manifest key = `HKDF-SHA256(root, info = ns u16 BE ‖ "PKOC/manifest/v1")`
  - domain key = `HKDF-SHA256(root, info = ns u16 BE ‖ key_domain u8 ‖ "PKOC/domain/v1")`
  - record key = `HKDF-SHA256(domain_key, info = "PKOC/object/v1" ‖ AAD[55])`
- **Seal/unseal** (`object_crypto_provider.c:171-245`): AES-256-GCM with the
  12-B record nonce and the 55-B AAD, 16-B tag;
  `FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC` (1) stores the plaintext in
  the clear with a truncated-16 `HMAC-SHA256(key, AAD ‖ nonce ‖ stored)` tag
  (`object_crypto_provider.c:143-169`); `AEAD_SECRET` = 2. Manifest
  authenticator = streaming HMAC-SHA256 over the manifest with the manifest key
  (`object_crypto_provider.c:266-315`).
- **Record-id allocator** — `"PKRI"` state block: version@4, high-water `u64 BE`@8,
  written to two recovery slots (`object_container.c:531-590`).

`root` for these derivations is the C root key established per namespace;
S-413-4 must mirror the exact chain above (root = kbase-rooted per class, cf.
PIV usage) — any deviation is caught by the known-answer tests before locking.

## 5. Per-class FID tables (C tree, `src/fido/files.h` / `src/openpgp/files.h`)

| Class | FID(s) | Evidence |
|---|---|---|
| FIDO keydev | `EF_KEY_DEV 0xCC00` | `src/fido/files.h:23` |
| FIDO vendor keydev | `EF_KEY_DEV_ENC 0xCC01` | `src/fido/files.h:24` |
| FIDO vault key / label | `EF_VAULT_KEY 0xCE03`, `EF_VAULT_LABEL 0xCE04` | `src/fido/files.h:27-28` |
| FIDO counter/opts | `EF_COUNTER 0xC000`, `EF_OPTS 0xC001` | `src/fido/files.h:29-30` |
| FIDO credentials / RPs | `EF_CRED 0xCF00` (…0xCFFF), `EF_RP 0xD000` (…0xD0FF) | `src/fido/files.h:41-42` |
| Large blob | `EF_LARGEBLOB 0x1101` | `src/fido/files.h:43` |
| OATH creds / code | `EF_OATH_CRED 0xBA00` (…0xBAFE), `EF_OATH_CODE 0xBAFF` | `src/fido/files.h:44-45` |
| OTP slots | `EF_OTP_SLOT1..4 0xBB00..0xBB03`, `EF_OTP_PIN 0x10A0` | `src/fido/files.h:46-51` |
| Management config | `EF_DEV_CONF 0x1122` | `src/fido/files.h:38`, `src/openpgp/files.h:178`; write `src/fido/management.c:183-204`, read `management.c:95-174` |
| OpenPGP PIN hashes | `EF_PW1 0x1081`, `EF_RC 0x1082`, `EF_PW3 0x1083` | `src/openpgp/files.h:26-28` |
| OpenPGP public keys | `EF_PK_SIG/DEC/AUT 0x10D1..0x10D3` | `src/openpgp/files.h:29-31` |
| OpenPGP binding sigs | `EF_PB_SIG/DEC/AUT 0x10D4..0x10D6` | `src/openpgp/files.h:32-34` |
| OpenPGP DEK (legacy) | `EF_DEK 0x1099` | `src/openpgp/files.h:40` |
| OpenPGP DEK wrappers | `EF_DEK_PW1 0x109A`, `EF_DEK_RC 0x109B`, `EF_DEK_PW3 0x109C`, `EF_DEK_PWPIV 0x109D` | `src/openpgp/files.h:41-44` |
| PIV (deferred) | `EF_PIV_PIN 0x1184`, `EF_PIV_PUK 0x1185`, `EF_PIV_ADMIN_DATA 0xFF00`, certs `0xC101…` | `src/openpgp/files.h:101-152` |

## 6. OpenPGP DEK (private-key wrapping; → S-413-6 passphrase flow)

- **Sizes** (`src/openpgp/openpgp.h:116-120`): `DEK_SIZE = 48`
  (`IV_SIZE + 32`), `DEK_AAD_SIZE = 76` (`PIN_KDF_SIZE(48) = 12+48+16`,
  `crypto_utils.h:74`), `DEK_FILE_SIZE = 77`, `DEK_FILE_SIZE_OLD = 144`.
- **New format** — `EF_DEK_PW1 (0x109A)`: `[0x03] ‖ encrypt_with_aad(session_pw1, DEK, PIN_KDF_V2)` →
  1 + 76 B. Bootstrap `src/openpgp/openpgp.c:384-395`; unlock `load_dek`
  `openpgp.c:637-734` (`ef_data[0] == 0x3` branch at `openpgp.c:655-662`).
  `session_pw1 = pin_derive_session(PW1)` (`crypto_utils.c:58-63`).
- **Legacy format** — `EF_DEK (0x1099)`, 144 B:
  `AES-256-CFB-256(session_pw1, IV = first 32 B, data = next 32 B)`
  (`openpgp.c:655-662`, helper `crypto_utils.c:275-280`). Same shape for
  RC/PW3/PWPIV (`openpgp.c:676-706,720-728`).

## 7. Rust re-seed targets (SecureStore v2)

- **Image format** (`platform/src/secure_store.rs:29-37`): magic
  `0x4632_5350` (LE bytes `"PS2F"`) + entry count u32 + entries
  `[key_len u32 | key | val_len u32 | val]` + CRC-32 u32; device store
  `DEV_MAX_VALUE_LEN = 512` (`secure_store.rs:371`).
- **Dual slot** (`firmware/src/main.rs:93-102`): primary at flash
  **`0x103F0000`** (`SECURE_PRIMARY_OFFSET 0x3F_0000`), shadow at
  `0x103F0000 + SECURE_SLOT_BYTES` (≈ `0x103F3000`). `0x103F0000` sits inside
  the C partition range but in the C rom-pool region the C never writes for
  `FILE_PERSISTENT` rows — no live C data there.
- **Slot names** (v1.0.0): `fido.hkey` (32 B keydev, hname used by
  `secure_store.rs:604`), `fido.keystore.v1` (CBOR keystore snapshot,
  `apps/fido/src/keystore.rs:330`), `piv.keystore.v1`, management
  `EF_DEV_CONF` blob slot (bounded 512 B, `apps/mgmt/src/lib.rs:87`), OATH and
  OTP keystore slots (naming fixed at S-413-5).

## 8. Per-class migration verdicts

| Class | Verdict | Basis (evidence) |
|---|---|---|
| FIDO keydev, 32 B / 33 B record | **Silent** | Unwrap needs only `otp_key_1` + `kbase` (`fido.c:239-243,275-278`) |
| FIDO keydev, 61 B record | **Conditional — PIN** | `decrypt_with_aad(session_pin, …)` needs the user PIN (`fido.c:245-274`) ⇒ `NEEDS_PASSPHRASE` until S-413-6 |
| FIDO vendor keydev (`EF_KEY_DEV_ENC 0xCC01` only) | **NotMigratable** | Vendor-held ChaChaPoly key; no device-side unwrap exists |
| FIDO credentials (`0xCF00…`), RPs (`0xD000…`), large blob (`0x1101`) | **Silent** (data re-seed; CTAP2 serving is post-cutover) | Plaintext/keystore-wrapped records; snapshot into `fido.keystore.v1` |
| OATH creds (`0xBA00–0xBAFE`, `0xBAFF`) | **Silent** | Stored records; re-seed into OATH keystore slot (app restore post-cutover) |
| OTP slots (`0xBB00–0xBB03`, `0x10A0`) | **Silent** | Stored records; re-seed into OTP keystore slot |
| Management `EF_DEV_CONF 0x1122` | **Silent** | Verbatim blob copy (`management.c:183-204`) |
| PIV objects (kbase-rooted) | **Silent re-seed** into `piv.keystore.v1`; PIV serving remains **deferred** | kbase derivable without user input (§3.3) |
| OpenPGP public keys / certs / DOs / PIN hashes (`0x10D1–0x10D6`, `0x1081–0x1083`, …) | **Silent** | Stored records, no DEK involved |
| OpenPGP private keys (`EF_DEK_PW1 0x109A` new / `EF_DEK 0x1099` legacy) | **Conditional — PW1** | Wrapped under `session_pw1 = pin_derive_session(PW1)` (`openpgp.c:384-395,637-734`) ⇒ `NEEDS_PASSPHRASE` until S-413-6 |

Detection guards (S-413-5): migration runs only when
`CState::Used` ∧ OTP row `0xE90` non-zero (`NeverBootC` otherwise) ∧ Rust
store empty ∧ no migration-complete marker; otherwise skip silently
(idempotent). The C partition is read-only for the entire flow —
byte-identity is test-enforced.
