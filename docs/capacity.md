# Capacity — hardware-verified ceilings

Where a number here is **derived**, it says so and names the derivation. Where
a compile-time constant *looks* like a capacity claim and is not, it is called
out; that gap is how the `MAX_CREDS = 68` misreading survived.

## The 24-entry store: four credentials, and the constant that was not a ceiling

- **FIDO2 resident credentials, before `FIDO-SECURE-STORE`: 4.** Measured on a
  soak board and reproduced against the device path in
  [`apps/fido/tests/key_store_ceiling.rs`](../apps/fido/tests/key_store_ceiling.rs).
- **OATH credentials, before: 30 maximal** — measured (US-1010), not derived.
  The ceiling was the chunked **part count under the double-buffered rewrite**,
  not bytes: 31 credentials fit the 5,952 B logical bound and still could not be
  made durable.
- **The store holds 24 entries** (`DEV_MAX_ENTRIES`), hardware-pinned: 32
  dark-boots, because the bss→MSPLIM stack distance scales with the count
  (DARK-BOOT-1; the reasoning and the bss ceiling that enforce it are in
  [`docs/size-report.md`](size-report.md)).
- **`DEVICE_MAX_CREDS = 12` was never a capacity.** It is the snapshot
  decoder's bound on how many credentials a snapshot may carry. Its doc comment
  claimed twelve "fits the chunked slot's 5,952-B payload capacity", which is
  arithmetic about `MAX_LOGICAL_LEN` and says nothing about the store's 24-entry
  occupancy — the constraint that actually refused the fifth credential.

The binding constraint was `other_slots + old_parts + new_parts ≤ 24`, with
`other_slots = 12` on a soak board (nine foreign applet slots, `fido.hkey`, and
the attestation scalar and certificate). Twelve credentials would have needed
`12 + 8 + 8 = 28`.

## The per-record key store: derived, not asserted

The region is `0x300_000 .. 0x3F0_000` — 960 KiB on the shipping 4 MiB `pico2`
part, reserved in the generated `memory.x` under `KEYREGION` so firmware cannot
be linked into it. Its size is board-derived (larger parts get a larger store).
The layout and every assertion about it are in
[`platform/src/flashmap.rs`](../platform/src/flashmap.rs) and
[`platform/src/keyregion/mod.rs`](../platform/src/keyregion/mod.rs).

| | value | derived from |
|---|---:|---|
| region size | 960 KiB | `flash_size_kb` − firmware − trussed − secure |
| record slot | 1 KiB | largest sealed record (836 B) + 16 B header + 128 B margin, rounded up |
| slots per NOR sector | 4 | 4 KiB erase granularity ÷ 1 KiB slot |
| total slots | 960 | region ÷ slot |
| **FIDO resident credentials** | **892** | total slots − OATH's slots |
| **OATH credentials** | **68** | `oath_core::MAX_CREDS`, a `heapless` **table** bound — it sizes the RAM array and nothing else |

Raising either capacity requires a region that fits it; the compile-time
assertions in `keyregion/mod.rs` stop the build otherwise. That is the whole
point — the old failure was a constant no region could contradict.

**No slot is reserved.** The epic proposed leaving ~500 KB spare; with
per-record commits there is nothing to spend it on, because the spare existed
to hold both generations of a double-buffered rewrite, which is exactly the
cost this design removes. Capacity runs 3.5× the acceptance floor instead, and
acceptance criterion 2's "≥500 KB spare" is therefore **not met, deliberately**.

## Still true

- **The compiled-in FIDO attestation key is a public, self-signed development
  key**; production devices generate per-device keys via TRNG.
- **U2F credentials are stateless.**

## What this document is not

It has no gate. No script and no workflow reads it, which is the same failure
mode as the 8,432 B and "~42 credentials" claims that survived as long as they
did. `check_flash_budget.py` (US-1534) gates the flash map; this file is the
prose view of the same numbers and can drift from it.

Related: the keystore capacity layers and the durable-ack latch are recorded in
[`docs/known-gate-divergences.md`](known-gate-divergences.md) under SF-1
(including the US-1010 amendment that supersedes the earlier `≤ 16` figure).