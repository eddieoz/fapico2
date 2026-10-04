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
| OATH reservation | 68 | `oath_core::MAX_CREDS`, a `heapless` **table** bound — it sizes the RAM array and nothing else |
| commit scratchpad | 4 | one whole NOR sector, staged through (US-1544) |
| index reservation | 32 | `index::INDEX_SLOT_COUNT` — one entry per slot in the region, rounded up to whole sectors |
| **FIDO resident credentials** | **856** | 960 − 68 − 4 − 32 |
| **OATH credentials** | **68** | as above |

Raising either capacity requires a region that fits it; the compile-time
assertions in `keyregion/mod.rs` stop the build otherwise. That is the whole
point — the old failure was a constant no region could contradict.

**No slot is reserved.** The epic proposed leaving ~500 KB spare; with
per-record commits there is nothing to spend it on, because the spare existed
to hold both generations of a double-buffered rewrite, which is exactly the
cost this design removes. Capacity runs 3.3× the acceptance floor instead, and
acceptance criterion 2's "≥500 KB spare" is therefore **not met, deliberately**.

## The 856 is measured, not asserted (US-1563)

The table above is a **derivation**. It says the region is 960 slots and the
four reservations tile it — and the compile-time assertions in
`keyregion/mod.rs` check that the tiling is exact. What it does *not* say is
that one enrolment really consumes one slot: a commit could strand a slot, a
delete could leak one, an index write could fail and orphan a record.

So the number is **run to**:
[`apps/fido/tests/capacity_boundary.rs`](../apps/fido/tests/capacity_boundary.rs)
enrols credentials until the first refusal and checks four things:

| claim | check |
|---|---|
| the device enrols 856 | each one is written **and read back byte-identically**, with its private key and RP compared |
| the 857th is refused | `RegionCredentialError::Full` → CTAP2 `0x28` (`KEY_STORE_FULL`) |
| the count matches the derivation | the measured run equals `FIDO_CAPACITY`, and the four terms sum to `TOTAL_SLOTS` |
| nothing partial is left | exactly 856 slots occupied, each at generation 1; every slot outside FIDO's range and the whole scratchpad erased |

**Measured: 856.** Every record in that run is a real `DeviceCredential`
encoded by the applet's own codec at its maximum field sizes (63-byte RP ID,
58-byte `user.name`, 43-byte `displayName`, 64-byte `user.id`, 32-byte
`credBlob`, `largeBlobKey`, `hmac-secret`) — 596 bytes sealed, against the
836-byte bound the stride was sized from. A boundary measured over filler would
be a boundary for the filler.

The fixture was not always this. Two defects it caught, both of which are the
kind a derivation cannot see:

* an RP ID built with `n.to_le_bytes()` produced `0x80` at credential 128, and
  `push_tstr` — correctly — refused the record. A CBOR `tstr` is a UTF-8 string;
  a fixture that is not one is not measuring a credential.
* a compaction pass originally identified freeable slots by asking which were
  **erased**, which is never true after a delete — a tombstone is a record. It
  reported "nothing to free" over a sector that was full of them, and the freed
  slot was never reused.

`capacity_docs_carry_the_measured_number` in the same file reads **this
document** and fails if `856` is not in it. That is the gate the section below
says this file does not otherwise have.

## What this document is not

It has no gate — with one exception, added above: the US-1563 test reads this
file and fails if the measured figure is absent. Everything else here is the
prose view of numbers that can drift. `check_flash_budget.py` (US-1534) gates
the flash map; this file has no equivalent for the other rows.

Related: the keystore capacity layers and the durable-ack latch are recorded in
[`docs/known-gate-divergences.md`](known-gate-divergences.md) under SF-1
(including the US-1010 amendment that supersedes the earlier `≤ 16` figure).