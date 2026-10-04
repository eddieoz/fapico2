# Capacity — hardware-verified ceilings

Where a number here is **derived**, it says so and names the derivation. Where
a compile-time constant *looks* like a capacity claim and is not, it is called
out; that gap is how both the `MAX_CREDS = 68` and the `MAX_LOGICAL_LEN = 5,952 B`
misreadings survived — and, before US-1564, how the `DEVICE_MAX_CREDS = 12`
reading survived two orders of magnitude.

**US-1564 added no numbers and removed none.** It corrected which of the figures
here may be called a capacity, which is the only thing that was ever wrong with
them.

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

## `MAX_LOGICAL_LEN` is a length, not a capacity either (US-1564)

The other number in that paragraph deserves its own heading, because it was
quoted as a capacity in three places and is not one.

**`chunked::MAX_LOGICAL_LEN` = 5,952 B is a *single-generation* figure.** A
chunked logical slot is double-buffered — a write goes to the buffer not holding
the current set — so a rewrite transiently holds `2 × MAX_PARTS` physical
entries, and an applet with an entry of its own needs `+1` beyond that.
`MAX_PARTS` is **12** precisely because `2 × 12 = 24` exactly exhausts
`DEV_MAX_ENTRIES` and leaves nothing for that third consumer, which is why
`secure_store.rs` keeps it at 12 with a compile-time assertion.

| reading | status |
|---|---|
| "a logical slot may be 5,952 bytes wide" | **true** — the only true thing here |
| "a device can store a 5,952-byte value" | **false** — the first full-width rewrite by an applet holding resident state returns `SecureStoreError::Full` |
| "twelve credentials fit it" | **false twice over** — the count was never derived from it, and `12 + 8 + 8 = 28 > 24` |

OATH is the worked example, and it is why this is worth a section rather than a
footnote: its table is sized for 68 and its **durable** ceiling is **30**
maximal credentials, measured (`apps/oath/tests/oath_capacity.rs`), because its
rewrite peak is `parts_live + parts_being_written + 1`. So 5,952 B has a real
consumer that provably cannot reach it, which is the sharpest available
statement of the difference.

**What was corrected, and where.** `platform/src/secure_store.rs` at the
`chunked` module header and on `MAX_PARTS` / `MAX_LOGICAL_LEN`; and
`apps/fido/src/device_keystore.rs` on `SNAPSHOT_MAX_CREDS`, where the surviving
sentence — *"it stays 12, because … `chunked::MAX_PARTS * PART_PAYLOAD_MAX` is
5,952 bytes"* — read as though the payload figure produced the 12. It never
did, and it says so now.

**No constant was changed.** Every number in this document is unchanged by
US-1564; what changed is which of them may be called a capacity. That is the
whole of the story: the defect was never an arithmetic error, it was a label.

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
| OATH **reservation** | 68 slots | `oath_core::MAX_CREDS`, a `heapless` **table** bound — it sizes the applet's RAM array, and `keyregion::OATH_CAPACITY` charges the same 68 slots to the region because a store that accepted more would refuse on a RAM bound it never mentions |
| commit scratchpad | 4 | one whole NOR sector, staged through (US-1544) |
| index reservation | 32 | `index::INDEX_SLOT_COUNT` — one entry per slot in the region, rounded up to whole sectors |
| **FIDO resident credentials** | **856** | 960 − 68 − 4 − 32, and **measured** below |

Raising either reservation requires a region that fits it; the compile-time
assertions in `keyregion/mod.rs` stop the build otherwise. That is the whole
point — the old failure was a constant no region could contradict.

**The two rows are deliberately not parallel, and US-1564 is why.** The FIDO row
is a **capacity claim** and this document measures it to the refusal (§ below).
The OATH row is a **reservation**: the region holds 68 OATH slots, and whether
any given build enrols 68 OATH credentials is a question about
`apps/oath`'s in-RAM table and its tombstone compaction, not about this region.
**No OATH enrolment count has been run to its boundary the way FIDO's has** —
`platform/tests/key_region_capacity.rs` proves the region *reserves* 68 slots
and that they tile the partition, which is a different statement from "the
device holds 68 OATH credentials".

**Served on a device build, and still a reservation rather than a measured
count.** `main.rs` now installs `oath_core::install_region_provider` after
`boot::release_key_region()`, and `attach_region_if_available` mounts on the
first command — so on hardware OATH uses the region and its ceiling is
[`MAX_CREDS`] = 68 rather than the legacy store's 30.

What that does **not** make is this a *measurement*. Two things stand between
the reservation and one, and neither is closed by the wiring:

* **The legacy path is still reachable.** `boot::derive_oath_payload_key`
  returns an `Option` and answers `None` for an unavailable OTP row rather than
  halting (S10), and a provider that yields nothing leaves the applet on the
  chunked store at its legacy ceiling. That is the right failure direction — a
  degraded applet that answers beats a board that parks — but it means the
  number an OATH build serves depends on whether the key derived.
* **No OATH enrolment count has been run to its boundary**, the same gap
  `capacity_boundary.rs` closes for FIDO. `key_region_capacity.rs` proves the
  region reserves 68 slots and that they tile the partition; that is geometry,
  not a device holding 68 credentials.

So the row keeps the word *reservation*, and the honest sentence is "the region
is mounted and its ceiling is 68 when it is", not "the device holds 68".

The earlier version of this table had a row reading **"OATH credentials | 68 |
as above"**, which quietly converted the reservation into a capacity claim. That
is the same defect the previous section is about, one row further down: a number
that looks like a measurement because it is in a table titled "derived from".

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

**And it is not a claim that any number in it is reachable.** Two specific
caveats are load-bearing and both are now stated above rather than implied:

* `MAX_LOGICAL_LEN`'s 5,952 B is a single-generation width, not a storeable
  size;
* `OATH_CAPACITY`'s 68 is a reservation, not a measured enrolment count.

The FIDO row is the only row in this document that has been **run to its
refusal**, and it says so.

Related: the keystore capacity layers and the durable-ack latch are recorded in
[`docs/known-gate-divergences.md`](known-gate-divergences.md) under SF-1
(including the US-1010 amendment that supersedes the earlier `≤ 16` figure).
## Four acceptance criteria that had to be restated (US-1566 amendment)

`docs/tasks/EPIC-secure-storage.md` is the story document for the work that
produced this file, but it is **untracked** (`.gitignore`: `docs/tasks/`), so
the divergences between its acceptance criteria and what actually shipped are
recorded here, in a file the US-1563 gate already reads. Each was a wording in
the criterion that the hardware or the design could not satisfy as written.

| Criterion as written | What shipped, and why |
|---|---|
| US-1544: "exactly one erase and one program" | **One sector**, not one slot. `SLOTS_PER_SECTOR` slots share one 4 KiB NOR sector and NOR cannot rewrite programmed bytes — the reason `commit.rs` exists at all. The consequence, that a sector's three *other* credentials survive a neighbour's update, is what is actually pinned. |
| US-1557: both twins "report the same capacity" | They cannot, and the divergence is the point. The host twin's capacity is a property of a RAM array and its store cannot reach the region. `twin_parity.rs` asserts `assert_ne!` and pins `Snapshot::advertised_capacity() == None`, so a fixture bound can never be published as a device capacity. |
| US-1546: "a region holding FIDO, OATH **and OpenPGP** records", "every slot is erased" | OpenPGP's keys are not in the key region (they are in the trussed `ifs` window), and a **FIDO** reset that erased every slot would destroy OATH's credentials — the opposite of what a scoped reset owes. `FidoRecordStore::wipe_fido_range` erases FIDO's sectors and the index tail; `reset_wipes_region.rs` pins both halves, including the refusal arm. |
| US-1573: "every absent-arm that writes state first takes a `try_` probe" | The **property** is met structurally instead. RS-Key's own docs reject that derivation method (`fs.rs:352-364`: "Do not derive the sites by asking 'does the absent arm write?' … missed six live regressions"). The store is stateless, so there is nothing to memoize a fault into, and every write already re-reads the same medium fallibly first. The one residual — a faulted `excludeList` probe reading as "not excluded", costing a duplicate credential in a free slot rather than credential loss — is recorded in §6 of the epic and is not fixed here. |

The audit that produced this table also found that **criterion 3's cited
evidence does not support it**. `apps/openpgp/tests/device_boot_order.rs`
replays a captured C-flash image across a simulated reboot; it does not
generate a key. The test that *would* show a generated key surviving a power
cycle is `key_storage_location.rs::the_generated_private_key_follows_the_card_location`,
and it is `#[ignore]`d RED against `vendor/opcard/src/command/gen.rs`, which
stamps `Location::Volatile` on a generated private key while the keyref goes to
flash — a real latent bug, reported with citations and parked as US-1537's
call rather than fixed inside a tests-only story. What US-1537 *does* deliver
is the gate: six passing tests that fail if the storage location moves.

## Two stories that shipped partly, and why

Recorded here rather than only in a module doc because this file is versioned
and already read by the US-1563 gate. Both are **partial, not deferred**, and
both name the specific thing that is missing rather than gesturing at it.

**US-1572 — no resident session keys.** The store key is done and tested
(`platform/tests/fused_key.rs`: `each_use_reads_derives_and_drops`,
`a_store_that_cannot_read_its_key_refuses_rather_than_degrading`). The BDD's
second half — "the OATH seal derived once and held for the session" becoming a
per-operation read — is **not** done, and it is not the same conversion:

`FusedKey` fuses **one** `[u8; 32]`, re-read per operation through a closure,
and that works for the store key because the store has a medium to read it back
from — its own encrypted image. `OathSeal` has no such medium and is not one
value: it is a three-field derived struct (`platform/src/ckey.rs:394-402`) —
`kenc` and `nonce_key` from two different derivations, plus a 16-byte `aad`
that is not key material at all. Converting it needs a container for a derived
*struct*, or three sources, and changes every `self.seal.*` use site in
`apps/oath`. That is a real piece of work in files this story does not own.

What it would buy, so the trade is legible: the seal is 16 bytes plus a nonce
root, resident for one session and cleared on drop. The store key was the
larger exposure and is the one US-1572 closed.

**US-1564 — capacity constants derived.** Now fully gated. The corrections
shipped earlier with nothing testing them; `capacity_boundary.rs`'s
`the_capacity_document_does_not_present_a_constant_as_a_capacity` now fails if
a table row re-presents `DEVICE_MAX_CREDS`, `MAX_LOGICAL_LEN` or OATH's 68 as a
ceiling, **and** requires the caveats to be present — deleting them would
satisfy a forbidden-wording check while making the document worse.
