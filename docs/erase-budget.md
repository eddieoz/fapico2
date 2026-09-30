# The flash erase budget (US-1010)

**What this document is.** The measurement the rest of EPIC `RS-KEY-ADOPT`
Phase 2 is judged against. It answers one question with a number instead of a
range: *how much flash is a FIDO assertion wearing out, and how many
assertions does that buy?*

> **Correction, 2026-09-28 (US-1010 review).** The first version of this
> document published an assertion ceiling of **12,500**. That figure was a
> **double-count** and it is withdrawn. The corrected ceiling is
> **100,000 assertions**. The correction is derived from first principles in
> §3.4 and gated in §3.5. The short form: the 8 sector erasures a persist
> performs land on **8 different sectors**, so each sector accumulates
> **one** erase cycle per persist; dividing the endurance figure by 8
> charged a single sector for erases that were spread across all eight. No
> measurement changed — only the divisor did.

It changes no production behaviour. It instruments the host path, records the
figures, and gates the document against them
(`tests/scripts/check_erase_budget.py`).

---

## 1. The defect, restated

Three facts compose into a lifetime defect.

1. `apps/fido/src/device_keystore.rs:1519-1547` —
   `bump_credential_counter_checked` calls `self.persist(store)` **inline on
   every `getAssertion`**. A FIDO2 sign-count bump is durable-before-ack by
   design, and this is where that guarantee is taken.
2. `platform/src/persist_sink.rs:86-111` — `FlashSlotSink::program`
   compare-then-writes each slot: a slot whose flash already matches the
   image is skipped. A counter bump *changes the image*, so the compare never
   fires and **both** slot windows are erased and reprogrammed, in full, on
   every assertion.
3. `firmware/src/boot.rs:48-49,60-61` — the slot size is
   `ceil(SECURE_PARTITION_IMAGE_MAX / 4096) * 4096` and the two slots are
   linked back to back at `0x103F0000`. `SECURE_PARTITION_IMAGE_MAX` is
   `Rp2350SecureStore::SEALED_PARTITION_IMAGE_MAX`
   (`platform/src/secure_store.rs:920-922`), bounded by the compile-time
   sizing gate at `platform/src/secure_store.rs:1261-1265` at 32,768 B.

The design intent was right; the implementation spends a whole-slot erase to
move one counter. US-1011 changes that. This document only prices it.

---

## 2. What was measured, and how

### 2.1 Measured — on the host, exactly

`platform/tests/persist_sink.rs::erase_budget_figures` drives the **real**
`FlashSlotSink` through the **real** `persist_apps` gate against the NOR-model
`FakeFlash`, over the **shipping** slot geometry, and prints the figures below.
The gate parses that output and fails if this document disagrees.

The scenario is the shipping one: a value that changes on every persist —
the shape of the FIDO sign-count bump — so the sealed image differs every
time and `slot_matches` cannot short-circuit.

The image the host store produces is far smaller than the device's 14,040-byte
sealed bound, and that does **not** flatter the figure: the sink's erase range
is `off .. off + slot_bytes` (`platform/src/persist_sink.rs:95`), fixed by the
slot geometry and entirely independent of `image_len`. Only the *program*
half is windowed over the image length. So the wear number is the shipping
wear number, and the host's smaller image changes nothing about it.

Two controls ride along; they are what make the measurement able to *fail*:

| Figure | Value | What it pins |
|---|---|---|
| `changed_erase_calls_per_persist` | 2 | one erase per slot, every persist |
| `changed_sector_erasures_per_persist` | 8 | 2 calls x 4 sectors each — the erase *operations* |
| `changed_distinct_sectors_erased_per_persist` | 8 | the 8 operations land on 8 **different** sectors |
| `changed_max_erases_per_sector_per_persist` | 1 | the busiest single sector takes **one** of them |
| `unchanged_erase_calls` | 0 | **the control** — a re-persist of the identical image must erase nothing |
| `partial_erase_calls` | 1 | a stale slot is repaired alone; the healthy one is not re-worn |

A sink that lost its compare (the pre-compare-then-write behaviour) would
still report `changed_erase_calls_per_persist = 2` — because the changed-image
path always erased both slots. Only `unchanged_erase_calls` moves, from 0 to
2. That single figure is what the gate holds, and it is why the gate measures
the code rather than only the prose.

The middle two figures are new as of the 2026-09-28 correction and are the
ones the lifetime is derived from. Before them the instrument could only say
*how many* sector erases a persist issues; it could not say *how they are
distributed*, and assuming the worst distribution (all on one sector) is what
produced the withdrawn 12,500. `platform/tests/persist_sink.rs`'s
`sector_erase_profile_since` now walks the erase log sector by sector and
counts what landed where, so the distribution is a measurement and not a
presumption.

Verbatim instrument output, as the gate compares it:

```text
ERASE_BUDGET sector_granularity_bytes=4096
ERASE_BUDGET slots=2
ERASE_BUDGET slot_bytes=16384
ERASE_BUDGET sectors_per_slot=4
ERASE_BUDGET changed_erase_calls_per_persist=2
ERASE_BUDGET changed_sector_erasures_per_persist=8
ERASE_BUDGET changed_distinct_sectors_erased_per_persist=8
ERASE_BUDGET changed_max_erases_per_sector_per_persist=1
ERASE_BUDGET unchanged_erase_calls=0
ERASE_BUDGET unchanged_sector_erasures=0
ERASE_BUDGET partial_erase_calls=1
ERASE_BUDGET partial_sector_erasures=4
```

### 2.2 Reasoned from the HAL source — the sector-split question, resolved

The EPIC flagged one ambiguity as its headline open item:

> whether the HAL splits the 32 KiB erase into 8 sector erases or one bulk op
> was not measured — US-1010 measures it.

**It splits.** Not measured on hardware — settled from the source path the
firmware actually takes. The chain, with nothing inferred:

1. `firmware/src/boot.rs:220-231` — `DevSlotFlash::erase` is
   `flash.blocking_erase(from, to)`.
2. `embassy-rp-0.10.0/src/flash.rs:148-161` — `blocking_erase` is
   `ram_helpers::flash_range_erase(from, len)`; the range is passed through
   whole, not pre-split.
3. `embassy-rp-0.10.0/src/flash.rs:528-542` — `flash_range_erase` is
   `write_flash_inner(addr, len, None, ..)`.
4. `embassy-rp-0.10.0/src/flash.rs:633-653` — the ARM path hands the bootrom
   `r0 = addr, r1 = len, r2 = 1 << 31, r3 = 0`, with the driver's own comment
   naming the call: `flash_range_erase(addr, len, 1 << 31, 0)`. Line 703 is the
   non-ARM twin and passes the same two constants.
5. Those two constants are the whole answer. The RP2350 bootrom's published
   contract for that entry point
   (`rp-hal/rp235x-hal/src/rom_data.rs:864-869`, quoting the RP2350
   datasheet §5.4.3) is:

   > Optionally, pass a block erase command e.g. D8h block erase, and the size
   > of the block erased by this command — this function will use the larger
   > block erase where possible, for much higher erase speed. addr must be
   > aligned to a 4096-byte sector, and count must be a multiple of 4096 bytes.

   `block_cmd = 0` means **no block-erase command was offered**, so the
   "larger block erase" path is not taken and the function walks the range in
   4096-byte sector erases. `1 << 31` is the sentinel that disables blocking,
   not a block size.

6. Independent corroboration from the C SDK, which drives the same bootrom
   entry point: `pico-sdk/src/rp2_common/hardware_flash/flash.c:231` passes
   `FLASH_BLOCK_SIZE` and `FLASH_BLOCK_ERASE_CMD`, defined as `1 << 16` and
   `0xd8` (`hardware_flash/include/hardware/flash.h:47`, `flash.c:21`). The C
   driver has to *explicitly opt in* to a 64 KiB chip erase. A bootrom that
   erased any range in one bulk op would make those arguments dead — and
   0xD8 over a 32 KiB range would erase the whole chip, which is not what a
   slot erase may do.

So a 16,384-byte slot erase is **4 physical 4 KiB sector erases**, and a
persist is **8**. The ambiguity is closed, and it closed on the *expensive*
side of the EPIC's range.

**What was not done.** The bootrom's own loop was not disassembled out of the
mask ROM image (`roms/rp2350/bootrom-combined.bin`); the argument above is the
ROM API contract plus the arguments the driver passes, which is a contract,
not an inference about an unread loop. A reader who wants the last degree
confirmed should count `0x20` command asserts on the QSPI lines.

### 2.3 Not measured — the device path

The device `SlotFlash` implementation is not counted programmatically, and
US-1010 did not make it so. There is **no existing vendor counter channel** to
hang a counter on: the RS-Key `0x41` CTAP2 vendor channel
(`apps/fido/src/vendor41.rs:531-567`) enumerates fourteen sub-commands
(`Mse`, `Export`, `Load`, `Finalize`, `State`, `Unlock`, `AuditRead`,
`AuditCheckpoint`, `AttImport`, `AttClear`, `AttState`, `ConfigWrite`,
`ConfigRead`, `AuditConfig`) and not one of them is a counter or telemetry
read. Building a fifteenth would be a new feature, which this story is not.

What the device does have, at zero cost, is an existing log line: every erase
followed by a successful program already emits
`defmt::info!("secure partition: programmed {=u32:x}..{=u32:x}", off, to)`
(`platform/src/persist_sink.rs:186-191`). On a board with a debug probe, one
`getAssertion` produces exactly two such lines, reproducing the measured `2`
without any firmware change. That is the reproduction recipe; it is not a
counter.

**The measurement that would close §2.2 at the hardware level** is a QSPI
logic-analyser capture across one `getAssertion`: count the chip-select
assertions carrying the 4 KiB block-erase opcode `0x20`. Four per slot, eight
per persist, is the prediction this document makes. It needs a board and a
probe, so it is outstanding and is not claimed.

---

## 3. The arithmetic

### 3.1 Inputs

| Symbol | Value | Provenance |
|---|---|---|
| `sector_granularity_bytes` | 4,096 | `FLASH_ERASE_SIZE` (`firmware/src/boot.rs:193`); measured |
| `slots` | 2 | primary + shadow (`firmware/src/boot.rs:60-61`); measured |
| `SECURE_PARTITION_IMAGE_MAX` | 14,040 B | `platform/src/secure_store.rs:920-922`; compile-time constant |
| `slot_bytes` | 16,384 B | measured |
| `sectors_per_slot` (`s`) | 4 | measured |
| erase calls per persist (`e`) | 2 | measured |
| sector erasures per persist | 8 | measured — 2 calls x 4 sectors |
| **distinct sectors those 8 land on** | **8** | measured — the distribution, not the total |
| **erases per sector per persist** | **1** | measured — the busiest single sector's count |
| `cycles_per_sector` | 100,000 | **literature** — a NOR-flash endurance figure, *not* measured on this part |

### 3.1a The budget is **shared**, and "3,200,000 assertions" is not a FIDO lifetime

**Every figure in this section is a property of the *persist*, not of any one
applet.** The 8 sectors enumerated in §3.2 are the entire secure partition —
`firmware/src/boot.rs:60-61,77` declares
`SECURE_PARTITION: [u8; 2 * SECURE_SLOT_BYTES]` at `0x3F_0000`, which is
`2 x 16,384 B = 8 x 4,096 B` and nothing more. There is no per-app budget and
no per-app region: the OATH keystore, PIV, the management applet, the
boot-entropy record, the firmware manifest and the FIDO keystore all persist
through the same `FlashSlotSink` over the same two slots, and every one of
them spends **the same 8 sector erasures per persist**.

So the correct reading of the numbers below is:

* `assertion_ceiling = 100,000` is the number of **persists** the partition
  survives, full stop;
* `batched_assertion_ceiling = 3,200,000` (§4a) is what *this particular
  consumer* would contribute to that budget if it were the only one, and
  **every other persisting applet's traffic comes out of the same total.**

"3,200,000 assertions" therefore reads as a FIDO-specific lifetime and is
not one. On a device that also writes PIV structures or resets OATH
credentials, the FIDO budget is whatever is left after those. This is stated
here because the review is right that its absence makes the number look
better than it is, and it makes the interval question in §4a harder rather
than easier: the deployments that would notice a 320-day FIDO ceiling are
exactly the ones whose partitions are also being spent by other applets.

What would make this precise is an instrument that apportions the persist
stream by source — measured, not argued. That does not exist and is not
built here; the sentence above is the honest limit of what the current
measurement supports.

The slot-size derivation, shown so a reader can check it:

```text
SEALED_PARTITION_IMAGE_MAX = 8 + 24 * (4 + 48 + 4 + 512) + 4      = 13,644   (format v2)
                            + V3_NONCE_LEN (12)
                            + DEV_MAX_ENTRIES (24) * V3_TAG_LEN (16)  = +396
                                                                    = 14,040
slot_bytes    = ceil(14,040 / 4,096) * 4,096 = 4 * 4,096          = 16,384
sectors_per_slot = 16,384 / 4,096                                =      4
```

The two slot bases, so the sector addresses are checkable
(`firmware/src/boot.rs:60-61`, offsets relative to `0x103F0000`):

```text
SECURE_PRIMARY_OFFSET = 0x3F0000
SECURE_SHADOW_OFFSET  = 0x3F0000 + SECURE_SLOT_BYTES = 0x3F4000
```

### 3.2 Which sectors a persist erases, and how often

This is the step the withdrawn 12,500 skipped, so it is spelled out sector by
sector. A persist on a counter bump takes this path (all measured, §2.1):

1. `FlashSlotSink::program` (`platform/src/persist_sink.rs:86-111`) loops
   over `[primary, shadow]`. For each, `slot_matches` compares the sealed
   image against what is already in flash.
2. The counter bump changes the image, so **neither** slot matches, so the
   compare short-circuit does not fire for either. (This is the defect: the
   compare works, the image just never matches. The measured control
   `unchanged_erase_calls = 0` proves the compare is real — an unchanged
   re-persist erases nothing.)
3. Each mismatched slot is erased over its **whole window**,
   `off .. off + slot_bytes` (`persist_sink.rs:95`) — the range is the slot
   geometry, not the image length, so it is always 16,384 B.
4. The two windows are `0x3F0000..0x3F4000` and `0x3F4000..0x3F8000`. They
   are **adjacent and disjoint**, and 4 KiB-granular, so they decompose into
   8 distinct sectors with no sector appearing twice.

| Sector | Flash range | Erases per persist | Source |
|---|---|---:|---|
| P0 | `0x103F0000..0x103F1000` | 1 | primary window, first 4 KiB |
| P1 | `0x103F1000..0x103F2000` | 1 | |
| P2 | `0x103F2000..0x103F3000` | 1 | |
| P3 | `0x103F3000..0x103F4000` | 1 | |
| S0 | `0x103F4000..0x103F5000` | 1 | shadow window, first 4 KiB |
| S1 | `0x103F5000..0x103F6000` | 1 | |
| S2 | `0x103F6000..0x103F7000` | 1 | |
| S3 | `0x103F7000..0x103F8000` | 1 | |
| | **8 sector-erase operations** | **8** | measured (`changed_sector_erasures_per_persist`) |
| | **8 distinct sectors touched** | | measured (`changed_distinct_sectors_erased_per_persist`) |
| | **busiest single sector** | **1** | measured (`changed_max_erases_per_sector_per_persist`) |

The instrument does not take the disjointness on trust. It walks the erase
log and counts, per 4 KiB sector, how many erases landed there
(`sector_erase_profile_since`); `distinct = 8` and `max = 1` are what it
reports, and the gate refuses the document if they stop agreeing with each
other or with the total.

**Cross-check against `platform/src/persist_sink.rs:86-111`, as asked.** Yes
— `program` erases **both** slots on any image change, and only the one that
matched on a partial repair. That is why all 8 sectors are worn on the
counter-bump path and why only 4 are worn on the `partial_erase_calls = 1`
control. It is also why the per-sector rate is 1 rather than 2: the two slots
do not overlap, so "both slots" means 8 distinct sectors, not 8 erases onto
4.

**Cross-check against the HAL.** §2.2 established that the RP2350 path walks
the range in 4 KiB sector erases (`flash_range_erase(addr, len, 1 << 31, 0)`
with `block_cmd = 0`, so no larger block erase is used). That is exactly the
granularity this table is written in: one hardware erase command per row. Had
the HAL issued a single 64 KiB chip erase instead, it would still have
consumed one cycle on each of the 8 sectors — a bulk erase is not one wear on
many, it is one wear each. So the *distribution* above does not depend on the
split question being settled, and this correction would stand even if §2.2
were revised.

### 3.3 The ceiling

NOR endurance is specified per sector: `cycles_per_sector = 100,000` means
each 4 KiB sector survives 100,000 erase cycles. The part fails when its
**first** sector runs out, so the divisor is the erases one sector takes per
persist — measured above as **1**:

```text
erases_per_sector_per_persist = max_erases_per_sector_per_persist   = 1
assertion_ceiling = cycles_per_sector / erases_per_sector_per_persist
                  = 100,000 / 1
                  = 100,000 assertions
```

The document's machine-readable figures for this section:

```text
cycles_per_sector = 100000
erases_per_sector_per_persist = 1
assertion_ceiling = 100000
```

The gate re-derives `100,000` from `cycles_per_sector` and the measured
`changed_max_erases_per_sector_per_persist`, and separately refuses the
document if `distinct != total` — i.e. if the premise that the erases spread
across distinct sectors ever stops holding.

### 3.4 The withdrawn 12,500, stated explicitly

The first version of this document published:

```text
sector_erasures_per_persist = e * s = 2 * 4 = 8
assertion_ceiling           = cycles_per_sector / (e * s) = 100,000 / 8 = 12,500
```

**That was a double-count and the figure is withdrawn.** Here is precisely
what it got wrong, so a reader never has to guess whether the change was a
correction or a convenience:

* `e * s = 8` is a correct count of **erase operations per persist**. It was
  never wrong.
* It was then used as **erases accumulated by one sector per persist**. That
  is a different quantity. It would be right only if all 8 erases hit the
  same sector — which §3.2 shows they do not; they hit 8 different ones.
* Dividing the *per-sector* endurance budget by a *per-persist operation
  count* mixes two units. The resulting 12,500 is not a conservative bound
  with a safety factor; it is simply the wrong number, off by exactly the
  number of sectors (`8x`).
* The EPIC's own 6,000–50,000 range carried the same error at both ends
  (`100,000 / (2*8) = 6,250` and `100,000 / (2*1) = 50,000`), so the
  corrected 100,000 sits **above** the EPIC's published band. That is the
  honest position: the band was derived from a model whose high end
  (one bulk erase per slot) is not even physically possible on a part whose
  erase granularity is 4 KiB. The band should be read as "an order of
  magnitude, somewhere between 10^4 and 10^5 persists", and 100,000 is its
  upper end, reached for a geometric reason — one erase per sector per
  persist is the *best case* wear distribution the two-slot layout can
  produce, since the sectors are disjoint by construction.

**What did not change.** Every measured figure in §2.1 is unchanged, the
instrument is unchanged in what it asserts about the sink, and no production
code changed. What changed is one divisor and the number derived from it.
The reason this is written out at length rather than quietly edited is that a
document whose headline silently moves is exactly the hand-written copy of
derivable evidence this project keeps paying for; the previous implementer
flagged the 12,500 as suspicious in their own concerns, and they were right.

**Does the defect survive the correction?** Yes, and this is the part worth
being careful about. The lifetime is ~100,000 assertions, not 12,500 — the
correction makes the defect **8x less severe**, and that is stated rather
than buried. But 100,000 assertions is still not a product lifetime: a FIDO2
sign counter that saturates forces re-enrolment, and 100k assertions is a
number a high-traffic deployment can reach. US-1011's batching fix is worth
the same on either model, because both charge a full-image erase to a
one-counter change. What the correction changes is the *urgency* and the
number to size Phase 2 against, not the direction.

### 3.5 What the gate holds, and what it deliberately does not

Held (each a named failure, not a warning):

* every measured figure in §2.1, including the two new distribution figures;
* the internal consistency of those figures (`sectors_per_slot` from
  `slot_bytes` and the granularity; `changed_sector_erasures_per_persist`
  from slots x sectors);
* `distinct == total` — the premise of the correction;
* `max_erases_per_sector_per_persist * distinct == total` — that the
  distribution adds up;
* `assertion_ceiling == cycles_per_sector / max_erases_per_sector_per_persist`;
* that `cycles_per_sector` is the literature value, and that the document
  labels it as literature;
* that the withdrawn 12,500 does not reappear as an `assertion_ceiling` line.

Not held, deliberately:

* **the 100,000 figure itself as a hardware claim.** It is `literature x
  measured-distribution`; the endurance side is a NOR-flash figure this
  project has never confirmed on this part, and the distribution side is
  measured on a host NOR model. A reader who needs a defensible number for a
  datasheet must take the endurance figure from the Pico 2's flash part
  number, not from here.
* **the device erase count** (§2.3) and the hardware erase-command count
  (§2.2's outstanding logic-analyser capture). Both are named as not
  measured, and a gate that pinned an unmeasured number could not fail
  honestly.

---

## 4. What this means for US-1011

The fix does not have to change how the sink erases; it has to change *when*
the sink is asked to. Every one of the 8 sector erasures per assertion is paid
for a store image that differs from the flash in a handful of bytes, and —
because the two slot windows are disjoint (§3.2) — that costs exactly one
erase cycle on each of 8 distinct sectors, per assertion. The measured
`unchanged_erase_calls = 0` already proves the sink knows how to erase
nothing — it just never gets the chance, because the counter bump always
changes the image first.

The correction in §3.4 makes the ceiling 8x larger than first published
(100,000 rather than 12,500). It does not make the fix less worth doing: at
100,000 persists the counter is still saturating inside the service life of
any credential that gets used heavily, and the fix costs the same either way,
because the waste is a full-image erase charged to a one-counter change.

---

## 4a. What US-1011 changed, and what it did not

**US-1011 landed.** The counter's persist is now batched: the whole keystore
image is rewritten **once per `COUNTER_PERSIST_INTERVAL` assertions** instead
of once per assertion (`apps/fido/src/device_keystore.rs`, constant
`COUNTER_PERSIST_INTERVAL`). This section is the arithmetic that follows.

**What did not change, and why the gate is unchanged.** Every measured figure
in §2.1 and §3.1 is a property of `FlashSlotSink::program` and the slot
geometry. US-1011 changes none of them: a persist still erases the same 8
sectors, in the same distribution, one per sector. What changed is **how
often a persist happens** — a property of the FIDO app, not of the sink — so
`check_erase_budget.py` re-measures the same instrument, gets the same
numbers, and passes unchanged. That is the intended division of labour: the
gate holds the sink's wear cost, and the FIDO test suite holds the batching.

The per-persist figures below are therefore unchanged and still the ones the
gate derives. The batched lifetime is a **different quantity** and is named
differently, so that `assertion_ceiling` keeps meaning what the gate computes
(it takes the first `assertion_ceiling =` line in this document, §3.3):

```text
COUNTER_PERSIST_INTERVAL      = 32
assertion_ceiling             = 100000          # per-PERSIST ceiling, §3.3, gated
erases_per_sector_per_persist = 1               # per-PERSIST rate, §3.2, measured
batched_assertion_ceiling     = 100000 * 32 / 1 = 3200000 assertions
```

Reading the last line out loud, because this is the claim being made:
`cycles_per_sector` (100,000, **literature**) buys one erase cycle per sector;
a persist costs one erase cycle per sector; and a persist now serves 32
assertions instead of 1. So

```text
batched_assertion_ceiling = cycles_per_sector x COUNTER_PERSIST_INTERVAL
                          / erases_per_sector_per_persist
                          = 100,000 x 32 / 1
                          = 3,200,000 assertions
```

**That 3,200,000 is this consumer's share of a budget that every applet
shares, not a FIDO lifetime** — see §3.1a. OATH, PIV, the management applet,
the boot-entropy record and the firmware manifest persist through the same
`FlashSlotSink` over the same entire secure partition, and each spends these
same 8 sector erasures.

**32x, not 8x and not 100x**, and the provenance is unchanged from §5: the
endurance figure is literature, the distribution is measured on a host NOR
model, and the product is a model. A reader who needs a defensible lifetime
for a product decision must still substitute the flash part's own endurance
spec; the `COUNTER_PERSIST_INTERVAL` factor then multiplies whatever that
figure is.

**The number is reasoned, not measured.** No board was attached, so there is
no wear measurement behind `COUNTER_PERSIST_INTERVAL = 32`. Both directions
of the trade-off are argued at the constant itself
(`apps/fido/src/device_keystore.rs`):

* *wear side* — the lifetime is linear in the constant, and at 32 it is
  **3.2 million assertions**. **This corrects a 1,000x arithmetic error.**
  This paragraph previously read "10,000 assertions a day would need 878
  years". It does not:
  `3,200,000 / 10,000 per day = 320 days ≈ 0.88 years`. Reaching 878 years at
  that rate needs `3.2 x 10^9` assertions, i.e. an interval of about 3,200.
  So the old sentence inverted its own argument — it claimed 32 already
  outlives any deployment, when a 10 k/day deployment exhausts the partition
  **in under a year** after this fix, and in about **10 days** before it.
  Which makes the *real* argument the opposite one, and it is the one worth
  making: a larger interval would buy a materially longer life for exactly
  the high-traffic deployments that motivated US-1011.
* *safety side* — the window is how far `signCount` may skip **forward** if
  the device loses power inside it, and US-1012 makes that skip the price of
  never repeating a value. FIDO does not read `signCount` as a count of
  assertions, but a reader diffing two values by hand will see a jump of up
  to 32 after a power cut, and a larger window makes that jump larger.

**So why is 32 still the answer — given the corrected arithmetic says a bigger
one is probably better for wear?** Because the *benefit* side is unmeasurable
here and the *cost* side is not. There is no board, so there is no endurance
measurement for the part actually fitted, and 32 was taken as the smallest
value that moves the lifetime out of that part's endurance envelope by a
meaningful factor (~32x) while keeping the post-cut forward skip small.
**A larger interval would very likely be better for wear and this branch
cannot justify one.** Settling it needs a measurement of the fitted part —
US-1007's job. It is not a decision a document or a comment comment should
make on the reviewer's behalf, and the corrected arithmetic is the reason to
stop pretending it already had been made.

**The coupling is now a gate, not prose.** `check_erase_budget.py` reads
`COUNTER_PERSIST_INTERVAL` out of
`apps/fido/src/device_keystore.rs` and fails if this document's
`COUNTER_PERSIST_INTERVAL` or `batched_assertion_ceiling` disagrees with it,
in either direction — the same treatment `cycles_per_sector` already had. A
developer editing the constant is no longer told in a comment to remember to
update this file.

**What the batching does not touch.** Only the counter is batched. A
credential created, deleted or grown inside a window persists immediately, on
its own account, and the persist gate's `dirty`/`stored` discipline is what
guarantees it — see `apps/fido/tests/counter_batching.rs`, whose
`credential_deleted_inside_a_batch_window_is_durable` is the test that would
catch a counter rewrite swallowing a delete.

**Monotonicity is US-1012's half and is not optional.** Between rewrites the
reply signs a counter that is not yet durable, so the guarantee that made
this safe — that the signed value is the durable one — no longer holds. The
property that replaces it is that a restore starts a whole window above the
durable image, so a power loss inside a window can only skip forward.
`apps/fido/tests/counter_monotonic.rs` pins it at **every** point of the
window, for the per-credential counter and for the keystore-wide one that
stateless U2F credentials sign against.

### 4b. US-1012, and the write pattern it leaves behind

**US-1012 landed.** A restore does not resume at the durable value:

```text
restore:   counter = durable + W,  counter_unpersisted = W
assert 1:  counter = durable + W + 1   -> whole-image rewrite (window closed)
assert k:  counter = durable + kW + 1, with at most W - 1 bumps un-persisted
```

so N assertions after a power-on cost `ceil(N / W)` rewrites — the `32`
multiplier in §4a, and `counter_batching.rs` measures exactly that for
`N` in `{1, W, 2W, 3W, 3W+1}`.

**Why the two halves of that sketch are one mechanism.** The restore grants
`W` of slack *and* marks it spent. Grant it without spending it and the
device can run a whole extra window past the skip, handing a restored device
a value below one the client already saw — the failure this story exists to
prevent. Spend it without granting it and the counter resumes at the durable
value, which is the same failure. The strictness comes from the `W - 1`: the
window-closing write fires on the `W`-th bump, so between two writes the
in-RAM counter is at most `durable + W - 1`, and the restore's
`durable + W` is **strictly** greater than anything the cut-away session
signed. Equal would already be a clone-detection failure.

**What it costs.** Nothing in the erase budget: the rewrite count is
unchanged (§4a). It costs one extra rewrite per power-on, which is the
"grant it and spend it" line above and is bounded by how often a device is
power-cycled, not by how often it is used.

**Stack.** The slack is folded into the decoder rather than applied to a
`let mut ks` after it. A named local of a 12-KiB `DeviceKeystore` is a
*second* copy of it: measured, the first cut grew the worst boot chain from
91,964 B to 106,048 B — exactly one keystore — and `load`'s own frame to
57 KB, which `check_boot_chain.py` (limit 98,304 B) rejected. Folding it into
the decode puts the chain at 92,704 B, 740 B above where it was: the price of
the extra loop and the parameter, and the only stack this story spends at
all.

---

## 5. Provenance table

| Figure | Value | Measured / reasoned | How |
|---|---|---|---|
| erase calls per persist | 2 | **measured** | host NOR model, real sink, real gate |
| erase range width | 16,384 B | **measured** | logged `erase` ranges |
| sectors per slot | 4 | **measured** | 16,384 / 4,096 |
| sector erase **operations** per persist | 8 | **measured** (range property) + **reasoned** (command count) | 2 x 4; confirmed against the RP2350 ROM contract |
| **distinct sectors** those 8 land on | **8** | **measured** | `sector_erase_profile_since` walks the erase log sector by sector |
| **erases per sector per persist** | **1** | **measured** | busiest single sector's count in the same walk |
| slot size | 16,384 B | **measured** | `SECURE_SLOT_BYTES` formula against the sealed bound |
| cycles per sector | 100,000 | **literature** | NOR-flash endurance, **not measured on this part** |
| **assertion ceiling** | **100,000** | **derived** | 100,000 / 1 — per **sector**, the unit endurance is specified in |
| ~~assertion ceiling (withdrawn)~~ | ~~12,500~~ | **withdrawn — double-count** | 100,000 / 8, dividing a per-sector budget by a per-persist operation count; §3.4 |
| device erase count | — | **not measured** | no vendor counter channel; reproducible from the existing `defmt` line |
| hardware erase commands | 8 (predicted) | **reasoned** | QSPI logic-analyser capture outstanding |

**One sentence on provenance, because the headline is a product of two
different kinds of knowledge.** The `100,000` cycles-per-sector is a
**literature** value for NOR flash — a typical endurance figure, not a
measurement of the flash part fitted to a Pico 2, and this project has never
characterised it. The `1` erase per sector per persist is **measured**, on a
host NOR model, from the real sink. The `100,000` ceiling is their product.
A reader who needs a defensible lifetime for a product decision should
substitute the flash part's own endurance spec for the literature figure and
keep the measured `1`; the gate is written so that substitution is a
deliberate, visible edit to both the document and the script rather than a
quiet divergence.
