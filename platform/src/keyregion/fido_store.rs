//! The FIDO-side adapter over the key region (US-1552).
//!
//! ```gherkin
//! Scenario: enrolling touches one record
//!   Given a region holding four credentials
//!   When a fifth is enrolled
//!   Then exactly one slot is erased and programmed
//!   And the other four are untouched
//!   And the operation commits or rolls back cleanly, never latching dirty state
//! ```
//!
//! # What this module is for
//!
//! The four-credential ceiling `apps/fido/tests/key_store_ceiling.rs`
//! reproduces is an **occupancy** ceiling, not a count ceiling:
//! `other_slots + old_parts + new_parts <= 24` in `crate::secure_store`, so the
//! fifth registration is refused `KeyStoreFull` (0x28). The ceiling is a
//! property of *one* backend's shape. This module is the other shape: one sealed
//! record per credential in a region of [`TOTAL_SLOTS`](super::TOTAL_SLOTS)
//! slots, so an enrolment erases **one sector** and programs at most four slots,
//! three of which carry unchanged records copied verbatim
//! (`commit.rs`, "Why sector-mates are copied verbatim, not re-sealed").
//!
//! # Why the whole array had to go, not just the bound
//!
//! Raising [`FIDO_CAPACITY`](super::FIDO_CAPACITY) to 856 while keeping
//! `DeviceKeystore`'s resident `HeaplessVec<DeviceCredential, N>` is not a
//! tuning decision, it is arithmetically impossible: `DeviceCredential` measures
//! **720 bytes** (`on_demand.rs`'s module docs), so 856 of them is **616,320
//! bytes of `.bss`** against 532,480 bytes of RAM on the part. So this module is
//! deliberately **stateless**: it holds a `&mut dyn KeyRegion` and no cache, no
//! resident set, and no pending-write marker. Everything else is either in flash
//! or in the caller's one [`CredentialWindow`].
//!
//! # "Never latching dirty state", stated as the reason this module is stateless
//!
//! The gherkin's last clause is the one the old design could not keep. The
//! whole-snapshot store kept a `dirty: bool` **and** a `stored: bool`
//! (`device_keystore.rs`) whose invariant — "the store holds exactly this dirty
//! snapshot" — is what SOAK-FINDING-1's `stored` arm is about, and it is a latch
//! a transaction has to be able to clear. Here there is nothing to latch:
//!
//! * a failed [`FidoRecordStore::put`] returns [`FidoStoreError`] and the store's
//!   observable state is either "the record is there" (the record commit
//!   succeeded and the index write failed — reported, never silent) or "it is
//!   not". There is no in-memory copy that could disagree with the medium;
//! * a credential that is in the region but has no index entry is **unfindable**,
//!   not corrupt. Its slot stays occupied, so the next allocation does not reuse
//!   it, and enrolling the credential again repairs the entry.
//!
//! That is why the rollback direction is "the **record** write is atomic
//! (`commit::commit`), the **index** write is not, and the non-atomic half is
//! ordered *after* the atomic half". The reverse order would let a power cut
//! leave an index entry pointing at a slot holding no record — an entry that
//! reads as a credential and is not one.
//!
//! # The index write, and why it is not a `commit`
//!
//! `commit::commit` is **record**-shaped: one record image into one slot, mates
//! included. An index slot is not that — it is
//! [`index::ENTRIES_PER_SLOT`] [`index::IndexEntry`] values at
//! `index::INDEX_ENTRY_BYTES` strides from offset 0 (`index.rs`, "Where the index
//! lives"), with no record header, so it cannot be expressed as a
//! [`Sealed`](super::Sealed) body: the header would occupy the offset the first
//! two entries live at.
//!
//! So [`write_index_entry`] does the read-modify-write itself, and the honest
//! accounting is:
//!
//! | fault point | live index sector | consequence |
//! |---|---|---|
//! | before the live erase | unchanged | staged copy discarded, nothing lost |
//! | after the live erase, before the copy-back | **empty** | up to 128 entries lost, so up to 128 credentials become *unfindable* |
//! | after the copy-back | current | correct |
//!
//! **Nothing is destroyed in the bad case.** A lost entry names a slot that is
//! still occupied by a sealed record, so the record is not overwritten and the
//! allocator will not hand the slot out again; the user re-enrols.
//!
//! **And the atomicity would buy nothing against the only attacker who cares**
//! — one who can cut power between two flash instructions. Anyone who can do
//! that can also simply erase the index, losing exactly the same entries with no
//! window at all. `AGENTS.md` §5: name the attack the complexity stops. There is
//! none, so no commit marker is invented here.
//!
//! # Why the allocator here and not [`SlotAllocator`](super::slotmap::SlotAllocator)
//!
//! [`SlotAllocator::alloc`] scans `0..region.slots()` and asks its
//! [`Occupancy`](super::slotmap::Occupancy) rule about each slot — but that rule
//! receives only the slot *image*, never the slot *index*, so it cannot express
//! "this slot is outside FIDO's range". The scan would be free to hand out an
//! OATH slot and, worse, an **index** slot, which is how `index.rs` says the
//! index gets destroyed ("at the tail the reservation is only reached after 928
//! slots are full, so the failure mode of a caller that forgets the reservation
//! is 'the index is destroyed when the store fills'").
//!
//! [`FidoAllocator`] exists for that one reason and is otherwise
//! [`record::RecordOccupancy`] plus a bound: there is exactly **one** occupancy
//! rule in this store — the codec's, which reads the generation out of the
//! header, so per-slot monotonicity survives a power cycle — and this type only
//! adds `slot.index() < FIDO_SLOT_LIMIT` to it.
//!
//! # Footprint
//!
//! One [`SlotImage`](super::slotmap::SlotImage) (1 KiB) at a time while writing
//! an index page, plus the caller's [`CredentialWindow`] (838 B) on a read.
//! **Zero `.bss`**: [`FidoRecordStore`] has one field, the region borrow.

extern crate alloc;

use alloc::vec;

use super::commit::{self, CommitError, CommitPlan, CommitReport, Recovery};
use super::crypto::{IndexKey, KeyDomain, PayloadKey};
use super::index::{self, IndexEntry, INDEX_FIRST_SLOT, INDEX_SLOT_COUNT, RpIdHash};
use super::on_demand::{self, CredentialWindow, OnDemandHit, SlotLocator, SlotQuery};
use super::record::{self, Domain, RecordHeader, RecordOccupancy};
use super::slotmap::{is_erased, Occupancy, SlotImage};
use super::{
    KeyRegion, Slot, SlotRead, FIDO_CAPACITY, FIDO_SLOT_BYTES, SLOTS_PER_SECTOR, TOTAL_SLOTS,
};

// ---------------------------------------------------------------------------
// The wear an index-entry write costs (US-1561, US-1562)
// ---------------------------------------------------------------------------
//
// The index writer runs the **same three-phase shape** a record commit does —
// stage a whole sector through the scratchpad, erase the live one, copy back,
// retire — so the two are expressed in terms of [`commit`]'s own published
// counts rather than in a second set of literals. Sharing them is deliberate:
// a second set would be a second protocol, and the gap between them is exactly
// what `docs/erase-budget.md` would then be publishing a lifetime from.

/// Sector erases one index-entry write issues against the **scratchpad**: the
/// prepare erase and the retire erase, the same two [`commit`] performs.
///
/// Stated by reference so a change to the staging shape in [`commit`] moves this
/// figure with it instead of leaving it stale here.
pub const INDEX_SCRATCHPAD_ERASES_PER_ENTRY_WRITE: u32 = commit::SCRATCHPAD_ERASES_PER_COMMIT;

/// Sector erases one index-entry write issues against the **live** index
/// sector: exactly one.
pub const INDEX_LIVE_ERASES_PER_ENTRY_WRITE: u32 = commit::LIVE_ERASES_PER_COMMIT;

/// Total sector erases one index-entry write issues: **three**.
///
/// This is the half of a durable counter write that is *not* the record. See
/// [`SECTOR_ERASES_PER_COUNTER_WRITE`] for why a counter write pays it.
pub const INDEX_SECTOR_ERASES_PER_ENTRY_WRITE: u32 =
    INDEX_SCRATCHPAD_ERASES_PER_ENTRY_WRITE + INDEX_LIVE_ERASES_PER_ENTRY_WRITE;

/// Sector erases one **durable** signature-counter write performs: the record
/// commit plus the index-entry rewrite that follows it.
///
/// **Six**, over three distinct sectors. And the distribution is **not** the
/// snapshot path's uniform one-per-sector: it is
///
/// | sector | erases | why |
/// |---|---:|---|
/// | the commit scratchpad | **4** | both writes stage through the **same** sector, and each erases it to prepare and again to retire |
/// | the live record sector | 1 | the record commit's step 5 |
/// | the live index sector | 1 | the index rewrite's live erase |
///
/// **The scratchpad is the wear bottleneck, and it is not visible from either
/// half's arithmetic taken alone.** A record commit costs three erases on three
/// different sectors; an index write costs three more on three different
/// sectors; together they cost six on **two** sectors they share and one they
/// do not. This is the number `docs/erase-budget.md` §4c divides by, and it is
/// four times the divisor the whole-snapshot path used — which is why the
/// per-record budget with the same interval comes out *smaller* in assertions,
/// not larger, despite erasing 2.7× fewer bytes per assertion.
///
/// Measured, not asserted: `platform/tests/key_region_counter_budget.rs`
/// publishes the full profile (`erase_profile_per_counter_write`) so the shape
/// is checkable and not just the maximum.
///
/// # Why the index half is paid at all (US-1561, and its cost stated)
///
/// A counter write has to advance the record's **generation** — `commit::commit`
/// refuses a commit that does not, and rightly so: a write at the generation
/// already in the slot is a replay by another name. The index entry's `generation`
/// field is bound into its MAC over `(domain, slot, generation, rp_id_hash)`
/// ([`index.rs`](super::index), "What the MAC covers"), and
/// [`IndexEntry::generation`] is documented as *the generation of the record this
/// entry names* — so a record that advances leaves an index asserting something
/// false about the region, and every later reader of that field would be reading
/// a lie.
///
/// **Named honestly: nothing currently compares the two.** `index::lookup_all`
/// verifies an entry's tag against the entry's *own* `(domain, slot,
/// generation)` and answers a slot; no call path today reads
/// [`IndexEntry::generation`] to decide anything. So this half buys an invariant
/// the index maintains rather than an attack it stops, and `AGENTS.md` §5 asks
/// for the attack to be named before a mechanism is added.
///
/// The name is: **the index must not be able to disagree with the region about
/// which generation is current.** The alternative is to leave the field stale and
/// document it as stale, which turns a field every future reader will consult
/// into one whose value is a lie by a factor that grows with the batch window.
/// That is not cheaper in any sense a later change can rely on. The cost is
/// published here, measured by `platform/tests/key_region_counter_budget.rs`,
/// and divided out of the lifetime in `docs/erase-budget.md` §4c — so a reader
/// who disagrees with the trade can see exactly what it costs, and can divide
/// three erases back out of six and recompute.
///
/// The other thing batching buys is that all of it is paid **once per
/// `COUNTER_PERSIST_INTERVAL` assertions** and not once per assertion: the
/// honest per-assertion figure is `6 / 32` sector erases, not 6.
pub const SECTOR_ERASES_PER_COUNTER_WRITE: u32 =
    commit::SECTOR_ERASES_PER_COMMIT + INDEX_SECTOR_ERASES_PER_ENTRY_WRITE;

/// Sector erases one durable counter write lands on its **busiest single**
/// sector: **four**, all of them on the commit scratchpad.
///
/// **This is the divisor the per-record lifetime is computed from.** NOR
/// endurance is specified per sector, so the lifetime is
/// `cycles_per_sector / this` — the same reasoning as §3.3 of
/// `docs/erase-budget.md`, and the same refusal to divide a per-sector budget
/// by a per-write operation count that produced the withdrawn 12,500 there.
///
/// Derived, not literal: the record commit and the index rewrite are two
/// three-phase writes that share one scratchpad, so each contributes
/// [`SCRATCHPAD_ERASES_PER_COMMIT`] to it.
pub const MAX_ERASES_PER_SECTOR_PER_COUNTER_WRITE: u32 =
    commit::SCRATCHPAD_ERASES_PER_COMMIT + INDEX_SCRATCHPAD_ERASES_PER_ENTRY_WRITE;

// ---------------------------------------------------------------------------
// Layout: which slots this applet may touch
// ---------------------------------------------------------------------------

/// The first slot a FIDO record may occupy.
///
/// Not the region's head: OATH owns `[0, OATH_CAPACITY)` and the commit
/// scratchpad the next `SLOTS_PER_SECTOR` slots, both because the allocator's
/// rule is **lowest free slot** (`slotmap.rs`, "Lowest free slot is a linear
/// scan") and a reservation placed at the head would be destroyed by the first
/// enrolment. `index.rs` makes the same argument for the tail ("Why the tail and
/// not the head"); FIDO's range sits between the scratchpad and the index.
pub const FIDO_FIRST_SLOT: u32 = super::FIDO_FIRST_SLOT;

/// The exclusive end of FIDO's slot range: slots
/// `[FIDO_FIRST_SLOT, FIDO_SLOT_LIMIT)`.
///
/// **The derived capacity, and the only number that decides how many passkeys
/// this device holds.** It is [`FIDO_CAPACITY`](super::FIDO_CAPACITY) — **856**
/// at the shipping geometry — and it is a function of the region's size, the
/// measured record size, the commit protocol and the index reservation
/// (`mod.rs`, "Capacities — derived, never asserted"). The number the old store
/// carried, `DEVICE_MAX_CREDS = 12`, was an assertion in a file no region could
/// contradict, and it was wrong by two orders of magnitude; on the board it was
/// also unreachable, because the real ceiling was 24 entries shared with every
/// other applet.
pub const FIDO_SLOT_LIMIT: u32 = super::FIDO_SLOT_LIMIT;

/// The head slot of the commit scratchpad sector: slots
/// `[SCRATCHPAD_FIRST_SLOT, SCRATCHPAD_FIRST_SLOT + SLOTS_PER_SECTOR)`.
///
/// Immediately before FIDO's range and after OATH's, so the boundary the
/// allocator stops at and the boundary the commit stages behind are
/// **adjacent and both sector-aligned**. `mod.rs` charges the scratchpad to
/// FIDO's capacity and says nothing else about where it goes; the only
/// constraints are that it be a whole sector inside the region and not the sector
/// being written — which this placement cannot be, because OATH's records stop
/// one sector short of it and FIDO's begin one sector after it.
pub const SCRATCHPAD_FIRST_SLOT: u32 = super::SCRATCHPAD_FIRST_SLOT;

/// The scratchpad sector's head slot, as the [`Slot`] `commit` wants it.
pub const fn scratchpad_slot() -> Slot {
    match Slot::new(SCRATCHPAD_FIRST_SLOT as u16) {
        Some(s) => s,
        // Unreachable, and stated rather than defaulted: `FIDO_CAPACITY` is
        // three terms below `TOTAL_SLOTS` and every one is non-negative, so the
        // scratchpad head is inside the region. A geometry change that breaks
        // that must fail here rather than hand `commit` a slot outside the
        // region, which `CommitPlan::validate` would only reject later — after
        // the caller had already sealed a record.
        None => panic!("the commit scratchpad must lie inside the key region"),
    }
}

/// Whether `slot` is one FIDO may allocate from or write to.
///
/// One predicate for both, because the hazard [`index::is_index_slot`] exists to
/// name is a scan that crosses into a reservation. The allocator stops here and
/// [`FidoRecordStore::put`] refuses.
pub const fn is_fido_slot(slot: Slot) -> bool {
    // Both bounds are tested, and `super::is_fido_slot` is the same predicate:
    // OATH owns the region's head (`[0, OATH_CAPACITY)`) and the scratchpad and
    // index follow it, so a lower bound of 0 would admit OATH's credentials to
    // every FIDO write — a tombstone committed over an OATH record would erase
    // its sector and destroy the credential. This file once stated "the
    // region's head" as the reason only the upper bound needed testing; that
    // stopped being true when the partition put OATH there (`mod.rs`), which is
    // exactly the drift the two-sided form makes representable.
    (slot.index() as u32) >= FIDO_FIRST_SLOT && (slot.index() as u32) < FIDO_SLOT_LIMIT
}

const _: () = {
    // The scratchpad must sit wholly inside the region and on a sector
    // boundary, or `CommitPlan::validate` refuses every plan naming it and the
    // store can never write. Stated as a multiple-of rather than `% n == 0`
    // because clippy runs with `-D warnings` and `manual_is_multiple_of`
    // rejects the `%` form in this tree (`mod.rs` gives the same argument for
    // the slot strides).
    assert!(
        SCRATCHPAD_FIRST_SLOT.is_multiple_of(SLOTS_PER_SECTOR),
        "the commit scratchpad must start on a sector boundary"
    );
    assert!(
        SCRATCHPAD_FIRST_SLOT + SLOTS_PER_SECTOR <= INDEX_FIRST_SLOT,
        "the commit scratchpad must be a whole sector inside the region and must not overlap the \
         index reservation"
    );
    // **Rewritten when the partition moved under it.** This assertion used to
    // say "FIDO's range ends where the scratchpad begins", which was true of
    // the layout this file invented — FIDO at the head, scratchpad after it —
    // and is false of the shared one: OATH, scratchpad, FIDO, index.
    //
    // The property it was protecting is unchanged and is now stated as what it
    // actually was: FIDO's range must not overlap anything it does not own, or
    // a credential could be written into the staging area and erased by the
    // next commit's prepare, or into the index and vanish with it.
    assert!(
        FIDO_FIRST_SLOT >= SCRATCHPAD_FIRST_SLOT + SLOTS_PER_SECTOR,
        "FIDO's range must begin past the scratchpad: a credential written into the staging \
         area would be erased by the next commit's prepare"
    );
    assert!(
        FIDO_SLOT_LIMIT <= INDEX_FIRST_SLOT,
        "FIDO's range must end at or before the index: a credential written into an index slot \
         would be erased when the index is rewritten"
    );
    // The range must be whole sectors inside the region, and non-zero: an
    // allocator scanning a range the region does not hold reaches past its own
    // area, which is the whole hazard this type exists to prevent.
    assert!(
        FIDO_SLOT_LIMIT <= TOTAL_SLOTS
            && FIDO_SLOT_LIMIT >= SLOTS_PER_SECTOR
            && FIDO_SLOT_LIMIT.is_multiple_of(SLOTS_PER_SECTOR),
        "FIDO's slot range must be a non-zero whole number of sectors inside the region"
    );
    // The index writer programs whole slot images, which is only a whole number
    // of flash pages when the stride is a power of two.
    assert!(
        FIDO_SLOT_BYTES >= 256 && FIDO_SLOT_BYTES & (FIDO_SLOT_BYTES - 1) == 0,
        "the index writer programs whole slot images"
    );
    // An entry splice must land inside its slot. `entry_offset` is a stride
    // multiply and `INDEX_ENTRY_BYTES` the splice length; if the two ever
    // disagreed with `FIDO_SLOT_BYTES`, `write_index_entry` would write out of
    // bounds on a path that has no bounds check left to save it.
    assert!(
        index::INDEX_ENTRY_BYTES <= FIDO_SLOT_BYTES as usize,
        "an index entry must fit its slot"
    );
    // The index reservation must not be reachable from FIDO's range.
    assert!(
        FIDO_SLOT_LIMIT <= INDEX_FIRST_SLOT,
        "FIDO's range must not reach the index reservation"
    );
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a write did not happen.
///
/// [`RegionUnreadable`](Self::RegionUnreadable) carries the "degrade, never
/// halt" obligation: it is a transport failure, it is **not** converted into "the
/// store is empty", and it maps onto a CTAP error rather than onto a panic or a
/// `fatal_boot`. `mod.rs`'s [`SlotRead`] exists for the same distinction on the
/// read side; this is the write side's spelling of it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FidoStoreError {
    /// The region could not be read or written. `reason` is the region's own
    /// `&'static str`, verbatim.
    RegionUnreadable(&'static str),
    /// Every slot in FIDO's range is occupied.
    ///
    /// "We found out and there is nothing free" — deliberately distinct from
    /// [`Self::RegionUnreadable`] ("we could not find out"), for the reason
    /// `slotmap::AllocError` splits them (`slotmap.rs`, "Why `alloc` refuses to
    /// skip a slot it could not read").
    Full,
    /// The plaintext is larger than the largest record this store can write.
    ///
    /// Kept apart from [`Self::Record`] because the two have different fixes: a
    /// body-too-large is the codec refusing, and a caller-visible "this
    /// credential does not fit" is a better answer than a codec error that looks
    /// like a bug.
    CredentialTooLarge {
        /// What was offered.
        len: usize,
        /// What this store can seal: [`super::FIDO_RECORD_MAX`].
        max: usize,
    },
    /// The record could not be sealed.
    Record(record::RecordError),
    /// The sector commit failed.
    ///
    /// [`CommitError::Incomplete`] specifically means the staged set is the only
    /// copy of that sector; the next [`FidoRecordStore::recover`] — which every
    /// [`FidoRecordStore::put`] runs first — finishes it, so a retry is safe.
    Commit(CommitError),
    /// Every index entry cell is occupied.
    IndexFull,
    /// The index could not be written.
    IndexUnreadable(&'static str),
}

impl core::fmt::Display for FidoStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FidoStoreError::RegionUnreadable(why) => {
                write!(f, "the key region could not be read or written: {why}")
            }
            FidoStoreError::Full => write!(f, "the key region holds no free FIDO slot"),
            FidoStoreError::CredentialTooLarge { len, max } => {
                write!(f, "a credential of {len} bytes exceeds the {max}-byte record bound")
            }
            FidoStoreError::Record(e) => write!(f, "the record could not be sealed: {e}"),
            FidoStoreError::Commit(e) => write!(f, "the record commit did not finish: {e}"),
            FidoStoreError::IndexFull => write!(f, "the key region index holds no free entry"),
            FidoStoreError::IndexUnreadable(why) => {
                write!(f, "the key region index could not be written: {why}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The allocator
// ---------------------------------------------------------------------------

/// Lowest free FIDO slot, at the next generation for it.
///
/// The bound is the whole reason this is not [`SlotAllocator`](super::slotmap::SlotAllocator)
/// — see the module docs. The generation rule is **not** reimplemented: it reads
/// the record header through [`record::RecordOccupancy`], the same rule the read
/// path uses, so "occupied" and "at what generation" cannot come to mean two
/// different things inside one store.
///
/// **The high-water table is not cached across operations.** Caching it would
/// mean holding it across calls on a `&mut dyn KeyRegion`, and this store is
/// deliberately stateless — that is what buys "never latching dirty state". The
/// cost is a bounded re-scan per allocation: at most [`FIDO_SLOT_LIMIT`] header
/// reads, and a *slot image* read is what `KeyRegion::read_slot` returns, so
/// this is [`FIDO_SLOT_LIMIT`] × 1 KiB of reads on a full region (856 KiB). It
/// is paid once per enrolment, off the boot path (S8/S9).
pub struct FidoAllocator;

impl FidoAllocator {
    /// The lowest free slot in `[0, FIDO_SLOT_LIMIT)`, and the generation its
    /// record must carry.
    ///
    /// Generation `0` never appears: a virgin slot's first write is generation 1,
    /// so a record claiming 0 is one this allocator did not issue — and
    /// `CommitPlan::validate` refuses it, which makes the rule structural rather
    /// than conventional.
    ///
    /// A read that faults **aborts** the allocation rather than skipping the
    /// slot: a slot whose contents could not be learned may still hold a
    /// credential, and the write that follows would destroy it. That is
    /// US-1573's hazard in its most expensive form, and `slotmap.rs` refuses it
    /// for the same reason.
    pub fn alloc(region: &mut dyn KeyRegion) -> Result<Allocation, FidoStoreError> {
        let mut high_water = vec![0u32; FIDO_SLOT_LIMIT as usize];
        let mut index = FIDO_FIRST_SLOT;
        while index < FIDO_SLOT_LIMIT {
            let slot = fido_slot_at(index)?;
            let raw = region
                .read_slot(slot)
                .map_err(FidoStoreError::RegionUnreadable)?;
            if RecordOccupancy.occupied(&raw) {
                if let Some(g) = RecordOccupancy.generation(&raw) {
                    high_water[index as usize] = g;
                }
            } else {
                let generation = high_water[index as usize]
                    .checked_add(1)
                    .ok_or(FidoStoreError::Full)?;
                return Ok(Allocation { slot, generation });
            }
            index += 1;
        }
        Err(FidoStoreError::Full)
    }
}

/// A slot and the generation its record must carry.
///
/// Re-exported rather than re-declared: the shape is `slotmap::Allocation`'s, the
/// generation rule behind it is the codec's, and two names for one struct is how
/// two generations get issued into one slot.
pub use super::slotmap::Allocation;

/// The [`Slot`] at a scan index, refusing one FIDO may not touch.
///
/// A typed refusal rather than a debug assertion: this is the boundary that keeps
/// an index slot out of a credential write, and a boundary that compiles out is
/// not one.
fn fido_slot_at(index: u32) -> Result<Slot, FidoStoreError> {
    let slot = Slot::new(index as u16)
        .ok_or(FidoStoreError::RegionUnreadable("a FIDO slot index is outside the region"))?;
    if !is_fido_slot(slot) {
        return Err(FidoStoreError::RegionUnreadable(
            "the allocator reached a slot outside the FIDO range",
        ));
    }
    Ok(slot)
}

// ---------------------------------------------------------------------------
// Locators
// ---------------------------------------------------------------------------

/// The upper bound on how many of one RP's credentials a lookup will consider.
///
/// A bound, and the reason it is small is a stack argument: the candidate array
/// is one [`Slot`] each, so 16 costs 32 B, while a capacity-sized array would
/// cost 1,712 B on a task frame that already carries a [`CredentialWindow`].
///
/// It is not a capacity claim. The store holds
/// [`FidoRecordStore::capacity`] credentials; this is how many of **one RP's**
/// a by-credential-ID lookup will open before giving up, and CTAP itself puts no
/// limit on how many passkeys one site may register — a site with 17 is refused
/// `NoCredentials` rather than served. The alternative, scanning the whole index
/// with no bound, turns one hostile `rp_id_hash` into one AEAD operation per
/// index entry.
pub const MAX_RP_CREDENTIALS: usize = 16;

/// The tombstone body: **one byte, `0xFF`**.
///
/// A delete is a commit whose target is this body, and the whole reason it is a
/// record rather than an erase is `commit.rs`'s "Why there is no single-slot
/// delete here": a target programmed `0xFF` is indistinguishable from a commit
/// that never reached its witness, so `commit::recover` would resurrect the
/// delete as a replay. A one-byte body is an ordinary record, so the delete is a
/// normal atomic commit and the generation still advances — which is what keeps
/// the next credential at this slot from spending a nonce the deleted one used.
///
/// **`0xFF` is unambiguous because a credential body cannot be one byte.** The
/// applet's record body is a CBOR map (`DeviceCredential::encode`,
/// `apps/fido/src/device_keystore.rs`), and CBOR major type 5 with an
/// additional-information field of 31 is the *break* stop code, not a map with
/// 31 entries — `cbor.rs`'s parser rejects it. So no credential body this store
/// can hold begins with, or equals, this value. The same argument `oath_store.rs`
/// makes for `TOMBSTONE_NAME_LEN`, over the same "an impossible field value"
/// shape rather than a magic string.
///
/// The applet-side check is `FidoCredential::is_deleted` on the *opened*
/// plaintext, never on the raw slot bytes: an erased slot reads as all-`0xFF`
/// too, and treating those two as the same would make "never written" and
/// "deleted" indistinguishable to a caller counting live credentials.
pub const TOMBSTONE_BODY: [u8; 1] = [0xFF];

/// Is this opened record body a tombstone?
///
/// Takes the **plaintext**, not the raw slot image — see [`TOMBSTONE_BODY`]'s
/// last paragraph for why the raw image cannot answer this question.
pub fn is_tombstone(body: &[u8]) -> bool {
    body == TOMBSTONE_BODY.as_slice()
}

/// A [`SlotLocator`] over the real index, sealed under the PIN-free index key.
///
/// This is the one `impl` [`on_demand::SlotLocator`] was designed to receive —
/// its module docs name exactly this signature and say the stand-in in its own
/// `testing` module is what gets replaced. It exists so
/// [`FidoRecordStore::load_by_rp`] goes through [`on_demand::load`] — the
/// composed fail-closed path — rather than reassembling `record::decode` plus
/// `record::open` at a fourth call site.
///
/// It opens **no payload**: the answer comes from `index::lookup_all`, which
/// reads index slots only and has no payload key anywhere in its signature
/// (`index.rs`, "The slot whose index entry authenticates `rp_id_hash`").
pub struct IndexLocator<'a> {
    index_key: &'a IndexKey,
    rp_id_hash: RpIdHash,
}

impl<'a> IndexLocator<'a> {
    /// Answer with the first record of one RP, whatever its credential ID.
    pub fn any_for_rp(index_key: &'a IndexKey, rp_id_hash: RpIdHash) -> Self {
        IndexLocator { index_key, rp_id_hash }
    }
}

impl SlotLocator for IndexLocator<'_> {
    fn locate(
        &mut self,
        region: &mut dyn KeyRegion,
        _want: &SlotQuery<'_>,
    ) -> on_demand::Located {
        // **`index::lookup_all`, not `index::lookup`.** `lookup` matches on
        // `(outcome, found)` and returns `Absent` for *both* "no match" and
        // "the index slot could not be read" — its own docs acknowledge the
        // collapse ("`Absent` means no entry in this domain authenticates the
        // hash … but see `SlotRead::present`'s warning"). `lookup_all`
        // propagates `Fault` instead, and this is a locator: `on_demand.rs`
        // names it as "the first component able to get wrong" US-1573's
        // distinction. A `Fault` that reached `on_demand::load` as `Absent`
        // would report a sick flash as "no such credential", which is the
        // precise shape of the bug the three states exist to prevent.
        let mut first: [Slot; 1] = [first_slot()];
        match index::lookup_all(
            self.index_key,
            region,
            KeyDomain::Fido,
            &self.rp_id_hash,
            &mut first,
        ) {
            SlotRead::Present(count) if count > 0 => on_demand::Located::Found(first[0]),
            SlotRead::Present(_) => on_demand::Located::None,
            SlotRead::Fault(why) => on_demand::Located::Fault(why),
            SlotRead::Absent => on_demand::Located::None,
        }
    }
}

/// A [`SlotLocator`] that narrows by `rp_id_hash` and then by credential ID.
///
/// # Why the second narrowing is not free, and what it costs
///
/// The index stores a **truncated MAC of the `rp_id_hash` and nothing else** —
/// no credential ID, by design (`index.rs`: "That is the entire content… no
/// credential ID, no RP name, no user name, no public key"). So an
/// exact-by-credential-ID query cannot be answered from the index alone, and
/// this locator has to open candidates to answer it:
///
/// 1. `index::lookup_all` for the RP — index slots only, no decryption;
/// 2. each candidate slot is read and unsealed **once**, inside a
///    [`record::Plaintext`] that zeroizes itself on drop, and the caller's
///    [`CredentialProbe`] decides whether that is the credential asked for.
///
/// The winning slot is then handed to [`on_demand::load`], which reads and
/// unseals it a second time to put it in the window. So the cost is
/// `candidates + 1` AEAD operations.
///
/// **That extra pass exists because the window has exactly one writer.**
/// [`CredentialWindow`] exposes no `&mut [u8]` and no constructor from bytes
/// (`on_demand.rs`: "Only `load` can write to it — there is no public
/// `&mut [u8]` and no constructor from bytes, so 'the only way plaintext enters
/// this buffer is the AEAD' is structural"). Exposing an `adopt` to avoid the
/// re-read would make that invariant depend on every future caller instead of on
/// the one `on_demand::load`. One extra AEAD is the cheaper of the two.
pub struct CredentialIdLocator<'a> {
    index_key: &'a IndexKey,
    payload_key: &'a PayloadKey,
    rp_id_hash: Option<RpIdHash>,
    credential_id: &'a [u8],
    probe: &'a dyn CredentialProbe,
    examined: u32,
}

impl<'a> CredentialIdLocator<'a> {
    /// Narrow by RP when one is known, then by credential ID.
    ///
    /// `rp_id_hash: None` searches **every** FIDO entry — the right behaviour
    /// and not merely the cautious one, because a credential ID a browser sends
    /// begins with the RP's `rp_id_hash` (CTAP 2.1 §5.8.3), so a caller that
    /// has one should hand it over rather than making the store scan.
    ///
    /// **The `None` walk is bounded at [`MAX_RP_CREDENTIALS`] and stops there.**
    /// That is not the same as "every FIDO entry" on a full device, and it is
    /// stated rather than left implicit: a credential beyond the bound is
    /// reported `Absent`, so a site with 17 passkeys cannot delete the 17th
    /// through this path. The bound is a **stack** decision — the candidate array
    /// is one [`Slot`] each, so 16 costs 32 B — and the alternative, a walk
    /// proportional to capacity, turns one attacker-chosen credential ID into one
    /// AEAD per index entry (856 of them). CTAP puts no limit on how many
    /// passkeys one site may register, so this is a real limit; it is the
    /// cheaper of the two, and the one whose cost is visible.
    ///
    /// The payload key is here because this locator is what opens the
    /// candidates: without it the search would have to ask the index for the
    /// credential ID, which `index.rs` deliberately never stores. The cost is
    /// that a by-ID lookup needs the PIN and an enumeration does not — which is
    /// the split `crypto.rs` derives two keys for.
    pub fn new(
        index_key: &'a IndexKey,
        payload_key: &'a PayloadKey,
        rp_id_hash: Option<RpIdHash>,
        credential_id: &'a [u8],
        probe: &'a dyn CredentialProbe,
    ) -> Self {
        CredentialIdLocator {
            index_key,
            payload_key,
            rp_id_hash,
            credential_id,
            probe,
            examined: 0,
        }
    }

    /// How many candidates the last [`SlotLocator::locate`] unsealed.
    ///
    /// Reset by every call, so a caller can measure one lookup rather than the
    /// accumulated total. It is the observable form of "one AEAD per candidate,
    /// plus one for the winner" — the winner's own open is counted by
    /// [`on_demand::testing::unseal_attempts`], which is the only counter that
    /// can see it because `on_demand`'s witness function is `pub(super)` and
    /// deliberately not callable from a sibling module.
    pub fn examined(&self) -> u32 {
        self.examined
    }
}

impl SlotLocator for CredentialIdLocator<'_> {
    fn locate(
        &mut self,
        region: &mut dyn KeyRegion,
        _want: &SlotQuery<'_>,
    ) -> on_demand::Located {
        self.examined = 0;
        let mut candidates: [Slot; MAX_RP_CREDENTIALS] = [first_slot(); MAX_RP_CREDENTIALS];
        // **`rp_id_hash: None` is a domain-wide walk, not a lookup with a zero
        // hash.** This used to call `index::lookup_all` with
        // `RpIdHash::from_bytes([0u8; 32])`, which is wrong in a way that read
        // as a working feature: `lookup_all` *verifies* each entry's tag against
        // the hash it is handed, and no entry's tag is a MAC of an all-zero
        // `rp_id_hash` — so the branch returned zero candidates for every input
        // and every by-ID lookup without an RP silently answered "absent". Its
        // own comment claimed the opposite ("`lookup_all` filters by domain but
        // not by tag"), which is not what `lookup_all` does: the tag check is the
        // body of its walk (`index.rs`, `lookup_all`).
        //
        // The fix is the one shape that is actually right for an unknown RP:
        // enumerate the FIDO-domain entries structurally and apply the caller's
        // probe to each. That is `fido_slots`, and it is the same walk
        // `fido_entries` counts — one index scan, one 1 KiB image at a time, no
        // allocation (`index.rs`, "Why the entry is 32 bytes").
        //
        // The result is **unauthenticated in its first step**: an entry is a
        // candidate because it parses and names this domain, not because its tag
        // verified against anything. That is safe here precisely because every
        // candidate is then *opened* — `record::read` fails a tag — and the
        // probe compares the credential ID out of the opened plaintext. A forged
        // entry therefore buys an attacker one extra AEAD, not a credential.
        let count = match self.rp_id_hash {
            Some(ref hash) => match index::lookup_all(
                self.index_key,
                region,
                KeyDomain::Fido,
                hash,
                &mut candidates,
            ) {
                SlotRead::Present(n) => n.min(MAX_RP_CREDENTIALS),
                SlotRead::Fault(why) => return on_demand::Located::Fault(why),
                SlotRead::Absent => return on_demand::Located::None,
            },
            None => {
                let mut n = 0usize;
                let mut ordinal = 0u32;
                while ordinal < index::index_capacity() && n < MAX_RP_CREDENTIALS {
                    let Some(slot) = index::entry_slot(ordinal) else {
                        return on_demand::Located::Fault(index::E_INDEX_SLOT_UNREADABLE);
                    };
                    let raw = match region.read_slot(slot) {
                        Ok(raw) => raw,
                        Err(why) => return on_demand::Located::Fault(why),
                    };
                    let at = index::entry_offset(ordinal) as usize;
                    if let SlotRead::Present(entry) =
                        IndexEntry::decode(&raw[at..at + index::INDEX_ENTRY_BYTES])
                    {
                        if entry.domain() == KeyDomain::Fido {
                            candidates[n] = entry.slot();
                            n += 1;
                        }
                    }
                    ordinal += 1;
                }
                n
            }
        };
        for &slot in candidates.iter().take(count) {
            self.examined += 1;
            let raw = match region.read_slot(slot) {
                Ok(raw) => raw,
                Err(why) => return on_demand::Located::Fault(why),
            };
            // `record::read` is the whole read path (`record.rs`, "The whole
            // read path"), so an erased slot, a bad header CRC, a transplanted
            // header and a failed tag all arrive as `Absent` and one bad record
            // costs itself alone — US-1549's fail-closed property, inherited
            // rather than reimplemented. `Plaintext` zeroizes its own buffer on
            // drop, so no candidate's plaintext outlives the comparison.
            match record::read(slot, &raw, self.payload_key.as_bytes()) {
                SlotRead::Present(plaintext) => {
                    if self.probe.matches(plaintext.as_slice(), self.credential_id) {
                        return on_demand::Located::Found(slot);
                    }
                }
                SlotRead::Fault(why) => return on_demand::Located::Fault(why),
                SlotRead::Absent => {}
            }
        }
        on_demand::Located::None
    }
}

/// Recognises a credential ID inside an opened record's plaintext.
///
/// A trait rather than a byte comparison because **deciding where the credential
/// ID lives in a record's plaintext is the caller's business**: this module owns
/// the sealing, the applet owns the CBOR map layout, and a second parser here
/// would be a second definition of a record's contents — the defect class
/// `AGENTS.md` §5 names ("one record format, one region, one key hierarchy").
pub trait CredentialProbe {
    /// Does this plaintext hold `credential_id`?
    ///
    /// Returning `true` is a claim that the record **is** that credential, so
    /// the comparison must cover the whole ID and not a prefix.
    fn matches(&self, plaintext: &[u8], credential_id: &[u8]) -> bool;
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// What one [`FidoRecordStore::put`] did, so a caller can check the erasure
/// count rather than trust it.
///
/// The gherkin's "exactly one slot is erased and programmed" is a statement about
/// **sectors**, because on this part the sector is the erase unit (`mod.rs`,
/// "Slots per NOR sector"): updating one credential erases one sector and
/// programs four slots, three of which carry unchanged records copied verbatim.
/// So [`CommitReport::live_erases`] is the number that means "one", and it is
/// returned rather than asserted in a comment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PutReport {
    /// Where the record landed.
    pub slot: Slot,
    /// The generation it carries.
    pub generation: u32,
    /// What the commit did to the medium.
    pub commit: CommitReport,
    /// The index slot the entry was written into.
    pub index_slot: Slot,
}

/// What one [`FidoRecordStore::delete`] did, so a caller can check the index
/// half landed rather than trust the return value.
///
/// Returned for the same reason [`PutReport`] is: the gherkin's claims here are
/// about the medium ("the slot is erased", "the credential is gone"), and a
/// number a caller can assert is worth more than a comment asserting it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeleteReport {
    /// The slot the tombstone landed in.
    pub slot: Slot,
    /// The generation the tombstone carries — one past whatever was there.
    pub generation: u32,
    /// What the record commit did to the medium.
    pub commit: CommitReport,
    /// The index slot the first cleared entry was in.
    ///
    /// `None` when the slot had no entry at all — a record the index never knew
    /// about, which [`FidoRecordStore::put`]'s fault table names as the orphan
    /// case. Such a credential was already unfindable, so the delete is still
    /// correct; the `None` is there so a caller can tell it from "an entry was
    /// removed".
    pub index_slot: Option<Slot>,
}

/// What one [`FidoRecordStore::compact`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactionReport {
    /// The live sector that was considered, reported even for a no-op so a
    /// caller can tell "this sector was already full" from "you named a slot
    /// outside FIDO's range" — which is an error, not a report.
    pub sector: Slot,
    /// Slots that are erased in the sector afterwards. **Zero means no erase was
    /// issued at all**: the sector was already full, and the same discipline
    /// `commit::recover`'s "nothing staged at all" follows.
    pub slots_erased: u32,
    /// Programs into the scratchpad: one per surviving record.
    pub staged_programs: u32,
}

impl Default for CompactionReport {
    /// An empty report. Never constructed by the library — the `Default` exists
    /// so a caller writing `CompactionReport { sector, ..Default::default() }`
    /// does not have to remember which half is optional. Named rather than
    /// derived so the type stays `Copy` and 20 bytes rather than growing an
    /// `Option<Slot>` the size of which is platform-dependent.
    fn default() -> Self {
        CompactionReport {
            sector: first_slot(),
            slots_erased: 0,
            staged_programs: 0,
        }
    }
}

/// The FIDO credential store: one record per credential, nothing resident.
///
/// Construct with [`FidoRecordStore::new`] and use it for the lifetime of one
/// applet activation. It owns **no** persistent state — that is the design, and
/// the module docs say why: a store with no in-RAM copy cannot latch dirty
/// state, which is the gherkin's last clause as a property of the shape rather
/// than of a rollback path.
///
/// # Keys
///
/// Two, and the split is not a convenience. [`IndexKey`] is OTP-rooted and
/// PIN-free, so *finding* a credential never needs the user's PIN — which is what
/// makes the index usable from a dump and keeps a lookup off the PIN path.
/// [`PayloadKey`] is PIN-derived, so *opening* one does. A caller holding the
/// index key and not the payload key can enumerate what a device holds and read
/// none of it.
pub struct FidoRecordStore<'region> {
    region: &'region mut dyn KeyRegion,
}

impl FidoRecordStore<'_> {
    /// Wrap a region.
    ///
    /// **Nothing is read here.** No discovery scan, no `recover`, no index
    /// probe: S8/S9 forbid the boot path from touching the key region, and a
    /// constructor is exactly the sort of thing a boot path calls. The first
    /// read happens in the first operation the applet performs, which is after
    /// `RUNG_USB`.
    pub fn new(region: &mut dyn KeyRegion) -> FidoRecordStore<'_> {
        FidoRecordStore { region }
    }

    /// How many FIDO credentials this region holds: [`FIDO_CAPACITY`](super::FIDO_CAPACITY).
    ///
    /// **Derived, never asserted** — `mod.rs`'s "Capacities" section names the
    /// four terms (region − OATH − scratchpad − index) and its compile-time
    /// assertion refuses a build in which they do not sum to `TOTAL_SLOTS`.
    /// **856** at the shipping geometry: 3.3× the 256 the acceptance criteria
    /// name, and 214× the four a soak board actually held.
    pub const fn capacity() -> u32 {
        FIDO_CAPACITY
    }

    /// The region, for the operations that need it directly.
    pub fn region(&mut self) -> &mut dyn KeyRegion {
        self.region
    }

    /// Finish, or abandon, a commit a power cut interrupted.
    ///
    /// Idempotent, and cheap when there is nothing staged: four slot reads and
    /// **no erase** (`commit::recover`, "Nothing staged at all"). It is the first
    /// thing [`Self::put`] does, which is what makes retrying after any error
    /// safe rather than destructive — including after
    /// [`CommitError::Incomplete`]. A caller that wants to be sure before its
    /// *first* operation can call it explicitly, and must not do so on the boot
    /// path (S9).
    pub fn recover(&mut self) -> Result<Recovery, FidoStoreError> {
        commit::recover(self.region, scratchpad_slot())
            .map_err(FidoStoreError::RegionUnreadable)
    }

    /// Write one credential record, then one index entry for it.
    ///
    /// # Order, and why it is that order
    ///
    /// 1. [`Self::recover`] — a previous failure must not leave the region in a
    ///    state this write would build on.
    /// 2. [`FidoAllocator::alloc`] — the lowest free slot, at its next
    ///    generation.
    /// 3. [`record::seal`] under an AAD naming *this* slot and generation. The
    ///    seal happens before the commit and never after, because
    ///    `commit::commit` copies the sealed bytes through a scratchpad: one
    ///    nonce per record, and the bytes are moved, never re-encrypted
    ///    (`commit.rs`, "Why this module does not seal anything").
    /// 4. [`commit::commit`] — one sector erase, four slot programs, target
    ///    last. Atomic: a power cut leaves generation *N* readable or the
    ///    complete generation *N+1*, never a mixture.
    /// 5. [`write_index_entry`]. **Last**, because an index entry naming a slot
    ///    with no record in it reads as a credential that is not one, while a
    ///    record with no entry is merely *unfindable* — and `index.rs` states
    ///    that direction deliberately ("a lost entry makes a credential
    ///    unfindable, whereas an invented one would have to carry a valid tag to
    ///    be believed").
    ///
    /// # Rollback
    ///
    /// There is nothing to roll back *into*, because this store holds no copy. A
    /// failure at 1–4 leaves the previous records exactly as they were: the
    /// commit is sector-atomic and the scratchpad is swept by the next
    /// [`Self::recover`]. A failure at 5 leaves a record whose slot is occupied
    /// and whose entry is missing — an orphan, not a corruption, repaired by
    /// enrolling the credential again. Both are reported; neither is silent.
    ///
    /// # The nonce
    ///
    /// Supplied by the caller and required to be unique per
    /// `(key, slot, generation)`. The store does not derive it, for the reason
    /// [`record::seal`]'s own docs give: it cannot know the caller's source of
    /// uniqueness, and a store that derived its own would be a third nonce
    /// policy beside `snapshot_crypt`'s and `store_v3`'s.
    pub fn put(
        &mut self,
        payload_key: &PayloadKey,
        index_key: &IndexKey,
        nonce: &[u8; record::NONCE_LEN],
        rp_id_hash: &RpIdHash,
        plaintext: &[u8],
    ) -> Result<PutReport, FidoStoreError> {
        let max = super::FIDO_RECORD_MAX as usize;
        if plaintext.len() > max {
            return Err(FidoStoreError::CredentialTooLarge { len: plaintext.len(), max });
        }

        // 1.
        self.recover()?;
        // 2.
        let allocation = FidoAllocator::alloc(self.region)?;
        // 3.
        let header = RecordHeader::new(Domain::Fido, allocation.slot, allocation.generation);
        let sealed = record::seal(&header, payload_key.as_bytes(), nonce, plaintext)
            .map_err(FidoStoreError::Record)?;
        // 4.
        let plan = CommitPlan::new(
            scratchpad_slot(),
            allocation.slot,
            Domain::Fido,
            allocation.generation,
        );
        let commit = commit::commit(self.region, plan, &sealed).map_err(FidoStoreError::Commit)?;
        // 5.
        let entry = IndexEntry::build(
            index_key,
            KeyDomain::Fido,
            allocation.slot,
            allocation.generation,
            rp_id_hash,
        );
        let index_slot = write_index_entry(self.region, entry)?;
        Ok(PutReport {
            slot: allocation.slot,
            generation: allocation.generation,
            commit,
            index_slot,
        })
    }

    /// Rewrite the record already in `slot`, and the index entry that names it.
    ///
    /// # What this is for
    ///
    /// **A signature-counter bump**, which changes one field of a record that is
    /// already stored — [`Self::put`]'s job is the opposite, and its allocator
    /// would hand a counter bump a *new* slot and strand the old one.
    ///
    /// # The generation, and why it advances
    ///
    /// The commit is offered `current + 1`, because [`commit::commit`] refuses a
    /// commit that does not advance the generation and the refusal is right: a
    /// write at the generation already in the slot is a replay by another name.
    /// That in turn is why this function rewrites the **index entry** rather than
    /// leaving it alone — see [`SECTOR_ERASES_PER_COUNTER_WRITE`] for the whole
    /// argument, including what the extra half of the wear buys and what it does
    /// not.
    ///
    /// # Order, and it is [`Self::put`]'s order with one difference
    ///
    /// Record first, index second, for the reason `put` gives: a record with no
    /// entry is *unfindable*, while an entry naming a slot whose record is stale
    /// reads as a credential at a generation the region does not hold. The
    /// difference is that the index write is a **rewrite of an existing cell**
    /// ([`rewrite_index_entry`]) rather than an append — appending here would
    /// leave two entries naming one slot, and every enumeration would return the
    /// credential twice.
    ///
    /// # The fault window
    ///
    /// Inherits both halves of the fault tables above it, and they are the same
    /// ones: a cut inside the record commit leaves generation *N* readable
    /// (`commit.rs`'s phase table); a cut inside the index rewrite leaves up to
    /// [`SLOTS_PER_SECTOR`] × [`index::ENTRIES_PER_SLOT`] entries unfindable,
    /// which makes credentials unfindable and destroys none. In the middle —
    /// after the record commit and before the index rewrite — the index names a
    /// generation the record has left behind, and a tag check against the
    /// *record's* generation would fail. That is the safe direction: the entry
    /// is not deleted, only described as an older generation of a slot that
    /// still holds the credential, and re-running the rewrite repairs it.
    ///
    /// `slot` must already hold a FIDO record. Over an erased slot this is
    /// [`Self::put`]'s job, and refusing is what keeps "a counter write" from
    /// quietly becoming "an enrolment".
    pub fn update(
        &mut self,
        payload_key: &PayloadKey,
        index_key: &IndexKey,
        slot: Slot,
        nonce: &[u8; record::NONCE_LEN],
        rp_id_hash: &RpIdHash,
        plaintext: &[u8],
    ) -> Result<PutReport, FidoStoreError> {
        let max = super::FIDO_RECORD_MAX as usize;
        if plaintext.len() > max {
            return Err(FidoStoreError::CredentialTooLarge { len: plaintext.len(), max });
        }
        if !is_fido_slot(slot) {
            return Err(FidoStoreError::RegionUnreadable(
                "an update named a slot outside the FIDO range",
            ));
        }
        // 1.
        self.recover()?;
        // 2. `0` means "empty, or a record this build cannot read", and an
        //    enrolment is the operation for that: allocating here would pick a
        //    different slot and leave `slot`'s index entry naming whatever is
        //    already there, which is a second definition of "where this
        //    credential lives".
        let current = self.record_generation(slot)?;
        if current == 0 {
            return Err(FidoStoreError::RegionUnreadable(
                "an update named a slot that holds no FIDO record",
            ));
        }
        let generation = current.checked_add(1).ok_or(FidoStoreError::Full)?;
        // 3.
        let header = RecordHeader::new(Domain::Fido, slot, generation);
        let sealed = record::seal(&header, payload_key.as_bytes(), nonce, plaintext)
            .map_err(FidoStoreError::Record)?;
        // 4.
        let plan =
            CommitPlan::new(scratchpad_slot(), slot, Domain::Fido, generation);
        let commit = commit::commit(self.region, plan, &sealed).map_err(FidoStoreError::Commit)?;
        // 5.
        let entry = IndexEntry::build(index_key, KeyDomain::Fido, slot, generation, rp_id_hash);
        let index_slot = rewrite_index_entry(self.region, slot, entry)?;
        Ok(PutReport { slot, generation, commit, index_slot })
    }

    /// Load one credential of one RP into `out`, opening nothing else.
    ///
    /// The single-decryption path, and the one [`on_demand::load`] exists to
    /// provide: the index names a slot from index slots alone, then that one
    /// slot is read and unsealed once. `out` is cleared first and on drop
    /// (`CredentialWindow`), so a lookup that fails cannot serve the previous
    /// operation's credential.
    ///
    /// With several credentials for one RP this answers with the index's choice
    /// of one — the first in index order, which is deterministic for a given
    /// region (`index::lookup`, "The first match in index order wins"). Use
    /// [`Self::load_by_credential_id`] when the credential ID is known, and
    /// [`Self::slots_for_rp`] when the whole set is wanted.
    pub fn load_by_rp(
        &mut self,
        payload_key: &PayloadKey,
        index_key: &IndexKey,
        rp_id_hash: &RpIdHash,
        out: &mut CredentialWindow,
    ) -> SlotRead<OnDemandHit> {
        let mut locator = IndexLocator::any_for_rp(index_key, *rp_id_hash);
        // `on_demand::SlotQuery::RpIdTag` and `index::RpIdHash` are both
        // 32-byte SHA-256 outputs, and the assertion below pins that; the tag is
        // *borrowed* from the `RpIdHash` rather than re-derived, because a second
        // tag function is the exact defect `on_demand::rp_id_tag` documents and
        // asks its successor not to repeat.
        let tag: &[u8; on_demand::RP_ID_TAG_LEN] = rp_id_hash.as_bytes();
        on_demand::load(self.region, &mut locator, payload_key, &SlotQuery::RpIdTag { tag }, out)
    }

    /// Load the credential of `rp_id_hash` whose credential ID is
    /// `credential_id`.
    ///
    /// Costs `candidates + 1` AEAD operations rather than one — see
    /// [`CredentialIdLocator`]'s docs for why the index cannot answer it alone
    /// and why the extra pass is preferred to widening the window's single-writer
    /// invariant.
    pub fn load_by_credential_id(
        &mut self,
        payload_key: &PayloadKey,
        index_key: &IndexKey,
        rp_id_hash: Option<&RpIdHash>,
        credential_id: &[u8],
        probe: &dyn CredentialProbe,
        out: &mut CredentialWindow,
    ) -> SlotRead<OnDemandHit> {
        let mut locator =
            CredentialIdLocator::new(index_key, payload_key, rp_id_hash.copied(), credential_id, probe);
        // The query's own fields are unused by this locator — it narrows by the
        // RP it holds and by the credential ID it holds — but `on_demand::load`
        // hands them to `locate`, so one has to exist. A tag-only query is the
        // honest choice: it is what the locator will not use, and claiming
        // otherwise would be a lie a future caller could act on.
        let tag: &[u8; on_demand::RP_ID_TAG_LEN] = match rp_id_hash {
            Some(hash) => hash.as_bytes(),
            None => &[0u8; on_demand::RP_ID_TAG_LEN],
        };
        on_demand::load(
            self.region,
            &mut locator,
            payload_key,
            &SlotQuery::RpIdTag { tag },
            out,
        )
    }

    /// Every FIDO slot whose index entry authenticates `rp_id_hash`.
    ///
    /// Index slots only — no payload key is in this signature, so there is
    /// nowhere for one to arrive (`index.rs` makes the same argument about
    /// `lookup`). This is the enumeration a credential-management
    /// `enumerateRPsBegin` needs, and the one `getAssertion` builds its
    /// candidate list from without decrypting anything.
    ///
    /// Returns the **total** number of matches, which may exceed `out.len()`, so
    /// a caller can tell "that was all of them" from "that was all that fit".
    pub fn slots_for_rp(
        &mut self,
        index_key: &IndexKey,
        rp_id_hash: &RpIdHash,
        out: &mut [Slot],
    ) -> SlotRead<usize> {
        index::lookup_all(index_key, self.region, KeyDomain::Fido, rp_id_hash, out)
    }

    /// What the region's index holds, counted without a key.
    ///
    /// [`index::inspect_region`] is the PIN-free structural pass: `present`,
    /// `free` and `malformed` counters over every reserved entry cell.
    ///
    /// This is deliberately **not** an authenticated count. `index.rs` states
    /// why an unauthenticated number is the one worth having here: no PIN-free
    /// operation certifies an entry in the abstract, because the MAC is checked
    /// against a message containing the `rp_id_hash`, which this call does not
    /// have. `malformed` is the field that matters operationally — a non-zero
    /// value is the difference between "the index is intact" and "the index is
    /// intact except for the sector a power cut landed in".
    pub fn inspect_index(&mut self) -> SlotRead<index::IndexSlotReport> {
        index::inspect_region(self.region)
    }

    /// Verify the index against a set of `rp_id_hash`es, with no PIN and no
    /// payload key.
    ///
    /// A thin re-export of [`index::verify`] so a caller holding only a
    /// `FidoRecordStore` does not have to reach past it for the one operation
    /// that must run off a dump.
    pub fn verify_index(
        &mut self,
        index_key: &IndexKey,
        rp_id_hashes: &[RpIdHash],
    ) -> SlotRead<index::Verification> {
        index::verify(index_key, self.region, KeyDomain::Fido, rp_id_hashes)
    }

/// Every FIDO-domain index entry in the region, in index order.
    ///
    /// **Structural, and unauthenticated.** An entry is reported because it
    /// parses and names `KeyDomain::Fido`; nothing here checks its tag, because
    /// a tag can only be checked against an `rp_id_hash` the caller holds and
    /// this signature has none — the same limit `index.rs` states for
    /// [`inspect_region`](Self::inspect_index), whose `malformed` counter is the
    /// operational half of the same answer.
    ///
    /// The count is what `remainingDiscoverableCredentialsCount` is computed
    /// from, and that is a deliberate choice over counting *records*: the index
    /// is what decides whether a credential can be found, so an entry is a
    /// credential as far as the wire is concerned, and a record with no entry is
    /// invisible to the user — the direction `FidoRecordStore::put`'s docs call
    /// the safe one.
    pub fn fido_entries(&mut self) -> SlotRead<u32> {
        let mut found = 0u32;
        let mut ordinal = 0u32;
        while ordinal < index::index_capacity() {
            let slot = match index::entry_slot(ordinal) {
                Some(s) => s,
                None => return SlotRead::Fault(index::E_INDEX_SLOT_UNREADABLE),
            };
            let raw = match self.region.read_slot(slot) {
                Ok(raw) => raw,
                Err(why) => return SlotRead::Fault(why),
            };
            let at = index::entry_offset(ordinal) as usize;
            if let SlotRead::Present(entry) =
                IndexEntry::decode(&raw[at..at + index::INDEX_ENTRY_BYTES])
            {
                if entry.domain() == KeyDomain::Fido {
                    found += 1;
                }
            }
            ordinal += 1;
        }
        SlotRead::Present(found)
    }

    /// How many FIDO credentials this region still has room for.
    ///
    /// [`FIDO_CAPACITY`](super::FIDO_CAPACITY) minus the live index entries, and
    /// the expression the credMgmt `getMetadata` reply answers
    /// `maxPossibleRemainingResidentCredentialsCount` with. It is a **count**,
    /// not a promise: a tombstone left by an uncompacted delete still occupies
    /// its slot, so it is excluded here exactly as it is excluded from the
    /// allocator's free list — the two numbers come from the same two facts
    /// (entries for the first, occupancy for the second), which is what keeps a
    /// wire claim and the command path from disagreeing (AGENTS.md §4).
    ///
    /// `None` rather than `0` on a fault: "the index could not be read" is not
    /// "the device is full", and reporting the latter would refuse enrolments
    /// with a claim about capacity the device never established.
    pub fn remaining_capacity(&mut self) -> Option<u32> {
        match self.fido_entries() {
            SlotRead::Present(used) => FIDO_CAPACITY.checked_sub(used),
            SlotRead::Absent | SlotRead::Fault(_) => None,
        }
    }

    /// Delete the credential in `slot`: a tombstone commit, then a cleared index
    /// entry.
    ///
    /// # Order, and why a tombstone rather than an erase
    ///
    /// The record half first. `commit.rs` has no single-slot delete on purpose
    /// ("Why there is no single-slot delete here") — an erased target is
    /// indistinguishable from a commit that never reached its witness, so
    /// `recover` would resurrect the delete as a replay. [`TOMBSTONE_BODY`] is an
    /// ordinary record, so the delete is a normal atomic commit, and
    /// `commit::commit`'s own generation check makes the replay impossible.
    ///
    /// The index half second, for the same ordering argument `put` uses: a
    /// record with no entry is merely *unfindable*, while an entry naming a slot
    /// whose record is a tombstone is a credential that reads as deleted on
    /// every path — which is the direction we want if the power fails between
    /// the two.
    ///
    /// `nonce` is the caller's, on the same terms as [`Self::put`]: unique per
    /// `(key, slot, generation)`, and the generation is one past whatever the
    /// slot already carried, so a nonce the deleted credential spent cannot be
    /// spent again here.
    pub fn delete(
        &mut self,
        payload_key: &PayloadKey,
        slot: Slot,
        nonce: &[u8; record::NONCE_LEN],
    ) -> Result<DeleteReport, FidoStoreError> {
        if !is_fido_slot(slot) {
            return Err(FidoStoreError::RegionUnreadable(
                "a delete named a slot outside the FIDO range",
            ));
        }
        self.recover()?;
        let current = self.record_generation(slot)?;
        let generation = current
            .checked_add(1)
            .ok_or(FidoStoreError::Full)?;
        let header = RecordHeader::new(Domain::Fido, slot, generation);
        let sealed = record::seal(&header, payload_key.as_bytes(), nonce, &TOMBSTONE_BODY)
            .map_err(FidoStoreError::Record)?;
        let plan = CommitPlan::new(scratchpad_slot(), slot, Domain::Fido, generation);
        let commit = commit::commit(self.region, plan, &sealed).map_err(FidoStoreError::Commit)?;
        // The entry is cleared **by slot**, not by `(slot, generation)`: a
        // caller deleting a credential it found may hold an entry written for
        // an earlier generation of that slot, and leaving that one behind would
        // keep the deleted credential findable on every enumeration. Every entry
        // naming this slot is removed, because every one of them names a record
        // that is now a tombstone.
        let index_slot = clear_index_entries(self.region, slot)?;
        Ok(DeleteReport { slot, generation, commit, index_slot })
    }

    /// The generation a record in `slot` currently carries; `0` for an empty or
    /// unreadable slot.
    ///
    /// Read through [`record::decode`], so a torn record counts as no record and
    /// therefore as generation 0 — the direction `commit.rs`'s `read_generation`
    /// argues for: refusing to write over a corrupt record would leave the owner
    /// permanently unable to enrol into that slot.
    pub fn record_generation(&mut self, slot: Slot) -> Result<u32, FidoStoreError> {
        let raw = self.region.read_slot(slot).map_err(FidoStoreError::RegionUnreadable)?;
        Ok(match record::decode(slot, &raw) {
            SlotRead::Present(decoded) => decoded.header().generation(),
            SlotRead::Absent | SlotRead::Fault(_) => 0,
        })
    }

    /// Free the slots of one sector that hold tombstones, leaving its live
    /// records byte-identical.
    ///
    /// # Why a delete is not enough
    ///
    /// [`Self::delete`] makes the credential *gone* but leaves its slot occupied:
    /// `FidoAllocator` reads occupancy out of the record header, and a tombstone
    /// is a record, so the slot stays off the free list forever. Without this
    /// operation a device that enrolled and deleted credentials would leak one
    /// slot per delete until it refused an enrolment at a capacity it still has
    /// room for — a wire claim about capacity the device does not honour, which
    /// is the defect AGENTS.md §4 is about.
    ///
    /// # Why it takes the payload key
    ///
    /// **Because a tombstone is a record, not an erase, so nothing structural
    /// distinguishes it.** The header of a deleted credential is a perfectly
    /// good record header, and its slot is as occupied as a live one's. Telling
    /// them apart means *opening* the body, and only the payload key can.
    ///
    /// That is the cost of the tombstone shape, and it is worth naming rather than
    /// hiding: a compaction is [`SLOTS_PER_SECTOR`] AEAD operations. The
    /// alternative — a `TOMBSTONE` bit in the record header, readable without a
    /// key — was refused because the flags byte is part of what
    /// [`record::RecordHeader`] authenticates into the AAD, so a new bit is a
    /// format version, and because four AEADs on a path that runs once per delete
    /// is not a cost worth a format change to avoid. `AGENTS.md` §5: take the
    /// simpler one.
    ///
    /// # Why it is safe where a record commit would not be
    ///
    /// This is a **sector rewrite** — stage, erase, copy back — the same three
    /// phases `write_index_entry` uses, and the same fault window (this file's
    /// "The index write, and why it is not a `commit`"). It is nevertheless the
    /// right shape here for a reason that does not apply to a record commit:
    ///
    /// * at every point before the erase, **nothing has changed** — the staged
    ///   set is discarded and the tombstone survives;
    /// * at every point after it, the staged set is a **complete** replacement
    ///   for the live sector: every live mate is in it, and the freed slot is
    ///   erased on both sides, which `commit::recover`'s replacement test scores
    ///   as "identical" — so a cut is replayed, reproducing the compacted state
    ///   byte for byte;
    /// * a tombstone carries nothing that is not already gone (its index entry
    ///   was cleared first), so **no cut point can lose a credential**.
    ///
    /// A record commit has none of that luxury: its target's *previous*
    /// generation is destroyed by the erase with nothing to restore it, which is
    /// the entire reason `commit.rs` stages through a scratchpad and refuses a
    /// single-slot delete.
    ///
    /// # A slot that is not a FIDO record is left alone
    ///
    /// An erased slot is already free and is left erased. A slot holding another
    /// domain's record, or one whose body does not open under the payload key, is
    /// **kept verbatim** — not treated as freeable and not treated as absent. A
    /// record this build cannot read still occupies its slot (US-1549's fail-closed
    /// property), and compacting it away would destroy a credential nobody has
    /// established is deleted.
    ///
    /// # Cost
    ///
    /// One scratchpad erase, one live erase, [`SLOTS_PER_SECTOR`] AEADs and one
    /// program per surviving mate — paid **once per delete**, off the boot path
    /// (S8/S9), and only for the sector the caller names. A sector with nothing to
    /// free costs four reads and **no erase**, the same discipline
    /// `commit::recover`'s "nothing staged at all" follows.
    pub fn compact(
        &mut self,
        payload_key: &PayloadKey,
        sector: Slot,
    ) -> Result<CompactionReport, FidoStoreError> {
        self.recover()?;
        let live_base = commit::sector_base(sector);
        if !is_fido_slot(live_base)
            || commit::sector_base_index(scratchpad_slot()) == live_base.index() as u32
        {
            return Err(FidoStoreError::RegionUnreadable(
                "a compaction named a sector that is not inside FIDO's range",
            ));
        }
        let scratch_base = commit::sector_base(scratchpad_slot());

        // Which slots survive, and whether anything is freeable. `keep` is the
        // decision per slot; `freeable` is "at least one slot changed", which is
        // the only thing that earns an erase.
        let mut keep = [true; SLOTS_PER_SECTOR as usize];
        let mut freeable = false;
        let mut offset = 0u32;
        while offset < SLOTS_PER_SECTOR {
            let live = slot_in_sector(live_base, offset)?;
            let raw = self.region.read_slot(live).map_err(FidoStoreError::RegionUnreadable)?;
            match classify_slot(live, &raw, payload_key) {
                // Already erased: nothing to do, and nothing to copy either.
                SlotShape::Erased => {
                    keep[offset as usize] = false;
                }
                // A tombstone: this is the slot the compaction exists to free.
                SlotShape::Tombstone => {
                    keep[offset as usize] = false;
                    freeable = true;
                }
                // A live record, a foreign one, or one this build cannot open —
                // all copied verbatim. See the doc's "A slot that is not a FIDO
                // record is left alone".
                SlotShape::Keep => {
                    keep[offset as usize] = true;
                }
            }
            offset += 1;
        }
        if !freeable {
            // Nothing to free. **No erase** — the same discipline `commit`'s
            // `recover` follows, so a compaction over a full sector costs four
            // slot reads and no wear.
            return Ok(CompactionReport {
                sector: live_base,
                slots_erased: 0,
                staged_programs: 0,
            });
        }

        // Stage. Every surviving slot is copied verbatim; the freed ones are left
        // erased in the staged image, which is what makes the copy-back *erase*
        // them rather than leave stale bytes.
        self.region
            .erase_sector(scratch_base)
            .map_err(FidoStoreError::RegionUnreadable)?;
        let mut programs = 0u32;
        offset = 0u32;
        while offset < SLOTS_PER_SECTOR {
            if keep[offset as usize] {
                let live = slot_in_sector(live_base, offset)?;
                let bytes = self
                    .region
                    .read_slot(live)
                    .map_err(FidoStoreError::RegionUnreadable)?;
                self.region
                    .program(slot_in_sector(scratch_base, offset)?, 0, &bytes)
                    .map_err(FidoStoreError::RegionUnreadable)?;
                programs += 1;
            }
            offset += 1;
        }

        self.region
            .erase_sector(live_base)
            .map_err(FidoStoreError::RegionUnreadable)?;

        let mut erased = 0u32;
        offset = 0u32;
        while offset < SLOTS_PER_SECTOR {
            let staged = slot_in_sector(scratch_base, offset)?;
            let bytes = self
                .region
                .read_slot(staged)
                .map_err(FidoStoreError::RegionUnreadable)?;
            if !is_erased(&bytes) {
                self.region
                    .program(slot_in_sector(live_base, offset)?, 0, &bytes)
                    .map_err(FidoStoreError::RegionUnreadable)?;
            }
            offset += 1;
        }
        // The count is what was **not** kept, not what the staged image happened
        // to hold: an erased-and-kept slot is impossible (it is not kept), so the
        // two agree, and deriving it from the decision rather than from the bytes
        // means a bookkeeping slip cannot under-report what was freed.
        for k in keep.iter() {
            if !*k {
                erased += 1;
            }
        }
        // Best effort, for the reason `commit`'s step 7 is: the live sector is
        // already correct, and a caller told `Err` would treat a rewrite that
        // happened as one that did not.
        let _ = self.region.erase_sector(scratch_base);
        Ok(CompactionReport { sector: live_base, slots_erased: erased, staged_programs: programs })
    }

    /// Erase every slot and entry this store owns.
    ///
    /// Wraps [`commit::wipe`] so a caller cannot wipe the records and leave the
    /// index pointing into them. `index.rs` splits that job in two ("a caller
    /// that needs 'the reset is complete or nothing happened' wipes the index
    /// first… and calls this afterwards"), and a whole-region erase is what
    /// makes the second half true. Not atomic across sectors and cannot be
    /// (`commit::wipe`, "What `wipe` promises").
    pub fn wipe(&mut self) -> Result<u32, FidoStoreError> {
        commit::wipe(self.region).map_err(FidoStoreError::RegionUnreadable)
    }
}

// ---------------------------------------------------------------------------
// Index writing
// ---------------------------------------------------------------------------

/// Insert one entry into the index, at sector granularity.
///
/// See the module docs, "The index write, and why it is not a `commit`", for the
/// fault table and for why the atomicity was left out.
///
/// # What it touches
///
/// One **sector** of the index — [`SLOTS_PER_SECTOR`] index slots, each holding
/// [`index::ENTRIES_PER_SLOT`] entries — plus the scratchpad sector it stages
/// through. No credential slot is read or written, and no payload key is
/// involved: an entry names a slot and a generation and says nothing about what
/// is in it.
///
/// Returns the index slot the entry landed in, for a caller that wants to log
/// it; the entry's *cell* is not returned because `index.rs` publishes no
/// ordinal→entry write, and inventing a second placement rule here is the
/// defect `find_free_entry_cell`'s own docs would then have to reconcile.
pub fn write_index_entry(
    region: &mut dyn KeyRegion,
    entry: IndexEntry,
) -> Result<Slot, FidoStoreError> {
    // 1. Where. One slot read per index slot, then a scan of its 32 cells —
    //    stopping at the first erased one, so a sparse index stays sparse and the
    //    write amplification is flat while there is room.
    let (target, at) = match find_free_entry_cell(region)? {
        Some(cell) => cell,
        None => return Err(FidoStoreError::IndexFull),
    };

    let live_base = commit::sector_base(target);
    let scratch_base = commit::sector_base(scratchpad_slot());
    let target_offset = target.index() as u32 - live_base.index() as u32;

    // 2a. Stage. Everything before the live erase leaves the index as it was,
    //     which is the same property `commit`'s phases 1–2 have and the reason
    //     staging exists. One slot image at a time — the page being modified, or
    //     the mate being copied — and never more than one.
    region
        .erase_sector(scratch_base)
        .map_err(FidoStoreError::IndexUnreadable)?;
    let mut offset = 0u32;
    while offset < SLOTS_PER_SECTOR {
        let live = slot_in_sector(live_base, offset)?;
        let mut bytes: SlotImage = region.read_slot(live).map_err(FidoStoreError::IndexUnreadable)?;
        if offset == target_offset {
            bytes[at as usize..at as usize + index::INDEX_ENTRY_BYTES].copy_from_slice(&entry.encode());
        }
        if !is_erased(&bytes) {
            region
                .program(slot_in_sector(scratch_base, offset)?, 0, &bytes)
                .map_err(FidoStoreError::IndexUnreadable)?;
        }
        offset += 1;
    }

    // 2b. The erase — the only irreversible step, and the only window in this
    //     function. Refusing to sweep the scratchpad afterwards is deliberate:
    //     the staged page is the only copy of that sector, and "tidying it up"
    //     is how an interrupted index write becomes permanent loss. The next
    //     [`commit::recover`] reads it, finds bytes that are not records, and
    //     sweeps it (`commit::recover`, "Partial, or spread across two sectors").
    region
        .erase_sector(target)
        .map_err(FidoStoreError::IndexUnreadable)?;

    // 2c. Copy back, one slot image at a time.
    offset = 0u32;
    while offset < SLOTS_PER_SECTOR {
        let staged = slot_in_sector(scratch_base, offset)?;
        let bytes = region.read_slot(staged).map_err(FidoStoreError::IndexUnreadable)?;
        if !is_erased(&bytes) {
            region
                .program(slot_in_sector(live_base, offset)?, 0, &bytes)
                .map_err(FidoStoreError::IndexUnreadable)?;
        }
        offset += 1;
    }
    // 2d. Retire. Best effort, for the reason `commit`'s step 7 is: the live
    //     sector already holds the new state, and a caller told `Err` would treat
    //     a write that *happened* as one that did not.
    let _ = region.erase_sector(scratch_base);
    Ok(target)
}

/// Remove every index entry naming `target`, and report the index slot the first
/// one was in.
///
/// # Why this is a splice rather than a write
///
/// **NOR cannot set a bit back from 0 to 1.** An entry cell that has been
/// programmed can only return to `0xFF` by erasing the sector it lives in — and
/// an index slot is a whole 1 KiB sector's worth of cells, so "erase one entry"
/// is "erase the sector and reprogram the other 31". That is the same
/// read-modify-write [`write_index_entry`] performs, and it inherits exactly its
/// fault table: a cut between the erase and the copy-back loses up to 31 entries,
/// which makes up to 31 credentials **unfindable**. Nothing is destroyed — the
/// records they name are still sealed in their slots, the allocator will not
/// hand those slots out, and the user re-enrols.
///
/// # Why the sector-granular shape is not a defect
///
/// A deletion is precisely the operation for which a partially-lost index is
/// least harmful: the entries most likely to be lost in the same sector are the
/// ones a delete has just removed. And the atomicity would buy nothing against
/// the only attacker who cares — one who can cut power between two flash
/// instructions can also erase the index outright, with no window at all. See
/// this file's module docs, "The index write, and why it is not a `commit`",
/// which reaches the same conclusion for [`write_index_entry`].
///
/// # Matched by slot, not by `(slot, generation)`
///
/// See [`FidoRecordStore::delete`]: a caller may hold an entry written for an
/// earlier generation of the slot it is deleting, and leaving that one behind
/// would keep a deleted credential visible to every enumeration.
fn clear_index_entries(
    region: &mut dyn KeyRegion,
    target: Slot,
) -> Result<Option<Slot>, FidoStoreError> {
    let want = target.index();
    let mut first: Option<Slot> = None;
    // One sector at a time, and as many passes as it takes. A slot's entry
    // lands in a single index slot in practice — `write_index_entry` always
    // takes the first erased cell, so entries fill densely and one delete touches
    // one sector — but "in practice" is not a property a loop should depend on,
    // and a second pass costs four slot reads when there is nothing to do.
    let mut pass = 0u32;
    while pass < INDEX_SLOT_COUNT {
        pass += 1;
        let Some((touched, _)) = find_entry_cell(region, want)? else {
            break;
        };
        if first.is_none() {
            first = Some(touched);
        }
        rewrite_index_sector(region, touched, |_offset, bytes| {
            let mut n = 0u32;
            while n < index::ENTRIES_PER_SLOT {
                let at = index::entry_offset(n) as usize;
                let cell = &bytes[at..at + index::INDEX_ENTRY_BYTES];
                if !IndexEntry::is_erased(cell) {
                    if let SlotRead::Present(e) = IndexEntry::decode(cell) {
                        if e.slot().index() == want {
                            bytes[at..at + index::INDEX_ENTRY_BYTES].fill(ERASED_CELL_BYTE);
                        }
                    }
                }
                n += 1;
            }
        })?;
    }
    Ok(first)
}

/// The index slot and byte offset of the first cell naming `want`, if any.
///
/// **Cell, not just slot**, because [`rewrite_index_entry`] has to overwrite the
/// entry that is already there: a rewrite that appended would leave two cells
/// naming one slot and every enumeration would return the credential twice.
/// `find_entry_sector`'s slot-only answer was enough for a delete — which clears
/// every cell naming the slot and so does not care where they are — and is not
/// enough for a rewrite, which does.
///
/// Matches on **slot only**, and the entry's tag is deliberately not checked: a
/// cell this build cannot parse is not this store's to rewrite, and overwriting
/// one would destroy a record this build does not own.
fn find_entry_cell(
    region: &mut dyn KeyRegion,
    want: u16,
) -> Result<Option<(Slot, u32)>, FidoStoreError> {
    let mut s = 0u32;
    while s < INDEX_SLOT_COUNT {
        let slot = index::entry_slot(s * index::ENTRIES_PER_SLOT)
            .ok_or(FidoStoreError::IndexUnreadable(index::E_INDEX_SLOT_UNREADABLE))?;
        let raw = region.read_slot(slot).map_err(FidoStoreError::IndexUnreadable)?;
        if let Some(at) = cell_naming(&raw, want) {
            return Ok(Some((slot, at)));
        }
        s += 1;
    }
    Ok(None)
}

/// The byte offset inside one index slot of a cell naming `want`.
fn cell_naming(raw: &SlotImage, want: u16) -> Option<u32> {
    let mut n = 0u32;
    while n < index::ENTRIES_PER_SLOT {
        let at = index::entry_offset(n);
        let cell = &raw[at as usize..at as usize + index::INDEX_ENTRY_BYTES];
        if !IndexEntry::is_erased(cell) {
            if let SlotRead::Present(e) = IndexEntry::decode(cell) {
                if e.slot().index() == want {
                    return Some(at);
                }
            }
        }
        n += 1;
    }
    None
}

/// Overwrite the one index cell naming `slot` with `entry`, at sector
/// granularity.
///
/// The in-place counterpart of [`write_index_entry`], and it shares that
/// function's fault table exactly: stage → erase the live index sector → copy
/// back → retire. A cut before the erase leaves the index as it was; a cut
/// between the erase and the copy-back leaves that sector **empty**, which makes
/// up to [`index::ENTRIES_PER_SLOT`] × [`SLOTS_PER_SECTOR`] credentials
/// *unfindable* and destroys none — their records are still sealed in their
/// slots, the allocator will not hand those slots out, and the user re-enrols.
///
/// **Why the cell is spliced rather than the whole slot rebuilt.** Splicing is
/// what keeps the entry's *position* stable, and a stable position is what lets
/// this find the same cell again after a failed write — a whole-slot rebuild
/// that re-derived the layout would be a second placement rule, which is the
/// defect [`write_index_entry`]'s own docs refuse to introduce.
pub fn rewrite_index_entry(
    region: &mut dyn KeyRegion,
    slot: Slot,
    entry: IndexEntry,
) -> Result<Slot, FidoStoreError> {
    let want = slot.index();
    let Some((live, at)) = find_entry_cell(region, want)? else {
        // The record exists but nothing names it: an orphan, which
        // `FidoRecordStore::put`'s fault table calls *unfindable* rather than
        // corrupt. Reported rather than repaired — inventing an entry here would
        // be the operation whose failure mode `index.rs` calls out: "an entry
        // naming a slot with no record reads as a credential that is not one",
        // and the converse of that rule is the one this call is on.
        return Err(FidoStoreError::IndexUnreadable(
            "no index entry names the slot being updated — the record is an orphan",
        ));
    };
    let bytes = entry.encode();
    // The splice lands in **one** cell — the one `find_entry_cell` named. The
    // edit closure is handed every slot image of the sector, so the offset has
    // to be guarded: an unguarded splice would write the entry at `at` of all
    // four slots, which both triplicates the entry (`fido_entries` counts three
    // credentials that are not there) and, on a dense index, overwrites the
    // entries of the three credentials whose cells sit at the same offset in the
    // mate slots — a counter bump corrupting three unrelated passkeys.
    let live_offset = live.index() as u32 - commit::sector_base(live).index() as u32;
    rewrite_index_sector(region, live, |offset, image| {
        if offset == live_offset {
            image[at as usize..at as usize + index::INDEX_ENTRY_BYTES].copy_from_slice(&bytes);
        }
    })?;
    Ok(live)
}

/// Erase `live`'s sector and reprogram it with `edit` applied to each slot image.
///
/// Stage → erase → copy back, one slot image at a time — the three phases and
/// the fault window `write_index_entry` documents, and the reason this function
/// exists as a closure-taking shape rather than two near-identical copies: the
/// delete and the counter-update paths differ by **one splice** and must not
/// differ by a staging protocol.
///
/// The staged set is a complete replacement for the live sector at every cut
/// point after the erase — the edited cells read the same on both sides, since
/// the staged image is a copy of the live one with the splice applied — so
/// `commit::recover` scores the staged sector as a legitimate replay rather than
/// abandoning it.
fn rewrite_index_sector(
    region: &mut dyn KeyRegion,
    live: Slot,
    mut edit: impl FnMut(u32, &mut SlotImage),
) -> Result<(), FidoStoreError> {
    let live_base = commit::sector_base(live);
    let scratch_base = commit::sector_base(scratchpad_slot());
    region
        .erase_sector(scratch_base)
        .map_err(FidoStoreError::IndexUnreadable)?;
    let mut offset = 0u32;
    while offset < SLOTS_PER_SECTOR {
        let from = slot_in_sector(live_base, offset)?;
        let mut bytes: SlotImage = region.read_slot(from).map_err(FidoStoreError::IndexUnreadable)?;
        edit(offset, &mut bytes);
        if !is_erased(&bytes) {
            region
                .program(slot_in_sector(scratch_base, offset)?, 0, &bytes)
                .map_err(FidoStoreError::IndexUnreadable)?;
        }
        offset += 1;
    }

    region
        .erase_sector(live_base)
        .map_err(FidoStoreError::IndexUnreadable)?;

    offset = 0u32;
    while offset < SLOTS_PER_SECTOR {
        let staged = slot_in_sector(scratch_base, offset)?;
        let bytes = region.read_slot(staged).map_err(FidoStoreError::IndexUnreadable)?;
        if !is_erased(&bytes) {
            region
                .program(slot_in_sector(live_base, offset)?, 0, &bytes)
                .map_err(FidoStoreError::IndexUnreadable)?;
        }
        offset += 1;
    }
    let _ = region.erase_sector(scratch_base);
    Ok(())
}

/// The byte an erased index cell holds.
///
/// Spelled out here rather than imported from `index.rs` or `slotmap.rs`: both
/// name the same `0xFF` for the same physical reason (an erased NOR cell reads
/// all-ones, `host.rs:73`, `device_region.rs`'s `nor::ERASED_BYTE`), and this
/// function writes it into a *cell* rather than a slot, which no existing
/// constant names. `IndexEntry::is_erased` is the reader that pairs with it.
const ERASED_CELL_BYTE: u8 = 0xFF;

/// What one slot holds, for the compaction decision.
enum SlotShape {
    /// Pristine — nothing was ever written, or a compaction already freed it.
    Erased,
    /// A FIDO record whose opened body is [`TOMBSTONE_BODY`].
    Tombstone,
    /// Anything else: a live credential, another domain's record, or a record
    /// this build cannot open.
    Keep,
}

/// Classify one slot for compaction.
///
/// **The payload key is required**, and that is the whole reason
/// [`FidoRecordStore::compact`] takes one: a tombstone is an ordinary record
/// header, so nothing structural separates it from a live credential. A record
/// that fails to open is [`SlotShape::Keep`] and never [`SlotShape::Erased`] —
/// a credential this build cannot read still occupies its slot, and compacting
/// it away would destroy a credential nobody has established is deleted (US-1549's
/// fail-closed property).
fn classify_slot(slot: Slot, raw: &SlotImage, payload_key: &PayloadKey) -> SlotShape {
    if is_erased(raw) {
        return SlotShape::Erased;
    }
    let SlotRead::Present(decoded) = record::decode(slot, raw) else {
        // A corrupt header is not evidence of a delete, so the slot is kept.
        return SlotShape::Keep;
    };
    if decoded.header().domain() != Domain::Fido {
        return SlotShape::Keep;
    }
    match record::open(decoded.header(), payload_key.as_bytes(), decoded.body()) {
        SlotRead::Present(pt) if is_tombstone(pt.as_slice()) => SlotShape::Tombstone,
        _ => SlotShape::Keep,
    }
}

/// The first erased cell of the index, as `(slot, byte offset within it)`.
fn find_free_entry_cell(region: &mut dyn KeyRegion) -> Result<Option<(Slot, u32)>, FidoStoreError> {
    let mut s = 0u32;
    while s < INDEX_SLOT_COUNT {
        let ordinal = s * index::ENTRIES_PER_SLOT;
        let slot = index::entry_slot(ordinal).ok_or(FidoStoreError::IndexUnreadable(
            index::E_INDEX_SLOT_UNREADABLE,
        ))?;
        let raw = region.read_slot(slot).map_err(FidoStoreError::IndexUnreadable)?;
        let mut n = 0u32;
        while n < index::ENTRIES_PER_SLOT {
            let at = index::entry_offset(n) as usize;
            if index::IndexEntry::is_erased(&raw[at..at + index::INDEX_ENTRY_BYTES]) {
                return Ok(Some((slot, index::entry_offset(n))));
            }
            n += 1;
        }
        s += 1;
    }
    Ok(None)
}

/// The slot `offset` positions into `base`'s sector.
fn slot_in_sector(base: Slot, offset: u32) -> Result<Slot, FidoStoreError> {
    debug_assert!(offset < SLOTS_PER_SECTOR);
    let index = base.index() as u32 + offset;
    if index >= TOTAL_SLOTS {
        return Err(FidoStoreError::IndexUnreadable(
            "an index sector reached past the end of the region",
        ));
    }
    Slot::new(index as u16)
        .ok_or(FidoStoreError::IndexUnreadable("an index slot is outside the key region"))
}

/// Slot 0, used only to give a fixed-size candidate array a type.
///
/// Not a value a caller can observe: every array element is overwritten before
/// it is read, because the loop that fills it runs to `count` and the count is
/// `min(matches, MAX_RP_CREDENTIALS)`.
const fn first_slot() -> Slot {
    match Slot::new(0) {
        Some(s) => s,
        None => panic!("slot 0 is always inside the key region"),
    }
}

// ---------------------------------------------------------------------------
// Compile-time assertions
// ---------------------------------------------------------------------------

const _: () = {
    // The two `rp_id_hash` widths are both 32 because both are SHA-256 outputs,
    // and `load_by_rp`/`load_by_credential_id` pass an `index::RpIdHash`'s bytes
    // straight into an `on_demand::SlotQuery::RpIdTag`. If either moved, that
    // would be a silent transmute at a borrow-checker-legal boundary rather than
    // a compile error.
    assert!(
        index::RP_ID_HASH_LEN == on_demand::RP_ID_TAG_LEN,
        "the index's rp_id_hash and the on-demand query tag must be the same width — \
         load_by_rp borrows one as the other"
    );
    // A candidate array that can hold one entry cannot tell "one match" from "the
    // first match", which is the difference between an enumeration and a lookup.
    assert!(
        MAX_RP_CREDENTIALS >= 2,
        "an enumeration that can hold one candidate cannot distinguish 'one match' from 'the \
         first match'"
    );
    // `Slot` is a `u16` and `FidoAllocator` casts the scan index to it. Exact
    // while the whole FIDO range fits, which is what makes the cast sound.
    assert!(
        FIDO_SLOT_LIMIT <= u16::MAX as u32,
        "FIDO's slot range must fit Slot's u16 index or fido_slot_at wraps and allocates from \
         the wrong slot"
    );
};