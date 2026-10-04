//! The slot allocator (US-1543): the lowest free slot, with a generation that
//! never goes backwards.
//!
//! # "Lowest free slot" is a linear scan, and that is a decision with a cost
//!
//! The gherkin is unambiguous — *it takes the lowest free slot* — and the
//! implementation is the obvious one: read slots from 0 upward and stop at the
//! first that is free. It is O(n) in the region's occupancy, which is fine and
//! deliberate on the **applet** path (US-1541's host region and a credential
//! enrollment are both off the boot path, and 960 slot reads of 1 KiB is a
//! bounded, one-off cost).
//!
//! It is **forbidden on the boot path** (S9). Boot runs before any UI, before
//! any PIN, and inside a time budget; a scan there turns a startup detail into
//! a latency cliff proportional to how many credentials the owner has. Whatever
//! boot needs must come from a summary whose size is bounded by the region
//! geometry rather than by the number of records in it. Nothing here may be
//! reached from boot; that is why the bound below is a **compile-time
//! constant** and not a field a caller can raise.
//!
//! # Why the bound is `TOTAL_SLOTS` and not the region's answer
//!
//! [`KeyRegion::slots`] is a method, so a region can report any capacity it
//! likes — including a wrong one. Trusting it unchecked would be worse than
//! having no bound: [`Slot`] is a `u16`, so an unclamped loop over a bogus
//! `u32::MAX` capacity wraps the index at 65 536 and turns a slow scan into a
//! **wrong answer** — a scan that silently re-reads slots 0..959 four billion
//! times and allocates from the first one. [`SCAN_BOUND`] clamps first, so the
//! worst a lying region can do is make the scan useless, never wrong.
//!
//! # Generations: monotonic **per slot**, and what "ever seen" can mean
//!
//! `alloc` hands out `high_water[slot] + 1`, where `high_water[slot]` is the
//! largest generation this allocator has ever observed in that slot — not the
//! generation currently sitting there. The difference is the whole requirement:
//!
//! ```text
//! allocate slot 3  -> generation 1     (high_water[3] := 1)
//! delete slot 3    -> sector erased, generation 1 physically gone
//! allocate slot 3  -> generation 2     (NOT 1)
//! ```
//!
//! A current-generation-only rule returns 1 on the second allocation, which is a
//! number an attacker who ever read that slot can replay.
//!
//! **What "ever seen" can honestly mean here, stated plainly because the
//! difference is a security property and not a detail.** The high-water table
//! is RAM. It is seeded once by the bounded discovery scan in
//! [`SlotAllocator::new`] and it survives for the allocator's life, which is
//! the applet session. It does **not** survive a power cycle, and it cannot:
//! a NOR sector erase physically destroys the generation bytes, so after an
//! erase there is no generation left *anywhere* in the region to read back.
//! Durable monotonicity is therefore US-1544/US-1545's commit discipline, not
//! this module's — every surviving record in an erased sector is rewritten with
//! a bumped generation (`keyregion/mod.rs:118-132`), which raises the region's
//! floor before the slot can be reused. Until that is wired, a cross-reset
//! reuse of an erased slot restarts its generation at 1. See
//! [`Occupancy::generation`] for the seam the codec has to fill.
//!
//! # Why `alloc` refuses to skip a slot it could not read
//!
//! `alloc` reads slots to decide whether they are free. If a read *faults* —
//! not "is empty", but "could not be learned" — treating the slot as free
//! hands the caller a slot that may hold a credential, and the next write
//! destroys it. That is US-1573's hazard in its most expensive form, so
//! [`AllocError::Fault`] aborts the allocation instead. The same rule is why
//! [`SlotAllocator::read`] maps a transport error onto
//! [`SlotRead::Fault`](super::SlotRead::Fault) and never onto
//! [`SlotRead::Absent`](super::SlotRead::Absent).
//!
//! # Footprint, and when this may be constructed
//!
//! The high-water table is `4 × bound` bytes — **3,840 B at a full
//! [`TOTAL_SLOTS`]-slot region** — allocated from the platform allocator. That
//! is a RAM claim and it is stated rather than hidden. Two consequences:
//!
//! * construct the allocator **once** per boot or applet activation, not per
//!   operation — the discovery scan costs `bound` slot reads;
//! * never construct it before `platform::rsa_heap::init()` runs inside
//!   `DeviceBackend::boot`. The US-961 heap gate
//!   (`tests/scripts/check_heap_gate.py`) proves nothing in device source
//!   allocates before that call; an allocation above it is a `LockedHeap::empty`
//!   abort, i.e. a dark boot that is indistinguishable from a store hang.
//!
//! This module is `no_std` + `alloc` and compiles for arm as well as the host:
//! the allocator runs on the device, only the *region* behind it (US-1541) is
//! host-only.

extern crate alloc;

use alloc::vec::Vec;

use super::{FIDO_SLOT_BYTES, KeyRegion, Slot, SlotRead, TOTAL_SLOTS};

/// A raw slot image exactly as [`KeyRegion::read_slot`] returns it.
///
/// A type alias rather than a new type: the region hands out `[u8; N]` and a
/// newtype here would mean converting at every boundary for no property. What
// the *contents* mean — occupied, free, and at what generation — is
/// [`Occupancy`]'s business, not the image's.
pub type SlotImage = [u8; FIDO_SLOT_BYTES as usize];

/// The compile-time bound on every scan an allocator performs.
///
/// [`TOTAL_SLOTS`], restated as its own name so that "is the scan bounded?" has
/// an answer a reader can check in one place instead of trusting each loop.
/// See the module docs for why this cannot be a runtime value.
pub const SCAN_BOUND: u32 = TOTAL_SLOTS;

/// The bound a given region's scans are limited to: its own capacity, clamped
/// to [`SCAN_BOUND`].
///
/// The clamp is the whole point (module docs): a region that reports a
/// capacity it does not have gets a bounded, useless scan rather than an
/// index that wraps.
pub const fn scan_bound_for(reported_slots: u32) -> u32 {
    if reported_slots < SCAN_BOUND {
        reported_slots
    } else {
        SCAN_BOUND
    }
}

const _: () = {
    // The bound is only a bound if it is the region's real geometry. If
    // `TOTAL_SLOTS` moves, this name must move with it or the module documents
    // a scan ceiling that does not exist.
    assert!(
        SCAN_BOUND == TOTAL_SLOTS,
        "SCAN_BOUND must be TOTAL_SLOTS — it is the region's geometry, not a tuning knob"
    );
    // `Slot` is a u16 and `alloc` casts the bound to u16 to build one. The cast
    // is only exact while the bound fits; this is what makes it safe rather
    // than merely currently-true.
    assert!(
        SCAN_BOUND <= u16::MAX as u32,
        "the scan bound must fit in Slot's u16 index, or building a Slot from a bound index \
         wraps and the scan answers a different question than it asked"
    );
};

/// The rule that decides whether a raw slot image carries a live record.
///
/// # What `record.rs` (US-1542) must supply
///
/// This trait exists so the allocator does not have to know the record's byte
/// layout — US-1542 is being written in parallel and the two must not both own
/// it. When the codec lands, it supplies **one** implementation of this trait
/// and [`ErasedProbe`] is retired:
///
/// 1. [`occupied`](Occupancy::occupied) must answer `false` for an erased
///    image **and** for a record whose header CRC fails — `mod.rs` already
///    commits to that reading ("a CRC failure is `Absent`, not `Fault`",
///    `keyregion/mod.rs:388-392`). Answering `true` for a CRC-failed slot
///    leaks a slot per torn write, which on a region whose sector erase
///    rewrites four slots at a time is four slots per interrupted commit.
/// 2. [`generation`](Occupancy::generation) must read the generation out of the
///    header for an occupied slot, and return `None` for an unoccupied one.
///    This is what makes the per-slot monotonicity survive a power cycle
///    (module docs); returning `None` unconditionally silently reduces the
///    guarantee to session scope.
/// 3. Both must agree with [`SlotAllocator::read`]'s mapping, or "occupied"
///    will mean two different things in the same allocator.
///
/// The duplication is one trait and one 20-line implementation, and it is
/// deliberately the *conservative* one: [`ErasedProbe`] calls a slot occupied
/// whenever it is not pristine, so it can under-report free space but can never
/// hand out a slot that still holds something.
pub trait Occupancy {
    /// Does this raw slot image carry a live record?
    fn occupied(&self, raw: &SlotImage) -> bool;

    /// The generation of that record, if the slot is occupied.
    ///
    /// `None` means "no durable generation is available here". It is the value
    /// [`ErasedProbe`] returns, and the consequence is the one the module docs
    /// state: per-slot monotonicity then holds only for this allocator's
    /// lifetime. `Some(g)` for an occupied slot is what lifts it across a
    /// power cycle.
    fn generation(&self, raw: &SlotImage) -> Option<u32>;
}

/// Whether a raw slot image is pristine `0xFF` — erased, never programmed.
pub fn is_erased(raw: &SlotImage) -> bool {
    raw.iter().all(|b| *b == 0xFF)
}

/// The conservative default [`Occupancy`]: a slot is occupied unless it is
/// pristine.
///
/// # Why this is the safe default
///
/// It can only ever *under*-report free space. A slot whose record was torn by
/// an interrupted commit reads as occupied here, so it is not reused — the
/// cost is one leaked slot per torn write, which US-1549's "fail closed for the
/// record itself" behaviour already accepts. The opposite error, a rule that
/// calls a half-written slot free, hands the next credential a slot that still
/// holds bits which can never be programmed back, and the write that follows it
/// fails on the part after the user has already been told the enrollment
/// succeeded.
///
/// It reports no generations, so a caller that needs cross-reset monotonicity
/// supplies the codec's own rule instead — see [`Occupancy`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ErasedProbe;

impl Occupancy for ErasedProbe {
    fn occupied(&self, raw: &SlotImage) -> bool {
        !is_erased(raw)
    }

    fn generation(&self, _raw: &SlotImage) -> Option<u32> {
        None
    }
}

/// A slot and the generation the record in it must carry.
///
/// Generation `0` never appears in an [`Allocation`]: the first write into a
/// virgin slot is generation 1, so a record claiming generation 0 is one this
/// allocator did not issue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allocation {
    /// Where the record goes.
    pub slot: Slot,
    /// The generation the record in it must carry.
    pub generation: u32,
}

/// Why an allocation did not happen.
///
/// Two variants, and the split is the security property: `Fault` is "we could
/// not find out", `Full` is "we found out and there is nothing free". Collapsing
/// them would let a flash fault read as an empty store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocError {
    /// A slot could not be read, so the allocator refuses to decide whether it
    /// is free. `reason` is the [`KeyRegion`]'s own error string.
    Fault {
        /// The slot whose read failed.
        slot: Slot,
        /// The transport's error string, verbatim.
        reason: &'static str,
    },
    /// Every slot in the bounded scan was occupied.
    Full,
    /// A slot's generation counter is at `u32::MAX`.
    ///
    /// Unreachable in practice (2^32 rewrites of one slot), and present because
    /// the alternative is `wrapping_add`, which turns 2^32 rewrites into a
    /// generation **0** — the exact replay this module exists to prevent.
    GenerationExhausted {
        /// The slot whose counter is exhausted.
        slot: Slot,
    },
}

/// Allocates slots in a [`KeyRegion`], lowest free first, with a per-slot
/// monotonic generation.
///
/// Construct with [`SlotAllocator::new`], which performs the bounded discovery
/// scan; keep the allocator for the session rather than rebuilding it per
/// operation (module docs, "Footprint").
pub struct SlotAllocator<'region, 'rule> {
    region: &'region mut dyn KeyRegion,
    rule: &'rule dyn Occupancy,
    /// The largest generation ever observed in each slot, `0` for "none seen".
    high_water: Vec<u32>,
    scans: u32,
    slot_reads: u32,
}

impl<'region, 'rule> SlotAllocator<'region, 'rule> {
    /// Build an allocator over `region`, seeded by a bounded discovery scan of
    /// every slot it will ever consider.
    ///
    /// The scan reads each slot once and asks `rule` for the generation of any
    /// occupied slot. It is eager on purpose: an allocator that allocated
    /// before knowing the region's generations would hand out generation 1 into
    /// a slot that has been at generation 900 all along, which is the replay
    /// this module exists to stop. Cost is `bound` slot reads; on a full
    /// region that is 960 reads of 1 KiB, paid once per allocator.
    ///
    /// A fault during the scan is an [`AllocError::Fault`], never a silently
    /// half-seeded allocator — a table with unknown entries looks exactly like
    /// one full of zeros, which is the mistake the scan's eagerness avoids.
    pub fn new(
        region: &'region mut dyn KeyRegion,
        rule: &'rule dyn Occupancy,
    ) -> Result<Self, AllocError> {
        let bound = scan_bound_for(region.slots());
        let mut high_water = alloc::vec![0u32; bound as usize];
        let mut slot_reads = 0u32;
        let mut i = 0u32;
        while i < bound {
            let slot = slot_at(i);
            slot_reads += 1;
            let raw = region
                .read_slot(slot)
                .map_err(|reason| AllocError::Fault { slot, reason })?;
            if rule.occupied(&raw) {
                if let Some(g) = rule.generation(&raw) {
                    high_water[i as usize] = g;
                }
            }
            i += 1;
        }
        Ok(Self {
            region,
            rule,
            high_water,
            scans: 0,
            slot_reads,
        })
    }

    /// The compile-time scan bound, as an associated constant so a caller can
    /// state the expectation without importing [`SCAN_BOUND`].
    pub const fn scan_bound() -> u32 {
        SCAN_BOUND
    }

    /// The bound this allocator's scans actually use: its region's capacity,
    /// clamped to [`scan_bound_for`].
    pub fn bound(&self) -> u32 {
        scan_bound_for(self.region.slots())
    }

    /// How many [`Self::alloc`] scans have run.
    pub fn scans(&self) -> u32 {
        self.scans
    }

    /// How many slots this allocator has read, discovery scan included.
    pub fn slot_reads(&self) -> u32 {
        self.slot_reads
    }

    /// The largest generation seen in `slot`, if `slot` is inside the bound.
    pub fn high_water(&self, slot: Slot) -> Option<u32> {
        self.high_water.get(slot.index() as usize).copied()
    }

    /// Record a generation observed in `slot`, raising its high-water mark.
    ///
    /// The hook US-1545 needs: a commit that rewrites a sector's surviving
    /// records with bumped generations can feed them in here, so a slot whose
    /// record has since been erased still knows the floor it has to clear.
    /// Raising only — a generation below the mark is ignored, never lowers it.
    pub fn observe(&mut self, slot: Slot, generation: u32) {
        if let Some(h) = self.high_water.get_mut(slot.index() as usize) {
            if generation > *h {
                *h = generation;
            }
        }
    }

    /// Read `slot` and classify it: a record, an absent record, or a fault.
    ///
    /// The transport error maps onto [`SlotRead::Fault`] and never onto
    /// [`SlotRead::Absent`] — the two look identical to a caller that only
    /// checks `is_some()`, and the difference is a credential (US-1573).
    pub fn read(&mut self, slot: Slot) -> SlotRead<SlotImage> {
        self.slot_reads += 1;
        match self.region.read_slot(slot) {
            Ok(raw) => {
                if self.rule.occupied(&raw) {
                    SlotRead::Present(raw)
                } else {
                    SlotRead::Absent
                }
            }
            Err(reason) => SlotRead::Fault(reason),
        }
    }

    /// Whether `slot` is free, or the reason it could not be determined.
    ///
    /// `Err` here is never `false`. A fault is not evidence of emptiness.
    pub fn is_free(&mut self, slot: Slot) -> Result<bool, AllocError> {
        self.slot_reads += 1;
        let raw = self
            .region
            .read_slot(slot)
            .map_err(|reason| AllocError::Fault { slot, reason })?;
        Ok(!self.rule.occupied(&raw))
    }

    /// The region this allocator allocates in.
    ///
    /// The record write goes through the same region, and it has to: a commit
    /// erases the slot's **sector** and programs four slots, so the caller is
    /// already reaching the region directly and an allocator that hid it would
    /// only be an obstacle, not a boundary. The allocator deliberately does not
    /// write records itself — the bytes belong to the codec (US-1542).
    pub fn region_mut(&mut self) -> &mut dyn KeyRegion {
        self.region
    }

    /// Allocate the lowest free slot at the next generation for it.
    ///
    /// The scan is `0..self.bound()` and therefore bounded by
    /// [`SCAN_BOUND`] by construction — there is no path through this function
    /// that reads outside it. A fault aborts the allocation rather than
    /// skipping the slot (module docs).
    pub fn alloc(&mut self) -> Result<Allocation, AllocError> {
        let bound = self.bound();
        self.scans += 1;
        let mut i = 0u32;
        while i < bound {
            let slot = slot_at(i);
            if self.is_free(slot)? {
                let generation = self.high_water[i as usize]
                    .checked_add(1)
                    .ok_or(AllocError::GenerationExhausted { slot })?;
                self.high_water[i as usize] = generation;
                return Ok(Allocation { slot, generation });
            }
            i += 1;
        }
        Err(AllocError::Full)
    }
}

/// The [`Slot`] at scan index `i`.
///
/// The `u16` cast is exact **because** `i < SCAN_BOUND <= u16::MAX`, which
/// `const _: ()` above pins at compile time. Without the bound this cast would
/// wrap at 65 536 and the scan would answer about the wrong slots.
fn slot_at(i: u32) -> Slot {
    debug_assert!(i < SCAN_BOUND);
    Slot::new(i as u16).expect("i < SCAN_BOUND <= TOTAL_SLOTS, so the index is a valid slot")
}