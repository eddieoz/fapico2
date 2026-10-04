//! Sector-atomic commits, the self-cleaning failure pass, and the factory wipe
//! (US-1544, US-1545, US-1546).
//!
//! # The problem the hardware creates
//!
//! [`SLOTS_PER_SECTOR`] is 4 ([`keyregion/mod.rs:119-132`]): a 4 KiB NOR
//! sector holds four 1 KiB slots, and a program can only clear bits. So an
//! update to **one** credential has to erase **four** slots and program all
//! four back, and the moment that erase executes the previous generation of
//! every one of them is gone from the medium.
//!
//! The acceptance criterion this module is built to meet says:
//!
//! ```gherkin
//! Then exactly one erase and one program occur
//! And the commit marker is written last
//! And a power loss before the marker leaves generation N readable
//! ```
//!
//! The third clause cannot be satisfied in place. Ordering the programs cannot
//! help, because the destruction happens at the **erase**, before any program.
//! After `erase_sector` returns, generation N exists nowhere on the part —
//! there is no ordering of the programs that brings it back. So this module
//! does not try. It **stages the new generation somewhere else first**.
//!
//! # The design: a scratchpad sector, and why it is worth one
//!
//! One whole sector of the region is designated the **scratchpad**. A commit is
//! four phases, and every crash point is one of four states:
//!
//! | # | phase | power cut here leaves | recovered by |
//! |---|-------|------------------------|--------------|
//! | 1 | erase scratchpad, program the mates | live sector untouched — **generation N readable** | `recover` sweeps the partial set |
//! | 2 | program the **target** into the scratchpad (the witness) | live sector untouched — **generation N readable** | `recover` abandons the set: it cannot replace what is in the live sector |
//! | 3 | erase the live sector, copy the scratchpad back | live sector torn | `recover` replays the complete set |
//! | 4 | erase the scratchpad (retire) | live sector complete at N+1 | `recover` sees live already current, sweeps |
//!
//! Phases 1–2 are the answer to "a power loss before the marker leaves
//! generation N readable", and they cost the old generation nothing because the
//! erase has not happened yet. Phases 3–4 answer the harder half — once the
//! erase has been issued the old generation is **unrecoverable**, no scheme can
//! save it, and what is guaranteed instead is that the outcome is the complete
//! new generation and never a mixture of two.
//!
//! **What the scratchpad buys, named as an attack rather than as tidiness.**
//! Without it, a brown-out during a credential write destroys up to
//! [`SLOTS_PER_SECTOR`] *other* credentials' records — the sector-mates that
//! were only ever in the way. That is precisely the failure mode the whole
//! per-record design was rebuilt to remove: AGENTS.md §5 names "every
//! credential write rewrites every credential, one corrupt byte costs the whole
//! set" as what the old whole-snapshot store did. A scratchpad sector does not
//! prevent a credential's *own* previous version from dying to the erase —
//! nothing can — but it confines the loss to the one sector being written
//! instead of spreading it across every sector the write touched, and it makes
//! the write **replayable** rather than merely reorderable.
//!
//! **What it costs:** one sector of capacity — 4 of 960 slots, 0.42% of the
//! region — and one extra erase plus one extra program pass per commit.
//! [`mod.rs`](super)'s `FIDO_CAPACITY` does not subtract the scratchpad, which
//! is a geometry change in a file this story does not own; the caller
//! designates the scratchpad slot explicitly rather than this module silently
//! consuming capacity.
//!
//! # Why the target is written last, and why that is not what makes it safe
//!
//! The target slot is programmed **last** in both the scratchpad and the live
//! sector. That ordering is kept, and it is what makes the phase table's
//! boundaries easy to state, but it is **not** what stops a partial commit from
//! being mistaken for a complete one — and an earlier revision of this module
//! claimed it was, which was wrong. The commit's test found it: a power cut
//! after two sector-mates had been staged and before the target left the
//! scratchpad holding what looked like a perfectly good staged set, and
//! `recover` replayed it — which erases the live sector, so the third mate,
//! never staged, would have been destroyed.
//!
//! **The rule that does hold is the replacement test.** The scratchpad may only
//! be replayed into the live sector if, at *every* slot of that sector, the
//! staged bytes are a legitimate replacement for what is there: either
//! identical, or the live slot is erased and so has nothing to lose. Anything
//! else means the staged set would destroy a record it does not carry, and the
//! set is abandoned instead. Checked at the byte level against the live sector,
//! using only `0xFF`-is-erased ([`slotmap::is_erased`]) and equality:
//!
//! | staged vs live | verdict |
//! |---|---|
//! | identical | fine — already applied, or never needed |
//! | live erased, staged has bytes | fine — the erase took, this is the replay |
//! | live has bytes, staged erased or different | **abandon the set** |
//!
//! Every crash point resolves, and the "abandon" row is exactly the
//! interrupted-staging case. The remaining degenerate case — a partial set whose
//! target slot was *virgin*, so the target offset is erased on both sides —
//! passes the test and is replayed; that is harmless, because a set that passes
//! is by definition a valid replacement, so the replay reproduces the
//! pre-commit state byte for byte. It costs one extra sector erase on an
//! interrupted enrolment and buys no correctness problem.
//!
//! So the honest summary of the protocol is: **stage, test, erase, copy.** The
//! erase is the only irreversible step and it happens last of the three, after
//! the scratchpad has been proved to carry everything the erase would destroy.
//!
//! # Why there is no descriptor byte
//!
//! A dedicated descriptor (sector number, target, generation, CRC) written last
//! was considered and refused. It would make the witness a structure this
//! module owns and formats — a second thing to keep parseable forever, in a
//! store whose whole argument is "one record format" — and its integrity could
//! only be a CRC, forgeable by anyone with flash-write access. The
//! replacement test needs no stored state at all: it compares the scratchpad
//! against the live sector and both of them are records the codec already
//! authenticates.

//! # Why this module does not seal anything
//!
//! The commit path is a **byte mover**. The caller seals the body with
//! [`record::seal`] and hands the [`Sealed`] in; this module never sees a key
//! and never derives a nonce. That is a deliberate consequence of the decision
//! below, and it keeps the commit path free of the one place a mistake is
//! unrecoverable (GCM nonce reuse).
//!
//! # Why sector-mates are copied verbatim, not re-sealed
//!
//! [`slotmap.rs:34-43`] describes the intended discipline as "every surviving
//! record in an erased sector is rewritten with a bumped generation", which
//! would raise the region's generation floor before a slot is reused. That
//! needs the *plaintext* of every mate — so the commit would need the payload
//! key, and would re-encrypt up to three unrelated credentials on every write.
//!
//! It is refused here, for a reason that survives the refusal: the bump is
//! **not durable**. The scratchpad is erased at the end of the commit, so
//! afterwards nothing anywhere records that mate's generation was once `g + 1`.
//! The next time the mate's slot is erased and reused, its floor is gone either
//! way. The bump buys nothing across the reset it was meant to survive, and
//! costs a key on the write path plus three re-seals whose only effect is to
//! make a record's AAD describe a write that changed nothing. AGENTS.md §5: take
//! the simpler one unless the attack can be named. **What does attack — a
//! rolled-back credential body — is not stopped by a bumped generation** either,
//! because the AAD binds the generation to the *record it is written in*: an
//! attacker who replays an old header with its old body replays a matching pair
//! and it verifies. Stopping that needs a durable per-slot floor compared at
//! read time, which is US-1549's/`index.rs`'s business and not this module's.
//!
//! The mates are therefore **preserved byte-for-byte** (`preserved and
//! rewritten`, not destroyed), which is the strongest form of preservation
//! available: not a re-derivation, a copy.
//!
//! # Mates that are not records
//!
//! A mate whose live bytes do not decode is copied verbatim if it is not
//! erased, and is otherwise left erased. It is *not* silently dropped:
//! programming it back keeps the flash contents identical, which matters
//! because a corrupt record is still occupying its slot in the allocator's eyes
//! until US-1549 says otherwise, and rewriting it as `0xFF` would quietly
//! release a slot that something may still believe in.
//!
//! # Why there is no single-slot delete here
//!
//! A delete is a commit whose target is programmed as `0xFF`, and on this
//! hardware that is **indistinguishable from a commit that had not reached its
//! witness yet**: both leave the target's scratchpad slot erased. The witness
//! cannot tell "this sector is now empty" from "this sector is not written
//! yet", so a delete could be resurrected as a replay by [`recover`].
//!
//! Rather than add a tombstone format, this module provides record writes and
//! the whole-region [`wipe`] (US-1546), and says the single-slot delete belongs
//! to the story that owns the record format. `AGENTS.md` §5 again: the
//! complexity is not warranted until a caller needs it, and the caller that
//! needs it can extend the witness without unpicking anything here.
//!
//! # Multi-slot commits are not provided either
//!
//! A credential **deletion** is the only real multi-slot operation, and see
//! above. Enrolment writes one record; a counter change writes one record. If a
//! future caller needs N records in one atomic step, the shape here extends
//! (stage N, witness last) but it is not built speculatively.
//!
//! # What `wipe` promises, and what it does not
//!
//! [`wipe`] erases every sector of the region, so **no record in it is
//! readable** — that is the whole of US-1546's promise, and it holds whether or
//! not the records were ever decipherable. It is idempotent and resumable: a
//! reset interrupted by a power cut leaves some sectors erased and some not,
//! and running it again finishes the job. It is deliberately **not atomic
//! across sectors**, and cannot be on this hardware (N sectors, N erase
//! instructions, no way to make the Nth depend on the first). A caller that
//! needs "the reset is complete or nothing happened" must make the store
//! *unreachable* first — which is the index's job
//! ([`crypto.rs`](super::crypto) deliberately derives a separate `IndexKey` and
//! `PayloadKey` for exactly this reason), and then `wipe` is garbage
//! collection. The house precedent is
//! `trusted_backend::device::wipe_internal_fs`
//! (`platform/src/trusted_backend/device.rs:1092`), which returns `bool` for the
//! same reason: a failed format is reported, not assumed.
//!
//! # Footprint
//!
//! At most **one** [`SlotImage`] (1 KiB) on the stack at a time, plus the heap
//! record image from [`record::encode`]. `recover` deliberately re-reads each
//! scratchpad slot rather than holding all four, because 4 KiB of stack on the
//! boot path is a real cost and this tree already tracks stack and BSS
//! (`docs/` size baseline, the US-961 heap gate). `live_slot_of` costs
//! `region.slots()` header parses per staged record — 3 840 CRC32s over 12 bytes
//! on a full 960-slot region, which is boot-time-cheap and buys the refusal to
//! trust an unparsed header.

use core::fmt;

use super::record::{self, Domain, RecordError};
use super::slotmap::{self, SlotImage};
use super::{KeyRegion, Sealed, Slot, SlotRead, SLOTS_PER_SECTOR};

use super::FIDO_SLOT_BYTES;

/// Slots the scratchpad occupies: exactly one sector.
///
/// Re-exported as the module's own name so a caller stating "I am giving this
/// module a sector" has something to name, and so the cost of the design is
/// visible at the call site rather than implied.
pub const SCRATCHPAD_SLOTS: u32 = SLOTS_PER_SECTOR;

/// Why a commit did not happen — or did not finish.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CommitError {
    /// The plan does not fit the region this commit was given.
    ///
    /// Reported **before** any flash operation: a plan that names a scratchpad
    /// outside the region is a geometry bug, and touching the medium for it
    /// would be the code deciding to erase something on the strength of an
    /// argument it has already lost.
    Plan {
        /// What was wrong, in the house's flat-`&'static str` style.
        reason: &'static str,
    },
    /// A slot could not be read.
    ///
    /// The commit refuses rather than proceeding with an unreadable mate.
    /// This is US-1573's hazard in its most expensive form: a mate read as
    /// "empty" is a mate whose credential is erased and never rewritten, and
    /// no later read reports that the loss happened.
    Read {
        /// The slot that could not be read.
        slot: Slot,
        /// The region's error string, verbatim.
        reason: &'static str,
    },
    /// An erase or a program was refused.
    Flash {
        /// The region's error string, verbatim.
        reason: &'static str,
    },
    /// The offered generation is not ahead of the one already in the slot.
    ///
    /// A commit that wrote generation `N` over generation `N` would be a
    /// replay by another name, and `N` over `N+1` would be a rollback the
    /// allocator's monotonicity ([`slotmap.rs:34-43`]) exists to prevent. The
    /// generation is the allocator's to issue
    /// ([`super::slotmap::Allocation`]), so this is a check, not a decision.
    Generation {
        /// The slot that was being written.
        target: Slot,
        /// The generation it already holds (`0` for an empty slot).
        current: u32,
        /// The generation offered.
        offered: u32,
    },
    /// The record could not be encoded — a body the slot cannot hold.
    Record(RecordError),
    /// The commit was interrupted **after** the live sector was erased, and
    /// the new generation is not in place yet.
    ///
    /// This is the one state where the old generation cannot be recovered —
    /// the erase destroyed it, and no ordering of any program brings it back
    /// (module docs). What is guaranteed is that the **scratchpad holds the
    /// complete new generation**, and [`recover`] finishes the job.
    ///
    /// It is deliberately left unrecovered rather than swept: the scratchpad is
    /// now the only copy of the sector, and cleaning it up "so the region is
    /// tidy" is precisely how a crash here becomes permanent data loss. A
    /// caller that sees this must call [`recover`] (or reboot, which does it on
    /// the boot path) and must not retry the commit blind — although
    /// [`commit`] recovers first precisely so that a blind retry is in fact
    /// safe.
    Incomplete {
        /// The operation that failed, as the region described it.
        reason: &'static str,
    },
}

impl fmt::Display for CommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitError::Plan { reason } => write!(f, "commit plan is not valid for this region: {reason}"),
            CommitError::Read { slot, reason } => {
                write!(f, "commit could not read slot {}: {reason}", slot.index())
            }
            CommitError::Flash { reason } => write!(f, "commit flash operation failed: {reason}"),
            CommitError::Generation { target, current, offered } => write!(
                f,
                "commit generation {offered} is not ahead of {} already in slot {}",
                current,
                target.index()
            ),
            CommitError::Record(e) => write!(f, "commit could not encode the record: {e}"),
            CommitError::Incomplete { reason } => write!(
                f,
                "commit was interrupted after the sector erase and needs recover() before the \
                 region is touched again: {reason}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Sector arithmetic
// ---------------------------------------------------------------------------

/// The index of the first slot of `slot`'s sector.
///
/// Exact division because `mod.rs`'s `const _` block already asserts
/// `BLOCK_SIZE == SLOTS_PER_SECTOR * FIDO_SLOT_BYTES`, so no slot straddles a
/// sector boundary and every slot's sector has a well-defined head.
pub const fn sector_base_index(slot: Slot) -> u32 {
    (slot.index() as u32 / SLOTS_PER_SECTOR) * SLOTS_PER_SECTOR
}

/// The head of `slot`'s sector.
pub const fn sector_base(slot: Slot) -> Slot {
    match Slot::new(sector_base_index(slot) as u16) {
        Some(s) => s,
        // Unreachable: `sector_base_index` returns `index - index % SLOTS_PER_SECTOR`,
        // which is never larger than `index`, and `Slot::new` already accepted
        // `index`. Stated as an `expect` rather than a silent fallback so a
        // geometry change that breaks the reasoning fails loudly here.
        None => panic!("sector base of a valid Slot is itself a valid Slot"),
    }
}

/// The slot `offset` positions into `base`'s sector.
fn slot_at(base: u32, offset: u32) -> Slot {
    debug_assert!(offset < SLOTS_PER_SECTOR);
    Slot::new((base + offset) as u16).expect("a slot inside a valid sector is itself a valid slot")
}

/// Whether a raw slot image is pristine erased flash.
///
/// [`slotmap::is_erased`] rather than a private loop: "erased" is the
/// allocator's word for this and there must be one of it.
fn erased(raw: &SlotImage) -> bool {
    slotmap::is_erased(raw)
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/// What a commit will write, and which sector it may use as scratch.
///
/// A plan is a value, not a session: it holds no flash state and can be built,
/// inspected and rejected without touching the region. `validate` is what keeps
/// that promise — it is called before the first erase, and a plan that fails it
/// has changed nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CommitPlan {
    /// A slot **in the scratchpad sector**. Its sector, not the slot itself, is
    /// what the commit uses — passing the middle of the scratchpad is a
    /// harmless no-op rather than an error, so a caller holding "somewhere over
    /// there" does not have to know the arithmetic.
    scratchpad: Slot,
    /// The slot the new record goes to.
    target: Slot,
    /// The key domain the record belongs to.
    domain: Domain,
    /// The generation the new record must carry.
    generation: u32,
}

impl CommitPlan {
    /// A plan writing `target` at `generation`, staging through `scratchpad`.
    ///
    /// Nothing is checked here — the region is not known yet. [`Self::validate`]
    /// runs at the top of [`commit`].
    pub const fn new(scratchpad: Slot, target: Slot, domain: Domain, generation: u32) -> Self {
        CommitPlan { scratchpad, target, domain, generation }
    }

    /// The slot the new record goes to.
    pub const fn target(&self) -> Slot {
        self.target
    }

    /// The scratchpad sector's head slot.
    pub const fn scratchpad_base(&self) -> Slot {
        sector_base(self.scratchpad)
    }

    /// The generation the new record carries.
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// The live sector this plan writes: its head slot.
    pub const fn live_base(&self) -> Slot {
        sector_base(self.target)
    }

    /// Refuse a plan the region cannot execute, before any flash operation.
    fn validate(&self, region_slots: u32) -> Result<(), CommitError> {
        if self.target.index() as u32 >= region_slots {
            return Err(CommitError::Plan { reason: "the target slot is outside this region" });
        }
        let scratch_base = sector_base_index(self.scratchpad);
        // Whole sectors only: `FileKeyRegion::create` already refuses a region
        // that is not a whole number of them (`host.rs:168-173`), so a
        // short region here means the caller pointed the scratchpad past the
        // end, and half a scratchpad is not a scratchpad.
        if scratch_base + SLOTS_PER_SECTOR > region_slots {
            return Err(CommitError::Plan {
                reason: "the scratchpad sector is not wholly inside this region",
            });
        }
        if sector_base_index(self.scratchpad) == self.live_base().index() as u32 {
            return Err(CommitError::Plan {
                reason: "the scratchpad sector is the sector being written — a commit that \
                        staged into the sector it erases would lose the staged copy at the erase",
            });
        }
        if self.generation == 0 {
            return Err(CommitError::Plan {
                reason: "generation 0 is never legitimate: the first write into a virgin slot is \
                        generation 1, so a record claiming 0 is one no allocator issued",
            });
        }
        Ok(())
    }
}

/// The generation a slot's record currently carries; `0` for an empty slot.
///
/// Read through [`record::decode`], so a torn or corrupt record counts as no
/// record rather than as some generation. That is deliberate and is
/// [`record.rs`](record)'s own rule: a CRC failure is absence, so an
/// unreadable target presents a floor of `0` and a commit over it is allowed —
/// which is the only safe direction, since the alternative (refusing) would
/// leave a corrupt record permanently un-replaceable and the owner with no way
/// to enrol again.
fn read_generation(region: &mut dyn KeyRegion, slot: Slot) -> Result<u32, CommitError> {
    let raw = region.read_slot(slot).map_err(|reason| CommitError::Read { slot, reason })?;
    Ok(match record::decode(slot, &raw) {
        SlotRead::Present(decoded) => decoded.header().generation(),
        // A fault cannot reach here — `read_slot` returned `Ok`, and the
        // buffer is a whole slot — so collapsing it into `0` is not a
        // fail-open; it names the same thing `Absent` names.
        SlotRead::Absent | SlotRead::Fault(_) => 0,
    })
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// What a completed commit actually did to the medium.
///
/// Exists because the acceptance criterion is stated as **counts** ("exactly one
/// erase and one program occur") and a caller — or a reviewer reading a device
/// log — should be able to check that claim without a wrapper. The counts are
/// of *mutating* operations; reads are not counted, because the criterion is
/// about wear and about what a power cut can lose.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CommitReport {
    /// Erases of the sector that held the live records: always 1.
    ///
    /// This is the number the criterion means. The two scratchpad erases are
    /// counted separately below, and they erase nothing the owner can lose.
    pub live_erases: u32,
    /// Erases of the scratchpad: 2 (prepare and retire).
    pub scratchpad_erases: u32,
    /// Programs into the scratchpad: one per non-empty mate plus the target.
    pub staged_programs: u32,
    /// Programs into the live sector: one per non-empty staged slot.
    pub live_programs: u32,
}

// ---------------------------------------------------------------------------
// Commit
// ---------------------------------------------------------------------------

/// Write `body` into `plan.target()`, atomically at sector granularity.
///
/// # The order, and why
///
/// 1. [`recover`] — so the region is in a state this commit may modify. This is
///    why a retry after *any* error is safe, including [`CommitError::Incomplete`];
/// 2. read the target slot, and **refuse** a generation that does not advance;
/// 3. erase the scratchpad and program the three mates into it;
/// 4. program the target into the scratchpad — **the witness**, last;
/// 5. erase the live sector;
/// 6. copy the scratchpad into the live sector, target last;
/// 7. erase the scratchpad (best effort).
///
/// Steps 3–4 happen entirely off to the side of the data being replaced, which
/// is the whole of the design: a cut anywhere in 3–4 leaves generation N intact
/// and readable, which is the clause an in-place ordering cannot deliver
/// (module docs).
///
/// # What "best effort" means for step 7, and why it is not an error
///
/// The retire erase can fail. Reporting that as a failure would be **lying**: the
/// live sector already holds generation N+1 in full, and a caller that saw
/// `Err` would reasonably treat the write as having not happened and try
/// again. The consequence of a failed retire is a stale staged set sitting in
/// the scratchpad, which the next [`recover`] recognises as already-current and
/// sweeps. `write_chunked` makes the same call about retiring its other buffer
/// (`platform/src/secure_store.rs:1870-1874`), and for the same reason.
///
/// # # Safety / exclusivity
///
/// The commit assumes exclusive access to `region` for its whole call. It reads
/// the live sector and later erases it; a concurrent writer could erase the
/// sector between the two, and this module would faithfully copy an older
/// image over a newer one. The region is not internally locked and there is no
/// lock to take here — a per-region mutex on the write path is the caller's
/// shape to choose (the same choice `key_region_host.rs` makes with its
/// `Arc<Mutex<…>>`).
pub fn commit(
    region: &mut dyn KeyRegion,
    plan: CommitPlan,
    body: &Sealed,
) -> Result<CommitReport, CommitError> {
    plan.validate(region.slots())?;

    // 1. Make the region safe to modify. Cheap when there is nothing staged
    //    (four slot reads), and the reason a caller never has to reason about
    //    whether a previous failure left the region writeable.
    recover(region, plan.scratchpad_base()).map_err(|reason| CommitError::Flash { reason })?;

    // 2. The generation check, before anything is staged: a rollback must not
    //    get as far as the scratchpad.
    let current = read_generation(region, plan.target)?;
    if current >= plan.generation {
        return Err(CommitError::Generation {
            target: plan.target,
            current,
            offered: plan.generation,
        });
    }

    // Sealed by the caller, under an AAD that names this exact slot and
    // generation (`record.rs:469-477`) — which is why the bytes can be copied
    // through the scratchpad without ever being re-sealed: the AAD describes
    // the *live* slot, and the scratchpad is a waypoint, not a new home.
    let header = record::RecordHeader::new(plan.domain, plan.target, plan.generation);
    let image = record::encode(&header, body).map_err(CommitError::Record)?;

    let mut report = CommitReport::default();


    // 3–4. Stage. Every failure here is *before* the erase, so the cleanup is
    //      the self-cleaning pass: erase the scratchpad and return. See
    //      `stage` for why that is safe rather than merely tidy.
    let staged_programs = match stage(region, &plan, image.as_bytes()) {
        Ok(programs) => programs,
        Err(e) => {
            // Best effort, and deliberately not reported: the scratchpad is a
            // scratchpad, and if *this* erase also fails then nothing was
            // staged either, which is the case the next `recover` sweeps.
            let _ = region.erase_sector(plan.scratchpad_base());
            return Err(e);
        }
    };
    report.scratchpad_erases += 1;
    report.staged_programs = staged_programs;

    // 5. The point of no return.
    //
    // A *refused* live erase is `Incomplete`, not `Flash`, and that is the
    // difference between "nothing happened" and "we no longer know what
    // happened". NOR gives no way to tell a failed erase from a partially
    // performed one, so the live sector's state is unknown — and the only
    // thing that resolves it is the staged set, which is therefore kept
    // rather than swept. `recover` decides: identical bytes mean the erase
    // never took and the set is retired; different bytes mean it did and the
    // set is replayed. Either answer is a whole sector.
    region
        .erase_sector(plan.target)
        .map_err(|reason| CommitError::Incomplete { reason })?;
    report.live_erases = 1;

    // 6. Copy back. A failure here is `Incomplete`, never cleaned up: the
    //    scratchpad is the only copy of the sector now.
    match copy_into_live(region, &plan) {
        Ok(programs) => {
            report.live_programs = programs;
        }
        // The slot is not lost to the caller: `plan.target()` names the live
        // sector this is about, and `CommitError::Read`'s slot would only ever
        // be a scratchpad slot whose own index says nothing the plan does not.
        Err(CommitError::Read { reason, .. }) => return Err(CommitError::Incomplete { reason }),
        Err(CommitError::Flash { reason }) => return Err(CommitError::Incomplete { reason }),
        // `stage`/`copy_into_live` are private and cannot produce the rest;
        // treating them as `Incomplete` rather than panicking keeps a future
        // variant from becoming an abort on a path that has already erased.
        Err(_) => return Err(CommitError::Incomplete { reason: "commit could not be replayed" }),
    }

    // 7. Retire. Best effort by design (fn docs).
    let _ = region.erase_sector(plan.scratchpad_base());
    report.scratchpad_erases += 1;
    Ok(report)
}

/// Program the whole sector into the scratchpad, target last.
///
/// On any failure the caller erases the scratchpad; see [`commit`].
///
/// **Why that cleanup is the right one, and not merely the tidy one.** The
/// live sector has not been erased, so generation N is still there and still
/// readable. What this call has written is confined to the scratchpad, so
/// erasing the scratchpad removes *exactly* this call's writes and nothing
/// else — the property `write_chunked` had to buy with a written-parts log
/// (`platform/src/secure_store.rs:1858-1866`). Here it is structural: the
/// commit has one scratch sector, not a variable number of part keys, so
/// "the records written by this call" is "the contents of one sector" and the
/// deletion is one erase.
///
/// The reason that cleanup is *needed* rather than cosmetic is the same
/// paragraph's: without it a transient failure leaves the scratchpad holding
/// staged bytes, and the next `recover` would see a set it has to reason about
/// rather than an empty one. A store that has to be swept before it can be
/// written again is one transient hiccup away from being permanently
/// unwritable.
///
/// Returns how many programs it issued, because an erased mate needs none and
/// [`CommitReport`] is a count rather than an estimate.
fn stage(
    region: &mut dyn KeyRegion,
    plan: &CommitPlan,
    image: &[u8],
) -> Result<u32, CommitError> {
    let scratch = plan.scratchpad_base();
    region.erase_sector(scratch).map_err(|reason| CommitError::Flash { reason })?;

    let base = plan.live_base().index() as u32;
    let target_offset = plan.target.index() as u32 - base;
    let mut programs = 0u32;
    let mut offset = 0u32;
    while offset < SLOTS_PER_SECTOR {
        if offset != target_offset {
            let live = region
                .read_slot(slot_at(base, offset))
                .map_err(|reason| CommitError::Read { slot: slot_at(base, offset), reason })?;
            if !erased(&live) {
                region
                    .program(slot_at(scratch.index() as u32, offset), 0, &live)
                    .map_err(|reason| CommitError::Flash { reason })?;
                programs += 1;
            }
        }
        offset += 1;
    }

    // The witness: the target, last. Kept because it is free and it is what
    // makes the phase table's boundaries true; `recover` does **not** rely on
    // it — the replacement test is what makes an interrupted commit safe (module
    // docs).
    region
        .program(slot_at(scratch.index() as u32, target_offset), 0, image)
        .map_err(|reason| CommitError::Flash { reason })?;
    Ok(programs + 1)
}

/// Copy the staged sector into the freshly erased live one, target last.
///
/// Returns how many programs it issued.
fn copy_into_live(region: &mut dyn KeyRegion, plan: &CommitPlan) -> Result<u32, CommitError> {
    let scratch_base = plan.scratchpad_base().index() as u32;
    let base = plan.live_base().index() as u32;
    let target_offset = plan.target.index() as u32 - base;
    let mut programs = 0u32;
    let mut offset = 0u32;
    while offset < SLOTS_PER_SECTOR {
        if offset != target_offset {
            let staged = slot_at(scratch_base, offset);
            let bytes = region
                .read_slot(staged)
                .map_err(|reason| CommitError::Read { slot: staged, reason })?;
            if !erased(&bytes) {
                region
                    .program(slot_at(base, offset), 0, &bytes)
                    .map_err(|reason| CommitError::Flash { reason })?;
                programs += 1;
            }
        }
        offset += 1;
    }
    let staged_target = slot_at(scratch_base, target_offset);
    let bytes = region
        .read_slot(staged_target)
        .map_err(|reason| CommitError::Read { slot: staged_target, reason })?;
    region
        .program(plan.target, 0, &bytes)
        .map_err(|reason| CommitError::Flash { reason })?;
    Ok(programs + 1)
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/// What [`recover`] found in the scratchpad.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Recovery {
    /// The scratchpad held no complete staged set. The live region was never
    /// touched (or was already complete), and the scratchpad has been swept.
    Swept,
    /// The scratchpad held a complete set the live region did not have; it was
    /// replayed into the live sector.
    Replayed {
        /// The live sector's head slot.
        sector: Slot,
        /// The target the staged set was committed for.
        target: Slot,
        /// The generation the set carries.
        generation: u32,
    },
    /// The scratchpad held a set the live region already had — a commit whose
    /// retire erase failed. Swept; nothing was rewritten.
    AlreadyCurrent {
        /// The live sector's head slot.
        sector: Slot,
        /// The target the staged set was committed for.
        target: Slot,
        /// The generation the set carries.
        generation: u32,
    },
}

/// Finish, or abandon, an interrupted commit.
///
/// # When this must run
///
/// Before anything else reads or writes the region on the boot path, and
/// implicitly at the top of every [`commit`] — which is what makes a retry
/// after [`CommitError::Incomplete`] safe rather than destructive. Skipping it
/// and reading directly is not a small omission: a live sector caught between
/// its erase and its copy program reads as **empty**, and "this credential is
/// gone" is what a caller concludes, and reports to the owner.
///
/// # What it decides, and on what evidence
///
/// Two questions, in this order, and the second is the one that matters.
///
/// 1. **Which live sector is this?** From the record headers themselves —
///    [`record::decode`] checks a header's `slot` against every candidate, and a
///    successful match hands back that header. Nothing in the scratchpad is
///    believed on its own account, so a scratchpad corrupted by flash rot or
///    forged by someone with flash-write access can at worst cause a sweep.
/// 2. **May the staged set be replayed?** Only if, at every slot of that sector,
///    the staged bytes are a legitimate replacement for what is there —
///    identical, or the live slot is erased. Anything else means the replay
///    would destroy a record the set does not carry, and the set is abandoned.
///    This is the replacement test, and the module docs say why it, rather than
///    the program ordering, is what stops an interrupted commit from taking a
///    credential with it.
///
/// An abandoned or already-applied set is **erased**, which is the same
/// self-cleaning pass the failed-commit path runs and for the same reason:
/// scratchpad bytes that are not a pending commit are not a record of anything,
/// and leaving them makes every later recovery re-derive the same "no". A set
/// the live region already has is likewise swept, which is what makes a failed
/// retire harmless.
pub fn recover(region: &mut dyn KeyRegion, scratchpad: Slot) -> Result<Recovery, &'static str> {
    let scratch_base = sector_base_index(scratchpad);
    let region_slots = region.slots();
    if scratch_base + SLOTS_PER_SECTOR > region_slots {
        return Err("recover: the scratchpad sector is not wholly inside this region");
    }

    // Pass 1 — hold at most one staged image at a time. Four 1 KiB images
    // would be 4 KiB of boot-path stack, which this tree pays for elsewhere
    // (the US-961 heap gate, the BSS baseline); the re-reads in pass 2 are
    // four slot reads on a path that runs once per boot.
    let mut staged: [Option<StagedRecord>; SCRATCHPAD_SLOTS as usize] =
        [None; SCRATCHPAD_SLOTS as usize];
    let mut any_content = false;
    let mut offset = 0u32;
    while offset < SLOTS_PER_SECTOR {
        let slot = slot_at(scratch_base, offset);
        let raw = region.read_slot(slot)?;
        if !erased(&raw) {
            any_content = true;
            staged[offset as usize] = staged_record(region_slots, &raw);
        }
        offset += 1;
    }

    // Nothing staged at all: the ordinary boot path, where there is no work and
    // — deliberately — no erase. Erasing unconditionally would spend a sector's
    // worth of NOR endurance on every [`commit`], which also calls this.
    if !any_content {
        return Ok(Recovery::Swept);
    }

    let Some(set) = staged_set(&staged) else {
        // Partial, or spread across two sectors. A commit of this module's
        // cannot produce the latter, so it is corruption or foreign bytes —
        // either way there is no complete set, so there is nothing to replay
        // and erasing the scratchpad returns it to pristine.
        region.erase_sector(scratchpad)?;
        return Ok(Recovery::Swept);
    };

    match sector_state(region, &set, scratch_base)? {
        SectorState::AlreadyCurrent => {
            // The commit finished and only its retire erase failed. Sweeping is
            // the whole of the repair, and it is why the retire erase is allowed
            // to be best-effort (`commit`'s step 7): the worst case is one extra
            // erase on the next boot, not a wrong sector.
            region.erase_sector(scratchpad)?;
            return Ok(Recovery::AlreadyCurrent {
                sector: set.base,
                target: set.target,
                generation: set.generation,
            });
        }
        SectorState::Incomplete => {
            // The scratchpad would destroy a record it does not carry. Erase it
            // and report nothing committed: this is the interrupted-staging
            // case, where the live sector is untouched and generation N stands.
            region.erase_sector(scratchpad)?;
            return Ok(Recovery::Swept);
        }
        SectorState::Replayable => {}
    }

    // Replay. The staged images *are* the new generation, so this is the
    // commit's phase 6 and nothing more — the erase first, because NOR cannot
    // rewrite programmed bytes, and target-last so the ordering that made the
    // set complete in the scratchpad makes it complete in the live sector too.
    region.erase_sector(set.base)?;
    let base = set.base.index() as u32;
    let mut offset = 0u32;
    while offset < SLOTS_PER_SECTOR {
        let slot = slot_at(scratch_base, offset);
        let raw = region.read_slot(slot)?;
        if !erased(&raw) {
            region.program(slot_at(base, offset), 0, &raw)?;
        }
        offset += 1;
    }
    region.erase_sector(scratchpad)?;
    Ok(Recovery::Replayed {
        sector: set.base,
        target: set.target,
        generation: set.generation,
    })
}

/// What the scratchpad's contents mean for the live sector.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SectorState {
    /// Every live slot already holds exactly the staged bytes — the commit
    /// finished and only its retire erase failed, or failed part-way through
    /// the copy.
    AlreadyCurrent,
    /// The live sector is missing bytes the scratchpad carries, and carries
    /// nothing the scratchpad would destroy: replaying is safe.
    Replayable,
    /// The live sector holds a record the scratchpad does not carry, or carries
    /// different bytes there. Replaying would destroy it, so the set is
    /// abandoned.
    Incomplete,
}

/// A staged scratchpad slot that turned out to be a live record: which live
/// slot it belongs to, and at what generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct StagedRecord {
    /// The live slot the record's own header names — read out of the header by
    /// [`record::decode`], which checks it against every candidate rather than
    /// trusting anything the scratchpad says about itself.
    slot: Slot,
    /// The generation the record carries.
    generation: u32,
}

/// Identify one staged image as a live record, or `None` if it is not one.
///
/// [`record::decode`] compares the header's `slot` against the slot it is given
/// and reports [`SlotRead::Absent`] on a mismatch (`record.rs:846-848`), so
/// there is no "parse the header" entry point to call: the only way to learn
/// which live slot a staged record names is to try them, and a successful try
/// hands back the header, so the generation comes along with the answer.
///
/// The cost is `region_slots` header parses per staged record — 960 CRC32s over
/// twelve bytes each on a full region, 3 840 for a completely full scratchpad.
/// It is paid once per recovery and buys the refusal to trust an unparsed
/// header, which is the cheaper of the two mistakes available here: a wrong
/// answer does not return the wrong credential, it **erases a sector**.
fn staged_record(region_slots: u32, raw: &SlotImage) -> Option<StagedRecord> {
    let mut index = 0u32;
    while index < region_slots {
        let candidate = Slot::new(index as u16)?;
        if let SlotRead::Present(decoded) = record::decode(candidate, raw) {
            return Some(StagedRecord {
                slot: candidate,
                generation: decoded.header().generation(),
            });
        }
        index += 1;
    }
    None
}

/// One consistent staged set: the live sector it belongs to, and its witness.
struct StagedSet {
    /// The live sector's head slot.
    base: Slot,
    /// The last-programmed record of the set — the one that proves it complete.
    target: Slot,
    /// The witness's generation.
    generation: u32,
}

/// Recognise a complete staged set, or `None`.
///
/// "Complete" means: every staged image that is a valid record names a slot in
/// **one** live sector, at the position this module wrote it, and at least one
/// of them does. The position check is the tight one — `stage` puts the mate
/// from live slot `base + i` at scratchpad offset `i`, and the record's own
/// header still names `base + i` because the bytes were never re-sealed — so a
/// staged record landing anywhere else is not something [`commit`] wrote, and
/// refusing it is what keeps a corrupt or forged scratchpad from steering a
/// recovery at a sector this commit never named.
///
/// Scratchpad slots holding bytes that are **not** a valid record impose no
/// constraint. They are corrupt mates that will be copied verbatim but say
/// nothing about where the set belongs, and requiring them to decode would mean
/// one corrupt neighbour could stop a commit from ever being recovered.
///
/// The witness is the staged record at the **highest offset**, which is the one
/// [`stage`] programs last (module docs) — so the set being recognised here and
/// the set being completed there are the same decision reached two ways, and a
/// set whose witness never landed is not a set.
fn staged_set(staged: &[Option<StagedRecord>; SCRATCHPAD_SLOTS as usize]) -> Option<StagedSet> {
    let mut base: Option<u32> = None;
    let mut witness: Option<&StagedRecord> = None;
    for (offset, entry) in staged.iter().enumerate() {
        let Some(entry) = entry else { continue };
        let offset = offset as u32;
        let this_base = sector_base_index(entry.slot);
        if entry.slot.index() as u32 != this_base + offset {
            return None;
        }
        match base {
            None => base = Some(this_base),
            Some(b) if b == this_base => {}
            Some(_) => return None,
        }
        witness = Some(entry);
    }
    let witness = witness?;
    Some(StagedSet {
        base: sector_base(witness.slot),
        target: witness.slot,
        generation: witness.generation,
    })
}

/// Classify the staged set against the live sector — the replacement test.
///
/// The whole of recovery's safety argument, and it is four lines of byte
/// comparison for a reason stated in the module docs: **the scratchpad may only
/// be replayed where replaying destroys nothing.** `Incomplete` is therefore
/// not an error, it is the answer for an interrupted staging pass, and it is
/// what keeps [`Recovery::Swept`] from being the wrong default.
fn sector_state(
    region: &mut dyn KeyRegion,
    set: &StagedSet,
    scratch_base: u32,
) -> Result<SectorState, &'static str> {
    let base = set.base.index() as u32;
    let mut differs = false;
    let mut offset = 0u32;
    while offset < SLOTS_PER_SECTOR {
        let live = region.read_slot(slot_at(base, offset))?;
        let staged = region.read_slot(slot_at(scratch_base, offset))?;
        if live != staged {
            if !erased(&live) {
                // The live slot holds a record the staged set does not carry.
                // Erasing it to make room for a replay would lose it.
                return Ok(SectorState::Incomplete);
            }
            differs = true;
        }
        offset += 1;
    }
    Ok(if differs { SectorState::Replayable } else { SectorState::AlreadyCurrent })
}

// ---------------------------------------------------------------------------
// Wipe (US-1546)
// ---------------------------------------------------------------------------

/// Erase every sector of `region`, so that no record in it is readable.
///
/// Returns how many sectors were erased. Idempotent and resumable: a wipe
/// interrupted part-way leaves some sectors erased, and running it again
/// finishes. It is **not atomic across sectors**, and on this hardware cannot
/// be — N sectors is N erase instructions and there is no way to make the last
/// conditional on the first (module docs).
///
/// The scratchpad is included whenever it lies inside `region`, which it must
/// for [`commit`] to work at all: a wipe that left staged records behind would
/// hand the next boot a `recover` to replay, and the credentials it replayed
/// into the live region are ones the caller just asked to destroy.
///
/// # What a caller must still do
///
/// Erasing the records makes them unreadable; it does not make the *store*
/// empty to an index that is stored elsewhere. A caller that needs "the reset
/// is complete or nothing happened" wipes the index first — the two key domains
/// ([`crypto`](super::crypto)) exist so that is possible — and calls this
/// afterwards as the reclamation step. The house precedent for reporting rather
/// than assuming is `trusted_backend::device::wipe_internal_fs`
/// (`platform/src/trusted_backend/device.rs:1092`): a format that failed is
/// reported as a failure, because a factory reset that reports success having
/// wiped nothing is worse than one that reports failure.
pub fn wipe(region: &mut dyn KeyRegion) -> Result<u32, &'static str> {
    let sectors = region.slots() / SLOTS_PER_SECTOR;
    let mut erased_count = 0u32;
    let mut index = 0u32;
    while index < sectors {
        let base = slot_at(index * SLOTS_PER_SECTOR, 0);
        region.erase_sector(base)?;
        erased_count += 1;
        index += 1;
    }
    Ok(erased_count)
}

// ---------------------------------------------------------------------------
// Compile-time assertions
// ---------------------------------------------------------------------------

const _: () = {
    // The scratchpad is a whole sector of whole slots. If the sector were
    // smaller than one slot this module could not stage anything; if it were
    // larger, the staging pass would silently skip slots the recovery would
    // then look at.
    assert!(
        SCRATCHPAD_SLOTS == SLOTS_PER_SECTOR && SCRATCHPAD_SLOTS >= 1,
        "the commit scratchpad is exactly one sector of slots"
    );
    // `Slot::new` is what every arithmetic helper here ends in, so the casts to
    // `u16` below must be exact for the whole slot space.
    assert!(
        SLOTS_PER_SECTOR <= u16::MAX as u32,
        "a sector's slot range must fit Slot's u16 index or slot_at wraps and stages into a \
         different sector than the one it read"
    );
    // The slot stride is what `read_slot` returns and what `program` is given;
    // a program window that is not the whole stride would leave the tail of a
    // slot un-rewritten after an erase, which reads as a corrupt record rather
    // than as absent.
    assert!(
        FIDO_SLOT_BYTES != 0 && FIDO_SLOT_BYTES & (FIDO_SLOT_BYTES - 1) == 0,
        "the commit path programs whole slot images"
    );
};