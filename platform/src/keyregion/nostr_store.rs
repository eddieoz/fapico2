//! The Nostr identity store (US-1641): one record per identity, in the eight
//! slots US-1639 carved from the top of FIDO's range.
//!
//! The model is [`super::oath_store`] — a borrowed view over the region, a
//! per-record codec, and the sector-commit machinery — shrunk to a domain that
//! holds at most [`NOSTR_CAPACITY`] fixed-width identities and has no index
//! (for 8 records the scan is the cheap half of every operation).
//!
//! # The body
//!
//! Fixed 97 bytes, the layout the design fixes and the slot bound
//! ([`super::NOSTR_RECORD_MAX`], 125 B sealed) derives from:
//!
//! ```text
//! scalar   32   the BIP-340 secret key, stored raw — EXPORT_KEY (US-1649)
//!               hands this back and SIGN (US-1645) signs with it
//! npub     32   the x-only public key, derived once at write time and stored
//!               alongside the scalar so GET_PUBKEY/LIST_KEYS never multiply
//! label    32   zero-padded UTF-8, zero-terminated by construction (a zero
//!               byte cannot occur inside a UTF-8 sequence), so the label is
//!               the bytes before the first zero and there is no length byte
//!               to disagree with itself
//! flags     1   opaque to the store; the applet assigns the bits
//! ```
//!
//! # The occupancy guard, and why this store is stricter than OATH's
//!
//! OATH's slots were never anyone else's, so an OATH write can commit at
//! `generation + 1` over whatever it finds. Nostr's slots **were** FIDO's
//! until the carve: a board carrying ≥ 849 FIDO credentials has FIDO records
//! sitting in what is now Nostr's range, and `FidoAllocator::alloc` will not
//! report `Full` to warn anyone (`fido_store.rs:466-484` scans only to
//! [`super::FIDO_SLOT_LIMIT`]). Writing over such a record would destroy a
//! passkey silently — the §2.4.2 hazard the carve created by vacating slots.
//!
//! So every write runs the design's predicate, **in this order**:
//!
//! 1. the slot reads back **virgin** (`RecordOccupancy` — no parseable
//!    header) → free; write it at generation 1;
//! 2. the slot reads back **occupied** → it must **open successfully as a
//!    Nostr record** — the `KeyDomain::Nostr` tag in the AAD matches *and*
//!    the AEAD authenticates under this device's payload key — before it is
//!    reused at the next generation. Anything else (a FIDO record, a record
//!    from another board, a Nostr record this key cannot open) is refused:
//!    the store does not write a slot whose occupant it cannot identify.
//!
//! A torn record (CRC-failed header) reads as *not occupied*, which is what
//! makes a replace possible: `commit::recover` and the generation rule keep
//! the commit safe, and refusing to overwrite a torn record would strand the
//! slot forever (`oath_store.rs:824-841` carries the same reasoning).
//!
//! # Deletes
//!
//! A tombstone, the same discipline as OATH: NOR cannot erase one slot, so
//! `delete` commits a one-byte body the codec refuses as an identity, the
//! generation still advances, and the next write to the slot is sealed at a
//! strictly higher generation than the deleted credential ever saw.
//!
//! [`TOMBSTONE`]: NostrStore::TOMBSTONE

extern crate alloc;

use alloc::boxed::Box;
use core::fmt;

use super::commit::{self, CommitError, CommitPlan, CommitReport, Recovery};
use super::crypto::{KeyDomain, PayloadKey, RecordAad, RECORD_OVERHEAD};
use super::record::{self, Domain, RecordOccupancy};
use super::slotmap::Occupancy;
use super::{KeyRegion, NOSTR_CAPACITY, NOSTR_FIRST_SLOT, NOSTR_RECORD_MAX, Sealed, Slot, SlotRead, TOTAL_SLOTS};

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/// The first slot Nostr owns: the top of what was FIDO's range (US-1639).
pub const NOSTR_SLOTS: u32 = NOSTR_CAPACITY;

/// The identity body's exact width: `scalar(32) ‖ npub(32) ‖ label(32) ‖
/// flags(1)`. Fixed, because the slot bound ([`super::NOSTR_RECORD_MAX`]) is
/// derived from it and a variable body would be a second thing to re-measure.
pub const NOSTR_BODY_LEN: usize = 97;

/// Longest label, in bytes ([`NOSTR_BODY_LEN`]'s own arithmetic, restated so
/// the codec cannot drift from the layout table).
pub const NOSTR_LABEL_MAX: usize = 32;

/// The tombstone body: one zero byte.
///
/// An identity body is exactly [`NOSTR_BODY_LEN`] bytes and a valid BIP-340
/// scalar is never zero, so a one-byte body is unambiguous from both sides.
pub const TOMBSTONE: &[u8] = &[0x00];

// ---------------------------------------------------------------------------
// The identity body
// ---------------------------------------------------------------------------

/// One Nostr identity, as it is sealed into a slot.
///
/// `Copy` because it is 97 bytes of scalars read and written once per
/// operation; `Clone` comes with it. There is no `Debug` that prints the
/// scalar — the same rule as [`super::Sealed`] and [`super::crypto`]'s key
/// types: a `Debug` that dumps key material is a `Debug` that puts it in a
/// log buffer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NostrIdentity {
    /// The BIP-340 secret key, raw. Never `Debug`-printed; never leaves the
    /// device except through `EXPORT_KEY`'s own touch gate.
    pub scalar: [u8; 32],
    /// The x-only public key. Stored alongside the scalar so the read
    /// commands never curve-multiply on device.
    pub npub: [u8; 32],
    /// Zero-padded UTF-8 label, [`NOSTR_LABEL_MAX`] bytes wide.
    label: [u8; NOSTR_LABEL_MAX],
    /// Opaque flags byte; the applet owns the bits.
    pub flags: u8,
}

impl NostrIdentity {
    /// Assemble an identity body. `label` may be any length up to
    /// [`NOSTR_LABEL_MAX`]; it must be valid UTF-8, because a label that is
    /// not a string is not a label — the same refusal
    /// `capacity_boundary.rs`'s fixture records for a non-UTF-8 RP ID.
    pub fn new(scalar: [u8; 32], npub: [u8; 32], label: &[u8], flags: u8) -> Option<Self> {
        if label.len() > NOSTR_LABEL_MAX || core::str::from_utf8(label).is_err() {
            return None;
        }
        let mut padded = [0u8; NOSTR_LABEL_MAX];
        padded[..label.len()].copy_from_slice(label);
        Some(NostrIdentity { scalar, npub, label: padded, flags })
    }

    /// The label, up to its zero terminator.
    pub fn label(&self) -> &[u8] {
        let end = self.label.iter().position(|&b| b == 0).unwrap_or(NOSTR_LABEL_MAX);
        &self.label[..end]
    }

    /// Encode into `out` (`[`NOSTR_BODY_LEN`]` bytes). Returns the length
    /// written, always [`NOSTR_BODY_LEN`].
    pub fn encode(&self, out: &mut [u8; NOSTR_BODY_LEN]) -> usize {
        out[..32].copy_from_slice(&self.scalar);
        out[32..64].copy_from_slice(&self.npub);
        out[64..96].copy_from_slice(&self.label);
        out[96] = self.flags;
        NOSTR_BODY_LEN
    }

    /// Decode an identity body. `None` on a length this codec does not
    /// produce — including [`TOMBSTONE`], which is how a delete is seen as
    /// something other than an undecodable record.
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() != NOSTR_BODY_LEN {
            return None;
        }
        let mut id = NostrIdentity {
            scalar: [0u8; 32],
            npub: [0u8; 32],
            label: [0u8; NOSTR_LABEL_MAX],
            flags: body[96],
        };
        id.scalar.copy_from_slice(&body[..32]);
        id.npub.copy_from_slice(&body[32..64]);
        id.label.copy_from_slice(&body[64..96]);
        Some(id)
    }

    /// Whether this body is the tombstone [`NostrStore::delete`] commits.
    pub fn is_tombstone(body: &[u8]) -> bool {
        body == TOMBSTONE
    }
}

impl fmt::Debug for NostrIdentity {
    /// Prints the public half and the label, never the scalar — the same rule
    /// as [`super::Sealed`]'s hand-written `Debug`: a `Debug` that dumps key
    /// material is a `Debug` that puts it in a log buffer.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut npub_hex = [0u8; 64];
        for (i, b) in self.npub.iter().enumerate() {
            npub_hex[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
            npub_hex[2 * i + 1] = b"0123456789abcdef"[(b & 0x0f) as usize];
        }
        f.debug_struct("NostrIdentity")
            .field("npub", &core::str::from_utf8(&npub_hex).unwrap_or("<hex>"))
            .field("label", &core::str::from_utf8(self.label()).unwrap_or("<utf8>"))
            .field("flags", &self.flags)
            .field("scalar", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Errors and read outcomes
// ---------------------------------------------------------------------------

/// A store operation's failure, named for the caller that can render it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NostrStoreError {
    /// The region could not be read or written — a transport error, never a
    /// fact about the data.
    Fault(&'static str),
    /// The index named is outside [`NOSTR_SLOTS`].
    IndexOutOfRange {
        index: u16,
    },
    /// The slot's occupant could not be identified as a Nostr record this
    /// device's key opens, and the write was refused (US-1641's guard). This
    /// is the refusal that protects a stale FIDO record in a carved slot.
    OccupiedForeign {
        slot: Slot,
    },
    /// The occupant still opens as ours under this device's key:
    /// [`NostrStore::force_tombstone`] refuses — `delete` owns live
    /// records, and it names what it destroyed.
    LiveRecord {
        slot: Slot,
    },
    /// The AEAD refused a seal or an open it should never refuse.
    Aead,
    /// The slot's generation counter is exhausted.
    GenerationExhausted {
        slot: Slot,
    },
    /// The commit machinery refused or lost the write.
    Commit(CommitError),
}

impl fmt::Display for NostrStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NostrStoreError::Fault(reason) => write!(f, "key region fault: {reason}"),
            NostrStoreError::IndexOutOfRange { index } => {
                write!(f, "identity index {index} is outside Nostr's {NOSTR_SLOTS}-slot range")
            }
            NostrStoreError::OccupiedForeign { slot } => write!(
                f,
                "slot {} holds a record this store cannot identify as its own; the write was \
                 refused rather than overwrite it",
                slot.index()
            ),
            NostrStoreError::LiveRecord { slot } => write!(
                f,
                "slot {} holds a live record: delete it through the named path, not a force",
                slot.index()
            ),
            NostrStoreError::Aead => write!(f, "the AEAD refused the record"),
            NostrStoreError::GenerationExhausted { slot } => {
                write!(f, "slot {} has exhausted its generation counter", slot.index())
            }
            NostrStoreError::Commit(e) => write!(f, "commit refused: {e:?}"),
        }
    }
}

/// What one slot holds, as [`NostrStore::read`] reports it.
///
/// The same five-way split as OATH's `Entry`, for the same reason: an empty
/// slot, a foreign record, and an undecodable one are three different facts,
/// and only the first is ordinary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Entry {
    /// The slot is erased or its header failed its CRC.
    Empty,
    /// The slot holds a live identity.
    Live(NostrIdentity),
    /// The slot holds a committed delete.
    Tombstone,
    /// The slot holds a record with our domain tag that would not open or
    /// decode. It stays occupied — the allocator will not hand it out — but
    /// the occupancy guard will refuse to overwrite it.
    Undecodable,
    /// The slot holds a record some *other* domain wrote. In FIDO's former
    /// range this is the stale-passkey case the occupancy guard exists for.
    Foreign,
}

// ---------------------------------------------------------------------------
// The store view
// ---------------------------------------------------------------------------

/// A borrowed view of the region, carrying the payload key it seals with.
///
/// The same shape as [`super::oath_store::OathStore`], for the same reasons:
/// the key is derived once per session and borrowed per operation.
pub struct NostrStore<'r> {
    region: &'r mut dyn KeyRegion,
    key: &'r PayloadKey,
}

impl<'r> NostrStore<'r> {
    /// A view over `region`, sealing and opening with `key`.
    pub fn new(region: &'r mut dyn KeyRegion, key: &'r PayloadKey) -> Self {
        NostrStore { region, key }
    }

    /// The region itself, for a caller that has to inspect the medium.
    pub fn region(&mut self) -> &mut dyn KeyRegion {
        self.region
    }

    /// Refuse an index this *region* cannot hold — the same check as OATH's
    /// `slot_for`, because the geometry here is a claim about the shipping
    /// region and a host fixture may be shorter.
    fn slot_for(&self, index: u16) -> Result<Slot, NostrStoreError> {
        let slot = nostr_slot(index).ok_or(NostrStoreError::IndexOutOfRange { index })?;
        if !holds_slot(self.region, slot) {
            return Err(NostrStoreError::Fault(E_SHORT_REGION));
        }
        Ok(slot)
    }

    /// Finish or abandon a commit interrupted by a power cut. **Must run
    /// before the region is read** — a live sector between its erase and its
    /// copy-back reads as empty (`commit::recover`'s docs).
    pub fn recover(&mut self) -> Result<Recovery, NostrStoreError> {
        let scratchpad = scratchpad_slot().ok_or(NostrStoreError::Fault(E_NO_SCRATCHPAD))?;
        commit::recover(self.region, scratchpad).map_err(NostrStoreError::Fault)
    }

    /// Read one slot's record and open it, as an [`Entry`].
    pub fn read(&mut self, index: u16) -> Result<Entry, NostrStoreError> {
        let slot = self.slot_for(index)?;
        let raw = self.region.read_slot(slot).map_err(NostrStoreError::Fault)?;
        let decoded = match record::decode(slot, &raw) {
            SlotRead::Present(d) => d,
            SlotRead::Absent => return Ok(Entry::Empty),
            SlotRead::Fault(reason) => return Err(NostrStoreError::Fault(reason)),
        };
        if decoded.header().domain() != Domain::Nostr {
            return Ok(Entry::Foreign);
        }
        let opened = match record::open(decoded.header(), self.key.as_bytes(), decoded.body()) {
            SlotRead::Present(pt) => pt,
            SlotRead::Absent | SlotRead::Fault(_) => return Ok(Entry::Undecodable),
        };
        let body = opened.as_slice();
        if NostrIdentity::is_tombstone(body) {
            return Ok(Entry::Tombstone);
        }
        match NostrIdentity::decode(body) {
            Some(id) => Ok(Entry::Live(id)),
            None => Ok(Entry::Undecodable),
        }
    }

    /// The occupancy guard (US-1641), in the design's fixed order, returning
    /// the generation the next write to `slot` may carry.
    ///
    /// **Order is load-bearing.** Virgin first — a virgin slot does not open,
    /// so asking the open question first would make the applet unable to
    /// write anything — and only then the identity question, which a slot
    /// answers by *opening as a Nostr record under this device's key*, not by
    /// carrying our domain tag: a tag is one header byte a transplanted
    /// record can carry, and the AEAD authentication is the part that cannot
    /// be forged without the key.
    fn admission(&mut self, slot: Slot) -> Result<u32, NostrStoreError> {
        let raw = self.region.read_slot(slot).map_err(NostrStoreError::Fault)?;

        // 1. Virgin (never written, or a torn record the codec reads as
        //    absent): free, and the first write is generation 1.
        if !RecordOccupancy.occupied(&raw) {
            return Ok(1);
        }

        // 2. Occupied: the occupant must identify itself as a Nostr record
        //    this key opens. Header first — a FIDO record fails here and is
        //    refused *before* anything touches it.
        let decoded = match record::decode(slot, &raw) {
            SlotRead::Present(d) => d,
            SlotRead::Absent => unreachable!("occupied slot decoded as absent"),
            SlotRead::Fault(reason) => return Err(NostrStoreError::Fault(reason)),
        };
        if decoded.header().domain() != Domain::Nostr {
            return Err(NostrStoreError::OccupiedForeign { slot });
        }
        // …and the AEAD leg: the tag without the key is not identification.
        match record::open(decoded.header(), self.key.as_bytes(), decoded.body()) {
            SlotRead::Present(_) => {}
            SlotRead::Absent | SlotRead::Fault(_) => {
                return Err(NostrStoreError::OccupiedForeign { slot })
            }
        }
        decoded
            .header()
            .generation()
            .checked_add(1)
            .ok_or(NostrStoreError::GenerationExhausted { slot })
    }

    /// Seal `body` for `(slot, generation)` under the payload key.
    fn seal(&self, slot: Slot, generation: u32, body: &[u8]) -> Result<Sealed, NostrStoreError> {
        let aad = RecordAad::new(KeyDomain::Nostr, slot, generation);
        let mut out = alloc::vec![0u8; body.len() + RECORD_OVERHEAD];
        let n = super::crypto::seal_payload(self.key, &aad, body, &mut out)
            .ok_or(NostrStoreError::Aead)?;
        out.truncate(n);
        Ok(Sealed::from_sealed_bytes(out))
    }

    /// Commit one identity to `index`.
    ///
    /// The occupancy guard runs first and refuses the write when the slot's
    /// occupant is not ours; a passed guard commits at the generation the
    /// guard itself computed, and `commit::commit` independently refuses a
    /// generation that does not advance.
    pub fn write(
        &mut self,
        index: u16,
        identity: &NostrIdentity,
    ) -> Result<CommitReport, NostrStoreError> {
        let mut body = [0u8; NOSTR_BODY_LEN];
        let n = identity.encode(&mut body);
        self.commit_body(index, &body[..n])
    }

    /// Tombstone `index`: a durable delete that keeps the slot reusable.
    pub fn delete(&mut self, index: u16) -> Result<CommitReport, NostrStoreError> {
        self.commit_body(index, TOMBSTONE)
    }

    /// Tombstone `index` bypassing the occupancy guard — the repair path
    /// for a slot whose record carries our domain tag but will not open
    /// (`Entry::Undecodable`, F-A5 in `docs/nostr-presence-audit.md`). The
    /// guard protects *live* records: one that opens is refused here
    /// ([`NostrStoreError::LiveRecord`] — delete it through
    /// [`NostrStore::delete`], which names what it destroyed); one that
    /// cannot open is by definition not live, and refusing to touch it
    /// stranded the slot behind `6A84` forever. The generation comes from
    /// the standing header when it can be read; a header too damaged to
    /// decode leaves nothing to advance past and the tombstone commits at
    /// generation 1. A fault-class decode (the region itself is failing)
    /// is refused, never papered over.
    pub fn force_tombstone(&mut self, index: u16) -> Result<CommitReport, NostrStoreError> {
        let slot = self.slot_for(index)?;
        let scratchpad = scratchpad_slot().ok_or(NostrStoreError::Fault(E_NO_SCRATCHPAD))?;
        let raw = self.region.read_slot(slot).map_err(NostrStoreError::Fault)?;
        let generation = match record::decode(slot, &raw) {
            SlotRead::Present(d) => {
                if matches!(
                    record::open(d.header(), self.key.as_bytes(), d.body()),
                    SlotRead::Present(_)
                ) {
                    return Err(NostrStoreError::LiveRecord { slot });
                }
                d.header()
                    .generation()
                    .checked_add(1)
                    .ok_or(NostrStoreError::GenerationExhausted { slot })?
            }
            SlotRead::Absent => 1,
            SlotRead::Fault(reason) => return Err(NostrStoreError::Fault(reason)),
        };
        let sealed = self.seal(slot, generation, TOMBSTONE)?;
        let plan = CommitPlan::new(scratchpad, slot, Domain::Nostr, generation);
        commit::commit(self.region, plan, &sealed).map_err(NostrStoreError::Commit)
    }

    /// The shared commit path: guard, seal, commit.
    fn commit_body(&mut self, index: u16, body: &[u8]) -> Result<CommitReport, NostrStoreError> {
        let slot = self.slot_for(index)?;
        let scratchpad = scratchpad_slot().ok_or(NostrStoreError::Fault(E_NO_SCRATCHPAD))?;
        let generation = self.admission(slot)?;
        let sealed = self.seal(slot, generation, body)?;
        let plan = CommitPlan::new(scratchpad, slot, Domain::Nostr, generation);
        commit::commit(self.region, plan, &sealed).map_err(NostrStoreError::Commit)
    }
}

/// The scratchpad could not be named — impossible on this geometry, and named
/// rather than `unwrap`ed so a change that breaks the reasoning fails loudly.
const E_NO_SCRATCHPAD: &str =
    "key region: the Nostr scratchpad slot is outside the region geometry";

/// The region handed to a [`NostrStore`] is shorter than the geometry.
const E_SHORT_REGION: &str =
    "key region: the region is shorter than the slot the Nostr geometry names";

/// Whether `slot` is inside the region this view was handed.
///
/// The same published predicate OATH's carries, for the same reason: the
/// geometry in this file is a claim about the *shipping* region and a test's
/// region may be shorter.
pub fn holds_slot(region: &dyn KeyRegion, slot: Slot) -> bool {
    (slot.index() as u32) < region.slots()
}

/// The [`Slot`] at applet index `index`, refusing one [`NOSTR_SLOTS`] cannot
/// hold.
///
/// `None` rather than a wrap, the same rule as `oath_slot`: the applet's
/// bound and the region's reservation are two constants in two crates, and
/// disagreement must refuse, not alias.
pub const fn nostr_slot(index: u16) -> Option<Slot> {
    let i = index as u32;
    if i < NOSTR_SLOTS {
        Slot::new((NOSTR_FIRST_SLOT + i) as u16)
    } else {
        None
    }
}

/// The scratchpad slot commits stage through: the region's **shared** one,
/// taken from OATH's own publisher so there is one definition of it
/// (`oath_store.rs:301-304`). Nostr's slots share no sector with the
/// scratchpad — the carve sits at the region's opposite end — so staging
/// through it is exactly as safe for a Nostr commit as for an OATH one.
pub const fn scratchpad_slot() -> Option<Slot> {
    super::oath_store::scratchpad_slot()
}

// ---------------------------------------------------------------------------
// Compile-time assertions
// ---------------------------------------------------------------------------

const _: () = {
    // The measured body must equal the constant the slot bound was sized
    // from. A fixed-width body makes this arithmetic; making it an assert
    // anyway is what keeps a future field from widening the body past the
    // bound without the build stopping.
    assert!(
        NOSTR_RECORD_MAX as usize == NOSTR_BODY_LEN + RECORD_OVERHEAD,
        "the Nostr body layout no longer seals to NOSTR_RECORD_MAX — re-derive the bound in \
         mod.rs rather than widening the body silently"
    );
    assert!(
        NOSTR_BODY_LEN + RECORD_OVERHEAD <= super::record::MAX_BODY_BYTES,
        "the Nostr record must fit the slot the region addresses"
    );
    assert!(NOSTR_SLOTS > 0, "a reservation of zero slots is not a reservation");
    assert!(
        NOSTR_FIRST_SLOT + NOSTR_SLOTS <= TOTAL_SLOTS,
        "Nostr's reservation must sit inside the region"
    );
};

// ---------------------------------------------------------------------------
// The owned handle
// ---------------------------------------------------------------------------

/// A region plus the payload key, owned by the applet for its session.
///
/// The same shape and the same one-rule-break as [`super::oath_store::OathRegion`]
/// (`oath_store.rs:944-990`'s doc explains why the key is held across the
/// session rather than derived per operation): the alternative keeps the OTP
/// row's *root* resident for the same window, which is strictly the worse
/// trade.
pub struct NostrRegion {
    region: Box<dyn KeyRegion>,
    key: PayloadKey,
}

impl NostrRegion {
    /// Take ownership of a region and the key to seal its records with.
    pub fn new(region: Box<dyn KeyRegion>, key: PayloadKey) -> Self {
        NostrRegion { region, key }
    }

    /// A borrowed view for one operation.
    pub fn store(&mut self) -> NostrStore<'_> {
        NostrStore::new(self.region.as_mut(), &self.key)
    }

    /// The region alone — for a caller that has to inspect or repair the
    /// medium rather than go through this module's API.
    pub fn region(&mut self) -> &mut dyn KeyRegion {
        self.region.as_mut()
    }
}

impl fmt::Debug for NostrRegion {
    /// Never prints the key, and never prints the region's path or contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NostrRegion(<region>, <key redacted>)")
    }
}
