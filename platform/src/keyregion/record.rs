//! The record codec: a 16-byte header with a CRC32 over it, and the fail-closed
//! read/write path over the region's AEAD (US-1542, US-1549).
//!
//! # What a slot holds
//!
//! One slot is one record, and a record is a header followed by a sealed body:
//!
//! ```text
//! [ 16-byte header ][ sealed body … ][ 0xFF padding to FIDO_SLOT_BYTES ]
//! ```
//!
//! The stride is [`super::FIDO_SLOT_BYTES`] (1,024 B) for
//! **both** domains, not `OATH_SLOT_BYTES`: the region's read unit is one FIDO
//! slot ([`super::KeyRegion::read_slot`] returns
//! `[u8; FIDO_SLOT_BYTES]`, `platform/src/keyregion/mod.rs:426`), and a grid
//! whose read size depends on which applet is asking is a grid nobody can do
//! address arithmetic on. OATH's 512 B stride (`mod.rs:117`) is a *sub-slot*
//! bound — it is what [`Domain::record_max`] is checked against, not what a
//! slot is.
//!
//! # Header layout (v1), all little-endian
//!
//! ```text
//!  off  width  field        why this width
//!   0     2    magic       u16, LE bytes 4B 31 = "K1": the region's tag byte
//!                         'K' and the layout version '1'. **Two bytes**, and
//!                         the reason is arithmetic rather than taste — see
//!                         "Why the magic is two bytes" below.
//!   2     1    domain      u8. Two domains exist (FIDO, OATH), and the byte is
//!                         bound into the AAD, so a body cannot be replayed
//!                         across the domain boundary. One byte is not a
//!                         compromise: 256 domains is 254 more than the epic
//!                         has.
//!   3     1    flags       u8. Exactly one bit is defined (FLAG_SEALED). It
//!                         stays its own byte rather than being packed into
//!                         domain so that "unknown bits set" is detectable — a
//!                         record written by a future format must not be parsed
//!                         under v1 rules.
//!   4     2    slot        u16. Slot::index() is a u16 by construction
//!                         (mod.rs:255) and TOTAL_SLOTS is 960 on the shipping
//!                         part, so u16 carries the whole address space.
//!   6     4    generation  u32 — see "Why the generation is 32 bits" below.
//!  10     2    body_len    u16. The bound it has to express is
//!                         FIDO_SLOT_BYTES - RECORD_HEADER_BYTES = 1008, which
//!                         is 10 bits; u16 costs nothing extra because the
//!                         field is 2 bytes wide anyway to keep the CRC on a
//!                         4-byte boundary.
//!  12     4    crc32       u32, CRC-32/IEEE over bytes 0..12. Four bytes
//!                         because this is the one field that may not be
//!                         narrowed — it is the torn-write detector this story
//!                         installs — and because a CRC whose width is not a
//!                         multiple of 4 would push every field off alignment.
//! ```
//!
//! The CRC covers the first twelve bytes and not itself: the standard
//! arrangement, and the one `secure_store.rs`'s part header already uses
//! (`platform/src/secure_store.rs:35-36`). The CRC-32 itself is
//! `secure_store::crc32`, tableless and shared with the v2/v3 image formats
//! (`platform/src/secure_store.rs:43-45`), so this store does not grow a second
//! CRC implementation that could disagree with the first.
//!
//! # Why the magic is two bytes
//!
//! Seven fields plus a CRC32 in 16 bytes leaves nothing to spare, and exactly
//! two fields cannot be narrowed: the CRC (the story asks for CRC32, and a
//! narrower CRC is a weaker torn-write detector for four bytes of cost) and
//! the generation (below). So the magic is what gives way, from four bytes to
//! two — and the two it keeps are the two it was actually carrying: a store tag
//! and a version. `store_v3` carries the same pair in four bytes
//! (`"PS2F"` -> `"PS3F"`, `platform/src/store_v3.rs:67-68`); a v2 layout here
//! changes the magic to `"K2"` and a v1 decoder reports absence rather than
//! misparsing the fields. Spending two bytes to recover four is the trade the
//! arithmetic offers, and the alternative — a `u16` generation — is a silent
//! truncation of the one number the allocator treats as a replay defence.
//!
//! # Why the generation is 32 bits
//!
//! Because the allocator says so, and it is not a preference there.
//! [`super::slotmap::Allocation::generation`] is a `u32` (`slotmap.rs:227`), the
//! per-slot high-water mark is a `u32` (`slotmap.rs:267`), and
//! [`super::slotmap::Occupancy::generation`] returns `Option<u32>` because "the largest
//! generation this allocator has ever observed in that slot" is the thing that
//! survives a power cycle (`slotmap.rs:34-43`). A 16-bit header field would
//! make the allocator's exhaustion state (`u32::MAX`, `slotmap.rs:247`) and its
//! replay refusal unreachable, and would turn "generation 65537" into
//! "generation 1" — a rollback the AAD is supposed to catch.
//!
//! The AAD binds the same 32 bits — [`RecordHeader::aad`] writes
//! `generation` as a 4-byte little-endian field — so the header and the
//! authenticated data agree on the width and no widening happens anywhere in
//! the chain. That is deliberate: a 16-bit generation in the AAD would leave a
//! replay window open at exactly 65,536 generations, and the header would be
//! the only thing keeping the record out of it.
//!
//! # Corruption is absence, not a fault (US-1549)
//!
//! [`decode`] returns [`super::SlotRead::Absent`] for an
//! erased slot **and** for a slot whose magic, domain, flags, body length or
//! CRC do not hold. This is not a convenience. `SlotRead`'s own doc
//! (`mod.rs:373-379`) makes the same call: a corrupt record is a fact about the
//! data, and reading it as absent is what lets one bad record fail closed for
//! itself alone instead of taking the store with it. `Fault` stays reserved for
//! the one thing that is *not* a fact about the data — a slot buffer that
//! arrived shorter than a slot, which says the transport lied, not the flash.
//!
//! The same rule runs a second time at the AEAD: a body whose tag does not
//! verify is [`super::SlotRead::Absent`] as well, through
//! [`open`]. So one bad record is absent and its neighbours are untouched —
//! which is the whole of US-1549's "one corrupt record does not lose the
//! others".
//!
//! # What this module owns, and what `crypto.rs` (US-1548) must call
//!
//! This module owns the **record format** and the **fail-closed composition**:
//!
//! * the header layout, the CRC, [`encode`] / [`encode_into`] / [`decode`];
//! * the AAD, in [`RecordHeader::aad`] — see below for why it lives here;
//! * the AEAD around a record body, in [`seal`] / [`open`] / [`open_into`];
//! * [`Plaintext`], the zeroizing buffer every plaintext passes through;
//! * the mapping of every failure onto [`SlotRead::Absent`], in [`read`].
//!
//! `crypto.rs` owns the **key half**: where the 32-byte key comes from (the OTP
//! root, the PIN-derived secret) and the nonce for each seal. It must call, and
//! must not re-implement:
//!
//! * [`RecordHeader::aad`] for the AAD — never assemble those bytes itself.
//!   Two builders of one AAD is a store whose records open under one of them
//!   and never under the other, and it is not a compile error;
//! * [`seal`] with a nonce it derived, and [`open`] to read
//!   one back. [`seal`] deliberately refuses to derive a nonce: under GCM a
//!   `(key, nonce)` pair used on two different plaintexts is catastrophic and
//!   unrecoverable, and a module that cannot see the key has no business
//!   choosing one;
//! * [`NONCE_LEN`] / [`SEALED_OVERHEAD`] as the sealed body's framing widths,
//!   which it re-exports rather than restates.
//!
//! # Why the AAD lives here and not in `crypto.rs`
//!
//! Because the AAD is a statement about **what a record is**, and the record
//! format is this module's. The header's field order and the AAD's field order
//! are deliberately the same — domain, slot, generation, all little-endian — so
//! a reader walking one can read the other, and so a change to either is a
//! change to both. Putting the AAD in the key module would let the two drift
//! apart with nothing failing: a record would still seal and still open, and
//! the transplant refusal US-1548 is about would quietly stop holding.
//!
//! What the AAD binds, and what it deliberately does not:
//!
//! * **domain** — a body sealed in an OATH slot cannot open in a FIDO slot.
//!   The two applets share one region and (deliberately, see `crypto.rs`) one
//!   payload key, so without this byte a record could cross between them;
//! * **slot** — a record cannot be moved to another slot. This is the
//!   transplant case: the record is valid, the bytes are intact, and the only
//!   thing wrong is where they are;
//! * **generation** — a record cannot be re-presented as an older write in the
//!   slot it still occupies, which is what `slotmap`'s per-slot monotonicity
//!   is for (`slotmap.rs:34-43`).
//!
//! What it does **not** bind is the body length. GCM authenticates the
//! ciphertext, so a truncated or extended body fails its own tag, and the
//! header's CRC32 covers the length field as the torn-write gate — a fourth
//! value in the AAD would buy nothing that these two do not already hold.
//!
//! The region (US-1541/1543) should therefore call a short list: [`seal`] plus
//! [`encode`] on the way in, [`read`] on the way out, and
//! [`RecordOccupancy`] where the allocator needs to know what a slot holds.
//!
//! # Known conflict with `crypto.rs`, stated rather than left to be discovered
//!
//! As of this commit `crypto.rs` (US-1548) **also** defines an AAD — an
//! 11-byte `RecordAad` over `"KR01" ‖ domain ‖ slot ‖ generation` — and its own
//! seal/open pair, and it compiles without depending on this module. So the
//! tree currently holds two AAD builders and two AEAD call sites for the same
//! record.
//!
//! That is a real defect and not a cosmetic one: a body sealed through
//! `crypto::seal_payload` does **not** open through [`open`], because the two
//! AADs differ and so do the nonce derivations — and the failure it produces is
//! a record that reports itself absent, which is indistinguishable from flash
//! rot. `AGENTS.md` §5 is the rule this breaks: one record format, one region,
//! one key hierarchy.
//!
//! It is recorded here rather than resolved here, because both files are two
//! agents' stories and only one of them is this module. The reconciliation is
//! one line in whichever direction is chosen:
//!
//! * if the AAD stays here, `crypto.rs` drops its `RecordAad` and calls
//!   [`RecordHeader::aad`] — its nonce helper already hashes "the AAD", so it
//!   needs no more than that;
//! * if the AAD moves there, [`RecordHeader::aad`] becomes a delegation and
//!   [`AAD_BYTES`] becomes `crypto::AAD_LEN`, which is what that module's own
//!   docs already ask for.
//!
//! Either way the seal path follows the AAD, and one of the two AEAD call sites
//! goes with it. What must **not** happen is the current state, and a test that
//! pins the AAD's exact bytes — as `platform/tests/key_region_crypto.rs` does —
//! is the fence that keeps it from happening again.
//!
//! # Why the padded tail is 0xFF
//!
//! An unwritten NOR byte reads back as `0xFF` — `slotmap::is_erased`
//! (`slotmap.rs:184-186`) is that test, and `secure_store.rs:208-214` walks a
//! slot the same way. The encoder fills the tail with the erased value rather
//! than with zeroes so that "the rest of this slot was never programmed" stays
//! visible on the medium, and so the encoder's output is byte-identical to what
//! a fresh slot plus this record looks like. The 1,024-byte image is also four
//! whole 256-byte flash pages, which is the unit `KeyRegion::program` programs
//! in (`mod.rs:436`) — the padding never creates a partial page.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use zeroize::Zeroize;

use super::slotmap::{Occupancy, SlotImage};
use super::{
    Sealed, Slot, SlotRead, FIDO_RECORD_MAX, FIDO_SLOT_BYTES, OATH_RECORD_MAX, OATH_SLOT_BYTES,
    RECORD_HEADER_BYTES,
};
use crate::secure_store::crc32;

// ---------------------------------------------------------------------------
// Wire constants
// ---------------------------------------------------------------------------

/// The v1 record magic — little-endian bytes `"K1"`.
///
/// The magic is the format version: a v2 layout changes this constant, and a v1
/// decoder reading a v2 slot sees a magic mismatch and reports
/// [`super::SlotRead::Absent`] rather than misparsing the
/// fields.
pub const RECORD_MAGIC_V1: u16 = 0x314B;

/// Header bytes as a `usize`, for slicing. The same 16 the geometry budgeted
/// (`mod.rs:73-78`) — which chose 16 so this store's framing cost is directly
/// comparable with `secure_store.rs`'s part header.
pub const RECORD_HEADER_LEN: usize = RECORD_HEADER_BYTES as usize;

/// The slot stride in bytes: 1,024, from [`super::FIDO_SLOT_BYTES`].
///
/// One stride for both domains, because this is the region grid's read unit
/// rather than a per-applet quantity — see the module docs.
pub const SLOT_BYTES: usize = FIDO_SLOT_BYTES as usize;

/// The largest sealed body a slot can hold: `1,024 - 16`.
///
/// The number that must not be exceeded is [`FIDO_RECORD_MAX`] (836,
/// `mod.rs:67`): a body larger than this is a record the encoder refused to
/// write, not a record that was written short. Truncation is the failure this
/// store was rebuilt to avoid — it is how the old whole-snapshot design lost an
/// entire credential set to one bad byte, and it is why the stride is derived
/// from a *measured* maximum (`mod.rs:56-66`) rather than an estimated one.
pub const MAX_BODY_BYTES: usize = SLOT_BYTES - RECORD_HEADER_LEN;

/// Erased NOR flash reads as `0xFF`.
pub const ERASED_BYTE: u8 = 0xFF;

/// Byte offset of the magic.
pub const OFF_MAGIC: usize = 0;
/// Byte offset of the domain.
pub const OFF_DOMAIN: usize = 2;
/// Byte offset of the flags.
pub const OFF_FLAGS: usize = 3;
/// Byte offset of the slot index.
pub const OFF_SLOT: usize = 4;
/// Byte offset of the generation.
pub const OFF_GENERATION: usize = 6;
/// Byte offset of the sealed body length.
pub const OFF_BODY_LEN: usize = 10;
/// Byte offset of the header CRC32.
pub const OFF_CRC: usize = 12;

/// The one defined flag bit: **this record's body is a complete, committed
/// AEAD blob**.
///
/// Required on decode, in both directions. A record whose bit is clear is a
/// write that did not finish — not hypothetical on this hardware, because a
/// slot update erases and reprograms a whole 4 KiB sector holding
/// [`super::SLOTS_PER_SECTOR`] slots (`mod.rs:119-132`), so a
/// power loss mid-sector leaves records that are present but incomplete. And a
/// record with a bit this build does not know is a format this build must not
/// guess at. Reading both as absent is the same fail-closed rule as the CRC:
/// incomplete is not usable, and unknown is not readable.
///
/// US-1544/1545 own the commit *ordering*; this bit is the marker that ordering
/// leaves behind.
pub const FLAG_SEALED: u8 = 0x01;

// The AAD itself is NOT defined here. `crypto::RecordAad` owns it — the AEAD
// layer that consumes it — and [`RecordHeader::aad`] is a call into it.
//
// An earlier revision of this file defined the AAD here *and* `crypto.rs`
// defined it there, and the two disagreed (35 bytes against 11). A body sealed
// through one did not open through the other, and the symptom was "reads as
// absent" — indistinguishable from flash rot. Two builders of one AAD is
// precisely what AGENTS.md §5 forbids, and it is the class of bug this epic
// keeps finding: `card.rs:569` against `device_shell.rs:123`, `DEVICE_MAX_CREDS`
// against the region. One record format, one AAD, one key hierarchy.

/// The AAD's exact length, which is `crypto::AAD_LEN` and not a restatement
/// of it.
///
/// It was 35 bytes here and 11 there for one commit. Making this an alias is
/// what stops that recurring: a layout change is then a compile error in one
/// place rather than a decryption failure in the field.
pub const AAD_BYTES: usize = crate::keyregion::crypto::AAD_LEN;

/// GCM nonce length — the `Aes256Gcm` standard 12 bytes, the same width
/// `store_v3` seals images with (`platform/src/store_v3.rs:70-72`) and
/// `snapshot_crypt` seals fields with (`snapshot_crypt.rs:85`).
pub const NONCE_LEN: usize = 12;

/// GCM authentication tag length.
pub const TAG_LEN: usize = 16;

/// Per-record sealing overhead: nonce(12) + tag(16). The ciphertext is
/// plaintext-length (GCM is a stream cipher), so
/// `sealed_len == plaintext_len + SEALED_OVERHEAD`.
pub const SEALED_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

/// Which key domain a record belongs to.
///
/// The AEAD binds the same byte ([`RecordHeader::aad`]), and `crypto.rs`
/// re-exports this type as `KeyDomain` rather than declaring a second one: a
/// domain named in two places is a domain whose byte will eventually disagree
/// with itself, and the byte decides where a record opens.
///
/// The discriminants are pinned. A tag is a byte in authenticated data, so
/// renumbering either one silently re-homes every record already stored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Domain {
    /// A FIDO2 credential. Bounded by [`FIDO_RECORD_MAX`] (836 B).
    Fido = 0x01,
    /// An OATH credential. Bounded by [`OATH_RECORD_MAX`] (210 B).
    Oath = 0x02,
}

impl Domain {
    /// The stable on-flash byte. Never renumber: a decoded byte is looked up
    /// through [`Domain::from_u8`], so renumbering silently re-homes every
    /// record already stored.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Decode a header byte, refusing an unknown one.
    ///
    /// `None` on an unassigned byte is what makes decode fail closed: a domain
    /// this build does not implement is a record this build must not touch, and
    /// the alternative — treating it as `Fido` — would put an OATH-shaped body
    /// into the FIDO path.
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Domain::Fido),
            0x02 => Some(Domain::Oath),
            _ => None,
        }
    }

    /// The largest *sealed* record this domain can produce
    /// ([`FIDO_RECORD_MAX`] / [`OATH_RECORD_MAX`]).
    ///
    /// The per-domain measurement is what OATH's 512 B sub-slot exists for
    /// (`mod.rs:110-117`); the slot itself is 1,024 B for both.
    pub const fn record_max(self) -> u32 {
        match self {
            Domain::Fido => FIDO_RECORD_MAX,
            Domain::Oath => OATH_RECORD_MAX,
        }
    }
}

// ---------------------------------------------------------------------------
// The header
// ---------------------------------------------------------------------------

/// One record's header: which domain, which slot, which write generation, and
/// whether it is committed. The body's length is not a field of the *header
/// type* — it is a property of the encode call — because the AAD is built from
/// this type, and a length that could differ between sealing and decoding would
/// be one more thing the two sides have to agree about.
///
/// Private fields with accessors, for the reason [`Slot`] has them
/// (`mod.rs:254-274`): the header is part of the AEAD's authenticated data, so
/// a field that could be mutated in place after sealing would let a caller
/// author an AAD that does not describe the bytes. Every construction goes
/// through [`RecordHeader::new`], which sets [`FLAG_SEALED`].
///
/// `Copy` because it is 8 bytes of scalars and is passed by value to [`seal`],
/// [`open`] and [`RecordHeader::aad`] on a path that runs once per record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecordHeader {
    domain: Domain,
    slot: Slot,
    generation: u32,
    flags: u8,
}

impl RecordHeader {
    /// A header for `(domain, slot, generation)`, sealed and ready to write.
    ///
    /// The generation is the allocator's to issue ([`super::slotmap::Allocation`]), not
    /// this module's to count: only the allocator knows which generations a slot
    /// has already served, which is the whole of the monotonicity guarantee
    /// (`slotmap.rs:34-43`). Generation `0` is never a legitimate value — the
    /// first write into a virgin slot is generation 1 — and the header does not
    /// enforce that, because the record's own AAD does not need to: a record
    /// claiming generation 0 in a virgin slot is one no allocator issued.
    pub const fn new(domain: Domain, slot: Slot, generation: u32) -> Self {
        RecordHeader { domain, slot, generation, flags: FLAG_SEALED }
    }

    /// Which key domain this record belongs to. Bound into the AAD.
    pub const fn domain(self) -> Domain {
        self.domain
    }

    /// Which slot this record claims. Bound into the AAD, and checked by
    /// [`decode`] against the slot the bytes were actually read from.
    pub const fn slot(self) -> Slot {
        self.slot
    }

    /// The write generation. Bound into the AAD; see the module docs on why it
    /// is 32 bits and what that buys.
    pub const fn generation(self) -> u32 {
        self.generation
    }

    /// The raw flags byte. Only [`FLAG_SEALED`] is defined.
    pub const fn flags(self) -> u8 {
        self.flags
    }

    /// This record's AAD: [`AAD_PREFIX`] + `0x00` + domain + slot + generation,
    /// as bytes.
    ///
    /// **This is the whole of the AAD policy**, and the order is fixed and
    /// documented so that `crypto.rs` and this module derive the same
    /// [`AAD_BYTES`]:
    ///
    /// 1. [`AAD_PREFIX`] — the format tag, `v1` included;
    /// 2. `0x00` — the field separator, as in the `FieldAad` pattern
    ///    (`apps/fido/src/snapshot_crypt.rs:149`);
    /// 3. `domain` as one byte ([`Domain::as_u8`]);
    /// 4. `slot` as `u16` little-endian ([`Slot::index`](Slot::index));
    /// 5. `generation` as `u32` little-endian.
    ///
    /// Fixed-size rather than `Vec<u8>`: a heap AAD would put an allocation on
    /// the per-credential path, and would make "the same bytes on both sides" a
    /// runtime question instead of a type.
    ///
    /// What it buys is in the module docs — the transplant, cross-domain and
    /// rollback refusals — and what it does not bind is the body length, also
    /// argued there.
    pub fn aad(&self) -> [u8; AAD_BYTES] {
        let domain = crate::keyregion::crypto::KeyDomain::from_tag(self.domain.as_u8())
            .expect("Domain::as_u8 and KeyDomain share one tag table (record.rs Domain::as_u8)");
        let built = crate::keyregion::crypto::RecordAad::new(domain, self.slot, self.generation);
        built
            .as_bytes()
            .try_into()
            .expect("RecordAad::as_bytes is AAD_LEN by construction")
    }
    /// Serialize into exactly [`RECORD_HEADER_LEN`] bytes at `out`, CRC
    /// included.
    ///
    /// `body_len` is an argument rather than a field because the AAD must not
    /// depend on it: length is already covered twice — by the CRC here as a
    /// torn-write gate, and by the ciphertext at the AEAD — and the AAD
    /// deliberately leaves it out (module docs).
    fn write(&self, body_len: u16, out: &mut [u8; RECORD_HEADER_LEN]) {
        out[OFF_MAGIC..OFF_MAGIC + 2].copy_from_slice(&RECORD_MAGIC_V1.to_le_bytes());
        out[OFF_DOMAIN] = self.domain.as_u8();
        out[OFF_FLAGS] = self.flags;
        out[OFF_SLOT..OFF_SLOT + 2].copy_from_slice(&self.slot.index().to_le_bytes());
        out[OFF_GENERATION..OFF_GENERATION + 4].copy_from_slice(&self.generation.to_le_bytes());
        out[OFF_BODY_LEN..OFF_BODY_LEN + 2].copy_from_slice(&body_len.to_le_bytes());
        let crc = crc32(&out[..OFF_CRC]);
        out[OFF_CRC..OFF_CRC + 4].copy_from_slice(&crc.to_le_bytes());
    }

    /// Parse the header at the front of `raw`, returning it with the sealed
    /// body length.
    ///
    /// `None` for every disagreement, in the order of cheapest and most
    /// decisive check first: magic (a wrong magic makes every later field
    /// meaningless), domain (an unknown domain is a different format), flags,
    /// body-length bound, CRC. The CRC is last because it is the only check
    /// that needs all twelve preceding bytes to mean something.
    ///
    /// This is the single header parser in the tree. [`decode`],
    /// [`RecordOccupancy`] and any future caller all come through here, so
    /// "occupied" cannot mean two different things in the same allocator
    /// (`slotmap.rs:157-159`).
    fn parse(raw: &[u8]) -> Option<(Self, usize)> {
        if raw.len() < RECORD_HEADER_LEN {
            return None;
        }
        let magic = u16::from_le_bytes(raw[OFF_MAGIC..OFF_MAGIC + 2].try_into().ok()?);
        if magic != RECORD_MAGIC_V1 {
            return None;
        }
        let domain = Domain::from_u8(raw[OFF_DOMAIN])?;
        let flags = raw[OFF_FLAGS];
        // Both directions, for the reasons on FLAG_SEALED: an unflagged record
        // is an unfinished write, an over-flagged one is a format this build
        // does not know.
        if flags & FLAG_SEALED == 0 || flags & !FLAG_SEALED != 0 {
            return None;
        }
        let body_len =
            u16::from_le_bytes(raw[OFF_BODY_LEN..OFF_BODY_LEN + 2].try_into().ok()?);
        // Bound the length before anything slices by it: a header claiming
        // 0xFFFF body bytes must not index past the slot.
        if body_len as usize > MAX_BODY_BYTES {
            return None;
        }
        let stored = u32::from_le_bytes(raw[OFF_CRC..OFF_CRC + 4].try_into().ok()?);
        if crc32(&raw[..OFF_CRC]) != stored {
            return None;
        }
        Some((
            RecordHeader {
                domain,
                // A slot index the region cannot hold is refused here rather
                // than carried: Slot::new already bounds it (mod.rs:272-278),
                // so this only fires on a corrupt-but-CRC-valid header, which
                // is exactly the case that must not become a `Slot` a caller
                // can use.
                slot: Slot::new(u16::from_le_bytes(raw[OFF_SLOT..OFF_SLOT + 2].try_into().ok()?))?,
                generation: u32::from_le_bytes(
                    raw[OFF_GENERATION..OFF_GENERATION + 4].try_into().ok()?,
                ),
                flags,
            },
            body_len as usize,
        ))
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything the codec refuses to do.
///
/// Note what is **not** here: there is no "corrupt record" variant. Corrupt
/// data is [`super::SlotRead::Absent`], never an `Err` —
/// see the module docs and `mod.rs:373-379`. An `Err` from this codec means a
/// caller offered something that cannot be written, which is a bug to fix at
/// the call site; it never means "these bytes are not trustworthy", which is a
/// fact to absorb.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordError {
    /// The body does not fit the slot; [`MAX_BODY_BYTES`] is the ceiling.
    ///
    /// Refused rather than truncated, because the caller cannot tell a
    /// truncated credential from a short one — it is gone, and nothing reports
    /// it. For [`seal`] this is the *sealed* length, so the AEAD overhead is
    /// counted against the same bound.
    BodyTooLarge {
        /// The length offered.
        len: usize,
        /// The bound it exceeded: [`MAX_BODY_BYTES`].
        max: usize,
    },
    /// The output buffer is smaller than one whole slot.
    ///
    /// A slot image is always [`SLOT_BYTES`], padding included, so that the
    /// commit path programs whole flash pages.
    BufferTooSmall {
        /// Bytes the codec needs.
        need: usize,
        /// Bytes it was given.
        have: usize,
    },
    /// The AEAD refused the operation.
    ///
    /// Unreachable for a buffer already bounded by [`MAX_BODY_BYTES`] — GCM's
    /// length ceiling is not in play, and `crypto`'s seal/open cores return
    /// `Option` only for buffer bounds (`crypto.rs:520-528`, `:552-556`). It is
    /// named rather than panicked so a device build cannot abort inside a
    /// credential write to defend against a condition its own bounds exclude.
    Aead,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::BodyTooLarge { len, max } => {
                write!(f, "record body of {len} bytes exceeds the slot's {max}-byte body bound")
            }
            RecordError::BufferTooSmall { need, have } => {
                write!(f, "record output buffer of {have} bytes is smaller than one slot ({need})")
            }
            RecordError::Aead => write!(f, "the AEAD refused the record"),
        }
    }
}

// ---------------------------------------------------------------------------
// Buffers
// ---------------------------------------------------------------------------

/// A plaintext buffer that zeroes itself when it goes out of scope.
///
/// # Why this type exists
///
/// GCM decrypts before it verifies, so by the time a tag is checked the buffer
/// already holds unauthenticated — and for a credential private key,
/// attacker-chosen — plaintext. So the guarantee is made by the buffer *type*,
/// not by a call site: this one clears itself on drop and on every failure path
/// of [`open_into`], which is what stops "no partial plaintext escapes" from
/// being a property of one function remembering to zeroize.
///
/// Mirrors the `ZeroWindow` discipline `secure_store.rs` already applies to its
/// image walks (`platform/src/secure_store.rs:110-118`), for the same reason:
/// bytes of key material must not outlive their use in freed memory.
pub struct Plaintext(Vec<u8>);

impl Plaintext {
    /// A zero-filled scratch buffer of `len` bytes for [`open_into`] to write
    /// into.
    ///
    /// Zeroed rather than uninitialised on purpose: a scratch buffer that
    /// starts at zero makes "no plaintext escaped" a checkable state rather
    /// than an accident of whatever was on the heap.
    pub fn scratch(len: usize) -> Self {
        Plaintext(alloc::vec![0u8; len])
    }

    /// The plaintext. Meaningful only after a `Some` from [`open_into`], or a
    /// [`super::SlotRead::Present`] from [`open`].
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Plaintext length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the buffer holds no plaintext.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

// Zeroizing goes through `<[u8] as Zeroize>` by `Deref`, which is available in
// this crate's configuration. It is deliberately *not* `Zeroizing<Vec<u8>>`:
// the crate declares zeroize with `default-features = false`
// (`platform/Cargo.toml`), which turns off the `alloc` feature that carries
// `impl Zeroize for Vec`, so a heap buffer must be zeroed through its slice.

impl Drop for Plaintext {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Plaintext {
    /// Never prints the bytes — the same rule as [`Sealed`]'s own `Debug`
    /// (`mod.rs:349-355`): a `Debug` that dumps plaintext puts a credential
    /// key in a log buffer.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plaintext({} bytes)", self.0.len())
    }
}

/// A whole encoded slot image: header, sealed body, and `0xFF` padding to
/// [`SLOT_BYTES`].
///
/// Exactly one slot, never a partial one: the commit path erases a sector and
/// programs whole slots (`mod.rs:119-132`), and an image that stopped at the
/// body's end would leave the programmer guessing how much of the slot it owns.
pub struct RecordImage {
    bytes: Vec<u8>,
    len: usize,
}

impl RecordImage {
    /// The whole slot image, padding included.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The slot image, for the region's program path.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The meaningful length: header + body, i.e. where the padding begins.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the meaningful length is zero. Never true for an encoded
    /// record — a zero-length body is still a 16-byte header — but the pair
    /// keeps the `len`/`is_empty` convention the crate's other buffers use.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for RecordImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordImage({} of {} bytes)", self.len, self.bytes.len())
    }
}

/// A record that survived [`decode`]: its header, its sealed body, and where
/// the padding began.
///
/// The body is a [`Sealed`], not a `Vec<u8>`, so the type system keeps saying
/// what `Sealed`'s own docs say (`mod.rs:296-315`): the only way to obtain one
/// is to have encrypted and authenticated the bytes. Decoding is not that step
/// — [`open`] is — so a `DecodedRecord` carries ciphertext by construction, and
/// nothing downstream of `decode` can mistake it for a credential.
pub struct DecodedRecord {
    header: RecordHeader,
    body: Sealed,
    len: usize,
}

impl DecodedRecord {
    /// The recovered header.
    pub fn header(&self) -> &RecordHeader {
        &self.header
    }

    /// The recovered sealed body.
    pub fn body(&self) -> &Sealed {
        &self.body
    }

    /// Take the sealed body, for handing to [`open`].
    pub fn into_body(self) -> Sealed {
        self.body
    }

    /// Header + body length; where this record's padding begins.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the meaningful length is zero; see [`RecordImage::is_empty`].
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for DecodedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecodedRecord({:?}, {} bytes sealed)", self.header, self.body.len())
    }
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Encode `header` + `body` into a whole [`SLOT_BYTES`] slot image.
///
/// Refuses a body over [`MAX_BODY_BYTES`] ([`RecordError::BodyTooLarge`]) and
/// fills the tail with [`ERASED_BYTE`] — see the module docs on why 0xFF.
pub fn encode(header: &RecordHeader, body: &Sealed) -> Result<RecordImage, RecordError> {
    let mut bytes = alloc::vec![ERASED_BYTE; SLOT_BYTES];
    let len = encode_into(header, body.as_bytes(), &mut bytes)?;
    Ok(RecordImage { bytes, len })
}

/// Encode into a caller-provided slot buffer; returns header + body length.
///
/// The allocation-free form, for a caller that already holds a slot-sized
/// window (the device program path). `out` must be at least [`SLOT_BYTES`]:
/// the erased-value padding is part of the image, so a shorter buffer would
/// have to be padded with something that is not erased flash.
///
/// Refuses a body over [`MAX_BODY_BYTES`] rather than truncating it.
pub fn encode_into(
    header: &RecordHeader,
    body: &[u8],
    out: &mut [u8],
) -> Result<usize, RecordError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(RecordError::BodyTooLarge { len: body.len(), max: MAX_BODY_BYTES });
    }
    if out.len() < SLOT_BYTES {
        return Err(RecordError::BufferTooSmall { need: SLOT_BYTES, have: out.len() });
    }
    let end = RECORD_HEADER_LEN + body.len();
    let mut header_bytes = [0u8; RECORD_HEADER_LEN];
    header.write(body.len() as u16, &mut header_bytes);
    out[..end].fill(ERASED_BYTE);
    out[..RECORD_HEADER_LEN].copy_from_slice(&header_bytes);
    out[RECORD_HEADER_LEN..end].copy_from_slice(body);
    Ok(end)
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Decode one slot's bytes.
///
/// `expected` is the slot the bytes were read from, and the decoded header must
/// name it. That check is here as well as in the AAD: failing it here costs one
/// comparison and reports absence immediately, where relying on the tag means
/// handing a transplanted record to the crypto layer first.
///
/// [`super::SlotRead::Absent`] for an erased slot, a bad
/// magic, an unknown domain, a missing or unknown flag, a body length over
/// [`MAX_BODY_BYTES`], a CRC mismatch, and a slot mismatch.
/// [`super::SlotRead::Fault`] for one case only — a buffer
/// shorter than [`SLOT_BYTES`], which says the transport returned less than it
/// promised and is not a fact about the data.
pub fn decode(expected: Slot, raw: &[u8]) -> SlotRead<DecodedRecord> {
    if raw.len() < SLOT_BYTES {
        return SlotRead::Fault("slot buffer shorter than one slot");
    }
    let Some((header, body_len)) = RecordHeader::parse(raw) else {
        return SlotRead::Absent;
    };
    if header.slot() != expected {
        return SlotRead::Absent;
    }
    let end = RECORD_HEADER_LEN + body_len;
    SlotRead::Present(DecodedRecord {
        header,
        // The bound on the body length was checked inside `parse`, so this
        // slice is inside the slot; the copy is the record's own bytes and
        // nothing else, so the padding never reaches the AEAD.
        body: Sealed::from_sealed_bytes(raw[RECORD_HEADER_LEN..end].to_vec()),
        len: end,
    })
}

// ---------------------------------------------------------------------------
// Per-record AEAD (US-1549)
// ---------------------------------------------------------------------------

/// The AES-256-GCM instance for a record key.
///
/// Mirrors `store_v3::cipher` (`platform/src/store_v3.rs:193-195`): the key is
/// 32 bytes, so `new_from_slice` cannot actually fail, and the `Option` keeps
/// that fact from becoming an unwrap on the device path. The cipher is the
/// house AEAD — the same crate, nonce width and tag width as `store_v3` and
/// `snapshot_crypt` — which is why there is one of these and not two.
fn cipher(key: &[u8; 32]) -> Option<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).ok()
}

/// Seal one record's body into `[nonce ‖ ciphertext ‖ tag]`, in a [`Sealed`].
///
/// The key and the **nonce are both supplied**. The nonce in particular is
/// never derived here: under GCM a `(key, nonce)` pair used on two different
/// plaintexts is catastrophic and unrecoverable, and a module that holds no key
/// has no business choosing one. `crypto::record_nonce` is the answer — the
/// mirror-image `SHA-256(key ‖ SHA-256(aad ‖ pt))[..12]` the tree already uses
/// for images and snapshot fields (`store_v3.rs:143-152`,
/// `snapshot_crypt.rs:229-244`) — and this function refuses nothing about the
/// nonce it is handed, because it cannot tell a fresh one from a replayed one.
///
/// The AAD is [`RecordHeader::aad`] and nothing else, so there is no path that
/// seals a record under an AAD that does not describe it.
///
/// Refuses a plaintext whose *sealed* length exceeds [`MAX_BODY_BYTES`], so a
/// body is never produced for a slot that could not hold it.
pub fn seal(
    header: &RecordHeader,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Sealed, RecordError> {
    let sealed_len = plaintext
        .len()
        .checked_add(SEALED_OVERHEAD)
        .ok_or(RecordError::BodyTooLarge { len: usize::MAX, max: MAX_BODY_BYTES })?;
    if sealed_len > MAX_BODY_BYTES {
        return Err(RecordError::BodyTooLarge { len: sealed_len, max: MAX_BODY_BYTES });
    }
    let mut buf = alloc::vec![0u8; sealed_len];
    buf[..NONCE_LEN].copy_from_slice(nonce);
    let body = &mut buf[NONCE_LEN..NONCE_LEN + plaintext.len()];
    body.copy_from_slice(plaintext);
    let tag = cipher(key)
        .ok_or(RecordError::Aead)?
        .encrypt_in_place_detached((&nonce[..]).into(), &header.aad(), body)
        .map_err(|_| RecordError::Aead)?;
    buf[NONCE_LEN + plaintext.len()..].copy_from_slice(tag.as_slice());
    Ok(Sealed::from_sealed_bytes(buf))
}

/// Open a sealed body into `out`, zeroizing `out` if the tag does not verify.
///
/// This is the fail-closed core of US-1549. Every failure path — too short, too
/// long, wrong length for the buffer, bad tag — leaves `out` all zeroes,
/// because by the time the tag is checked GCM has already written
/// unauthenticated plaintext into the buffer. Returns the plaintext length on
/// success.
pub fn open_into(
    header: &RecordHeader,
    key: &[u8; 32],
    sealed: &Sealed,
    out: &mut Plaintext,
) -> Option<usize> {
    let blob = sealed.as_bytes();
    let buf = out.as_mut_slice();
    // `checked_sub` is the length bound: a blob shorter than the AEAD framing
    // has no plaintext in it at all.
    let pt_len = blob.len().checked_sub(SEALED_OVERHEAD)?;
    // Bounds checked before any copy, so no length out of the blob is ever
    // allowed to index the caller's buffer.
    if pt_len > MAX_BODY_BYTES || buf.len() < pt_len {
        buf.zeroize();
        return None;
    }
    let Ok(nonce) = <[u8; NONCE_LEN]>::try_from(&blob[..NONCE_LEN]) else {
        buf.zeroize();
        return None;
    };
    let Ok(tag) = <[u8; TAG_LEN]>::try_from(&blob[blob.len() - TAG_LEN..]) else {
        buf.zeroize();
        return None;
    };
    buf[..pt_len].copy_from_slice(&blob[NONCE_LEN..NONCE_LEN + pt_len]);
    // Past the plaintext: zeroed rather than left holding whatever the previous
    // occupant of this scratch buffer put there, so a shorter record cannot
    // leave the tail of a longer one readable.
    buf[pt_len..].zeroize();
    let aad = header.aad();
    let opened = cipher(key)
        .and_then(|c| {
            c.decrypt_in_place_detached(
                (&nonce).into(),
                &aad,
                &mut buf[..pt_len],
                (&tag).into(),
            )
            .ok()
        })
        .is_some();
    if !opened {
        // The line that makes a failed unseal fail *closed* rather than merely
        // fail: by now the buffer holds whatever GCM wrote there before the tag
        // said no, and nobody downstream is entitled to it.
        buf.zeroize();
        return None;
    }
    Some(pt_len)
}

/// Open a sealed body into a fresh [`Plaintext`].
///
/// [`super::SlotRead::Absent`] on any failure — bad tag, wrong
/// key, a blob that is not a well-formed sealed body, or a record presented
/// with a slot / generation / domain its AAD does not name. Absent rather than
/// `Fault`, because a failed tag is a fact about the bytes.
pub fn open(header: &RecordHeader, key: &[u8; 32], sealed: &Sealed) -> SlotRead<Plaintext> {
    let mut scratch = Plaintext::scratch(sealed.len().saturating_sub(SEALED_OVERHEAD));
    match open_into(header, key, sealed, &mut scratch) {
        Some(len) => {
            scratch.truncate(len);
            SlotRead::Present(scratch)
        }
        None => SlotRead::Absent,
    }
}

/// The whole read path: decode one slot and open it, in one call.
///
/// This is the entry point the region (US-1541/1543) should use, because the
/// fail-closed composition *is* the security property and it should not be
/// reassembled at each call site: an erased slot, a corrupt header, a corrupt
/// body, and a body sealed for a different slot all arrive as the same
/// [`super::SlotRead::Absent`]. That is what lets one bad
/// record fail closed for itself alone instead of taking the store with it.
pub fn read(expected: Slot, raw: &[u8], key: &[u8; 32]) -> SlotRead<Plaintext> {
    match decode(expected, raw) {
        SlotRead::Present(record) => open(record.header(), key, record.body()),
        SlotRead::Absent => SlotRead::Absent,
        SlotRead::Fault(why) => SlotRead::Fault(why),
    }
}

// ---------------------------------------------------------------------------
// Occupancy: the codec's own rule for the allocator (US-1543)
// ---------------------------------------------------------------------------

/// The [`Occupancy`] rule for slots written by this codec.
///
/// [`super::slotmap::ErasedProbe`] is the conservative default: anything not pristine
/// `0xFF` is occupied, and it reports no generations, so per-slot monotonicity
/// lasts only as long as the allocator's own lifetime
/// (`slotmap.rs:190-215`). This rule is the one `slotmap::Occupancy`'s docs
/// ask the codec for: it reads occupancy and the generation out of the record
/// header itself, which is what lifts monotonicity across a power cycle
/// (`slotmap.rs:157-159`).
///
/// It answers "not occupied" for a CRC-failed slot, which is the requirement
/// the allocator states first (`slotmap.rs:161-165`): a torn record must not
/// leak a slot per interrupted commit, and on a region whose sector erase
/// rewrites four slots at a time that would be four slots per interruption.
///
/// Occupancy is read from the header alone, without the expected-slot check
/// [`decode`] applies — [`Occupancy::occupied`] has no slot argument to check
/// against (`slotmap.rs:171-180`). The AAD closes that gap on the read path:
/// a record whose header names a slot it does not sit in cannot be opened
/// there, so the worst a header-only rule can do is call a transplanted record
/// occupied, which leaks a slot and never leaks a credential.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordOccupancy;

impl Occupancy for RecordOccupancy {
    fn occupied(&self, raw: &SlotImage) -> bool {
        RecordHeader::parse(raw).is_some()
    }

    fn generation(&self, raw: &SlotImage) -> Option<u32> {
        RecordHeader::parse(raw).map(|(header, _)| header.generation())
    }
}

// ---------------------------------------------------------------------------
// Host-only observation point (mirrors `crypto.rs`'s)
// ---------------------------------------------------------------------------

/// Host-only hooks the device build does not have.
///
/// `Sealed`'s only constructor is `pub(crate)`
/// (`mod.rs:326`), which is the point of the type — an applet in `apps/`
/// cannot mint one — but it also means an integration test cannot build a
/// *malformed* sealed body, which is exactly what US-1549's "a failed unseal
/// leaves no partial plaintext" case has to hand to the unsealer. This is the
/// same shape `crypto::testing` uses for the same class of problem
/// ("asserting that a key really is cleared when it goes out of scope",
/// `crypto.rs:576-600`): host-only, narrow, and carrying no production
/// capability.
///
/// The device build has none of this, which is the point — the only way to
/// obtain a `Sealed` there is to have sealed one.
#[cfg(not(target_arch = "arm"))]
pub mod testing {
    use super::{Sealed, Vec};

    /// A [`Sealed`] from arbitrary bytes — **including bytes no AEAD produced**.
    ///
    /// For tests that need a body which is well-framed but wrong. It cannot
    /// make a body authenticate: the tag is still checked.
    pub fn sealed_from_bytes(bytes: Vec<u8>) -> Sealed {
        Sealed::from_sealed_bytes(bytes)
    }
}

// ---------------------------------------------------------------------------
// Compile-time assertions
// ---------------------------------------------------------------------------

const _: () = {
    // The header and the body tile one slot exactly: a header that did not fit
    // would either overflow the stride or leave a gap the AEAD's length does
    // not describe.
    assert!(
        RECORD_HEADER_LEN + MAX_BODY_BYTES == SLOT_BYTES,
        "the header and the body must tile one slot exactly"
    );
    // Every field in the layout table must land inside the header, in order,
    // and the CRC must close it. The offsets are the contract between encode
    // and decode, so they are checked rather than trusted.
    assert!(OFF_MAGIC == 0, "the magic opens the header");
    assert!(OFF_DOMAIN == OFF_MAGIC + 2, "the domain follows the 2-byte magic");
    assert!(OFF_FLAGS == OFF_DOMAIN + 1, "the flags follow the domain");
    assert!(OFF_SLOT == OFF_FLAGS + 1, "the slot index follows the flags");
    assert!(OFF_GENERATION == OFF_SLOT + 2, "the generation follows the slot index");
    assert!(OFF_BODY_LEN == OFF_GENERATION + 4, "the body length follows the 4-byte generation");
    assert!(OFF_CRC == OFF_BODY_LEN + 2, "the CRC follows the body length");
    assert!(OFF_CRC + 4 == RECORD_HEADER_LEN, "the CRC must close the header");
    // The largest record each domain can produce must fit the body bound. This
    // is the same relationship `mod.rs:172-180` asserts from the other side; it
    // is repeated here because this codec is what would truncate, and the codec
    // should not have to trust that whoever sized the region read it.
    assert!(
        MAX_BODY_BYTES as u32 >= FIDO_RECORD_MAX,
        "the FIDO slot cannot hold the largest FIDO record — raise SLOT_MARGIN_BYTES or lower the \
         measured record. Do not let a record be truncated to fit"
    );
    assert!(
        MAX_BODY_BYTES as u32 >= OATH_RECORD_MAX,
        "the FIDO slot cannot hold the largest OATH record"
    );
    assert!(
        OATH_SLOT_BYTES as usize <= SLOT_BYTES,
        "the OATH sub-slot must divide into the region slot, or the two grids could not share one \
         region"
    );
    // The AAD length is the layout, not a number anyone may tune: crypto.rs
    // hashes it into every nonce and stores nothing about it, so a length that
    // drifts here silently invalidates every record already written.
    assert!(
        AAD_BYTES == crate::keyregion::crypto::AAD_LEN,
        "AAD_BYTES must BE crypto::AAD_LEN, not a restatement of it — two lengths is the \
         defect this module used to have"
    );
    assert!(SEALED_OVERHEAD == NONCE_LEN + TAG_LEN, "sealing overhead is nonce + tag");
};
