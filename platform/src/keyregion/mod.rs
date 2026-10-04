//! The per-record key store (US-1539, US-1540).
//!
//! This is where FIDO and OATH credentials move to, out of the 24-entry
//! [`crate::secure_store`] they currently co-tenant. Finding 1 of
//! `FIDO-SECURE-STORE` is the arithmetic in [`geometry`]: 24 entries split
//! between two applets is four credentials each, and `DEVICE_MAX_CREDS = 12`
//! was never reachable at any credential size because it was asserted rather
//! than derived.
//!
//! # The shape
//!
//! The region is a flat grid of fixed-size **slots**. A slot holds one record:
//! a header with a CRC over it, and a sealed body. A credential write erases
//! one slot and programs one slot — which is the property the old whole-snapshot
//! design could not have, because it rewrote everything on every change.
//!
//! # Why the stride is per-domain, not one round number
//!
//! A maximal FIDO credential seals to 836 B, so a 512 B slot is impossible and
//! a 1 KiB slot leaves ~170 B of margin. A maximal OATH credential seals to
//! ~210 B, which fits a 256 B slot with room to spare. One stride for both
//! would either make FIDO impossible or waste five sixths of every OATH slot,
//! so each domain's stride is derived from **its own** measured maximum record.
//!
//! # Why no slot is reserved
//!
//! An earlier revision of the epic proposed leaving ~500 KB spare. With
//! per-record commits there is nothing to spend it on: the old design needed
//! spare capacity because a chunked rewrite held both generations live at the
//! peak, and that is exactly the cost this design removes. Reserving capacity
//! against no named failure is capacity a user could have had, so the regions
//! are filled. The acceptance criteria's "≥500 KB spare" is therefore not met,
//! deliberately — the capacities below exceed the required floor by 3.7× and
//! the spare is visible as address space on a larger part, which is the honest
//! form of growth.
//!
//! # What this module does not do
//!
//! It defines geometry and the capacities derived from it. The record codec
//! (US-1542), the allocator (US-1543) and the commit discipline (US-1544/1545)
//! are separate stories, and none of them can change a capacity here without
//! the compile-time assertions below stopping the build.

use crate::flashmap::{BLOCK_SIZE, KEY_REGION_BYTES};

// ---------------------------------------------------------------------------
// Record sizes (measured, not estimated)
// ---------------------------------------------------------------------------

/// The largest sealed FIDO record, in bytes, measured on the host against
/// `device_core.rs`'s makeCredential path with the longest fields CTAP 2.1
/// permits.
///
/// The fields that set it: a 63-byte RP ID, a 58-byte `user.name`, a 43-byte
/// `displayName`, a 64-byte `user.id`, a 32-byte `credBlob`, plus
/// `largeBlobKey` and the auth map's own floor. `apps/fido/tests/
/// key_store_ceiling.rs` measures the unpacked snapshot at 611 B per credential
/// on a 105-B floor; the sealed record adds the AEAD framing and this store's
/// header on top of that.
///
/// The number is a **floor on the design, not a claim about the codec**: it is
/// what the stride has to accommodate, and a stride derived from a smaller
/// number than the hardware can produce is how `DEVICE_MAX_CREDS = 12`
/// happened.
pub const FIDO_RECORD_MAX: u32 = 836;

/// The largest sealed OATH record, in bytes: a credential's identity, secret
/// and properties, sealed.
pub const OATH_RECORD_MAX: u32 = 210;

/// Header bytes per record: a magic, the domain, the slot, the generation, the
/// flags, the body length, and a CRC32 over all of it (US-1542).
///
/// 16 bytes is the same width `secure_store.rs`'s part header already uses for
/// the same job, so the two stores' framing costs can be compared directly.
pub const RECORD_HEADER_BYTES: u32 = 16;

/// Bytes of slack kept free inside every slot.
///
/// Not padding: it is the room a record has to grow into without the stride
/// being re-derived, which is what makes a future credential with a longer
/// field a widening of one constant rather than a change to the region's
/// layout.
const SLOT_MARGIN_BYTES: u32 = 128;

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/// Slot stride for one domain: the largest record that domain can produce,
/// plus its header and a margin, rounded **up** to a power of two.
///
/// Rounding up to a power of two is what makes the slot address arithmetic a
/// shift rather than a multiply, and it leaves the stride a whole number of
/// flash pages (256 B) on every path.
const fn stride_for(record_max: u32) -> u32 {
    let needed = record_max + RECORD_HEADER_BYTES + SLOT_MARGIN_BYTES;
    let mut s = 256u32;
    while s < needed {
        s *= 2;
    }
    s
}

/// FIDO slot stride: 1 KiB — 836 + 16 + 128 = 980 B rounds up to 1,024.
pub const FIDO_SLOT_BYTES: u32 = stride_for(FIDO_RECORD_MAX);

/// OATH slot stride: 512 B — 210 + 16 + 128 = 354 B rounds up to 512.
///
/// **512, not 256.** A 256 B slot would hold a 210 B record with 46 B of
/// growth room, which is less than the 128 B margin claims to provide — so
/// rounding to 256 would have quietly made the margin a fiction. Stating the
/// arithmetic here rather than in a comment is what stops the two numbers from
/// drifting apart.
pub const OATH_SLOT_BYTES: u32 = stride_for(OATH_RECORD_MAX);

/// Slots per NOR sector at the FIDO stride.
///
/// **This is the constraint the epic's stride analysis missed.** RP2350 QSPI
/// flash erases in 4 KiB sectors and NOR cannot rewrite programmed bytes, so a
/// 1 KiB slot cannot be erased on its own: updating one credential would clear
/// the three slots sharing its sector. The slot therefore stays at 1 KiB — it
/// is the unit of *identity*, the address a record is found at — while the
/// **sector is the unit of erasure and of commit**.
///
/// So a credential update erases one sector and programs four slots, three of
/// which carry unchanged records, and the commit marker goes last within the
/// sector. US-1544 and US-1545 make that sector atomic; nothing in those
/// stories may assume a one-slot erase, because the hardware cannot do it.
pub const SLOTS_PER_SECTOR: u32 = BLOCK_SIZE as u32 / FIDO_SLOT_BYTES;

/// Total slots the region holds at the FIDO stride.
pub const TOTAL_SLOTS: u32 = KEY_REGION_BYTES / FIDO_SLOT_BYTES;

// ---------------------------------------------------------------------------
// Capacities — derived, never asserted
// ---------------------------------------------------------------------------

/// Resident FIDO credentials the region holds.
///
/// Derived: the region, less OATH's slots, divided by FIDO's stride. The old
/// `DEVICE_MAX_CREDS = 12` was a number in a file that no region could
/// contradict; this one is a function of the region and the measured record
/// size, so raising the region or lowering the record raises it, and lowering
/// the region lowers it.
pub const FIDO_CAPACITY: u32 = TOTAL_SLOTS - OATH_CAPACITY;

/// Resident OATH credentials the region holds.
///
/// `oath_core.rs` already carries `MAX_CREDS = 68` as a `heapless` **table**
/// bound — it sizes the in-RAM array and nothing else, and its own comment
/// says so. It is the number here too, because it is the number the applet can
/// actually hold in RAM; a store that accepted more would refuse on a RAM bound
/// it never mentions. What changes under US-1553 is not this number but what
/// it competes for: 68 slots of flash instead of a share of 24.
pub const OATH_CAPACITY: u32 = 68;

// ---------------------------------------------------------------------------
// Compile-time assertions — the discipline US-1540 exists to install
// ---------------------------------------------------------------------------

const _: () = {
    // A stride that cannot hold its own domain's largest record is not a
    // capacity, it is a truncation: the record would be written with its tail
    // silently dropped.
    //
    // Plain messages, no interpolation: `assert!` in a const context cannot
    // format. The values are in the constants' own doc comments, which is why
    // they are repeated there rather than only here.
    assert!(
        FIDO_SLOT_BYTES >= FIDO_RECORD_MAX + RECORD_HEADER_BYTES,
        "the FIDO slot stride cannot hold the largest FIDO record — raise SLOT_MARGIN_BYTES \
         or lower the measured record. Do not let a record be truncated to fit"
    );
    assert!(
        OATH_SLOT_BYTES >= OATH_RECORD_MAX + RECORD_HEADER_BYTES,
        "the OATH slot stride cannot hold the largest OATH record"
    );

    // Strides must be whole flash pages, and the region must divide into whole
    // slots, so the last slot of the region is not partly outside it.
    assert!(
        FIDO_SLOT_BYTES % 256 == 0 && OATH_SLOT_BYTES % 256 == 0,
        "a slot stride must be a whole number of flash pages"
    );
    assert!(
        KEY_REGION_BYTES % FIDO_SLOT_BYTES == 0,
        "the key region does not divide into whole FIDO slots — the region's size is \
         board-derived, so a board whose remainder is non-zero needs a different stride, not \
         a partial last slot"
    );

    // The sector is the erase and commit unit, so a slot must never straddle
    // one: a record whose bytes spanned two sectors could not be erased without
    // destroying a record in the other.
    assert!(
        BLOCK_SIZE as u32 % FIDO_SLOT_BYTES == 0,
        "a FIDO slot must divide a NOR sector exactly, or a record would straddle two of them \
         and erasing one would destroy the other"
    );
    assert!(
        FIDO_SLOT_BYTES % OATH_SLOT_BYTES == 0,
        "the OATH slot must divide the FIDO slot, or the two grids could not share one region"
    );

    // The capacities must be real: positive, and the areas must not overlap.
    assert!(
        FIDO_CAPACITY > 0 && OATH_CAPACITY > 0,
        "a capacity of zero is not a capacity"
    );
    assert!(
        (FIDO_CAPACITY + OATH_CAPACITY) * FIDO_SLOT_BYTES <= KEY_REGION_BYTES,
        "the two domains' slots overrun the key region"
    );
};

/// The key region's size in slots at the FIDO stride — the denominator every
/// capacity above is built from.
pub const fn region_slots() -> u32 {
    TOTAL_SLOTS
}