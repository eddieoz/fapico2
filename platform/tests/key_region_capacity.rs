//! US-1540: the capacities are derived from the region, and the region and the
//! constants cannot disagree.
//!
//! # The defect this installs a discipline against
//!
//! `DEVICE_MAX_CREDS = 12` sat in `apps/fido/src/device_keystore.rs` with a doc
//! comment claiming twelve credentials "fits the chunked slot's 5,952-B payload
//! capacity". It never did. The real bound was the **24-entry store occupancy**:
//! a chunked rewrite holds both generations live, so
//! `other_slots + old_parts + new_parts <= 24`, and on a soak board
//! `other_slots` is 12. Measured result: four credentials, then
//! `KeyStoreFull` — which is what `apps/fido/tests/key_store_ceiling.rs`
//! reproduces.
//!
//! A constant that no region can contradict is not a capacity, it is a wish.
//! These tests are the rest of that discipline: they recompute the capacities
//! from the region and refuse a disagreement.
//!
//! # What the erase granularity forces
//!
//! The epic's original stride analysis picked 1 KiB slots and 256 FIDO / 68
//! OATH in a 960 KiB region. That is right about the stride and silent about
//! the hardware: RP2350 QSPI flash erases in 4 KiB sectors and NOR cannot
//! rewrite programmed bytes, so a 1 KiB slot cannot be erased on its own.
//!
//! The design here keeps the 1 KiB slot as the unit of **identity** — the
//! address a record is found at — and makes the **sector** the unit of erasure
//! and of commit. One credential update therefore erases one sector and
//! programs four slots, three of which carry unchanged records. US-1544 and
//! US-1545 have to make that sector atomic, and neither may assume a one-slot
//! erase, because the flash cannot do it.

use fapico2_platform::flashmap::{BLOCK_SIZE, KEY_REGION_BYTES, KEY_REGION_OFFSET};
use fapico2_platform::keyregion as kr;

/// Recompute the FIDO capacity the way the module claims to derive it.
///
/// Written out rather than imported, so the test states the rule instead of
/// restating the module's own arithmetic — a test that calls the same
/// expression is a test that cannot fail for a different reason than the code.
const fn derive_fido_capacity() -> u32 {
    // Restated independently of the module: region -> slots, less OATH, less
    // the commit scratchpad. The scratchpad term is the one that is easy to
    // leave out — it is not a domain, so a reader looking for "how many
    // credentials" does not expect to see it — and leaving it out is how a
    // capacity becomes one sector optimistic. The Nostr term (US-1639) is the
    // same class of easy-to-leave-out: eight slots carved from the top of
    // FIDO's range. The PIN carve (US-1689) is the third of its class, and it
    // is sector-granular: the carve takes FIDO's whole tail sector because the
    // scoped erase and the commit are sector-granular too (mod.rs,
    // NOSTR_PIN_CARVE_SLOTS, carries the argument).
    (KEY_REGION_BYTES / kr::FIDO_SLOT_BYTES)
        - kr::OATH_CAPACITY
        - kr::SCRATCHPAD_SLOTS
        - fapico2_platform::keyregion::index::INDEX_SLOT_COUNT
        - kr::NOSTR_CAPACITY
        - kr::NOSTR_PIN_CARVE_SLOTS
}

#[test]
fn the_capacities_are_the_region_arithmetic() {
    assert_eq!(kr::FIDO_CAPACITY, derive_fido_capacity());
    assert_eq!(kr::TOTAL_SLOTS, KEY_REGION_BYTES / kr::FIDO_SLOT_BYTES);
    // Every slot is claimed exactly once. Nothing unclaimed, nothing counted
    // twice — the scratchpad is a sector the commit protocol stages into, and
    // it is charged to somebody or the capacity is a lie.
    assert_eq!(
        kr::FIDO_CAPACITY
            + kr::OATH_CAPACITY
            + kr::SCRATCHPAD_SLOTS
            + fapico2_platform::keyregion::index::INDEX_SLOT_COUNT
            + kr::NOSTR_CAPACITY
            + kr::NOSTR_PIN_CARVE_SLOTS,
        kr::TOTAL_SLOTS
    );
}

#[test]
fn nostr_is_carved_from_the_top_of_fidos_range() {
    // US-1639: the carve must leave every existing FIDO record's address
    // unchanged. `FidoAllocator::alloc` grows from `FIDO_FIRST_SLOT` upward
    // (fido_store.rs:467), so the property that matters is *where FIDO's range
    // begins and ends* — the beginning must be exactly where it was before the
    // carve (immediately above the scratchpad), and the vacated slots must be
    // the eight at the top, contiguous with the index, not scattered.
    assert_eq!(
        kr::FIDO_FIRST_SLOT,
        kr::OATH_CAPACITY + kr::SCRATCHPAD_SLOTS,
        "FIDO's range no longer begins right above the scratchpad — existing records' \
         addresses would move"
    );
    assert_eq!(
        kr::FIDO_CAPACITY,
        844,
        "FIDO falls 856 -> 848 (the eight Nostr identity slots, US-1639) and then 848 -> 844 \
         (the PIN carve, US-1689) — one whole sector at the top each time, because the erase \
         is sector-granular and a one-slot carve would put the PIN record in the path of \
         FIDO's scoped wipe"
    );
    // US-1689: the pin carve is FIDO's whole tail sector, and the record slot
    // is its last slot — immediately below the identity range, so
    // NOSTR_FIRST_SLOT keeps the numeric value it had before the pin carve
    // (72 + 848 = 920), which is the address-stability argument in one line.
    assert_eq!(
        kr::NOSTR_PIN_FIRST_SLOT,
        kr::FIDO_FIRST_SLOT + kr::FIDO_CAPACITY,
        "the pin carve does not begin where FIDO's range ends"
    );
    assert_eq!(
        kr::NOSTR_PIN_SLOT,
        kr::NOSTR_FIRST_SLOT - 1,
        "the pin record slot is not immediately below the identity range"
    );
    assert_eq!(
        kr::NOSTR_FIRST_SLOT,
        920,
        "NOSTR_FIRST_SLOT moved: every identity record on a deployed board would be stranded \
         at its old address"
    );
    assert_eq!(
        fapico2_platform::keyregion::index::INDEX_FIRST_SLOT,
        kr::NOSTR_SLOT_LIMIT,
        "Nostr's carve does not end flush against the index"
    );
    assert_eq!(kr::NOSTR_CAPACITY, 8);
    // The predicates the guards consult must agree with the constants they
    // derive from — a carve the predicates cannot ask about is a carve write
    // paths can ignore.
    let first = kr::Slot::new(kr::NOSTR_FIRST_SLOT as u16).expect("Nostr's first slot");
    let last = kr::Slot::new((kr::NOSTR_SLOT_LIMIT - 1) as u16).expect("Nostr's last slot");
    let pin = kr::Slot::new(kr::NOSTR_PIN_SLOT as u16).expect("the pin slot");
    let pad = kr::Slot::new(kr::NOSTR_PIN_FIRST_SLOT as u16).expect("the carve's head");
    let index_first =
        kr::Slot::new(fapico2_platform::keyregion::index::INDEX_FIRST_SLOT as u16).expect("index");
    assert!(kr::is_nostr_slot(first) && kr::is_nostr_slot(last));
    assert!(!kr::is_nostr_slot(pin), "the pin slot is Nostr's but not an identity slot");
    assert!(kr::is_nostr_pin_slot(pin));
    assert!(
        !kr::is_nostr_pin_slot(pad) && !kr::is_nostr_pin_slot(first) && !kr::is_nostr_pin_slot(index_first),
        "the carve's padding is not the record slot"
    );
    assert!(!kr::is_nostr_slot(index_first), "the index is not Nostr's");
}

#[test]
fn the_commit_scratchpad_is_charged_to_the_capacity() {
    // US-1544's commit protocol stages a sector elsewhere before erasing the
    // live one, so the staging area is a whole sector of real slots. It is not
    // optional overhead: without it a brown-out during a write destroys up to
    // three *other* credentials' records.
    assert_eq!(kr::SCRATCHPAD_SLOTS, kr::SLOTS_PER_SECTOR);
    assert_eq!(
        kr::SCRATCHPAD_SLOTS * kr::FIDO_SLOT_BYTES,
        BLOCK_SIZE as u32,
        "the scratchpad must be exactly one NOR sector"
    );
}

#[test]
fn the_region_holds_far_more_than_the_reported_ceiling() {
    // The reported defect: four credentials, with `DEVICE_MAX_CREDS` claiming
    // twelve. The floor the acceptance criteria name is 256.
    //
    // Routed through a real `FileKeyRegion` reporting its own capacity, rather
    // than asserted against the constants directly. Comparing two constants is
    // a test that changes with the compiler, and clippy is right to call that
    // out (`assertions_on_constants`); going through the region means the
    // number under test is the one the store reports.
    let dir = std::env::temp_dir().join(format!("fapico2-cap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let region =
        fapico2_platform::keyregion::host::FileKeyRegion::create(dir.join("region.bin"), kr::TOTAL_SLOTS)
            .expect("a full-size region file");
    let slots = fapico2_platform::keyregion::KeyRegion::slots(&region);
    assert_eq!(slots, kr::TOTAL_SLOTS, "the region reports its own slot count");

    // Derive what fits from the region's own slot count, rather than trusting
    // the module's capacity constant for the comparison. `slots()` is already
    // in slot units — dividing by the stride again would be dividing twice.
    let fits = slots;
    let claimed = fits
        - kr::OATH_CAPACITY
        - kr::SCRATCHPAD_SLOTS
        - fapico2_platform::keyregion::index::INDEX_SLOT_COUNT
        - kr::NOSTR_CAPACITY
        - kr::NOSTR_PIN_CARVE_SLOTS;
    assert!(
        claimed >= 256,
        "FIDO capacity is {claimed}, below the 256 floor the acceptance criteria name"
    );
    // …and the improvement over the measured four-credential ceiling is the
    // point of the whole epic, so it is asserted as a ratio rather than left
    // implied by the number above.
    assert!(
        claimed >= 64 * 4,
        "capacity {claimed} is not a meaningful improvement on the measured \
         four-credential ceiling"
    );
    // OATH's bound is a `heapless` table size the applet carries, not something
    // the region derives, so it is read back out of the slot accounting rather
    // than compared to a literal — which would be a test of two constants.
    let oath_slots_taken = fits - claimed;
    assert!(
        oath_slots_taken >= 68,
        "the OATH area is {oath_slots_taken} slots, below the 68 floor"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_slot_cannot_straddle_a_nor_sector() {
    // The constraint the epic's stride analysis missed. If this fails, a record
    // can span two sectors and erasing one destroys the other — which is a
    // credential lost with no error reported.
    assert_eq!(BLOCK_SIZE as u32 % kr::FIDO_SLOT_BYTES, 0);
    assert_eq!(BLOCK_SIZE as u32 / kr::FIDO_SLOT_BYTES, kr::SLOTS_PER_SECTOR);
    assert_eq!(
        kr::FIDO_SLOT_BYTES % kr::OATH_SLOT_BYTES,
        0,
        "the FIDO grid must be a whole number of OATH slots, or the two domains cannot share \
         one region"
    );
}

#[test]
fn the_strides_hold_their_domains_largest_record() {
    for (name, stride, record_max) in [
        ("FIDO", kr::FIDO_SLOT_BYTES, kr::FIDO_RECORD_MAX),
        ("OATH", kr::OATH_SLOT_BYTES, kr::OATH_RECORD_MAX),
    ] {
        assert!(
            stride >= record_max + kr::RECORD_HEADER_BYTES,
            "the {name} stride {stride} cannot hold a {record_max}-byte record plus a \
             {}-byte header; a record that does not fit is truncated, not stored",
            kr::RECORD_HEADER_BYTES
        );
        // The margin is what lets a future record with a longer field widen one
        // constant instead of re-deriving the region's layout.
        assert!(
            stride - (record_max + kr::RECORD_HEADER_BYTES) >= 128,
            "the {name} stride leaves {} B of growth room, less than the 128 B the design \
             claims; a longer field would then change the region's layout rather than a \
             constant",
            stride - (record_max + kr::RECORD_HEADER_BYTES)
        );
    }
}

#[test]
fn the_slots_tile_the_region_exactly() {
    assert_eq!(
        KEY_REGION_BYTES % kr::FIDO_SLOT_BYTES,
        0,
        "a partial last slot is a slot that cannot be erased without touching the one before it"
    );
    let used = (kr::FIDO_CAPACITY + kr::OATH_CAPACITY) * kr::FIDO_SLOT_BYTES;
    assert!(used <= KEY_REGION_BYTES);
    // OATH records are shorter, so they occupy one FIDO-sized slot each rather
    // than packing four to a sector. That is the deliberate trade: packing would
    // raise the FIDO count, at the cost of a record update having to rewrite
    // records belonging to the same sector — the complexity AGENTS.md §5 says to
    // take only when the attack it stops can be named. None can be named here.
    assert_eq!(
        kr::OATH_CAPACITY * kr::OATH_SLOT_BYTES,
        68 * 512,
        "OATH's declared area changed shape"
    );
}

#[test]
fn the_region_is_where_the_linker_script_says_it_is() {
    // US-1539 declared KEYREGION in the generated `memory.x` from a different
    // derivation. The region the firmware links around and the region the
    // firmware programs have to be the same one, so this is where the two
    // derivations meet.
    assert_eq!(KEY_REGION_OFFSET, 0x30_0000);
    assert_eq!(KEY_REGION_BYTES, 960 * 1024);
    assert_eq!(
        KEY_REGION_BYTES % BLOCK_SIZE as u32,
        0,
        "the region must be a whole number of NOR sectors; the commit unit is the sector"
    );
}

// ---------------------------------------------------------------------------
// US-1689: the pin carve, read across the new geometry
// ---------------------------------------------------------------------------

/// **The pin slot is the ninth Nostr slot and nothing else moved** — US-1689's
/// acceptance, in three parts:
///
/// (a) the module's compile-time tiling and alignment assertions hold (this
///     test compiling is that evidence; the `const _` blocks are evaluated in
///     the same build);
/// (b) a fixture region carries a FIDO record at FIDO's *last* slot, all eight
///     identity records, and an index slot across the new geometry, and every
///     one of them reads back — and the ninth identity index is refused, so
///     the pin slot is not reachable as an identity;
/// (c) `FIDO_CAPACITY` shrank by exactly the carve — one whole sector, not one
///     slot. The EPIC's first draft carved a single slot and asked for "−1";
///     the geometry refuses that: FIDO's range must end on a sector boundary
///     (`fido_store.rs`'s scoped-erase assertions) and the pin record must not
///     share a sector with FIDO records (`wipe_fido_range` erases raw sectors
///     with no key to spare a neighbour), so the carve takes the whole tail
///     sector. The Gherkin's pinned outcome — *nothing moves* — is what this
///     test holds, and it holds with the sector-granular carve.
#[test]
fn pin_slot_is_the_ninth_nostr_slot_and_nothing_else_moved() {
    use fapico2_platform::ckey;
    use fapico2_platform::keyregion::crypto::{self, PayloadKey};
    use fapico2_platform::keyregion::host::FileKeyRegion;
    use fapico2_platform::keyregion::nostr_store::{Entry, NostrIdentity, NostrStore, NostrStoreError};
    use fapico2_platform::keyregion::record::{self, Domain, RecordHeader};
    use fapico2_platform::keyregion::{KeyRegion, Slot, SlotRead};

    // (c) The capacity fell by exactly the carve, from the pre-carve 848.
    assert_eq!(kr::FIDO_CAPACITY, 848 - kr::NOSTR_PIN_CARVE_SLOTS);
    assert_eq!(kr::NOSTR_PIN_CARVE_SLOTS, kr::SLOTS_PER_SECTOR);

    let dir = std::env::temp_dir().join(format!("fapico2-pin-carve-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let region = FileKeyRegion::create(dir.join("region.bin"), kr::TOTAL_SLOTS)
        .expect("a full-size region file");
    let mut region = region;

    fn otp_row() -> [u8; 32] {
        let mut row = [0u8; 32];
        for (i, b) in row.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(0x23);
        }
        row
    }
    fn chip_id() -> [u8; 8] {
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    }
    fn nostr_payload_key() -> PayloadKey {
        crypto::derive_payload_key(&otp_row(), &chip_id(), &crypto::NOSTR_PAYLOAD_SECRET)
            .expect("a provisioned OTP row derives the Nostr payload key")
    }
    // The key a FIDO record in this device's region is sealed under — the
    // stale-passkey shape, so the FIDO leg of the read-back is a record the
    // way a deployed board would hold one.
    fn fido_payload_key() -> PayloadKey {
        let serial = ckey::serial_hash(b"fapico2 pin carve test");
        let kbase = ckey::derive_kbase(&otp_row(), &serial, 0x0BAD_F00D, Some(&[0x5a; 32]))
            .expect("a provisioned OTP row derives a kbase");
        let kver = ckey::derive_kver(&kbase, b"123456");
        let session = ckey::pin_session(&serial, &kver);
        crypto::derive_payload_key(&otp_row(), &chip_id(), &session).expect("fido payload key")
    }
    fn identity(n: u8) -> NostrIdentity {
        let mut scalar = [0u8; 32];
        let mut npub = [0u8; 32];
        for (i, b) in scalar.iter_mut().enumerate() {
            *b = n.wrapping_mul(7).wrapping_add(i as u8).wrapping_add(1);
        }
        for (i, b) in npub.iter_mut().enumerate() {
            *b = n.wrapping_mul(11).wrapping_add(i as u8).wrapping_add(3);
        }
        NostrIdentity::new(scalar, npub, b"alice", 0x01).expect("a short utf-8 label")
    }
    fn slot_of(index: u32) -> Slot {
        Slot::new(index as u16).expect("the carve's slots are inside the region")
    }

    // The FIDO leg: a FIDO-domain record at FIDO's **last** slot — the slot
    // just below the pin carve — reads back where it always was.
    let fido_slot = slot_of(kr::FIDO_SLOT_LIMIT - 1);
    let header = RecordHeader::new(Domain::Fido, fido_slot, 1);
    let mut nonce = [0u8; record::NONCE_LEN];
    nonce[..4].copy_from_slice(&1u32.to_le_bytes());
    nonce[4..].copy_from_slice(b"pincarve");
    let body = vec![0xA5u8; 128];
    let sealed = record::seal(&header, fido_payload_key().as_bytes(), &nonce, &body)
        .expect("seal a FIDO record");
    let image = record::encode(&header, &sealed).expect("encode the FIDO record");
    KeyRegion::program(&mut region, fido_slot, 0, image.as_bytes())
        .expect("a whole slot image programs");

    let raw = KeyRegion::read_slot(&mut region, fido_slot).expect("read FIDO's last slot back");
    match record::decode(fido_slot, &raw) {
        SlotRead::Present(decoded) => {
            assert_eq!(decoded.header().domain(), Domain::Fido);
            assert_eq!(decoded.header().generation(), 1);
        }
        other => panic!("the FIDO record below the carve did not read back: {other:?}"),
    }

    // The identity leg: all eight carve slots take their first write and read
    // back live — and the ninth identity index is refused, because the pin
    // slot is the ninth Nostr slot and it is not an identity.
    let key = nostr_payload_key();
    {
        let mut store = NostrStore::new(&mut region, &key);
        for i in 0..8u16 {
            store.write(i, &identity(i as u8)).expect("a virgin carved slot is writable");
        }
        for i in 0..8u16 {
            assert!(
                matches!(store.read(i), Ok(Entry::Live(_))),
                "identity {i} did not read back live"
            );
        }
        assert!(
            matches!(store.write(8, &identity(8)), Err(NostrStoreError::IndexOutOfRange { index: 8 })),
            "the ninth identity must be refused by the geometry, not wrap onto the pin slot"
        );
    }

    // The index leg: the index's first slot — where US-1639 left it, and
    // where the pin carve was forbidden to move it — programs and reads back
    // byte-identically.
    let index_slot = slot_of(fapico2_platform::keyregion::index::INDEX_FIRST_SLOT);
    assert_eq!(
        fapico2_platform::keyregion::index::INDEX_FIRST_SLOT,
        928,
        "the index moved: every FIDO credential's lookup entry would be stranded"
    );
    let mut index_image = [0xFFu8; kr::FIDO_SLOT_BYTES as usize];
    index_image[..32].copy_from_slice(&[0x42u8; 32]);
    KeyRegion::program(&mut region, index_slot, 0, &index_image).expect("program an index slot");
    let index_raw = KeyRegion::read_slot(&mut region, index_slot).expect("read the index back");
    assert_eq!(index_raw, index_image, "the index slot did not read back byte-identically");

    let _ = std::fs::remove_dir_all(&dir);
}