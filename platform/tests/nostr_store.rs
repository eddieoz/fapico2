//! US-1641: the Nostr identity store's record format and occupancy guard.
//!
//! # The hazard the guard exists for
//!
//! Nostr's eight slots were FIDO's until US-1639 carved them. A board carrying
//! ≥ 849 FIDO credentials has real passkey records sitting in what is now
//! Nostr's range, `FidoAllocator::alloc` will not report `Full` about them
//! (its scan stops at `FIDO_SLOT_LIMIT`), and a Nostr write that overwrote
//! one would destroy a passkey silently. The guard refuses every write whose
//! occupant does not open as a Nostr record under this device's key — and
//! these tests build that occupant for real, through the region's own record
//! codec, not a synthetic blob.
//!
//! # The story's three cases
//!
//! Red first, per the epic: a slot still holding a FIDO record is refused for
//! a Nostr write; a virgin slot is written; a previously-opened Nostr record
//! is reopened. The refusal tests craft their occupants the way a deployed
//! board would have them — sealed records programmed whole into the slot.

use std::path::{Path, PathBuf};

use fapico2_platform::ckey;
use fapico2_platform::keyregion::crypto::{self, PayloadKey};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::nostr_store::{
    NostrIdentity, NostrStore, NostrStoreError, Entry, TOMBSTONE, NOSTR_BODY_LEN,
};
use fapico2_platform::keyregion::record::{self, Domain, RecordHeader};
use fapico2_platform::keyregion::{
    Slot, NOSTR_FIRST_SLOT, NOSTR_RECORD_MAX, TOTAL_SLOTS,
};

/// The whole region: a short stand-in would move what the carve's slots are.
const REGION_SLOTS: u32 = TOTAL_SLOTS;

struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("fapico2-nostr-store-{}-{tag}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRegion {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

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

/// The Nostr payload key: derived with [`crypto::NOSTR_PAYLOAD_SECRET`], the
/// way the applet derives it (US-1638) — no PIN anywhere in the chain.
fn nostr_payload_key() -> PayloadKey {
    crypto::derive_payload_key(&otp_row(), &chip_id(), &crypto::NOSTR_PAYLOAD_SECRET)
        .expect("a provisioned OTP row derives the Nostr payload key")
}

/// A PIN-derived payload key, the way FIDO seals its records — used to craft
/// the stale FIDO occupant the refusal tests need.
fn fido_payload_key() -> PayloadKey {
    let serial = ckey::serial_hash(b"fapico2 nostr store test");
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

/// The raw slot bytes of a record sealed the way its domain would seal it.
fn foreign_record(domain: Domain, key: &PayloadKey, slot: Slot, generation: u32) -> Vec<u8> {
    let body = match domain {
        Domain::Fido => vec![0xA5u8; 128],
        Domain::Nostr => {
            let mut b = [0u8; NOSTR_BODY_LEN];
            identity(0xFF).encode(&mut b);
            b.to_vec()
        }
        Domain::Oath => vec![0x5A; 64],
    };
    let header = RecordHeader::new(domain, slot, generation);
    let mut nonce = [0u8; record::NONCE_LEN];
    nonce[..4].copy_from_slice(&generation.to_le_bytes());
    nonce[4..].copy_from_slice(b"nostrst!");
    let sealed = record::seal(&header, key.as_bytes(), &nonce, &body).expect("seal");
    let image = record::encode(&header, &sealed).expect("a 97-byte body fits the slot");
    image.as_bytes().to_vec()
}

fn slot_of(index: u16) -> Slot {
    Slot::new(NOSTR_FIRST_SLOT as u16 + index).expect("the carve's slots are inside the region")
}

/// Program a whole record into a slot, simulating the stale occupant a
/// deployed board carries after the carve.
fn program_record(region: &mut FileKeyRegion, slot: Slot, image: &[u8]) {
    use fapico2_platform::keyregion::KeyRegion;
    region.program(slot, 0, image).expect("a whole slot image programs at page granularity");
}

// ---------------------------------------------------------------------------
// The story's green path: virgin slot written, written record reopened
// ---------------------------------------------------------------------------

/// **A virgin slot is written** — the guard's first branch. The carve is only
/// a success if the applet can actually use what it carved.
#[test]
fn a_virgin_slot_is_written() {
    let tmp = TempRegion::new("virgin");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let key = nostr_payload_key();
    let mut store = NostrStore::new(&mut region, &key);

    store.write(0, &identity(1)).expect("a virgin carved slot is writable");
    assert!(
        matches!(store.read(0), Ok(Entry::Live(_))),
        "the identity just written must read back live"
    );
}

/// **A previously-opened Nostr record is reopened** — byte-identically, all
/// four fields, and the slot is reusable at the next generation.
#[test]
fn a_written_nostr_record_is_reopened() {
    let tmp = TempRegion::new("reopen");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let key = nostr_payload_key();
    let mut store = NostrStore::new(&mut region, &key);
    let written = identity(2);
    store.write(0, &written).expect("write");

    match store.read(0) {
        Ok(Entry::Live(id)) => {
            assert_eq!(id.scalar, written.scalar, "the scalar did not survive the seal");
            assert_eq!(id.npub, written.npub);
            assert_eq!(id.label(), b"alice");
            assert_eq!(id.flags, written.flags);
        }
        other => panic!("expected a live identity, got {other:?}"),
    }

    // And the label encodes at its zero terminator: a padded field the reader
    // trims correctly is part of the format's contract.
    let long = NostrIdentity::new(written.scalar, written.npub,
        &[b'a'; 32], 0).expect("a 32-byte label");
    store.write(1, &long).expect("write a full-length label");
    match store.read(1) {
        Ok(Entry::Live(id)) => assert_eq!(id.label(), &[b'a'; 32]),
        other => panic!("expected a live identity, got {other:?}"),
    }

    // The sealed bound is what mod.rs sized the carve's slot for.
    assert_eq!(NOSTR_RECORD_MAX as usize, NOSTR_BODY_LEN + 28);
}

/// **The same slot is reusable at the next generation**, and a delete is a
/// tombstone the reader reports as its own fact — not an undecodable record.
#[test]
fn a_delete_is_a_tombstone_and_the_slot_is_reusable() {
    let tmp = TempRegion::new("tombstone");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let key = nostr_payload_key();
    let mut store = NostrStore::new(&mut region, &key);

    store.write(0, &identity(3)).expect("write");
    store.delete(0).expect("delete");
    assert!(matches!(store.read(0), Ok(Entry::Tombstone)));

    // The tombstone body is what the codec refuses as an identity.
    assert!(NostrIdentity::is_tombstone(TOMBSTONE));
    assert!(NostrIdentity::decode(TOMBSTONE).is_none());

    // Reusable: the write over the tombstone is a plain Nostr-over-Nostr
    // reuse, generation 3, and reads back live.
    store.write(0, &identity(4)).expect("write over the tombstone");
    assert!(matches!(store.read(0), Ok(Entry::Live(_))));
}

// ---------------------------------------------------------------------------
// The guard: occupied slots must identify themselves as Nostr records
// ---------------------------------------------------------------------------

/// **A slot still holding a FIDO record is refused for a Nostr write** — the
/// story's red case, and the §2.4.2 hazard the carve created. The occupant
/// here is a *real* FIDO record: sealed under the PIN-derived payload key by
/// the region's own codec, programmed whole into a carved slot, exactly what
/// a board carrying ≥ 849 passkeys has in Nostr's range.
#[test]
fn a_slot_holding_a_fido_record_is_refused_for_a_nostr_write() {
    let tmp = TempRegion::new("fido-occupant");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let stale = slot_of(0);
    program_record(
        &mut region,
        stale,
        &foreign_record(Domain::Fido, &fido_payload_key(), stale, 1),
    );

    let key = nostr_payload_key();
    let mut store = NostrStore::new(&mut region, &key);
    let err = store.write(0, &identity(5)).expect_err(
        "a FIDO occupant must be refused, not overwritten — the carve made this slot Nostr's",
    );
    assert!(matches!(err, NostrStoreError::OccupiedForeign { .. }), "got {err:?}");

    // And the read path reports the fact as its own kind: foreign, not
    // undecodable, not empty. A caller that counted Foreign as Empty would
    // silently hide the stale passkey.
    assert!(matches!(store.read(0), Ok(Entry::Foreign)));
}

/// **The AEAD leg of the guard**: a record carrying Nostr's own domain tag
/// but sealed under a different device's key does not identify as ours. The
/// tag is one header byte a transplanted record can carry; the payload key
/// is the part that cannot be forged.
#[test]
fn a_nostr_tagged_record_from_another_device_is_refused() {
    let tmp = TempRegion::new("foreign-nostr");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let stale = slot_of(0);
    let other_chip = [0x99u8; 8];
    let other_key =
        crypto::derive_payload_key(&otp_row(), &other_chip, &crypto::NOSTR_PAYLOAD_SECRET)
            .expect("the other board's Nostr key");
    program_record(
        &mut region,
        stale,
        &foreign_record(Domain::Nostr, &other_key, stale, 1),
    );

    let key = nostr_payload_key();
    let mut store = NostrStore::new(&mut region, &key);
    let err = store
        .write(0, &identity(6))
        .expect_err("an unopenable occupant must be refused, not overwritten");
    assert!(matches!(err, NostrStoreError::OccupiedForeign { .. }), "got {err:?}");
    assert!(matches!(store.read(0), Ok(Entry::Undecodable)));
}

/// **The guard's order is load-bearing**: a slot that is *virgin* does not
/// open, so asking the open question first would leave the applet unable to
/// write anything. This is the design's correction to its own first draft
/// (`nostr-applet-design.md` §2.4.2), pinned as a positive write into every
/// slot the carve created — all eight.
#[test]
fn every_carved_slot_takes_its_first_write() {
    let tmp = TempRegion::new("all-eight");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let key = nostr_payload_key();
    let mut store = NostrStore::new(&mut region, &key);
    for i in 0..8u16 {
        store.write(i, &identity(i as u8)).expect("a virgin carved slot is writable");
    }
    // …and index 8 is refused, typed: the reservation and the applet's bound
    // are two constants that must refuse, not alias.
    assert!(
        matches!(store.write(8, &identity(8)), Err(NostrStoreError::IndexOutOfRange { index: 8 })),
        "the ninth identity must be refused by the geometry, not wrap onto slot 0"
    );
}
