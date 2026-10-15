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
    nostr_pin_slot, nostr_slot, Entry, NostrIdentity, NostrPinRecord, NostrStore, NostrStoreError,
    PinEntry, TOMBSTONE, NOSTR_BODY_LEN, NOSTR_PIN_BODY_LEN,
};
use fapico2_platform::keyregion::record::{self, Domain, RecordHeader};
use fapico2_platform::keyregion::{
    KeyRegion, Slot, NOSTR_FIRST_SLOT, NOSTR_PIN_SLOT, NOSTR_RECORD_MAX, TOTAL_SLOTS,
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

/// F-A5 (docs/nostr-presence-audit.md): a slot our own tag marks but whose
/// body will not open is deletable. The occupancy guard protects *live*
/// records; a record that cannot open is by definition not one — refusing
/// the remedy stranded the slot behind 6A84 forever. force_tombstone
/// commits at the standing header's next generation and leaves the slot
/// reusable by the writers.
#[test]
fn an_undecodable_slot_is_force_tombstoned_and_reusable() {
    let tmp = TempRegion::new("force-tombstone");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let stale = slot_of(0);
    let other_chip = [0x99u8; 8];
    let other_key =
        crypto::derive_payload_key(&otp_row(), &other_chip, &crypto::NOSTR_PAYLOAD_SECRET)
            .expect("the other board's Nostr key");
    program_record(&mut region, stale, &foreign_record(Domain::Nostr, &other_key, stale, 1));

    let key = nostr_payload_key();
    let mut store = NostrStore::new(&mut region, &key);
    assert!(matches!(store.read(0), Ok(Entry::Undecodable)));
    store.force_tombstone(0).expect("the corrupt occupant is force-tombstoned");
    assert!(
        matches!(store.read(0), Ok(Entry::Tombstone)),
        "the slot reads as a tombstone, not a fault"
    );
    store.write(0, &identity(6)).expect("the slot is reusable by the writers");
}

/// F-A5's safety rail: force_tombstone is not a guard bypass for *live*
/// records — a slot that opens as ours must go through `delete` (which
/// names what it destroyed, D12); force refuses it and leaves it standing.
#[test]
fn force_tombstone_refuses_a_live_record() {
    let tmp = TempRegion::new("force-live");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let key = nostr_payload_key();
    let mut store = NostrStore::new(&mut region, &key);
    store.write(0, &identity(3)).expect("write a live identity");
    let err = store
        .force_tombstone(0)
        .expect_err("a live record is delete's business, not a force's");
    assert!(matches!(err, NostrStoreError::LiveRecord { .. }), "got {err:?}");
    assert!(matches!(store.read(0), Ok(Entry::Live(_))), "the live record is untouched");
}

/// F-A7 (docs/nostr-presence-audit.md): "occupied but names another slot"
/// is a typed refusal, not a reboot. A valid-CRC header programmed into
/// the wrong slot decodes Absent at the reading slot; admission must
/// answer OccupiedForeign like any other foreign occupant — the arm used
/// to be `unreachable!`, and panic = abort = reboot mid-ceremony.
#[test]
fn a_misaddressed_record_is_a_typed_refusal_not_a_panic() {
    let tmp = TempRegion::new("misaddressed");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let placed_at = slot_of(0);
    let named = slot_of(5);
    let key = nostr_payload_key();
    // A well-formed Nostr record for slot 5, sealed under our own key,
    // programmed into slot 0: the header's CRC is valid, so the slot reads
    // occupied, but the codec refuses it at slot 0 (the header names 5).
    let image = foreign_record(Domain::Nostr, &key, named, 1);
    program_record(&mut region, placed_at, &image);
    let mut store = NostrStore::new(&mut region, &key);
    let err = store
        .write(0, &identity(7))
        .expect_err("a misaddressed occupant is refused, typed");
    assert!(matches!(err, NostrStoreError::OccupiedForeign { .. }), "got {err:?}");
}

// ---------------------------------------------------------------------------
// US-1690: the PIN custody record
// ---------------------------------------------------------------------------

/// A PIN record with deterministic salt and verifier — the fields' *values*
/// are the applet's business (the OATH `PinRecord` derivation); the store's
/// is that the same 49 bytes come back out.
fn pin_record(counter: u8) -> NostrPinRecord {
    let mut salt = [0u8; 16];
    let mut verifier = [0u8; 32];
    for (i, b) in salt.iter_mut().enumerate() {
        *b = counter.wrapping_mul(5).wrapping_add(i as u8).wrapping_add(0x40);
    }
    for (i, b) in verifier.iter_mut().enumerate() {
        *b = counter.wrapping_mul(17).wrapping_add(i as u8).wrapping_add(0x80);
    }
    NostrPinRecord { counter, salt, verifier }
}

/// The raw slot bytes of a record with an arbitrary body, sealed under `key`
/// at `slot` — the PIN-slot edition of [`foreign_record`], which is bound to
/// the identity body's width.
fn pin_slot_record(key: &PayloadKey, slot: Slot, generation: u32, body: &[u8]) -> Vec<u8> {
    let header = RecordHeader::new(Domain::Nostr, slot, generation);
    let mut nonce = [0u8; record::NONCE_LEN];
    nonce[..4].copy_from_slice(&generation.to_le_bytes());
    nonce[4..].copy_from_slice(b"nostrst!");
    let sealed = record::seal(&header, key.as_bytes(), &nonce, body).expect("seal");
    let image = record::encode(&header, &sealed).expect("a 49-byte body fits the slot");
    image.as_bytes().to_vec()
}

/// **The round trip preserves all 49 bytes, and a rewrite goes through the
/// guard.** US-1690's green path: the virgin PIN slot is the no-PIN state,
/// `write_pin` commits through the same admission/seal machinery an identity
/// uses, and the record reads back field-for-field — the verifier included,
/// because a codec that mangles it cannot be caught by a shape check.
#[test]
fn pin_record_round_trip_and_admission() {
    let tmp = TempRegion::new("pin-record");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let key = nostr_payload_key();
    let mut store = NostrStore::new(&mut region, &key);

    assert!(
        matches!(store.read_pin(), Ok(PinEntry::Empty)),
        "the virgin PIN slot reads as the no-PIN state"
    );
    store.write_pin(&pin_record(0)).expect("the virgin PIN slot is writable");
    match store.read_pin() {
        Ok(PinEntry::Live(read)) => {
            assert_eq!(read, pin_record(0), "the round trip preserves all 49 bytes");
        }
        other => panic!("expected a live PIN record, got {other:?}"),
    }

    // Rewriting the live slot is the guard's own path (it opens as ours), so
    // a rotation commits at the advanced generation — US-1692's change-PIN
    // write stands on this.
    store.write_pin(&pin_record(1)).expect("a live PIN slot is rewritable");
    match store.read_pin() {
        Ok(PinEntry::Live(read)) => assert_eq!(read, pin_record(1)),
        other => panic!("expected the rotated record, got {other:?}"),
    }
}

/// **The PIN slot is typed apart from the identity range.** US-1690's
/// reachability clause: `nostr_slot` cannot name the PIN slot (it sits below
/// [`NOSTR_FIRST_SLOT`]) and `nostr_pin_slot` takes no index — the two
/// accessor families are disjoint by construction, so an identity read never
/// decodes the PIN record and a PIN write never lands in an identity slot.
#[test]
fn the_pin_slot_is_typed_apart_from_the_identity_range() {
    let pin = nostr_pin_slot().expect("the carve's geometry names the PIN slot");
    assert_eq!(pin.index() as u32, NOSTR_PIN_SLOT);
    assert!(
        pin.index() < NOSTR_FIRST_SLOT as u16,
        "the PIN slot must sit below the identity range, or nostr_slot reaches it"
    );
    for i in 0..fapico2_platform::keyregion::NOSTR_CAPACITY as u16 {
        assert_ne!(
            nostr_slot(i),
            Some(pin),
            "identity index {i} must not alias the PIN slot"
        );
    }
}

/// **A foreign or torn PIN record is refused or reads Undecodable — never a
/// wrong verifier.** US-1690's admission and torn-body clauses, both halves
/// of "fail closed": a stale FIDO record in the PIN slot is
/// `OccupiedForeign`, never a silent overwrite; a record that opens as ours
/// but does not decode to a PIN body reads `Undecodable` (US-1695's
/// fail-closed state); and a record with one flipped ciphertext byte fails
/// the AEAD, so no verifier can be synthesized from damaged bytes.
#[test]
fn a_foreign_or_torn_pin_record_refuses_and_never_yields_a_verifier() {
    let tmp = TempRegion::new("pin-torn");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let key = nostr_payload_key();
    let pin = nostr_pin_slot().expect("the carve's geometry names the PIN slot");

    // Half 1: the stale FIDO occupant. The occupancy guard refuses the
    // write; the read reports Foreign, not a PIN.
    let stale = foreign_record(Domain::Fido, &fido_payload_key(), pin, 1);
    program_record(&mut region, pin, &stale);
    {
        let mut store = NostrStore::new(&mut region, &key);
        assert!(matches!(store.read_pin(), Ok(PinEntry::Foreign)));
        let err = store
            .write_pin(&pin_record(0))
            .expect_err("a foreign occupant is refused, never overwritten");
        assert!(matches!(err, NostrStoreError::OccupiedForeign { .. }), "got {err:?}");
    }

    // Half 2: a body that opens as ours but is not a PIN body — a record
    // sealed under this device's own key with a 50-byte body. The AEAD is
    // satisfied; the codec is not. It reads Undecodable, never a verifier.
    // The slot is erased first — NOR cannot program over live bytes — and
    // erasing the pin slot's sector can spare nothing: the pad slots
    // (US-1689) are never written, which is part of the carve's point.
    region.erase_sector(pin).expect("the pad slot's sector erases cleanly");
    let torn_wide = pin_slot_record(&key, pin, 2, &[0x7F; 50]);
    program_record(&mut region, pin, &torn_wide);
    {
        let mut store = NostrStore::new(&mut region, &key);
        assert!(
            matches!(store.read_pin(), Ok(PinEntry::Undecodable)),
            "a wrong-width body is Undecodable, not a PIN"
        );
    }

    // Half 3: a valid PIN body with one flipped byte inside the sealed
    // region — the first ciphertext byte after the nonce (the image's tail
    // is erased padding, not part of the record). The AEAD refuses the
    // open; nothing decodes.
    let mut good = [0u8; NOSTR_PIN_BODY_LEN];
    pin_record(3).encode(&mut good);
    let mut image = pin_slot_record(&key, pin, 3, &good);
    let first_ciphertext =
        record::RECORD_HEADER_LEN + record::NONCE_LEN;
    image[first_ciphertext] ^= 0x01;
    region.erase_sector(pin).expect("erase before the flipped-byte program");
    program_record(&mut region, pin, &image);
    {
        let mut store = NostrStore::new(&mut region, &key);
        assert!(
            matches!(store.read_pin(), Ok(PinEntry::Undecodable)),
            "a flipped ciphertext byte must fail closed, never decode to a verifier"
        );
    }
}
