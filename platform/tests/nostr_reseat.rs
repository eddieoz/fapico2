//! US-1713's acceptance tests: the reseat migration, the completion marker,
//! and the G1 assertion.
//!
//! The region fixtures build deployed-board state for real — records sealed
//! through the store's own codec under the legacy constant-KDF key, the way
//! every board flashed before the ceremony carries them — never synthetic
//! blobs.

use std::path::{Path, PathBuf};

use fapico2_platform::ckey;
use fapico2_platform::keyregion::crypto::{self, NostrKeySource, PayloadKey};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::nostr_store::{
    nostr_slot, Entry, NostrIdentity, NostrPinRecord, NostrStore, NostrStoreError, PinEntry,
    RESEAT_MARKER, reseat_marker_slot,
};
use fapico2_platform::keyregion::record::{self, Domain, RecordHeader};
use fapico2_platform::keyregion::{KeyRegion, Slot, NOSTR_FIRST_SLOT, NOSTR_RECORD_MAX, TOTAL_SLOTS};

/// The whole region: a short stand-in would move what the carve's slots are.
const REGION_SLOTS: u32 = TOTAL_SLOTS;

/// The custody secret as the OTP rows would read it back —
/// [`crate::custody::custody_secret_bytes`]'s output shape.
const CUSTODY_BYTES: [u8; 16] = *b"custody-row-read";

struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("fapico2-nostr-reseat-{}-{tag}.bin", std::process::id()));
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

/// The pre-custody key: the constant-KDF derivation every v0.2.0 board's
/// records carry.
fn legacy_key() -> PayloadKey {
    crypto::derive_nostr_payload_key(&otp_row(), &chip_id(), NostrKeySource::LegacyConstant)
        .expect("a provisioned OTP row derives the legacy key")
}

/// The post-ceremony key: the custody rows over the same root.
fn custody_key() -> PayloadKey {
    crypto::derive_nostr_payload_key(&otp_row(), &chip_id(), NostrKeySource::Custody(&CUSTODY_BYTES))
        .expect("a provisioned OTP row derives the custody key")
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

fn pin_record(counter: u8) -> NostrPinRecord {
    let mut salt = [0u8; 16];
    for (i, b) in salt.iter_mut().enumerate() {
        *b = counter.wrapping_mul(5).wrapping_add(i as u8);
    }
    NostrPinRecord {
        counter,
        salt,
        verifier: [0x42; 32],
    }
}

/// A stale FIDO record, programmed whole the way a deployed board would
/// carry one into the carved range.
fn fido_record(slot: Slot, generation: u32) -> Vec<u8> {
    let serial = ckey::serial_hash(b"fapico2 nostr reseat test");
    let kbase = ckey::derive_kbase(&otp_row(), &serial, 0x0BAD_F00D, Some(&[0x5a; 32]))
        .expect("a provisioned OTP row derives a kbase");
    let kver = ckey::derive_kver(&kbase, b"123456");
    let session = ckey::pin_session(&serial, &kver);
    let key = crypto::derive_payload_key(&otp_row(), &chip_id(), &session).expect("fido key");
    let body = vec![0xA5u8; 128];
    let header = RecordHeader::new(Domain::Fido, slot, generation);
    let mut nonce = [0u8; record::NONCE_LEN];
    nonce[..4].copy_from_slice(&generation.to_le_bytes());
    nonce[4..].copy_from_slice(b"nostrst!");
    let sealed = record::seal(&header, key.as_bytes(), &nonce, &body).expect("seal");
    let image = record::encode(&header, &sealed).expect("fits the slot");
    image.as_bytes().to_vec()
}

fn slot_of(index: u16) -> Slot {
    nostr_slot(index).expect("inside the carve")
}

fn program_record(region: &mut FileKeyRegion, slot: Slot, image: &[u8]) {
    region.program(slot, 0, image).expect("programs whole");
}

/// A v0.2.0 board's Nostr domain: two identities, a tombstone, and the PIN
/// record, all sealed under the legacy key.
fn seed_legacy_board(region: &mut FileKeyRegion) {
    let key = legacy_key();
    let mut store = NostrStore::new(region, &key);
    store.write(0, &identity(1)).expect("write idx0");
    store.write(1, &identity(2)).expect("write idx1");
    store.delete(2).expect("tombstone idx2");
    store.write_pin(&pin_record(0)).expect("write pin");
}

/// The interrupted board: identities 0 and 1 still legacy-sealed, the PIN
/// record still legacy-sealed — the walk never reached them — and identity
/// 2 already migrated as a custody-sealed tombstone: a power cut left the
/// walk halfway, and no marker stands. The custody-key delete runs on a
/// slot that is *virgin* in the legacy image — the guard refuses to
/// overwrite a legacy record with anything but the reseat, which is the
/// point of US-1713.
fn seed_interrupted_board(region: &mut FileKeyRegion) {
    {
        let key = legacy_key();
        let mut store = NostrStore::new(region, &key);
        store.write(0, &identity(1)).expect("write idx0");
        store.write(1, &identity(2)).expect("write idx1");
        store.write_pin(&pin_record(0)).expect("write pin");
    }
    let key = custody_key();
    let mut store = NostrStore::new(region, &key);
    store.delete(2).expect("the migrated tombstone, on a virgin slot");
}

#[test]
fn reseat_through_the_guard() {
    let tmp = TempRegion::new("guard");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    seed_legacy_board(&mut region);

    // The walk refuses to cross the guard's own refusal: a slot occupied by
    // a record that opens under neither key is not ours to overwrite, and
    // the migration stops fail-closed with no marker.
    program_record(&mut region, slot_of(7), &fido_record(slot_of(7), 1));
    {
        let key = custody_key();
        let mut store = NostrStore::new(&mut region, &key);
        let err = store.reseat(&legacy_key()).expect_err("foreign occupant refuses");
    // The walk stops fail-closed **where it stood**: identities 0–2 migrated
    // before the husk, the PIN record — last in the walk — did not, and no
    // marker stands. Resumable by design, not half-broken.
    assert_eq!(err, NostrStoreError::OccupiedForeign { slot: slot_of(7) });
    assert!(!store.reseat_complete().expect("marker readable"), "no marker");
    }

    // The repair path is the standing one (F-A5): a record that will not
    // open is force-tombstoned, named, and then the walk can proceed.
    {
        let key = custody_key();
        let mut store = NostrStore::new(&mut region, &key);
        store.force_tombstone(7).expect("the husk is named and buried");
    }

    // Re-entering the walk finishes it: identities 0–2 and the buried husk
    // open under the custody key and are skipped, and the PIN record — the
    // only slot the aborted walk never reached — migrates.
    let report = {
        let key = custody_key();
        let mut store = NostrStore::new(&mut region, &key);
        store.reseat(&legacy_key()).expect("the walk completes")
    };
    assert_eq!(report.migrated, 1, "the PIN record, last in the walk");
    assert_eq!(report.already, 4, "idx0, idx1, idx2's tombstone, the husk's");
    {
        let key = custody_key();
        let mut store = NostrStore::new(&mut region, &key);
        assert!(matches!(store.read(0), Ok(Entry::Live(_))));
        assert!(matches!(store.read(1), Ok(Entry::Live(_))));
        assert!(matches!(store.read(2), Ok(Entry::Tombstone)));
        assert!(matches!(store.read_pin(), Ok(PinEntry::Live(_))));
        assert!(store.reseat_complete().expect("marker readable"));
    }
}

#[test]
fn marker_after_full_reseat_only() {
    let tmp = TempRegion::new("marker");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    seed_legacy_board(&mut region);

    // Before the walk: no marker.
    let key = custody_key();
    let legacy = legacy_key();
    let mut store = NostrStore::new(&mut region, &key);
    assert!(!store.reseat_complete().expect("marker readable"));

    // The marker opens only under the custody key: a legacy-key store
    // cannot read it as complete — before or after the walk.
    {
        let mut legacy_store = NostrStore::new(&mut region, &legacy);
        assert!(!legacy_store.reseat_complete().expect("marker slot readable"));
    }

    let mut store = NostrStore::new(&mut region, &key);
    let report = store.reseat(&legacy).expect("the walk completes");
    assert_eq!(report.migrated, 4);
    assert!(store.reseat_complete().expect("marker readable"));

    // And the marker record is sealed under the custody key, body-for-body
    // the marker magic — a record like any other, at the marker slot.
    let slot = reseat_marker_slot();
    let raw = region.read_slot(slot).expect("marker slot readable");
    let decoded = match record::decode(slot, &raw) {
        fapico2_platform::keyregion::SlotRead::Present(d) => d,
        other => panic!("the marker decodes: {other:?}"),
    };
    assert_eq!(decoded.header().domain(), Domain::Nostr);
    match record::open(decoded.header(), custody_key().as_bytes(), decoded.body()) {
        fapico2_platform::keyregion::SlotRead::Present(pt) => {
            assert_eq!(pt.as_slice(), RESEAT_MARKER);
        }
        _ => panic!("the marker must open under the custody key"),
    }
}

#[test]
fn no_record_opens_under_legacy_after_marker() {
    // The load-bearing wall: after the marker, no record in the Nostr
    // domain — identities, the PIN record, the tombstone — opens under the
    // legacy KDF. Otherwise a v0.2.0 possessor re-derives the legacy key
    // offline, opens the PIN verifier, brute-forces the PIN, and re-enters
    // through the front door.
    let tmp = TempRegion::new("g1");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    seed_legacy_board(&mut region);
    let legacy = legacy_key();
    {
        let key = custody_key();
        let mut store = NostrStore::new(&mut region, &key);
        store.reseat(&legacy).expect("the walk completes");
    }

    // The exhaustive half: walk every Nostr-domain slot and try the legacy
    // key against the raw record. Nothing opens.
    for index in 0..8u16 {
        let slot = slot_of(index);
        let raw = region.read_slot(slot).expect("slot readable");
        if let Some(decoded) = decoded_or_empty(&raw, slot) {
            assert!(
                !matches!(
                    record::open(decoded.header(), legacy.as_bytes(), decoded.body()),
                    fapico2_platform::keyregion::SlotRead::Present(_)
                ),
                "slot {index} still opens under the legacy key"
            );
        }
    }
    // The store-level shape: a legacy-key store finds Undecodable records
    // where custody-sealed ones live — never Live — and reads no PIN.
    let mut legacy_store = NostrStore::new(&mut region, &legacy);
    let mut seen_live = false;
    for index in 0..8u16 {
        if matches!(legacy_store.read(index).expect("read"), Entry::Live(_)) {
            seen_live = true;
        }
    }
    assert!(!seen_live, "a record opened live under the legacy key after the marker");
    assert!(matches!(
        legacy_store.read_pin().expect("pin readable"),
        PinEntry::Undecodable | PinEntry::Empty
    ));
}

#[test]
fn interrupted_reseat_is_idempotent() {
    let tmp = TempRegion::new("interrupted");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    seed_interrupted_board(&mut region);

    // The interrupted state, read through the dual-KDF window: identity 0
    // is still legacy-sealed and reads live anyway — the window exists for
    // exactly this state and nothing else.
    {
        let key = custody_key();
        let legacy = legacy_key();
        let mut windowed = NostrStore::new_with_window(&mut region, &key, &legacy);
        assert!(matches!(windowed.read(0), Ok(Entry::Live(_))));
        assert!(matches!(windowed.read(1), Ok(Entry::Live(_))));
        assert!(matches!(windowed.read(2), Ok(Entry::Tombstone)));
        assert!(matches!(windowed.read_pin(), Ok(PinEntry::Live(_))));
        // ...and without the window, the not-yet-migrated slots do not
        // pretend to be readable.
        let mut custody_only = NostrStore::new(&mut region, &key);
        assert!(matches!(custody_only.read(0), Ok(Entry::Undecodable)));
        assert!(!custody_only.reseat_complete().expect("no marker"));
    }

    // Re-entering the walk finishes it: the migrated slot is skipped and
    // never rewritten, the legacy-sealed ones migrate, and the marker lands.
    let report = {
        let key = custody_key();
        let mut store = NostrStore::new(&mut region, &key);
        store.reseat(&legacy_key()).expect("the walk resumes and completes")
    };
    assert_eq!(report.migrated, 3, "idx0, idx1, the PIN record");
    assert_eq!(report.already, 1, "the migrated tombstone");
    assert!(matches!(
        { let key = custody_key(); let mut s = NostrStore::new(&mut region, &key); s.read(0).expect("read") },
        Entry::Live(_)
    ));

    // A third entry is a full no-op: the marker stands, the walk is short-
    // circuited by it.
    let noop = {
        let key = custody_key();
        let mut store = NostrStore::new(&mut region, &key);
        store.reseat(&legacy_key()).expect("idempotent")
    };
    assert_eq!(noop.migrated, 0);
    assert_eq!(noop.already, 0);
}

/// Decode-or-absent: a slot whose bytes do not parse returns `None` rather
/// than panicking — the walk's own tolerance, mirrored in the G1 sweep.
fn decoded_or_empty(
    raw: &[u8],
    slot: Slot,
) -> Option<fapico2_platform::keyregion::record::DecodedRecord> {
    match record::decode(slot, raw) {
        fapico2_platform::keyregion::SlotRead::Present(d) => Some(d),
        _ => None,
    }
}

/// The pin carve's marker slot is unreachable from the identity accessors —
/// the typed-apartness the carve built, holding for the marker too.
#[test]
fn the_marker_slot_is_outside_the_identity_range() {
    for index in 0..8u16 {
        let slot = nostr_slot(index).expect("inside the carve");
        assert_ne!(slot.index(), reseat_marker_slot().index());
    }
    assert!(NOSTR_RECORD_MAX as usize == 97 + 28); // the bound the codec pins elsewhere
    let _ = NOSTR_FIRST_SLOT; // named for readability of the geometry above
}
