//! US-1551, requirement **S1**: *a flash dump is structurally checkable
//! offline* — every index entry authenticates under the device-rooted key, no
//! payload is decrypted, and nothing identifying is recoverable from the dump.
//!
//! ```gherkin
//! Scenario: a flash dump is structurally checkable offline
//!   Given the key region written by a device with a PIN set
//!   And the OTP row read from the chip
//!   When the index is verified
//!   Then every entry authenticates under the device-rooted key
//!   And no payload is decrypted
//!   And no credential ID, RP name, user name or key material is recoverable
//! ```
//!
//! # The two claims that need different machinery
//!
//! **"every entry authenticates under the device-rooted key"** is a claim about
//! bytes, so it is asserted on bytes: the region here is written with real
//! index entries, verified with only [`OTP`] and [`CHIPID`], and every counter
//! in [`Verification`] is checked. The PIN matters to the fixture — the
//! credential records in it are sealed under a *payload* key derived from a PIN
//! secret — so "verifies with no PIN" is a statement about a region that really
//! did have one, not about an empty store.
//!
//! **"no payload is decrypted"** cannot be asserted by reading the
//! implementation, so it is asserted by *observation*: [`MemRegion`] is the only
//! [`KeyRegion`] in this file and it **records every slot it is asked to read**.
//! A decryption needs the record's slot; the walk therefore has to touch index
//! slots and nothing else. That is a behavioural property — a future edit that
//! reached for a credential slot to "help" would fail the test rather than pass
//! it — and it is the reason this file does not drive `FileKeyRegion`, whose
//! [`Stats`](fapico2_platform::keyregion::host::Stats) counts operations but not
//! *which* slots.
//!
//! # The harvest contrast, asserted rather than described
//!
//! pico-fido marks a resident credential's `rp_id_hash` and `client_data_hash`
//! `FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC`
//! (`../pico-fido/src/fido/resident_container.c:324-327`, `:330-333`), so one
//! dump enumerates the owner's whole account list. Here the index holds a
//! **truncated MAC**, so the dump holds pseudonyms. That is only worth claiming
//! if the plaintext is genuinely absent from every byte of the medium, which is
//! what `a_dump_yields_no_credential_id_rp_name_user_name_or_key_material`
//! checks — it scans all 960 KiB for the four strings the scenario names.
//!
//! # What the fixtures deliberately put in the credential records
//!
//! Real-looking FIDO fields, in one plaintext blob per record:
//! [`CRED_ID`], [`RP_NAME`], [`USER_NAME`] and [`PRIVATE_KEY`]. They are
//! searched for across the whole dump by name, so the test would still pass if
//! the *index* leaked an RP name in some other encoding only if that encoding
//! happened to contain these bytes — which is why [`PRIVATE_KEY`] is 64
//! distinct bytes rather than a word, and why the assertion is on bytes
//! appearing, not on a length or a `Debug` string.

use std::collections::BTreeSet;

use fapico2_platform::ckey;
use fapico2_platform::keyregion::crypto::{self, IndexKey, KeyDomain, RecordAad};
use fapico2_platform::keyregion::index::{self, IndexEntry, RpIdHash, Verification};
use fapico2_platform::keyregion::record::{self, Domain};
use fapico2_platform::keyregion::slotmap::SlotImage;
use fapico2_platform::keyregion::{
    FIDO_CAPACITY, FIDO_SLOT_BYTES, KeyRegion, OATH_CAPACITY, SCRATCHPAD_SLOTS, Slot, SlotRead,
    SLOTS_PER_SECTOR, TOTAL_SLOTS,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A provisioned-looking OTP key row — not all-zero, because that is the one
/// row `derive_index_key` refuses (`crypto.rs`, "Why a failed derivation
/// returns `None`").
const OTP: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

/// This device's chip id. `an_index_entry_from_another_device` swaps both this
/// and the OTP row.
const CHIPID: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];

/// The other device used by the cross-device case: a different OTP row *and* a
/// different chip id, so both inputs to the root differ.
const OTHER_OTP: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe,
];
const OTHER_CHIPID: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

/// The owner's PIN, and the fact that it is set.
///
/// Every payload-sealed record in this file is sealed under a key derived from
/// this. Nothing in the index path ever sees it, and
/// `an_index_written_with_a_pin_set_is_identical_to_one_written_without_one`
/// proves that by sweeping the whole PIN space and watching the index bytes not
/// move.
const PIN: &[u8] = b"123456";

/// A PIN-derived secret, made the way an applet makes one: through the house
/// PIN chain, which is not this module's business.
///
/// `derive_payload_key` takes 32 already-derived bytes rather than raw PIN
/// characters precisely so it does not have to choose between FIDO's verifier
/// and OATH's (`ckey.rs`); building the fixture through the real chain keeps
/// the test honest about that.
fn pin_secret(pin: &[u8]) -> [u8; 32] {
    let serial = ckey::serial_hash(b"fapico2 keyregion index test flash uid");
    let kbase = ckey::derive_kbase(&OTP, &serial, 0x0BAD_F00D, Some(&[0x5a; 32]))
        .expect("a provisioned OTP row derives a kbase");
    let kver = ckey::derive_kver(&kbase, pin);
    ckey::pin_session(&serial, &kver)
}

fn payload_key() -> crypto::PayloadKey {
    crypto::derive_payload_key(&OTP, &CHIPID, &pin_secret(PIN))
        .expect("a provisioned OTP row derives a payload key")
}

fn index_key() -> IndexKey {
    crypto::derive_index_key(&OTP, &CHIPID).expect("a provisioned OTP row derives an index key")
}

// -- the four strings the scenario says must not be recoverable ----------------

const CRED_ID: &[u8] = b"cred-id-7f3a91c2-b0e4-4c7d-9a55-0c1de2f3a4b5";
const RP_NAME: &[u8] = b"First National Bank (example-bank.test)";
const USER_NAME: &[u8] = b"alice.smith@example-bank.test";
/// 64 distinct bytes, so "the key material appears in the dump" is a statement
/// about a 64-byte string rather than about a word that could occur by
/// accident in a magic number.
const PRIVATE_KEY: &[u8] = &[
    0x9e, 0x27, 0x44, 0x81, 0x0b, 0xd6, 0x39, 0xf2, 0x5c, 0x1a, 0x7e, 0x88, 0x34, 0x6b, 0x0d, 0xa9,
    0x52, 0xc3, 0x17, 0xe8, 0x71, 0x2d, 0xbf, 0x96, 0x08, 0x45, 0xa1, 0x73, 0xdb, 0x60, 0x2f, 0xc4,
    0x19, 0x83, 0xea, 0x57, 0x04, 0xd1, 0x6b, 0x9c, 0x38, 0xf0, 0x25, 0xad, 0x71, 0xe6, 0x3c, 0x92,
    0x18, 0xb5, 0x4f, 0xc8, 0x20, 0x77, 0xaa, 0x63, 0x05, 0xde, 0x39, 0xf1, 0x86, 0x2b, 0x50, 0xcc,
];

/// Every string the scenario names, as `(name, bytes)` so a failure says which.
const SECRETS: &[(&str, &[u8])] = &[
    ("credential id", CRED_ID),
    ("RP name", RP_NAME),
    ("user name", USER_NAME),
    ("private key", PRIVATE_KEY),
];

// -- rp_id_hashes -------------------------------------------------------------

/// A deterministic `SHA-256(rpId)` stand-in. Distinct per RP, and **not**
/// derived from the RP name by any function the index could invert — it is a
/// raw 32-byte value here because `rp_id_hash` is already a digest in CTAP and
/// hashing it again would only add a step.
fn rp_id_hash(id: u8) -> RpIdHash {
    let mut bytes = [0u8; 32];
    for (n, b) in bytes.iter_mut().enumerate() {
        *b = id.wrapping_mul(31).wrapping_add(n as u8);
    }
    RpIdHash::from_bytes(bytes)
}

/// One index entry's raw bytes — the stride is the module's constant, so the
/// alias cannot drift from it.
type EntryBytes = [u8; index::INDEX_ENTRY_BYTES];

fn slot(n: u16) -> Slot {
    Slot::new(n).expect("slot inside the region")
}

/// Unwrap a [`SlotRead`] the way this file wants to read it.
///
/// The three variants are all failures here, deliberately: an index slot in
/// this fixture is always readable, so `Absent` and `Fault` both mean the test
/// is wrong rather than the store. Spelling that out in one place is what keeps
/// `expect` off [`SlotRead`] — which has none, and whose `present()` returns
/// `None` for both non-present cases.
fn present<T: std::fmt::Debug>(read: SlotRead<T>, what: &str) -> T {
    match read {
        SlotRead::Present(value) => value,
        SlotRead::Absent => panic!("{what}: the read reported Absent"),
        SlotRead::Fault(why) => panic!("{what}: the read faulted ({why})"),
    }
}

// ---------------------------------------------------------------------------
// The region under test
// ---------------------------------------------------------------------------

/// An in-memory [`KeyRegion`] that **records every slot it is asked to read**.
///
/// Two jobs:
///
/// * it lets a test read back exactly the bytes a dump would hold, so the
///   "nothing identifying is in the dump" assertion runs on the medium rather
///   than on a value the index code produced;
/// * its read log is the instrument for "verification decrypts nothing" — see
///   the module docs.
///
/// Two write paths, and the difference is the point:
///
/// * [`MemRegion::program`] applies the NOR rule (`data & existing == data`), so
///   the fixture writes index entries the way the part would;
/// * [`MemRegion::forge`] writes the raw bytes with no NOR rule, because that is
///   the *attacker* editing a dump in RAM. A tamper test must be able to set a
///   bit from 0 back to 1, which no flash operation could do.
struct MemRegion {
    slots: Vec<SlotImage>,
    reads: BTreeSet<u16>,
    read_count: u32,
}

impl MemRegion {
    /// A full-size region, erased to `0xFF` everywhere.
    fn erased() -> Self {
        MemRegion {
            slots: vec![[0xFFu8; FIDO_SLOT_BYTES as usize]; TOTAL_SLOTS as usize],
            reads: BTreeSet::new(),
            read_count: 0,
        }
    }

    fn program(&mut self, target: Slot, offset: u32, data: &[u8]) {
        let at = offset as usize;
        let existing = &mut self.slots[target.index() as usize][at..at + data.len()];
        for (d, cur) in data.iter().zip(existing.iter()) {
            assert_eq!(d & !cur, 0, "NOR cannot set a bit from 0 to 1");
        }
        existing.copy_from_slice(data);
    }

    /// The dump attacker: write bytes with no NOR rule and no erase.
    fn forge(&mut self, target: Slot, offset: u32, data: &[u8]) {
        let at = offset as usize;
        self.slots[target.index() as usize][at..at + data.len()].copy_from_slice(data);
    }

    /// Every slot read so far.
    fn reads(&self) -> &BTreeSet<u16> {
        &self.reads
    }

    /// The whole region as one flat dump — what an attacker gets.
    fn dump(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.slots.len() * FIDO_SLOT_BYTES as usize);
        for image in &self.slots {
            out.extend_from_slice(image);
        }
        out
    }

    /// Write an index entry at its ordinal, through the NOR path.
    fn put_entry(&mut self, ordinal: u32, entry: &IndexEntry) {
        let target = index::entry_slot(ordinal).expect("ordinal inside the index");
        self.program(target, index::entry_offset(ordinal), &entry.encode());
    }
}

impl KeyRegion for MemRegion {
    fn read_slot(&mut self, target: Slot) -> Result<SlotImage, &'static str> {
        self.reads.insert(target.index());
        self.read_count += 1;
        Ok(self.slots[target.index() as usize])
    }

    fn erase_sector(&mut self, target: Slot) -> Result<(), &'static str> {
        let first = (target.index() as u32 / SLOTS_PER_SECTOR) * SLOTS_PER_SECTOR;
        for n in first..first + SLOTS_PER_SECTOR {
            self.slots[n as usize] = [0xFF; FIDO_SLOT_BYTES as usize];
        }
        Ok(())
    }

    fn program(&mut self, target: Slot, offset: u32, data: &[u8]) -> Result<(), &'static str> {
        MemRegion::program(self, target, offset, data);
        Ok(())
    }

    fn slots(&self) -> u32 {
        TOTAL_SLOTS
    }
}

// ---------------------------------------------------------------------------
// The fixture: a region written by a device with a PIN set
// ---------------------------------------------------------------------------

/// One credential the fixture stores: where, for which RP, and the plaintext
/// that must never appear in the dump.
struct Credential {
    rp: RpIdHash,
    slot: Slot,
    generation: u32,
    plaintext: Vec<u8>,
}

fn credential_plaintext(n: u8) -> Vec<u8> {
    let mut pt = Vec::new();
    pt.extend_from_slice(&[n; 4]);
    pt.extend_from_slice(CRED_ID);
    pt.push(0);
    pt.extend_from_slice(RP_NAME);
    pt.push(0);
    pt.extend_from_slice(USER_NAME);
    pt.push(0);
    pt.extend_from_slice(PRIVATE_KEY);
    pt
}

fn fixture() -> (MemRegion, Vec<Credential>) {
    fixture_with(4, slot)
}

/// `count` FIDO credentials at slots chosen by `place`, each with a real
/// payload-sealed record and a real index entry.
fn fixture_with(
    count: u8,
    place: impl Fn(u16) -> Slot,
) -> (MemRegion, Vec<Credential>) {
    let mut region = MemRegion::erased();
    let key = index_key();
    let payload = payload_key();
    let mut credentials = Vec::new();

    for n in 0..count {
        let target = place(n as u16);
        let generation = 1 + u32::from(n);
        let rp = rp_id_hash(0x40 + n);
        let plaintext = credential_plaintext(n);

        // The record: sealed under the **payload** key, so it needs the PIN to
        // open. This is the half of the region the index must not touch.
        let aad = RecordAad::new(KeyDomain::Fido, target, generation);
        let mut sealed = vec![0u8; plaintext.len() + crypto::RECORD_OVERHEAD];
        let len = crypto::seal_payload(&payload, &aad, &plaintext, &mut sealed)
            .expect("a fixture credential seals under the payload key");
        sealed.truncate(len);

        let header = record::RecordHeader::new(Domain::Fido, target, generation);
        let mut image = [0xFFu8; FIDO_SLOT_BYTES as usize];
        record::encode_into(&header, &sealed, &mut image).expect("the record fits its slot");
        let target_slot = target;
        region.program(target_slot, 0, &image);

        // The index entry: which slot, tagged under the **index** key.
        let entry = IndexEntry::build(&key, KeyDomain::Fido, target, generation, &rp);
        region.put_entry(n.into(), &entry);

        credentials.push(Credential { rp, slot: target, generation, plaintext });
    }
    (region, credentials)
}

/// The set of slots the reserved index occupies, for comparison against a read
/// log.
fn index_slots() -> BTreeSet<u16> {
    let mut set = BTreeSet::new();
    let mut n = 0u32;
    while n < index::INDEX_SLOT_COUNT {
        set.insert(index::entry_slot(n * index::ENTRIES_PER_SLOT).expect("inside the index").index());
        n += 1;
    }
    set
}

fn all_rps(credentials: &[Credential]) -> Vec<RpIdHash> {
    credentials.iter().map(|c| c.rp).collect()
}

fn assert_absent(haystack: &[u8], needle: &[u8], what: &str) {
    assert!(
        !haystack.windows(needle.len()).any(|w| w == needle),
        "the {} appears verbatim in the flash dump — the index leaked it",
        what
    );
}

// ---------------------------------------------------------------------------
// Then every entry authenticates under the device-rooted key
// ---------------------------------------------------------------------------

#[test]
fn an_index_written_by_a_device_with_a_pin_set_verifies_with_only_the_otp_row_and_chip_id() {
    let (mut region, credentials) = fixture();
    assert_eq!(credentials.len(), 4);

    // The fixture really did have a PIN set: the payload key is only reachable
    // through the PIN-derived secret, so every record in `region` is sealed
    // under something this test does not have to hand to the index path.
    assert!(crypto::derive_index_key(&OTP, &CHIPID).is_some());

    // Verification: the OTP row and the chip id, and nothing else. There is no
    // PIN argument to pass even if a caller wanted to.
    let key = crypto::derive_index_key(&OTP, &CHIPID).expect("index key");
    let rps = all_rps(&credentials);
    let result = present(
        index::verify(&key, &mut region, KeyDomain::Fido, &rps),
        "verify",
    );

    assert_eq!(
        result,
        Verification { present: 4, authenticated: 4, rejected: 0 },
        "every entry in a PIN-set device's index must authenticate from the OTP row alone"
    );

    // And each one is findable, which is the property the index exists for.
    for c in &credentials {
        match index::lookup(&key, &mut region, KeyDomain::Fido, &c.rp) {
            SlotRead::Present(found) => assert_eq!(found, c.slot),
            other => panic!("lookup returned {other:?}, not a slot"),
        }
    }
}

#[test]
fn an_index_written_with_a_pin_set_is_identical_to_one_written_without_one() {
    // The complement of the claim above, and the half a signature cannot show:
    // sweeping the PIN moves the *payload* key visibly and leaves every byte of
    // the index bit-identical. A derivation that had quietly started reading a
    // PIN through some other route would fail here while passing the first test.
    let base = {
        let key = index_key();
        let mut region = MemRegion::erased();
        let c = credential_plaintext(0);
        region.put_entry(
            0,
            &IndexEntry::build(&key, KeyDomain::Fido, slot(7), 3, &rp_id_hash(0x41)),
        );
        // Silence the unused warning while keeping the credential in scope.
        assert!(!c.is_empty());
        region
    };
    let baseline = base.slots[index::INDEX_FIRST_SLOT as usize][..].to_vec();

    let mut payload_keys = Vec::new();
    for digits in 0u32..64 {
        let pin = format!("{:06}", digits).into_bytes();
        let key = crypto::derive_index_key(&OTP, &CHIPID).expect("index key");
        let entry = IndexEntry::build(&key, KeyDomain::Fido, slot(7), 3, &rp_id_hash(0x41));
        let mut region = MemRegion::erased();
        region.put_entry(0, &entry);
        assert_eq!(
            region.slots[index::INDEX_FIRST_SLOT as usize][..].to_vec(),
            baseline,
            "the index entry moved when the PIN changed"
        );
        // And the payload key, built the same way, visibly does move.
        payload_keys.push(ckey::pin_session(
            &ckey::serial_hash(b"fapico2 keyregion index test flash uid"),
            &ckey::derive_kver(
                &ckey::derive_kbase(&OTP, &ckey::serial_hash(b"fapico2 keyregion index test flash uid"), 0x0BAD_F00D, Some(&[0x5a; 32])).expect("kbase"),
                &pin,
            ),
        ));
    }
    // `skip(1)`: the first PIN is compared against itself, which is trivially
    // equal and would make `all` false on a sweep that worked perfectly.
    let all_different = payload_keys.iter().skip(1).all(|k| *k != payload_keys[0]);
    assert!(all_different, "the PIN sweep did not move the payload key, so it proves nothing");
}

// ---------------------------------------------------------------------------
// And no payload is decrypted
// ---------------------------------------------------------------------------

#[test]
fn verifying_the_index_decrypts_no_payload() {
    let (mut region, credentials) = fixture();

    // Deliberately distinct credential slots, including ones at both ends of
    // the data area, so "the walk read the whole region" would be caught.
    let key = index_key();
    let rps = all_rps(&credentials);
    let _ = present(index::verify(&key, &mut region, KeyDomain::Fido, &rps), "verify");
    let _ = present(index::inspect_region(&mut region), "inspect_region");
    for c in &credentials {
        let _ = index::lookup(&key, &mut region, KeyDomain::Fido, &c.rp);
    }

    // The read log is the instrument. A decryption needs the record's slot;
    // nothing in this module holds a payload key, so nothing here may read one.
    assert_eq!(
        *region.reads(),
        index_slots(),
        "verification read a slot outside the reserved index — that is a payload being opened"
    );
    for c in &credentials {
        assert!(
            !region.reads().contains(&c.slot.index()),
            "verification read credential slot {}",
            c.slot.index()
        );
    }
}

#[test]
fn the_verification_result_does_not_depend_on_what_the_payload_slots_contain() {
    // The other half of "decrypts nothing", stated differentially: two regions
    // with byte-identical index areas and different credential records produce
    // the same answer. Had verification opened a payload it would have had to
    // derive something from it, and the two answers would differ — the second
    // region's records are pure noise, so an attempt to interpret them fails
    // rather than accidentally agreeing.
    let (mut real, credentials) = fixture();
    let (mut noisy, _) = fixture();

    // Corrupt every credential record in the second region, keeping the index.
    for c in &credentials {
        let mut junk = [0xFFu8; FIDO_SLOT_BYTES as usize];
        for (n, b) in junk.iter_mut().enumerate() {
            *b = (n as u8).wrapping_mul(7).wrapping_add(3);
        }
        noisy.forge(c.slot, 0, &junk);
    }

    let key = index_key();
    let rps = all_rps(&credentials);
    let a = present(index::verify(&key, &mut real, KeyDomain::Fido, &rps), "verify real");
    let b = present(index::verify(&key, &mut noisy, KeyDomain::Fido, &rps), "verify noisy");

    assert_eq!(
        a, b,
        "verification changed when the credential records changed — something on this path read a \
         payload"
    );
    assert_eq!(a.authenticated, 4);
}

// ---------------------------------------------------------------------------
// And no credential ID, RP name, user name or key material is recoverable
// ---------------------------------------------------------------------------

#[test]
fn a_dump_yields_no_credential_id_rp_name_user_name_or_key_material() {
    let (region, _) = fixture();
    let dump = region.dump();

    // The literal strings the scenario names, searched across all 960 KiB.
    for (what, needle) in SECRETS {
        assert_absent(&dump, needle, what);
    }

    // And the `rp_id_hash`es themselves: they are in the index only as MAC
    // input, so the 32 raw bytes must not appear anywhere either. This is the
    // pico-fido contrast made mechanical — `resident_container.c:324-327` stores
    // exactly those bytes as `AUTHENTICATED_PUBLIC`.
    for n in 0u8..4 {
        assert_absent(&dump, rp_id_hash(0x40 + n).as_bytes(), "rp_id_hash");
    }

    // And the tags really are 16 bytes of pseudonymous MAC, not the hash with
    // its tail cut: two different RPs get unrelated 16-byte tags.
    let key = index_key();
    let a = IndexEntry::build(&key, KeyDomain::Fido, slot(0), 1, &rp_id_hash(0x40));
    let b = IndexEntry::build(&key, KeyDomain::Fido, slot(0), 1, &rp_id_hash(0x41));
    assert_ne!(a.tag(), b.tag());
    assert_ne!(a.tag(), &rp_id_hash(0x40).as_bytes()[..index::TAG_LEN]);
    assert_eq!(index::TAG_LEN, 16);
}

// ---------------------------------------------------------------------------
// A tampered entry fails verification
// ---------------------------------------------------------------------------

#[test]
fn a_tampered_index_entry_fails_verification() {
    // Four separate edits, because they attack four different properties:
    // the tag, the transplant, the rollback, and the structural envelope.
    let base = {
        let key = index_key();
        let entry = IndexEntry::build(&key, KeyDomain::Fido, slot(9), 5, &rp_id_hash(0x50));
        entry.encode()
    };
    let rp = rp_id_hash(0x50);
    let key = index_key();

    // One named alias rather than the tuple-of-boxed-closures inline, because
    // the alternative is a very complex type written twice.
    type Tamper = (&'static str, fn(&mut EntryBytes));
    let cases: &[Tamper] = &[
        ("a flipped tag bit", |b| b[8] ^= 0x01),
        ("a rewritten slot (transplant)", |b| b[2..4].copy_from_slice(&11u16.to_le_bytes())),
        ("a rolled-back generation", |b| b[4..8].copy_from_slice(&4u32.to_le_bytes())),
        ("a swapped domain", |b| b[0] = KeyDomain::Oath.tag()),
    ];

    for (what, edit) in cases {
        let mut bytes = base;
        (edit)(&mut bytes);
        let mut region = MemRegion::erased();
        region.forge(
            index::entry_slot(0).expect("inside the index"),
            index::entry_offset(0),
            &bytes,
        );

        match index::lookup(&key, &mut region, KeyDomain::Fido, &rp) {
            SlotRead::Absent => {}
            other => panic!("{what} still resolved: {other:?}"),
        }
        let report = present(
            index::verify(&key, &mut region, KeyDomain::Fido, &[rp]),
            "verify",
        );
        assert_eq!(
            report.authenticated, 0,
            "{what} authenticated under the device-rooted key"
        );
    }
}

#[test]
fn a_tampered_index_entry_is_reported_rather_than_dropped() {
    // "Fails verification" and "is not there" are different answers and the
    // counters have to say which. A structurally broken entry — one carrying a
    // flag bit this build does not know, or a nonzero reserved tail — is
    // `malformed`, not `free`: an index that quietly skips entries looks exactly
    // like an index with fewer credentials.
    let base = IndexEntry::build(&index_key(), KeyDomain::Fido, slot(9), 5, &rp_id_hash(0x50)).encode();

    let mut region = MemRegion::erased();
    let target = index::entry_slot(0).expect("inside the index");
    let mut unknown_flag = base;
    unknown_flag[1] = index::ENTRY_PRESENT | 0x80;
    region.forge(target, index::entry_offset(0), &unknown_flag);

    let mut dirty_reserved = base;
    dirty_reserved[index::INDEX_ENTRY_BYTES - 1] = 0x01;
    region.forge(target, index::entry_offset(1), &dirty_reserved);

    match index::inspect_region(&mut region) {
        SlotRead::Present(report) => {
            assert_eq!(report.present, 0);
            assert_eq!(
                report.malformed, 2,
                "two broken entries must be counted, not skipped"
            );
            assert_eq!(
                report.free,
                index::INDEX_CAPACITY - 2,
                "every other entry is a pristine cell"
            );
        }
        other => panic!("inspect_region returned {other:?}"),
    }
}

#[test]
fn an_erased_index_reports_free_entries_and_no_present_ones() {
    // The state a factory-fresh region is in: nothing written, nothing claimed.
    let mut region = MemRegion::erased();
    match index::inspect_region(&mut region) {
        SlotRead::Present(report) => {
            assert_eq!(report.present, 0);
            assert_eq!(report.malformed, 0);
            assert_eq!(report.free, index::INDEX_CAPACITY);
        }
        other => panic!("inspect_region returned {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// An entry from another device fails verification
// ---------------------------------------------------------------------------

#[test]
fn an_index_entry_from_another_device_fails_verification() {
    // Both inputs to the root differ, so this is the strongest form of the
    // case: the entry was written by a device that had an OTP row and a chip
    // id, just not *this* device's.
    let foreign = crypto::derive_index_key(&OTHER_OTP, &OTHER_CHIPID).expect("foreign index key");
    let mine = crypto::derive_index_key(&OTP, &CHIPID).expect("index key");

    let rp = rp_id_hash(0x60);
    let entry = IndexEntry::build(&foreign, KeyDomain::Fido, slot(3), 1, &rp);

    assert!(
        !entry.verify(&mine, &rp),
        "another device's index entry authenticated under this device's key"
    );

    // A whole foreign index, on the medium, and this device's verification of
    // it: nothing authenticates, and nothing is reported as present-but-bad in
    // a way a caller could mistake for a match.
    let mut region = MemRegion::erased();
    region.put_entry(0, &entry);
    region.put_entry(
        1,
        &IndexEntry::build(&foreign, KeyDomain::Fido, slot(4), 1, &rp_id_hash(0x61)),
    );

    let result = present(
        index::verify(&mine, &mut region, KeyDomain::Fido, &[rp, rp_id_hash(0x61)]),
        "verify under this device's key",
    );
    assert_eq!(result.present, 2);
    assert_eq!(
        result.authenticated, 0,
        "a foreign index authenticated under this device's key"
    );
    assert_eq!(result.rejected, 2);

    // And the same region verified under the *foreign* key does authenticate,
    // which is what makes the refusal above a device binding rather than a
    // broken MAC.
    let ok = present(
        index::verify(&foreign, &mut region, KeyDomain::Fido, &[rp, rp_id_hash(0x61)]),
        "verify under the foreign key",
    );
    assert_eq!(ok.authenticated, 2);
}

// ---------------------------------------------------------------------------
// Matching finds the slot without decrypting it
// ---------------------------------------------------------------------------

#[test]
fn matching_an_rp_id_hash_finds_its_slot_without_decrypting_that_slot() {
    // Scattered slots, so "it found the right one" is not "it found the first
    // occupied slot".
    let (mut region, credentials) = fixture_with(4, |n| slot(400 + n * 7));
    let key = index_key();

    for c in &credentials {
        // Prove the credential is really there and really sealed: the record
        // opens under the payload key (which needs the PIN) and not otherwise.
        let payload = payload_key();
        let aad = RecordAad::new(KeyDomain::Fido, c.slot, c.generation);
        let mut sealed = vec![0u8; c.plaintext.len() + crypto::RECORD_OVERHEAD];
        let len = crypto::seal_payload(&payload, &aad, &c.plaintext, &mut sealed).expect("seals");
        sealed.truncate(len);
        let header = record::RecordHeader::new(Domain::Fido, c.slot, c.generation);
        assert_eq!(
            record::open(&header, payload.as_bytes(), &fapico2_platform::keyregion::record::testing::sealed_from_bytes(sealed))
                .present()
                .map(|p| p.as_slice().to_vec()),
            Some(c.plaintext.clone()),
            "the fixture's credential must be a real payload-sealed record"
        );

        // Now find it with only the OTP row, and read no credential slot to do
        // it.
        let before = region.reads().len();
        match index::lookup(&key, &mut region, KeyDomain::Fido, &c.rp) {
            SlotRead::Present(found) => assert_eq!(found, c.slot),
            other => panic!("lookup returned {other:?}"),
        }
        assert!(
            !region.reads().contains(&c.slot.index()),
            "matching opened the credential slot it was only meant to find"
        );
        assert!(
            region.reads().len() >= before,
            "the read log must not shrink"
        );
    }

    // Every read across the whole sequence was an index slot. `lookup` stops at
    // the first match, so the log is a *prefix* of the index rather than all of
    // it — the property under test is that it contains nothing else, and that
    // it is not empty (an empty log would mean the lookup answered from
    // somewhere that is not the region at all).
    assert!(
        !region.reads().is_empty(),
        "lookup answered without reading the index at all"
    );
    assert!(
        region.reads().is_subset(&index_slots()),
        "matching read a slot outside the reserved index: {:?}",
        region.reads().difference(&index_slots()).collect::<Vec<_>>()
    );
}

#[test]
fn a_lookup_for_one_domain_does_not_answer_for_the_other() {
    // FIDO and OATH share one slot grid and one payload key, so an entry whose
    // domain is not checked would let an OATH query return a FIDO credential.
    let key = index_key();
    let rp = rp_id_hash(0x70);
    let mut region = MemRegion::erased();
    region.put_entry(0, &IndexEntry::build(&key, KeyDomain::Fido, slot(5), 1, &rp));

    match index::lookup(&key, &mut region, KeyDomain::Oath, &rp) {
        SlotRead::Absent => {}
        other => panic!("an Oath lookup returned {other:?} for a Fido entry"),
    }
    assert!(matches!(
        index::lookup(&key, &mut region, KeyDomain::Fido, &rp),
        SlotRead::Present(_)
    ));
}

#[test]
fn several_credentials_for_one_rp_are_all_enumerable_without_decrypting_any() {
    // The normal CTAP2 credential-management shape: one RP, several users. The
    // index has to answer "which slots" for all of them, still without a PIN.
    let key = index_key();
    let rp = rp_id_hash(0x80);
    let mut region = MemRegion::erased();
    let targets = [slot(11), slot(12), slot(19)];
    for (n, t) in targets.iter().enumerate() {
        region.put_entry(
            n as u32,
            &IndexEntry::build(&key, KeyDomain::Fido, *t, n as u32 + 1, &rp),
        );
    }
    // A different RP in the same index, which must not show up.
    region.put_entry(
        3,
        &IndexEntry::build(&key, KeyDomain::Fido, slot(20), 1, &rp_id_hash(0x81)),
    );

    let mut out = [Slot::new(0).unwrap(); 8];
    let total = present(
        index::lookup_all(&key, &mut region, KeyDomain::Fido, &rp, &mut out),
        "lookup_all",
    );
    assert_eq!(total, 3);
    assert_eq!(&out[..total], &targets);

    // And the count exceeds a short buffer without overrunning it.
    let mut tight = [Slot::new(0).unwrap(); 2];
    let total = present(
        index::lookup_all(&key, &mut region, KeyDomain::Fido, &rp, &mut tight),
        "lookup_all (short buffer)",
    );
    assert_eq!(total, 3, "the total must report what did not fit");
    assert_eq!(&tight[..], &targets[..2]);
    assert_eq!(*region.reads(), index_slots());
}

#[test]
fn an_index_that_has_been_wiped_reports_nothing_and_the_wipe_reads_only_the_index() {
    // The index is part of the region, so `commit::wipe` erases it. After a wipe
    // the region must not claim to hold credentials: the index is the reachability
    // gate `commit.rs` relies on ("What `wipe` promises").
    let (mut region, _) = fixture();
    for n in 0..index::INDEX_SLOT_COUNT {
        let target = index::entry_slot(n * index::ENTRIES_PER_SLOT).expect("inside the index");
        region.erase_sector(target).expect("erase");
    }
    match index::inspect_region(&mut region) {
        SlotRead::Present(report) => {
            assert_eq!(report.present, 0);
            assert_eq!(report.malformed, 0);
        }
        other => panic!("inspect_region returned {other:?}"),
    }
    let key = index_key();
    assert!(matches!(
        index::lookup(&key, &mut region, KeyDomain::Fido, &rp_id_hash(0x40)),
        SlotRead::Absent
    ));
}

// ---------------------------------------------------------------------------
// The geometry claims, asserted on the constants
// ---------------------------------------------------------------------------

#[test]
fn the_index_entry_is_fixed_size_and_tiles_an_index_slot_exactly() {
    // Fixed-size and bounded is a boot-path budget, not tidiness: the boot stack
    // is 5,056 B and a materialised index would be 32 KiB.
    assert_eq!(index::INDEX_ENTRY_BYTES, 32);
    assert_eq!(index::TAG_LEN, 16);
    assert_eq!(index::ENTRY_CONTENT_BYTES, 8 + index::TAG_LEN);
    assert_eq!(index::ENTRIES_PER_SLOT, 32);
    assert_eq!(
        index::ENTRIES_PER_SLOT as usize * index::INDEX_ENTRY_BYTES,
        FIDO_SLOT_BYTES as usize,
        "the entries must tile an index slot exactly, with no partial entry at the end"
    );
}

#[test]
fn the_index_is_the_tail_of_the_region_so_the_lowest_free_allocator_cannot_reach_it_first() {
    assert_eq!(index::INDEX_FIRST_SLOT + index::INDEX_SLOT_COUNT, TOTAL_SLOTS);
    assert_eq!(
        index::INDEX_SLOT_COUNT,
        (index::INDEX_SLOT_COUNT / SLOTS_PER_SECTOR) * SLOTS_PER_SECTOR,
        "the reservation must be whole NOR sectors, so erasing an index sector never touches a \
         credential"
    );
    assert_eq!(index::INDEX_FIRST_SLOT % SLOTS_PER_SECTOR, 0);

    // The predicate the allocator has to honour, checked at both ends.
    let first = index::INDEX_FIRST_SLOT as u16;
    assert!(!index::is_index_slot(slot(first - 1)));
    assert!(index::is_index_slot(slot(first)));
    assert!(index::is_index_slot(slot(TOTAL_SLOTS as u16 - 1)));
    assert!(!index::is_index_slot(slot(0)));
}

#[test]
fn the_index_covers_every_record_the_region_can_hold() {
    // The load-bearing arithmetic. 28 index slots would be 896 entries against
    // 960 records, and the last 64 credentials would simply be unfindable.
    assert_eq!(TOTAL_SLOTS, 960);
    assert_eq!(
        index::INDEX_CAPACITY,
        index::INDEX_SLOT_COUNT * index::ENTRIES_PER_SLOT
    );

    // The claim, against the capacity the **region reports** rather than
    // against a restatement of it: `index.rs` already asserts the same
    // inequality in a `const` block, and a test that repeated the constant
    // would only be testing that two constants agree. Going through
    // `KeyRegion::slots` also keeps the comparison off clippy's
    // "assertion has a constant value" lint.
    let region = MemRegion::erased();
    let record_slots = region.slots();
    assert_eq!(record_slots, TOTAL_SLOTS);
    // `mod.rs` partitions the region into four reservations and asserts they
    // tile it exactly: FIDO records, OATH records, the commit scratchpad, and
    // this index. Only the first two hold records, so neither the scratchpad
    // nor the index itself needs an index entry.
    assert_eq!(
        record_slots,
        FIDO_CAPACITY + OATH_CAPACITY + SCRATCHPAD_SLOTS + index::INDEX_SLOT_COUNT,
        "every slot in the region is FIDO, OATH, the commit scratchpad, or the index; the first \
         two need an entry and the other two do not"
    );
    assert!(FIDO_CAPACITY + OATH_CAPACITY <= record_slots);
    assert_eq!(
        SCRATCHPAD_SLOTS, SLOTS_PER_SECTOR,
        "the scratchpad reservation is one sector"
    );
    assert!(
        index::INDEX_CAPACITY >= record_slots,
        "the index holds {} entries for {} record slots — the last {} credentials would be \
         unfindable",
        index::INDEX_CAPACITY,
        record_slots,
        record_slots - index::INDEX_CAPACITY.min(record_slots)
    );

    // Entry placement round-trips: ordinal -> (slot, offset) -> back.
    for ordinal in [0u32, 1, 31, 32, 33, index::INDEX_CAPACITY - 1] {
        let target = index::entry_slot(ordinal).expect("inside the index");
        assert!(index::is_index_slot(target));
        let offset = index::entry_offset(ordinal);
        assert!(offset + index::INDEX_ENTRY_BYTES as u32 <= FIDO_SLOT_BYTES);
    }
    assert!(index::entry_slot(index::INDEX_CAPACITY).is_none());
}

#[test]
fn an_index_entry_round_trips_through_its_thirty_two_bytes() {
    let key = index_key();
    let entry = IndexEntry::build(&key, KeyDomain::Fido, slot(123), 0xDEAD_BEEF, &rp_id_hash(0x90));
    let bytes = entry.encode();
    assert_eq!(bytes.len(), index::INDEX_ENTRY_BYTES);
    assert!(
        bytes[index::INDEX_ENTRY_BYTES - index::ENTRY_RESERVED_BYTES..]
            .iter()
            .all(|b| *b == 0),
        "the reserved tail is zero in an encoded entry"
    );
    match IndexEntry::decode(&bytes) {
        SlotRead::Present(decoded) => assert_eq!(decoded, entry),
        other => panic!("decode returned {other:?} for an entry this module just encoded"),
    }
    assert!(entry.verify(&key, &rp_id_hash(0x90)));
    assert!(!entry.verify(&key, &rp_id_hash(0x91)));
}

#[test]
fn an_entry_never_prints_its_tag() {
    // The tag is not secret, but it is a stable per-RP pseudonym, and a `Debug`
    // that prints it puts "this owner has a credential for that site" into a log
    // buffer.
    let key = index_key();
    let entry = IndexEntry::build(&key, KeyDomain::Fido, slot(2), 9, &rp_id_hash(0xA0));
    let rendered = format!("{entry:?}");
    let hex: String = entry.tag().iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !rendered.contains(&hex),
        "Debug printed the tag: {rendered}"
    );
    assert!(rendered.contains("redacted"), "{rendered}");
}
