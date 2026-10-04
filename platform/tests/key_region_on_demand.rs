//! US-1554: on-demand credential load — one record decrypted, into a bounded
//! buffer, per operation.
//!
//! # What this file is evidence for
//!
//! `apps/fido/src/device_keystore.rs:919` keeps
//! `HeaplessVec<DeviceCredential, 12>` resident, and `DeviceCredential` is 720
//! bytes on this layout — so 8,640 B of `.bss` for twelve credentials, against
//! a derived capacity of 892 (`keyregion::FIDO_CAPACITY`) whose resident form
//! would be 642,240 B on a part with 532,480 B of RAM. The two cannot both
//! hold. This file proves the mechanism that replaces the array: nothing is
//! resident, the index is scanned, **exactly one** record is decrypted per
//! lookup, and the buffer it landed in is zeroized.
//!
//! # How "exactly one decryption" is counted, and why it is not vacuous
//!
//! Two independent instruments, deliberately:
//!
//! * **`FileKeyRegion::stats().slot_reads`** — an instrument this test does not
//!   own and cannot bias, because it lives in the region (`host.rs:117`). It
//!   bounds the property from above: `record::read` takes a slot image **by
//!   value**, so *no payload decryption can happen without a distinct
//!   `read_slot`*. `slot_reads == 1` therefore caps the decryption count at one
//!   no matter what the module does internally.
//! * **`on_demand::testing::unseal_attempts()`** — the module's own count of
//!   read-path invocations, which is the only way to observe work performed
//!   inside a function from outside.
//!
//! Neither alone suffices: the first is satisfied by an implementation that
//! decrypts zero times and returns nothing, the second by one that decrypts
//! everything and throws it away. Together with the assertion that the
//! returned plaintext is *correct*, they pin the count at exactly one — and
//! `the_decryption_counter_is_not_pinned_to_one` then shows both instruments
//! **moving**, which is what stops them being two ways of asserting a constant.
//!
//! # What the stand-in locator is, and what it is not
//!
//! [`DirectoryLocator`] holds its entries in RAM because it stands in for
//! US-1551's flash index. It is a test double, not the design: the real index
//! is read from flash under the PIN-free index key and never materialises a
//! directory. Everything asserted here about *payload* decryption survives that
//! swap; everything asserted about RAM does not, and is scoped accordingly.
//! `SlotLocator`'s own docs state the contract `index.rs` has to satisfy.

use std::path::{Path, PathBuf};

use fapico2_platform::keyregion::crypto::{self, PayloadKey};
use fapico2_platform::keyregion::host::{Faults, FileKeyRegion};
use fapico2_platform::keyregion::on_demand::testing::{DirectoryEntry, DirectoryLocator};
use fapico2_platform::keyregion::on_demand::{
    self, CredentialWindow, Located, SlotLocator, SlotQuery, ON_DEMAND_WINDOW_BYTES, RP_ID_TAG_LEN,
};
use fapico2_platform::keyregion::record::{self, Domain, RecordHeader};
use fapico2_platform::keyregion::{
    FIDO_CAPACITY, FIDO_RECORD_MAX, FIDO_SLOT_BYTES, KeyRegion, Slot, SlotRead, SLOTS_PER_SECTOR,
};

/// Credentials in the fixture region.
///
/// The gherkin's 64. Deliberately **not** [`FIDO_CAPACITY`]: this file is about
/// the lookup cost being independent of how many credentials exist, and 64 is
/// both what the story names and comfortably more than the 12 the resident
/// array could hold — so the two can be compared directly.
const CREDENTIALS: u32 = 64;

/// Index of the credential the "the matching one" tests look up.
///
/// **The last one**, in both the region's slot order and the directory's entry
/// order, so a lookup cannot succeed by being lucky and the scan cannot pass
/// by being short. Every other fixture credential has a different RP and a
/// different credential ID, so a match here can only come from the right slot.
const TARGET: u32 = CREDENTIALS - 1;

/// Bytes of a flash page, the unit `KeyRegion::program` takes.
const PAGE: usize = 256;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// A region file in the host temp directory, removed on drop.
struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("fapico2-ondemand-{}-{tag}.bin", std::process::id()));
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

/// The RP ID of fixture credential `i`.
///
/// Distinct per credential, so a match on the target's tag cannot be produced
/// by another record's plaintext.
fn rp_id_of(i: u32) -> String {
    format!("rp{i:02}.example")
}

/// The credential ID of fixture credential `i` — 32 bytes, distinct per
/// credential.
fn credential_id_of(i: u32) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&i.to_le_bytes());
    id
}

/// The plaintext sealed into fixture credential `i`'s record.
///
/// Carries both identifiers in the clear *inside* the ciphertext, so the test
/// can tell which record it got back without trusting itself to have asked for
/// the right one.
fn plaintext_of(i: u32) -> Vec<u8> {
    let rp = rp_id_of(i);
    format!("credential:{i}|rp:{rp}|id:{:02x?}", &credential_id_of(i)[..4]).into_bytes()
}

/// The nonce fixture credential `i` is sealed under.
///
/// A real nonce comes from `crypto::record_nonce`, which is private by design
/// (`crypto.rs`, "Deterministic record nonce"). A test does not need it to be
/// unpredictable — it needs two records not to share a `(key, nonce)` pair, and
/// distinct slots make the AAD distinct, which the derivation would have
/// honoured anyway. Keyed on the slot, so it is.
fn nonce_for(slot: u32) -> [u8; record::NONCE_LEN] {
    let mut nonce = [0u8; record::NONCE_LEN];
    nonce[..4].copy_from_slice(&slot.to_le_bytes());
    nonce
}

/// How a fixture record's image is damaged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Damage {
    /// One ciphertext byte flipped: the header's CRC still holds, so `decode`
    /// succeeds and the **AEAD tag** is what refuses it.
    Body,
    /// One header byte flipped: the CRC fails, so `decode` never reaches the
    /// AEAD at all.
    Header,
}

/// Flip a byte of an encoded image to damage it.
///
/// The flip is a `^= 0xFF` and is applied **before** the image is programmed,
/// so it never has to survive the host region's NOR refusal (`host.rs:92`):
/// every byte is set exactly once, into erased flash.
fn damage_image(image: &mut [u8], damage: Damage) {
    let at = match damage {
        // Offset 4 into the sealed body: the header is 16 B and the nonce is
        // 12 B, so this is ciphertext — and the header's CRC covers only bytes
        // 0..12, so it still holds and `decode` still succeeds.
        Damage::Body => record::RECORD_HEADER_LEN + 4,
        // Offset 3 is the flags byte, inside the CRC's range.
        Damage::Header => 3,
    };
    image[at] ^= 0xFF;
}

/// The payload key the fixture seals and opens under.
///
/// Derived through the production chain rather than a raw constant, so the
/// fixture exercises the same key type (`PayloadKey` — non-`Copy`,
/// non-`Clone`, zeroized on drop) the device path hands to [`on_demand::load`].
/// The OTP row is non-zero because [`crypto::derive_payload_key`] refuses an
/// all-zero one — the `drbg_seed.rs` argument about a key derived from a
/// constant input — and a fixture that could not derive one would test nothing.
fn payload_key() -> PayloadKey {
    let otp = [0xA5u8; 32];
    let chipid = [0x11u8; 8];
    let pin_secret = [0x5Au8; 32];
    crypto::derive_payload_key(&otp, &chipid, &pin_secret).expect("a non-zero OTP row derives")
}

/// A region of [`CREDENTIALS`] records plus the directory that points into it.
struct Fixture {
    _temp: TempRegion,
    region: FileKeyRegion,
    key: PayloadKey,
    locator: DirectoryLocator,
    plain: Vec<Vec<u8>>,
}

impl Fixture {
    /// Build a region of [`CREDENTIALS`] records, damaging slot `damaged_at`.
    ///
    /// Written the way the hardware requires — erase the whole sector set
    /// first, then program — rather than record by record with an erase
    /// between. `erase_sector` clears [`SLOTS_PER_SECTOR`] slots
    /// (`mod.rs:119-132`), so "erase, write, erase, write" would destroy the
    /// previous credential on every iteration. That is a property of the part,
    /// not of this fixture, and getting it wrong here would leave every
    /// assertion below running against a region that never held 64 records.
    fn build(tag: &str, damaged_at: Option<(u32, Damage)>) -> Self {
        let temp = TempRegion::new(tag);
        let mut region = FileKeyRegion::create(temp.path(), CREDENTIALS).expect("temp region file");
        let key = payload_key();

        let mut plain = Vec::new();
        let mut images = Vec::new();
        for i in 0..CREDENTIALS {
            let slot = slot_of(i);
            let header = RecordHeader::new(Domain::Fido, slot, 1);
            let bytes = plaintext_of(i);
            let sealed = record::seal(&header, key.as_bytes(), &nonce_for(i), &bytes)
                .expect("a 64-byte plaintext fits any slot");
            let mut image = record::encode(&header, &sealed).expect("encode into one slot").into_bytes();
            if let Some((at, damage)) = damaged_at {
                if at == i {
                    damage_image(&mut image, damage);
                }
            }
            plain.push(bytes);
            images.push(image);
        }

        // Every sector, then every slot. See the doc comment.
        for first in (0..CREDENTIALS).step_by(SLOTS_PER_SECTOR as usize) {
            region.erase_sector(slot_of(first)).expect("erase");
        }
        for (i, image) in images.iter().enumerate() {
            for page in 0..(FIDO_SLOT_BYTES as usize / PAGE) {
                let from = page * PAGE;
                region
                    .program(slot_of(i as u32), from as u32, &image[from..from + PAGE])
                    .expect("program a whole page");
            }
        }

        // The stand-in index, in the same order as the slots.
        let locator = {
            let mut d = DirectoryLocator::new();
            for i in 0..CREDENTIALS {
                d.insert(DirectoryEntry {
                    tag: Fixture::tag_of(i),
                    credential_id: credential_id_of(i).to_vec(),
                    slot: slot_of(i),
                });
            }
            d
        };

        Self { _temp: temp, region, key, locator, plain }
    }

    /// The RP tag of fixture credential `i`.
    fn tag_of(i: u32) -> [u8; RP_ID_TAG_LEN] {
        on_demand::rp_id_tag(rp_id_of(i).as_bytes())
    }
}

/// Fixture credential `i`'s slot. `i < CREDENTIALS <= TOTAL_SLOTS` everywhere.
fn slot_of(i: u32) -> Slot {
    Slot::new(i as u16).expect("fixture indices are inside the region")
}

/// Forget the host witnesses, so a test cannot pass on another's work.
fn reset_counters() {
    on_demand::testing::clear();
}

// ---------------------------------------------------------------------------
// The gherkin
// ---------------------------------------------------------------------------

#[test]
fn the_index_is_scanned_for_the_matching_rp_id_tag() {
    let mut f = Fixture::build("scan", None);
    let mut window = CredentialWindow::new();

    let tag = Fixture::tag_of(TARGET);
    let hit = on_demand::load(
        &mut f.region,
        &mut f.locator,
        &f.key,
        &SlotQuery::RpIdTag { tag: &tag },
        &mut window,
    )
    .present()
    .expect("the target is present");

    assert_eq!(hit.slot(), slot_of(TARGET), "the scan answered with some other slot");
    // The target is the *last* of CREDENTIALS entries, so a linear scan that
    // finds it examined every one. This is the clause "the index is scanned",
    // as a number rather than as a claim about a loop someone read.
    assert_eq!(
        f.locator.examined(),
        CREDENTIALS,
        "the scan must actually walk the index to reach the last entry"
    );
}

#[test]
fn exactly_one_record_is_decrypted() {
    let mut f = Fixture::build("one-decrypt", None);
    let mut window = CredentialWindow::new();
    reset_counters();

    let tag = Fixture::tag_of(TARGET);
    let hit = on_demand::load(
        &mut f.region,
        &mut f.locator,
        &f.key,
        &SlotQuery::RpIdTag { tag: &tag },
        &mut window,
    )
    .present()
    .expect("the target is present");

    // The read path ran once...
    assert_eq!(
        on_demand::testing::unseal_attempts(),
        1,
        "one lookup over a region of {CREDENTIALS} credentials ran the read path other than once"
    );
    // ...the region says one slot was read, which caps the AEAD at one...
    assert_eq!(
        f.region.stats().slot_reads,
        1,
        "the lookup read more than one slot — with {CREDENTIALS} records present, that is the \
         signature of a scan that decrypts to decide"
    );
    // ...and it scanned the index to get there.
    assert_eq!(f.locator.examined(), CREDENTIALS);
    // ...and produced a credential, so the one slot read was a decryption
    // rather than a refusal. Zero is excluded by this and one by the two above.
    assert_eq!(hit.slot(), slot_of(TARGET));
    assert_eq!(window.as_slice(), f.plain[TARGET as usize].as_slice());
}

#[test]
fn the_decryption_counter_is_not_pinned_to_one() {
    // The falsification half of the previous test: an instrument that cannot
    // leave 1 is not an instrument. Three loads, three reads, three opens.
    let mut f = Fixture::build("counter-moves", None);
    let mut window = CredentialWindow::new();
    reset_counters();

    for i in [TARGET, TARGET - 1, 0] {
        let tag = Fixture::tag_of(i);
        on_demand::load(
            &mut f.region,
            &mut f.locator,
            &f.key,
            &SlotQuery::RpIdTag { tag: &tag },
            &mut window,
        )
        .present()
        .expect("the fixture credential is present");
    }

    assert_eq!(on_demand::testing::unseal_attempts(), 3, "the counter did not follow the work");
    assert_eq!(f.region.stats().slot_reads, 3, "the region's own counter did not follow either");
}

#[test]
fn the_record_is_decrypted_into_a_bounded_buffer() {
    let mut f = Fixture::build("bounded", None);
    let mut window = CredentialWindow::new();

    let tag = Fixture::tag_of(TARGET);
    let hit = on_demand::load(
        &mut f.region,
        &mut f.locator,
        &f.key,
        &SlotQuery::RpIdTag { tag: &tag },
        &mut window,
    )
    .present()
    .expect("the target is present");

    assert_eq!(hit.len(), window.len(), "the reported length and the window's disagree");
    assert!(
        window.len() <= ON_DEMAND_WINDOW_BYTES,
        "the window holds {} bytes, above its own bound of {ON_DEMAND_WINDOW_BYTES}",
        window.len()
    );
    assert!(!window.is_empty(), "a successful load left the window empty");
}

#[test]
fn the_window_is_bounded_by_construction() {
    // The RAM number, pinned rather than asserted in a comment: 836 B of array
    // plus a u16 length, both 1-byte aligned, so no padding.
    assert_eq!(ON_DEMAND_WINDOW_BYTES, FIDO_RECORD_MAX as usize);
    assert_eq!(
        std::mem::size_of::<CredentialWindow>(),
        ON_DEMAND_WINDOW_BYTES + 2,
        "the window's size changed — the resident-RAM figure US-1552 reports is this number"
    );

    // The figure it replaces, for the same reason: a net-bss claim needs both
    // sides in one place, and both are derived rather than remembered.
    const DEVICE_CREDENTIAL_BYTES: usize = 720;
    const DEVICE_MAX_CREDS: usize = 12;
    let old_array = DEVICE_CREDENTIAL_BYTES * DEVICE_MAX_CREDS;
    let new_window = std::mem::size_of::<CredentialWindow>();
    eprintln!(
        "on-demand window = {new_window} B resident; replaces a {old_array} B resident array \
         ({DEVICE_CREDENTIAL_BYTES} B x {DEVICE_MAX_CREDS}); net {old_array} B once the array is \
         gone; {} credentials resident would be {} B",
        FIDO_CAPACITY,
        FIDO_CAPACITY as usize * DEVICE_CREDENTIAL_BYTES,
    );
    assert!(new_window < old_array, "one window must cost less than the array it replaces");
}

#[test]
fn the_returned_credential_is_the_right_one_and_no_other() {
    let mut f = Fixture::build("right-one", None);
    let mut window = CredentialWindow::new();

    let tag = Fixture::tag_of(TARGET);
    on_demand::load(
        &mut f.region,
        &mut f.locator,
        &f.key,
        &SlotQuery::RpIdTag { tag: &tag },
        &mut window,
    )
    .present()
    .expect("the target is present");

    assert_eq!(
        window.as_slice(),
        f.plain[TARGET as usize].as_slice(),
        "the window does not hold the credential that was asked for"
    );
    // And no other. Not a formality: an implementation that decrypted the set
    // and returned the right one would satisfy every assertion above.
    for (i, other) in f.plain.iter().enumerate() {
        if i == TARGET as usize {
            continue;
        }
        assert!(
            !window.as_slice().windows(other.len()).any(|w| w == other.as_slice()),
            "the window also holds credential {i}"
        );
    }
    // Read the other way round: the only record ever read from flash is the one
    // that was asked for.
    assert_eq!(f.region.stats().slot_reads, 1);
}

#[test]
fn a_lookup_by_credential_id_picks_the_right_one_of_a_shared_rp() {
    // Two credentials at one RP is the case a tag-only query cannot answer, and
    // the reason [`SlotQuery`] has two variants. The tag query would answer
    // with whichever the index lists first; the id query answers with the one
    // the client named.
    let mut f = Fixture::build("shared-rp", None);
    let mut window = CredentialWindow::new();

    let id = credential_id_of(TARGET);
    let want = SlotQuery::RpIdTagAndCredentialId { tag: &Fixture::tag_of(TARGET), credential_id: &id };
    on_demand::load(&mut f.region, &mut f.locator, &f.key, &want, &mut window)
        .present()
        .expect("the credential is present");

    assert_eq!(
        window.as_slice(),
        f.plain[TARGET as usize].as_slice(),
        "the id query returned the wrong credential"
    );

    // An id that belongs to no credential of this RP is not that of another.
    let other_id = credential_id_of(0);
    let want = SlotQuery::RpIdTagAndCredentialId { tag: &Fixture::tag_of(TARGET), credential_id: &other_id };
    assert_eq!(
        on_demand::load(&mut f.region, &mut f.locator, &f.key, &want, &mut window),
        SlotRead::Absent,
        "an id query matched a credential of a different RP"
    );
}

#[test]
fn the_buffer_is_zeroized_after_use() {
    let mut f = Fixture::build("zeroize", None);
    reset_counters();

    let tag = Fixture::tag_of(TARGET);
    let mut window = CredentialWindow::new();
    on_demand::load(
        &mut f.region,
        &mut f.locator,
        &f.key,
        &SlotQuery::RpIdTag { tag: &tag },
        &mut window,
    )
    .present()
    .expect("the target is present");

    // The credential really is in the buffer, so zeroes below are a clear and
    // not a buffer that was never written.
    assert_eq!(window.as_slice(), f.plain[TARGET as usize].as_slice());

    // (a) the explicit clear, read back on the caller's own bytes.
    window.zeroize_now();
    assert!(window.as_slice().iter().all(|&b| b == 0), "zeroize_now left plaintext behind");
    assert_eq!(window.len(), 0, "zeroize_now left the length standing");
    assert!(window.is_empty());

    // (b) the backstop: dropped without the explicit call, still cleared — and
    // the witness is what the bytes held *after* the clear, which is the only
    // place that can be read (by now the memory is freed).
    drop(window);
    let dropped = on_demand::testing::dropped_windows();
    assert_eq!(dropped.len(), 1, "the window's drop recorded nothing");
    assert!(
        dropped[0].iter().all(|&b| b == 0),
        "the dropped window still held plaintext after its own zeroize"
    );
}

#[test]
fn a_lookup_that_matches_nothing_does_not_decrypt_anything() {
    let mut f = Fixture::build("no-match", None);
    let mut window = CredentialWindow::new();
    reset_counters();

    let tag = on_demand::rp_id_tag(b"nowhere.example");
    let outcome = on_demand::load(
        &mut f.region,
        &mut f.locator,
        &f.key,
        &SlotQuery::RpIdTag { tag: &tag },
        &mut window,
    );

    assert_eq!(outcome, SlotRead::Absent, "an unknown RP must not resolve");
    assert_eq!(
        on_demand::testing::unseal_attempts(),
        0,
        "a lookup that matched nothing ran the read path"
    );
    assert_eq!(f.region.stats().slot_reads, 0, "a lookup that matched nothing read flash");
    assert_eq!(f.locator.examined(), CREDENTIALS, "…though it did scan the whole index");
    assert!(window.is_empty(), "a failed lookup left something in the window");
}

#[test]
fn a_failed_lookup_leaves_no_credential_in_the_window() {
    // The clear-first rule, tested through the sequence that motivates it: a
    // successful load followed by a failed one. A window cleared only on
    // success would serve the *previous* credential here — the bug the rule
    // exists to prevent, and one no single-lookup test can see.
    let mut f = Fixture::build("clear-first", None);
    let mut window = CredentialWindow::new();

    let tag = Fixture::tag_of(TARGET);
    on_demand::load(
        &mut f.region,
        &mut f.locator,
        &f.key,
        &SlotQuery::RpIdTag { tag: &tag },
        &mut window,
    )
    .present()
    .expect("the target is present");
    assert_eq!(window.as_slice(), f.plain[TARGET as usize].as_slice());

    let missing = on_demand::rp_id_tag(b"nowhere.example");
    let outcome = on_demand::load(
        &mut f.region,
        &mut f.locator,
        &f.key,
        &SlotQuery::RpIdTag { tag: &missing },
        &mut window,
    );
    assert_eq!(outcome, SlotRead::Absent);
    assert!(
        window.is_empty(),
        "the window still holds the previous credential after a failed lookup"
    );
}

#[test]
fn a_corrupt_record_does_not_cost_the_intact_ones() {
    // US-1549 end to end: one record in 64 is refused by the AEAD tag. The
    // intact ones still load, one read and one read-path invocation each —
    // which is the whole property: a bad record fails closed for itself alone.
    let mut f = Fixture::build("corrupt", Some((3, Damage::Body)));
    let mut window = CredentialWindow::new();

    let tag = Fixture::tag_of(3);
    assert_eq!(
        on_demand::load(&mut f.region, &mut f.locator, &f.key, &SlotQuery::RpIdTag { tag: &tag }, &mut window),
        SlotRead::Absent,
        "a record whose tag does not verify must not resolve"
    );
    assert!(window.is_empty());

    reset_counters();
    for i in [0u32, 2, 4, TARGET] {
        let mut w = CredentialWindow::new();
        let tag = Fixture::tag_of(i);
        let hit = on_demand::load(&mut f.region, &mut f.locator, &f.key, &SlotQuery::RpIdTag { tag: &tag }, &mut w)
            .present()
            .unwrap_or_else(|| panic!("intact credential {i} did not resolve"));
        assert_eq!(hit.slot(), slot_of(i));
        assert_eq!(w.as_slice(), f.plain[i as usize].as_slice());
    }
    assert_eq!(on_demand::testing::unseal_attempts(), 4, "four intact loads, four read paths");
    // Five reads: the four intact loads plus the one refused record.
    assert_eq!(f.region.stats().slot_reads, 5);
}

#[test]
fn a_header_corrupt_record_is_absent_too() {
    let mut f = Fixture::build("crc", Some((3, Damage::Header)));
    let mut window = CredentialWindow::new();
    reset_counters();

    let tag = Fixture::tag_of(3);
    assert_eq!(
        on_demand::load(&mut f.region, &mut f.locator, &f.key, &SlotQuery::RpIdTag { tag: &tag }, &mut window),
        SlotRead::Absent,
        "a record whose header CRC fails must not resolve"
    );
    // One read-path invocation, which stopped at the CRC: the AEAD never ran.
    // The window is empty either way, which is the property — not the count.
    assert_eq!(on_demand::testing::unseal_attempts(), 1);
    assert!(window.is_empty());

    let tag = Fixture::tag_of(4);
    on_demand::load(&mut f.region, &mut f.locator, &f.key, &SlotQuery::RpIdTag { tag: &tag }, &mut window)
        .present()
        .expect("the neighbour is intact");
    assert_eq!(window.as_slice(), f.plain[4].as_slice());
}

#[test]
fn a_wrong_key_does_not_resolve() {
    // The payload key is PIN-derived (`crypto.rs`, "The payload key"), so this
    // is the shape of a wrong PIN: the record is intact, the bytes are intact,
    // and the tag is what refuses.
    let mut f = Fixture::build("wrong-key", None);
    let wrong = crypto::derive_payload_key(&[0xA5u8; 32], &[0x11u8; 8], &[0x11u8; 32])
        .expect("a non-zero OTP row derives");
    let mut window = CredentialWindow::new();
    reset_counters();

    let tag = Fixture::tag_of(TARGET);
    let outcome =
        on_demand::load(&mut f.region, &mut f.locator, &wrong, &SlotQuery::RpIdTag { tag: &tag }, &mut window);

    assert_eq!(outcome, SlotRead::Absent, "a wrong payload key resolved a record");
    assert!(window.is_empty(), "and it left unauthenticated plaintext in the window");
}

#[test]
fn a_faulted_region_is_a_fault_not_an_absence() {
    // US-1573: "could not be learned" and "does not exist" are different facts,
    // and the lookup is the first place that can confuse them.
    let mut f = Fixture::build("fault", None);
    let mut window = CredentialWindow::new();
    f.region.inject_faults(Faults { reads: true, ..Faults::default() });
    reset_counters();

    let tag = Fixture::tag_of(TARGET);
    let outcome =
        on_demand::load(&mut f.region, &mut f.locator, &f.key, &SlotQuery::RpIdTag { tag: &tag }, &mut window);

    match outcome {
        SlotRead::Fault(_) => {}
        other => panic!("a faulted read reported {other:?}; it must never be memoized as absence"),
    }
    assert!(window.is_empty());
    assert_eq!(
        on_demand::testing::unseal_attempts(),
        0,
        "a read that never happened must not count as a decryption"
    );
}

#[test]
fn a_faulted_index_scan_is_a_fault_not_an_absence() {
    // The same distinction one layer up: US-1551's real index will read flash,
    // and a transport error there must not read as "this RP has no credential".
    let mut f = Fixture::build("scan-fault", None);
    let mut window = CredentialWindow::new();
    f.locator.inject_fault(Some("index region could not be read"));

    let tag = Fixture::tag_of(TARGET);
    let outcome =
        on_demand::load(&mut f.region, &mut f.locator, &f.key, &SlotQuery::RpIdTag { tag: &tag }, &mut window);

    match outcome {
        SlotRead::Fault(why) => assert_eq!(why, "index region could not be read"),
        other => panic!("a faulted scan reported {other:?}; it must never be memoized as absence"),
    }
    assert_eq!(f.region.stats().slot_reads, 0, "it should not have read a record either");
}

#[test]
fn the_rp_id_tag_is_sha256_of_the_rp_id() {
    // Known-answer, so the tag every query here is built on cannot drift from
    // the one credential IDs embed — a drift that would read as "no such
    // credential", silently and totally.
    assert_eq!(
        on_demand::rp_id_tag(b"example.com").to_vec(),
        vec![
            0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11, 0x80, 0x34,
            0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab, 0x13, 0xd2, 0x12, 0x55,
            0x86, 0xce, 0x19, 0x47,
        ]
    );
    assert_ne!(
        on_demand::rp_id_tag(b"example.com"),
        on_demand::rp_id_tag(b"example.co"),
        "a one-character RP difference must change the tag"
    );
}

// ---------------------------------------------------------------------------
// The seam US-1551 has to fill
// ---------------------------------------------------------------------------

#[test]
fn the_seam_answers_with_exactly_one_slot() {
    // A check that the seam has the shape US-1551 needs. [`SlotLocator::locate`]
    // returns one [`Slot`], so a locator has no way to hand a caller a
    // candidate list, and "one decryption per lookup" is structural rather than
    // a loop that might run twice. An implementation may still *choose* to
    // read slots while scanning — which is what a flash-backed index does — but
    // this signature gives it no way to unseal and return plaintext.
    struct SingleAnswer;
    impl SlotLocator for SingleAnswer {
        fn locate(&mut self, _region: &mut dyn KeyRegion, _want: &SlotQuery<'_>) -> Located {
            Located::Found(slot_of(0))
        }
    }

    let mut f = Fixture::build("seam", None);
    let mut window = CredentialWindow::new();
    let mut locator = SingleAnswer;
    reset_counters();

    let id = credential_id_of(0);
    let tag = Fixture::tag_of(0);
    let want = SlotQuery::RpIdTagAndCredentialId { tag: &tag, credential_id: &id };
    let hit = on_demand::load(&mut f.region, &mut locator, &f.key, &want, &mut window)
        .present()
        .expect("slot 0 is occupied");

    assert_eq!(hit.slot(), slot_of(0));
    assert_eq!(on_demand::testing::unseal_attempts(), 1);
    assert_eq!(
        window.as_slice(),
        f.plain[0].as_slice(),
        "a locator naming a slot gets that slot's record and nothing else"
    );
}