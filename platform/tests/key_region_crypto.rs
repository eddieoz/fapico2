//! US-1547, US-1548: one OTP root, two subkeys; and a record that cannot be
//! transplanted between domains, moved between slots, or replayed at a stale
//! generation.
//!
//! # The two claims under test
//!
//! **US-1547** — the index key is a function of the OTP row and the chip id
//! *only*, and it is not the payload key. "A flash dump must be structurally
//! checkable offline with no PIN" (S1) is a property of a function's
//! *signature* as much as of its output, so both halves are asserted here: the
//! derivation reproduces exactly the documented HKDF chain, and a sweep of PIN
//! material which visibly moves the payload key leaves the index key
//! bit-identical. A test that only checked the second would pass against a
//! derivation that had quietly started reading a PIN through some other route;
//! one that only checked the first would pass against a payload key that
//! ignored the PIN entirely.
//!
//! **US-1548** — each of the three transplanted presentations is its own test,
//! because each is its own byte in the AAD. A change to the encoding that
//! dropped the generation would leave the domain and slot cases green, which is
//! exactly the gap `snapshot_crypt::FieldAad` has and this region must not.
//!
//! The four scenario cases are driven through this module's `seal_payload` /
//! `open_payload`, which is the mechanism `record.rs` is required to call. They
//! are deliberately not driven through `record.rs` while the two modules are
//! landing in parallel: a test that re-encodes another author's moving API
//! tests nothing about this story. What `record.rs` has to do to inherit all
//! four cases unchanged is stated in `RecordAad::new`'s doc comment.
//!
//! # The zeroize assertion, and how it is made
//!
//! "The key is cleared when it goes out of scope" is a claim about bytes that
//! are, by then, in freed stack — reading them from a test is unsound. So it
//! is not asserted by reading them either. `crypto::testing` records, from the
//! key types' own `Drop` **after** their explicit zeroize, what the buffer
//! held; the test asserts that record is all zeroes, and that a drop actually
//! happened (otherwise "all zeroes" would be true of an empty vector). The
//! `Drop` body under test is the production one — the device build runs the
//! same two lines with the recording call compiled out.

use fapico2_platform::ckey;
use fapico2_platform::keyregion::crypto::{self, testing as key_witness, KeyDomain, RecordAad};
use fapico2_platform::keyregion::{Slot, TOTAL_SLOTS};
use fapico2_platform::store_v3;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A provisioned-looking OTP key row: not all-zero, because that is the one
/// row the derivation refuses (see `the_zero_otp_row_returns_none_rather_than_halting`).
const OTP: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

const CHIPID: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];

/// The scenario's record body: a FIDO credential's private key, or close
/// enough for a byte-order argument.
const PLAINTEXT: &[u8] = b"the private key";

/// A PIN-derived secret, made the way an applet makes one: the house PIN
/// chain, which is not this module's business.
///
/// The indirection is the point. `derive_payload_key` takes 32 derived bytes
/// rather than raw PIN characters precisely so it does not have to choose
/// between FIDO's verifier and OATH's (`ckey.rs:577-611`); building the fixture
/// through the real chain keeps the test honest about that.
fn pin_secret(pin: &[u8]) -> [u8; 32] {
    let serial = ckey::serial_hash(b"fapico2 keyregion test flash uid");
    let kbase = ckey::derive_kbase(&OTP, &serial, 0x1234_5678, Some(&[0x5a; 32]))
        .expect("a provisioned OTP row derives a kbase");
    let kver = ckey::derive_kver(&kbase, pin);
    ckey::pin_session(&serial, &kver)
}

fn slot(n: u16) -> Slot {
    Slot::new(n).expect("slot inside the region")
}

fn payload_key() -> crypto::PayloadKey {
    crypto::derive_payload_key(&OTP, &CHIPID, &pin_secret(b"123456")).expect("payload key")
}

/// A sealed record plus the exact AAD it was sealed against.
struct Sealed {
    bytes: Vec<u8>,
    aad: RecordAad,
}

impl Sealed {
    fn new(key: &crypto::PayloadKey, aad: RecordAad, plaintext: &[u8]) -> Self {
        let mut bytes = vec![0u8; plaintext.len() + crypto::RECORD_OVERHEAD];
        let n = crypto::seal_payload(key, &aad, plaintext, &mut bytes).expect("seal");
        bytes.truncate(n);
        Sealed { bytes, aad }
    }

    /// Present this record to a different header and report whether it opens.
    fn opens_as(&self, key: &crypto::PayloadKey, presented: RecordAad) -> bool {
        let mut out = vec![0u8; self.bytes.len().saturating_sub(crypto::RECORD_OVERHEAD)];
        crypto::open_payload(key, &presented, &self.bytes, &mut out).is_some()
    }

    /// Present it to its own header.
    fn opens_as_itself(&self, key: &crypto::PayloadKey) -> bool {
        self.opens_as(key, self.aad)
    }
}

// ---------------------------------------------------------------------------
// US-1547 — the index key does not depend on the PIN
// ---------------------------------------------------------------------------

#[test]
fn the_index_key_is_hkdf_over_the_otp_row_and_chip_id_only() {
    // The root is `store_v3::derive_store_key` and nothing else. Asserting
    // byte-identity against that function is what makes S7 mechanical: this
    // module cannot have grown a second OTP-rooted derivation without this
    // test changing, because the root it derives from is the store's.
    let root = crypto::derive_otp_root(&OTP, &CHIPID).expect("provisioned row derives");
    assert_eq!(*root, store_v3::derive_store_key(&OTP, &CHIPID));

    // And the one-shot index key is exactly one expansion from that root —
    // the same value the from-root entry point produces, so there is no second
    // path into the key.
    let one_shot = crypto::derive_index_key(&OTP, &CHIPID).expect("index key");
    let from_root = crypto::derive_index_key_from_root(&root);
    assert_eq!(*one_shot.as_bytes(), *from_root.as_bytes());

    // Device binding: the chip id is an input, so a dump from one board does
    // not verify on another — and an attacker holding only the chip id cannot
    // compute the key.
    let other_board = crypto::derive_index_key(&OTP, &[0x00; 8]).expect("index key");
    assert_ne!(
        *one_shot.as_bytes(),
        *other_board.as_bytes(),
        "the index key must be bound to the chip id, or a dump is portable"
    );
    let other_row = crypto::derive_index_key(&[0xAB; 32], &CHIPID).expect("index key");
    assert_ne!(
        *one_shot.as_bytes(),
        *other_row.as_bytes(),
        "the index key must be bound to the OTP row"
    );
}

#[test]
fn the_index_key_is_not_a_function_of_any_pin_secret() {
    // `derive_index_key` has no parameter that can hold PIN-derived material;
    // this proves the complement — that a sweep of PIN secrets which visibly
    // moves the payload key leaves the index key bit-identical. If the index
    // key were PIN-gated through any route, this is where it would show.
    let index = crypto::derive_index_key(&OTP, &CHIPID).expect("index key");
    let baseline = *index.as_bytes();

    let mut seen_payloads: Vec<[u8; 32]> = Vec::new();
    for pin in [
        b"1234".as_slice(),
        b"123456",
        b"1234567",
        b"12345678",
        b"000000",
        b"9999999999999999",
        b"",
    ] {
        let secret = pin_secret(pin);
        let payload = crypto::derive_payload_key(&OTP, &CHIPID, &secret).expect("payload key");
        seen_payloads.push(*payload.as_bytes());

        // Re-derive the index key with the same OTP row and chip id. There is
        // no argument through which `secret` could have reached it.
        let again = crypto::derive_index_key(&OTP, &CHIPID).expect("index key");
        assert_eq!(
            *again.as_bytes(),
            baseline,
            "the index key moved with the PIN secret; it is PIN-gated"
        );
    }

    // …and the sweep was not vacuous: distinct PINs really do produce distinct
    // payload keys, so the assertions above had something to see.
    for (i, a) in seen_payloads.iter().enumerate() {
        for (j, b) in seen_payloads.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "two different PINs produced the same payload key");
            }
        }
    }
}

#[test]
fn the_index_key_differs_from_the_payload_key() {
    let index = crypto::derive_index_key(&OTP, &CHIPID).expect("index key");
    let payload = payload_key();
    assert_ne!(
        *index.as_bytes(),
        *payload.as_bytes(),
        "the index and payload keys are the same key, so a PIN-gated payload is readable \
         through the PIN-free index path"
    );

    // Distinct HKDF labels are the mechanism; a different label over a
    // different IKM is belt and braces. Both halves are named so a future edit
    // that collapses either one is visible in review.
    assert_ne!(crypto::INDEX_KEY_INFO, crypto::PAYLOAD_KEY_INFO);
    assert!(crypto::INDEX_KEY_INFO.starts_with(b"fapico2/keyregion/"));
    assert!(crypto::PAYLOAD_KEY_INFO.starts_with(b"fapico2/keyregion/"));

    // Neither label can collide with a label already in the tree. This is the
    // list `ckey.rs` / `store_v3.rs` / `apps/` actually use, written out
    // rather than imported: a test that calls the same constants proves
    // nothing about a collision.
    const EXISTING: [&[u8]; 12] = [
        b"store",
        b"DEVICE/ROOT",
        b"DEVICE/ROOT\0",
        b"DRBG/SEED",
        b"PIN/VERIFY",
        b"PIN/TOKEN",
        b"PIN/ENC",
        b"PIN/ENC2",
        b"OATH/KEYS",
        b"OATH/SEAL-NONCE/v1",
        b"fapico2/ckey/wrap/v1",
        b"PicoKeys Vault enrollment v1",
    ];
    for label in EXISTING {
        for ours in [crypto::INDEX_KEY_INFO, crypto::PAYLOAD_KEY_INFO] {
            assert_ne!(ours, label, "a new HKDF label collides with an existing one");
            // Prefix-extension is what `DEVICE/ROOT` vs `DEVICE/ROOT\0`
            // already shows this tree cares about.
            assert!(
                !label.starts_with(ours) && !ours.starts_with(label),
                "one label is a prefix of the other ({label:?} / {ours:?})"
            );
        }
    }
}

#[test]
fn the_zero_otp_row_returns_none_rather_than_halting() {
    // The one input the derivation refuses. A constant row would make the
    // index key a function of the chip id alone — a keystream any attacker
    // computes offline, which is what `ckey::derive_drbg_seed`
    // (`ckey.rs:244`) refuses for the same reason.
    let zero = [0u8; 32];

    // `None`, not a panic and not a halt: this function returning is the whole
    // failure behaviour. If it panicked, this line would not be reached and
    // the test binary would report a failure — which is the assertion.
    assert!(crypto::derive_otp_root(&zero, &CHIPID).is_none());
    assert!(crypto::derive_index_key(&zero, &CHIPID).is_none());
    assert!(crypto::derive_payload_key(&zero, &CHIPID, &pin_secret(b"1234")).is_none());

    // S10: a device that derives nothing must reach the same structural
    // surface as one that derives everything. The region is *empty*, not
    // *absent*: AADs still build, slots still enumerate, nothing halted.
    assert_eq!(RecordAad::new(KeyDomain::Fido, slot(0), 0).as_bytes().len(), crypto::AAD_LEN);
    assert!(Slot::new(0).is_some());
    assert!(Slot::new(TOTAL_SLOTS as u16 - 1).is_some());

    // And the refusal is *only* about the zero row: one non-zero byte is
    // enough, which is the shape a factory part written once has.
    let mut one_byte = [0u8; 32];
    one_byte[31] = 1;
    assert!(crypto::derive_index_key(&one_byte, &CHIPID).is_some());
}

#[test]
fn the_index_path_reads_a_dump_with_no_pin() {
    // The S1 requirement as a round trip: seal an index record, unseal it
    // knowing only the OTP row and the chip id. No PIN, no presence, and no
    // `pin_secret` anywhere in this test.
    let key = crypto::derive_index_key(&OTP, &CHIPID).expect("index key");
    let aad = RecordAad::new(KeyDomain::Fido, slot(7), 12);
    let mut sealed = vec![0u8; PLAINTEXT.len() + crypto::RECORD_OVERHEAD];
    let n = crypto::seal_index_record(&key, &aad, PLAINTEXT, &mut sealed).expect("seal");
    assert_eq!(n, sealed.len(), "the sealed length is plaintext + the AEAD overhead");

    // Deterministic: the same content re-seals byte-identically, which is what
    // keeps an unchanged index entry from being rewritten.
    let mut again = vec![0u8; sealed.len()];
    let n2 = crypto::seal_index_record(&key, &aad, PLAINTEXT, &mut again).expect("seal");
    assert_eq!(&sealed[..n], &again[..n2]);

    let mut out = vec![0u8; PLAINTEXT.len()];
    let len = crypto::open_index_record(&key, &aad, &sealed, &mut out).expect("unseal");
    assert_eq!(&out[..len], PLAINTEXT);
}

// ---------------------------------------------------------------------------
// US-1548 — a record cannot be transplanted or replayed
// ---------------------------------------------------------------------------

/// The scenario's "given": a valid record sealed for domain FIDO, slot 7,
/// generation 12.
fn record_for_fido_slot_7_generation_12(key: &crypto::PayloadKey) -> Sealed {
    Sealed::new(key, RecordAad::new(KeyDomain::Fido, slot(7), 12), PLAINTEXT)
}

#[test]
fn it_does_not_unseal_as_domain_oath() {
    let key = payload_key();
    let sealed = record_for_fido_slot_7_generation_12(&key);

    assert!(
        !sealed.opens_as(&key, RecordAad::new(KeyDomain::Oath, slot(7), 12)),
        "a record sealed for domain FIDO unsealed as domain OATH — the domain is not bound"
    );
}

#[test]
fn it_does_not_unseal_as_slot_8() {
    let key = payload_key();
    let sealed = record_for_fido_slot_7_generation_12(&key);

    assert!(
        !sealed.opens_as(&key, RecordAad::new(KeyDomain::Fido, slot(8), 12)),
        "a record sealed for slot 7 unsealed as slot 8 — the slot is not bound"
    );
}

#[test]
fn it_does_not_unseal_as_generation_11() {
    let key = payload_key();
    let sealed = record_for_fido_slot_7_generation_12(&key);

    // The replay case, and the byte the `FieldAad` precedent is missing:
    // `snapshot_crypt.rs` binds slot, scope and credential id but no
    // generation, so a record written at generation 11 would unseal over the
    // generation-12 record that replaced it.
    assert!(
        !sealed.opens_as(&key, RecordAad::new(KeyDomain::Fido, slot(7), 11)),
        "a generation-12 record unsealed as generation 11 — the generation is not bound"
    );
}

#[test]
fn it_unseals_under_its_own_domain_slot_and_generation() {
    // The last line of the scenario, and it is a separate test: a set of
    // transplants that all "fail" because sealing never worked would be green.
    let key = payload_key();
    let sealed = record_for_fido_slot_7_generation_12(&key);
    assert!(sealed.opens_as_itself(&key));

    let mut out = vec![0u8; PLAINTEXT.len()];
    let len =
        crypto::open_payload(&key, &sealed.aad, &sealed.bytes, &mut out).expect("unseal");
    assert_eq!(&out[..len], PLAINTEXT);
}

#[test]
fn a_record_sealed_under_another_pin_does_not_unseal() {
    // The key half of US-1548, as distinct from the AAD half: the same header,
    // the same slot, the same generation, and a different PIN secret. Nothing
    // in the AAD differs here — the tag fails on the key, which is why the
    // derivation has to keep the two keys apart at all.
    let sealed = record_for_fido_slot_7_generation_12(&payload_key());
    let wrong_pin =
        crypto::derive_payload_key(&OTP, &CHIPID, &pin_secret(b"654321")).expect("payload key");

    assert!(
        !sealed.opens_as_itself(&wrong_pin),
        "a record opened under a different PIN's payload key"
    );
}

#[test]
fn a_failed_unseal_leaves_no_plaintext_behind() {
    // GCM decrypts in place, so at the moment the tag fails the output buffer
    // holds attacker-chosen bytes (`ckey.rs:533-541`, Appendix A M-5). They
    // must not survive into the caller's hands.
    let key = payload_key();
    let sealed = record_for_fido_slot_7_generation_12(&key);

    let mut out = vec![0xffu8; PLAINTEXT.len()];
    let opened =
        crypto::open_payload(&key, &RecordAad::new(KeyDomain::Fido, slot(8), 12), &sealed.bytes, &mut out);
    assert!(opened.is_none());
    assert!(
        out.iter().all(|&b| b == 0),
        "a failed unseal left {out:02x?} in the caller's buffer"
    );
}

#[test]
fn the_record_aad_is_exactly_these_eleven_bytes() {
    // The byte order is authenticated data. A reordering compiles, round-trips
    // fine, and silently invalidates every record already written to the
    // region — so it is pinned here to the exact string, once.
    let aad = RecordAad::new(KeyDomain::Fido, slot(7), 12);
    assert_eq!(aad.as_bytes().len(), 11);
    assert_eq!(
        aad.as_bytes(),
        &[
            b'K', b'R', b'0', b'1', // AAD_MAGIC — version + separation
            0x01, // KeyDomain::Fido.tag()
            0x07, 0x00, // slot 7, little-endian
            0x0c, 0x00, 0x00, 0x00, // generation 12, little-endian
        ]
    );

    // Little-endian is the tree's rule for flash-resident scalars, and this
    // test is what keeps a big-endian "improvement" out.
    let big = RecordAad::new(KeyDomain::Oath, slot(0x0102), 0x0304_0506);
    assert_eq!(&big.as_bytes()[5..7], &[0x02u8, 0x01]);
    assert_eq!(&big.as_bytes()[7..11], &[0x06u8, 0x05, 0x04, 0x03]);

    // Cross-AEAD separation: this prefix is what stops a keyregion record
    // being presented to a store-v3 AEAD (whose per-entry AAD begins "PS3F")
    // or to a PKOR one (which begins "PKOR") as a byte-identical AAD.
    assert_ne!(aad.as_bytes()[..4], store_v3::PARTITION_IMAGE_MAGIC_V3.to_le_bytes());
    assert_ne!(aad.as_bytes()[..4], *b"PKOR");
    assert_ne!(aad.as_bytes()[..4], *b"OATH");

    // Every field is bound: changing any one of the three changes the bytes.
    assert_ne!(aad.as_bytes(), RecordAad::new(KeyDomain::Oath, slot(7), 12).as_bytes());
    assert_ne!(aad.as_bytes(), RecordAad::new(KeyDomain::Fido, slot(8), 12).as_bytes());
    assert_ne!(aad.as_bytes(), RecordAad::new(KeyDomain::Fido, slot(7), 11).as_bytes());
}

#[test]
fn an_unknown_domain_tag_decodes_to_nothing() {
    // A record written by an applet this firmware does not have must not be
    // read as one it does: `from_tag` returns `None`, and a caller that
    // defaulted here would authenticate an unknown applet's record as FIDO.
    assert_eq!(KeyDomain::from_tag(0), None);
    assert_eq!(KeyDomain::from_tag(3), None);
    assert_eq!(KeyDomain::from_tag(0xff), None);
    assert_eq!(KeyDomain::from_tag(KeyDomain::Fido.tag()), Some(KeyDomain::Fido));
    assert_eq!(KeyDomain::from_tag(KeyDomain::Oath.tag()), Some(KeyDomain::Oath));
}

#[test]
fn a_generation_change_also_moves_the_nonce() {
    // The AAD is the rollback defence; the nonce digest covers the header as
    // well, so a re-seal at a new generation cannot reuse the old
    // `(key, nonce)` pair either. Both are needed: the AAD stops the replay,
    // the nonce keeps two records from sharing a GCM counter.
    let key = payload_key();
    let at_12 = Sealed::new(&key, RecordAad::new(KeyDomain::Fido, slot(7), 12), PLAINTEXT);
    let at_11 = Sealed::new(&key, RecordAad::new(KeyDomain::Fido, slot(7), 11), PLAINTEXT);
    let at_12_again = Sealed::new(&key, RecordAad::new(KeyDomain::Fido, slot(7), 12), PLAINTEXT);

    assert_ne!(
        &at_12.bytes[..crypto::NONCE_LEN],
        &at_11.bytes[..crypto::NONCE_LEN],
        "two generations of one record reused a GCM nonce"
    );
    assert_eq!(at_12.bytes, at_12_again.bytes, "the nonce must be a function of its inputs");
}

// ---------------------------------------------------------------------------
// Key lifetime
// ---------------------------------------------------------------------------

#[test]
fn a_key_is_zeroized_when_it_goes_out_of_scope() {
    key_witness::clear();
    assert!(
        key_witness::dropped_keys().is_empty(),
        "the witness must start empty, or this test proves nothing"
    );

    let index = crypto::derive_index_key(&OTP, &CHIPID).expect("index key");
    let payload = payload_key();
    // Both keys are live and non-zero right now — so a witness that observed
    // zeroes could not have observed a buffer that was never populated.
    assert!(
        index.as_bytes().iter().any(|&b| b != 0),
        "the index key buffer is already zero before drop, so the zeroize assertion is vacuous"
    );
    assert!(payload.as_bytes().iter().any(|&b| b != 0));

    drop(index);
    drop(payload);

    let dropped = key_witness::dropped_keys();
    assert_eq!(
        dropped.len(),
        2,
        "expected one witness entry per key; the Drop path under test did not run"
    );
    for (i, bytes) in dropped.iter().enumerate() {
        assert!(
            bytes.iter().all(|&b| b == 0),
            "key {i} still held {bytes:02x?} when it went out of scope"
        );
    }

    // And a key derived again afterwards is a normal key: the zeroize is on
    // the way out, not on the value.
    key_witness::clear();
    let after = crypto::derive_index_key(&OTP, &CHIPID).expect("index key");
    assert!(after.as_bytes().iter().any(|&b| b != 0));
    drop(after);
    assert!(key_witness::dropped_keys()[0].iter().all(|&b| b == 0));
}

#[test]
fn a_key_owns_a_droppable_buffer_and_hands_out_only_a_borrow() {
    // The structural half of the zeroize claim, as distinct from the observed
    // half above: a type whose storage is a `Zeroizing` is `needs_drop`, and
    // that is what makes the clearing in `Drop` reachable at all. Without it
    // the key would be plain bytes that merely happen to look zeroed when the
    // stack is reused.
    assert!(
        core::mem::needs_drop::<crypto::IndexKey>(),
        "IndexKey owns no droppable storage, so nothing is cleared when it goes out of scope"
    );
    assert!(core::mem::needs_drop::<crypto::PayloadKey>());

    // `as_bytes` borrows: the key cannot outlive the borrow, and there is no
    // accessor that hands out an owned copy to keep. (`Copy`, `Clone` and
    // `Debug` are deliberately not implemented; their absence cannot be
    // asserted from inside a file that has to compile, so it is a review
    // obligation — and `cargo doc` shows the resulting API surface.)
    let key = crypto::derive_index_key(&OTP, &CHIPID).expect("index key");
    let borrowed: &[u8; 32] = key.as_bytes();
    assert_ne!(*borrowed, OTP);
    assert_ne!(&borrowed[..8], &CHIPID);
    assert_eq!(borrowed.len(), crypto::KEY_LEN);
}