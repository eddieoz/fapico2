//! US-1542 + US-1549: the record codec and its fail-closed read path.
//!
//! Two gherkin scenarios, and the properties they stand on:
//!
//! * *"a record round-trips and a flipped bit is caught"* — the header layout,
//!   the CRC32 over it, and the refusal to encode a body that does not fit.
//! * *"one corrupt record does not lose the others"* — per-record AES-256-GCM
//!   with every failure mapped onto `SlotRead::Absent` and no partial plaintext
//!   escaping a failed open.
//!
//! # The CRC is written out here rather than imported
//!
//! `record.rs` calls the crate-internal `secure_store::crc32`, which an
//! integration test cannot reach. Rather than re-implement it and call that a
//! check, the tests that need to *forge* a header (a clear commit flag with a
//! correct CRC, a length beyond the slot with a correct CRC) carry their own
//! tableless CRC-32 and assert that the codec accepts what it should accept.
//! That turns the CRC from "the thing under test" into the thing the test uses
//! as a tool, which is the only way both can be checked at once — and a test
//! that calls the same expression as the code is a test that cannot fail for a
//! different reason than the code.

use fapico2_platform::keyregion::record::{self, Domain, Plaintext, RecordHeader, RecordOccupancy};
use fapico2_platform::keyregion::slotmap::{self, Occupancy};
use fapico2_platform::keyregion::{
    Slot, SlotRead, FIDO_RECORD_MAX, FIDO_SLOT_BYTES, OATH_RECORD_MAX, OATH_SLOT_BYTES,
    RECORD_HEADER_BYTES,
};

/// The test key. A fixed constant because these are tests of the *codec*, not
/// of key derivation — `crypto.rs` (US-1548) owns that, and `platform/tests/
/// key_region_crypto.rs` owns its tests.
const KEY: [u8; 32] = [0x5A; 32];

/// A distinct key, for the "sealed under another key" case.
const OTHER_KEY: [u8; 32] = [0xA5; 32];

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn slot(index: u16) -> Slot {
    Slot::new(index).expect("test slot index must be inside the region")
}

fn header(domain: Domain, slot_index: u16, generation: u32) -> RecordHeader {
    RecordHeader::new(domain, slot(slot_index), generation)
}

/// A per-record nonce. Deterministic so a failing test is reproducible; the
/// nonce *policy* is `crypto.rs`'s, and the only property this module needs is
/// that the nonce is 12 bytes and travels inside the sealed body.
fn nonce(seed: u8) -> [u8; record::NONCE_LEN] {
    [seed; record::NONCE_LEN]
}

fn seal(hdr: &RecordHeader, seed: u8, plaintext: &[u8]) -> fapico2_platform::keyregion::Sealed {
    record::seal(hdr, &KEY, &nonce(seed), plaintext).expect("plaintext must fit the slot")
}

/// The whole slot image a record occupies: header, sealed body, `0xFF` padding.
fn image(hdr: &RecordHeader, seed: u8, plaintext: &[u8]) -> Vec<u8> {
    let body = seal(hdr, seed, plaintext);
    record::encode(hdr, &body).expect("sealed body must fit the slot").into_bytes()
}

/// A five-byte plaintext that is unmistakably not its ciphertext, so a test can
/// tell "opened" from "returned the bytes it was handed".
fn plaintext(seed: u8) -> Vec<u8> {
    (0..611u16).map(|i| (i as u8) ^ seed).collect()
}

/// CRC-32 (IEEE 802.3, reflected, poly `0xEDB8_8320`), written out rather than
/// imported — see the module docs. Used only to forge headers a test needs to
/// be *internally* consistent.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Rewrite a slot image's CRC so the header is internally consistent again —
/// the tool for isolating one header rule (flag, length) from the CRC.
fn refresh_crc(image: &mut [u8]) {
    let crc = crc32(&image[..record::OFF_CRC]);
    image[record::OFF_CRC..record::OFF_CRC + 4].copy_from_slice(&crc.to_le_bytes());
}

// ---------------------------------------------------------------------------
// US-1542 — "every field is recovered byte-identically"
// ---------------------------------------------------------------------------

#[test]
fn a_record_round_trips_and_every_field_is_recovered_byte_identically() {
    for (domain, index, generation, seed) in [
        (Domain::Fido, 0u16, 1u32, 0x11u8),
        (Domain::Fido, 7, 65_536, 0x22),
        (Domain::Oath, 959, u32::MAX, 0x33),
        (Domain::Oath, 1, 2, 0x44),
    ] {
        let hdr = header(domain, index, generation);
        let pt = plaintext(seed);
        let sealed = seal(&hdr, seed, &pt);

        // The encoded image is byte-identical to what the region will program.
        let a = record::encode(&hdr, &sealed).expect("encode");
        let b = record::encode(&hdr, &sealed).expect("encode again");
        assert_eq!(a.as_bytes(), b.as_bytes(), "encoding must be a pure function");

        let decoded = match record::decode(slot(index), a.as_bytes()) {
            SlotRead::Present(d) => d,
            other => panic!("a freshly encoded record must decode as Present, got {other:?}"),
        };

        // Every header field, one by one, byte for byte.
        assert_eq!(decoded.header().domain(), hdr.domain(), "domain");
        assert_eq!(decoded.header().slot(), hdr.slot(), "slot");
        assert_eq!(decoded.header().generation(), hdr.generation(), "generation");
        assert_eq!(decoded.header().flags(), hdr.flags(), "flags");
        assert_eq!(*decoded.header(), hdr, "the header is equal as a whole");
        assert_eq!(decoded.header().aad(), hdr.aad(), "the AAD is a pure function");

        // And the body, byte for byte: the decoded bytes are the sealed ones,
        // not the plaintext.
        assert_eq!(decoded.body().as_bytes(), sealed.as_bytes(), "sealed body");
        assert_eq!(decoded.len(), record::RECORD_HEADER_LEN + sealed.len(), "encoded length");
    }
}

#[test]
fn the_header_is_written_at_the_offsets_the_layout_states() {
    let hdr = header(Domain::Oath, 0x0102, 0x0304_0506);
    let pt = plaintext(0x5A);
    let sealed = seal(&hdr, 0x5A, &pt);
    let img = record::encode(&hdr, &sealed).expect("encode").into_bytes();

    assert_eq!(&img[0..2], &record::RECORD_MAGIC_V1.to_le_bytes(), "magic at 0");
    assert_eq!(img[2], Domain::Oath.as_u8(), "domain at 2");
    assert_eq!(img[3], record::FLAG_SEALED, "flags at 3");
    assert_eq!(&img[4..6], &0x0102u16.to_le_bytes(), "slot at 4");
    assert_eq!(&img[6..10], &0x0304_0506u32.to_le_bytes(), "generation at 6");
    assert_eq!(
        &img[10..12],
        &(sealed.len() as u16).to_le_bytes(),
        "body length at 10"
    );
    assert_eq!(
        &img[12..16],
        &crc32(&img[..12]).to_le_bytes(),
        "the CRC covers bytes 0..12 and is written at 12"
    );

    // The whole slot is programmed: the tail is erased flash, not zeroes, and
    // the image is a whole number of 256-byte flash pages.
    assert_eq!(img.len(), record::SLOT_BYTES);
    assert!(record::SLOT_BYTES.is_multiple_of(256), "a slot image is whole flash pages");
    assert!(
        img[record::RECORD_HEADER_LEN + sealed.len()..].iter().all(|b| *b == record::ERASED_BYTE),
        "the tail is the erased value, so 'never programmed' stays visible on the medium"
    );
}

#[test]
fn the_codec_fits_the_region_the_geometry_derived() {
    // The relation `mod.rs:172-180` asserts, restated here as a test: the body
    // bound must hold both domains' largest *measured* record, or the encoder
    // would be the thing that truncates a credential.
    assert!(
        record::MAX_BODY_BYTES as u32 >= FIDO_RECORD_MAX,
        "the slot cannot hold the largest FIDO record ({FIDO_RECORD_MAX})"
    );
    assert!(
        record::MAX_BODY_BYTES as u32 >= OATH_RECORD_MAX,
        "the slot cannot hold the largest OATH record ({OATH_RECORD_MAX})"
    );
    assert_eq!(record::RECORD_HEADER_LEN, RECORD_HEADER_BYTES as usize);
    assert_eq!(record::SLOT_BYTES, FIDO_SLOT_BYTES as usize);
    assert!(OATH_SLOT_BYTES as usize <= record::SLOT_BYTES);
    assert_eq!(
        record::MAX_BODY_BYTES,
        record::SLOT_BYTES - RECORD_HEADER_BYTES as usize,
        "header + body must tile the slot exactly"
    );
}

#[test]
fn the_largest_measured_fido_record_fits_one_slot() {
    // `FIDO_RECORD_MAX` is a *sealed* length (`mod.rs:57-67`), so the plaintext
    // that produces it is that minus the AEAD framing. If this ever fails, a
    // maximal credential no longer fits a slot and the stride is wrong.
    let hdr = header(Domain::Fido, 3, 1);
    let pt = vec![0xC3u8; FIDO_RECORD_MAX as usize - record::SEALED_OVERHEAD];
    let sealed = record::seal(&hdr, &KEY, &nonce(1), &pt).expect("the measured maximum must seal");
    assert_eq!(sealed.len(), FIDO_RECORD_MAX as usize);
    let img = record::encode(&hdr, &sealed).expect("the measured maximum must encode");
    assert_eq!(img.as_bytes().len(), record::SLOT_BYTES, "the image is a whole slot");
    assert_eq!(
        img.len(),
        record::RECORD_HEADER_LEN + FIDO_RECORD_MAX as usize,
        "and the record ends where the padding begins"
    );
    assert!(matches!(record::decode(slot(3), img.as_bytes()), SlotRead::Present(_)));
}

// ---------------------------------------------------------------------------
// US-1542 — "flipping one header bit fails the CRC"
// ---------------------------------------------------------------------------

#[test]
fn flipping_one_header_bit_fails_the_crc() {
    let hdr = header(Domain::Fido, 12, 300);
    let good = image(&hdr, 0x31, &plaintext(0x31));

    // Every bit of every header byte, in turn. A CRC-32 detects all single-bit
    // errors, so this is exhaustive for one flip; the named cases below say
    // *which* field each byte belongs to, so a failure names a field.
    for byte in 0..record::RECORD_HEADER_LEN {
        for bit in 0..8 {
            let mut img = good.clone();
            img[byte] ^= 1 << bit;
            assert!(
                matches!(record::decode(slot(12), &img), SlotRead::Absent),
                "flipping bit {bit} of header byte {byte} ({} offset) must not decode",
                field_name(byte)
            );
        }
    }

    // The same sweep, field by field, so a regression names the field rather
    // than an offset.
    for (name, first, _) in fields() {
        let mut img = good.clone();
        img[first] ^= 0x01;
        assert!(
            matches!(record::decode(slot(12), &img), SlotRead::Absent),
            "a flipped bit in the {name} field must not decode"
        );
    }
}

/// The header's fields as `(name, offset, width)` — the sweep above, named, so
/// a regression reports a field rather than an offset.
fn fields() -> [(&'static str, usize, usize); 7] {
    [
        ("magic", record::OFF_MAGIC, 2),
        ("domain", record::OFF_DOMAIN, 1),
        ("flags", record::OFF_FLAGS, 1),
        ("slot", record::OFF_SLOT, 2),
        ("generation", record::OFF_GENERATION, 4),
        ("body length", record::OFF_BODY_LEN, 2),
        ("crc", record::OFF_CRC, 4),
    ]
}

fn field_name(byte: usize) -> &'static str {
    for (name, off, width) in fields() {
        if (off..off + width).contains(&byte) {
            return name;
        }
    }
    "padding"
}

#[test]
fn a_recomputed_crc_does_not_rescue_a_flipped_field() {
    // The forgery store_v3 was hardened against (`store_v3.rs:29-35`): an
    // unkeyed CRC is not a defence against anyone who can recompute it, which
    // is why the body is sealed. So a header whose CRC has been *correctly*
    // recomputed over a corrupted field must still be refused — by the rule
    // that field violates, not by the CRC.
    let hdr = header(Domain::Fido, 12, 300);
    let good = image(&hdr, 0x31, &plaintext(0x31));

    // Slot 12 rewritten to claim slot 13, CRC refreshed — a forgery that is
    // internally consistent in every way the header can be. It decodes (the
    // structure is intact, and the allocator is right to call the slot
    // occupied), and it does not *open*: the body was sealed under an AAD that
    // named slot 12, and the tag is what refuses it.
    let mut moved = good.clone();
    moved[record::OFF_SLOT..record::OFF_SLOT + 2].copy_from_slice(&13u16.to_le_bytes());
    refresh_crc(&mut moved);
    assert!(
        matches!(record::decode(slot(13), &moved), SlotRead::Present(_)),
        "the header of a moved record is still a valid header"
    );
    assert!(
        matches!(record::read(slot(13), &moved, &KEY), SlotRead::Absent),
        "a record moved to another slot must not open there"
    );

    // An unknown domain byte with a valid CRC.
    let mut alien = good.clone();
    alien[record::OFF_DOMAIN] = 0x7F;
    refresh_crc(&mut alien);
    assert!(
        matches!(record::decode(slot(12), &alien), SlotRead::Absent),
        "an unassigned domain byte must not be parsed as FIDO"
    );
}

#[test]
fn a_header_whose_commit_flag_is_clear_reads_as_absent() {
    // An interrupted sector commit leaves records that are present but
    // incomplete (`mod.rs:119-132`). The flag check runs before the CRC, so
    // this case is isolated by refreshing the CRC afterwards: what refuses it
    // is the flag, not the checksum.
    let hdr = header(Domain::Fido, 5, 9);
    let mut img = image(&hdr, 0x41, &plaintext(0x41));
    img[record::OFF_FLAGS] = 0x00;
    refresh_crc(&mut img);
    assert!(matches!(record::decode(slot(5), &img), SlotRead::Absent));

    // And a flag bit this build does not know is a different format, not a v1
    // record with an extra bit set.
    let mut future = image(&hdr, 0x41, &plaintext(0x41));
    future[record::OFF_FLAGS] = record::FLAG_SEALED | 0x80;
    refresh_crc(&mut future);
    assert!(matches!(record::decode(slot(5), &future), SlotRead::Absent));
}

#[test]
fn a_body_length_beyond_the_slot_reads_as_absent() {
    // 0xFFFF body bytes in a 1,024-byte slot, with a valid CRC: the bound is
    // checked before anything slices by the length, so this cannot index past
    // the slot.
    let hdr = header(Domain::Fido, 6, 1);
    let mut img = image(&hdr, 0x51, &plaintext(0x51));
    img[record::OFF_BODY_LEN..record::OFF_BODY_LEN + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    refresh_crc(&mut img);
    assert!(matches!(record::decode(slot(6), &img), SlotRead::Absent));

    // One byte over the body bound, likewise.
    let mut over = image(&hdr, 0x51, &plaintext(0x51));
    let too_big = (record::MAX_BODY_BYTES + 1) as u16;
    over[record::OFF_BODY_LEN..record::OFF_BODY_LEN + 2].copy_from_slice(&too_big.to_le_bytes());
    refresh_crc(&mut over);
    assert!(matches!(record::decode(slot(6), &over), SlotRead::Absent));
}

#[test]
fn an_erased_slot_reads_as_absent_and_a_short_buffer_reads_as_a_fault() {
    let erased = vec![record::ERASED_BYTE; record::SLOT_BYTES];
    let raw: slotmap::SlotImage = erased.clone().try_into().unwrap();
    assert!(slotmap::is_erased(&raw));
    assert!(
        matches!(record::decode(slot(0), &erased), SlotRead::Absent),
        "an erased slot is absence, not a record"
    );

    // A buffer shorter than a slot is the one thing that is *not* a fact about
    // the data: the transport returned less than it promised, and that must
    // never be memoized as "no credentials here" (`mod.rs:379-383`).
    let short = &erased[..record::SLOT_BYTES - 1];
    match record::decode(slot(0), short) {
        SlotRead::Fault(_) => {}
        other => panic!("a short buffer is a fault, got {other:?}"),
    }
    assert!(record::decode(slot(0), short).is_fault());
}

// ---------------------------------------------------------------------------
// US-1542 — "a body too large for the stride is refused at encode"
// ---------------------------------------------------------------------------

#[test]
fn a_body_too_large_for_the_stride_is_refused_at_encode() {
    let hdr = header(Domain::Fido, 0, 1);
    let mut out = vec![0u8; record::SLOT_BYTES];

    // One byte over the body bound. Refused, not truncated: a caller cannot
    // tell a truncated credential from a short one, and a credential is not
    // something to lose quietly.
    let too_big = vec![0xABu8; record::MAX_BODY_BYTES + 1];
    match record::encode_into(&hdr, &too_big, &mut out) {
        Err(record::RecordError::BodyTooLarge { len, max }) => {
            assert_eq!(len, record::MAX_BODY_BYTES + 1);
            assert_eq!(max, record::MAX_BODY_BYTES);
        }
        other => panic!("an oversized body must be refused, got {other:?}"),
    }
    assert!(
        out.iter().all(|b| *b == 0),
        "a refused encode must not have written a partial record"
    );

    // Exactly at the bound is accepted — the bound is inclusive, or the
    // geometry's own margin arithmetic would be a fiction.
    let at_bound = vec![0xABu8; record::MAX_BODY_BYTES];
    let n = record::encode_into(&hdr, &at_bound, &mut out).expect("the bound itself must encode");
    assert_eq!(n, record::RECORD_HEADER_LEN + record::MAX_BODY_BYTES);
    assert!(out[n..].iter().all(|b| *b == record::ERASED_BYTE));

    // The same refusal on the sealing path, where the bound applies to the
    // *sealed* length: the AEAD overhead is charged against the same budget.
    let pt_too_big = vec![0xCDu8; record::MAX_BODY_BYTES - record::SEALED_OVERHEAD + 1];
    assert!(matches!(
        record::seal(&hdr, &KEY, &nonce(1), &pt_too_big),
        Err(record::RecordError::BodyTooLarge { .. })
    ));
    let pt_at_bound = vec![0xCDu8; record::MAX_BODY_BYTES - record::SEALED_OVERHEAD];
    assert!(record::seal(&hdr, &KEY, &nonce(1), &pt_at_bound).is_ok());

    // And a slot buffer smaller than a slot is refused too: the padding is part
    // of the image, so a short buffer would have to be padded with something
    // that is not erased flash.
    let mut small = vec![0u8; record::SLOT_BYTES - 1];
    match record::encode_into(&hdr, b"x", &mut small) {
        Err(record::RecordError::BufferTooSmall { need, have }) => {
            assert_eq!(need, record::SLOT_BYTES);
            assert_eq!(have, record::SLOT_BYTES - 1);
        }
        other => panic!("a short slot buffer must be refused, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// US-1549 — per-record AEAD, fail closed
// ---------------------------------------------------------------------------

#[test]
fn a_flipped_bit_in_the_sealed_body_fails_authentication() {
    let hdr = header(Domain::Fido, 4, 77);
    let pt = plaintext(0x61);
    let sealed = seal(&hdr, 0x61, &pt);

    // The ciphertext must not be the plaintext — otherwise "it authenticated"
    // would prove nothing.
    assert_ne!(
        &sealed.as_bytes()[record::NONCE_LEN..sealed.len() - record::TAG_LEN],
        &pt[..],
        "the body must be encrypted, not merely framed"
    );

    let good = image(&hdr, 0x61, &pt);
    assert!(matches!(record::read(slot(4), &good, &KEY), SlotRead::Present(_)));

    // Each region of the sealed blob, in turn: the nonce (a different nonce
    // yields different keystream), the ciphertext, and the tag.
    let ct_start = record::OFF_CRC + 4 + record::NONCE_LEN;
    for (name, at) in [
        ("nonce", record::RECORD_HEADER_LEN),
        ("ciphertext", ct_start),
        ("tag", ct_start + sealed.len() - record::SEALED_OVERHEAD),
    ] {
        let mut img = good.clone();
        img[at] ^= 0x01;
        assert!(
            matches!(record::read(slot(4), &img, &KEY), SlotRead::Absent),
            "a flipped bit in the {name} must not authenticate"
        );
    }

    // The wrong key, and a key one bit away, are the same refusal.
    assert!(matches!(record::read(slot(4), &good, &OTHER_KEY), SlotRead::Absent));
    let mut near = KEY;
    near[0] ^= 0x01;
    assert!(matches!(record::read(slot(4), &good, &near), SlotRead::Absent));

    // A truncated blob is not a record body either.
    let mut short = good.clone();
    let len = record::RECORD_HEADER_LEN + sealed.len() - 1;
    short[record::RECORD_HEADER_LEN..len].copy_from_slice(&sealed.as_bytes()[..sealed.len() - 1]);
    short[len..].fill(record::ERASED_BYTE);
    refresh_crc(&mut short);
    assert!(matches!(record::read(slot(4), &short, &KEY), SlotRead::Absent));
}

#[test]
fn one_corrupt_record_does_not_lose_the_others() {
    // Five stored credentials, one with a corrupted sealed body.
    let specs: [(Domain, u16, u32, u8); 5] = [
        (Domain::Fido, 0, 1, 0x01),
        (Domain::Fido, 1, 2, 0x02),
        (Domain::Fido, 2, 3, 0x03), // this one is corrupted below
        (Domain::Oath, 3, 1, 0x04),
        (Domain::Fido, 4, 9_001, 0x05),
    ];
    let corrupted = 2usize;

    let mut slots: Vec<Vec<u8>> = Vec::new();
    for (domain, index, generation, seed) in specs {
        slots.push(image(&header(domain, index, generation), seed, &plaintext(seed)));
    }
    // Corrupt the sealed *body* only — the header and its CRC stay valid, which
    // is the interesting case: the record looks occupied to the allocator, and
    // it is the AEAD that has to be the one to refuse it.
    let body_at = record::RECORD_HEADER_LEN + record::NONCE_LEN + 3;
    slots[corrupted][body_at] ^= 0x40;

    for (i, spec) in specs.iter().enumerate() {
        let (domain, index, generation, seed) = *spec;
        let hdr = header(domain, index, generation);
        let pt = plaintext(seed);
        let outcome = record::read(slot(index), &slots[i], &KEY);

        if i == corrupted {
            assert!(
                matches!(outcome, SlotRead::Absent),
                "the corrupted record must read as absent, not as a fault and not as data"
            );
            // …and it still decodes: the header is intact, which is exactly
            // why the tag is what has to catch this. A store that relied on the
            // CRC alone would hand this record on.
            assert!(
                matches!(record::decode(slot(index), &slots[i]), SlotRead::Present(_)),
                "the header survives; the body is what fails"
            );
            assert_eq!(hdr.domain(), domain, "the header is still the record's own");
            assert_eq!(hdr.generation(), generation);
        } else {
            let opened = match outcome {
                SlotRead::Present(p) => p,
                other => panic!("record {i} (slot {index}) must still be usable, got {other:?}"),
            };
            assert_eq!(opened.as_slice(), &pt[..], "record {i} opened byte-identically");
        }
    }

    // And the allocator's view: the corrupt slot is still *occupied* (its
    // header is valid, so it must not be handed to another credential), while
    // its plaintext is unreachable. Occupancy and usability are different
    // questions, and the codec answers them separately.
    let probe = RecordOccupancy;
    let raw: slotmap::SlotImage = slots[corrupted].clone().try_into().unwrap();
    assert!(probe.occupied(&raw), "a corrupt record must not leak its slot");
    assert_eq!(probe.generation(&raw), Some(specs[corrupted].2));
}

#[test]
fn a_failed_unseal_leaves_no_partial_plaintext() {
    let hdr = header(Domain::Fido, 8, 3);
    let pt = plaintext(0x71);
    let sealed = seal(&hdr, 0x71, &pt);

    // A scratch buffer that has already held a real credential...
    let mut scratch = Plaintext::scratch(pt.len());
    let n = record::open_into(&hdr, &KEY, &sealed, &mut scratch).expect("the good record opens");
    assert_eq!(&scratch.as_slice()[..n], &pt[..], "the plaintext is there to be leaked");
    assert!(scratch.as_slice().iter().any(|b| *b != 0), "precondition: the buffer is not empty");

    // …must not keep a single byte of it after a failed unseal into the same
    // buffer. GCM decrypts before it verifies, so the buffer holds
    // unauthenticated plaintext at the moment the tag is checked; zeroizing it
    // is what makes the failure closed rather than merely reported.
    let mut corrupt_bytes = sealed.as_bytes().to_vec();
    corrupt_bytes[record::NONCE_LEN + 1] ^= 0x80;
    let corrupt = record::testing::sealed_from_bytes(corrupt_bytes);
    assert!(
        record::open_into(&hdr, &KEY, &corrupt, &mut scratch).is_none(),
        "a corrupted body must not open"
    );
    assert!(
        scratch.as_slice().iter().all(|b| *b == 0),
        "a failed unseal must leave nothing readable in the buffer"
    );

    // The same for the other refusals, each of which must also leave a clean
    // buffer rather than whatever GCM wrote on the way to failing.
    let mut too_short = Plaintext::scratch(64);
    assert!(record::open_into(&hdr, &KEY, &sealed, &mut too_short).is_none());
    assert!(too_short.as_slice().iter().all(|b| *b == 0), "buffer too small -> zeroed");

    let mut wrong_key = Plaintext::scratch(pt.len());
    assert!(record::open_into(&hdr, &OTHER_KEY, &sealed, &mut wrong_key).is_none());
    assert!(wrong_key.as_slice().iter().all(|b| *b == 0), "wrong key -> zeroed");

    // And the same for a record presented with an AAD it was not sealed under:
    // the tag fails, and the buffer is clean.
    let mut transplanted = Plaintext::scratch(pt.len());
    assert!(record::open_into(&header(Domain::Fido, 9, 3), &KEY, &sealed, &mut transplanted).is_none());
    assert!(transplanted.as_slice().iter().all(|b| *b == 0), "wrong slot -> zeroed");
}

#[test]
fn a_record_cannot_be_replayed_into_another_slot_generation_or_domain() {
    let hdr = header(Domain::Fido, 21, 500);
    let pt = plaintext(0x81);
    let sealed = seal(&hdr, 0x81, &pt);
    let img = record::encode(&hdr, &sealed).expect("encode").into_bytes();

    assert!(matches!(record::read(slot(21), &img, &KEY), SlotRead::Present(_)));

    // Every one of the three bound fields, changed one at a time. Each is a
    // refusal at the AEAD, and each is a refusal of a record that is
    // structurally perfect: right magic, right CRC, right length.
    for (name, other) in [
        ("slot", header(Domain::Fido, 22, 500)),
        ("generation", header(Domain::Fido, 21, 499)),
        ("domain", header(Domain::Oath, 21, 500)),
    ] {
        assert_ne!(other.aad(), hdr.aad(), "the {name} must be bound into the AAD");
        assert!(
            matches!(record::open(&other, &KEY, &sealed), SlotRead::Absent),
            "a record presented with a different {name} must not open"
        );
    }
}

#[test]
fn the_allocator_reads_occupancy_and_generation_from_the_header() {
    // `slotmap::Occupancy` asks the codec for the rule; the requirements it
    // states are that an erased slot and a CRC-failed slot are both *free*, and
    // that an occupied slot reports the generation that survives a power cycle.
    let probe = RecordOccupancy;

    let erased: slotmap::SlotImage = vec![record::ERASED_BYTE; record::SLOT_BYTES]
        .try_into()
        .unwrap();
    assert!(!probe.occupied(&erased), "an erased slot is free");
    assert_eq!(probe.generation(&erased), None, "an erased slot has no generation");

    let hdr = header(Domain::Fido, 17, 40_000);
    let good = image(&hdr, 0x91, &plaintext(0x91));
    let raw: slotmap::SlotImage = good.clone().try_into().unwrap();
    assert!(probe.occupied(&raw));
    assert_eq!(probe.generation(&raw), Some(40_000), "the generation is durable in the header");

    // A torn write must not leak the slot. This is the requirement slotmap
    // states first (`slotmap.rs:161-165`): on a region whose sector erase
    // rewrites four slots at a time, a CRC-failed slot reported as occupied
    // costs four slots per interrupted commit.
    let mut torn = good.clone();
    torn[9] ^= 0x08; // one bit of the generation
    let raw: slotmap::SlotImage = torn.try_into().unwrap();
    assert!(!probe.occupied(&raw), "a CRC-failed slot is free, not leaked");
    assert_eq!(probe.generation(&raw), None);

    // …and it agrees with the codec's own decode, or "occupied" would mean two
    // different things in one allocator.
    for occupied in [true, false] {
        let img = if occupied {
            good.clone()
        } else {
            vec![record::ERASED_BYTE; record::SLOT_BYTES]
        };
        let raw: slotmap::SlotImage = img.clone().try_into().unwrap();
        let decodes = !matches!(record::decode(slot(17), &img), SlotRead::Absent);
        assert_eq!(probe.occupied(&raw), decodes, "occupancy must agree with decode");
    }
}
