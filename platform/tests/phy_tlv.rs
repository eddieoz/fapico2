//! US-116 host tests: the PHY record TLV codec, walked **one tag at a time**.
//!
//! The framing itself is pinned inline in `src/phy_tlv.rs` (one-byte tag,
//! one-byte length, the 255-byte ceiling, a full buffer refused whole). This
//! file is the per-tag walk the US-114 notes said US-116 still owed, and it is
//! deliberately *not* only a round-trip.
//!
//! # Why a round-trip alone is not a test of a wire format
//!
//! "Encode, decode, get the value back" is satisfied by an encoder whose
//! widths and byte orders are uniformly *wrong* — it agrees with itself. So
//! every case here carries two extra pins, both taken from the **client** and
//! not from this crate:
//!
//! * the exact record bytes, read off `build_rskey_phy_tlv`
//!   (`picoforge/src/hal/fido/mod.rs:1015`), which writes a literal length
//!   constant at every call site (`tlv.push(0x04); tlv.extend_from_slice(&vid.to_be_bytes())`),
//!   and
//! * the declared width, which is the length byte the client pushes for that
//!   tag — `0x04` for VID/PID, `0x02` for options, `0x04` for curves, `0x01`
//!   for every one-byte tag.
//!
//! The client's values are big-endian — `vid.to_be_bytes()`,
//! `opts.to_be_bytes()`, `mask.to_be_bytes()`
//! (`picoforge/src/hal/fido/mod.rs:1027-1029`, `:1056`, `:1111`) — and the
//! values below are chosen so that the little-endian spelling of each is a
//! *different literal*: `0x1209` vs `0x0912`, `0x000A` vs `0x0A00`,
//! `0x0000000A` vs `0x0A000000`. That makes the table a check on the client's
//! byte order rather than on anything this crate does: `encode_record` is
//! byte-opaque and has no endianness of its own to get wrong, so the encoder
//! that would fail is `vendor41::write_phy_record`, which builds the values
//! and is not exercised by this file.
//!
//! The one thing this file does **not** pin is the BER question, and not
//! because the format forbids it — `encode_record` will happily take a
//! 255-byte value under any tag, and the inline
//! `value_length_ceiling_is_255` unit test does exactly that on `0x09`. It is
//! that the widest value the *client* writes is a 33-byte string, well under
//! the 127 where a long form would first appear, so no per-tag case can raise
//! the question and restating it here would only duplicate a test that already
//! holds.

// One module-qualified import rather than eight names. rustfmt orders a
// braced import list differently under style edition 2021 (this workspace's)
// and 2024, and a named list is therefore only ever clean under one of them;
// the module path has no ordering to get wrong.
use fapico2_platform::phy_tlv;
use heapless::Vec as HeaplessVec;

/// Every one of the twelve tags, with the value shape the client uses and the
/// full record it puts on the wire.
struct Case {
    tag: phy_tlv::PhyTag,
    value: &'static [u8],
    /// `tag, len, value…` exactly as `build_rskey_phy_tlv` emits it.
    record: &'static [u8],
    /// The length byte above, restated so a wrong length fails the case even
    /// if `record` were edited to match.
    declared_len: u8,
}

const CASES: &[Case] = &[
    // `tlv.push(RSKEY_PHY_TAG_VIDPID); tlv.push(0x04);` then VID and PID
    // each `to_be_bytes()` — mod.rs:1024-1030.
    Case {
        tag: phy_tlv::PhyTag::VidPid,
        value: &[0x12, 0x09, 0x00, 0x01],
        record: &[0x00, 0x04, 0x12, 0x09, 0x00, 0x01],
        declared_len: 0x04,
    },
    // `tlv.push(0x01); tlv.push(val);` — mod.rs:1033-1036.
    Case {
        tag: phy_tlv::PhyTag::LedGpio,
        value: &[0x04],
        record: &[0x04, 0x01, 0x04],
        declared_len: 0x01,
    },
    // Brightness 100, the top of the range `vendorff::validate` accepts —
    // mod.rs:1039-1042.
    Case {
        tag: phy_tlv::PhyTag::LedBrightness,
        value: &[0x64],
        record: &[0x05, 0x01, 0x64],
        declared_len: 0x01,
    },
    // `tlv.push(0x02); tlv.extend_from_slice(&opts.to_be_bytes());` with
    // LED_DIMMABLE | LED_STEADY — mod.rs:1046-1058. `0x000A` big-endian is
    // `0x00 0x0A`; little-endian would be `0x0A 0x00`.
    Case {
        tag: phy_tlv::PhyTag::Options,
        value: &[0x00, 0x0A],
        record: &[0x06, 0x02, 0x00, 0x0A],
        declared_len: 0x02,
    },
    // mod.rs:1061-1064.
    Case {
        tag: phy_tlv::PhyTag::PresenceTimeout,
        value: &[0x1E],
        record: &[0x08, 0x01, 0x1E],
        declared_len: 0x01,
    },
    // The name plus its trailing NUL: the length is `bytes.len() + 1` and a
    // `0x00` follows the name — mod.rs:1066-1080. "fapico2" is 7 bytes, so
    // the record is 8 long.
    Case {
        tag: phy_tlv::PhyTag::UsbProduct,
        value: b"fapico2\0",
        record: &[0x09, 0x08, 0x66, 0x61, 0x70, 0x69, 0x63, 0x6F, 0x32, 0x00],
        declared_len: 0x08,
    },
    // `tlv.push(0x04); tlv.extend_from_slice(&mask.to_be_bytes());` with
    // SECP256K1 | SECP384R1 = `0x08 | 0x02` — mod.rs:1108-1112. The flag
    // names are `RescueCurves` in
    // `picoforge/src/hal/rescue/constants.rs:400-426`, and the value is chosen
    // as two bits that differ in more than one position so a byte-swapped or
    // nibble-swapped `u32` cannot land on it.
    Case {
        tag: phy_tlv::PhyTag::Curves,
        value: &[0x00, 0x00, 0x00, 0x0A],
        record: &[0x0A, 0x04, 0x00, 0x00, 0x00, 0x0A],
        declared_len: 0x04,
    },
    // CCID | HID | LWIP = 0x01 | 0x04 | 0x10 — mod.rs:1126-1129.
    Case {
        tag: phy_tlv::PhyTag::EnabledUsbItf,
        value: &[0x15],
        record: &[0x0B, 0x01, 0x15],
        declared_len: 0x01,
    },
    // mod.rs:1115-1118.
    Case {
        tag: phy_tlv::PhyTag::LedDriver,
        value: &[0x01],
        record: &[0x0C, 0x01, 0x01],
        declared_len: 0x01,
    },
    // mod.rs:1120-1123.
    Case {
        tag: phy_tlv::PhyTag::LedOrder,
        value: &[0x03],
        record: &[0x0D, 0x01, 0x03],
        declared_len: 0x01,
    },
    // mod.rs:1130-1133.
    Case {
        tag: phy_tlv::PhyTag::LedNum,
        value: &[0x03],
        record: &[0x0E, 0x01, 0x03],
        declared_len: 0x01,
    },
    // Same shape as the product string — mod.rs:1082-1096. "The BLOCO
    // Community" is 19 bytes, so with its NUL the record is 20 (0x14) long.
    Case {
        tag: phy_tlv::PhyTag::UsbManufacturer,
        value: b"The BLOCO Community\0",
        record: &[
            0x0F, 0x14, 0x54, 0x68, 0x65, 0x20, 0x42, 0x4C, 0x4F, 0x43, 0x4F, 0x20, 0x43, 0x6F,
            0x6D, 0x6D, 0x75, 0x6E, 0x69, 0x74, 0x79, 0x00,
        ],
        declared_len: 0x14,
    },
];

#[test]
fn phy_tlv_roundtrip_all_tags() {
    // The walk is over `phy_tlv::PhyTag::ALL`, so a tag dropped from the enum is a
    // dropped case rather than a silently shorter test.
    assert_eq!(
        phy_tlv::PhyTag::ALL.len(),
        CASES.len(),
        "the case table must cover every tag `phy_tlv::PhyTag::ALL` enumerates, or \
         `ALL` and this test disagree about how many tags the protocol has"
    );
    assert_eq!(
        phy_tlv::PhyTag::ALL.map(|t| t.byte()).as_slice(),
        CASES
            .iter()
            .map(|c| c.tag.byte())
            .collect::<HeaplessVec<u8, 16>>()
            .as_slice(),
        "the walk must be in `phy_tlv::PhyTag::ALL` order — the canonical order a \
         full-blob expectation is written against — not just the same set"
    );
    assert_eq!(
        phy_tlv::PhyTag::ALL.as_slice(),
        &CASES
            .iter()
            .map(|c| c.tag)
            .collect::<HeaplessVec<phy_tlv::PhyTag, 16>>(),
        "and a tag listed twice, or in the wrong slot, must not pass as \
         coverage of all twelve"
    );

    for case in CASES {
        let mut out: HeaplessVec<u8, 64> = HeaplessVec::new();
        phy_tlv::encode_record(case.tag, case.value, &mut out).unwrap_or_else(|e| {
            panic!("{:?} must encode, refused with {e}", case.tag);
        });

        // Pin 1: the bytes on the wire, taken from the client's writer.
        assert_eq!(
            out.as_slice(),
            case.record,
            "{:?} must serialize to the bytes `build_rskey_phy_tlv` writes; a \
             different length byte, byte order or tag byte is a record the \
             client reads as a different field",
            case.tag
        );
        // Pin 2: the length byte, restated on its own so a record literal
        // edited to match a wrong encoder still cannot pass.
        assert_eq!(
            out[1], case.declared_len,
            "{:?} declares a one-byte length of {:#04X} on the client's wire",
            case.tag, case.declared_len
        );
        assert_eq!(
            out.len(),
            phy_tlv::record_len(case.declared_len as usize),
            "{:?}: no header, no padding, no terminator beyond the record",
            case.tag
        );
        // And the round-trip, so a decoder that skipped or reordered this
        // record cannot pass either.
        let got: Result<HeaplessVec<(u8, u8), 4>, phy_tlv::TlvError> = phy_tlv::Decoder::new(&out)
            .map(|r| r.map(|(t, v)| (t, v.len() as u8)))
            .collect();
        assert_eq!(
            got,
            Ok(HeaplessVec::from_slice(&[(case.tag.byte(), case.declared_len)]).unwrap()),
            "{:?} must decode back to exactly one record of its own length",
            case.tag
        );

        // Each tag appears exactly once in `ALL`, and its byte round-trips.
        assert_eq!(
            phy_tlv::PhyTag::ALL
                .iter()
                .filter(|t| **t == case.tag)
                .count(),
            1,
            "{:?} must appear exactly once in `phy_tlv::PhyTag::ALL`",
            case.tag
        );
        assert_eq!(
            phy_tlv::PhyTag::from_byte(case.tag.byte()),
            Some(case.tag),
            "the wire byte and the variant must not drift apart"
        );
    }
}

/// `0x09` and `0x0F` are variable-length by construction (the string's own
/// length plus its NUL), so they have no fixed declared width; the other ten
/// do, and the widths are the length bytes `build_rskey_phy_tlv` pushes.
#[test]
fn fixed_width_tags_declare_the_width_the_client_writes() {
    for (tag, want) in [
        (phy_tlv::PhyTag::VidPid, 4),
        (phy_tlv::PhyTag::LedGpio, 1),
        (phy_tlv::PhyTag::LedBrightness, 1),
        (phy_tlv::PhyTag::Options, 2),
        (phy_tlv::PhyTag::PresenceTimeout, 1),
        (phy_tlv::PhyTag::Curves, 4),
        (phy_tlv::PhyTag::EnabledUsbItf, 1),
        (phy_tlv::PhyTag::LedDriver, 1),
        (phy_tlv::PhyTag::LedOrder, 1),
        (phy_tlv::PhyTag::LedNum, 1),
    ] {
        assert_eq!(
            tag.declared_width(),
            Some(want),
            "{:?} is a fixed-width field in the client's writer",
            tag
        );
    }
    for tag in [
        phy_tlv::PhyTag::UsbProduct,
        phy_tlv::PhyTag::UsbManufacturer,
    ] {
        assert_eq!(
            tag.declared_width(),
            None,
            "{:?} is a NUL-terminated string, so its width follows the text",
            tag
        );
    }
}

/// The two string tags are written with a trailing NUL and refused — never
/// truncated — when the name is too long.
///
/// The client's own limit is `bytes.len() + 1 > 33` refused
/// (`build_rskey_phy_tlv`, `picoforge/src/hal/fido/mod.rs:1073-1077`), i.e. a
/// 32-byte name and a 33-byte record value. Truncating to fit would write a
/// *different* product name than the one configured. A value with no
/// terminator would not, by itself, be visible to this client — its
/// `trim_matches(char::from(0))` (`picoforge/src/hal/fido/mod.rs:963-966`)
/// takes leading and trailing NULs alike, so a NUL-free value reads back as
/// exactly the name written. The terminator is kept because the client's
/// schema says the field is NUL-terminated, not because this reader would
/// object.
#[test]
fn nul_string_tags_refuse_an_over_long_name_instead_of_truncating() {
    let max = "a".repeat(phy_tlv::MAX_NUL_STRING_LEN);
    let mut out: HeaplessVec<u8, 64> = HeaplessVec::new();
    phy_tlv::encode_nul_string(phy_tlv::PhyTag::UsbProduct, &max, &mut out).unwrap();
    let mut want: HeaplessVec<u8, 64> = HeaplessVec::new();
    want.push(0x09).unwrap();
    want.push((phy_tlv::MAX_NUL_STRING_LEN + 1) as u8).unwrap();
    want.extend_from_slice(max.as_bytes()).unwrap();
    want.push(0x00).unwrap();
    assert_eq!(
        out.as_slice(),
        want.as_slice(),
        "a 32-byte name is 32 text bytes plus a NUL, so the length byte is 33 \
         (0x21) and the NUL is inside the record, not after it"
    );

    let too_long = "a".repeat(phy_tlv::MAX_NUL_STRING_LEN + 1);
    let mut out2: HeaplessVec<u8, 64> = HeaplessVec::new();
    assert_eq!(
        phy_tlv::encode_nul_string(phy_tlv::PhyTag::UsbProduct, &too_long, &mut out2),
        Err(phy_tlv::TlvError::StringTooLong {
            got: phy_tlv::MAX_NUL_STRING_LEN + 1
        }),
        "33 text bytes is 34 with the NUL, past what the client's writer will \
         emit; the name must be refused, not shortened"
    );
    assert!(
        out2.is_empty(),
        "a refused string must write nothing, so no record with a wrapped \
         length reaches the client"
    );

    // The client trims leading *and* trailing NULs, so an interior one is
    // not removed by that trim — it is carried into the host's product name.
    // Which means stripping it here would be the wrong fix, and so would
    // accepting it.
    let mut out3: HeaplessVec<u8, 64> = HeaplessVec::new();
    assert_eq!(
        phy_tlv::encode_nul_string(phy_tlv::PhyTag::UsbManufacturer, "Edi\0eOz", &mut out3),
        Err(phy_tlv::TlvError::EmbeddedNul { at: 3 }),
        "an interior NUL is a name the client will read back differently, and \
         the offset is what tells the caller which part of the name was wrong"
    );
    assert!(out3.is_empty(), "and it must write nothing");

    // An empty name is a legal value here and a no-op for the client, which
    // filters empty names out before writing
    // (`picoforge/src/hal/fido/mod.rs:1068`) and so would emit no record at
    // all. The asymmetry is documented rather than refused; this pins what
    // this side does with it.
    let mut out4: HeaplessVec<u8, 64> = HeaplessVec::new();
    phy_tlv::encode_nul_string(phy_tlv::PhyTag::UsbProduct, "", &mut out4).unwrap();
    assert_eq!(
        out4.as_slice(),
        &[0x09, 0x01, 0x00],
        "an empty name is a one-byte value holding just the terminator — a \
         record the client would never write, but which decodes back to the \
         empty string"
    );
}

/// `encode_nul_string` does not check its tag, and the damage from a wrong one
/// is a silent misparse rather than a refusal — so this pins the misparse.
///
/// The only guard is a `debug_assert`, which is compiled out of a release
/// build; the doc on the function says so and points here. That is the same
/// stated-not-enforced posture as `PhyTag::declared_width`, and the reason it
/// is acceptable is the same: the two string tags are the only tags whose
/// `declared_width` is `None`, so a caller can ask, and US-117 is where the
/// callers arrive.
#[test]
#[should_panic(expected = "is not a NUL-terminated string tag")]
fn a_string_on_a_fixed_width_tag_is_caught_in_debug() {
    // `0x06` with the two bytes `0x78 0x00` is read back by the client as
    // `u16::from_be_bytes` = `0x7800` — option bits outside
    // `RESCUE_OPTIONS_MASK` that `vendor41::apply_phy_record` would then
    // reject, so the firmware would refuse its own writer's record.
    let mut out: HeaplessVec<u8, 64> = HeaplessVec::new();
    let _ = phy_tlv::encode_nul_string(phy_tlv::PhyTag::Options, "x", &mut out);
}

/// The bit values US-116 names, checked against the client's own tables.
///
/// `RescueOptions` is read off `RescueOptions` in
/// `picoforge/src/hal/rescue/constants.rs` (WCID `0x01`, LED_DIMMABLE
/// `0x02`, DISABLE_POWER_RESET `0x04`, LED_STEADY `0x08`) and cross-checked
/// against the FIDO writer's `RSKEY_OPT_*`
/// (`picoforge/src/hal/fido/mod.rs:110-112`); `UsbInterfaces` off `UsbInterfaces`
/// in the same file (CCID `0x01`, WCID `0x02`, HID `0x04`, KB `0x08`, LWIP
/// `0x10`).
#[test]
fn bitflags_match_the_clients_bitflag_tables() {
    assert_eq!(phy_tlv::RESCUE_OPT_WCID, 0x01);
    assert_eq!(phy_tlv::RESCUE_OPT_LED_DIMMABLE, 0x02);
    assert_eq!(phy_tlv::RESCUE_OPT_DISABLE_POWER_RESET, 0x04);
    assert_eq!(phy_tlv::RESCUE_OPT_LED_STEADY, 0x08);
    assert_eq!(
        phy_tlv::RESCUE_OPTIONS_MASK,
        0x0F,
        "the four documented bits and nothing else; a mask wider than the \
         client's table would accept option bits no client can set"
    );

    assert_eq!(phy_tlv::USB_ITF_CCID, 0x01);
    assert_eq!(phy_tlv::USB_ITF_WCID, 0x02);
    assert_eq!(phy_tlv::USB_ITF_HID, 0x04);
    assert_eq!(phy_tlv::USB_ITF_KB, 0x08);
    assert_eq!(phy_tlv::USB_ITF_LWIP, 0x10);
    assert_eq!(
        phy_tlv::USB_ITF_MASK,
        0x1F,
        "five interface bits in one byte, leaving bits 5..7 undefined — the \
         client's `UsbInterfaces` is a `u8` bitflags with no bits above LWIP"
    );
}
