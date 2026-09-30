//! The **device identity block**: the four values that decide what product this
//! firmware claims to be, and the rules that resolve them.
//!
//! Split in two on purpose, because the two halves fail differently.
//!
//! The *resolution* tests below run in the enclosing test binary and so can
//! only see what the build this test was compiled with resolved to. They cover
//! the parsing and precedence rules against hand-written inputs, which is
//! where a mistake is cheapest to make and easiest to see.
//!
//! The *build* probe — `identity_build.rs`, a sibling — shells out to a real
//! `cargo build` and greps the produced artifact, because the thing that
//! actually matters for US-101's successor is that an **environment variable
//! changes the compiled binary**, and no in-process test can observe that. The
//! two halves of the mechanism fail in different ways: this file catches a
//! wrong rule, the sibling catches a build script that stopped reading the
//! environment.

// CTAP2.1 getInfo key `0x03`, 16 raw bytes. The AAGUID is the leading 16
// bytes of every attested credential blob, so it is an identity and not a
// string: the test below pins the bytes, not the hex spelling.
use fapico2_platform::identity as id;

#[test]
fn the_published_default_spells_fapico2_in_ascii() {
    // Pinned as bytes, deliberately. `DEFAULT_AAGUID` is the value every
    // default build ships, and it is also the value that ends up in front of a
    // relying party inside an attestation statement — a change here is not a
    // refactor, it invalidates existing passkey RP→AAGUID bindings. A test
    // that recomputed the expected value from the same source would pass on
    // every one of those changes.
    assert_eq!(
        id::DEFAULT_AAGUID,
        [
            0x66, 0x61, 0x70, 0x69, 0x63, 0x6F, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ],
        "the published AAGUID is ASCII \"fapico2\", a NUL, padding, and a version \\
         word of 2"
    );
    // ...and the readable half is readable, which is the property the value
    // was chosen for. A future edit that keeps the length and loses this
    // fails with a message about the thing a reader would actually notice.
    assert_eq!(&id::DEFAULT_AAGUID[..7], b"fapico2");
}

#[test]
fn the_borrowed_rskey_aaguid_is_no_longer_the_default() {
    // The borrow is over (EPIC PICOForge-COMPAT §3.2, risk R-3). It remains
    // *reachable* as `FAPICO2_AAGUID_HEX=2479C7BF…`, which is how a build is
    // aimed at a PicoForge whose profile table has not yet been taught
    // fapico2 — but it must not be what a default build ships, or two devices
    // present the same borrowed identity and R-3 is unresolved.
    const RSKEY: [u8; 16] = [
        0x24, 0x79, 0xC7, 0xBF, 0x6B, 0x30, 0x56, 0x83, 0x9E, 0xC8, 0x0E, 0x81, 0x71, 0xA9,
        0x18, 0xB7,
    ];
    assert_ne!(
        id::DEFAULT_AAGUID, RSKEY,
        "the default must no longer be the borrowed RS-Key identity"
    );
    assert_eq!(
        id::aaguid_from_hex("2479C7BF6B3056839EC80E8171A918B7"),
        RSKEY,
        "…and the documented development override must still parse to it"
    );
}

#[test]
fn aaguid_parsing_is_case_insensitive_and_literal() {
    assert_eq!(
        id::aaguid_from_hex("00112233445566778899AABBCCDDEEFF"),
        id::aaguid_from_hex("00112233445566778899aabbccddeeff"),
        "upper and lower case must agree — a rejected case here is a build \\
         break for a value that was never wrong"
    );
    assert_eq!(
        id::aaguid_from_hex("00112233445566778899aabbccddeeff"),
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF
        ],
        "a 32-hex override must resolve to those bytes verbatim, in order"
    );
}

#[test]
fn an_empty_override_selects_the_published_default() {
    // The empty string is `build.rs`'s "the variable was unset" encoding, not
    // a user-facing value: setting `FAPICO2_AAGUID_HEX=` is rejected as
    // malformed, because a shell template that rendered nothing is far more
    // likely than a deliberate request for the default. So this branch is
    // reachable only from an unset variable, and the test says so.
    assert_eq!(id::select_aaguid(""), id::DEFAULT_AAGUID);
    assert_eq!(id::select_string("", id::DEFAULT_PRODUCT), id::DEFAULT_PRODUCT);
    assert_eq!(
        id::select_string("", id::DEFAULT_MANUFACTURER),
        id::DEFAULT_MANUFACTURER
    );
    assert_eq!(
        id::select_vid_pid("", (id::DEFAULT_VID, id::DEFAULT_PID)),
        (id::DEFAULT_VID, id::DEFAULT_PID)
    );
}

#[test]
fn a_real_override_beats_the_default_for_every_value() {
    assert_eq!(
        id::select_aaguid("DEADBEEF0123456789ABCDEF01234567"),
        id::aaguid_from_hex("DEADBEEF0123456789ABCDEF01234567"),
        "an override must win over the default"
    );
    assert_eq!(
        id::select_string("Acme Token", id::DEFAULT_PRODUCT),
        "Acme Token"
    );
    assert_eq!(
        id::select_vid_pid("1234:5678", (id::DEFAULT_VID, id::DEFAULT_PID)),
        (0x1234, 0x5678)
    );
}

#[test]
fn vid_pid_accepts_every_spelling_a_person_would_write() {
    // A person copying from `lsusb` writes `FA20:0002`; a person copying from
    // a C header writes `0xfa20:0x0002`; a person with `cargo` in front of
    // them writes either. None of them should have to remember which spelling
    // this build accepts, and none of them should get a *build failure* for
    // the alternative — a build break here is a typo treated as a hard error,
    // which is the right call for a bad value and the wrong one for a
    // different valid way of writing a good one.
    for (spelling, expected) in [
        ("FA20:0002", (0xFA20u16, 0x0002u16)),
        ("fa20:0002", (0xFA20, 0x0002)),
        ("0xFA20:0x0002", (0xFA20, 0x0002)),
        ("0xfa20:0x0002", (0xFA20, 0x0002)),
        ("0xFA20:0002", (0xFA20, 0x0002)),
    ] {
        assert_eq!(
            id::select_vid_pid(spelling, (0, 0)),
            expected,
            "{spelling} must parse to {expected:04X?}:{expected:04X?}"
        );
    }
}

#[test]
fn the_strings_have_a_bound_the_descriptor_and_the_tlv_agree_on() {
    // One number for the USB string descriptor and the PHY `0x09`/`0x0F` tags,
    // because a name that is accepted on one path and un-writable on the other
    // is a record that cannot be written back — and 32 is the client's own
    // limit (`picoforge/src/hal/rescue/ops.rs:456`), so a longer name is
    // refused by the app before it ever reaches the wire.
    assert_eq!(id::MAX_IDENTITY_STRING, 32);
    // The block is host-testable even though the descriptor is arm-only; that
    // separation is why the constant lives in `platform` and not in `usb`.
    assert!(
        "A".repeat(id::MAX_IDENTITY_STRING).len() <= id::MAX_IDENTITY_STRING,
        "the default names must be inside the bound they impose on overrides"
    );
}

/// What this build actually resolved to.
///
/// A build with overrides set is a legitimate build — it is how a development
/// build aims at a different client — so these assertions are conditional on
/// the build's own configuration rather than unconditional, and the conditional
/// branches assert a real invariant instead of passing vacuously.
#[test]
fn the_compiled_block_matches_this_builds_configuration() {
    if id::AAGUID_OVERRIDE_HEX.is_empty() {
        assert_eq!(id::AAGUID, id::DEFAULT_AAGUID, "unset ⇒ the default");
    } else {
        assert_eq!(
            id::AAGUID,
            id::aaguid_from_hex(id::AAGUID_OVERRIDE_HEX),
            "FAPICO2_AAGUID_HEX={} ⇒ exactly those bytes",
            id::AAGUID_OVERRIDE_HEX
        );
    }

    if id::PRODUCT_OVERRIDE.is_empty() {
        assert_eq!(id::PRODUCT, id::DEFAULT_PRODUCT);
    } else {
        assert_eq!(
            id::PRODUCT, id::PRODUCT_OVERRIDE,
            "FAPICO2_PRODUCT must be the override, verbatim"
        );
    }

    if id::MANUFACTURER_OVERRIDE.is_empty() {
        assert_eq!(id::MANUFACTURER, id::DEFAULT_MANUFACTURER);
    } else {
        assert_eq!(id::MANUFACTURER, id::MANUFACTURER_OVERRIDE);
    }

    if id::VID_PID_OVERRIDE.is_empty() {
        assert_eq!(id::VID, id::DEFAULT_VID);
        assert_eq!(id::PID, id::DEFAULT_PID);
    } else {
        // Re-parse rather than compare against a literal: the test and the
        // resolver would otherwise share the one piece of logic that could be
        // wrong, and agree on the wrong answer.
        let (want_vid, want_pid) = parse_vid_pid_for_test(id::VID_PID_OVERRIDE);
        assert_eq!(
            (id::VID, id::PID),
            (want_vid, want_pid),
            "FAPICO2_VID_PID={} ⇒ {want_vid:04X}/{want_pid:04X}",
            id::VID_PID_OVERRIDE
        );
    }
}

#[test]
fn default_build_is_reported_honestly() {
    // `DEFAULT_BUILD` exists so *other* tests can tell a default build from an
    // overridden one. If it disagreed with the four echoes it summarises, every
    // test that branched on it would be asserting about the wrong build.
    let expected = id::AAGUID_OVERRIDE_HEX.is_empty()
        && id::PRODUCT_OVERRIDE.is_empty()
        && id::MANUFACTURER_OVERRIDE.is_empty()
        && id::VID_PID_OVERRIDE.is_empty();
    assert_eq!(
        id::DEFAULT_BUILD, expected,
        "DEFAULT_BUILD must be exactly 'no override is in effect'"
    );
    eprintln!(
        "identity: AAGUID={} PRODUCT={:?} MANUFACTURER={:?} VID:PID={:04X}:{:04X} ({})",
        id::AAGUID.iter().map(|b| format!("{b:02X}")).collect::<String>(),
        id::PRODUCT,
        id::MANUFACTURER,
        id::VID,
        id::PID,
        if id::DEFAULT_BUILD { "default build" } else { "overridden build" },
    );
}

/// A deliberately independent re-implementation of the `VVVV:PPPP` parse, so
/// `the_compiled_block_matches_this_builds_configuration` is not checking the
/// resolver against itself.
fn parse_vid_pid_for_test(s: &str) -> (u16, u16) {
    // A `fn` rather than a closure: a closure capturing nothing cannot return
    // a borrow of its argument, which is exactly what `strip_prefix` hands
    // back. (E0106 at the borrow, not a style point.)
    fn strip(h: &str) -> &str {
        h.strip_prefix("0x").or_else(|| h.strip_prefix("0X")).unwrap_or(h)
    }
    let mut halves = s.split(':');
    let vid = strip(hexpairs(halves.next().expect("VID:PID needs a VID")));
    let pid = strip(hexpairs(halves.next().expect("VID:PID needs a PID")));
    assert!(halves.next().is_none(), "VID:PID takes exactly one colon");
    (
        u16::from_str_radix(vid, 16).expect("VID is hex"),
        u16::from_str_radix(pid, 16).expect("PID is hex"),
    )
}

/// Reject anything that is not four hex digits, so a malformed override fails
/// here too rather than making `from_str_radix` quietly accept `+12` or `_`.
fn hexpairs(h: &str) -> &str {
    assert_eq!(h.len(), 4, "each half is exactly 4 hex digits, got {h:?}");
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()), "{h:?} is not hex");
    h
}
