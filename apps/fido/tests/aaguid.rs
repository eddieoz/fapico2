//! US-101 (EPIC PICOForge-COMPAT): the AAGUID is a build-time configurable
//! constant, defaulting to the RS-Key profile.
//!
//! PicoForge exact-matches the CTAP2.1 GetInfo key `0x03` (aaguid) against
//! a three-entry device-profile table; the RS-Key entry is the one that
//! surfaces the OpenPGP applet. RS-Key's AAGUID is a *borrowed* identity
//! (it is shared with real RS-Key hardware), so the plan (EPIC §3, §8) is to
//! claim it now and swap in a dedicated fapico2 AAGUID later as a **one-line
//! build change**, not a second refactor of the constant and its fixtures.
//!
//! That promise is only credible if the override path is actually exercised,
//! which is what `aaguid_is_overridable_at_build_time` does: it drives the
//! very `const fn` that resolves the build-time override, with a known
//! override value, and asserts the resolved bytes are that value — plus
//! asserts the default when the override is absent.
//!
//! A Cargo build cannot change environment variables part-way through a test
//! run, so a true end-to-end "build with the env var set" integration test is
//! not expressible as a `#[test]`; it would have to be a second process. The
//! const-fn path is the exact same code the env var feeds, so testing it
//! directly is a real test rather than a restatement of the default. The
//! process-level version of that proof is `aaguid_build.rs`.
//!
//! # Running under an override
//!
//! The parser and precedence cases here are override-independent and always
//! run. The one assertion that is not — "a default build ships the RS-Key
//! AAGUID" — is explicitly conditioned on this build having no override, so
//! that
//!
//! ```text
//! FAPICO2_AAGUID_HEX=00112233445566778899AABBCCDDEEFF cargo test -p fapico2-fido
//! ```
//!
//! (the exact procedure for verifying the override, and for the eventual
//! upstream AAGUID migration) is green and says why, rather than failing with
//! a misleading "the constant is wrong" message. Run with `--nocapture` to see
//! the skip explanation.
//!
//! This file touches no host stack, so it needs no `[[test]]` stanza in
//! `Cargo.toml` and compiles under both the `host` and `device` features.

/// The documented build-time override, spelled the way
/// `FAPICO2_AAGUID_HEX` is documented in the crate docs for `AAGUID`.
const OVERRIDE_HEX: &str = "00112233445566778899aabbccddeeff";

/// A second, realistic-looking override so the test cannot pass by accident
/// on a value that happens to equal the default.
const OTHER_OVERRIDE_HEX: &str = "DEADBEEF0123456789ABCDEF01234567";

#[test]
fn aaguid_is_overridable_at_build_time() {
    use fapico2_fido::aaguid_from_hex;

    // 1. A valid override resolves to exactly the bytes it names — this is
    //    the path `apps/fido/build.rs` feeds from `FAPICO2_AAGUID_HEX`.
    assert_eq!(
        aaguid_from_hex(OVERRIDE_HEX),
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff
        ],
        "US-101: a 32-hex-char override must resolve to those 16 bytes verbatim"
    );

    // 2. Case-insensitive: the documented form is upper-case, but a
    //    lower-case override must resolve identically rather than being
    //    rejected (a rejected typo here would be a build break, not a
    //    silent identity change).
    assert_eq!(
        aaguid_from_hex(OTHER_OVERRIDE_HEX),
        aaguid_from_hex(&OTHER_OVERRIDE_HEX.to_lowercase()),
        "US-101: hex parsing must be case-insensitive (upper and lower agree)"
    );

    // 3. The default is **fapico2's own** AAGUID, not RS-Key's.
    //
    //    This used to be RS-Key's `2479C7BF…`, borrowed so that PicoForge —
    //    which exact-matches getInfo key `0x03` against a three-entry profile
    //    table — would select the RS-Key device profile, the only one under
    //    which the app offers OpenPGP. The borrow has done its job and is over
    //    (EPIC `PICOForge-COMPAT` §3.2, risk R-3): the default is now the
    //    ASCII bytes of `fapico2` plus a version word, which reads
    //    recognisably in a hex dump and in `lsusb`/`pcsc_scan` output.
    //
    //    Pinned as bytes rather than derived, because the point is that the
    //    published value does not move by accident: the AAGUID is the leading
    //    16 bytes of every attested credential blob, so changing it invalidates
    //    every existing passkey RP→AAGUID binding on every deployed device.
    assert_eq!(
        fapico2_fido::DEFAULT_AAGUID,
        [
            0x66, 0x61, 0x70, 0x69, 0x63, 0x6F, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02
        ],
        "DEFAULT_AAGUID must be fapico2's own identity: ASCII \"fapico2\", a NUL, \
         padding, and a version word of 2"
    );
    // ...and the first seven bytes really are the ASCII the name claims to be,
    // so a future edit that keeps the length but loses the readability fails
    // with a message about the thing a reader would actually notice.
    assert_eq!(
        &fapico2_fido::DEFAULT_AAGUID[..7],
        b"fapico2",
        "the published AAGUID must still spell fapico2 in ASCII"
    );

    // 3a. The borrowed RS-Key value stays **parseable**, because it is the
    //     documented development override: a build aimed at a PicoForge that
    //     has not yet added fapico2's AAGUID to its table must still be one
    //     environment variable away. Losing the borrow must not lose the
    //     escape hatch.
    const RSKEY_AAGUID: [u8; 16] = [
        0x24, 0x79, 0xC7, 0xBF, 0x6B, 0x30, 0x56, 0x83, 0x9E, 0xC8, 0x0E, 0x81, 0x71, 0xA9, 0x18,
        0xB7,
    ];
    assert_eq!(
        aaguid_from_hex("2479C7BF6B3056839EC80E8171A918B7"), RSKEY_AAGUID,
        "the documented RS-Key override string must still parse to RS-Key, so a \
         development build can keep classifying as RS-Key while upstream catches up"
    );
    assert_ne!(
        fapico2_fido::DEFAULT_AAGUID, RSKEY_AAGUID,
        "the default must no longer be the borrowed identity — if these are equal the \
         borrow is back and R-3 is unresolved"
    );

    // 3b. The compiled `AAGUID` only equals the default in a build with no
    //     override. Verifying an override build — the whole purpose of this
    //     mechanism, and exactly how a build is aimed at a client with a
    //     different profile table — must not fail here with a misleading
    //     "wrong AAGUID" message. So branch on the build's own configuration
    //     and assert the expectation that actually applies.
    if fapico2_fido::AAGUID_OVERRIDE_ACTIVE {
        // The override is in effect: RS-Key is (correctly) NOT the answer.
        // Assert the override invariant instead so this branch is a real
        // check, never a silent no-op.
        assert_eq!(
            fapico2_fido::AAGUID,
            aaguid_from_hex(fapico2_fido::AAGUID_OVERRIDE_HEX),
            "US-101: with FAPICO2_AAGUID_HEX={} in effect, the compiled AAGUID must be \
             exactly those bytes",
            fapico2_fido::AAGUID_OVERRIDE_HEX
        );
        eprintln!(
            "SKIPPING the default-AAGUID assertion — this build has \
             FAPICO2_AAGUID_HEX={} set, so the default does not apply. The override \
             invariant above was asserted instead. Re-run without FAPICO2_AAGUID_HEX \
             to exercise the default.",
            fapico2_fido::AAGUID_OVERRIDE_HEX
        );
    } else {
        // Default build: fapico2's own bytes must be what actually ships. This
        // is the assertion that genuinely pins them.
        assert_eq!(
            fapico2_fido::AAGUID,
            fapico2_fido::DEFAULT_AAGUID,
            "a default build (no FAPICO2_AAGUID_HEX) must ship fapico2's own AAGUID"
        );
    }

    // 4. Precedence is override-then-default. This is the exact expression
    //    `lib.rs` uses to select `AAGUID`, so it is the precedence rule under
    //    test. The empty case is reachable only via build.rs's "unset ⇒
    //    publish the empty string" convention — a real build cannot set
    //    FAPICO2_AAGUID_HEX to empty, because build.rs rejects that as
    //    malformed. See `select_aaguid`'s docs.
    assert_eq!(
        fapico2_fido::select_aaguid(""),
        fapico2_fido::DEFAULT_AAGUID,
        "the empty string must select the published default \
         (this is the 'override unset' encoding, not a supported user-facing value)"
    );
    // And the precedence is not merely "empty means the default" — a real
    // override must beat the default. The RS-Key value is the interesting
    // case, because it is the one a development build actually uses.
    assert_eq!(
        fapico2_fido::select_aaguid("2479C7BF6B3056839EC80E8171A918B7"),
        RSKEY_AAGUID,
        "a real override must win over the published default, including the \
         borrowed RS-Key value a development build is aimed at"
    );
    assert_eq!(
        fapico2_fido::select_aaguid(OVERRIDE_HEX),
        aaguid_from_hex(OVERRIDE_HEX),
        "US-101: a present override must win over the default"
    );
    assert_eq!(
        fapico2_fido::select_aaguid(OTHER_OVERRIDE_HEX),
        aaguid_from_hex(OTHER_OVERRIDE_HEX),
        "US-101: a present override must win over the default (second value)"
    );
}
