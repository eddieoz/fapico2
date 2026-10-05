//! Tests for fapico2-fido CTAP2 getInfo.

#[test]
fn test_get_info_has_required_fields() {
    use fapico2_fido::ctap2::Ctap2Info;

    let info = Ctap2Info::default();
    assert!(info.versions.contains(&"FIDO_2_0"));
    assert!(info.versions.contains(&"FIDO_2_1"));
    assert!(info.versions.contains(&"FIDO_2_3"));
    // US-1531: the seed must NOT claim CTAP1. Advertising `U2F_V2` made
    // Chrome enter a U2F register and abandon the CTAP2 makeCredential the
    // page actually asked for, which is the QR-popup / blinking-board report
    // on demo.yubico.com, X.com and Proton. Both twins put it back through
    // `Ctap2Info::set_u2f_v2` only when no PIN is set — see
    // `ctap2::u2f_v2_advertised`. Asserted on the seed rather than on the
    // wire in `u2f_v2_advertisement.rs`.
    assert!(
        !info.versions.contains(&"U2F_V2"),
        "the bare seed must fail closed on CTAP1, exactly as it does for \
         makeCredUvNotRqd"
    );
    assert!(info.extensions.contains(&"hmac-secret"));
    assert!(info.extensions.contains(&"credBlob"));
    assert!(info.extensions.contains(&"largeBlobKey"));
    assert!(info.extensions.contains(&"minPinLength"));
    assert!(info.extensions.contains(&"credProtect"));
    assert_eq!(info.max_msg_size, 7609);
    assert_eq!(info.pin_protocols.as_slice(), &[1, 2]);
    assert!(info.max_creds_in_list.is_some());
    assert!(info.max_cred_id_len.is_some());
    // FX-404 decision: only ES256 (-7) is advertised. ESP256 (-9) is accepted
    // for key generation (suite curve-preservation test) but deliberately not
    // advertised, matching the reference C firmware and keeping the suite's
    // parametrized algorithm tests skipped rather than failing.
    assert_eq!(info.algorithms.len(), 4);
    assert_eq!(info.algorithms[0], -7);
    assert!(info.transports.contains(&"usb"));
    assert!(info.authenticator_config_commands.len() >= 4);
    assert_eq!(info.enc_cred_store_state.len(), 32);
    assert_eq!(info.enc_identifier.len(), 32);
    assert_eq!(info.option("rk"), Some(true));
    // "up" is deliberately not advertised (see Ctap2Info::default).
    assert!(info.option("up").is_none());
    assert!(info.option("clientPin").is_some());
    assert!(info.option("pinUvAuthToken").is_some());
    assert!(info.option("credMgmt").is_some());
    assert!(info.option("largeBlobs").is_some());
    assert!(info.option("setMinPINLength").is_some());
}

// US-101 (EPIC PICOForge-COMPAT): the AAGUID must be a build-time
// constant whose DEFAULT is the RS-Key profile, because PicoForge
// exact-matches GetInfo key 0x03 against a three-entry device-profile
// table and only the RS-Key profile surfaces the OpenPGP applet.
//
// The assertion pins the LITERAL bytes rather than round-tripping
// `info.aaguid` against the crate constant — the previous test
// (`test_get_info_aaguid_matches`, deleted by US-101) compared the struct
// field to the very constant the struct was built from and therefore could
// never fail, whatever the value was.
//
// CTAP2.1 §5.1.2 authenticatorGetInfo, key 0x03 (aaguid): 16 raw bytes,
// 24 79 C7 BF 6B 30 56 83 9E C8 0E 81 71 A9 18 B7.
#[test]
fn aaguid_is_the_published_default() {
    use fapico2_fido::app::FidoApp;
    use fapico2_fido::cbor;
    use fapico2_fido::keystore::MemoryKeystore;

    // Drive the real host stack so the assertion covers the wire bytes the
    // desktop app actually reads, not just the in-memory struct field.
    let mut app = FidoApp::with_keystore(MemoryKeystore::new());
    let resp = app.process_ctap2(0x04, &[], [1, 2, 3, 4]);
    // CTAP2 responses are a one-byte status prefix followed by the CBOR body.
    assert_eq!(resp[0], 0x00, "getInfo (0x04) must succeed");
    let (decoded, _) =
        cbor::decode(&resp[1..]).expect("getInfo response body must be valid CBOR");
    let cbor::Value::M(map) = decoded else {
        panic!("getInfo response must be a CBOR map");
    };
    let (_, aaguid) = map
        .iter()
        .find(|(k, _)| *k == cbor::Value::U(0x03))
        .expect("getInfo must carry key 0x03 (aaguid)");
    let cbor::Value::B(bytes) = aaguid else {
        panic!("getInfo key 0x03 must be a bstr, got {aaguid:?}");
    };

    // A build with FAPICO2_AAGUID_HEX set is *not* a default build, and the
    // RS-Key expectation does not apply to it. Verifying an override build is
    // the whole purpose of this mechanism (and how the eventual upstream
    // AAGUID migration will be done), so it must not fail here with a
    // misleading "the constant is wrong" message. Assert the expectation that
    // actually applies instead — never a silent no-op.
    if fapico2_fido::AAGUID_OVERRIDE_ACTIVE {
        let expected = fapico2_fido::aaguid_from_hex(fapico2_fido::AAGUID_OVERRIDE_HEX);
        assert_eq!(
            bytes, &expected[..],
            "US-101: getInfo key 0x03 must be exactly the FAPICO2_AAGUID_HEX \
             override ({}) that this build was configured with",
            fapico2_fido::AAGUID_OVERRIDE_HEX
        );
        eprintln!(
            "SKIPPING the default-AAGUID assertion — this build has \
             FAPICO2_AAGUID_HEX={} set, so the published default does not apply. \
             The wire value was instead checked against that override. Re-run \
             without FAPICO2_AAGUID_HEX to exercise the default.",
            fapico2_fido::AAGUID_OVERRIDE_HEX
        );
    } else {
        // The **published** default: fapico2's own AAGUID. The wire bytes are
        // asserted against the literal, not against the constant, so a change
        // to the constant alone cannot move both and leave the test green —
        // which is the failure mode a "compare to what we computed" assertion
        // cannot see.
        //
        // The RS-Key value is no longer the default. It stays reachable as
        // `FAPICO2_AAGUID_HEX=2479C7BF…`, which is how a build is aimed at a
        // PicoForge whose profile table has not yet been taught fapico2; see
        // `tests/aaguid_build.rs`, which builds both and probes the artifacts.
        const FAPICO2_DEFAULT: [u8; 16] = [
            0x66, 0x61, 0x70, 0x69, 0x63, 0x6F, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];
        assert_eq!(
            bytes, &FAPICO2_DEFAULT[..],
            "the default-build AAGUID must be fapico2's own identity \
             (66 61 70 69 63 6F 32 00 ... 02 — ASCII \"fapico2\")"
        );

        // The crate constant is the single source of truth; pin its bytes too
        // so a change to the constant alone cannot silently drift from the
        // wire.
        assert_eq!(
            fapico2_fido::AAGUID, FAPICO2_DEFAULT,
            "fapico2_fido::AAGUID must default to fapico2's own published bytes"
        );
    }
}

#[test]
fn test_get_info_encode_cbor() {
    use fapico2_fido::cbor;
    use fapico2_fido::ctap2::Ctap2Info;

    let info = Ctap2Info::default();
    let cbor_value = info.to_cbor();
    let encoded = cbor::encode(&cbor_value);
    assert!(!encoded.is_empty());

    let (decoded, _) = cbor::decode(&encoded).unwrap();
    match decoded {
        cbor::Value::M(map) => {
            // Verify key fields exist
            assert!(map.iter().any(|(k, _)| *k == cbor::Value::U(0x01))); // versions
            assert!(map.iter().any(|(k, _)| *k == cbor::Value::U(0x02))); // extensions
            assert!(map.iter().any(|(k, _)| *k == cbor::Value::U(0x03))); // aaguid
            assert!(map.iter().any(|(k, _)| *k == cbor::Value::U(0x04))); // options
            assert!(map.iter().any(|(k, _)| *k == cbor::Value::U(0x06))); // pinUvAuthProtocols
            assert!(map.iter().any(|(k, _)| *k == cbor::Value::U(0x09))); // transports
            assert!(map.iter().any(|(k, _)| *k == cbor::Value::U(0x0A))); // algorithms
            // 0x15 is deliberately absent — see "getInfo must not contain a CBOR
            // integer wider than 32 bits" below.
            assert!(map.iter().any(|(k, _)| *k == cbor::Value::U(0x1E))); // encCredStoreState
            assert!(map.iter().any(|(k, _)| *k == cbor::Value::U(0x1F))); // authenticatorConfigCommands
        }
        _ => panic!("expected map"),
    }
}

#[test]
fn test_get_info_enc_cred_store_state_is_32_bytes() {
    use fapico2_fido::ctap2::Ctap2Info;

    let info = Ctap2Info::default();
    assert_eq!(info.enc_cred_store_state.len(), 32);
}

#[test]
fn test_get_info_config_commands_include_required() {
    use fapico2_fido::ctap2::Ctap2Info;

    let info = Ctap2Info::default();
    let cmds: std::collections::HashSet<u8> = info.authenticator_config_commands.iter().copied().collect();
    assert!(cmds.contains(&0x01));
    assert!(cmds.contains(&0x02));
    assert!(cmds.contains(&0x03));
    assert!(cmds.contains(&0xFF));
}

#[test]
fn test_get_info_enc_state_fresh_iv_per_call() {
    use fapico2_fido::app::FidoApp;
    use fapico2_fido::keystore::MemoryKeystore;

    let mut app = FidoApp::with_keystore(MemoryKeystore::new());
    let resp1 = app.process_ctap2(0x04, &[], [1, 2, 3, 4]);
    let resp2 = app.process_ctap2(0x04, &[], [1, 2, 3, 4]);
    // The encrypted encCredStoreState bytes use a fresh IV per call, so the
    // encoded getInfo differs; the encrypted plaintext is deterministic
    // (device random + credential counter) and only the suite, which decrypts
    // with a persistent token, can observe that stability.
    assert_ne!(resp1, resp2, "fresh IV per getInfo call");
}

// ---------------------------------------------------------------------------
// US-102 (EPIC PICOForge-COMPAT): getInfo key 0x0E firmwareVersion encoding
// ---------------------------------------------------------------------------
//
// PicoForge (`picoforge/src/hal/fido/mod.rs:133-144`) reads the raw
// firmwareVersion integer and formats it as:
//
//   raw > 0xFFFF  ->  "major.minor.patch"
//   otherwise      ->  "major.minor"
//
// so a device that reports 0 renders "0.0" and lands on the wrong branch of
// both `supports_fido_config_write` and
// `supports_legacy_fido_hardware_config`. The value must therefore be a real,
// non-zero, correctly packed `(major << 8) | minor`.
//
// Two encoder paths are covered below, because both are live:
//   * the host-alloc path (`Ctap2Info::to_cbor` + `cbor::encode`), which is
//     what `FidoApp::process_ctap2(0x04, ..)` actually serves on the host;
//   * the zero-alloc no-heap path (`Ctap2Info::write_cbor_into`), which is
//     what the no_std device build serves.

/// GetInfo over the real host command path and decode the wire CBOR,
/// returning the raw firmwareVersion integer carried under key 0x0E.
fn firmware_version_from_wire() -> u64 {
    use fapico2_fido::app::FidoApp;
    use fapico2_fido::cbor;
    use fapico2_fido::keystore::MemoryKeystore;

    let mut app = FidoApp::with_keystore(MemoryKeystore::new());
    let resp = app.process_ctap2(0x04, &[], [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "getInfo (0x04) must succeed");
    let (decoded, _) = cbor::decode(&resp[1..]).expect("getInfo body must be valid CBOR");
    let cbor::Value::M(map) = decoded else {
        panic!("getInfo response must be a CBOR map");
    };
    let (_, v) = map
        .iter()
        .find(|(k, _)| *k == cbor::Value::U(0x0E))
        .expect("getInfo must carry key 0x0E (firmwareVersion)");
    let cbor::Value::U(raw) = v else {
        panic!("getInfo key 0x0E must be a CBOR unsigned integer, got {v:?}");
    };
    *raw
}

/// The same value, read out of the bytes the no-heap (no_std device) encoder
/// actually produced.
///
/// # Why this decodes with the host codec instead of the no-heap `Parser`
///
/// The tempting alternative is to walk `no_heap::Parser` as a flat key/value
/// stream. That is wrong. `Parser::next` yields `Item::Map(n)` /
/// `Item::Array(n)` for a container and advances the cursor past the
/// **header only** — it does not descend into the container. So the first
/// read is the outer map header consumed as a "key" and every subsequent read
/// is off by one relative to the document. It happens to land on key 0x0E
/// today only because 0x0E falls on an even stream index; adding a single
/// entry earlier in the map (e.g. `transports.push("nfc")`) flips that parity
/// and breaks a test that looks perfectly sound.
///
/// Round-tripping through the host `cbor::decode` instead keeps the two
/// encoder paths genuinely distinct — the *bytes* still come from
/// `write_cbor_into`, the device encoder, which is the thing under test — and
/// makes the read insensitive to depth, ordering, and entry count, because
/// the decoder walks the real structure rather than assuming a shape.
fn firmware_version_from_no_heap_encoder() -> u64 {
    use fapico2_fido::cbor;
    use fapico2_fido::ctap2::Ctap2Info;
    use heapless::Vec as HeaplessVec;

    let mut out: HeaplessVec<u8, 1024> = HeaplessVec::new();
    Ctap2Info::default()
        .write_cbor_into(&mut out)
        .expect("no-heap getInfo encoding must fit its buffer");

    let (decoded, consumed) =
        cbor::decode(&out).expect("no-heap getInfo output must be valid CBOR");
    assert_eq!(
        consumed,
        out.len(),
        "US-102: the no-heap getInfo encoding must be exactly one CBOR item; \
         trailing bytes mean the encoder emitted more than the assertion below \
         inspects"
    );
    let cbor::Value::M(map) = decoded else {
        panic!("no-heap getInfo output must be a CBOR map");
    };
    let (_, v) = map
        .iter()
        .find(|(k, _)| *k == cbor::Value::U(0x0E))
        .expect("no-heap getInfo encoding must carry key 0x0E (firmwareVersion)");
    let cbor::Value::U(raw) = v else {
        panic!("no-heap getInfo key 0x0E must be a CBOR unsigned integer, got {v:?}");
    };
    *raw
}

#[test]
fn firmware_version_is_packed_major_minor() {
    use fapico2_fido::pack_firmware_version;

    // Pin the ENCODING itself against the spec, on literal inputs — this is
    // what makes the assertion independent of whatever constant the crate
    // happens to carry today.
    //
    // 1.1.0 is the EPIC's worked example: (1 << 8) | 1 == 0x000101.
    assert_eq!(
        pack_firmware_version("1.1.0"),
        0x0000_0101,
        "US-102: 1.1.0 must pack to (major << 8) | minor == 0x000101"
    );
    // The patch component is intentionally dropped: anything above 0xFFFF
    // would be re-read by the consumer as major.minor.patch.
    assert_eq!(
        pack_firmware_version("2.7.13"),
        0x0207,
        "US-102: the patch component must be dropped so raw stays <= 0xFFFF"
    );
    assert_eq!(
        pack_firmware_version("0.1.0"),
        0x0000_0001,
        "US-102: 0.1.0 must pack to 0x000001 (renders \"0.1\")"
    );

    // The workspace's real crate version, decomposed INDEPENDENTLY in the
    // test from the literal version string, must be what both encoders put on
    // the wire. Comparing against the production const fn alone would only
    // restate the constant and could never fail.
    let pkg = env!("CARGO_PKG_VERSION");
    let mut parts = pkg.split('.');
    let major: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("US-102: CARGO_PKG_VERSION {pkg:?} has no numeric major"));
    let minor: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("US-102: CARGO_PKG_VERSION {pkg:?} has no numeric minor"));
    let expected = (major << 8) | minor;

    assert_eq!(
        firmware_version_from_wire(),
        u64::from(expected),
        "US-102: getInfo key 0x0E on the host-alloc path must be \
         (major << 8) | minor of CARGO_PKG_VERSION {pkg:?} == 0x{expected:06X}"
    );
    assert_eq!(
        firmware_version_from_no_heap_encoder(),
        u64::from(expected),
        "US-102: getInfo key 0x0E on the no-heap (device) path must be \
         (major << 8) | minor of CARGO_PKG_VERSION {pkg:?} == 0x{expected:06X}"
    );

    // The consumer branches on the raw value, so the encoding must stay inside
    // the "major.minor" arm: anything > 0xFFFF is read as major.minor.patch
    // and would render a three-component version instead.
    assert!(
        firmware_version_from_wire() <= 0xFFFF,
        "US-102: firmwareVersion must be <= 0xFFFF, or the consumer reads it as \
         major.minor.patch instead of major.minor"
    );
}

#[test]
fn firmware_version_nonzero() {
    // RED before US-102: the field was a hard-coded 0 (ctap2.rs:101, :423),
    // which renders "0.0" and mis-gates every version-dependent path in
    // PicoForge. Assert on the wire value, not the struct field, so this
    // covers the actual bytes the desktop app reads.
    let raw = firmware_version_from_wire();
    assert_ne!(
        raw, 0,
        "US-102: getInfo key 0x0E must not be 0 — the consumer renders 0 as \
         \"0.0\" and gates on the wrong branch. Firmware must report a real, \
         packed major.minor version."
    );
    assert_ne!(
        firmware_version_from_no_heap_encoder(),
        0,
        "US-102: the no-heap (device) getInfo encoder must not report 0 either"
    );
}

// ---------------------------------------------------------------------------
// getInfo must not contain a CBOR integer wider than 32 bits — which is why
// key 0x15 (vendorPrototypeConfigCommands) is no longer advertised
// ---------------------------------------------------------------------------
//
// US-122 made this suite pin the *opposite*: that 0x15 lists the six 64-bit
// ids PicoForge can edit. That was correct about PicoForge and wrong about
// everyone else, and the cost landed on Yubico's own clients.
//
// The six ids are 64-bit, so `no_heap::push_uint` emits each one canonically
// as head `0x1B` + 8 bytes — a CBOR unsigned integer with additional-info 27.
// `yubikit`'s `Cbor.loadInt` stops at additional-info 26 and throws
// `IllegalArgumentException("Unable to load integer")` for 27, from inside
// `Ctap2Session`'s constructor. The whole getInfo response is then unreadable
// and Yubico Authenticator's Passkeys screen never loads. Measured on
// hardware: the failure is at byte offset 381 of a 519-byte payload, the
// first element of the 0x15 array, and allowing additional-info 27 lets the
// remaining 20 keys decode with no trailing bytes — so this one array was the
// entire difference between a working and a broken authenticator.
//
// Why removal is safe, and why not the alternative:
//
//   * The ids are 64-bit because *PicoForge* says so. `VendorConfigCommand::from_u64`
//     (`picoforge/src/hal/fido/constants.rs:487-521`) hardcodes these exact
//     values and sends them on write, so narrowing them is not ours to do.
//   * Advertising them was never load-bearing. Both twins dispatch
//     `authenticatorConfig` 0xFF on the id in key `0x01` of the *request*
//     (`app.rs::cfg_vendor_prototype`, `device_core.rs` via
//     `PhyCommand::decode`) and never read getInfo.
//   * PicoForge's write path uses a compile-time enum
//     (`picoforge/src/hal/fido/ops.rs:154`), never the discovered list, so no
//     setting becomes uneditable. Only an info-dump string goes empty.
//   * A real YubiKey 5 omits 0x15 entirely (`docs/webauthn-discovery-ab.md`).
//
// `python-fido2` reads 64-bit integers without complaint, which is why this
// never showed up on the Linux desktop and why the emulation suite was green.

/// The ids the client gives the four US-113 physical-config commands. Pinned
/// as literals so the test can fail if `vendorff::SUPPORTED_IDS` is changed
/// without the client changing with it (the same reasoning as the AAGUID
/// test above: a comparison against the very constant the list was built from
/// could never fail). Served, not advertised — see the section header.
const US113_IDS: [(&str, u64); 4] = [
    ("PhysicalVidPid", 0x6fcb19b0cbe3acfa),
    ("PhysicalLedGpio", 0x7b392a394de9f948),
    ("PhysicalLedBrightness", 0x76a85945985d02fd),
    ("PhysicalOptions", 0x269f3b09eceb805f),
];

/// Credential-metadata ids handled by the same `0xFF` match arm
/// (`app.rs::cfg_vendor_prototype`) and driven end-to-end by
/// `tests/pico-fido/test_043_credential_metadata.py`.
const CRED_MGMT_IDS: [(&str, u64); 2] = [
    ("CONFIG_CREDENTIAL_EXPIRE", 0x0004E532E1FEB2FD),
    ("CONFIG_CREDENTIAL_REVOKE", 0x0005961ECBA040F9),
];

/// Raw getInfo bytes from the host twin's `to_cbor()`.
fn bytes_from_host_encoder() -> Vec<u8> {
    use fapico2_fido::cbor;
    use fapico2_fido::ctap2::Ctap2Info;

    cbor::encode(&Ctap2Info::default().to_cbor())
}

/// Raw getInfo bytes from the no-heap `write_cbor_into()` — what the no_std
/// device build serves. NOT the emulation binary: that runs the *host*
/// `FidoApp` (`firmware/src/emul_main.rs` -> `process_ctap2` -> `app.rs`
/// `get_info` -> `to_cbor`), i.e. `bytes_from_host_encoder` above;
/// `write_cbor_into` is reached only through `device_app.rs` ->
/// `device_core.rs` `handle_get_info` on real hardware.
fn bytes_from_device_encoder() -> Vec<u8> {
    use fapico2_fido::ctap2::Ctap2Info;
    use heapless::Vec as HeaplessVec;

    let mut out: HeaplessVec<u8, 1024> = HeaplessVec::new();
    Ctap2Info::default()
        .write_cbor_into(&mut out)
        .expect("no-heap getInfo encoding must fit its buffer");
    out.to_vec()
}

/// Every `(label, bytes)` pair: both encoders, because they are separate code
/// and only one of them ships.
fn both_encoders() -> [(&'static str, Vec<u8>); 2] {
    [
        ("host", bytes_from_host_encoder()),
        ("device", bytes_from_device_encoder()),
    ]
}

/// Recursively assert every integer in `p` fits in 32 bits.
///
/// On canonical CBOR an integer needs additional-info 27 (a `0x1B` head) iff
/// its value exceeds `0xFFFF_FFFF`, so the value check *is* the head-width
/// check — and it says what we mean rather than which byte spells it.
fn assert_ints_fit_in_32_bits(p: &mut fapico2_fido::cbor::no_heap::Parser<'_>, path: &str) {
    use fapico2_fido::cbor::no_heap::Item;

    let item = p.next().unwrap_or_else(|e| panic!("{path}: decode error {e:?}"));
    match item {
        Item::U(v) => assert!(
            v <= u32::MAX as u64,
            "{path}: unsigned integer {v} (0x{v:X}) needs a 64-bit CBOR head \
             (0x1B); yubikit's loadInt rejects additional-info 27 with \
             \"Unable to load integer\" and cannot parse the rest of getInfo"
        ),
        Item::N(v) => assert!(
            v >= -(u32::MAX as i64),
            "{path}: negative integer {v} needs a 64-bit CBOR head (0x3B), \
             which yubikit cannot parse"
        ),
        Item::Array(n) => {
            for _ in 0..n {
                assert_ints_fit_in_32_bits(p, path);
            }
        }
        Item::Map(n) => {
            for _ in 0..n {
                assert_ints_fit_in_32_bits(p, path); // key
                assert_ints_fit_in_32_bits(p, path); // value
            }
        }
        _ => {}
    }
}

/// The gate. Every integer anywhere in getInfo, on both encoder paths, must be
/// readable by the 32-bit-only decoder every Yubico client ships.
#[test]
fn getinfo_holds_no_integer_wider_than_32_bits() {
    use fapico2_fido::cbor::no_heap::Parser;

    for (label, bytes) in both_encoders() {
        let mut p = Parser::new(&bytes);
        assert_ints_fit_in_32_bits(&mut p, label);
        assert_eq!(p.remaining(), 0, "{label}: trailing bytes after the getInfo item");
    }
}

/// The six 64-bit ids are still what the `0xFF` dispatch arm answers for — they
/// are simply no longer advertised, because advertising them is what made
/// getInfo unreadable.
///
/// Asserting the *constants* rather than a getInfo list is the point: the
/// handler (`app.rs::cfg_vendor_prototype`, `device_core.rs` ->
/// `PhyCommand::decode`) matches on these values in the incoming request, so
/// pinning them here pins the commands. `tests/pico-fido/test_043_credential_metadata.py`
/// then drives two of them end-to-end over the emulator.
#[test]
fn vendor_ids_are_served_but_not_advertised() {
    let served: Vec<u64> = fapico2_fido::vendorff::SUPPORTED_IDS
        .iter()
        .map(|(_, id)| *id)
        .chain([
            fapico2_fido::ctap2::CONFIG_CREDENTIAL_EXPIRE,
            fapico2_fido::ctap2::CONFIG_CREDENTIAL_REVOKE,
        ])
        .collect();

    for ((name, id), pinned) in US113_IDS.iter().chain(CRED_MGMT_IDS.iter()).zip(&served) {
        assert_eq!(
            id, pinned,
            "the served vendor id for {name} drifted from the value pinned for PicoForge"
        );
    }

    // All six exceed 32 bits — the whole reason the advertisement had to go.
    for id in &served {
        assert!(
            *id > u32::MAX as u64,
            "0x{id:016X} now fits in 32 bits; if it is still correct to omit \
             key 0x15, say why here rather than leaving the old reason standing"
        );
    }

    // And neither encoder advertises it any more.
    for (label, bytes) in both_encoders() {
        let (decoded, consumed) =
            fapico2_fido::cbor::decode(&bytes).expect("getInfo must be valid CBOR");
        assert_eq!(consumed, bytes.len(), "{label}: getInfo must be one CBOR item");
        let fapico2_fido::cbor::Value::M(map) = decoded else {
            panic!("{label}: getInfo must be a CBOR map");
        };
        assert!(
            !map.iter().any(|(k, _)| *k == fapico2_fido::cbor::Value::U(0x15)),
            "{label}: getInfo must not carry key 0x15 — its value is an array \
             of 64-bit ids, which no Yubico client can decode"
        );
    }
}

// ---------------------------------------------------------------------------
// US-FIX (encCredStoreState length): the 32-byte field must be 32 bytes on
// the wire, from the path the EMULATOR and the suite actually run.
// ---------------------------------------------------------------------------
//
// This closes a hole that let a real defect ship. Two `getInfo`
// implementations exist:
//
//   * `device_core.rs::get_info` — builds `enc_state` in a fresh vec and
//     ASSIGNS it (`info.enc_cred_store_state = enc_state`). 32 B. Correct.
//   * `app.rs::get_info` — starts from `Ctap2Info::default()`, which already
//     holds 32 zero bytes, and APPENDS IV(16) || ciphertext(16). 64 B.
//
// `firmware/src/emul_main.rs -> process_ctap2` goes through `app.rs`, so the
// emulator — and therefore every pytest suite — served a 64-byte
// encCredStoreState, and `test_get_info_enc_cred_store_state_is_32_bytes`
// above still passed, because it asserts on `Ctap2Info::default()` and never
// invokes either `get_info`. A gate that cannot fail is not a gate.
//
// CTAP2.1 §6.5.1: encCredStoreState is a 16-byte AES-CBC IV followed by
// exactly one 16-byte ciphertext block = 32 bytes.

/// Pull getInfo key `0x1E` (encCredStoreState) out of an encoded response.
///
/// The response is `[0x00 status][CBOR map]`; this walks the map rather than
/// trusting an offset, so a key-order change cannot silently pass this.
fn enc_state_len_from_response(resp: &[u8]) -> usize {
    use fapico2_fido::cbor::Value;

    let (decoded, _) = fapico2_fido::cbor::decode(&resp[1..])
        .expect("getInfo response must be a CBOR map");
    let Value::M(entries) = decoded else {
        panic!("getInfo response must be a CBOR map");
    };
    entries
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::U(0x1E), Value::B(b)) => Some(b.len()),
            (Value::U(0x1E), other) => {
                panic!("encCredStoreState (0x1E) must be a bstr, got {other:?}")
            }
            _ => None,
        })
        .expect("getInfo must carry encCredStoreState (0x1E)")
}

#[test]
fn test_get_info_wire_enc_state_is_32_bytes_on_the_app_path() {
    use fapico2_fido::app::FidoApp;
    use fapico2_fido::keystore::MemoryKeystore;

    let mut app = FidoApp::with_keystore(MemoryKeystore::new());
    // CTAP2_GET_INFO = 0x04.
    let resp = app.process_ctap2(0x04, &[], [1, 2, 3, 4]);

    assert_eq!(
        enc_state_len_from_response(&resp),
        32,
        "CTAP2.1 §5.1.2: encCredStoreState (0x1E) is IV(16) || one AES-CBC \
         block(16) = 32 bytes. A longer field means the 32-byte default in \
         `Ctap2Info::default()` was appended to instead of replaced."
    );
}
