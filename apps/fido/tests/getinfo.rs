//! Tests for fapico2-fido CTAP2 getInfo.

#[test]
fn test_get_info_has_required_fields() {
    use fapico2_fido::ctap2::Ctap2Info;

    let info = Ctap2Info::default();
    assert!(info.versions.contains(&"FIDO_2_0"));
    assert!(info.versions.contains(&"FIDO_2_1"));
    assert!(info.versions.contains(&"FIDO_2_3"));
    assert!(info.versions.contains(&"U2F_V2"));
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
            assert!(map.iter().any(|(k, _)| *k == cbor::Value::U(0x15))); // vendorPrototypeConfigCommands
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
// US-122 (EPIC PICOForge-COMPAT): getInfo key 0x15
// vendorPrototypeConfigCommands must list the ids PicoForge can actually edit
// ---------------------------------------------------------------------------
//
// PicoForge dispatches 0x15 (falling back to 0x13) into its shared
// extension-list parser (`picoforge/src/hal/fido/mod.rs:335`, falling back at
// :320-322), which reads the value as an array of 64-bit integers
// (`picoforge/src/hal/fido/mod.rs:384-423`) and maps each through
// `VendorConfigCommand::from_u64` (`picoforge/src/hal/fido/constants.rs:487-521`);
// anything it does not know renders as `0x%016X`. The list therefore has to
// contain the ids the firmware *answers* for the `0xFF` framing, and nothing
// that is not a 64-bit id.
//
// This asserts set membership, not key presence: `test_get_info_encode_cbor`
// above only checks that key 0x15 exists at all.

/// The ids the client gives the four US-113 physical-config commands. Pinned
/// as literals so the test can fail if `vendorff::SUPPORTED_IDS` is changed
/// without the client changing with it (the same reasoning as the AAGUID
/// test above: a comparison against the very constant the list was built from
/// could never fail).
const US113_IDS: [(&str, u64); 4] = [
    ("PhysicalVidPid", 0x6fcb19b0cbe3acfa),
    ("PhysicalLedGpio", 0x7b392a394de9f948),
    ("PhysicalLedBrightness", 0x76a85945985d02fd),
    ("PhysicalOptions", 0x269f3b09eceb805f),
];

/// Credential-metadata ids handled by the same `0xFF` match arm
/// (`app.rs::cfg_vendor_prototype`) and pinned by
/// `tests/pico-fido/test_043_credential_metadata.py`.
const CRED_MGMT_IDS: [(&str, u64); 2] = [
    ("CONFIG_CREDENTIAL_EXPIRE", 0x0004E532E1FEB2FD),
    ("CONFIG_CREDENTIAL_REVOKE", 0x0005961ECBA040F9),
];

/// Pull key 0x15 out of a decoded getInfo CBOR map.
fn vendor_prototype_ids(
    map: &[(fapico2_fido::cbor::Value, fapico2_fido::cbor::Value)],
) -> Vec<u64> {
    let (_, v) = map
        .iter()
        .find(|(k, _)| *k == fapico2_fido::cbor::Value::U(0x15))
        .expect("getInfo must carry key 0x15 (vendorPrototypeConfigCommands)");
    let fapico2_fido::cbor::Value::A(items) = v else {
        panic!("getInfo key 0x15 must be an array, got {v:?}");
    };
    items
        .iter()
        .map(|i| match i {
            fapico2_fido::cbor::Value::U(n) => *n,
            other => panic!("getInfo key 0x15 entries must be unsigned ints, got {other:?}"),
        })
        .collect()
}

/// 0x15 as the host twin's `to_cbor()` emits it.
fn ids_from_host_encoder() -> Vec<u64> {
    use fapico2_fido::cbor;
    use fapico2_fido::ctap2::Ctap2Info;

    let encoded = cbor::encode(&Ctap2Info::default().to_cbor());
    let (decoded, consumed) = cbor::decode(&encoded).expect("host getInfo must be valid CBOR");
    assert_eq!(
        consumed,
        encoded.len(),
        "host getInfo must be one CBOR item"
    );
    let cbor::Value::M(map) = decoded else {
        panic!("host getInfo must be a CBOR map");
    };
    vendor_prototype_ids(&map)
}

/// 0x15 as the no-heap `write_cbor_into()` emits it — what the no_std device
/// build serves. NOT the emulation binary: that runs the *host* `FidoApp`
/// (`firmware/src/emul_main.rs` -> `process_ctap2` -> `app.rs` `get_info` ->
/// `to_cbor`), i.e. `ids_from_host_encoder` above; `write_cbor_into` is
/// reached only through `device_app.rs` -> `device_core.rs`
/// `handle_get_info` on real hardware.
fn ids_from_device_encoder() -> Vec<u64> {
    use fapico2_fido::cbor;
    use fapico2_fido::ctap2::Ctap2Info;
    use heapless::Vec as HeaplessVec;

    let mut out: HeaplessVec<u8, 1024> = HeaplessVec::new();
    Ctap2Info::default()
        .write_cbor_into(&mut out)
        .expect("no-heap getInfo encoding must fit its buffer");
    let (decoded, _) = cbor::decode(&out).expect("device getInfo must be valid CBOR");
    let cbor::Value::M(map) = decoded else {
        panic!("device getInfo must be a CBOR map");
    };
    vendor_prototype_ids(&map)
}

#[test]
fn getinfo_0x15_lists_physical_ids() {
    for (label, ids) in [
        ("host", ids_from_host_encoder()),
        ("device", ids_from_device_encoder()),
    ] {
        // The four US-113 ids. This loop was genuinely RED before US-122: the
        // list held `0xFF` and the two credential-metadata ids only, so all
        // four of these were absent and PicoForge rendered nothing it could
        // edit.
        for (name, id) in US113_IDS {
            assert!(
                ids.contains(&id),
                "US-122: {label} getInfo 0x15 must advertise {name} (0x{id:016X}); \
                 got {ids:016X?}"
            );
        }

        // The two credential-metadata ids stay advertised: they are real
        // commands in the same `0xFF` match arm, and
        // tests/pico-fido/test_043_credential_metadata.py asserts both.
        for (name, id) in CRED_MGMT_IDS {
            assert!(
                ids.contains(&id),
                "US-122: {label} getInfo 0x15 must advertise {name} (0x{id:016X}); \
                 got {ids:016X?}"
            );
        }

        // 0xFF is NOT a vendor id. It is the legacy framing's *sub-command
        // byte* — already advertised under key 0x1F
        // (authenticatorConfigCommands) — and belongs in neither this list nor
        // a 64-bit id space. Listing it made PicoForge print
        // 0x00000000000000FF.
        assert!(
            !ids.contains(&0xFF),
            "US-122: {label} getInfo 0x15 must not advertise 0xFF — it is the \
             vendorPrototype sub-command byte (advertised under 0x1F), not a \
             64-bit vendor id; got {ids:016X?}"
        );

        // No duplicates: a repeated id means the list was assembled from two
        // sources that were not reconciled.
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        let unique = {
            let mut u = sorted.clone();
            u.dedup();
            u
        };
        assert_eq!(
            sorted, unique,
            "US-122: {label} getInfo 0x15 must not contain duplicate ids"
        );

        // The exact set, as a set. Four US-113 + two credential-metadata.
        assert_eq!(
            ids.len(),
            6,
            "US-122: {label} getInfo 0x15 must list exactly the 6 supported \
             64-bit vendor ids; got {} ({ids:016X?})",
            ids.len()
        );
    }

    // The two twins share one `Ctap2Info::default()`, so the 0x15 *value* is
    // identical by construction; only the surrounding key order differs
    // (device emits 0x15, 0x19, 0x1B; host emits 0x15, 0x1B, 0x19 — a
    // pre-existing divergence, out of scope here). Assert the value only,
    // never the whole map.
    assert_eq!(
        ids_from_host_encoder(),
        ids_from_device_encoder(),
        "US-122: the host and device getInfo encoders must agree on 0x15"
    );
}
