//! US-103 (PICOForge-COMPAT): the stable 8-digit USB serial.
//!
//! **Why this file does not touch `platform::usb` directly.** The device USB
//! stack lives in `platform/src/usb.rs`, which is gated on
//! `#[cfg(all(feature = "device", target_arch = "arm"))]` (`platform/src/lib.rs:21`)
//! because every embassy dependency in it is arm-only. A host `cargo test`
//! therefore never compiles that module, so the serial *derivation* it needs
//! could not be tested there. Following the `platform/src/hid_control.rs`
//! precedent (US-391 E7 — class-control decision logic extracted out of the
//! gated `usb.rs` precisely so it becomes host-testable), the derivation lives
//! in the ungated [`fapico2_platform::usb_ident`] module and `usb.rs` only
//! consumes it.
//!
//! # What these tests do *not* cover (the honest blind spot)
//!
//! These tests cover the **derivation**, not the **wiring**. Nothing here can
//! observe `platform/src/usb.rs`, because that file is never compiled on the
//! host. Hardcoding `config.serial_number = Some("00012345")` inside the
//! arm-gated `usb.rs` leaves every test in this file passing. The only gates
//! on that line are the `thumbv8m` build (it must still typecheck) and human
//! review of the one-line assignment. A green run here is **not** evidence that
//! `usb.rs` is wired correctly.
//!
//! # Invocation
//!
//! These tests run under the crate-local invocation
//! `cargo test --target x86_64-unknown-linux-gnu -p fapico2-platform --test usb`
//! and under the workspace invocation
//! `cargo test --target x86_64-unknown-linux-gnu --workspace --exclude fapico2-firmware`.
//!
//! The `--target x86_64-unknown-linux-gnu` is required in both: the repo's
//! `.cargo/config.toml` pins the default target to `thumbv8m.main-none-eabi`,
//! where this crate's `host` feature does not build. The workspace form
//! additionally needs `--exclude fapico2-firmware` because all four of that
//! crate's bins fail to build on a host target (pre-existing).
//!
//! The behaviour under test is the whole point of US-103: PicoForge
//! fingerprints the device as `vid:pid:serial` for hotplug
//! (`transport/fido.rs:237-248`), so the serial must be
//!
//! * **present** — a `None` `serial_number` leaves the fingerprint incomplete;
//! * **8 decimal digits** — the shape the host app parses;
//! * **stable across reboots** — a random or per-boot value would re-enumerate
//!   as a different device on every plug;
//! * **per-device** — a constant would fingerprint the whole fleet as one unit,
//!   which is the bug R12 closed for the management `TAG_SERIAL`.

use fapico2_platform::usb_ident::{
    decimal8, serial_digits, serial_hash4, serial_value, EMULATION_CHIPID, SERIAL_DIGITS,
    SERIAL_MODULUS,
};

/// The EPIC's named test. The `UsbConfig::serial_number` field itself is only
/// settable on the arm device path; what is host-observable — and what the
/// field is assigned from — is the derived value. These assertions are the
/// contract `usb.rs:142` must honour when it stops leaving the field `None`.
#[test]
fn usb_config_carries_serial_number() {
    // A representative device chipid (the RP2350 OTP chipid is an arbitrary
    // 64-bit value; these are the mnemonics the codebase already uses).
    let chipid = 0x0102_0304_0506_0708u64;

    // (1) Present, and exactly 8 decimal digits — never `None`, never padded
    //     with anything but ASCII '0'..'9'.
    let digits = serial_digits(chipid);
    assert_eq!(digits.len(), SERIAL_DIGITS);
    assert!(digits.len() == 8, "serial must be 8 digits, got {}", digits.len());
    for (i, &b) in digits.iter().enumerate() {
        assert!(
            b.is_ascii_digit(),
            "serial digit {i} is {:?}, not a decimal digit (whole serial {:?})",
            b as char,
            core::str::from_utf8(&digits).unwrap()
        );
    }

    // (2) Stable across reboots: a pure function of the chipid. Called twice
    //     "as if" the device rebooted and re-enumerated.
    assert_eq!(
        serial_digits(chipid),
        serial_digits(chipid),
        "serial must be stable across reboots"
    );
    // …and independent of call order / any prior call.
    let other = 0xDEAD_BEEF_CAFE_0001u64;
    assert_eq!(serial_digits(chipid), digits);
    assert_eq!(serial_digits(other), serial_digits(other));

    // (3) Per-device, NOT a constant. A single extra distinct chipid is not
    //     enough: sample a spread and require every serial to be unique. This
    //     is the assertion that fails if someone replaces the derivation with
    //     a literal.
    let samples = [
        0u64,
        1,
        2,
        0x0102_0304_0506_0708,
        0x0102_0304_0506_0709,
        0xDEAD_BEEF_CAFE_0001,
        0xDEAD_BEEF_CAFE_0002,
        0x6661_7069_636F_3200, // EMULATION_CHIPID
        0x6661_7069_636F_3201,
        u64::MAX,
    ];
    for &a in &samples {
        for &b in &samples {
            if a < b {
                assert_ne!(
                    serial_digits(a),
                    serial_digits(b),
                    "chipids {a:#018x} and {b:#018x} collided — the derivation \
                     is not per-device, or the sample set is beyond the \
                     documented collision budget (see usb_ident module docs)"
                );
            }
        }
    }
}

/// The USB serial and the management applet's `TAG_SERIAL` must derive from the
/// *same* chip-id hash, or a host sees two different identities for one
/// device. This test pins that relationship at the byte level: the ASCII digits
/// are a pure function of the same `SHA-256(chipid)[..4]` the management applet
/// serialises into its 4-byte TLV value.
///
/// US-1825 follow-up (WARM-BOOT-SERVE audit D-WB2): the value is scaled into
/// **26 bits**, not 10^8 — the space PicoForge's rescue-body serial decode can
/// express. PicoForge derives the CCID-side serial as
/// `u32::from_be_bytes([body[4] & 0x03, body[5], body[6], body[7]])` of the
/// rescue identity (the pico-keys-sdk wire convention: the body carries the
/// platform serial id whose head *is* the serial), and pairs interfaces by
/// comparing that against the TAG_SERIAL render. A serial wider than 26 bits
/// cannot be expressed there, and the mismatch silently skips every CCID
/// reader — the 2026-11-10 "Applet not available on any PicoFido or RS-Key
/// reader" regression. Hence the two pins below: the value fits 26 bits, and
/// `serial_hash4` returns exactly its big-endian bytes (the "already
/// serial4-masked by the firmware" shape picoforge's comment expects).
#[test]
fn usb_serial_and_mgmt_serial_share_one_derivation() {
    let chipid = 0x0102_0304_0506_0708u64;

    // What `fapico2_mgmt::serial_from_chipid` returns (R12 / TAG_SERIAL 0x02).
    let mgmt = serial_hash4(chipid);
    assert_eq!(mgmt.len(), 4, "the mgmt TAG_SERIAL is a 4-byte TLV value");

    // Recomputing the management derivation independently must not change the
    // USB one — they are the same function, not two look-alike ones.
    assert_eq!(serial_hash4(chipid), mgmt);

    // The digit rendering is a function of that same 4-byte value, so the
    // mapping is inspectable: `SHA-256(chipid)[..4]` -> 8 digits via
    // `serial_value`'s scaled truncation. Asserted here so a change to the
    // *rule* cannot silently desynchronise the two identities.
    assert_eq!(serial_digits(chipid), decimal8(serial_value(chipid)));
    // The rule is exactly "shift the 32-bit prefix into the 2^26 space" — pinned
    // against the documented formula so a refactor to a different (still
    // deterministic) rule has to update this test deliberately. The prefix
    // comes from the device-bound hash directly: `serial_hash4` is now the
    // *output* (the serial4-masked bytes), so deriving `n` from it would be
    // circular.
    let n = u32::from_be_bytes(
        fapico2_platform::ckey::serial_hash(&chipid.to_be_bytes())[0..4]
            .try_into()
            .unwrap(),
    ) as u64;
    assert_eq!(serial_value(chipid), (n * SERIAL_MODULUS) >> 32);

    // D-WB2: the serial must fit the 26-bit space PicoForge's rescue-body
    // decode can express — a wider serial silently breaks CCID pairing.
    assert!(
        serial_value(chipid) < (1u64 << 26),
        "serial_value must fit PicoForge's 26-bit rescue decode"
    );
    // …and `serial_hash4` returns exactly the serial4-masked bytes: byte 0
    // carries only the top 2 serial bits (the mask is automatic below 2^26),
    // so picoforge's `[b0 & 0x03, b1, b2, b3]` decode round-trips the value.
    assert_eq!(
        serial_hash4(chipid),
        (serial_value(chipid) as u32).to_be_bytes(),
        "serial_hash4 is the serial4-masked BE encoding of serial_value"
    );
}

/// **Golden vectors** — the only assertions here that pin the actual output
/// bytes end to end.
///
/// The other tests in this file are self-referential: the formula assertion
/// above restates the implementation, and the `decimal8` test checks the
/// renderer against literal inputs. Both would stay green if the *rule* were
/// swapped wholesale for a different wrong-but-self-consistent one (say a
/// little-endian hash read, or a shift by 24 instead of 32). These vectors pin
/// the bytes themselves.
///
/// Expected values were produced **independently**, by Python's `hashlib`
/// (SHA-256) and integer arithmetic — not by running this crate. Reproduce
/// with:
///
/// ```python
/// n = int.from_bytes(hashlib.sha256(cid.to_bytes(8,'big')).digest()[:4],'big')
/// f"{(n*(1<<26))>>32:08d}"
/// ```
///
/// If a vector here ever needs updating, that is a **behaviour change to a
/// shipped device's USB serial** — every unit's PicoForge hotplug identity
/// would change, and hosts would re-enumerate it as a different device. It is
/// not a routine test edit; it needs an EPIC decision. (It would be a
/// fleet-wide re-enumeration but not a *collision* change, since the mapping
/// stays as injective-in-practice as it was.)
#[test]
fn golden_serial_vectors() {
    // chipid, SHA-256(chipid BE)[..4] (big-endian u32), expected 8 digits —
    // the value scaled into the 26-bit space (D-WB2).
    let vectors: [(u64, u32, &str); 4] = [
        (0x0102_0304_0506_0708, 0x6684_0DDA, "26873911"),
        (0xDEAD_BEEF_CAFE_0001, 0x55FE_19BB, "22542438"),
        // The emulation stand-in: lands below 10^7, so it also pins the
        // zero-padding path (leading "0" must survive).
        (EMULATION_CHIPID, 0x0D2D_FE68, "03454969"),
        (0, 0xAF55_70F5, "45962691"),
    ];

    for (chipid, hash4, expected) in vectors {
        // The hash half: confirms the derivation feeds the documented SHA-256
        // prefix, in the documented byte order — recomputed from the raw hash
        // (serial_hash4 is the scaled *output*, not the prefix).
        let prefix = u32::from_be_bytes(
            fapico2_platform::ckey::serial_hash(&chipid.to_be_bytes())[0..4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            prefix, hash4,
            "hash prefix changed for chipid {chipid:#018x}"
        );
        // The serial4 half (D-WB2): the bytes the rescue body and the
        // management TAG_SERIAL carry are the scaled value, big-endian.
        assert_eq!(
            serial_hash4(chipid),
            (serial_value(chipid) as u32).to_be_bytes(),
            "serial4 changed for chipid {chipid:#018x}"
        );
        // The output half: the literal 8 characters the host will read.
        assert_eq!(
            serial_digits(chipid),
            *expected.as_bytes(),
            "serial changed for chipid {chipid:#018x}"
        );
        // …and it really is 8 ASCII digits, not just equal bytes.
        assert_eq!(serial_digits(chipid).len(), 8);
        assert!(serial_digits(chipid).iter().all(u8::is_ascii_digit));
    }
}

/// The digit renderer itself: fixed-width, zero-padded, no allocator, no float.
/// Tested independently of the hash so a rendering bug is distinguishable
/// from a derivation bug.
#[test]
fn decimal8_is_fixed_width_zero_padded() {
    assert_eq!(decimal8(0), *b"00000000");
    assert_eq!(decimal8(1), *b"00000001");
    assert_eq!(decimal8(9), *b"00000009");
    assert_eq!(decimal8(10), *b"00000010");
    // The 26-bit space (D-WB2): the top of the range renders as its own
    // digits, and every wider input saturates at MODULUS-1 = 67108863.
    assert_eq!(decimal8(99_999_999), *b"67108863");
    assert_eq!(decimal8(u32::MAX as u64), *b"67108863");
    assert_eq!(decimal8(SERIAL_MODULUS - 1), *b"67108863");
    for v in [0u64, 1, 42, 1_234_567, 99_999_998, SERIAL_MODULUS - 1] {
        let d = decimal8(v);
        assert_eq!(d.len(), 8);
        assert!(d.iter().all(u8::is_ascii_digit));
    }
}
