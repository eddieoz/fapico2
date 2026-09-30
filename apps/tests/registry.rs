//! US-386 TDD — device CCID app registry.
//!
//! The device build must wire exactly six CCID apps behind the AID dispatcher
//! (Management, OATH, OTP, OpenPGP, vendor LED, Rescue) with distinct AIDs;
//! FIDO rides the HID transport (not AID-dispatched) and PIV is deferred. This
//! test proves the registry holds six entries with the six expected, distinct
//! AIDs, using the real app objects so a duplicate/typo'd AID is caught at
//! compile-test time.
//!
//! US-160 (PICOForge-COMPAT) took the set from four to five when the RS-Key
//! vendor LED applet (`F0 00 00 00 01`) was added, and US-161/162/163 (Phase H)
//! took it to six with the **Rescue** applet (`A0 58 3F C1 9B 7E 4F 21`). The
//! Rescue AID is a *standard* one rather than a vendor one — it is shared by
//! pico-fido's C `rescue.c` and the RS-Key Rust applet — which is exactly why
//! the set is pinned here against the client source rather than left implicit:
//! a typo there is silent, the SELECT answers `6A82`, and the Config screen is
//! unreachable with no other test failing.
//!
//! (USB-level `lsusb` + live SELECT validation is Phase 6 hardware acceptance.)

use fapico2_apps::registry::{register_ccid_apps, CCID_AIDS};
use fapico2_mgmt::ManagementApp;
use fapico2_oath::{OathApp, OtpApp};
use fapico2_openpgp::{with_ram_client, OpenPgpApp};
use fapico2_platform::dispatch::{App, Dispatcher};
use fapico2_rescue::RescueApp;
use fapico2_vendor_led::VendorLedApp;

/// All six device CCID apps register cleanly into a `Dispatcher<6>` (no
/// duplicate AID, capacity holds). The OpenPGP (opcard/trussed-virt) client
/// only lives inside `with_ram_client`, so the whole registration runs within
/// it.
#[test]
fn device_registers_six_ccid_apps_with_distinct_aid() {
    // Unique client id per process so parallel test runs never collide on the
    // trussed-virt IPC channel.
    let client_id = format!("fapico2-registry-{}", std::process::id());
    with_ram_client(&client_id, |client| {
        let mut openpgp = OpenPgpApp::new(client);
        let mut management = ManagementApp::new();
        let mut oath = OathApp::new();
        let mut otp = OtpApp::new();
        let mut vendor_led = VendorLedApp::new();
        // The Rescue applet is constructed **bare** here — no config owner, no
        // device handler — on purpose. Registration is a wiring assertion, and
        // a bare applet is the honest thing to register: a handler needs a
        // `&'static mut` owner that only the firmware can supply, and the
        // no-handler arms are exercised in `apps/rescue/tests/protocol.rs`
        // instead.
        let mut rescue = RescueApp::new();

        // Each app answers for its own AID (checked before the dispatcher
        // mutably borrows them).
        assert_eq!(management.aid(), AID_EXPECTED[0]);
        assert_eq!(oath.aid(), AID_EXPECTED[1]);
        assert_eq!(otp.aid(), AID_EXPECTED[2]);
        assert_eq!(openpgp.aid(), AID_EXPECTED[3]);
        assert_eq!(vendor_led.aid(), AID_EXPECTED[4]);
        assert_eq!(rescue.aid(), AID_EXPECTED[5]);

        let mut d: Dispatcher<6> = Dispatcher::new();
        assert!(
            register_ccid_apps(
                &mut d,
                &mut management,
                &mut oath,
                &mut otp,
                &mut openpgp,
                &mut vendor_led,
                &mut rescue,
            ),
            "all six device CCID apps must register (distinct AIDs, capacity 6)"
        );
    });
}

/// The six AIDs are exactly the ones the merged suite drives and are pairwise
/// distinct.
#[test]
fn ccid_aid_set_is_the_six_device_apps() {
    assert_eq!(CCID_AIDS, AID_EXPECTED);
    for (i, a) in CCID_AIDS.iter().enumerate() {
        for b in &CCID_AIDS[i + 1..] {
            assert_ne!(a, b, "device AIDs must be distinct");
        }
    }
}

/// The vendor LED AID is the one the PicoForge client SELECTs
/// (`picoforge/src/hal/rescue/constants.rs:484`). A typo here is silent: the
/// client's SELECT would answer `6A82` and the LED screen would be
/// unreachable, with no other test failing.
#[test]
fn vendor_led_aid_is_the_one_the_client_selects() {
    assert_eq!(
        CCID_AIDS[4],
        &[0xF0, 0x00, 0x00, 0x00, 0x01],
        "the vendor LED AID must match the client's VENDOR_LED_AID"
    );
}

/// The Rescue AID is `RESCUE_AID` (`picoforge/src/hal/rescue/constants.rs:106`),
/// and its SELECT is `00 A4 04 04 08 <AID>` — an ordinary AID SELECT that the
/// dispatcher routes on P1 alone (`is_select_apdu` checks `P1 == 0x04` and does
/// not constrain P2), so the client's `P2 = 0x04` needs no special casing.
#[test]
fn rescue_aid_is_the_one_the_client_selects() {
    assert_eq!(
        CCID_AIDS[5],
        &[0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21],
        "the Rescue AID must match the client's RESCUE_AID"
    );
}

/// The six device AIDs, in registration order (shared by both tests so a
/// change in one place fails both).
const AID_EXPECTED: [&[u8]; 6] = [
    // Management (matches `management.c` `man_aid`).
    &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17],
    // OATH.
    &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01],
    // OTP.
    &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01],
    // OpenPGP card (spec §4.2.1: RID D2 76, 00 01 24 01).
    &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01],
    // RS-Key vendor LED applet.
    &[0xF0, 0x00, 0x00, 0x00, 0x01],
    // RS-Key Rescue applet.
    &[0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21],
];
