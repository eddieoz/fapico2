//! US-701: malformed-APDU bounds on the management applet.
//!
//! A 1-byte APDU `[0x00]` (CLA gate passes, `apdu[1]` indexes out of bounds)
//! used to panic the device (panic handler = `loop {}` → remote hang). The
//! app must return a status word instead and keep serving.

use fapico2_mgmt::ManagementApp;
use fapico2_platform::dispatch::{App, MAX_RESPONSE, Sw, SW_WRONG_LENGTH}; // Sw = u16
use heapless::Vec as HeaplessVec;

/// Drive one APDU through the app and return (response_bytes, sw).
fn drive(app: &mut ManagementApp, apdu: &[u8]) -> (Vec<u8>, Sw) {
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    app.process(apdu, &mut resp);
    let bytes: Vec<u8> = resp.as_slice().to_vec();
    assert!(bytes.len() >= 2, "response must carry a status word");
    let sw = u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
    (bytes[..bytes.len() - 2].to_vec(), sw)
}

#[test]
fn one_byte_apdu_returns_sw_not_panic() {
    let mut app = ManagementApp::new();
    let (_, sw) = drive(&mut app, &[0x00]);
    assert_eq!(sw, SW_WRONG_LENGTH);
    // The app keeps serving after the malformed input.
    let (_, sw2) = drive(&mut app, &[0x00, 0x1D, 0x00, 0x00, 0x00]);
    assert_eq!(sw2, 0x9000);
}

/// Zero-length APDU (dispatcher entry point): the header guard rejects it —
/// the bound is "a status word, no panic".
#[test]
fn zero_length_apdu_returns_sw_not_panic() {
    let mut app = ManagementApp::new();
    let (_, sw) = drive(&mut app, &[]);
    assert_eq!(sw, SW_WRONG_LENGTH);
}

/// RESET / MIGRATION with truncated headers must not panic (US-701 audit
/// entry): every sub-4-byte APDU is answered by the header guard with
/// SW_WRONG_LENGTH; the full-length RESET still answers OK.
#[test]
fn reset_short_data_returns_sw() {
    let mut app = ManagementApp::new();
    for apdu in [
        vec![0x00, 0x1E],
        vec![0x00, 0x1E, 0x00],
        vec![0x00, 0x1F],
        vec![0x00, 0x1F, 0x00],
    ] {
        let (_, sw) = drive(&mut app, &apdu);
        assert_eq!(
            sw, SW_WRONG_LENGTH,
            "truncated APDU ({:?}) must answer WRONG_LENGTH",
            apdu
        );
    }
    // Full-length (4-byte header, no data) RESET/MIGRATION: RESET → OK;
    // MIGRATION with no handler → INS_NOT_SUPPORTED — never a panic.
    let (_, sw) = drive(&mut app, &[0x00, 0x1E, 0x00, 0x00]);
    assert_eq!(sw, 0x9000, "header-only RESET must answer OK");
    let (_, sw) = drive(&mut app, &[0x00, 0x1F, 0x00, 0x00, 0x00]);
    assert_ne!(sw, 0x0000, "MIGRATION must answer a status word");
}
