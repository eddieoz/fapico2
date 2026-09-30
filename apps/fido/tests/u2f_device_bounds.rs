//! US-701: U2F AUTHENTICATE bounds on the **device** command path.
//!
//! The device copy of `u2f_authenticate` (`device_core.rs`) drifted from its
//! host twin (`u2f.rs`): its guard was `data.len() < 64` while the key-handle
//! byte is read at `data[64]`, so a 64-byte body (client_param ‖ app_param,
//! no key-handle byte) panicked the device (panic handler = `loop {}`).
//! Both malformed cases must return a CTAP1/ISO status, never panic.

use fapico2_fido::FidoApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;

/// Build a U2F AUTHENTICATE APDU over the given body and return the response.
fn drive_auth(app: &mut FidoApp, p1: u8, body: &[u8]) -> Vec<u8> {
    // Short-form APDU: CLA INS P1 P2 Lc <body>.
    let mut apdu = vec![0x00, 0x02, p1, 0x00, body.len() as u8];
    apdu.extend_from_slice(body);
    let mut out = heapless::Vec::<u8, { fapico2_fido::CTAP2_MAX_MSG }>::new();
    let n = app.process_u2f(&apdu, &mut out);
    out[..n].to_vec()
}

fn new_app() -> FidoApp {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    FidoApp::boot(&mut trng, &mut store).unwrap()
}

/// A 64-byte body (client_param ‖ app_param, no key-handle byte) must return
/// a status word — not panic at `data[64]`.
#[test]
fn u2f_auth_64_byte_body_returns_sw() {
    let mut app = new_app();
    let mut body = vec![0u8; 64];
    body[..32].fill(0xA1); // client_param
    body[32..].fill(0xA2); // app_param
    let resp = drive_auth(&mut app, 0x03, &body);
    assert!(resp.len() >= 2, "response must carry a status word");
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    assert_eq!(sw, 0x6700, "64-byte body must be rejected with WRONG_LENGTH");
}

/// The same body with the trailing key-handle byte present (65 bytes, empty
/// handle) is a *valid* frame: check-only (P1=0x07) must answer with a
/// status, and enroll-check (P1=0x03) with a key handle that does not exist
/// must answer WRONG_DATA — exercising the guard's green path.
#[test]
fn u2f_auth_65_byte_body_keeps_serving() {
    let mut app = new_app();
    let mut body = vec![0u8; 65];
    body[..32].fill(0xA1);
    body[32..64].fill(0xA2);
    body[64] = 0; // kh_len = 0
    let resp = drive_auth(&mut app, 0x07, &body);
    assert!(resp.len() >= 2, "response must carry a status word");
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    // P1=0x07 with an unknown handle → WRONG_DATA, not a panic.
    assert_eq!(sw, 0x6A80, "check-only must resolve to WRONG_DATA");
}
