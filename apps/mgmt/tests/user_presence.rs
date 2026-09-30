//! US-702: user-presence gating of WRITE_CONFIG / config-lock enforcement.
//!
//! The C firmware gates `WRITE_CONFIG` on a physical button press
//! (`management.c`); the Rust device build had `user_present() -> true`
//! compiled in, so any host process could silently reconfigure the token.
//! The device firmware injects the board button as the presence source
//! (`firmware/src/button.rs`); these tests exercise the injectable seam.

use fapico2_mgmt::ManagementApp;
use fapico2_platform::dispatch::{App, MAX_RESPONSE};
use heapless::Vec as HeaplessVec;

static CALLS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn presence_counting() -> bool {
    CALLS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    false
}

fn presence_granted() -> bool {
    CALLS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    true
}

/// The `CALLS` counter is process-global and the presence sources are
/// `fn()` pointers (no capture) — cargo's default per-file parallelism
/// would race the `store(0)`/`assert(==1)` pairs, so every test holds
/// this lock for its duration (the `presence_gating.rs` fixture style).
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Drive one APDU through the app and return (response_bytes, sw).
fn drive(app: &mut ManagementApp, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    app.process(apdu, &mut resp);
    let bytes: Vec<u8> = resp.as_slice().to_vec();
    assert!(bytes.len() >= 2, "response must carry a status word");
    let sw = u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
    (bytes[..bytes.len() - 2].to_vec(), sw)
}

fn write_config_apdu(config: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0x1C, 0x00, 0x00, (1 + config.len()) as u8, config.len() as u8];
    apdu.extend_from_slice(config);
    apdu
}

/// WRITE_CONFIG without a presence grant → 0x6985 and the config unchanged.
#[test]
fn write_config_rejected_without_up() {
    let _g = TEST_LOCK.lock().unwrap();
    CALLS.store(0, core::sync::atomic::Ordering::SeqCst);
    let mut app = ManagementApp::new().with_user_presence(presence_counting);
    let (_, sw) = drive(&mut app, &write_config_apdu(&[0xAA, 0xBB]));
    assert_eq!(sw, 0x6985, "missing user presence must reject WRITE_CONFIG");
    assert!(!app.has_config(), "EF_DEV_CONF must be unchanged");
    assert_eq!(
        CALLS.load(core::sync::atomic::Ordering::SeqCst),
        1,
        "the presence source must be consulted exactly once per WRITE_CONFIG"
    );
}

/// With a grant (the button pressed) WRITE_CONFIG stores the blob.
#[test]
fn write_config_accepted_with_up() {
    let _g = TEST_LOCK.lock().unwrap();
    CALLS.store(0, core::sync::atomic::Ordering::SeqCst);
    let mut app = ManagementApp::new().with_user_presence(presence_granted);
    let (_, sw) = drive(&mut app, &write_config_apdu(&[0xAA, 0xBB]));
    assert_eq!(sw, 0x9000);
    assert!(app.has_config());
}

/// A config whose blob carries TAG_CONFIG_LOCK (0x0A, len 1, value 0x01)
/// locks the device: further WRITE_CONFIG is rejected even *with* presence
/// (C `management.c` config_lock). RESET clears it.
#[test]
fn config_lock_blocks_further_writes() {
    let _g = TEST_LOCK.lock().unwrap();
    let mut app = ManagementApp::new().with_user_presence(presence_granted);
    // Lock byte as the last TLV inside the stored blob.
    let (_, sw) = drive(&mut app, &write_config_apdu(&[0x01, 0x0A, 0x01, 0x01]));
    assert_eq!(sw, 0x9000);

    let (_, sw) = drive(&mut app, &write_config_apdu(&[0x02, 0x03]));
    assert_eq!(sw, 0x6985, "locked config must refuse further writes");

    // READ_CONFIG advertises the locked state (TAG_CONFIG_LOCK = 0x01).
    let (data, _) = drive(&mut app, &[0x00, 0x1D, 0x00, 0x00, 0x00]);
    assert!(data.windows(3).any(|w| w == [0x0A, 0x01, 0x01]), "lock byte must be advertised");

    // RESET clears the lock (factory state) and writes work again.
    let (_, sw) = drive(&mut app, &[0x00, 0x1E, 0x00, 0x00, 0x00]);
    assert_eq!(sw, 0x9000);
    let (_, sw) = drive(&mut app, &write_config_apdu(&[0x05]));
    assert_eq!(sw, 0x9000, "RESET must clear the config lock");
}

/// An unlocked config (no lock TLV) keeps accepting writes.
#[test]
fn unlocked_config_keeps_accepting_writes() {
    let _g = TEST_LOCK.lock().unwrap();
    let mut app = ManagementApp::new().with_user_presence(presence_granted);
    let (_, sw) = drive(&mut app, &write_config_apdu(&[0x0A, 0x01, 0x00]));
    assert_eq!(sw, 0x9000);
    let (_, sw) = drive(&mut app, &write_config_apdu(&[0x07]));
    assert_eq!(sw, 0x9000, "unlocked config must keep accepting writes");
}

// ---------------------------------------------------------------------------
// US-921: the cross-call consent window — the device build injects
// `window_grant` (join-or-open, `fn(u32) -> bool`) and the refused
// command's 6985 OPENS the window: the user's press on the RETRY is
// consent for the retry. The host gate below refuses the first call for a
// tag and grants the retry — the device interleaving, minus the transport.
// ---------------------------------------------------------------------------

/// Gate modes: 0 = deny, 1 = grant, 2 = refuse the first call then grant.
static GATE_MODE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Calls consumed by the gate since the test last reset it.
static GATE_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// The last tag the gate was consulted under (tag-binding pin).
static GATE_TAG: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The device gate stand-in (`fn(u32) -> bool`, no capture — statics only).
fn windowed_grant(tag: u32) -> bool {
    GATE_TAG.store(tag, core::sync::atomic::Ordering::SeqCst);
    let n = GATE_CALLS.fetch_add(1, core::sync::atomic::Ordering::SeqCst) + 1;
    match GATE_MODE.load(core::sync::atomic::Ordering::SeqCst) {
        0 => false,
        1 => true,
        _ => n >= 2,
    }
}

/// Case 14 — WRITE_CONFIG grant-on-2nd-call: the first APDU is 6985 and
/// the config is NOT stored; the windowed retry applies it.
#[test]
fn write_config_granted_on_second_call_applies_once() {
    let _g = TEST_LOCK.lock().unwrap();
    GATE_MODE.store(2, core::sync::atomic::Ordering::SeqCst);
    GATE_CALLS.store(0, core::sync::atomic::Ordering::SeqCst);
    let mut app = ManagementApp::new().with_presence_grant(windowed_grant);

    let (_, sw) = drive(&mut app, &write_config_apdu(&[0xAA, 0xBB]));
    assert_eq!(sw, 0x6985, "the refused first attempt");
    assert!(!app.has_config(), "no config may be stored without a grant");
    assert_eq!(
        GATE_TAG.load(core::sync::atomic::Ordering::SeqCst),
        0x1C,
        "the gate must be consulted under the WRITE_CONFIG tag"
    );

    let (_, sw) = drive(&mut app, &write_config_apdu(&[0xAA, 0xBB]));
    assert_eq!(sw, 0x9000, "the windowed retry applies the config");
    assert!(app.has_config(), "exactly the granted write stored the blob");
    GATE_MODE.store(0, core::sync::atomic::Ordering::SeqCst);
}

/// Case 15 — RESET parity: the first attempt is 6985 and wipes nothing;
/// the windowed retry wipes (the config is gone).
#[test]
fn reset_granted_on_second_call_wipes_once() {
    let _g = TEST_LOCK.lock().unwrap();
    // Provision a config with an always-granting gate, then switch to the
    // windowed gate for the RESET.
    GATE_MODE.store(1, core::sync::atomic::Ordering::SeqCst);
    let mut app = ManagementApp::new().with_presence_grant(windowed_grant);
    let (_, sw) = drive(&mut app, &write_config_apdu(&[0x01, 0x02]));
    assert_eq!(sw, 0x9000);

    GATE_MODE.store(2, core::sync::atomic::Ordering::SeqCst);
    GATE_CALLS.store(0, core::sync::atomic::Ordering::SeqCst);
    let (_, sw) = drive(&mut app, &[0x00, 0x1E, 0x00, 0x00, 0x00]);
    assert_eq!(sw, 0x6985, "the refused first RESET");
    assert!(app.has_config(), "the refused RESET must wipe nothing");
    assert_eq!(
        GATE_TAG.load(core::sync::atomic::Ordering::SeqCst),
        0x1E,
        "the gate must be consulted under the RESET tag"
    );

    let (_, sw) = drive(&mut app, &[0x00, 0x1E, 0x00, 0x00, 0x00]);
    assert_eq!(sw, 0x9000, "the windowed retry wipes");
    assert!(!app.has_config(), "exactly the granted RESET wiped");
    GATE_MODE.store(0, core::sync::atomic::Ordering::SeqCst);
}
