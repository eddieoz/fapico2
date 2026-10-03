//! US-1524 follow-up: the **host twin** must be able to refuse user presence.
//!
//! `apps/fido/src/app.rs` is the host twin — the app the `fapico2-emulation`
//! binary runs. It had no presence gate at all, so `process_ctap2` could never
//! answer `CTAP2 UpRequired`, `firmware/src/hid_serve.rs` never parked a
//! consent window, and the emulator put **no CTAPHID keepalive on the wire,
//! ever**. `tests/pico-fido/test_055_hid.py::test_keep_alive` is the CTAPHID
//! conformance witness that a `makeCredential` reports progress inside 500 ms,
//! and it was red against the emulator because of this gap.
//!
//! The fix is on this twin, not in the shared serve loop: the emulator needs
//! to model a human, and a human is not firmware. (The device-side equivalent
//! — an unconditional `0x01 PROCESSING` per accepted CTAP2 command, which is
//! what `pico-keys-sdk/src/usb/hid/hid.c:585-587` does — was built and
//! measured at +164 B of `.text`, one whole 512 B block past the flash
//! ratchet, so it was routed here instead. `docs/size-report.md` records
//! both numbers.)
//!
//! What this file pins:
//! * default (`None`) grants immediately — the 438 host tests and every
//!   existing suite stay on the behaviour they were written against;
//! * an attached source that denies produces `UpRequired`, signs nothing, and
//!   grants on the next call;
//! * an always-granting source is indistinguishable from no source;
//! * `options.up = false` is decided by US-1526 before the gate is reachable.

use fapico2_fido::app::FidoApp;
use fapico2_fido::cbor::no_heap as nh;
use heapless::Vec as HV;

/// `CTAP2_ERR_UP_REQUIRED` (0x3B) and `CTAP2_ERR_UP_REQUIRED` on the wire —
/// `fido2/ctap.py` names 0x3B `ERR.UP_REQUIRED`, and it is the byte
/// `hid_serve` turns into a parked consent window.
const UP_REQUIRED: u8 = 0x3B;
const SUCCESS: u8 = 0x00;
/// `CTAP2_ERR_INVALID_OPTION` (0x11) — US-1526's `up:false` policy on this
/// twin.
const INVALID_OPTION: u8 = 0x11;

/// `fn() -> bool` cannot capture, so the tests flip a process-global — the
/// same construct `presence_gating.rs` uses for the device twin.
static DENY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn deny() -> bool {
    !DENY.load(Ordering::SeqCst)
}

fn grant() -> bool {
    true
}

use std::sync::atomic::Ordering;

fn app() -> FidoApp {
    FidoApp::with_keystore(fapico2_fido::keystore::MemoryKeystore::new())
}

fn app_with(f: fn() -> bool) -> FidoApp {
    app().with_user_presence(f)
}

fn mc_req(up: Option<bool>) -> Vec<u8> {
    let mut r: HV<u8, 512> = HV::new();
    let pairs = if up.is_some() { 5 } else { 4 };
    nh::push_map_header(&mut r, pairs).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_bstr(&mut r, &[0xCC; 32]).unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_tstr(&mut r, "example.com").unwrap();
    nh::push_uint(&mut r, 3).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_bstr(&mut r, b"user-1").unwrap();
    nh::push_uint(&mut r, 4).unwrap();
    nh::push_array_header(&mut r, 1).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "type").unwrap();
    nh::push_tstr(&mut r, "public-key").unwrap();
    nh::push_tstr(&mut r, "alg").unwrap();
    nh::push_neg(&mut r, -7).unwrap();
    if let Some(v) = up {
        nh::push_uint(&mut r, 5).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "up").unwrap();
        nh::push_bool(&mut r, v).unwrap();
    }
    r.as_slice().to_vec()
}

/// The host twin's default is "grant", and that is load-bearing: every
/// existing host suite runs on it. If this goes red, the change to the
/// `presence` field's `None` arm broke them all at once.
#[test]
fn the_default_source_grants_immediately() {
    let _g = TEST_LOCK.lock().unwrap();
    DENY.store(true, Ordering::SeqCst);
    let mut a = app();
    let out = a.process_ctap2(0x01, &mc_req(None), [0, 0, 0, 1]);
    assert_eq!(
        out[0],
        SUCCESS,
        "with no source attached the host twin must auto-ack, exactly as before \
         US-1524's follow-up: got {:#04x}",
        out[0]
    );
}

/// The gate the emulator depends on: a denying source produces
/// `UpRequired` on the first call and the real answer on the second. That is
/// the whole of the board's frame sequence for a makeCredential — park,
/// `0x01 PROCESSING`, re-drive, grant, answer.
#[test]
fn a_denying_source_makes_make_credential_answer_up_required() {
    let _g = TEST_LOCK.lock().unwrap();
    DENY.store(true, Ordering::SeqCst);
    let mut a = app_with(deny);
    let first = a.process_ctap2(0x01, &mc_req(None), [0, 0, 0, 1]);
    assert_eq!(
        first[0],
        UP_REQUIRED,
        "a makeCredential with no touch must answer UpRequired so the serve \
         loop parks: got {:#04x}",
        first[0]
    );
    assert_eq!(
        first.len(),
        1,
        "the refusal is a bare status byte — nothing may be signed while the \
         touch is outstanding"
    );
    DENY.store(false, Ordering::SeqCst);
    let second = a.process_ctap2(0x01, &mc_req(None), [0, 0, 0, 1]);
    assert_eq!(
        second[0],
        SUCCESS,
        "the windowed retry is granted once the touch lands: got {:#04x}",
        second[0]
    );
}

/// A granting source must be indistinguishable from no source at all —
/// otherwise attaching one (as the emulator does) would change every command
/// that is not a makeCredential.
#[test]
fn a_granting_source_is_indistinguishable_from_the_default() {
    let _g = TEST_LOCK.lock().unwrap();
    DENY.store(true, Ordering::SeqCst);
    let mut with_src = app_with(grant);
    let mut without = app();
    let a = with_src.process_ctap2(0x01, &mc_req(None), [0, 0, 0, 1]);
    let b = without.process_ctap2(0x01, &mc_req(None), [0, 0, 0, 1]);
    assert_eq!(a[0], SUCCESS);
    assert_eq!(
        a[0], b[0],
        "attaching an always-granting source must not change the answer"
    );
}

/// CTAP2 silent authentication never reaches the gate on this twin, because
/// US-1526 already decided it: `up = false` on makeCredential is
/// `INVALID_OPTION` (0x11) here, and that check runs first
/// (`app.rs::make_credential`, "THE `up` POLICY, decided"). The gate's
/// `options.up != Some(false)` condition is therefore defence in depth
/// against a future relaxation of that policy — which is exactly what would
/// be needed for silent auth to work on this twin, and exactly the change
/// that must not quietly start parking windows.
#[test]
fn up_false_is_decided_before_the_gate_is_reachable() {
    let _g = TEST_LOCK.lock().unwrap();
    DENY.store(true, Ordering::SeqCst);
    let mut a = app_with(deny);
    let out = a.process_ctap2(0x01, &mc_req(Some(false)), [0, 0, 0, 1]);
    assert_eq!(
        out[0],
        INVALID_OPTION,
        "US-1526: up=false is INVALID_OPTION on this twin, not a consent-gated \
         command: got {:#04x}",
        out[0]
    );
}
