//! US-1837 — the clock seam (EPIC NOSTR-BYPASS-ACCOUNTING, Phase 1).
//!
//! The invariant the file pins: a monotonic millisecond clock reaches the
//! applet as an injected `fn` provider — the same shape as the RNG and
//! presence seams — with `0` as the honest "no clock wired" value, exactly
//! the fido audit ring's `uptime_ms` convention (`apps/fido/src/vendor41.rs`:
//! "the clock is the caller's"). The applet gains no time dependency; the
//! device and the emulator supply the real clock (US-1844), the tests supply
//! a fake.
//!
//! RED until `with_now_provider` and the host-only `now_ms` accessor exist.
//! Later stories in this file build on this seam: US-1838 the accounting
//! state, US-1839 the cap, US-1840 the expiry, US-1841 the ring, US-1842 the
//! GET_AUDIT verb — each story's scenarios land here RED-first.

use fapico2_nostr::{
    crypto, NostrApp, AuditRecord, BYPASS_AUDIT_DEPTH, BYPASS_CAP, INS_LOCK, INS_SET_PIN,
    INS_VERIFY_PIN, SW_PIN_SESSION_REQUIRED, SW_WRONG_P1_P2,
};
use fapico2_platform::dispatch::{App, Sw, SW_OK};
use fapico2_platform::keyregion::crypto::{derive_payload_key, NOSTR_PAYLOAD_SECRET};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::nostr_store::{NostrIdentity, NostrRegion};
use fapico2_platform::keyregion::TOTAL_SLOTS;
use heapless::Vec as HeaplessVec;

/// The thread-local fake clock. `with_now_provider` takes a capture-free
/// `fn`, so the tests' variability lives here — the `PRESSES` counting
/// pattern of the presence tests.
fn fake_now() -> u64 {
    FAKE_MS.with(|c| c.get())
}

fn advance(ms: u64) {
    FAKE_MS.with(|c| c.set(c.get() + ms));
}

thread_local! {
    static FAKE_MS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

// ---------------------------------------------------------------------------
// Fixtures (the touch_bypass.rs set, mirrored — test files do not name each
// other; US-1838 grew the identity and PIN fixtures the later stories share)
// ---------------------------------------------------------------------------

fn region_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fapico2-nostr-us1837-{tag}-{}.bin",
        std::process::id()
    ))
}

fn fixture_key(region: FileKeyRegion) -> NostrRegion {
    let otp_row: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x11));
    let chipid: [u8; 8] = 0x0000_BADC_0FFE_EE01_0203_u64.to_be_bytes();
    let key = derive_payload_key(&otp_row, &chipid, &NOSTR_PAYLOAD_SECRET)
        .expect("a non-zero OTP row");
    NostrRegion::new(Box::new(region), key)
}

fn fixture_region(path: &std::path::Path) -> NostrRegion {
    let region = FileKeyRegion::create(path, TOTAL_SLOTS).expect("a fresh region file");
    fixture_key(region)
}

fn open_region(path: &std::path::Path) -> NostrRegion {
    let region = FileKeyRegion::open(path).expect("an existing region file");
    fixture_key(region)
}

/// The seeded identity's scalar — SIGN's fixture signs with it.
fn seed_scalar() -> [u8; 32] {
    core::array::from_fn(|i| 0x21u8.wrapping_add(i as u8))
}

/// An applet whose slot 1 holds a live identity (the presence.rs shape:
/// SIGN's state refusals must all have passed before the touch is asked).
fn app_with_identity(tag: &str) -> (NostrApp, std::path::PathBuf) {
    let path = region_path(tag);
    std::fs::remove_file(&path).ok();
    {
        let mut region = fixture_region(&path);
        let scalar = seed_scalar();
        let npub = crypto::xonly_pubkey(&scalar).expect("a valid seed scalar");
        let id = NostrIdentity::new(scalar, npub, b"seed", 0).expect("a valid identity");
        region.store().write(1, &id).expect("seed slot 1");
    }
    let app = NostrApp::boot(open_region(&path));
    (app, path)
}

/// Drive one APDU through the applet, returning (data, SW).
fn call(app: &mut NostrApp, apdu: &[u8]) -> (HeaplessVec<u8, 4096>, Sw) {
    let mut resp = HeaplessVec::new();
    app.process(apdu, &mut resp);
    assert!(resp.len() >= 2, "the applet must always answer with a status word");
    let n = resp.len();
    let sw = u16::from_be_bytes([resp[n - 2], resp[n - 1]]);
    let data: HeaplessVec<u8, 4096> = resp[..n - 2].iter().copied().collect();
    (data, sw)
}

fn apdu(ins: u8, p1: u8, data: &[u8]) -> HeaplessVec<u8, 300> {
    let mut a = HeaplessVec::new();
    a.extend_from_slice(&[0x00, ins, p1, 0x00]).unwrap();
    a.push(data.len() as u8).unwrap();
    a.extend_from_slice(data).unwrap();
    a
}

/// A PIN-set, verified applet holding the slot-1 identity — the "session
/// open" precondition the accounting tests need (the touch_bypass.rs shape),
/// with the fake clock wired: arming stamps the timestamp from it, so every
/// accounting test must be able to move time.
fn pin_app(tag: &str) -> (NostrApp, std::path::PathBuf) {
    const PIN: &[u8] = b"731742"; // six bytes, the minimum
    let (app, path) = app_with_identity(tag);
    let mut app = app
        .with_rng_provider(|out| out.fill(0x5A))
        .with_now_provider(fake_now);
    let (_, sw) = call(&mut app, &apdu(INS_SET_PIN, 0x00, PIN));
    assert_eq!(sw, SW_OK, "the fixture's PIN sets");
    let (_, sw) = call(&mut app, &apdu(INS_VERIFY_PIN, 0x00, PIN));
    assert_eq!(sw, SW_OK, "the fixture's session opens");
    (app, path)
}

// ---------------------------------------------------------------------------
// US-1837 — the clock seam
// ---------------------------------------------------------------------------

/// A bare applet with no clock wired reads `0` — and `0` is a legal value,
/// not an error (the fido audit ring's caller-owned clock).
#[test]
fn default_clock_reads_zero() {
    let app = NostrApp::new();
    assert_eq!(app.now_ms(), 0, "no clock wired reads zero, honestly");
}

/// An injected provider is returned verbatim — the applet is a conduit for
/// the caller's clock, never a second source of truth.
#[test]
fn injected_clock_is_returned_verbatim() {
    let app = NostrApp::new().with_now_provider(|| 12_345);
    assert_eq!(app.now_ms(), 12_345, "the injected clock is the clock");
}

/// The clock advances between reads — a fake that never moves would make
/// every later expiry test vacuous.
#[test]
fn clock_advances_between_reads() {
    let app = NostrApp::new().with_now_provider(fake_now);
    let first = app.now_ms();
    advance(50);
    let second = app.now_ms();
    assert_eq!(first, 0, "the fake starts at zero");
    assert_eq!(second, 50, "the second read is strictly greater");
}

// ---------------------------------------------------------------------------
// US-1838 — accounting state beside the flag trio
// ---------------------------------------------------------------------------

/// A fresh applet's accounting starts down: budget 0 (not armed), timestamp
/// 0, ring empty. Budget 0 *means* "not armed" — arming sets [`BYPASS_CAP`].
#[test]
fn accounting_state_starts_down_at_boot() {
    let app = NostrApp::new();
    assert_eq!(app.bypass_budget(), 0, "budget 0 = not armed");
    assert_eq!(app.bypass_armed_at_ms(), 0, "no arming timestamp");
    assert!(
        app.bypass_audit().is_empty(),
        "the ring starts empty"
    );
}

/// The host seam arms like the wire verb will: budget [`BYPASS_CAP`],
/// timestamp stamped from the clock that is wired at arm time.
#[test]
fn the_host_seam_arms_the_budget_and_stamps_the_clock() {
    advance(100);
    let mut app = NostrApp::new().with_now_provider(fake_now);
    assert_eq!(app.bypass_armed_at_ms(), 0, "nothing armed yet");
    app.set_touch_bypass(true);
    assert_eq!(app.bypass_budget(), BYPASS_CAP, "arming fills the budget");
    assert_eq!(app.bypass_armed_at_ms(), 100, "the clock is read at arm time");
}

/// **LOCK clears the accounting state** — the US-1745 rationale applies to
/// every field of the session privilege, not just the flag.
#[test]
fn lock_clears_the_accounting_state() {
    let (mut app, path) = pin_app("acct-lock");
    advance(10);
    app.set_touch_bypass(true);
    let (_, sw) = call(&mut app, &apdu(INS_LOCK, 0x00, &[]));
    assert_eq!(sw, SW_OK, "LOCK answers 9000 idempotently");
    assert_eq!(app.bypass_budget(), 0, "the budget dies with the session");
    assert_eq!(app.bypass_armed_at_ms(), 0, "the timestamp dies with the session");
    assert!(app.bypass_audit().is_empty(), "the ring dies with the session");
    std::fs::remove_file(&path).ok();
}

/// **A failed verify clears the accounting state** — a stale accounting
/// surviving it would let the next VERIFY silently resurrect a half-spent
/// touch-free session the user believes they closed.
#[test]
fn a_failed_verify_clears_the_accounting_state() {
    const WRONG: &[u8] = b"000000";
    let (mut app, path) = pin_app("acct-verify");
    advance(10);
    app.set_touch_bypass(true);
    let (_, sw) = call(&mut app, &apdu(INS_VERIFY_PIN, 0x00, WRONG));
    assert_ne!(sw, SW_OK, "a wrong PIN is refused (63CX)");
    assert_eq!(app.bypass_budget(), 0, "the budget dies with the session");
    assert_eq!(app.bypass_armed_at_ms(), 0, "the timestamp dies with the session");
    assert!(app.bypass_audit().is_empty(), "the ring dies with the session");
    std::fs::remove_file(&path).ok();
}

/// **The factory wipe clears the accounting state** — the flag's clearest
/// site, and the ring's (US-1745's wipe row applies verbatim).
#[test]
fn factory_wipe_clears_the_accounting_state() {
    let (mut app, path) = pin_app("acct-wipe");
    advance(10);
    app.set_touch_bypass(true);
    App::factory_wipe(&mut app);
    assert_eq!(app.bypass_budget(), 0, "the budget dies with the wipe");
    assert_eq!(app.bypass_armed_at_ms(), 0, "the timestamp dies with the wipe");
    assert!(app.bypass_audit().is_empty(), "the ring dies with the wipe");
    std::fs::remove_file(&path).ok();
}

/// **A fresh boot over the same region clears the accounting state** — a
/// boot is the same as a power cycle for the session privilege (US-1741's
/// boot row), and the accounting fields are not exempt.
#[test]
fn a_fresh_boot_over_the_same_region_clears_the_accounting_state() {
    let (mut app, path) = pin_app("acct-boot");
    advance(10);
    app.set_touch_bypass(true);
    let app2 = NostrApp::boot(open_region(&path));
    assert_eq!(app2.bypass_budget(), 0, "the budget comes up down");
    assert_eq!(app2.bypass_armed_at_ms(), 0, "the timestamp comes up down");
    assert!(app2.bypass_audit().is_empty(), "the ring comes up empty");
    let _ = app; // the old session's RAM dies with the drop
    std::fs::remove_file(&path).ok();
}

/// **Deselect preserves the accounting state** — deselect/re-select is not
/// a session close (US-1745's deselect row), and the accounting is not
/// exempt from that.
#[test]
fn deselect_preserves_the_accounting_state() {
    let (mut app, path) = pin_app("acct-deselect");
    advance(10);
    app.set_touch_bypass(true);
    App::deselect(&mut app);
    assert_eq!(app.bypass_budget(), BYPASS_CAP, "the budget survives deselect");
    assert_eq!(app.bypass_armed_at_ms(), 10, "the timestamp survives deselect");
    std::fs::remove_file(&path).ok();
}
