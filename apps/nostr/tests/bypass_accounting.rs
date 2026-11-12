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
    crypto, NostrApp, AuditRecord, BYPASS_AUDIT_DEPTH, BYPASS_CAP, BYPASS_SESSION_MS,
    INS_GET_AUDIT, INS_GET_INFO, INS_LOCK, INS_NIP44_DECRYPT, INS_NIP44_ENCRYPT, INS_SET_PIN,
    INS_SIGN, INS_VERIFY_PIN, OP_NIP44_DEC, OP_NIP44_ENC, OP_SIGN, SW_PIN_SESSION_REQUIRED,
    SW_TOUCH_REQUIRED,
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

/// The counting grant closures — the touch_bypass.rs `PRESSES` pattern.
/// `counting_deny` counts the consult and refuses; `counting_allow` counts
/// and grants. `presses()` reads the ledger.
fn presses() -> u32 {
    PRESSES.with(|p| p.get())
}

fn counting_deny(_tag: u32) -> bool {
    PRESSES.with(|p| p.set(p.get() + 1));
    false
}

fn counting_allow(_tag: u32) -> bool {
    PRESSES.with(|p| p.set(p.get() + 1));
    true
}

thread_local! {
    static PRESSES: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

// ---------------------------------------------------------------------------
// NIP-44 APDU fixtures (the touch_bypass.rs shape)
// ---------------------------------------------------------------------------

/// A valid curve point that is not the identity — the NIP-44 peer.
fn peer_x() -> [u8; 32] {
    let peer_scalar: [u8; 32] = core::array::from_fn(|i| 0x71u8.wrapping_add(i as u8));
    crypto::xonly_pubkey(&peer_scalar).expect("a valid peer scalar")
}

fn apdu_nip44_encrypt(idx: u8, plaintext: &[u8]) -> HeaplessVec<u8, 300> {
    let mut d = Vec::new();
    d.extend_from_slice(&peer_x());
    d.extend_from_slice(plaintext);
    apdu(INS_NIP44_ENCRYPT, idx, &d)
}

fn apdu_nip44_decrypt(idx: u8, payload: &[u8]) -> HeaplessVec<u8, 300> {
    let mut d = Vec::new();
    d.extend_from_slice(&peer_x());
    d.extend_from_slice(payload);
    apdu(INS_NIP44_DECRYPT, idx, &d)
}

/// The `SET_TOUCH_POLICY` verb — INS `0x1F`; P1 selects the leg.
fn apdu_policy_verb(p1: u8) -> HeaplessVec<u8, 300> {
    apdu(0x1F, p1, &[])
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

// ---------------------------------------------------------------------------
// US-1839 — the cap
// ---------------------------------------------------------------------------

/// **Thirty-two bypassed SIGNs run grant-free** — the whole [`BYPASS_CAP`]
/// budget, consumed one per operation, with the grant closure never
/// consulted.
#[test]
fn thirty_two_bypassed_signs_run_grant_free() {
    let (app, path) = pin_app("cap-signs");
    let mut app = app.with_presence_grant(counting_deny);
    app.set_touch_bypass(true);
    for i in 0..BYPASS_CAP {
        let (_, sw) = call(&mut app, &apdu(INS_SIGN, 1, &[0x5A; 32]));
        assert_eq!(sw, SW_OK, "bypassed SIGN #{i} needs no press");
        assert_eq!(app.bypass_budget(), BYPASS_CAP - 1 - i, "budget counts down");
    }
    assert_eq!(presses(), 0, "no press was ever consulted");
    std::fs::remove_file(&path).ok();
}

/// **The thirty-third requires the press** — the budget exhausted at 0, the
/// guard behaves exactly as bypass-off: the grant closure is consulted and
/// the refusal is [`SW_TOUCH_REQUIRED`].
#[test]
fn the_thirty_third_requires_the_press() {
    let (app, path) = pin_app("cap-33rd");
    let mut app = app.with_presence_grant(counting_deny);
    app.set_touch_bypass(true);
    for _ in 0..BYPASS_CAP {
        let (_, sw) = call(&mut app, &apdu(INS_SIGN, 1, &[0x5A; 32]));
        assert_eq!(sw, SW_OK);
    }
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 1, &[0x5A; 32]));
    assert_eq!(sw, SW_TOUCH_REQUIRED, "a spent budget costs a press");
    assert_eq!(presses(), 1, "the grant was consulted exactly once");
    std::fs::remove_file(&path).ok();
}

/// **A pressed 33rd succeeds and does not go negative** — the touch path is
/// untouched by the accounting: the press grants, the operation runs, and
/// the budget stays at 0 (saturating, never wrapping).
#[test]
fn a_pressed_33rd_succeeds_and_does_not_go_negative() {
    let (app, path) = pin_app("cap-press");
    let mut app = app.with_presence_grant(counting_deny);
    app.set_touch_bypass(true);
    for _ in 0..BYPASS_CAP {
        call(&mut app, &apdu(INS_SIGN, 1, &[0x5A; 32]));
    }
    let mut app = app.with_presence_grant(counting_allow);
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 1, &[0x5A; 32]));
    assert_eq!(sw, SW_OK, "the press grants, the operation runs");
    assert_eq!(app.bypass_budget(), 0, "a touched op burns no budget");
    assert_eq!(presses(), 1, "the press was real");
    std::fs::remove_file(&path).ok();
}

/// **The cap counts ENC and DEC too** — the budget is per *session*, not
/// per verb: 16 ENC + 16 DEC spend it, and the 17th ENC needs the touch.
#[test]
fn the_cap_counts_enc_and_dec_too() {
    let (app, path) = pin_app("cap-encdec");
    let mut app = app
        .with_presence_grant(counting_deny)
        .with_rng_provider(|out| out.fill(0x42));
    app.set_touch_bypass(true);
    let plaintext = b"budgeted conversation";
    for i in 0..16u8 {
        let (ct, sw) = call(&mut app, &apdu_nip44_encrypt(1, plaintext));
        assert_eq!(sw, SW_OK, "bypassed ENC #{i}");
        let (_, sw) = call(&mut app, &apdu_nip44_decrypt(1, &ct));
        assert_eq!(sw, SW_OK, "bypassed DEC #{i}");
    }
    assert_eq!(app.bypass_budget(), 0, "32 ops spent the session");
    let (_, sw) = call(&mut app, &apdu_nip44_encrypt(1, plaintext));
    assert_eq!(sw, SW_TOUCH_REQUIRED, "the 33rd op costs a press");
    assert_eq!(presses(), 1, "the grant was consulted once");
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// US-1840 — the expiry
// ---------------------------------------------------------------------------

/// **Inside the window the bypass still exempts** — one millisecond before
/// [`BYPASS_SESSION_MS`], the armed session runs grant-free.
#[test]
fn inside_the_window_the_bypass_still_exempts() {
    let (app, path) = pin_app("exp-inside");
    let mut app = app.with_presence_grant(counting_deny);
    app.set_touch_bypass(true); // armed at the clock's 0
    advance(BYPASS_SESSION_MS - 1);
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 1, &[0x5A; 32]));
    assert_eq!(sw, SW_OK, "the session lives until the deadline");
    assert_eq!(presses(), 0, "no press inside the window");
    std::fs::remove_file(&path).ok();
}

/// **Past the window the press is required and the flag is cleared** — the
/// expiry is lazy but truthful: the guard clears the session at guard time,
/// so the very next GET_INFO reports the bypass down.
#[test]
fn past_the_window_the_press_is_required_and_the_flag_is_cleared() {
    let (app, path) = pin_app("exp-past");
    let mut app = app.with_presence_grant(counting_deny);
    app.set_touch_bypass(true);
    advance(BYPASS_SESSION_MS);
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 1, &[0x5A; 32]));
    assert_eq!(sw, SW_TOUCH_REQUIRED, "an expired session costs a press");
    assert_eq!(presses(), 1, "the grant was consulted once");
    let (data, sw) = call(&mut app, &apdu(INS_GET_INFO, 0x00, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(
        data[7] & 0x08,
        0,
        "GET_INFO no longer advertises the bypass — the lazy clear is truthful"
    );
    std::fs::remove_file(&path).ok();
}

/// **Re-arming after expiry resets the budget and the timestamp** — the
/// expired session is gone, but the PIN session still stands, so the verb
/// can arm again; the new session starts whole.
#[test]
fn re_arming_after_expiry_resets_the_budget_and_the_timestamp() {
    let (app, path) = pin_app("exp-rearm");
    let mut app = app.with_presence_grant(counting_allow);
    app.set_touch_bypass(true);
    advance(BYPASS_SESSION_MS);
    call(&mut app, &apdu(INS_SIGN, 1, &[0x5A; 32])); // expires + clears lazily
    advance(100);
    let (_, sw) = call(&mut app, &apdu_policy_verb(0x01));
    assert_eq!(sw, SW_OK, "the PIN session still stands after expiry");
    assert_eq!(app.bypass_budget(), BYPASS_CAP, "the new session starts whole");
    assert_eq!(app.bypass_armed_at_ms(), BYPASS_SESSION_MS + 100, "the new stamp");
    std::fs::remove_file(&path).ok();
}

/// **Re-arming while live also resets the budget** — arming is the reset:
/// a half-spent session re-armed by the verb's press starts whole again.
#[test]
fn re_arming_while_live_also_resets_the_budget() {
    let (app, path) = pin_app("exp-live");
    let mut app = app.with_presence_grant(counting_allow);
    app.set_touch_bypass(true);
    for _ in 0..5 {
        call(&mut app, &apdu(INS_SIGN, 1, &[0x5A; 32]));
    }
    assert_eq!(app.bypass_budget(), BYPASS_CAP - 5);
    advance(100);
    let (_, sw) = call(&mut app, &apdu_policy_verb(0x01));
    assert_eq!(sw, SW_OK, "the verb's press re-arms");
    assert_eq!(app.bypass_budget(), BYPASS_CAP, "the budget is whole again");
    assert_eq!(app.bypass_armed_at_ms(), 100, "the stamp is the new clock value");
    std::fs::remove_file(&path).ok();
}

/// **A stale session reads as gone** (the final review's Important finding):
/// the expiry must not live only in the signing guards — GET_INFO and
/// GET_AUDIT run the same leg, or ten idle minutes leave the popup
/// advertising "bypass armed — 32 left" over a session the very next
/// signature will refuse. The dead session's ring reads as gone with it,
/// the same rule every other session death obeys (LOCK, failed verify,
/// wipe): the ring accounts the *live* session.
#[test]
fn a_stale_session_reads_as_gone() {
    let (app, path) = pin_app("stale-read");
    let mut app = app.with_now_provider(fake_now);
    app.set_touch_bypass(true);
    call(&mut app, &apdu(INS_SIGN, 1, &[0x5A; 32]));
    advance(BYPASS_SESSION_MS + 1);
    // No signing command in between — the read paths must decide.
    let (data, sw) = call(&mut app, &apdu(INS_GET_INFO, 0x00, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(data[7] & 0x08, 0, "GET_INFO must not advertise a dead session");
    let (data, sw) = call(&mut app, &apdu(INS_GET_AUDIT, 0x00, &[]));
    assert_eq!(sw, SW_OK);
    let (budget, records) = parse_audit_body(&data);
    assert_eq!(budget, 0, "the stale budget reads as gone");
    assert!(records.is_empty(), "the dead session's ring reads as gone");
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// US-1841 — the audit ring
// ---------------------------------------------------------------------------

/// SHA-256 over the request payload, truncated to 16 — the record digest the
/// arms write. Mirrored here so the tests verify the *value*, not the code.
fn digest16(data: &[u8]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let full = Sha256::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// **Each bypassed SIGN appends one record** — op, identity index, the
/// clock at operation time, and the digest of what was signed.
#[test]
fn each_bypassed_sign_appends_one_record() {
    let (app, path) = pin_app("ring-sign");
    let mut app = app
        .with_presence_grant(counting_deny)
        .with_now_provider(fake_now);
    app.set_touch_bypass(true);
    for i in 0..3u8 {
        advance(10);
        let (_, sw) = call(&mut app, &apdu(INS_SIGN, 1, &[i.wrapping_add(0x40); 32]));
        assert_eq!(sw, SW_OK, "bypassed SIGN #{i}");
    }
    let ring = app.bypass_audit();
    assert_eq!(ring.len(), 3, "one record per bypassed op");
    for (i, r) in ring.iter().enumerate() {
        let i = i as u8;
        assert_eq!(r.op, OP_SIGN, "op tag");
        assert_eq!(r.idx, 1, "identity index");
        assert_eq!(r.ts_ms, (i as u32 + 1) * 10, "the clock at op time");
        assert_eq!(
            r.digest,
            digest16(&[i.wrapping_add(0x40); 32]),
            "the digest of what was signed"
        );
    }
    std::fs::remove_file(&path).ok();
}

/// **The touched 33rd writes no record** — a touched op already has its
/// consent artifact; the ring is bypass accounting, not an operation log.
#[test]
fn the_touched_33rd_writes_no_record() {
    let (app, path) = pin_app("ring-touched");
    let mut app = app.with_presence_grant(counting_deny);
    app.set_touch_bypass(true);
    for _ in 0..BYPASS_CAP {
        call(&mut app, &apdu(INS_SIGN, 1, &[0x5A; 32]));
    }
    assert_eq!(app.bypass_audit().len(), BYPASS_AUDIT_DEPTH, "ring full");
    let mut app = app.with_presence_grant(counting_allow);
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 1, &[0x5A; 32]));
    assert_eq!(sw, SW_OK, "the press grants");
    assert_eq!(
        app.bypass_audit().len(),
        BYPASS_AUDIT_DEPTH,
        "the touched op wrote no record"
    );
    std::fs::remove_file(&path).ok();
}

/// **The ring overwrites the oldest** — 17 bypassed operations leave 16
/// records, and the oldest survivor is operation #1's (zero-indexed #0
/// fell off).
#[test]
fn the_ring_overwrites_the_oldest() {
    let (app, path) = pin_app("ring-overwrite");
    let mut app = app.with_presence_grant(counting_deny);
    app.set_touch_bypass(true);
    for i in 0..17u8 {
        let (_, sw) = call(&mut app, &apdu(INS_SIGN, 1, &[i.wrapping_add(0x40); 32]));
        assert_eq!(sw, SW_OK, "bypassed SIGN #{i}");
    }
    let ring = app.bypass_audit();
    assert_eq!(ring.len(), BYPASS_AUDIT_DEPTH, "16 survivors");
    assert_ne!(
        ring[0].digest,
        digest16(&[0x40; 32]),
        "operation #0 fell off"
    );
    assert_eq!(
        ring[0].digest,
        digest16(&[0x41; 32]),
        "operation #1 is the oldest survivor"
    );
    assert_eq!(
        ring[15].digest,
        digest16(&[0x50; 32]),
        "operation #16 is the newest"
    );
    std::fs::remove_file(&path).ok();
}

/// **ENC and DEC records carry their op tags and payload digests** — the
/// whole request payload is digested (`peer ‖ plaintext` / `peer ‖ payload`),
/// so a record identifies both the counterpart and the content.
#[test]
fn enc_and_dec_records_carry_their_op_tags_and_payload_digests() {
    let (app, path) = pin_app("ring-encdec");
    let mut app = app
        .with_presence_grant(counting_deny)
        .with_rng_provider(|out| out.fill(0x42))
        .with_now_provider(fake_now);
    app.set_touch_bypass(true);
    let plaintext = b"audited conversation";
    let (ct, sw) = call(&mut app, &apdu_nip44_encrypt(1, plaintext));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &apdu_nip44_decrypt(1, &ct));
    assert_eq!(sw, SW_OK);
    let ring = app.bypass_audit();
    assert_eq!(ring.len(), 2);
    assert_eq!(ring[0].op, OP_NIP44_ENC);
    let enc_payload: Vec<u8> = peer_x().iter().copied().chain(plaintext.iter().copied()).collect();
    assert_eq!(ring[0].digest, digest16(&enc_payload));
    assert_eq!(ring[1].op, OP_NIP44_DEC);
    let dec_payload: Vec<u8> = peer_x().iter().copied().chain(ct.iter().copied()).collect();
    assert_eq!(ring[1].digest, digest16(&dec_payload));
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// US-1842 — the GET_AUDIT verb
// ---------------------------------------------------------------------------

/// The wire body: `budget(1) ‖ n(1) ‖ n × { op(1), idx(1), ts(4 BE),
/// digest(16) }`. Mirrored here so the tests verify the *shape*, not the
/// code.
fn parse_audit_body(data: &[u8]) -> (u8, Vec<AuditRecord>) {
    let budget = data[0];
    let n = data[1] as usize;
    let mut records = Vec::new();
    for i in 0..n {
        let b = &data[2 + i * 22..2 + (i + 1) * 22];
        records.push(AuditRecord {
            op: b[0],
            idx: b[1],
            ts_ms: u32::from_be_bytes([b[2], b[3], b[4], b[5]]),
            digest: b[6..22].try_into().expect("a 16-byte digest"),
        });
    }
    (budget, records)
}

/// **A closed session is refused** — the ring is session-adjacent state:
/// the read rides the same gate the secret operations do, so a sessionless
/// host learns nothing, not even the budget.
#[test]
fn a_closed_session_is_refused() {
    let (app, path) = app_with_identity("audit-closed");
    let mut app = app.with_rng_provider(|out| out.fill(0x5A));
    let (_, sw) = call(&mut app, &apdu(INS_SET_PIN, 0x00, b"731742"));
    assert_eq!(sw, SW_OK, "the fixture's PIN sets");
    // No VERIFY — the session is closed.
    let (_, sw) = call(&mut app, &apdu(INS_GET_AUDIT, 0x00, &[]));
    assert_eq!(sw, SW_PIN_SESSION_REQUIRED, "a sessionless host learns nothing");
    std::fs::remove_file(&path).ok();
}

/// **An open session reads budget and records** — the body is
/// `budget ‖ n ‖ records`, well-formed, matching what the arms wrote.
#[test]
fn an_open_session_reads_budget_and_records() {
    let (mut app, path) = pin_app("audit-read");
    app.set_touch_bypass(true);
    advance(10);
    call(&mut app, &apdu(INS_SIGN, 1, &[0x41; 32]));
    advance(10);
    call(&mut app, &apdu(INS_SIGN, 1, &[0x42; 32]));
    let (data, sw) = call(&mut app, &apdu(INS_GET_AUDIT, 0x00, &[]));
    assert_eq!(sw, SW_OK);
    let (budget, records) = parse_audit_body(&data);
    assert_eq!(budget, BYPASS_CAP - 2, "the budget is the session's");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].op, OP_SIGN);
    assert_eq!(records[0].idx, 1);
    assert_eq!(records[0].ts_ms, 10);
    assert_eq!(records[0].digest, digest16(&[0x41; 32]));
    assert_eq!(records[1].ts_ms, 20);
    std::fs::remove_file(&path).ok();
}

/// **A PIN-less board answers honestly empty** — the bypass can never have
/// been armed there, so an empty ring is the truth, not a refusal.
#[test]
fn a_pin_less_board_answers_honestly_empty() {
    let (mut app, path) = app_with_identity("audit-no-pin");
    let (data, sw) = call(&mut app, &apdu(INS_GET_AUDIT, 0x00, &[]));
    assert_eq!(sw, SW_OK);
    let (budget, records) = parse_audit_body(&data);
    assert_eq!(budget, 0);
    assert!(records.is_empty(), "nothing to audit");
    std::fs::remove_file(&path).ok();
}

/// **LOCK closes the read along with the session** — the ring dies with the
/// session (US-1838), and the read dies with it too.
#[test]
fn lock_closes_the_read_along_with_the_session() {
    let (mut app, path) = pin_app("audit-lock");
    app.set_touch_bypass(true);
    call(&mut app, &apdu(INS_SIGN, 1, &[0x5A; 32]));
    let (_, sw) = call(&mut app, &apdu(INS_LOCK, 0x00, &[]));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &apdu(INS_GET_AUDIT, 0x00, &[]));
    assert_eq!(sw, SW_PIN_SESSION_REQUIRED, "the read died with the session");
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// US-1843 — the capability bit
// ---------------------------------------------------------------------------

/// **GET_INFO advertises the accounting** on both board shapes — the caps
/// bit is unconditional (the verb is served whatever the PIN state), the
/// flags byte is unchanged (bit 3 already carries the live state, and the
/// US-1840 lazy clear keeps it truthful), and `APPLET_VERSION` is
/// untouched: a command added is not a layout change.
#[test]
fn get_info_advertises_bypass_accounting_on_both_board_shapes() {
    use fapico2_nostr::{APPLET_VERSION, CAPS, CAP_BYPASS_ACCOUNTING};
    assert_eq!(CAPS & CAP_BYPASS_ACCOUNTING, CAP_BYPASS_ACCOUNTING);
    for tag in ["caps-pin", "caps-nopin"] {
        let path = region_path(tag);
        std::fs::remove_file(&path).ok();
        let mut app = NostrApp::boot(fixture_region(&path));
        if tag == "caps-pin" {
            let (_, sw) = call(&mut app, &apdu(INS_SET_PIN, 0x00, b"731742"));
            assert_eq!(sw, SW_OK);
        }
        let (data, sw) = call(&mut app, &apdu(INS_GET_INFO, 0x00, &[]));
        assert_eq!(sw, SW_OK);
        assert_eq!(u16::from_be_bytes([data[2], data[3]]), CAPS, "the advertised caps");
        assert_eq!(&data[0..2], APPLET_VERSION.as_slice(), "version unchanged");
        // The flags byte: bit 3 is FLAG_TOUCH_BYPASS and is down here (the
        // session is not armed); the upper nibble stays unused — the byte's
        // layout is closed above bit 3 (bits 0-2 carry real board state:
        // PIN set, session open, migration pending).
        assert_eq!(data[7] & 0x08, 0, "the bypass flag is down");
        assert_eq!(data[7] & 0xF0, 0, "no flag bits above bit 3 — the layout is closed");
        std::fs::remove_file(&path).ok();
    }
}

// ---------------------------------------------------------------------------
// US-1844 — the clock is actually wired (the presence.rs source-reading
// pattern: the wiring gates that cannot fail as unit tests otherwise)
// ---------------------------------------------------------------------------

/// **The device path wires the monotonic clock** — `install_nostr_providers`
/// takes the caller's clock (`now: fn() -> u64`, because `tasks` belongs to
/// the device binary and the lib cannot name it) and main.rs hands it
/// `tasks::now_ms`, the same millisecond clock the HID assemblers' timeouts
/// use. Without this the bypass never expires on the device (an unwired
/// clock reads 0) and the accounting is dead code where it matters.
#[test]
fn install_nostr_providers_wires_the_monotonic_clock() {
    let shared_rs = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../firmware/src/nostr_shared.rs"
    ))
    .expect("firmware/src/nostr_shared.rs is readable from the nostr test crate");
    let signature = shared_rs
        .split("pub fn install_nostr_providers(")
        .nth(1)
        .expect("install_nostr_providers exists");
    let signature = &signature[..signature
        .find(") {")
        .expect("the signature terminates")];
    assert!(
        signature.contains("now: fn() -> u64"),
        "install_nostr_providers must take the caller's clock — the lib cannot \
         name the device binary's tasks module"
    );
    let call = shared_rs
        .split("install_providers(")
        .nth(1)
        .expect("install_nostr_providers calls install_providers");
    let call = &call[..call.find(";").expect("the install_providers call terminates")];
    assert!(
        call.contains(", now)"),
        "install_nostr_providers must pass the caller's clock into the applet — \
         without it the bypass never expires on the device"
    );
    let main_rs = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../firmware/src/main.rs"
    ))
    .expect("firmware/src/main.rs is readable from the nostr test crate");
    let boot_chain = main_rs
        .split("install_nostr_providers(")
        .nth(1)
        .expect("main.rs installs the nostr providers");
    let boot_chain = &boot_chain[..boot_chain
        .find(";")
        .expect("the install_nostr_providers statement terminates")];
    assert!(
        boot_chain.contains("tasks::now_ms"),
        "main.rs must hand the applet the device's monotonic clock — \
         without it the bypass never expires on the device"
    );
}

/// **The emulator wires its virtual clock** — `emul_now_ms` into the booted
/// nostr applet, so the CCID suites can exercise expiry with real time.
#[test]
fn the_emulator_wires_its_virtual_clock_into_the_nostr_applet() {
    let emul = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../firmware/src/emul_main.rs"
    ))
    .expect("firmware/src/emul_main.rs is readable from the nostr test crate");
    let chain = emul
        .split("NostrApp::boot(region)")
        .nth(1)
        .expect("emul_main.rs boots the nostr applet");
    let chain = &chain[..chain.find(";").expect("the nostr_app construction terminates")];
    assert!(
        chain.contains("with_now_provider"),
        "the emulator must wire emul_now_ms into the nostr applet — \
         without it the CCID suites cannot exercise expiry"
    );
}
