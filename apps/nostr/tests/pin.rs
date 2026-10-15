//! US-1691 — `SET_PIN` on an unset board (EPIC Phase 2).
//!
//! The PIN is the custody root for everything the session gate will protect,
//! so the record's honesty is pinned here before any gate exists: the stored
//! 49 bytes are `counter ‖ salt ‖ SHA256(salt ‖ pin)` — a verifier, never
//! the PIN — the shape refusal costs nothing, and a second `SET_PIN` is a
//! state refusal that leaves the first record standing, including across an
//! applet reboot (the boot-derived `pin_set` cache, fail-closed).
//!
//! The PIN verbs are touch-free by design (§2.2: the PIN is the consent), so
//! these tests run with no presence provider wired — a `6985` here would be
//! a touch gate that must not exist on a PIN verb.

use fapico2_nostr::crypto::pin_verifier;
use fapico2_nostr::NostrApp;
use fapico2_nostr::{
    INS_SET_PIN, PIN_MAX_RETRIES, SW_PIN_ALREADY_SET, SW_STORE_FAULT, SW_WRONG_DATA,
};
use fapico2_platform::dispatch::{App, Sw, SW_OK};
use fapico2_platform::keyregion::crypto::{derive_payload_key, NOSTR_PAYLOAD_SECRET};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::nostr_store::{NostrRegion, PinEntry};
use fapico2_platform::keyregion::TOTAL_SLOTS;
use heapless::Vec as HeaplessVec;

const PIN: &[u8] = b"731742"; // six bytes, the minimum

// ---------------------------------------------------------------------------
// Fixtures (the keymgmt.rs set, mirrored — test files do not name each other)
// ---------------------------------------------------------------------------

fn region_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("fapico2-nostr-us1691-{tag}-{}.bin", std::process::id()))
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

/// Re-open a region a booted app already holds — the read-back path the
/// verifier claim needs, and the reboot path the cache claim needs.
fn open_region(path: &std::path::Path) -> NostrRegion {
    let region = FileKeyRegion::open(path).expect("an existing region file");
    fixture_key(region)
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

fn set_pin(p1: u8, data: &[u8]) -> HeaplessVec<u8, 300> {
    let mut a = HeaplessVec::new();
    a.extend_from_slice(&[0x00, INS_SET_PIN, p1, 0x00]).unwrap();
    a.push(data.len() as u8).unwrap();
    a.extend_from_slice(data).unwrap();
    a
}

/// A deterministic salt: the applet draws 16 bytes for the PIN salt, and the
/// bytes' *values* are not load-bearing — only that the stored verifier is
/// a function of them, which the round trip re-derives.
fn pinned_salt(out: &mut [u8]) {
    for (i, b) in out.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x5B).wrapping_add(0xA0);
    }
}

/// An applet booted from a fresh, empty region, with the salt pinned.
fn booted_app(tag: &str) -> (NostrApp, std::path::PathBuf) {
    let path = region_path(tag);
    std::fs::remove_file(&path).ok();
    let app = NostrApp::boot(fixture_region(&path)).with_rng_provider(pinned_salt);
    (app, path)
}

/// Open the PIN slot's record through an independent store view on the same
/// region file — the "opened with the fixture key" of the acceptance note.
fn stored_pin(path: &std::path::Path) -> PinEntry {
    open_region(path).store().read_pin().expect("the pin slot reads")
}

// ---------------------------------------------------------------------------
// US-1691 acceptance
// ---------------------------------------------------------------------------

/// **`SET_PIN` stores a verifier, not the PIN** — the claim everything else
/// stands on. The sealed record, opened with the fixture key, re-derives
/// `SHA256(salt ‖ pin)` from its own salt, and its body contains no byte
/// sequence of the PIN anywhere a codec could hide one.
#[test]
fn set_pin_stores_verifier_not_the_pin() {
    let (mut app, path) = booted_app("verifier");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK, "a fresh board sets its PIN");

    let record = match stored_pin(&path) {
        PinEntry::Live(record) => record,
        other => panic!("expected a live PIN record, got {other:?}"),
    };
    assert_eq!(record.counter, PIN_MAX_RETRIES, "the budget starts full");
    assert_eq!(
        record.verifier,
        pin_verifier(PIN, &record.salt),
        "the stored verifier is SHA256(salt ‖ pin) over the record's own salt"
    );
    let mut body = [0u8; 49];
    record.encode(&mut body);
    for window in body.windows(PIN.len()) {
        assert!(window != PIN, "the raw PIN bytes appear in the stored record");
    }
    std::fs::remove_file(&path).ok();
}

/// **The shape refusal costs nothing and precedes every state read** —
/// payloads under 6 and over 64 bytes are `6A80` before the store is even
/// touched, and the board after them is still unsettable-by-nothing: a valid
/// `SET_PIN` still succeeds.
#[test]
fn set_pin_refuses_wrong_length_payloads_before_any_state() {
    let (mut app, path) = booted_app("shape");
    let (_, sw) = call(&mut app, &set_pin(0x00, b"12345"));
    assert_eq!(sw, SW_WRONG_DATA, "five bytes is too short");
    let (_, sw) = call(&mut app, &set_pin(0x00, &[0x41u8; 65]));
    assert_eq!(sw, SW_WRONG_DATA, "65 bytes is too long");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK, "the refusals consumed nothing — a valid set still lands");
    assert!(matches!(stored_pin(&path), PinEntry::Live(_)));
    std::fs::remove_file(&path).ok();
}

/// **A second `SET_PIN` is a state refusal, and the first record survives
/// it** — including across an applet reboot, where the `pin_set` cache
/// derives from the region instead of the constructor.
#[test]
fn set_pin_twice_is_refused_and_the_first_record_survives() {
    let (mut app, path) = booted_app("twice");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);
    let first = match stored_pin(&path) {
        PinEntry::Live(record) => record,
        other => panic!("expected a live PIN record, got {other:?}"),
    };

    let (_, sw) = call(&mut app, &set_pin(0x00, b"another"));
    assert_eq!(sw, SW_PIN_ALREADY_SET, "the state does not allow a second set");
    match stored_pin(&path) {
        PinEntry::Live(record) => {
            assert_eq!(record, first, "the stored record is untouched by the refusal");
        }
        other => panic!("expected the first record to survive, got {other:?}"),
    }

    // Reboot: the cache derives from the region, so the second set is
    // refused with no session memory of the first — and a boot over a
    // no-PIN board still sets (pinned by the shape test's fresh board).
    let app2 = NostrApp::boot(open_region(&path)).with_rng_provider(pinned_salt);
    let (mut app2, path) = (app2, path);
    let (_, sw) = call(&mut app2, &set_pin(0x00, b"another"));
    assert_eq!(sw, SW_PIN_ALREADY_SET, "a rebooted applet still knows a PIN exists");
    std::fs::remove_file(&path).ok();
}

/// **Setting is not unlocking, and a P1 other than `0x00` is not `SET_PIN`.**
/// P1 `0x01` is `CHANGE_PIN`'s arm (US-1692) — until that story lands it is
/// a `6A86`, not a silent alias of the set path.
#[test]
fn set_pin_p1_other_than_zero_is_wrong_p1() {
    let (mut app, path) = booted_app("p1");
    let (_, sw) = call(&mut app, &set_pin(0x01, PIN));
    assert_eq!(sw, 0x6A86, "P1 0x01 is CHANGE_PIN's arm, not an alias");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);
    std::fs::remove_file(&path).ok();
}

/// **A store fault is not a silent success**: with no region attached the
/// applet refuses with its own word rather than answering `9000` about a
/// PIN it could not store.
#[test]
fn set_pin_without_a_store_refuses() {
    let mut app = NostrApp::new();
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_STORE_FAULT);
}
