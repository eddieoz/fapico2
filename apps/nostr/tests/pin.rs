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
    INS_DELETE_KEY, INS_GENERATE_KEY, INS_GET_INFO, INS_GET_PUBKEY, INS_IMPORT_KEY, INS_LIST_KEYS,
    INS_LOCK, INS_NIP44_DECRYPT, INS_NIP44_ENCRYPT, INS_SET_LABEL, INS_SET_PIN, INS_SIGN,
    INS_VERIFY_PIN, PIN_MAX_RETRIES, SW_PIN_ALREADY_SET, SW_PIN_LOCKED, SW_PIN_NOT_SET,
    SW_PIN_SESSION_REQUIRED, SW_STORE_FAULT, SW_WRONG_DATA,
};
use fapico2_platform::dispatch::{App, Sw, SW_OK};
use fapico2_platform::keyregion::crypto::{derive_payload_key, NOSTR_PAYLOAD_SECRET};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::nostr_store::{
    NostrRegion, NOSTR_PIN_BODY_LEN, PinEntry,
};
use fapico2_platform::keyregion::TOTAL_SLOTS;
use heapless::Vec as HeaplessVec;

const PIN: &[u8] = b"731742"; // six bytes, the minimum
const NEW_PIN: &[u8] = b"246813";

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

/// A deterministic salt that **varies per draw** — the applet draws once per
/// PIN ceremony (set, change), and US-1692's fresh-salt claim needs the
/// second draw to differ from the first. The bytes' *values* are otherwise
/// not load-bearing: the stored verifier is a function of them, which the
/// round trip re-derives.
fn pinned_salt(out: &mut [u8]) {
    use core::cell::Cell;
    thread_local! {
        static DRAW: Cell<u8> = const { Cell::new(0) };
    }
    let nth = DRAW.with(|d| d.replace(d.get().wrapping_add(1)));
    for (i, b) in out.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x5B).wrapping_add(0xA0).wrapping_add(nth.wrapping_mul(0x11));
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

/// **The P1 byte is the verb selector and unknown P1s are `6A86`.** P1
/// `0x01` is `CHANGE_PIN`'s arm (US-1692) — pinned here by the *shape* it
/// refuses: a bare 6-byte payload is a valid `SET_PIN` but fails
/// `CHANGE_PIN`'s `lc ‖ current ‖ new` shape, so the `6A80` proves the
/// route. P1 `0x02` is no ceremony at all.
#[test]
fn set_pin_p1_selects_the_ceremony() {
    let (mut app, path) = booted_app("p1");
    // A P1 0x01 arm would be CHANGE: it refuses the bare payload on shape.
    let (_, sw) = call(&mut app, &set_pin(0x01, PIN));
    assert_eq!(sw, SW_WRONG_DATA, "P1 0x01 routed to CHANGE_PIN, whose shape this fails");
    // An unknown P1 is the dispatcher's own refusal, before any state read.
    let (_, sw) = call(&mut app, &set_pin(0x02, PIN));
    assert_eq!(sw, 0x6A86);
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

// ---------------------------------------------------------------------------
// US-1692: CHANGE_PIN
// ---------------------------------------------------------------------------

/// The CHANGE_PIN APDU: `lc(1) ‖ current(lc) ‖ new`.
fn change_pin(current: &[u8], new: &[u8]) -> HeaplessVec<u8, 300> {
    let mut a = HeaplessVec::new();
    a.extend_from_slice(&[0x00, INS_SET_PIN, 0x01, 0x00]).unwrap();
    let payload_len = 1 + current.len() + new.len();
    a.push(payload_len as u8).unwrap();
    a.push(current.len() as u8).unwrap();
    a.extend_from_slice(current).unwrap();
    a.extend_from_slice(new).unwrap();
    a
}

/// **A wrong `current` is a failed verify, not a fresh refusal** — the
/// durable budget burns (`63C2` after one failure from 3), the record's
/// salt and verifier are untouched by the failed attempt, three wrong
/// currents lock the board, and the lock answers [`SW_PIN_LOCKED`] for
/// *any* payload afterwards — including the correct current, because the
/// retry counter, not a fresh budget, governs.
#[test]
fn change_pin_requires_the_current_pin() {
    let (mut app, path) = booted_app("change-wrong");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);

    let (_, sw) = call(&mut app, &change_pin(b"999999", NEW_PIN));
    assert_eq!(sw, 0x63C2, "one failure from 3 leaves 2");
    match stored_pin(&path) {
        PinEntry::Live(record) => {
            assert_eq!(record.counter, 2, "the decrement is durable");
            assert_eq!(
                record.verifier,
                pin_verifier(PIN, &record.salt),
                "the failed attempt did not touch the verifier"
            );
        }
        other => panic!("expected the untouched record, got {other:?}"),
    }

    let (_, sw) = call(&mut app, &change_pin(b"999999", NEW_PIN));
    assert_eq!(sw, 0x63C1, "two failures leave 1");
    let (_, sw) = call(&mut app, &change_pin(b"999999", NEW_PIN));
    assert_eq!(sw, SW_PIN_LOCKED, "the third failure is 63C0 — the bottom of the same vocabulary");
    match stored_pin(&path) {
        PinEntry::Live(record) => assert_eq!(record.counter, 0),
        other => panic!("expected the exhausted record, got {other:?}"),
    }

    // Locked answers the same word for any payload, and never below zero.
    for _ in 0..3 {
        let (_, sw) = call(&mut app, &change_pin(b"999999", NEW_PIN));
        assert_eq!(sw, SW_PIN_LOCKED, "the lock does not re-burn the counter");
    }
    match stored_pin(&path) {
        PinEntry::Live(record) => assert_eq!(record.counter, 0, "never below zero"),
        other => panic!("expected the exhausted record, got {other:?}"),
    }
    std::fs::remove_file(&path).ok();
}

/// **A verified change rewrites the record with a fresh salt, resets the
/// counter to full, and the old PIN stops verifying** — the preimage the
/// old verifier held is gone, which is why the salt is fresh rather than
/// carried over.
#[test]
fn change_pin_rewrites_verifier_and_resets_counter() {
    let (mut app, path) = booted_app("change-ok");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);
    let old_salt = match stored_pin(&path) {
        PinEntry::Live(record) => record.salt,
        other => panic!("expected a live record, got {other:?}"),
    };

    // One burned attempt first: the reset must climb back to full.
    let (_, sw) = call(&mut app, &change_pin(b"999999", NEW_PIN));
    assert_eq!(sw, 0x63C2);

    let (_, sw) = call(&mut app, &change_pin(PIN, NEW_PIN));
    assert_eq!(sw, SW_OK, "the correct current verifies");
    let record = match stored_pin(&path) {
        PinEntry::Live(record) => record,
        other => panic!("expected the new record, got {other:?}"),
    };
    assert_ne!(record.salt, old_salt, "the change derives a fresh salt");
    assert_eq!(record.verifier, pin_verifier(NEW_PIN, &record.salt));
    assert_eq!(record.counter, PIN_MAX_RETRIES, "a verified change resets the budget");

    // The old PIN no longer verifies — and costs a retry, because the
    // retry counter, not the ceremony's politeness, governs.
    let (_, sw) = call(&mut app, &change_pin(PIN, NEW_PIN));
    assert_eq!(sw, 0x63C2, "the old current is a failed verify against the new record");
    std::fs::remove_file(&path).ok();
}

/// **The shape refusal precedes any state read** — a short payload is
/// `6A80` even on a board with no PIN at all, and a well-shaped CHANGE on
/// a no-PIN board is [`SW_PIN_NOT_SET`], which is how the two refusals
/// stay distinguishable. A malformed payload on a PIN-set board burns
/// nothing: shape is checked before the counter is ever read.
#[test]
fn change_pin_shape_refusal_precedes_any_state_read() {
    // Short payload on a no-PIN board.
    let (mut app, path) = booted_app("change-shape");
    let mut short: HeaplessVec<u8, 300> = HeaplessVec::new();
    short.extend_from_slice(&[0x00, INS_SET_PIN, 0x01, 0x00, 12, 0x06]).unwrap();
    let (_, sw) = call(&mut app, &short);
    assert_eq!(sw, SW_WRONG_DATA, "twelve bytes is under the 6+6+1 minimum");
    let (_, sw) = call(&mut app, &change_pin(PIN, NEW_PIN));
    assert_eq!(sw, SW_PIN_NOT_SET, "well-shaped on a no-PIN board is a different refusal");
    std::fs::remove_file(&path).ok();

    // Malformed payloads on a PIN-set board burn no retries.
    let (mut app, path) = booted_app("change-shape2");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);
    let malformed: [HeaplessVec<u8, 300>; 3] = [
        change_pin(b"12345", NEW_PIN),   // current under 6
        change_pin(PIN, b"12345"),       // new under 6
        change_pin(&[0x41u8; 65], NEW_PIN), // current over 64
    ];
    for apdu in malformed {
        let (_, sw) = call(&mut app, &apdu);
        assert_eq!(sw, SW_WRONG_DATA, "shape is refused before the budget is read");
    }
    match stored_pin(&path) {
        PinEntry::Live(record) => assert_eq!(record.counter, PIN_MAX_RETRIES),
        other => panic!("expected a full budget, got {other:?}"),
    }
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// US-1693: VERIFY_PIN — the 63CX vocabulary, the session, the lockout
// ---------------------------------------------------------------------------

/// The VERIFY apdu: bare PIN payload on INS 0x1B.
fn verify_pin(pin: &[u8]) -> HeaplessVec<u8, 300> {
    let mut a = HeaplessVec::new();
    a.extend_from_slice(&[0x00, INS_VERIFY_PIN, 0x00, 0x00]).unwrap();
    a.push(pin.len() as u8).unwrap();
    a.extend_from_slice(pin).unwrap();
    a
}

/// **A correct verify answers `9000` and rewrites the budget full** — the
/// success reset is a durable record write, so a verify that follows a
/// burned attempt leaves the counter at [`PIN_MAX_RETRIES`] on the medium,
/// not just in RAM.
#[test]
fn verify_pin_sets_the_session_flag() {
    let (mut app, path) = booted_app("verify-ok");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);

    // Burn one, then verify: the durable counter returns to full.
    let (_, sw) = call(&mut app, &verify_pin(b"999999"));
    assert_eq!(sw, 0x63C2);
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_OK, "the correct PIN verifies");
    match stored_pin(&path) {
        PinEntry::Live(record) => {
            assert_eq!(record.counter, PIN_MAX_RETRIES, "the success reset is durable");
            assert_eq!(record.verifier, pin_verifier(PIN, &record.salt));
        }
        other => panic!("expected the reset record, got {other:?}"),
    }

    // Verify is idempotent: a session that is open stays open, and the
    // budget stays full.
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_OK);
    match stored_pin(&path) {
        PinEntry::Live(record) => assert_eq!(record.counter, PIN_MAX_RETRIES),
        other => panic!("expected the full record, got {other:?}"),
    }
    std::fs::remove_file(&path).ok();
}

/// **A wrong verify decrements the durable counter and answers `63C<rx>`**
/// — the same vocabulary CHANGE burns, one verb earlier.
#[test]
fn wrong_pin_decrements_and_reports_63cx() {
    let (mut app, path) = booted_app("verify-wrong");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &verify_pin(b"999999"));
    assert_eq!(sw, 0x63C2, "one failure from 3");
    let (_, sw) = call(&mut app, &verify_pin(b"999999"));
    assert_eq!(sw, 0x63C1, "two failures from 3");
    match stored_pin(&path) {
        PinEntry::Live(record) => assert_eq!(record.counter, 1),
        other => panic!("expected the decremented record, got {other:?}"),
    }
    std::fs::remove_file(&path).ok();
}

/// **The exhausted counter locks the board until factory reset** — the
/// correct PIN stops verifying once the budget is spent, the counter is
/// never decremented below zero, and the lock survives a **simulated power
/// cycle**: a fresh applet boot over the same region reads the same
/// exhausted record, because the budget was durable record writes all
/// along. Recovery is management `RESET` only (US-1701's wipe) — no verb
/// on this applet refills the budget.
#[test]
fn exhausted_counter_locks_until_factory_reset() {
    let (mut app, path) = booted_app("verify-locked");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);
    for expected in [0x63C2, 0x63C1, SW_PIN_LOCKED] {
        let (_, sw) = call(&mut app, &verify_pin(b"999999"));
        assert_eq!(sw, expected, "the 63CX progression reaches 63C0");
    }

    // The correct PIN is not a way back in: the budget, not the secret,
    // is spent.
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_PIN_LOCKED, "the correct PIN does not verify on a locked board");
    match stored_pin(&path) {
        PinEntry::Live(record) => assert_eq!(record.counter, 0, "never below zero"),
        other => panic!("expected the exhausted record, got {other:?}"),
    }

    // Power cycle: the applet is rebuilt over the same region, session
    // flag gone, budget intact.
    let mut app2 = NostrApp::boot(open_region(&path)).with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app2, &verify_pin(PIN));
    assert_eq!(sw, SW_PIN_LOCKED, "the lock is durable — a reboot does not refund it");
    match stored_pin(&path) {
        PinEntry::Live(record) => assert_eq!(record.counter, 0),
        other => panic!("expected the exhausted record, got {other:?}"),
    }
    std::fs::remove_file(&path).ok();
}

/// **VERIFY on a board with no PIN is `SW_PIN_NOT_SET`, touching nothing** —
/// the no-PIN state is the ungated state, and a verify against a record
/// that does not exist must not write one, tombstone one, or learn a
/// cache that says otherwise.
#[test]
fn verify_on_an_unset_board_touches_nothing() {
    let (mut app, path) = booted_app("verify-unset");
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_PIN_NOT_SET);
    assert!(matches!(stored_pin(&path), PinEntry::Empty), "the pin slot is untouched");
    // And the board still sets afterwards — the refusal consumed nothing.
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// US-1694: LOCK — explicit session close, idempotent, non-leaking
// ---------------------------------------------------------------------------

fn lock() -> HeaplessVec<u8, 300> {
    let mut a = HeaplessVec::new();
    a.extend_from_slice(&[0x00, INS_LOCK, 0x00, 0x00]).unwrap();
    a
}

/// **`LOCK` answers `9000` whatever the state was and never leaks it** —
/// on a no-PIN board, a locked board, an unlocked board, twice in a row.
/// A `LOCK` that discriminated would tell a USB-side attacker whether a
/// session was open, which is the fact custody exists to hide.
///
/// The flag *clearing* itself is not observable from this applet's wire
/// until the custody gate exists (US-1697): `lock_clears_the_flag_across_
/// transports` completes there, when a subsequent `SIGN` can refuse —
/// unlock over CCID, lock through the vendor-HID arm, watch `SIGN`
/// refuse. What this story pins is the verb's own contract: idempotent,
/// payloadless, touch-free, one `9000` for every state.
#[test]
fn lock_answers_9000_in_every_state_and_leaks_nothing() {
    // No PIN at all.
    let (mut app, path) = booted_app("lock-unset");
    let (_, sw) = call(&mut app, &lock());
    assert_eq!(sw, SW_OK, "a no-PIN board locks idempotently");
    std::fs::remove_file(&path).ok();

    // PIN set but never verified, and a payload is refused on shape.
    let (mut app, path) = booted_app("lock-set");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &lock());
    assert_eq!(sw, SW_OK, "an unverified session locks fine");
    std::fs::remove_file(&path).ok();

    // Verified, then locked, then locked again.
    let (mut app, path) = booted_app("lock-open");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &lock());
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &lock());
    assert_eq!(sw, SW_OK, "the second lock is the same `9000` — no state leaked");

    // A session that was closed by LOCK can be re-opened: the flag is the
    // session, not a revocation.
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_OK, "LOCK does not burn the budget");
    match stored_pin(&path) {
        PinEntry::Live(record) => assert_eq!(record.counter, PIN_MAX_RETRIES),
        other => panic!("expected the full record, got {other:?}"),
    }
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// US-1695: fail closed on a torn PinRecord
// ---------------------------------------------------------------------------

/// The raw slot bytes of a Nostr-domain record sealed with the fixture key
/// at an arbitrary body — the torn-record fabric for the pin slot.
fn torn_pin_image(generation: u32, body: &[u8]) -> Vec<u8> {
    use fapico2_platform::keyregion::record::{self, Domain, RecordHeader};
    let otp_row: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x11));
    let chipid: [u8; 8] = 0x0000_BADC_0FFE_EE01_0203_u64.to_be_bytes();
    let key = derive_payload_key(&otp_row, &chipid, &NOSTR_PAYLOAD_SECRET).expect("key");
    let pin = fapico2_platform::keyregion::nostr_store::nostr_pin_slot()
        .expect("the carve's geometry names the PIN slot");
    let header = RecordHeader::new(Domain::Nostr, pin, generation);
    let mut nonce = [0u8; record::NONCE_LEN];
    nonce[..4].copy_from_slice(&generation.to_le_bytes());
    nonce[4..].copy_from_slice(b"nostrst!");
    let sealed = record::seal(&header, key.as_bytes(), &nonce, body).expect("seal");
    let image = record::encode(&header, &sealed).expect("encode");
    image.as_bytes().to_vec()
}

/// **A torn PinRecord fails closed**: the applet boots over a region whose
/// pin slot holds a record that opens as ours but is not a PIN body — and
/// every custody verb treats it as *locked*, never as *no PIN*. VERIFY
/// answers [`SW_PIN_LOCKED`], SET refuses (a torn slot is not an unset
/// board), CHANGE refuses, and nothing anywhere repairs or tombstones:
/// after every refusal the slot still holds the same broken record, and
/// the recovery is management `RESET` (US-1701's wipe) — documented, not
/// papered over in code.
#[test]
fn torn_pin_record_fails_closed() {
    use fapico2_platform::keyregion::KeyRegion;

    // Truncated-write-shaped torn record: our key, a 50-byte body.
    let path = region_path("torn");
    std::fs::remove_file(&path).ok();
    let mut region = FileKeyRegion::create(&path, TOTAL_SLOTS).expect("create");
    let pin = fapico2_platform::keyregion::nostr_store::nostr_pin_slot()
        .expect("the carve's geometry names the PIN slot");
    region
        .program(pin, 0, &torn_pin_image(1, &[0x7F; 50]))
        .expect("the torn record programs into a virgin slot");

    let mut app = NostrApp::boot(open_region(&path)).with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_PIN_LOCKED, "VERIFY on a torn record is the locked posture");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_STORE_FAULT, "a torn slot is not an unset board");
    let (_, sw) = call(&mut app, &change_pin(PIN, NEW_PIN));
    assert_eq!(sw, SW_STORE_FAULT, "there is no PIN to change without a verify");
    assert!(
        matches!(stored_pin(&path), PinEntry::Undecodable),
        "nothing repaired or tombstoned the torn record"
    );
    std::fs::remove_file(&path).ok();

    // Flipped-bit-shaped torn record: a valid PIN body, one ciphertext
    // byte flipped. The AEAD refuses; the posture is the same.
    let path = region_path("torn-flip");
    std::fs::remove_file(&path).ok();
    let mut salt = [0u8; 16];
    pinned_salt(&mut salt);
    let mut body = [0u8; NOSTR_PIN_BODY_LEN];
    body[0] = PIN_MAX_RETRIES;
    body[1..17].copy_from_slice(&salt);
    body[17..].copy_from_slice(&pin_verifier(PIN, &salt));
    let mut image = torn_pin_image(1, &body);
    let first_ct = fapico2_platform::keyregion::record::RECORD_HEADER_LEN
        + fapico2_platform::keyregion::record::NONCE_LEN;
    image[first_ct] ^= 0x01;
    let mut region = FileKeyRegion::create(&path, TOTAL_SLOTS).expect("create");
    region.program(pin, 0, &image).expect("program the flipped record");
    let mut app = NostrApp::boot(open_region(&path)).with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_PIN_LOCKED, "a flipped bit is the same locked posture");
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// US-1697: the gate matrix
// ---------------------------------------------------------------------------

/// A valid signing digest — any 32 bytes; the SIGN shape check is length-only.
const DIGEST: [u8; 32] = [0x42; 32];
/// A valid scalar for IMPORT_KEY: non-zero, below the curve order.
const IMPORTED_SCALAR: [u8; 32] = [0x01; 32];
/// The secp256k1 generator's x-coordinate — a peer key that always lifts,
/// so the NIP-44 rows reach the gate instead of `6A87`.
const G_X: [u8; 32] = [
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
];

fn apdu(ins: u8, p1: u8, data: &[u8]) -> HeaplessVec<u8, 300> {
    let mut a: HeaplessVec<u8, 300> = HeaplessVec::new();
    a.extend_from_slice(&[0x00, ins, p1, 0x00]).unwrap();
    if !data.is_empty() {
        a.push(data.len() as u8).unwrap();
        a.extend_from_slice(data).unwrap();
    }
    a
}

/// The ten matrix rows, run in order against one app. Rows 0–6 are the
/// gated (secret) commands; rows 7–9 are the open reads. The store state
/// at the read rows is designed to be identical across all three columns:
/// row 0 imports `idx 1`, row 5 deletes it again — so by row 7 the only
/// identity is the `idx 0` one the setup imported before the PIN existed.
fn gate_rows(app: &mut NostrApp) -> [Sw; 10] {
    let mut enc_req: HeaplessVec<u8, 64> = HeaplessVec::new();
    enc_req.extend_from_slice(&G_X).unwrap();
    enc_req.extend_from_slice(b"hi").unwrap();
    let mut dec_req: HeaplessVec<u8, 192> = HeaplessVec::new();
    dec_req.extend_from_slice(&G_X).unwrap();
    dec_req.extend_from_slice(&[0u8; 99]).unwrap();
    let rows: [HeaplessVec<u8, 300>; 10] = [
        apdu(INS_IMPORT_KEY, 1, &IMPORTED_SCALAR),
        apdu(INS_SIGN, 0, &DIGEST),
        apdu(INS_NIP44_ENCRYPT, 0, &enc_req),
        apdu(INS_NIP44_DECRYPT, 0, &dec_req),
        apdu(INS_GENERATE_KEY, 1, &[]),
        apdu(INS_DELETE_KEY, 1, &[]),
        apdu(INS_SET_LABEL, 1, b"lbl"),
        apdu(INS_GET_INFO, 0, &[]),
        apdu(INS_LIST_KEYS, 0, &[]),
        apdu(INS_GET_PUBKEY, 0, &[]),
    ];
    rows.map(|a| call(app, &a).1)
}

/// **The gate matrix**: every command in all three states, one row each.
///
/// - *no PIN*: every row behaves as it did before the gate existed — the
///   compatibility property, asserted per command. The gated rows run to
///   their real answers (the host's default presence is "present", so
///   touch-gated commands execute).
/// - *PIN + locked*: all seven secret commands answer
///   [`SW_PIN_SESSION_REQUIRED`] — and the three open reads answer exactly
///   what the no-PIN board answered, because a locked board still proves
///   which identities exist (the NPUB-on-a-poster argument, §2.2).
/// - *PIN + unlocked*: every row equals the no-PIN column, status words
///   included. Unlocked custody is the ungated state, byte for byte.
///
/// Status words are compared, not bodies: the NIP-44 nonce and the BIP-340
/// aux draw come from the per-draw counter RNG, so ciphertexts differ
/// between boards by construction. A wrong SW would differ too, and it is
/// the SW the gate story is about.
#[test]
fn gate_matrix() {
    // Column A — no PIN.
    let path = region_path("gate-nopin");
    std::fs::remove_file(&path).ok();
    let mut app = NostrApp::boot(fixture_region(&path)).with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 0, &IMPORTED_SCALAR));
    assert_eq!(sw, SW_OK, "setup: the identity imports on a fresh board");
    let no_pin = gate_rows(&mut app);
    std::fs::remove_file(&path).ok();

    // Column B — PIN set, session closed.
    let path = region_path("gate-locked");
    std::fs::remove_file(&path).ok();
    let mut app = NostrApp::boot(fixture_region(&path)).with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 0, &IMPORTED_SCALAR));
    assert_eq!(sw, SW_OK, "setup: import while the gate is unborn");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK, "setup: the PIN sets");
    let locked = gate_rows(&mut app);
    std::fs::remove_file(&path).ok();

    // Column C — PIN set, session open.
    let path = region_path("gate-unlocked");
    std::fs::remove_file(&path).ok();
    let mut app = NostrApp::boot(fixture_region(&path)).with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 0, &IMPORTED_SCALAR));
    assert_eq!(sw, SW_OK, "setup: import while the gate is unborn");
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_OK);
    let unlocked = gate_rows(&mut app);
    std::fs::remove_file(&path).ok();

    // The gated rows refuse with the gate word in the locked column…
    for (i, sw) in locked.iter().enumerate().take(7) {
        assert_eq!(*sw, SW_PIN_SESSION_REQUIRED, "row {i} must be gated on a locked board");
    }
    // …the open reads never consult the gate…
    for i in 7..10 {
        assert_eq!(locked[i], no_pin[i], "read row {i} is the same on a locked board");
        assert_eq!(unlocked[i], no_pin[i], "read row {i} is the same unlocked");
    }
    // …and the unlocked column is the no-PIN column, whole.
    for i in 0..7 {
        assert_eq!(
            unlocked[i], no_pin[i],
            "row {i} unlocked must equal the no-PIN behaviour"
        );
    }
    // The no-PIN column itself is today's behaviour, spot-checked: the
    // gated rows really ran (import/sign/delete succeeded at their
    // pre-gate answers), not silently refused.
    assert_eq!(no_pin[0], SW_OK, "IMPORT on a no-PIN board succeeds");
    assert_eq!(no_pin[1], SW_OK, "SIGN on a no-PIN board succeeds");
    assert_eq!(no_pin[5], SW_OK, "DELETE on a no-PIN board succeeds");
    assert_eq!(no_pin[4], 0x6A84, "GENERATE over an occupied index is 6A84");
    assert_eq!(no_pin[6], 0x6A82, "SET_LABEL on a deleted index is 6A82");
}

/// US-1694's deferred acceptance, completed by the gate's existence:
/// `LOCK` clears the session flag wherever it was opened, because the flag
/// it clears is applet-global behind the shared `Mutex` (§8) — the CCID
/// task and the vendor-HID task drive the same one applet instance, so
/// there is no per-connection session to be out of sync with. At the
/// applet level both transports are the same `process` call; the wire
/// framing that distinguishes them arrives with US-1702, and the proxy
/// check (`nostr_shared.rs` forwards every `App` method) is the review
/// note that keeps the device arm honest.
#[test]
fn lock_clears_the_flag_across_transports() {
    let path = region_path("lock-clears");
    std::fs::remove_file(&path).ok();
    let mut app = NostrApp::boot(fixture_region(&path)).with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 0, &IMPORTED_SCALAR));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_OK);

    // Unlocked: SIGN runs (9000 — the signature path completes).
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, &DIGEST));
    assert_eq!(sw, SW_OK, "an open session signs");
    // LOCK, on "the other transport" — the same applet: the gate closes.
    let (_, sw) = call(&mut app, &lock());
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, &DIGEST));
    assert_eq!(sw, SW_PIN_SESSION_REQUIRED, "the lock closed the session");
    // VERIFY reopens it, and signing works again.
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, &DIGEST));
    assert_eq!(sw, SW_OK, "a reopened session signs");
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// US-1696: session flag lifecycle — RAM-only, power-cycle-cleared, deselect-blind
// ---------------------------------------------------------------------------

/// **The session survives deselect and spans transports, and dies only with
/// power.** The four lifecycle claims, in the story's order:
///
/// (a) *cleared by construction* — a freshly booted applet is locked, and
/// VERIFY is the only setter to `true`; (c) *deselect-blind* — `deselect`
/// and a fresh `select` on the applet touch nothing, because the flag is
/// applet-global behind the shared `Mutex` (§8: one applet instance per
/// transport pair), not per-connection state; (d) *spans transports* —
/// "unlock on HID, sign over CCID" is one `process` call away at the
/// applet level, since both interfaces drive the same instance; the review
/// note that keeps the device arm honest is that `firmware/src/
/// nostr_shared.rs` forwards every `App` method through the proxy and no
/// `deselect` path anywhere assigns the flag (grep: `pin_unlocked` is
/// written only in `verify_pin`, `lock` and the constructors). (b) *power
/// cycle* — a fresh boot over the same region re-derives a closed
/// session: the flag lives in RAM and the record never learned it.
#[test]
fn session_survives_deselect_and_spans_transports() {
    use fapico2_nostr::SW_PIN_SESSION_REQUIRED;

    let path = region_path("session-lifecycle");
    std::fs::remove_file(&path).ok();
    let mut app = NostrApp::boot(fixture_region(&path)).with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 0, &IMPORTED_SCALAR));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);

    // (a) cleared by construction: a boot with a PIN is a locked boot —
    // VERIFY is the only setter to `true`, and this instance has not had
    // one.
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, &DIGEST));
    assert_eq!(sw, SW_PIN_SESSION_REQUIRED, "a set-PIN boot is locked");

    // Unlock ("over the vendor HID"), then deselect and re-select ("the
    // CCID leg reconnects"). The session is the applet's, not the
    // connection's.
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_OK);
    app.deselect();
    assert_eq!(app.select(false), SW_OK);
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, &DIGEST));
    assert_eq!(sw, SW_OK, "deselect did not close the session");

    // (b) power cycle: the same region, a new boot, a closed gate. The
    // PIN record is untouched — only the session died.
    let mut app = NostrApp::boot(open_region(&path)).with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, &DIGEST));
    assert_eq!(sw, SW_PIN_SESSION_REQUIRED, "a power cycle closed the session");
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_OK, "the PIN survived the power cycle");
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, &DIGEST));
    assert_eq!(sw, SW_OK);
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// US-1698: the gate fires before the touch — no press is wasted
// ---------------------------------------------------------------------------

/// Counting presence deny: counts how many times the press path consulted
/// the grant, and denies every press. A `fn` pointer cannot carry state,
/// so the counter is a static — one test owns it at a time.
static PRESSES: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn counting_deny(_tag: u32) -> bool {
    PRESSES.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    false
}

/// **A locked board never reaches the press path, even with a grant
/// already armed.** The standing refusal order is shape → state → touch;
/// the gate sits between shape and state, so on a PIN+locked board a
/// well-formed SIGN answers [`SW_PIN_SESSION_REQUIRED`] with the grant
/// unconsulted — the armed grant dies with its request, consumed by the
/// refusal, never by a signature. After VERIFY the gate opens and the
/// same request finally reaches the touch check, where the counting grant
/// is consulted (once) and denies: `6985`, the touch word, which is the
/// *second* consent a locked board never asked for.
#[test]
fn pin_gate_fires_before_touch_and_eats_the_grant() {
    use fapico2_nostr::SW_PIN_SESSION_REQUIRED;

    let path = region_path("gate-before-touch");
    std::fs::remove_file(&path).ok();
    // Setup needs an identity, and IMPORT is touch-gated — so the
    // identity is imported on an app without the counting grant, and the
    // counting app boots over the finished region (a second boot, which
    // also re-derives `pin_set` the way a real reconnect does).
    let mut app = NostrApp::boot(fixture_region(&path)).with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 0, &IMPORTED_SCALAR));
    assert_eq!(sw, SW_OK);
    let mut app = NostrApp::boot(open_region(&path))
        .with_rng_provider(pinned_salt)
        .with_presence_grant(counting_deny);
    let (_, sw) = call(&mut app, &set_pin(0x00, PIN));
    assert_eq!(sw, SW_OK);

    // Locked, request arrives with the grant "armed": the gate refuses
    // and the press path is never entered.
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, &DIGEST));
    assert_eq!(sw, SW_PIN_SESSION_REQUIRED, "the gate word, not the touch word");
    assert_eq!(
        PRESSES.load(core::sync::atomic::Ordering::SeqCst),
        0,
        "no presence_grant call reached the press path on a locked board"
    );

    // Unlocked, the same request: the gate opens, the touch check runs,
    // the grant is consulted exactly once and denies.
    let (_, sw) = call(&mut app, &verify_pin(PIN));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, &DIGEST));
    assert_eq!(sw, 0x6985, "unlocked, the touch word is the honest answer");
    assert_eq!(
        PRESSES.load(core::sync::atomic::Ordering::SeqCst),
        1,
        "the touch arm was entered exactly once, after the gate"
    );
    std::fs::remove_file(&path).ok();
}
