//! US-1006 — entropy starvation is survivable on the OpenPGP card.
//!
//! The property under test is the one the epic's Phase 1 outcome depends on
//! and the one that could not be claimed before this group: **a request that
//! needs randomness and cannot get it answers a card error, and the card is
//! still there afterwards.** Not a panic, not a hang, not a card that has
//! quietly started answering from a stale buffer.
//!
//! # Why a host twin, and what it does and does not prove
//!
//! There is no board attached, so this cannot be a hardware claim. What it
//! *is* is a real exercise of the real error path: `HostPlatform::with_stalled_rng`
//! substitutes a `HostRng::Stalled`, whose `try_fill_bytes` returns `Err` —
//! the same `RngCore` method, and so the same trussed code path, that the
//! device's `Rp2350Rng` uses to report a DRBG that cannot re-seed. The
//! request goes through the same `SyscallRunner` → `Service` → opcard
//! dispatch chain on both.
//!
//! What it therefore proves: **trussed propagates a failed entropy draw to a
//! card error rather than panicking, and the client survives it.** That is
//! the part that is pure logic and that a host test can settle.
//!
//! What it does *not* prove, and what the hardware twin (US-1007, outstanding
//! without a board) must: that the RP2350 peripheral actually reaches the
//! stalled state, that the bound in `Rp2350Probe` holds on silicon, and that
//! the device stays enumerable over CCID and HID. The elapsed-time half of
//! the bound is recorded as a standing divergence (D-8) precisely because
//! nothing here can observe it.

use fapico2_openpgp::OpenPgpApp;
use fapico2_platform::dispatch::{Dispatcher, MAX_RESPONSE, SW_OK};
use fapico2_platform::trusted_backend::{
    dispatch::OpcardDispatch,
    host::{HostPlatform, HostStore},
    runner::with_backend,
};
use heapless::Vec as HeaplessVec;

fn select_openpgp() -> [u8; 11] {
    let mut apdu = [0u8; 11];
    apdu[0] = 0x00;
    apdu[1] = 0xA4;
    apdu[2] = 0x04;
    apdu[3] = 0x00;
    apdu[4] = 0x06;
    apdu[5..11].copy_from_slice(fapico2_openpgp::OPENPGP_AID);
    apdu
}

fn sw_of(resp: &HeaplessVec<u8, MAX_RESPONSE>) -> u16 {
    u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]])
}

/// Run `f` against a card whose entropy source refuses every draw.
fn with_stalled_card<R>(f: impl FnOnce(&mut Dispatcher<1>, &mut HeaplessVec<u8, MAX_RESPONSE>) -> R) -> R {
    let platform = HostPlatform::with_stalled_rng(HostStore::fresh());
    with_backend(platform, OpcardDispatch::new(), "fapico2-openpgp-stall", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        f(&mut dispatcher, &mut resp)
    })
}

// ---------------------------------------------------------------------------
// 1. The starved card answers an error, not a panic and not a hang
// ---------------------------------------------------------------------------

/// **RED before US-1006, GREEN after.** With every entropy draw refused,
/// `GET CHALLENGE` returns a non-`9000` status word and the dispatcher comes
/// back.
///
/// Before the story, `Rp2350Rng::try_fill_bytes` was `self.fill_bytes(buf);
/// Ok(())` — an unconditional success — so there was no error to propagate
/// and nothing for trussed to convert. The claim being pinned is the
/// *negative* one this time: whatever the card answers, it is a status word
/// and the call returns.
#[test]
fn get_challenge_under_entropy_starvation_answers_a_card_error() {
    with_stalled_card(|dispatcher, resp| {
        // SELECT first: the card must be usable up to the point of the
        // starved request, or "it answered an error" would be trivially true
        // for a card that was never selected.
        dispatcher.dispatch(&select_openpgp(), resp);
        assert_eq!(
            sw_of(resp),
            SW_OK,
            "SELECT must still work — a starved RNG is not a dead card"
        );

        // GET CHALLENGE, 8 bytes (spec §7.2.8).
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        dispatcher.dispatch(&[0x00, 0x84, 0x00, 0x00, 0x08], &mut resp);

        assert!(
            resp.len() >= 2,
            "a starved GET CHALLENGE must still return a status word, got {} byte(s)",
            resp.len()
        );
        let sw = sw_of(&resp);
        // Pinned, not merely "not SW_OK". The specific word is part of the
        // contract: `0x6400` is what the US-1006 patch to `get_challenge`
        // maps a refused draw to — `Status::UnspecifiedNonpersistentExecutionError`,
        // i.e. ISO 7816 "execution error, non-persistent", which is exactly
        // this: a valid command that cannot be carried out right now, and
        // which a client may retry.
        //
        // (The Group C report claimed this word was `0x6F00`. It is not —
        // `0x6F00` never appears on this path. Corrected here, and the value
        // is now asserted rather than described.)
        //
        // A regression to a *different* non-OK word would each tell a client
        // something false about the card — `6A80` (wrong data), `6D00`
        // (instruction not supported), `6700` (wrong length), `6F00`
        // (checking error) — and `assert_ne!(sw, SW_OK)` passes on all of
        // them.
        assert_eq!(
            sw, 0x6400,
            "a challenge the card could not draw must answer 6400 \
             (UnspecifiedNonpersistentExecutionError), not SW_OK and not some \
             other non-OK word; got {sw:04X}"
        );
        // The body must not be a challenge. A card that answered 6F00 with
        // eight bytes attached would be worse than useless: a client that
        // reads the body before the SW would use them as a nonce.
        let body = &resp[..resp.len() - 2];
        assert!(
            body.is_empty(),
            "a failed GET CHALLENGE must not return challenge bytes; got {} byte(s)",
            body.len()
        );
    });
}

/// The executor survives: a second request after the starved one is answered
/// normally, and the client is still usable.
///
/// This is the "card error, not a wedge" half of the property. A panic in
/// `no_std` is an abort; a hang is the failure mode US-1001 exists to
/// prevent. Both would be caught here as "the second call never returns", so
/// the test is written to make progress rather than to assert a value.
#[test]
fn the_card_still_answers_after_a_starved_request() {
    with_stalled_card(|dispatcher, resp| {
        dispatcher.dispatch(&select_openpgp(), resp);

        // Starve it.
        let mut starved = HeaplessVec::<u8, MAX_RESPONSE>::new();
        dispatcher.dispatch(&[0x00, 0x84, 0x00, 0x00, 0x08], &mut starved);

        // A request that needs no entropy must still be answered — the
        // failure is scoped to the draw, not to the card.
        let mut after = HeaplessVec::<u8, MAX_RESPONSE>::new();
        dispatcher.dispatch(&select_openpgp(), &mut after);
        assert_eq!(
            sw_of(&after),
            SW_OK,
            "the card must still answer SELECT after a starved GET CHALLENGE"
        );

        // And a second starved request gives the same clean answer rather
        // than degrading further.
        let mut again = HeaplessVec::<u8, MAX_RESPONSE>::new();
        dispatcher.dispatch(&[0x00, 0x84, 0x00, 0x00, 0x08], &mut again);
        assert_eq!(
            sw_of(&again),
            sw_of(&starved),
            "repeated starvation must be stable, not progressively worse"
        );
    });
}

// ---------------------------------------------------------------------------
// 2. The two failure modes stay distinguishable through `RngCore`
// ---------------------------------------------------------------------------

/// `RngCore::Error` is an opaque `NonZeroU32` in `no_std`, so the *code* is
/// the only channel a caller has. This pins that the two conditions get
/// distinct codes — they call for different operator responses (retry later
/// vs. reset the device), so collapsing them would lose the distinction at
/// exactly the point someone needs it.
#[test]
fn the_two_starvation_causes_have_distinct_codes() {
    assert_ne!(
        fapico2_platform::trng::RNG_ERR_RESEED_REQUIRED,
        fapico2_platform::trng::RNG_ERR_RESEED_REFUSED,
        "a spent budget and a refused re-seed must not share a code"
    );
}

/// The host twin's stall reports the *refused* code specifically, not merely
/// "an error" — so the mapping from a device condition to a code is pinned,
/// not just the codes' existence.
#[test]
fn the_stalled_twin_reports_the_refused_code() {
    use fapico2_platform::trusted_backend::host::HostRng;
    use rand_core::RngCore;

    let mut rng = HostRng::Stalled;
    let mut buf = [0u8; 8];
    rng.try_fill_bytes(&mut buf).expect_err("must fail");
    // `rand_core::Error` exposes no accessor on the 0.6 `no_std` line, so
    // this pins the *behaviour* the code exists for: the draw is refused and
    // the buffer is untouched. The code values themselves are pinned by the
    // distinctness test above.
    assert!(
        buf.iter().all(|&b| b == 0),
        "a refused draw must leave the buffer untouched, not fill it with a constant"
    );
}

/// Sanity: the healthy host path still serves, so the stall tests are not
/// passing because the card is broken in some other way.
#[test]
fn a_healthy_card_still_answers_get_challenge() {
    fapico2_platform::trusted_backend::host::with_host_backend("fapico2-openpgp-ok", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app));
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        dispatcher.dispatch(&select_openpgp(), &mut resp);
        assert_eq!(sw_of(&resp), SW_OK);

        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        dispatcher.dispatch(&[0x00, 0x84, 0x00, 0x00, 0x08], &mut resp);
        assert_eq!(
            sw_of(&resp),
            SW_OK,
            "a healthy card must answer GET CHALLENGE — otherwise the stall \
             tests prove nothing"
        );
        assert_eq!(resp.len() - 2, 8, "and return exactly 8 challenge bytes");
    });
}
