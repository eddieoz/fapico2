//! PICOForge-COMPAT: the factory-reset path the reference client drives
//! (`picoforge/src/hal/applets/openpgp.rs:438-457`) — up to ten wrong VERIFYs
//! against PW1 then PW3, then `00 E6 00 00` (TERMINATE) and `00 44 00 00`
//! (ACTIVATE).
//!
//! Three things about that sequence are load-bearing and none of them is
//! what the client assumes, so each is pinned here against the card rather
//! than against the client's reading of the card:
//!
//! * **The card never answers `6983`.** The client breaks out of its retry
//!   loop on `6983` (`OperationBlocked`); the card answers `63C2`, `63C1`,
//!   then `63C0` for the rest of time. `6983` is only reachable through the
//!   migration-source arm of `verification_status`
//!   (`vendor/opcard/src/state.rs:1319-1327`), and a factory card has
//!   `migration_source: None`, so the `63Cx` arm
//!   (`state.rs:1316-1318`) is the only one taken. The client's `break` is
//!   therefore dead code against this card: the loop runs its full ten
//!   iterations for each PIN and only then proceeds. The end state is the
//!   same — both counters reach zero — so the reset works, but by
//!   exhaustion, not by detection.
//! * **TERMINATE succeeds on the PW3-*locked* arm, not the admin-verified
//!   one.** `terminate_df` accepts `admin_verified() || is_locked(Pw3)`
//!   (`vendor/opcard/src/command.rs:528-535`); the client never VERIFYs
//!   PW3, it burns its retries, so only the second arm can be the one that
//!   fires. Both arms are pinned separately below, because "TERMINATE works"
//!   alone would not distinguish them.
//! * **The card must already be personalised.** `terminate_df` refuses with
//!   `6985` while `factory_defaults_in_force()`
//!   (`command.rs:518-522`), and that flag is set until *both* PINs have
//!   been changed away from the shipped defaults
//!   (`vendor/opcard/src/state.rs:1348-1350`). This holds even with PW3
//!   locked and the admin session verified, so a never-personalised card is
//!   unreachable for this flow at all.
//!
//! ACTIVATE is the other half and is deliberately the opposite: it
//! authenticates *nobody* (§7.2.17, `command.rs:576-592`) and then performs
//! a full `factory_reset` — wipe of Internal/External/Volatile plus
//! `delete_all_pins()`. That is spec-correct OpenPGP behaviour, and it also
//! means an unauthenticated party can wipe the card. Pinned explicitly so
//! the posture is a recorded decision rather than an accident.

use fapico2_openpgp::OpenPgpApp;
use fapico2_platform::dispatch::{Dispatcher, MAX_RESPONSE, SW_OK};
use heapless::Vec as HeaplessVec;

/// SELECT AID for the OpenPGP app (short Lc, no Le).
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

/// TERMINATE DF, §7.2.16. The client sends exactly these four bytes — a
/// case-1 APDU with no Le.
const TERMINATE: [u8; 4] = [0x00, 0xE6, 0x00, 0x00];
/// ACTIVATE FILE, §7.2.17. Same four-byte shape.
const ACTIVATE: [u8; 4] = [0x00, 0x44, 0x00, 0x00];

/// The wrong PIN the client sends: the ASCII string `00000000`.
const WRONG_PIN: [u8; 8] = *b"00000000";

/// One APDU through the dispatcher; returns (body, SW).
fn apdu(dispatcher: &mut Dispatcher<1>, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(apdu, &mut resp);
    assert!(resp.len() >= 2, "response too short for {:x?}", apdu);
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    (resp[..resp.len() - 2].to_vec(), sw)
}

/// VERIFY (INS 20) with an explicit PIN, P2 = 0x81 (PW1 sign) or 0x83 (PW3).
fn verify(dispatcher: &mut Dispatcher<1>, p2: u8, pin: &[u8]) -> u16 {
    let mut p = vec![0x00u8, 0x20, 0x00, p2, pin.len() as u8];
    p.extend_from_slice(pin);
    apdu(dispatcher, &p).1
}

/// GET DATA (INS CA) for the PW-status DO, which is where the three retry
/// counters live (`0xC4`[4] PW1, [5] reset code, [6] PW3).
fn pw_status(dispatcher: &mut Dispatcher<1>) -> Vec<u8> {
    let (body, sw) = apdu(dispatcher, &[0x00, 0xCA, 0x00, 0xC4, 0x00]);
    assert_eq!(sw, SW_OK, "GET DATA 0xC4 must answer 9000, got {:04X}", sw);
    body
}

/// CHANGE REFERENCE DATA (INS 24) — new value only, old value omitted.
fn change_pin(dispatcher: &mut Dispatcher<1>, p2: u8, new: &[u8]) {
    let mut p = vec![0x00u8, 0x24, 0x00, p2, new.len() as u8];
    p.extend_from_slice(new);
    let (_, sw) = apdu(dispatcher, &p);
    assert_eq!(sw, SW_OK, "CHANGE REFERENCE DATA {:02X} must answer 9000", p2);
}

/// The personalised PINs. Deliberately not the shipped defaults, because
/// TERMINATE is refused while the defaults are in force. The admin PIN is
/// written as 16 bytes but only its trailing 8 authenticate — trussed
/// matches the PIN against the stored key of the recorded PIN length, and
/// the `pso_presence.rs` fixtures rely on the same split.
const NEW_PW1: &[u8] = b"123456654321";
const NEW_PW3: &[u8] = b"1234567887654321";
const NEW_PW3_TAIL: &[u8] = b"87654321";
/// The shipped defaults, which a factory reset must restore.
const FACTORY_PW1: &[u8] = b"123456";
const FACTORY_PW3: &[u8] = b"12345678";

/// Move both PINs off the factory defaults so `factory_defaults_in_force()`
/// clears and the TERMINATE precondition is reachable at all.
fn personalise(dispatcher: &mut Dispatcher<1>) {
    change_pin(dispatcher, 0x81, NEW_PW1);
    change_pin(dispatcher, 0x83, NEW_PW3);
}

/// One pass of the client's blocking loop against a single PIN, returning
/// every status word the card produced. The client discards all but the
/// loop-breaking one; keeping the whole vector is what makes the
/// zeroing-attempt status word a pinned fact instead of an assumption.
fn client_wrong_pin_loop(dispatcher: &mut Dispatcher<1>, p2: u8) -> Vec<u16> {
    (0..10).map(|_| verify(dispatcher, p2, &WRONG_PIN)).collect()
}

/// Boot an app over a fresh RAM trussed client, run `body`, and return.
/// A fresh client per test because this story mutates card state that does
/// not come back: a test that blocks PW3 or terminates the card would
/// otherwise poison every test that shares its client.
fn on_fresh_card(client_id: &str, body: impl FnOnce(&mut Dispatcher<1>)) {
    opcard::virt::with_ram_client(client_id, |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
        assert_eq!(sw, SW_OK, "SELECT AID must answer 9000");
        body(&mut dispatcher);
    });
}

/// The status words a wrong-PIN attempt produces, in order, and the fact
/// that the counter runs out on the third attempt.
///
/// This is the single most consequential thing the client gets wrong. Its
/// loop terminates on `6983`; if the card answered `6983` on the zeroing
/// attempt the client's `break` would be correct and its bound of 10 would
/// merely be slack. It does not: the counter is hardcoded to 3
/// (`MAX_RETRIES`, `vendor/opcard/src/state.rs:800`), the exhausted state is
/// reported as `RemainingRetries(0)` = `63C0`, and it stays `63C0` for every
/// later attempt. A test asserting "the wrong PIN is eventually refused"
/// would pass against any of these; the exact words are the point.
#[test]
fn wrong_pin_exhausts_at_three_and_reports_63c0_not_6983() {
    on_fresh_card(&format!("us154-retries-{}", std::process::id()), |d| {
        personalise(d);
        let before = pw_status(d);
        assert_eq!(before[4], 3, "a personalised card starts with 3 PW1 tries");
        assert_eq!(before[6], 3, "a personalised card starts with 3 PW3 tries");

        for (label, p2, index) in [("PW1", 0x81u8, 4usize), ("PW3", 0x83u8, 6usize)] {
            let sws = client_wrong_pin_loop(d, p2);

            assert_eq!(
                sws[0], 0x63C2,
                "{label} attempt 1 reports 2 remaining tries"
            );
            assert_eq!(
                sws[1], 0x63C1,
                "{label} attempt 2 reports 1 remaining try"
            );
            assert_eq!(
                sws[2], 0x63C0,
                "{label} attempt 3 is the one that zeroes the counter, and it \
                 says 63C0 — NOT 6983. The client's loop breaks on 6983 \
                 (picoforge openpgp.rs:446), so it never breaks here."
            );
            for (i, &sw) in sws.iter().enumerate().skip(3) {
                assert_eq!(
                    sw, 0x63C0,
                    "{label} attempt {} re-reports the exhausted counter; a card \
                     that started answering 6983 after the first 63C0 would \
                     make the client's break fire on attempt 4 instead",
                    i + 1
                );
            }

            let after = pw_status(d);
            assert_eq!(
                after[index], 0,
                "{label} is blocked after the loop: {:02x?}",
                after
            );
        }
    });
}

/// The client's own `Ok(_) => continue` arm swallows every status word
/// except `6983`, so from its point of view the loop above runs to
/// completion for both PINs and it then issues TERMINATE blind. Replaying
/// that exact shape end-to-end and asserting on every intermediate
/// observable is what turns "the client's code is written this way" into
/// "the client's code is *correct* on this card, for a reason".
#[test]
fn the_clients_ten_by_ten_loop_reaches_terminated_state() {
    on_fresh_card(&format!("us154-loop-{}", std::process::id()), |d| {
        personalise(d);
        let untouched_reset_code = pw_status(d)[5];

        for p2 in [0x81u8, 0x83u8] {
            let sws = client_wrong_pin_loop(d, p2);
            assert!(
                !sws.contains(&0x6983),
                "the client's break condition is unreachable on this card: \
                 {sws:04X?}"
            );
            assert_eq!(sws.len(), 10, "the client always issues all ten");
        }
        let blocked = pw_status(d);
        assert_eq!(blocked[4], 0, "PW1 blocked");
        assert_eq!(blocked[6], 0, "PW3 blocked");
        // The reset code is a third PIN with its own counter, and the
        // client never touches it. Comparing against the value read before
        // the loop rather than a literal, because a card with no reset code
        // installed reports 0 there and one that has a code installed
        // reports its remaining tries — the point is that the loop does not
        // move it either way.
        assert_eq!(
            blocked[5], untouched_reset_code,
            "the reset-code counter must not move: the two zeroed counters \
             are zeroed individually, not as a side effect"
        );

        // No re-SELECT and no VERIFY between the loop and TERMINATE: this
        // is the client's exact sequence.
        let (_, sw) = apdu(d, &TERMINATE);
        assert_eq!(
            sw, SW_OK,
            "TERMINATE after the blocking loop must answer 9000"
        );

        // The card really is terminated — the very next command proves it,
        // and it is the same command the client would not issue but a host
        // would.
        let (_, sw) = apdu(d, &[0x00, 0xCA, 0x00, 0xC4, 0x00]);
        assert_eq!(
            sw, 0x6985,
            "a terminated card refuses GET DATA, so TERMINATE was not a no-op"
        );
    });
}

/// TERMINATE has two accepting arms (`command.rs:528-535`) and this story's
/// client depends on the second one, because it burns PW3's retries instead
/// of verifying PW3. Pin both, plus the refusal when neither holds: a test
/// that only asserted "TERMINATE answers 9000" would pass on the
/// admin-verified arm and prove nothing about the path the client walks.
#[test]
fn terminate_succeeds_on_the_pw3_locked_arm_not_admin_verified() {
    // Arm 1 — admin verified, PW3 not locked.
    on_fresh_card(&format!("us154-arm-admin-{}", std::process::id()), |d| {
        personalise(d);
        assert_eq!(
            verify(d, 0x83, NEW_PW3_TAIL),
            SW_OK,
            "VERIFY the personalised PW3 must answer 9000"
        );
        assert_eq!(
            pw_status(d)[6],
            3,
            "the admin arm must run with PW3 still unspent"
        );
        assert_eq!(
            apdu(d, &TERMINATE).1,
            SW_OK,
            "admin_verified() alone must authorise TERMINATE"
        );
    });

    // Arm 2 — PW3 locked, no admin session. This is the client's arm.
    on_fresh_card(&format!("us154-arm-locked-{}", std::process::id()), |d| {
        personalise(d);
        client_wrong_pin_loop(d, 0x83);
        assert_eq!(pw_status(d)[6], 0, "PW3 is locked");
        assert_eq!(
            apdu(d, &TERMINATE).1,
            SW_OK,
            "is_locked(Pw3) alone must authorise TERMINATE — the client never \
             verifies PW3, so this is the arm its screen actually reaches"
        );
    });

    // Neither arm — personalised, no admin session, PW3 unspent.
    on_fresh_card(&format!("us154-arm-none-{}", std::process::id()), |d| {
        personalise(d);
        assert_eq!(
            apdu(d, &TERMINATE).1,
            0x6985,
            "an authenticated-but-unverified TERMINATE must be refused"
        );
        assert_eq!(
            apdu(d, &[0x00, 0xCA, 0x00, 0xC4, 0x00]).1,
            SW_OK,
            "the refusal must leave the card operational"
        );
    });
}

/// The US-912 `factory_defaults_in_force()` gate stands in front of
/// TERMINATE and it is absolute: it refuses even when one of the accepting
/// arms holds. Both the personalised and the locked cases are pinned
/// because a change that made the gate advisory would silently widen who
/// can terminate a card.
#[test]
fn terminate_is_refused_while_the_factory_pins_are_in_force() {
    // Admin verified, factory PINs untouched.
    on_fresh_card(&format!("us154-fd-admin-{}", std::process::id()), |d| {
        assert_eq!(
            verify(d, 0x83, FACTORY_PW3),
            SW_OK,
            "the shipped admin PIN must verify on an unpersonalised card"
        );
        assert_eq!(
            apdu(d, &TERMINATE).1,
            0x6985,
            "TERMINATE must be refused while factory_defaults_in_force()"
        );
    });

    // PW3 locked, factory PINs untouched.
    on_fresh_card(&format!("us154-fd-locked-{}", std::process::id()), |d| {
        client_wrong_pin_loop(d, 0x83);
        assert_eq!(pw_status(d)[6], 0, "PW3 is locked");
        assert_eq!(
            apdu(d, &TERMINATE).1,
            0x6985,
            "a locked PW3 must not override the factory-defaults gate"
        );
    });
}

/// ACTIVATE authenticates nobody (§7.2.17) and wipes everything. Asserted
/// against a personalised card whose PINs are wrong, whose counters are
/// zero, and which has no verified session — so a regression that added an
/// auth requirement, or that only cleared part of the state, shows up here
/// rather than on a user's factory-fresh card.
#[test]
fn activate_needs_no_pin_and_restores_an_operational_factory_card() {
    on_fresh_card(&format!("us154-activate-{}", std::process::id()), |d| {
        personalise(d);
        client_wrong_pin_loop(d, 0x81);
        client_wrong_pin_loop(d, 0x83);
        assert_eq!(apdu(d, &TERMINATE).1, SW_OK);

        // No PIN, no VERIFY, and no re-SELECT between TERMINATE and ACTIVATE
        // — the client sends the two back to back.
        assert_eq!(
            apdu(d, &ACTIVATE).1,
            SW_OK,
            "ACTIVATE must answer 9000 with no authentication at all"
        );

        // Retry counters are back to their full complement. The reset code
        // stays at 0 because no reset code is ever installed, so `9000`
        // would be the wrong expectation there — it is the two PIN
        // counters the loop zeroed that must come back.
        let restored = pw_status(d);
        assert_eq!(
            restored[4],
            0x03,
            "delete_all_pins() must restore the PW1 retry counter: {:02x?}",
            restored
        );
        assert_eq!(
            restored[6],
            0x03,
            "delete_all_pins() must restore the PW3 retry counter: {:02x?}",
            restored
        );
        // The shipped PINs work again and the personalised ones do not,
        // which is the signature of a real wipe rather than a counter reset.
        assert_eq!(verify(d, 0x81, FACTORY_PW1), SW_OK, "factory PW1 restored");
        assert_eq!(verify(d, 0x83, FACTORY_PW3), SW_OK, "factory PW3 restored");
        assert_ne!(
            verify(d, 0x83, NEW_PW3_TAIL),
            SW_OK,
            "the personalised admin PIN must be gone, not merely out-ranked"
        );

        // Operational again: the lifecycle gate is open.
        assert_eq!(
            apdu(d, &[0x00, 0xCA, 0x00, 0xC4, 0x00]).1,
            SW_OK,
            "GET DATA must be accepted again after ACTIVATE"
        );
        assert_eq!(
            apdu(d, &select_openpgp()).1,
            SW_OK,
            "SELECT must answer 9000 (not 6285) on an operational card"
        );

        // And the wipe is a genuine re-initialisation, so the card is back
        // at the point where TERMINATE is once again refused.
        assert_eq!(
            apdu(d, &TERMINATE).1,
            0x6985,
            "the factory defaults are in force again after ACTIVATE"
        );
    });
}

/// ACTIVATE is idempotent by construction — it returns `Ok(())` early when
/// the card is already operational rather than wiping an in-use card. That
/// early return is a real branch with a real consequence, so it is pinned
/// against a card that is operational *and* personalised: a regression that
/// dropped the guard would silently wipe a live card on a stray ACTIVATE.
#[test]
fn activate_on_an_operational_card_is_a_no_op() {
    on_fresh_card(&format!("us154-idem-{}", std::process::id()), |d| {
        personalise(d);
        assert_eq!(
            verify(d, 0x83, NEW_PW3_TAIL),
            SW_OK,
            "the personalised admin PIN works before the stray ACTIVATE"
        );
        assert_eq!(apdu(d, &ACTIVATE).1, SW_OK, "ACTIVATE answers 9000");
        assert_eq!(
            verify(d, 0x83, NEW_PW3_TAIL),
            SW_OK,
            "a stray ACTIVATE on an operational card must not wipe it"
        );
        assert_eq!(pw_status(d)[6], 3, "the retry counters are untouched");

        // The same APDU on a terminated card does wipe — the difference
        // between the two calls is the whole idempotence contract.
        client_wrong_pin_loop(d, 0x83);
        assert_eq!(apdu(d, &TERMINATE).1, SW_OK);
        assert_eq!(apdu(d, &ACTIVATE).1, SW_OK);
        assert_ne!(
            verify(d, 0x83, NEW_PW3_TAIL),
            SW_OK,
            "after TERMINATE + ACTIVATE the personalised PIN is gone"
        );
    });
}

/// The lifecycle gate (`command.rs:51-59`) admits exactly three commands
/// while the card is terminated. The refusals are what make the terminated
/// state a real state; the two that succeed are what let the client finish
/// the reset. A gate that let, say, GET DATA through would still pass a test
/// that only checked the happy path.
#[test]
fn only_the_three_lifecycle_commands_run_while_terminated() {
    on_fresh_card(&format!("us154-gate-{}", std::process::id()), |d| {
        personalise(d);
        client_wrong_pin_loop(d, 0x83);
        assert_eq!(apdu(d, &TERMINATE).1, SW_OK);
        // Prove the card is terminated before asserting anything about the
        // gate, so a TERMINATE that silently failed cannot make every
        // assertion below pass for the wrong reason.
        assert_eq!(
            apdu(d, &[0x00, 0xCA, 0x00, 0xC4, 0x00]).1,
            0x6985,
            "precondition: the card is terminated"
        );

        for (name, a) in [
            ("GET DATA", &[0x00u8, 0xCA, 0x00, 0xC4, 0x00].as_slice()),
            (
                "GET CHALLENGE",
                &[0x00u8, 0x84, 0x00, 0x00, 0x08].as_slice(),
            ),
            (
                "VERIFY",
                &[0x00u8, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
                    .as_slice(),
            ),
            (
                "CHANGE REFERENCE DATA",
                &[0x00u8, 0x24, 0x00, 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36].as_slice(),
            ),
            (
                "PUT DATA",
                &[0x00u8, 0xDA, 0x00, 0xC4, 0x04, 0x7F, 0x7F, 0x7F, 0x7F].as_slice(),
            ),
        ] {
            assert_eq!(
                apdu(d, a).1,
                0x6985,
                "{name} must be refused with ConditionsOfUseNotSatisfied while \
                 the card is terminated"
            );
        }

        // SELECT is permitted by the gate but reports the termination state
        // rather than `9000` — `Status::SelectedFileInTerminationState`
        // (`vendor/opcard/src/command.rs:355`).
        assert_eq!(
            apdu(d, &select_openpgp()).1,
            0x6285,
            "SELECT answers 6285 while terminated, not 9000"
        );
        // TERMINATE and ACTIVATE are the two that carry the client to the
        // end of the flow. TERMINATE is itself idempotent: it re-writes the
        // lifecycle marker and answers `9000` on an already-terminated card.
        assert_eq!(
            apdu(d, &TERMINATE).1,
            SW_OK,
            "TERMINATE stays available while terminated"
        );
        assert_eq!(
            apdu(d, &ACTIVATE).1,
            SW_OK,
            "ACTIVATE stays available while terminated"
        );
    });
}

/// The four-byte framing is the one thing in this story that has a
/// documented precedent for being wrong on this codebase — the OATH/OTP
/// applets shipped a 4-byte case-1 bug (US-132). The client's TERMINATE and
/// ACTIVATE are both four bytes with no Le, so both are exercised as
/// written. A three-byte APDU is rejected by the ISO 7816 parser with
/// `6D00` *before* opcard sees it, which is the discriminator: a `6D00` on
/// the 4-byte form would mean a framing regression, and `6985`/`9000`
/// proves the command reached its handler.
#[test]
fn the_four_byte_case_1_framing_parses_and_three_bytes_does_not() {
    on_fresh_card(&format!("us154-framing-{}", std::process::id()), |d| {
        personalise(d);

        // TERMINATE: the `6985` is the not-authorised answer, i.e. the
        // command was decoded and dispatched, not rejected at the parser.
        assert_eq!(
            apdu(d, &TERMINATE).1,
            0x6985,
            "4-byte TERMINATE must reach its handler (6985 = not authorised)"
        );
        assert_eq!(
            apdu(d, &[0x00, 0xE6, 0x00]).1,
            0x6D00,
            "a 3-byte TERMINATE is a framing error, not a shorter encoding"
        );

        // ACTIVATE: `9000` because the card is operational and ACTIVATE is
        // an early-return no-op there.
        assert_eq!(
            apdu(d, &ACTIVATE).1,
            SW_OK,
            "4-byte ACTIVATE must parse and answer 9000"
        );
        assert_eq!(
            apdu(d, &[0x00, 0x44, 0x00]).1,
            0x6D00,
            "a 3-byte ACTIVATE is a framing error"
        );

        // A 5-byte case-1 with an explicit Le=0 is still valid ISO 7816
        // and must not be confused with the 4-byte form.
        assert_eq!(
            apdu(d, &[0x00, 0xE6, 0x00, 0x00, 0x00]).1,
            0x6985,
            "the Le=0 form is accepted by the parser and reaches the handler"
        );
    });
}
