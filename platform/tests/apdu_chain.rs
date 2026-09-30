//! US-181 (`PICOForge-COMPAT`) — receive-side ISO 7816-4 command chaining.
//!
//! These are the *unit* tests for `platform::apdu_chain`, and they are
//! deliberately card-free: the module is policy, and policy is testable
//! without a card, a reader, or an emulator. The end-to-end proof that the
//! wire behaviour matches PicoForge's `send_chained` is
//! `tests/openpgp/test_openpgp_chaining.py`.
//!
//! Every APDU here is transcribed from **the client**, not from the
//! accumulator, for the reason `tests/harness/rescue_ccid.py` gives at
//! length: a test built from the implementation's own constants cannot fail
//! when the implementation and the client disagree, which is the only failure
//! mode that matters on a single-consumer compatibility surface.

use fapico2_platform::apdu_chain::{
    ChainAssembler, ChainError, Step, CLA_CHAIN, MAX_CHAINED_APDU, MAX_CHAINED_BODY,
};
use fapico2_platform::dispatch::SW_WRONG_LENGTH;

/// `CHAIN_CHUNK` (`picoforge/src/hal/transport/ccid.rs:22`) — the fragment
/// size `send_chained` uses, and therefore the only fragment length a
/// conforming client ever sends.
const CHAIN_CHUNK: usize = 255;

/// `CLA_ISO` — the class byte of a command that is *not* chained
/// (`picoforge/src/hal/apdu/mod.rs:25`).
const CLA_ISO: u8 = 0x00;

/// `INS_PUT_DATA` — the instruction both applets care about
/// (`picoforge/src/hal/applets/piv.rs` `INS_PUT_DATA`; `vendor/opcard`
/// `Command::PutData` for OpenPGP).
const INS_PUT_DATA: u8 = 0xDA;

/// Build the fragment `send_chained` would send for `body[i..i+255]`
/// (`ccid.rs:121-130`): `cla | CLA_CHAIN`, same INS/P1/P2, short Lc, the
/// 255 bytes.
fn fragment(ins: u8, p1: u8, p2: u8, body: &[u8]) -> Vec<u8> {
    let mut apdu = vec![CLA_ISO | CLA_CHAIN, ins, p1, p2, body.len() as u8];
    apdu.extend_from_slice(body);
    apdu
}

/// Build the tail `send_chained` would send (`ccid.rs:135-142`): the
/// **original** class byte, the same INS/P1/P2, short Lc, the remainder.
fn tail(ins: u8, p1: u8, p2: u8, body: &[u8]) -> Vec<u8> {
    let mut apdu = vec![CLA_ISO, ins, p1, p2, body.len() as u8];
    apdu.extend_from_slice(body);
    apdu
}

/// Drive a whole body through the accumulator exactly as `send_chained`
/// would, returning the SW each step should be answered with. `Broken` maps
/// to the error status, which is the only way to see a refusal from here.
fn send_chained(acc: &mut ChainAssembler, ins: u8, p1: u8, p2: u8, body: &[u8]) -> Vec<u16> {
    let mut sws = Vec::new();
    let mut i = 0;
    while body.len() - i > CHAIN_CHUNK {
        match acc.push(&fragment(ins, p1, p2, &body[i..i + CHAIN_CHUNK])) {
            Step::Buffered | Step::Pass => sws.push(0x9000),
            Step::Complete => sws.push(0x9000),
            Step::Broken(e) => {
                sws.push(e.status());
                return sws;
            }
        }
        i += CHAIN_CHUNK;
    }
    match acc.push(&tail(ins, p1, p2, &body[i..])) {
        // A resolved chain is `Complete`; a body that never chained is
        // `Pass` — both are a 9000 to the client.
        Step::Buffered | Step::Pass => sws.push(0x9000),
        Step::Complete => sws.push(0x9000),
        Step::Broken(e) => sws.push(e.status()),
    }
    sws
}

/// Feed one APDU the way an applet does and return `(step, bytes-to-dispatch)`.
///
/// On `Step::Pass` the applet dispatches the **caller's own slice** and the
/// accumulator contributes nothing, so the second element is empty — that is
/// the contract, not an omission. Only `Step::Complete` has a render buffer.
fn step_and_apdu(acc: &mut ChainAssembler, apdu: &[u8]) -> (Step, Vec<u8>) {
    let step = acc.push(apdu);
    let bytes = match step {
        Step::Complete => acc.apdu().to_vec(),
        _ => Vec::new(),
    };
    (step, bytes)
}

/// The data field of a reassembled APDU, read back through `iso7816`.
///
/// **The trap this avoids:** a test that slices the body out at a hardcoded
/// offset is asserting the layout this implementation happens to pick, not
/// the thing the applets care about — which is that the emitted APDU parses
/// and carries the whole body. The offset is 5 for the short-Lc form and 7
/// for the extended one, and a test that hardcodes either one silently stops
/// testing anything the moment the other form is chosen. (It did exactly
/// that while this file was being written.)
fn body_of(apdu: &[u8]) -> &[u8] {
    use iso7816::command::CommandView;
    CommandView::try_from(apdu)
        .unwrap_or_else(|e| panic!("reassembled APDU {apdu:02x?} rejected: {e:?}"))
        .data()
}

// ---------------------------------------------------------------------------
// The bound
// ---------------------------------------------------------------------------

/// The bound is *derived*, and the derivation is the test: if any of the three
/// numbers it is built from moves, this fails and the doc comment moves with
/// it.
#[test]
fn the_bound_is_the_largest_body_a_conforming_client_can_need() {
    // opcard `MAX_GENERIC_LENGTH` (`vendor/opcard/src/state.rs:36`) — the
    // largest OpenPGP DO.
    const MAX_GENERIC_LENGTH: usize = 4096;
    // PIV `MAX_OBJECT_SIZE` (`apps/piv/src/lib.rs:55`).
    const MAX_OBJECT_SIZE: usize = 2048;

    // OpenPGP: 2 tag bytes (the `0x7F21` two-byte form) + 3 length bytes
    // (`82 hi lo`, which 4096 requires) + the value.
    let openpgp_worst = MAX_GENERIC_LENGTH + 2 + 3;
    // PIV: `5C 03 5F C1 <fid>` + `53 82 hi lo` + the value.
    let piv_worst = MAX_OBJECT_SIZE + 5 + 3;

    assert_eq!(openpgp_worst, MAX_CHAINED_BODY, "OpenPGP dominates");
    assert!(
        piv_worst < MAX_CHAINED_BODY,
        "PIV's worst case ({piv_worst}) must fit inside the OpenPGP-derived bound"
    );
    // The envelope must hold the body plus the widest header it can need.
    const { assert!(MAX_CHAINED_APDU >= MAX_CHAINED_BODY + 9) };
}

/// The chain bit this module keys on is the bit `iso7816` keys on. If a
/// future `iso7816` moved it, every rule below would silently stop applying.
#[test]
fn the_chain_bit_is_the_one_iso7816_reads() {
    use iso7816::command::class::Class;
    for cla in 0u8..=255 {
        let ours = cla & CLA_CHAIN != 0;
        let theirs = match Class::try_from(cla) {
            Ok(c) => !c.chain().last_or_only(),
            // `Class::try_from` rejects the reserved class values; there is
            // no chain bit to disagree about.
            Err(_) => continue,
        };
        assert_eq!(ours, theirs, "CLA {cla:#04x} disagrees");
    }
}

// ---------------------------------------------------------------------------
// Reassembly
// ---------------------------------------------------------------------------

/// The headline case: a 512-byte `PUT DATA` body arrives as 255 + 255 + 2 and
/// comes out as one 512-byte command — with a **correct extended Lc**, which
/// is what a naive `cla | 0x10` strip-and-concatenate would get wrong.
#[test]
fn reassembles_a_512_byte_body_into_one_command() {
    let body: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
    let mut acc: ChainAssembler = ChainAssembler::new();

    let sws = send_chained(&mut acc, INS_PUT_DATA, 0x00, 0x00, &body);
    assert_eq!(sws, vec![0x9000, 0x9000, 0x9000], "every SW is 9000");
    assert!(!acc.is_pending(), "the chain is closed");

    let apdu = acc.apdu();
    assert_eq!(&apdu[0..4], &[CLA_ISO, INS_PUT_DATA, 0x00, 0x00]);
    // Extended Lc: `00 02 00` for 512.
    assert_eq!(&apdu[4..7], &[0x00, 0x02, 0x00], "extended Lc for 512");
    assert_eq!(apdu.len(), 7 + 512, "no trailing Le");
    assert_eq!(&apdu[7..], &body[..], "body reassembled byte-for-byte");
}

/// The reassembled APDU must be a command `iso7816` itself accepts with the
/// declared Lc — the property the applets depend on when they re-parse it.
#[test]
fn the_reassembled_apdu_parses_back_with_the_declared_lc() {
    use iso7816::command::CommandView;

    // 1 and 255 never chain (`send_chained` short-circuits at `<= CHAIN_CHUNK`),
    // so only the lengths above that go through the accumulator. 256 is the
    // smallest that does.
    for len in [256usize, 257, 510, 4096, MAX_CHAINED_BODY] {
        let body: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
        let mut acc: ChainAssembler = ChainAssembler::new();
        let sws = send_chained(&mut acc, INS_PUT_DATA, 0x00, 0x00, &body);
        assert_eq!(*sws.last().unwrap(), 0x9000, "len {len}");

        let cmd = CommandView::try_from(acc.apdu())
            .unwrap_or_else(|e| panic!("len {len}: reassembled APDU rejected: {e:?}"));
        assert_eq!(cmd.data(), &body[..], "len {len}: body round-trips");
        // And the *rendered* command is no longer a chain — the chain bit is
        // cleared, which is what a caller re-parsing it would rely on.
        assert!(
            cmd.class().chain().last_or_only(),
            "len {len}: the render must not re-set the chain bit"
        );
    }
}

/// A body that fits the short Lc form is emitted in it — a client that
/// inspects the reassembled bytes should not see the wire change shape for
/// small bodies.
#[test]
fn a_short_reassembled_body_keeps_the_short_lc_form() {
    // A *chained* body that still fits one Lc byte: two 100/50 pieces, not
    // the 255/1 that `send_chained` would produce. The point is that resolving
    // a chain does not force the extended form — the render picks the
    // minimal legal encoding, so a client that inspects the bytes is not
    // handed a different shape for a small body.
    let mut acc: ChainAssembler = ChainAssembler::new();
    assert_eq!(
        acc.push(&fragment(INS_PUT_DATA, 0x00, 0x00, &[0xA1; 100])),
        Step::Buffered
    );
    let (step, apdu) = step_and_apdu(&mut acc, &tail(INS_PUT_DATA, 0x00, 0x00, &[0xB2; 50]));
    assert_eq!(step, Step::Complete);
    assert_eq!(apdu.len(), 5 + 150, "short form: 4 header + 1 Lc + 150");
    assert_eq!(apdu[4], 150, "short Lc byte");
    assert_eq!(body_of(&apdu), &[vec![0xA1u8; 100], vec![0xB2u8; 50]].concat()[..]);
}

/// A case-4 terminator's `Le` survives reassembly, and is re-encoded at the
/// width the reassembled Lc requires. `CommandView::expected()` must be
/// unchanged — that is what the OpenPGP `serve` path sizes its reply with.
#[test]
fn the_terminators_le_survives_and_is_re_encoded_to_match_the_lc() {
    use iso7816::command::CommandView;

    for body_len in [300usize, 260] {
        let body: Vec<u8> = (0..body_len).map(|i| (i % 251) as u8).collect();

        // Case 4S terminator: `... <tail> Le`, Le = 0 meaning 256.
        let mut acc: ChainAssembler = ChainAssembler::new();
        let mut i = 0;
        while body.len() - i > CHAIN_CHUNK {
            assert_eq!(
                acc.push(&fragment(INS_PUT_DATA, 0x00, 0x00, &body[i..i + CHAIN_CHUNK])),
                Step::Buffered
            );
            i += CHAIN_CHUNK;
        }
        let rest = &body[i..];
        let mut term = vec![CLA_ISO, INS_PUT_DATA, 0x00, 0x00, rest.len() as u8];
        term.extend_from_slice(rest);
        term.push(0x00); // Le = 0 -> 256
        assert_eq!(acc.push(&term), Step::Complete);

        let cmd = CommandView::try_from(acc.apdu())
            .unwrap_or_else(|e| panic!("body_len {body_len}: {e:?}"));
        assert_eq!(cmd.data(), &body[..], "body_len {body_len}");
        assert_eq!(cmd.expected(), 256, "body_len {body_len}: Le preserved");
        // 256 cannot be spelled in one Le byte alongside an extended Lc, so
        // it must have been widened to `01 00`.
        assert_eq!(&acc.apdu()[acc.apdu().len() - 2..], &[0x01, 0x00]);
        assert_eq!(acc.apdu().len(), 7 + body_len + 2, "extended Lc + 2-byte Le");
    }
}

// ---------------------------------------------------------------------------
// A non-chained command is unaffected
// ---------------------------------------------------------------------------

/// Every ordinary command must come out **byte-identical**. This is the
/// property that keeps US-181 from changing any existing behaviour: a card
/// that rewrote untouched APDUs would be a card nobody could review.
#[test]
fn a_non_chained_command_passes_through_byte_for_byte() {
    let cases: Vec<Vec<u8>> = vec![
        // case 1
        vec![0x00, 0xC0, 0x00, 0x00],
        // case 2S (Le = 0 -> 256)
        vec![0x00, 0xCA, 0x7F, 0x21, 0x00],
        // case 2S (Le = 32)
        vec![0x00, 0xCA, 0x5F, 0x52, 0x20],
        // case 3S
        vec![0x00, 0xDA, 0x00, 0x00, 0x03, 0xF0, 0x01, 0x02],
        // case 3E
        {
            let mut v = vec![0x00, 0xDA, 0x00, 0x00, 0x00, 0x01, 0x00];
            v.extend_from_slice(&[0xAA; 256]);
            v
        },
        // case 4S
        vec![0x00, 0x20, 0x00, 0x00, 0x02, 0x31, 0x32, 0x40],
        // case 4E
        vec![0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x02, 0x31, 0x32, 0x01, 0x00],
    ];
    for case in &cases {
        let mut acc: ChainAssembler = ChainAssembler::new();
        assert_eq!(
            acc.push(case),
            Step::Pass,
            "{:02x?} is not part of a chain, so it must pass through",
            case
        );
        // The accumulator copied nothing: the applet keeps its own slice, so
        // a rewrite is not merely unlikely here, it is unrepresentable. An
        // empty render buffer is the observable proof.
        assert!(acc.apdu().is_empty(), "{:02x?} was copied into the buffer", case);
        assert!(!acc.is_pending());
    }
}

/// A chained run followed by an ordinary command must not leak state into it.
#[test]
fn a_command_after_a_completed_chain_is_unaffected() {
    let body = vec![0x5Au8; 300];
    let mut acc: ChainAssembler = ChainAssembler::new();
    send_chained(&mut acc, INS_PUT_DATA, 0x00, 0x00, &body);
    assert!(!acc.is_pending());

    let next = vec![0x00u8, 0xCA, 0x5F, 0x52, 0x20];
    assert_eq!(acc.push(&next), Step::Pass, "no chain is in progress");
    assert!(acc.apdu().is_empty(), "no bytes carried over");
}

// ---------------------------------------------------------------------------
// Fail-closed: every malformed shape
// ---------------------------------------------------------------------------

/// A fragment that changes a header field mid-chain is refused, and the
/// accumulated bytes are gone — never handed to the terminator. All four
/// fields (CLA with b4 cleared, INS, P1, P2) are exercised, because "P1 and
/// P2 match" is the only check someone would write, and it is the one that
/// lets an INS change through.
#[test]
fn a_fragment_that_changes_a_header_field_breaks_the_chain() {
    // (INS, P1, P2) of the offending fragment, against a chain opened with
    // (INS_PUT_DATA, 0x00, 0x00). CLA is covered separately: a differing
    // chain bit is the *normal* case, so a differing non-bit CLA is not
    // expressible for an interindustry class.
    for (ins, p1, p2) in [
        (INS_PUT_DATA, 0x3F, 0x00), // P1
        (INS_PUT_DATA, 0x00, 0xFF), // P2
        (0xDBu8, 0x00, 0x00),        // INS
    ] {
        let mut acc: ChainAssembler = ChainAssembler::new();
        assert_eq!(
            acc.push(&fragment(INS_PUT_DATA, 0x00, 0x00, &[0xAA; 255])),
            Step::Buffered
        );
        assert_eq!(acc.pending_len(), 255);
        assert_eq!(
            acc.push(&fragment(ins, p1, p2, &[0xBB; 255])),
            Step::Broken(ChainError::HeaderMismatch),
            "INS {ins:#04x} P1 {p1:#04x} P2 {p2:#04x}"
        );
        assert!(!acc.is_pending(), "accumulated bytes are dropped");
        assert_eq!(acc.pending_len(), 0);
        // And the next command is served on its own merits.
        let next = vec![0x00u8, 0xCA, 0x5F, 0x52, 0x20];
        assert_eq!(acc.push(&next), Step::Pass, "no residue from the broken chain");
        assert!(acc.apdu().is_empty());
    }
}

/// **The trap this guards:** a non-chained command that arrives while a chain
/// is pending but is a *different* command must NOT be handed the abandoned
/// bytes. That is the corruption case, and it is the reason rule 1 exists.
#[test]
fn an_unrelated_command_never_receives_an_abandoned_chains_bytes() {
    let mut acc: ChainAssembler = ChainAssembler::new();
    assert_eq!(
        acc.push(&fragment(INS_PUT_DATA, 0x00, 0x00, &[0xAA; 255])),
        Step::Buffered
    );
    // A `GET DATA` turns up instead of the chain's terminator. It must be
    // dispatched with its own (empty) body, not with 255 bytes of `0xAA`.
    let get = vec![0x00u8, 0xCA, 0x7F, 0x21, 0x00];
    assert_eq!(
        acc.push(&get),
        Step::Pass,
        "GET DATA carried no chain bytes, so it is the caller's own slice"
    );
    assert!(acc.apdu().is_empty(), "no chain bytes were rendered into it");
    assert!(!acc.is_pending(), "the abandoned chain is dropped");
}

/// `reset()` is the SELECT path. It is the only thing standing between an
/// abandoned chain and the *next* command after a re-SELECT.
#[test]
fn reset_drops_a_pending_chain() {
    let mut acc: ChainAssembler = ChainAssembler::new();
    acc.push(&fragment(INS_PUT_DATA, 0x00, 0x00, &[0xAA; 255]));
    assert!(acc.is_pending());
    acc.reset();
    assert!(!acc.is_pending());
    assert_eq!(acc.pending_len(), 0);

    // A fresh chain after a reset starts from empty, and does not inherit the
    // old header.
    assert_eq!(
        acc.push(&fragment(0xDB, 0x3F, 0xFF, &[0xCC; 10])),
        Step::Buffered
    );
    assert_eq!(acc.pending_len(), 10);
    let term = vec![0x00u8, 0xDB, 0x3F, 0xFF, 0x02, 0xDD, 0xDD];
    assert_eq!(acc.push(&term), Step::Complete);
    // The terminator's own two bytes are part of the command, so the body is
    // the fragment *and* the tail — 12 bytes, not 10.
    let expect: Vec<u8> = [vec![0xCCu8; 10], vec![0xDD, 0xDD]].concat();
    assert_eq!(body_of(acc.apdu()), &expect[..]);
}

/// A chain that would exceed the bound is refused **at the fragment that
/// would cross it**, not after silently growing. This is the
/// memory-exhaustion-surface rule.
#[test]
fn an_over_long_chain_is_refused_at_the_fragment_that_crosses_the_bound() {
    let mut acc: ChainAssembler = ChainAssembler::new();
    let chunk = vec![0xA5u8; CHAIN_CHUNK];

    let chunks = MAX_CHAINED_BODY / CHAIN_CHUNK; // 16 full fragments = 4080
    for i in 0..chunks {
        assert_eq!(
            acc.push(&fragment(INS_PUT_DATA, 0x00, 0x00, &chunk)),
            Step::Buffered,
            "fragment {i}"
        );
        assert_eq!(acc.pending_len(), (i + 1) * CHAIN_CHUNK);
    }
    // 4080 + 255 = 4335 > 4101.
    assert_eq!(
        acc.push(&fragment(INS_PUT_DATA, 0x00, 0x00, &chunk)),
        Step::Broken(ChainError::TooLong)
    );
    assert!(!acc.is_pending());
    assert_eq!(acc.pending_len(), 0, "nothing is left half-appended");

    // The refusal is recoverable: a fresh, legal chain still works.
    assert_eq!(
        acc.push(&fragment(INS_PUT_DATA, 0x00, 0x00, &[0x11; 10])),
        Step::Buffered
    );
    let term = vec![0x00u8, INS_PUT_DATA, 0x00, 0x00, 0x01, 0x22];
    assert_eq!(acc.push(&term), Step::Complete);
    // Fragment bytes *and* the terminator's one byte — the whole body.
    let expect: Vec<u8> = [vec![0x11u8; 10], vec![0x22]].concat();
    assert_eq!(body_of(acc.apdu()), &expect[..]);
}

/// A body of exactly the bound is accepted; one byte more is not. The bound
/// is a bound, not a rounding.
#[test]
fn the_bound_is_inclusive_and_one_byte_over_is_not() {
    let body = vec![0x7Cu8; MAX_CHAINED_BODY];
    let mut acc: ChainAssembler = ChainAssembler::new();
    let sws = send_chained(&mut acc, INS_PUT_DATA, 0x00, 0x00, &body);
    assert_eq!(*sws.last().unwrap(), 0x9000);
    assert_eq!(acc.apdu().len(), 7 + MAX_CHAINED_BODY);

    let mut acc: ChainAssembler = ChainAssembler::new();
    let over = vec![0x7Cu8; MAX_CHAINED_BODY + 1];
    let sws = send_chained(&mut acc, INS_PUT_DATA, 0x00, 0x00, &over);
    assert_eq!(*sws.last().unwrap(), SW_WRONG_LENGTH);
    assert!(!acc.is_pending());
}

/// Every chain error answers `6700`, and **`6Cxx` is never used** — the
/// reason is recorded on [`ChainError::status`]: a `6Cxx` makes
/// `transceive_paged` re-send the same fragment, which the card cannot tell
/// from a new one, duplicating data.
#[test]
fn every_chain_error_is_6700_and_never_6cxx() {
    for e in [
        ChainError::HeaderMismatch,
        ChainError::TooLong,
        ChainError::Malformed,
    ] {
        let sw = e.status();
        assert_eq!(sw, SW_WRONG_LENGTH, "{e:?}");
        assert_ne!(sw & 0xFF00, 0x6C00, "{e:?} must not be 6Cxx");
    }
}

/// An APDU too short to be a command — including the 1-byte and 0-byte ones
/// that the mgmt applet had to grow a guard for (US-701) — is refused, and
/// specifically does not index past the end.
#[test]
fn a_sub_four_byte_apdu_is_refused_not_indexed() {
    // With the chain bit clear and no chain in progress, a short APDU is not
    // this module's business: it passes through so the applet can answer it
    // as it always has. The trap a reader would otherwise believe is that the
    // accumulator "validates" every APDU — it does not, and routing these
    // through the parser would have silently changed a status word.
    for n in 0..4usize {
        let apdu = vec![0x00u8; n];
        let mut acc: ChainAssembler = ChainAssembler::new();
        assert_eq!(acc.push(&apdu), Step::Pass, "len {n}");
    }
    // But a *chained* short APDU is a broken fragment, and is refused — and
    // refused without ever indexing `apdu[1..3]`.
    for n in 1..4usize {
        let mut apdu = vec![CLA_ISO | CLA_CHAIN; n];
        apdu.truncate(n);
        let mut acc: ChainAssembler = ChainAssembler::new();
        assert_eq!(
            acc.push(&apdu),
            Step::Broken(ChainError::Malformed),
            "chained len {n}"
        );
    }
}

/// An APDU whose declared `Lc` overruns its own length is refused. It is
/// refused *before* anything is appended, so a truncated fragment can never
/// end up inside a body.
#[test]
fn a_fragment_whose_lc_overruns_the_apdu_is_refused() {
    let mut acc: ChainAssembler = ChainAssembler::new();
    // Declares Lc = 0x20 (32) but carries 4 bytes.
    let bad = vec![0x10u8, INS_PUT_DATA, 0x00, 0x00, 0x20, 0xAA, 0xBB, 0xCC, 0xDD];
    assert_eq!(acc.push(&bad), Step::Broken(ChainError::Malformed));
    assert!(!acc.is_pending());
    assert_eq!(acc.pending_len(), 0);

    // A good chain still works after the malformed one.
    assert_eq!(
        acc.push(&fragment(INS_PUT_DATA, 0x00, 0x00, &[0x01, 0x02])),
        Step::Buffered
    );
    let term = vec![0x00u8, INS_PUT_DATA, 0x00, 0x00, 0x00];
    assert_eq!(acc.push(&term), Step::Complete);
    assert_eq!(body_of(acc.apdu()), &[0x01, 0x02][..]);
}

/// A 4-byte `cla|0x10` APDU is a legal case-1 fragment: it contributes no
/// bytes and is *not* an error. A reader would reasonably expect it to be
/// either accepted or refused, and the answer here is accepted — with
/// nothing written.
#[test]
fn a_bodyless_chained_apdu_is_a_fragment_contributing_nothing() {
    let mut acc: ChainAssembler = ChainAssembler::new();
    assert_eq!(acc.push(&[0x10, INS_PUT_DATA, 0x00, 0x00]), Step::Buffered);
    assert_eq!(acc.pending_len(), 0);
    // A following fragment is treated as the chain's continuation, not as a
    // header mismatch.
    assert_eq!(
        acc.push(&fragment(INS_PUT_DATA, 0x00, 0x00, &[0x77, 0x88])),
        Step::Buffered
    );
    let term = vec![0x00u8, INS_PUT_DATA, 0x00, 0x00, 0x01, 0x99];
    assert_eq!(acc.push(&term), Step::Complete);
    assert_eq!(body_of(acc.apdu()), &[0x77, 0x88, 0x99][..]);
}

/// A chain terminated by a bodyless **case 2S** command (a bare `Le`) must
/// keep that `Le`. The trap: it is the same length as a case-3S with `Lc = 0`,
/// and a length-only classification would drop the `Le` silently.
#[test]
fn a_case_2s_terminator_keeps_its_le() {
    use iso7816::command::CommandView;

    let mut acc: ChainAssembler = ChainAssembler::new();
    acc.push(&fragment(0xCA, 0x7F, 0x21, &[0x01, 0x02, 0x03]));
    // `00 CA 7F 21 00` — case 2S, Le = 256, no data.
    let term = vec![0x00u8, 0xCA, 0x7F, 0x21, 0x00];
    assert_eq!(acc.push(&term), Step::Complete);
    let cmd = CommandView::try_from(acc.apdu()).expect("reassembled parses");
    assert_eq!(cmd.data(), &[0x01, 0x02, 0x03][..], "the chain bytes survived");
    assert_eq!(cmd.expected(), 256, "the case-2 Le survived");
}

/// PicoForge's exact call shape for a 255-byte body: `send_chained` short
/// circuits to a single unchained `transceive_full` (`ccid.rs:116-118`), so
/// no fragment is ever sent and the accumulator must not be involved.
#[test]
fn a_body_of_exactly_255_bytes_sends_no_fragment() {
    // The client's loop is `while data.len() - i > CHAIN_CHUNK`, so a
    // 255-byte body never enters it. Asserted here because an off-by-one the
    // other way would put a *zero-length* fragment on the wire.
    let body = vec![0x5Au8; 255];
    let mut acc: ChainAssembler = ChainAssembler::new();
    assert_eq!(
        acc.push(&tail(INS_PUT_DATA, 0x00, 0x00, &body)),
        Step::Pass,
        "no fragment was sent, so the accumulator is not involved at all"
    );
    assert!(acc.apdu().is_empty());
    assert!(!acc.is_pending());
}

/// A 256-byte body is the smallest that actually chains: 255 + 1.
#[test]
fn the_smallest_chained_body_is_256_bytes() {
    let body: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
    let mut acc: ChainAssembler = ChainAssembler::new();
    let sws = send_chained(&mut acc, INS_PUT_DATA, 0x00, 0x00, &body);
    assert_eq!(sws, vec![0x9000, 0x9000], "one fragment, then a 1-byte tail");
    let apdu = acc.apdu();
    assert_eq!(&apdu[4..7], &[0x00, 0x01, 0x00], "extended Lc for 256");
    assert_eq!(&apdu[7..], &body[..]);
}
