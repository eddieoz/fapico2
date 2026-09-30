//! US-182 (PICOForge-COMPAT, Phase J) — the OpenPGP applet's status words.
//!
//! The companion to `apps/tests/sw_universe.rs`, which carries the other six
//! CCID applets. This one is separate for a reason that is worth stating
//! before anything else, because it looks like an omission and is not one.
//!
//! # Why OpenPGP's table is not a list
//!
//! Every other applet in this workspace returns a status word it chose. The
//! OpenPGP applet does not: `OpenPgpApp` runs the vendored `opcard`
//! implementation unmodified and hands opcard's error status straight to the
//! wire —
//!
//! ```text
//! // apps/openpgp/src/device_shell.rs:664
//! Err(status) => Sw::from(status),
//! ```
//!
//! `Sw::from(status)` is `u16::from(iso7816::Status)`, so the applet's
//! permitted set is **exactly the set of `u16` values that decode to an
//! `iso7816::Status` variant** — which, because `Status::from_u16` is
//! exhaustive over ranges plus a `__Unknown` fallback
//! (`iso7816-0.2.0/src/response/status.rs:297-372`), is every 16-bit value
//! except the ones that fall through to `__Unknown`.
//!
//! The consequence is that a *hand-written* list here would be strictly worse
//! than nothing:
//!
//! * it would go stale on every `iso7816` upgrade, silently, because nothing
//!   compares it to the enum;
//! * it would be a **weaker** claim, not a stronger one — "the applet answers
//!   one of these 40 words" is checkable against a list, whereas "the applet
//!   answers a word the card specification defines" is checkable against the
//!   enum, which is the actual contract;
//! * and the interesting half of the question — *which* words the applet
//!   actually emits — is answered by the closed-world corpus below, which does
//!   not care what the permitted set is at all.
//!
//! So the table row is **"the whole `iso7816::Status` enum"**, and the test
//! that holds it is [`every_observed_word_is_an_iso7816_status`], which
//! derives the permitted set from the crate rather than restating it. The
//! words a client actually needs are still driven individually — see
//! [`the_words_the_client_depends_on_are_driven_one_by_one`] — because "the
//! enum permits it" is not the same claim as "this APDU produces it", and only
//! the second one is worth anything to somebody debugging a `6A82` where a
//! `6982` belongs.
//!
//! # The naming trap, once more
//!
//! `0x6A80` is `Status::IncorrectDataParameter` here and `SW_INCORRECT_PARAMS`
//! in the OATH and PIV applets; `0x6A82` is `Status::NotFound` here and
//! `SW_FILE_NOT_FOUND` in the dispatcher. Nothing in this file keys off a name
//! — the closed-world check compares `u16` against `Status::from_u16`.
//!
//! # A nuance about `0x6A83`
//!
//! The other sweep pins `0x6A83` (record not found) as a word **nothing in
//! this firmware emits**. Here it is worth being precise about why, because
//! the reason is not the same for the two: `0x6A83` *is* a real `iso7816`
//! variant (`Status::RecordNotFound`), so this applet is *permitted* to answer
//! it — it simply never does, because opcard's command set has no record-based
//! INS. "Dead" here means "no APDU in this firmware's command set produces
//! it", which is a statement about the command set, not about the enum. The
//! permitted set being a superset of the produced set is exactly why the
//! corpus layer exists.

use fapico2_openpgp::{OpenPgpApp, OPENPGP_AID};
use fapico2_platform::dispatch::{Dispatcher, MAX_RESPONSE, Sw};
use heapless::Vec as HeaplessVec;
use iso7816::Status;
use std::collections::BTreeSet;

// ── the table row ──────────────────────────────────────────────────────────

/// The OpenPGP applet's row in the US-182 table, stated as the *only* row
/// that cannot be a list.
///
/// Kept as a `const` rather than only as prose so a reader grepping the other
/// file's tables finds this one too, and so [`the_permitted_set_is_the_enum`]
/// has something to point at.
const OPENPGP_PERMITTED: &str = "every u16 that decodes to a non-__Unknown iso7816::Status";

// ── the driver ─────────────────────────────────────────────────────────────

fn select_openpgp() -> Vec<u8> {
    let mut a = vec![0x00u8, 0xA4, 0x04, 0x00, OPENPGP_AID.len() as u8];
    a.extend_from_slice(OPENPGP_AID);
    a
}

/// A SELECT of an AID that is deliberately not registered. The dispatcher
/// answers `0x6A82` (`platform/src/dispatch.rs:177-181`) — the one word here
/// that the applet itself never returns, exactly as in the other six tables.
const SELECT_UNKNOWN_AID: [u8; 8] = [0x00, 0xA4, 0x04, 0x00, 0x03, 0x01, 0x02, 0x03];

fn sw_of(resp: &HeaplessVec<u8, MAX_RESPONSE>) -> Option<Sw> {
    if resp.len() < 2 {
        return None;
    }
    let n = resp.len();
    Some(u16::from_be_bytes([resp[n - 2], resp[n - 1]]))
}

fn short(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        v.push(data.len() as u8);
        v.extend_from_slice(data);
    }
    v
}

fn ext(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![cla, ins, p1, p2, 0x00];
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    v
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

/// The INS values opcard's `Command::try_from` dispatches on
/// (`vendor/opcard/src/command.rs:122-213`), plus one unhandled byte for the
/// `_ => InstructionNotSupportedOrInvalid` arm.
///
/// Every one of these is a real INS, which is the point: the P1/P2 space below
/// is where opcard's *other* refusals live, and they are all `Status` values.
const INS: &[u8] = &[
    0x20, 0x21, 0x22, 0x24, 0x2A, 0x2C, 0x44, 0x47, 0x84, 0x88, 0xA4, 0xA5, 0xC0, 0xCA, 0xCB, 0xCC,
    0xDA, 0xDB, 0xE6, 0x00, 0xFF,
];

/// The P1 values the applet's own INS arms compare against: `VerifyMode`,
/// `PasswordMode`, `GenerateAsymmetricKeyPairMode`, `Occurrence`, `Tag` low
/// bytes, and the two-byte P1 of PSO (`0x80 00 0x86 00 0x9E 00 0xB6`).
const P1: &[u8] = &[0x00, 0x01, 0x02, 0x41, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x86, 0x9E, 0xB6, 0xFF];

/// The P2 values the arms compare against, plus `0x04` (SELECT/SELECT DATA),
/// `0x86`/`0x80` (the PSO pair) and `0x81` (RESET RETRY).
const P2: &[u8] = &[0x00, 0x01, 0x04, 0x80, 0x81, 0x82, 0x86, 0x9A, 0x7F, 0xFF];

/// The CLA values worth sweeping: `0x00`, the chain bit `0x10` (US-181 — a
/// *real* class on this wire, and the one the chaining module exists for), and
/// two rejected ones.
const CLA: &[u8] = &[0x00, 0x10, 0x80];

/// Bodies chosen to hit the TLV reader and the length checks rather than to
/// hit every value: empty, a bare DO TLV, a cardholder-certificate-shaped
/// blob, and the two extended-header forms a `GET DATA` uses.
fn bodies() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0x00; 8],
        vec![0x00; 32],
        vec![0x00; 255],
        (0u8..=255).collect(),
        // A one-byte DO TLV (`5C 01 5F C1`) — the smallest well-formed
        // `GET DATA` body.
        vec![0x5C, 0x01, 0x5F],
        // A `PUT DATA` body with the extended two-byte length form
        // (`81 82 01 00 <256>`) that a cardholder certificate uses. The
        // extended form is the only way to carry a body over 255 bytes, so it
        // is the one place the two- and three-byte `take_len` branches of
        // opcard's TLV reader (`vendor/opcard/src/tlv.rs`) are both reached.
        {
            let mut b = vec![0x81, 0x82, 0x01, 0x00];
            b.extend_from_slice(&[0x5Au8; 256]);
            b
        },
    ];
    v.sort();
    v.dedup();
    v
}

/// The full sweep, in one place: register, SELECT, corpus, unknown-AID.
///
/// Returns the observed set plus the first APDU that produced each word, so a
/// failure names the command rather than just the number.
fn sweep(app: &mut dyn fapico2_platform::dispatch::App) -> (BTreeSet<Sw>, Vec<(Sw, String)>) {
    let mut d: Dispatcher<1> = Dispatcher::new();
    assert!(d.register(app), "the dispatcher must accept the OpenPGP applet");
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    let mut seen = BTreeSet::new();
    let mut witness: Vec<(Sw, String)> = Vec::new();

    let note = |sw: Option<Sw>, what: String, seen: &mut BTreeSet<Sw>, witness: &mut Vec<(Sw, String)>| {
        if let Some(sw) = sw {
            if seen.insert(sw) {
                witness.push((sw, what));
            }
        }
    };

    d.dispatch(&select_openpgp(), &mut resp);
    note(sw_of(&resp), "SELECT AID".into(), &mut seen, &mut witness);

    for &cla in CLA {
        for &ins in INS {
            for &p1 in P1 {
                for &p2 in P2 {
                    d.dispatch(&[cla, ins, p1, p2], &mut resp);
                    note(sw_of(&resp), format!("{cla:02x} {ins:02x} {p1:02x} {p2:02x} (case 1)"), &mut seen, &mut witness);
                    for b in bodies() {
                        d.dispatch(&short(cla, ins, p1, p2, &b), &mut resp);
                        note(sw_of(&resp), format!("{} (short)", hex(&short(cla, ins, p1, p2, &b))), &mut seen, &mut witness);
                        d.dispatch(&ext(cla, ins, p1, p2, &b), &mut resp);
                        note(sw_of(&resp), format!("{} (ext)", hex(&ext(cla, ins, p1, p2, &b))), &mut seen, &mut witness);
                    }
                }
            }
        }
    }

    d.dispatch(&SELECT_UNKNOWN_AID, &mut resp);
    note(sw_of(&resp), "SELECT unknown AID".into(), &mut seen, &mut witness);

    (seen, witness)
}

// ── the closed-world layer ─────────────────────────────────────────────────

/// **The permitted set, derived rather than restated.** Every status word the
/// OpenPGP applet produced must decode to a real `iso7816::Status` — i.e. not
/// `__Unknown`.
///
/// This is the row's whole content, and the reason it is written against the
/// enum is in the module docs: a hand-typed list would be a weaker claim and
/// would rot silently on an `iso7816` upgrade. `Status::from_u16` is the
/// contract (`device_shell.rs:664` is a straight `Sw::from(status)`), so the
/// contract is what gets checked.
#[test]
fn every_observed_word_is_an_iso7816_status() {
    opcard::virt::with_ram_client("fapico2-openpgp-sw", |client| {
        let mut app = OpenPgpApp::new(client);
        let (seen, witness) = sweep(&mut app);
        let bad: Vec<String> = seen
            .iter()
            .filter(|sw| matches!(Status::from_u16(**sw), Status::__Unknown(v) if v == **sw))
            .map(|sw| {
                let w = witness
                    .iter()
                    .find(|(s, _)| s == sw)
                    .map(|(_, w)| w.clone())
                    .unwrap_or_default();
                format!("  {sw:04x}  produced by: {w}")
            })
            .collect();
        assert!(
            bad.is_empty(),
            "the OpenPGP applet produced {} word(s) that are not iso7816::Status variants \
             (permitted set = {OPENPGP_PERMITTED}):\n{}",
            bad.len(),
            bad.join("\n")
        );
        assert!(!seen.is_empty(), "the sweep must have observed something");
    });
}

/// **What the applet produces today**, as distinct from what it is permitted.
///
/// The permitted set is the whole enum, which is a deliberately weak ceiling —
/// it says nothing about what a user will actually see. This test records the
/// observed set as a literal, so the file carries both halves of the row and
/// a reader can diff them:
///
/// | word | `iso7816` name | who produces it |
/// |---|---|---|
/// | `0x9000` | `Success` | every command that worked, plus a SELECT and a buffered chain fragment |
/// | `0x6300` | `VerificationFailed` | opcard, CHANGE REFERENCE DATA with no `P1 = 0x00` |
/// | `0x63Cx` | `RemainingRetries(x)` | opcard, VERIFY / RESET RETRY COUNTER — the family the other sweep also finds on PIV |
/// | `0x6700` | `WrongLength` | the chaining module's `ChainError::status()`, and opcard's own length refusals |
/// | `0x6982` | `SecurityStatusNotSatisfied` | opcard, a command behind an un-granted permission |
/// | `0x6985` | `ConditionsOfUseNotSatisfied` | opcard, the on-card PIN-pad mode (US-936 / OQ-3) |
/// | `0x6A80` | `IncorrectDataParameter` | opcard, an algorithm attribute this build will not serve |
/// | `0x6A81` | `FunctionNotSupported` | opcard, a DO with no implemented access rule |
/// | `0x6A82` | `NotFound` | **the dispatcher only** — see the note below |
/// | `0x6A86` | `IncorrectP1OrP2Parameter` | opcard's `Command::try_from` and the P1/P2 arms |
/// | `0x6A88` | `KeyReferenceNotFound` | opcard, an unknown DO — *not* `0x6A82` |
/// | `0x6D00` | `InstructionNotSupportedOrInvalid` | opcard's `_` arm, and the shell's unparsable-SELECT arm |
///
/// Note `0x6A82` and `0x6A88` sitting next to each other. `0x6A82` is what a
/// client reads as "that applet does not exist" and the *only* thing producing
/// it here is the dispatcher's AID routing, exactly as in the other six tables
/// — opcard's own "I do not have that DO" answer is `0x6A88`, which a client
/// reads as "that reference does not exist". Swapping them is precisely the
/// wrong-but-plausible substitution the US-182 rationale names, and on this
/// applet it would be a one-word change in `device_shell.rs` with nothing
/// else in the tree noticing.
///
/// This test is a **pin, not a ceiling**: the permitted set stays the enum, so
/// a word added to the observed set does not fail anything here. That is
/// intentional and is the reason the observed set is written out rather than
/// derived — it is documentation that a test failure would make you update on
/// purpose, and the closed-world test above is the one that would catch a
/// word escaping the enum.
#[test]
fn the_observed_set_is_what_this_file_says() {
    /// Every word the corpus above produced, on this build, with the current
    /// opcard command set. If this fails, the change is real and the table in
    /// this file's docs is stale — read the witness in the failure before
    /// editing anything.
    const OBSERVED: &[Sw] = &[
        0x6300, 0x63C0, 0x63C1, 0x63C2, 0x63C3, 0x6700, 0x6982, 0x6985, 0x6A80, 0x6A81, 0x6A82,
        0x6A86, 0x6A88, 0x6D00, 0x9000,
    ];
    opcard::virt::with_ram_client("fapico2-openpgp-sw", |client| {
        let mut app = OpenPgpApp::new(client);
        let (seen, witness) = sweep(&mut app);
        let missing: Vec<String> = OBSERVED
            .iter()
            .filter(|w| !seen.contains(w))
            .map(|w| {
                format!(
                    "  {w:04x} ({:?}) is documented as observed but the corpus did not produce it",
                    Status::from_u16(*w)
                )
            })
            .collect();
        assert!(missing.is_empty(), "stale observed set:\n{}", missing.join("\n"));
        // And the direction that actually matters: every observed word is
        // already an enum variant (the closed-world test), and every one of
        // them is in the documented list. This is the assertion that turns
        // the table above into a maintained document rather than a comment.
        let undocumented: Vec<String> = seen
            .iter()
            .filter(|w| !OBSERVED.contains(w))
            .map(|w| {
                let where_ = witness
                    .iter()
                    .find(|(s, _)| s == w)
                    .map(|(_, x)| x.clone())
                    .unwrap_or_default();
                format!("  {w:04x} ({:?}) is new — produced by: {where_}", Status::from_u16(*w))
            })
            .collect();
        assert!(
            undocumented.is_empty(),
            "the OpenPGP applet produced {} word(s) this file does not document — add the row \
             to the table in this file's module docs:\n{}",
            undocumented.len(),
            undocumented.join("\n")
        );
    });
}

/// **The shell layer widens nothing.** `OpenPgpApp` is not a pure pass-through
/// even though its status words come from opcard: `select_apdu` answers
/// `SW_INS_NOT_SUPPORTED` for an APDU `iso7816` cannot parse
/// (`device_shell.rs:654`), `process` answers `SW_OK` for a buffered chain
/// fragment (`platform::apdu_chain::Step::Buffered`), and the chain's
/// `ChainError::status()` answers `0x6700`. All three are `iso7816` values, but
/// none of them is opcard's — they are the firmware's, and a firmware that
/// grew a shell-level word outside the enum would be a real finding. This
/// asserts the shell's own words, individually, so the claim is checked where
/// it is made rather than inferred from a corpus run.
#[test]
fn the_shell_layer_answers_only_iso7816_words() {
    use fapico2_platform::apdu_chain::{ChainAssembler, Step, MAX_CHAINED_APDU};
    use fapico2_platform::dispatch::{SW_INS_NOT_SUPPORTED, SW_OK};

    // Every word the shell itself can originate.
    let shell_words = [
        SW_INS_NOT_SUPPORTED,
        SW_OK,
        fapico2_platform::apdu_chain::ChainError::Malformed.status(),
        fapico2_platform::apdu_chain::ChainError::HeaderMismatch.status(),
        fapico2_platform::apdu_chain::ChainError::TooLong.status(),
    ];
    for sw in shell_words {
        assert!(
            !matches!(Status::from_u16(sw), Status::__Unknown(v) if v == sw),
            "the OpenPGP shell can answer {sw:04x}, which is not an iso7816::Status — the \
             permitted set is the enum, so this widens the applet's universe"
        );
    }
    // And the chaining step itself, so the `0x6700` is observed rather than
    // read off a constant. A 255-byte fragment with `cla | 0x10` is exactly
    // what `picoforge::send_chained` sends (`ccid.rs:115-144`).
    let mut asm: ChainAssembler<MAX_CHAINED_APDU> = ChainAssembler::new();
    // `cla | CLA_CHAIN`, same INS/P1/P2, short `Lc = 0xFF`, 255 bytes — the
    // exact shape `picoforge::send_chained` emits (`ccid.rs:121-130`).
    let mut fragment = vec![0x10u8, 0xDA, 0x00, 0x00, 0xFF];
    fragment.extend_from_slice(&[0x5Au8; 255]);
    assert_eq!(asm.push(&fragment), Step::Buffered, "a 255-byte fragment must buffer");
    // A fragment whose INS disagrees with the chain is refused, and the status
    // is `0x6700` — never `0x6Cxx`, which `transceive_paged` would re-send and
    // make the card append the same 255 bytes twice. See the module docs in
    // `platform::apdu_chain` for why that is a corruption vector, not a wrong
    // answer.
    let mut other = vec![0x10u8, 0xDB, 0x00, 0x00, 0xFF];
    other.extend_from_slice(&[0x5Au8; 255]);
    let broken = asm.push(&other);
    match broken {
        Step::Broken(err) => {
            let sw = err.status();
            assert_eq!(sw, 0x6700, "a broken chain must answer 0x6700");
            assert!(
                !matches!(Status::from_u16(sw), Status::__Unknown(v) if v == sw),
                "0x6700 is an iso7816::Status (WrongLength)"
            );
        }
        other => panic!("a mismatched fragment must break the chain, got {other:?}"),
    }
    // A whole chain — the final fragment, which is a normal APDU — resolves
    // to `Step::Complete` rather than a status, and the app then answers
    // `0x9000` because PicoForge hard-fails on any other status
    // (`ccid.rs:129-131`).
    let mut asm2: ChainAssembler<MAX_CHAINED_APDU> = ChainAssembler::new();
    assert_eq!(asm2.push(&fragment), Step::Buffered);
    // The terminator is the *same* command with CLA b4 clear and no body: a
    // four-byte case-1 APDU. (`apdu_chain`'s own test uses the same shape,
    // `platform/tests/apdu_chain.rs:403`.)
    let tail = vec![0x00u8, 0xDA, 0x00, 0x00];
    assert_eq!(asm2.push(&tail), Step::Complete, "the closing fragment completes the chain");
    assert!(
        !matches!(Status::from_u16(SW_OK), Status::__Unknown(v) if v == SW_OK),
        "a buffered fragment answers 0x9000, which is iso7816::Success"
    );
}

/// The word the applet is *permitted* but that no APDU in this firmware's
/// command set produces.
///
/// `0x6A83` is `Status::RecordNotFound` — a real enum variant, so this applet
/// is allowed to answer it. It never does, because opcard's command set has no
/// record-based INS. The other sweep pins `0x6A83` as dead across the whole
/// firmware; this one pins that the OpenPGP applet is not the thing that would
/// start producing it, so a future story knows which file to look in.
#[test]
fn record_not_found_is_permitted_but_not_produced() {
    opcard::virt::with_ram_client("fapico2-openpgp-sw", |client| {
        let mut app = OpenPgpApp::new(client);
        let (seen, _) = sweep(&mut app);
        assert!(
            !matches!(Status::from_u16(0x6A83), Status::__Unknown(_)),
            "0x6A83 is a real iso7816::Status (RecordNotFound) — if this ever fails, \
             iso7816 dropped the variant and the permitted set changed"
        );
        assert!(
            !seen.contains(&0x6A83),
            "the OpenPGP applet produced 0x6A83; opcard has no record-based INS, so this means \
             the command set gained one and the table row above should be re-read"
        );
    });
}

// ── the reachability layer ─────────────────────────────────────────────────

/// **The words a client actually depends on, driven one by one.**
///
/// "The enum permits it" and "this APDU produces it" are different claims and
/// only the second is worth anything when a user is looking at the wrong
/// diagnosis. Each case below is one the PicoForge/gpg path can be observed to
/// reach, with the exact expected value.
///
/// Every expected value is a `u16` literal, never a `Status` variant name and
/// never a constant imported from the applet — the naming trap from the module
/// docs applies here too, and `Status::NotFound` for `0x6A82` is exactly the
/// kind of thing that would let a re-spelling slip through.
#[test]
fn the_words_the_client_depends_on_are_driven_one_by_one() {
    opcard::virt::with_ram_client("fapico2-openpgp-sw", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut d: Dispatcher<1> = Dispatcher::new();
        assert!(d.register(&mut app));
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        let mut failures: Vec<String> = Vec::new();

        let check = |label: &str, apdu: &[u8], expect: Sw, d: &mut Dispatcher<1>, resp: &mut HeaplessVec<u8, MAX_RESPONSE>, failures: &mut Vec<String>| {
            d.dispatch(apdu, resp);
            match sw_of(resp) {
                Some(sw) if sw == expect => {}
                Some(sw) => failures.push(format!("{label}: {sw:04x}, expected {expect:04x}")),
                None => failures.push(format!("{label}: no status word")),
            }
        };

        // 9000 — SELECT AID, and the synthesized FCI that comes with it.
        check("SELECT AID", &select_openpgp(), 0x9000, &mut d, &mut resp, &mut failures);
        assert!(
            resp.len() > 2 && resp.starts_with(&[0x62, 0x20]),
            "SELECT must carry the synthesized FCI template ({:02x?}…)",
            &resp[..resp.len().min(8)]
        );

        // 9000 — VERIFY with the correct default PW1 ("123456"). opcard's
        // default card state carries the C reference firmware's PIN, which is
        // what `apps/openpgp/tests/dispatch.rs` relies on.
        check(
            "VERIFY the default PW1",
            &ext(0x00, 0x20, 0x00, 0x82, b"123456"),
            0x9000,
            &mut d,
            &mut resp,
            &mut failures,
        );

        // 6A80 — PUT DATA of an algorithm attribute this build cannot serve.
        // Brainpool P-512r1 is the real instance: US-944/946 shipped P-384r1
        // and P-512r1 was never implemented, and the card **fails closed**
        // with `0x6A80` rather than accepting an attribute it will not honour
        // (`vendor/opcard/src/command/data.rs:1180-1183`). This is the
        // hardware-verified refusal the workspace's AGENTS.md records, so it
        // is the `0x6A80` case here rather than a synthetic one — and it is
        // exactly the "wrong-but-plausible code" the US-182 rationale is
        // about: `0x6A88` would read as "that reference does not exist"
        // instead of "that parameter is not acceptable".
        // The `C1` DO is behind the **admin** permission, so PW3 has to be
        // verified first or the applet answers `0x6982` from the permission
        // gate and never reaches the algorithm check
        // (`vendor/opcard/src/command/data.rs:868-872`). The default PW3 is
        // "12345678", the C reference firmware's value.
        check(
            "VERIFY the default PW3",
            &[0x00, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38],
            0x9000,
            &mut d,
            &mut resp,
            &mut failures,
        );
        let mut attr = vec![0x13u8]; // ECDSA
        attr.extend_from_slice(&[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D]);
        let mut put = vec![0x00, 0xDA, 0x00, 0xC1, attr.len() as u8];
        put.extend_from_slice(&attr);
        check(
            "PUT DATA of an unservable algorithm attribute",
            &put,
            0x6A80,
            &mut d,
            &mut resp,
            &mut failures,
        );

        // 6985 — CHANGE REFERENCE DATA with P1 0x01, the on-card PIN-pad
        // verification mode. opcard answers `ConditionsOfUseNotSatisfied`
        // rather than "not supported" precisely so a host can tell the two
        // apart (US-936 / OQ-3, `vendor/opcard/src/command.rs:139-141`). It is
        // the one word in this applet's universe that says "implemented, but
        // you must be here" — and the INS that carries it is `0x21`/`0x24`,
        // **not** `0x20` VERIFY, whose `VerifyMode::try_from(p1)` rejects 0x01
        // first and answers `0x6A86`.
        check(
            "CHANGE REFERENCE with the on-card PIN-pad mode",
            &[0x00, 0x24, 0x01, 0x83],
            0x6985,
            &mut d,
            &mut resp,
            &mut failures,
        );

        // 6A86 — VERIFY with a P1 the `VerifyMode` table does not define, which
        // is the *other* half of the case above and a genuinely different
        // answer to a P1 of 1.
        check(
            "VERIFY with an undefined P1",
            &[0x00, 0x20, 0x07, 0x82],
            0x6A86,
            &mut d,
            &mut resp,
            &mut failures,
        );

        // And the permission gate itself, which is the `0x6982` a client hits
        // when it PUTs an attribute before verifying PW3. Worth a case in its
        // own right: it is the same value as "you are not verified for this
        // command" and a different one from "this parameter is not
        // acceptable", which is exactly the wrong-but-plausible confusion the
        // US-182 rationale is about.
        check(
            "GET DATA of an admin-gated DO unverified",
            &[0x00, 0xCA, 0x00, 0xC1],
            0x9000,
            &mut d,
            &mut resp,
            &mut failures,
        );

        // 6A88 — GET DATA of a DO that does not exist. **Not** `0x6A82`, and
        // that is worth pinning: opcard's tag tables are `TryFrom<u16>` with
        // a `Status::KeyReferenceNotFound` default
        // (`vendor/opcard/src/command/data.rs:46`), and `0x6A88` is
        // "key reference not found" while `0x6A82` is "file or application
        // not found". A card that answered `0x6A82` here would tell a client
        // its applet had gone away.
        check(
            "GET DATA of an absent DO",
            &[0x00, 0xCA, 0x7F, 0x7E],
            0x6A88,
            &mut d,
            &mut resp,
            &mut failures,
        );

        // 6A86 — PSO with a (P1, P2) pair that is not one of the three opcard
        // accepts (`vendor/opcard/src/command.rs:165-171`). The `0x80 0x86`
        // (decipher) and `0x86 0x80` (encipher) pairs are the ones a client
        // actually sends, so this refusal is what a typo'd P1P2 produces.
        check(
            "PSO with an undefined P1P2 pair",
            &[0x00, 0x2A, 0x11, 0x22],
            0x6A86,
            &mut d,
            &mut resp,
            &mut failures,
        );

        // 6D00 — an INS opcard does not implement. This is the EPIC's own
        // example of a code a user would be misled by, so it is pinned here
        // next to the `6A86` that must *not* be answered instead.
        check(
            "an unimplemented INS",
            &[0x00, 0xEE, 0x00, 0x00],
            0x6D00,
            &mut d,
            &mut resp,
            &mut failures,
        );

        // 6A82 — the dispatcher's own answer, for an unregistered AID. Not the
        // applet: the OpenPGP applet is selected at this point and answers
        // nothing itself, which is the same `Layer::Dispatcher` fact the other
        // six tables record. And it is the *only* place `0x6A82` appears in
        // this applet's universe — opcard's own absent-DO answer is `0x6A88`,
        // two rows above.
        check(
            "SELECT of an unregistered AID",
            &SELECT_UNKNOWN_AID,
            0x6A82,
            &mut d,
            &mut resp,
            &mut failures,
        );

        // 63Cx — VERIFY with a wrong PW1 spends an attempt, and the status
        // word carries the remaining count. **Last**, deliberately: a failed
        // VERIFY clears the card's verified state
        // (`vendor/opcard/src/command/verify.rs`), and the `0x6A80` case above
        // is behind that state. It is asserted as the *family* member the card
        // is documented to answer rather than as a fixed number, because the
        // low nibble is the retry count and a table row of "0x63C0" would be
        // wrong for every attempt after the first.
        d.dispatch(&ext(0x00, 0x20, 0x00, 0x82, b"000000"), &mut resp);
        match sw_of(&resp) {
            Some(sw) => assert_eq!(
                sw & 0xFFF0,
                0x63C0,
                "a wrong PW1 must answer 63Cx (retries remaining), got {sw:04x}"
            ),
            None => failures.push("a wrong PW1 produced no status word".into()),
        }

        assert!(
            failures.is_empty(),
            "openpgp reachability ({} disagreed):\n{}",
            failures.len(),
            failures.join("\n")
        );
    });
}

/// The permitted set is the enum, stated once and checked once.
///
/// This test exists so [`OPENPGP_PERMITTED`] is not a string nothing reads. It
/// asserts the two halves that make the sentence true: a value the enum
/// defines decodes to a variant, and `Status::from_u16` is total over the
/// 16-bit range (every input produces *some* `Status`), which is why "not
/// `__Unknown`" is a decidable predicate rather than a hope.
#[test]
fn the_permitted_set_is_the_enum() {
    assert!(matches!(Status::from_u16(0x9000), Status::Success));
    assert!(matches!(Status::from_u16(0x6A82), Status::NotFound));
    assert!(matches!(Status::from_u16(0x6A86), Status::IncorrectP1OrP2Parameter));
    assert!(matches!(Status::from_u16(0x63C2), Status::RemainingRetries(2)));
    assert!(matches!(Status::from_u16(0x6100), Status::MoreAvailable(0)));
    assert!(matches!(Status::from_u16(0x6A80), Status::IncorrectDataParameter));
    assert!(matches!(Status::from_u16(0x6D00), Status::InstructionNotSupportedOrInvalid));
    // And the boundary: a value in none of the documented ranges falls through
    // to `__Unknown`, which is what makes the check above a real filter rather
    // than a tautology. `0x0000` is in no range and no named arm.
    assert!(matches!(Status::from_u16(0x0000), Status::__Unknown(0x0000)));
    assert!(matches!(Status::from_u16(0x6A01), Status::__Unknown(0x6A01)));
}
