//! US-153 (PICOForge-COMPAT): GENERATE, and the same-session VERIFY it depends
//! on. The reference client's `openpgp_generate`
//! (`picoforge/src/hal/io.rs:846-856`) opens a session, VERIFYs PW3 on it,
//! PUTs the slot's algorithm attribute, and issues GENERATE on that same
//! session — and states in three places (`transport/ccid.rs:1-8`,
//! `hal/io.rs:789-799`, `applets/openpgp.rs:9-10`) that it depends on SELECT
//! resetting the security status to keep the two together.
//!
//! Four things here are not visible from the client's side, and each is a way
//! the pairing can silently rot:
//!
//! 1. **The GENERATE APDU framing is a non-issue.** The client encodes
//!    `Apdu::read(0x00, 0x47, 0x80, 0x00, &[crt, 0x00])` as
//!    `00 47 80 00 02 <crt> 00 00` — short Lc *and* a trailing `Le` of 0, i.e.
//!    neither a clean case 3 nor a clean case 2. The OATH/OTP applets
//!    hand-roll their parsers and US-132 had to fix exactly that shape in
//!    them; the OpenPGP app runs the `iso7816` crate, whose
//!    `CommandView::try_from` accepts any body of `len >= 4` and splits the
//!    short-length field itself
//!    (`iso7816-0.2.0/src/command.rs:528-556`; the `len < 4` floor is at
//!    `:531`). Pinned here from both ends
//!    so a future switch to a hand-rolled parser cannot regress it silently.
//! 2. **Two gates, not one.** `vendor/opcard/src/command.rs:497-506` refuses
//!    GENERATE with `6985` while `factory_defaults_in_force()` — that is
//!    `pw1_changed != Some(true) || pw3_changed != Some(true)`
//!    (`state.rs:1349-1351`) — so **both** PW1 and PW3 must be moved off the
//!    shipped defaults, not just the admin PIN the client verifies. Changing
//!    only PW3 leaves GENERATE at `6985`; a client that prompts for the
//!    admin PIN alone can never reach a key. The second gate
//!    (`admin_verified()`, `state.rs:1948-1950`) is the `6982` the client
//!    *expects* from its own session discipline.
//! 3. **The `7F49` reply is a two-byte tag** (`7F 49`, not `7F49` as a
//!    shorthand), whose value is a single `86` MPI — 2-byte bit length then
//!    `ceil(bits/8)` bytes. The client's only caller discards the body
//!    (`io.rs:852` `.map(|_| ())`), so a malformed-but-`9000` reply is
//!    invisible to it and would only surface as a broken key in whatever
//!    imports next. `public_key_mpi` below is the strict parse.
//! 4. **SELECT does NOT clear the security status here** — the opposite of
//!    what the client documents. `select()`
//!    (`vendor/opcard/src/command.rs:346-361`) clears `cur_do` and `keyrefs`
//!    and never touches `volatile.user` / `volatile.admin`, so the PW3 latch
//!    outlives a re-SELECT of the same AID. It is cleared by
//!    `Card::reset()`, which the dispatcher reaches through
//!    `App::deselect` — and the dispatcher calls `deselect()` on the
//!    *previous* app only when a **different** app is selected
//!    (`platform/src/dispatch.rs:163-170`); the same-app path
//!    (`:161-163`) re-selects without it. Both halves are pinned below
//!    because "more permissive than the client needs" is still a posture
//!    the client is not entitled to assume, and the boundary is invisible
//!    from a passing test.
//!
//! Pagination is pinned too: the client reaches the reply through
//! `transceive_full` (`transport/ccid.rs:77`), which loops GET RESPONSE on
//! `61xx`. A card that answered `9000` with a short body, or `6100` with a
//! count that did not match what was left, would break the session even
//! though the key is fine.

use fapico2_openpgp::OpenPgpApp;
use fapico2_platform::dispatch::{App, Dispatcher, MAX_RESPONSE, Sw, SW_OK};
use heapless::Vec as HeaplessVec;
use std::sync::atomic::{AtomicUsize, Ordering};

/// SELECT AID (short Lc, no Le) — every GENERATE below needs the app selected
/// first, because the dispatcher answers `6A82` to anything else.
fn select_openpgp() -> Vec<u8> {
    let mut apdu = vec![0x00u8, 0xA4, 0x04, 0x00, 0x06];
    apdu.extend_from_slice(fapico2_openpgp::OPENPGP_AID);
    apdu
}

fn apdu(dispatcher: &mut Dispatcher<2>, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(apdu, &mut resp);
    assert!(resp.len() >= 2, "response too short for {:x?}", apdu);
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    (resp[..resp.len() - 2].to_vec(), sw)
}

/// One APDU plus the GET RESPONSE (INS C0) chain the client's
/// `transceive_full` walks. `6100` is normalised to the exact remaining
/// count so a card that answered `6100` regardless of what it had left would
/// be caught rather than followed.
fn apdu_read(dispatcher: &mut Dispatcher<2>, first: &[u8]) -> (Vec<u8>, u16) {
    let (mut body, mut sw) = apdu(dispatcher, first);
    while sw & 0xFF00 == 0x6100 {
        let (chunk, next) = apdu(dispatcher, &[0x00, 0xC0, 0x00, 0x00, (sw & 0xFF) as u8]);
        assert!(
            next & 0xFF00 != 0x6100 || (next & 0xFF) != 0,
            "GET RESPONSE re-announced 6100 with nothing left"
        );
        body.extend_from_slice(&chunk);
        sw = next;
    }
    (body, sw)
}

/// The client's GENERATE, byte for byte: `Apdu::read(CLA_ISO, 0x47, 0x80,
/// 0x00, &[crt, 0x00])` (`picoforge/src/hal/applets/openpgp.rs:426-432`)
/// encoded by `Apdu::encode` — short Lc `02`, the CRT, the specification
/// control byte `00`, and the trailing short Le `00`. Spelled out rather than
/// assembled so the test fails on a change to the *framing*, not only to the
/// opcode.
fn generate_apdu(crt: u8) -> [u8; 8] {
    [0x00, 0x47, 0x80, 0x00, 0x02, crt, 0x00, 0x00]
}

const CRT_SIGN: u8 = 0xB6;
const CRT_DEC: u8 = 0xB8;
const CRT_AUT: u8 = 0xA4;

/// The client's per-slot EC substitution (`ec(..)` in
/// `picoforge/src/hal/applets/openpgp.rs`): ECDSA on the signature and
/// authentication slots, ECDH on the decryption slot. Only P-256 is used
/// here — the full attribute/curve matrix belongs to `picoforge_algo.rs`,
/// and repeating it here would let one of the two files drift.
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const ALGO_ECDSA: u8 = 0x13;
const ALGO_ECDH: u8 = 0x12;

fn ec_attr(on_dec_slot: bool) -> Vec<u8> {
    let mut v = vec![if on_dec_slot { ALGO_ECDH } else { ALGO_ECDSA }];
    v.extend_from_slice(OID_P256);
    v
}

/// CHANGE REFERENCE DATA (INS 24) for PW1 (`0x81`) or PW3 (`0x83`), in the
/// client's `old ‖ new` form (`openpgp.rs:340-356`). Unverified, so the card
/// applies its `2 * min_len` rule and needs both halves.
fn change_pin(dispatcher: &mut Dispatcher<2>, reference: u8, old: &str, new: &str) -> u16 {
    let mut body = old.as_bytes().to_vec();
    body.extend_from_slice(new.as_bytes());
    let mut cmd = vec![0x00u8, 0x24, 0x00, reference, body.len() as u8];
    cmd.extend_from_slice(&body);
    apdu(dispatcher, &cmd).1
}

fn verify(dispatcher: &mut Dispatcher<2>, p1: u8, reference: u8, pin: &str) -> u16 {
    let mut cmd = vec![0x00u8, 0x20, p1, reference, pin.len() as u8];
    cmd.extend_from_slice(pin.as_bytes());
    apdu(dispatcher, &cmd).1
}

/// PUT DATA (INS DA) for a `C1`/`C2`/`C3` algorithm attribute — admin-gated,
/// so it answers `6982` until PW3 has been verified in the session. The
/// client does this on the same session as the GENERATE.
fn put_attr(dispatcher: &mut Dispatcher<2>, tag: u8, attr: &[u8]) -> u16 {
    let mut cmd = vec![0x00u8, 0xDA, 0x00, tag, attr.len() as u8];
    cmd.extend_from_slice(attr);
    apdu(dispatcher, &cmd).1
}

/// Move both PINs off the factory defaults and verify the new PW3. This is
/// the whole of what stands between a factory card and a GENERATE; the
/// client's UI exposes PW1 and PW3 as two separate actions
/// (`picoforge/src/hal/io.rs:806,810`), so a user who only changes the
/// admin PIN is left at `6985` with no diagnostic.
fn lift_factory_gate_and_verify(dispatcher: &mut Dispatcher<2>) {
    assert_eq!(change_pin(dispatcher, 0x81, "123456", NEW_PW1), SW_OK, "change PW1");
    assert_eq!(change_pin(dispatcher, 0x83, "12345678", NEW_PW3), SW_OK, "change PW3");
    assert_eq!(verify(dispatcher, 0x00, 0x83, NEW_PW3), SW_OK, "VERIFY PW3");
}

const NEW_PW1: &str = "246813";
const NEW_PW3: &str = "86429753";

/// Strict `7F49` parse: returns the single `86` MPI payload. Both lengths are
/// *declared* lengths that must account for the whole rest of the message —
/// not searched-for, not assumed. A card that emitted a short MPI under a
/// longer declared length would still answer `9000`, and the client's only
/// caller throws the body away (`io.rs:852`), so the defect would surface
/// one key import later.
///
/// The MPI payload is the curve's own serialization, so its size and first
/// byte are curve-dependent and deliberately *not* asserted here: with no
/// attribute written the card's default signature algorithm is Ed25519 and
/// the MPI is a bare 32-octet point, while a NIST curve gets opcard's SEC1
/// `0x04` prefix (`command/gen.rs:352-360` against `:362-368`). The
/// curve-to-size mapping belongs to `picoforge_algo.rs`; what is pinned here
/// is that the envelope is exact and the payload is non-empty.
fn public_key_mpi(body: &[u8]) -> Vec<u8> {
    assert!(
        body.len() >= 5,
        "GENERATE reply is too short to be a 7F49: {:02x?}",
        body
    );
    assert_eq!(&body[..2], &[0x7F, 0x49], "reply is not a 7F49: {:02x?}", body);
    let declared = body[2] as usize;
    assert_eq!(
        3 + declared,
        body.len(),
        "7F49 declares {} bytes but the body carries {}: {:02x?}",
        declared,
        body.len().saturating_sub(3),
        body
    );
    // The 7F49 value is a single 86 MPI, so its declared length must close
    // over the value exactly — anything left over would be an unwrapped
    // sibling the client would silently drop.
    let value = &body[3..];
    assert_eq!(value[0], 0x86, "7F49 does not open with an 86 MPI: {:02x?}", value);
    let mpi_len = value[1] as usize;
    assert_eq!(
        2 + mpi_len,
        value.len(),
        "86 MPI declares {} bytes but carries {}: {:02x?}",
        mpi_len,
        value.len().saturating_sub(2),
        value
    );
    assert!(mpi_len > 0, "7F49 carries a zero-length MPI");
    value[2..].to_vec()
}

/// The SEC1 form opcard emits for a NIST curve: the uncompressed marker plus
/// the raw x‖y the trussed serializer hands back (`gen.rs:356-359`).
/// Asserted only where the test wrote a P-256 attribute, so it cannot be
/// confused with the Ed25519 default.
fn assert_uncompressed_p256(point: &[u8], context: &str) {
    assert_eq!(
        point.len(),
        65,
        "{}: a P-256 SEC1 point is 0x04 || x || y, got {} octets: {:02x?}",
        context,
        point.len(),
        point
    );
    assert_eq!(point[0], 0x04, "{}: not an uncompressed point", context);
}

struct OtherApp {
    aid: &'static [u8],
    deselects: &'static AtomicUsize,
}

impl App for OtherApp {
    fn aid(&self) -> &[u8] {
        self.aid
    }
    fn select(&mut self, _internal: bool) -> Sw {
        SW_OK
    }
    fn deselect(&mut self) {
        self.deselects.fetch_add(1, Ordering::SeqCst);
    }
    fn process(&mut self, _apdu: &[u8], _resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {}
}

/// A stand-in for the second applet on the bus (the OATH AID). It only needs
/// to be selectable: the point of the test is what the dispatcher does to
/// the *previous* app on the way past it, which is `deselect()`.
const OTHER_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

/// Boot a card with a second registered app and run `body`. The second
/// argument counts how many times that other app was `deselect`ed, which is
/// the observable form of "the dispatcher tore the previous app down" — the
/// call the OpenPGP app's own `deselect` sits behind, and the only thing
/// that clears its security status. Each test gets its own client so a
/// card-shaped change in one (retry counters move, keys land) cannot leak
/// into another.
fn on_fresh_card(client_id: &str, body: impl FnOnce(&mut Dispatcher<2>, &AtomicUsize)) {
    opcard::virt::with_ram_client(client_id, |client| {
        let mut app = OpenPgpApp::new(client);
        // Leaked so the stub can hold the counter for `'static`; eight bytes
        // per test, and a per-test counter is what keeps parallel test
        // threads from reading each other's deselect counts.
        let deselects: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
        let mut other = OtherApp {
            aid: OTHER_AID,
            deselects,
        };
        let mut dispatcher: Dispatcher<2> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        assert!(dispatcher.register(&mut other), "register second app");
        let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
        assert_eq!(sw, SW_OK, "SELECT AID must answer 9000");
        body(&mut dispatcher, deselects);
    });
}

fn on_fresh_card_named(suffix: &str, body: impl FnOnce(&mut Dispatcher<2>, &AtomicUsize)) {
    on_fresh_card(&format!("us153-{}-{}", suffix, std::process::id()), body)
}

/// The three CRTs the client can name, each paired with the attribute tag it
/// PUTs first. `0xB6` sign, `0xB8` decryption, `0xA4` authentication
/// (`openpgp.rs:426-432`).
#[test]
fn client_generate_apdus_are_accepted_and_well_formed() {
    on_fresh_card_named("framing", |d, _peer| {
        assert_eq!(change_pin(d, 0x81, "123456", NEW_PW1), SW_OK);
        assert_eq!(change_pin(d, 0x83, "12345678", NEW_PW3), SW_OK);
        assert_eq!(verify(d, 0x00, 0x83, NEW_PW3), SW_OK);

        for (crt, tag, on_dec) in [
            (CRT_SIGN, 0xC1u8, false),
            (CRT_DEC, 0xC2, true),
            (CRT_AUT, 0xC3, false),
        ] {
            assert_eq!(
                put_attr(d, tag, &ec_attr(on_dec)),
                SW_OK,
                "PUT DATA {:02X} must be admin-gated-clean on a verified session",
                tag
            );
            let (body, sw) = apdu_read(d, &generate_apdu(crt));
            assert_eq!(sw, SW_OK, "GENERATE {:02X} must answer 9000, got {:02x?}", crt, body);
            let point = public_key_mpi(&body);
            assert_uncompressed_p256(&point, &format!("CRT {:02X}", crt));
        }

        // The framing is load-bearing: the same command without the
        // specification control byte is a different APDU. If the parser ever
        // tightens to a strict case 2/case 3 split, this is the shape that
        // must keep working.
        let (body, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(sw, SW_OK);
        assert_eq!(
            body.len(),
            70,
            "7F 49 | 43 | 86 | 41 | 0x04 + 64 octets of x||y is 70 bytes, got {}",
            body.len()
        );
    });
}

/// The reply must survive the `61xx`/GET RESPONSE chain `transceive_full`
/// walks, with the announced remaining count matching what is actually left.
/// A card that answered `6100` for "some more" would make the client re-ask
/// forever or truncate the key.
#[test]
fn the_generate_reply_pages_over_61xx_without_loss() {
    on_fresh_card_named("pages", |d, _peer| {
        lift_factory_gate_and_verify(d);
        // P-256 so the two calls below produce the same *shape*; the content
        // differs (each GENERATE mints a new key) and only the envelope is
        // comparable across them.
        assert_eq!(put_attr(d, 0xC1, &ec_attr(false)), SW_OK);
        let (whole, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(sw, SW_OK);
        let whole_len = whole.len();

        // Short Le: the card must answer the page and the exact remainder.
        let (first, sw) = apdu(d, &[0x00, 0x47, 0x80, 0x00, 0x02, CRT_SIGN, 0x00, 0x10]);
        assert_eq!(sw & 0xFF00, 0x6100, "short Le must page, got {:04X}", sw);
        let outstanding = (sw & 0xFF) as usize;
        assert_eq!(
            outstanding,
            whole_len - 16,
            "6100 announced {} bytes, the reply has {} outstanding after 16",
            outstanding,
            whole_len - 16
        );
        let (rest, sw) = apdu(d, &[0x00, 0xC0, 0x00, 0x00, outstanding as u8]);
        assert_eq!(sw, SW_OK, "the final GET RESPONSE must answer 9000, got {:04X}", sw);
        assert_eq!(rest.len(), outstanding, "the last page is short");

        let mut joined = first;
        joined.extend_from_slice(&rest);
        assert_eq!(joined.len(), whole_len, "paged reply is a different length");
        // The public key must be byte-identical to the unpaged one: the page
        // boundary is a transport artefact, not a different key.
        // The page boundary is a transport artefact: the reassembled body
        // must parse as the same whole point the unpaged call produced. A
        // card that counted the page break into the declared length would
        // still answer 9000 on both calls.
        assert_uncompressed_p256(&public_key_mpi(&joined), "reassembled");
        assert_uncompressed_p256(&public_key_mpi(&whole), "unpaged");
    });
}

/// `6985` is the load-bearing precondition the client never mentions: the
/// card refuses key generation while the *factory* PINs are in force, and
/// "in force" is the OR of two flags, not an AND. `6985` — not `6982` — is
/// what a factory card answers even with PW3 verified, because the gate is
/// checked first.
#[test]
fn generate_is_refused_while_the_factory_pins_are_in_force() {
    on_fresh_card_named("factory", |d, _peer| {
        // The client verifies the *factory* admin PIN on its own session, so
        // the latch is set; the gate still refuses.
        assert_eq!(verify(d, 0x00, 0x83, "12345678"), SW_OK);
        let (body, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(
            sw, 0x6985,
            "factory PINs in force must answer 6985, got {:04X} {:02x?}",
            sw, body
        );
        assert!(body.is_empty(), "6985 carries no data");

        // Reading the public key back is public and stays available — the
        // gate sits after the CRT-read branch (`command.rs:490-496`), so a
        // client can inspect an existing key on a factory card but not make
        // a new one.
        let (body, sw) = apdu_read(d, &[0x00, 0x47, 0x80, 0x00, 0x02, CRT_SIGN, 0x00]);
        assert_eq!(
            sw, 0x6985,
            "an unset slot has no public key to read back either: {:04X} {:02x?}",
            sw, body
        );
    });
}

/// Both flags, not one. This is the failure mode the client's UI invites: it
/// prompts for the admin PIN on the GENERATE path, so a user who changes
/// only PW3 — the one the client asks for — never sees the gate lift.
#[test]
fn the_gate_needs_both_pins_moved_not_just_the_admin_pin() {
    on_fresh_card_named("pw3only", |d, _peer| {
        assert_eq!(change_pin(d, 0x83, "12345678", NEW_PW3), SW_OK);
        assert_eq!(verify(d, 0x00, 0x83, NEW_PW3), SW_OK);
        let (_, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(
            sw, 0x6985,
            "PW3 alone does not lift the factory gate: {:04X}",
            sw
        );

        // PW1 is the missing half; moving it lifts the gate without any
        // further admin action, because the PW3 latch was never dropped.
        assert_eq!(change_pin(d, 0x81, "123456", NEW_PW1), SW_OK);
        let (body, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(sw, SW_OK, "both PINs moved: {:04X} {:02x?}", sw, body);
        public_key_mpi(&body);
    });

    on_fresh_card_named("pw1only", |d, _peer| {
        assert_eq!(change_pin(d, 0x81, "123456", NEW_PW1), SW_OK);
        assert_eq!(verify(d, 0x00, 0x83, "12345678"), SW_OK);
        let (_, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(
            sw, 0x6985,
            "PW1 alone does not lift the factory gate: {:04X}",
            sw
        );
    });
}

/// The gate the client *does* model. With the factory gate lifted but no
/// VERIFY in the session, GENERATE answers `6982` — the status the client's
/// "VERIFY and the operation run on the same session" comment is actually
/// about. Ordering matters too: the `6985` check runs first, so an
/// unverified factory card cannot be told apart from an unverified
/// personalised one by this status alone.
#[test]
fn generate_requires_pw3_verified_in_the_same_session() {
    on_fresh_card_named("unverified", |d, _peer| {
        assert_eq!(change_pin(d, 0x81, "123456", NEW_PW1), SW_OK);
        assert_eq!(change_pin(d, 0x83, "12345678", NEW_PW3), SW_OK);

        let (body, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(
            sw, 0x6982,
            "both PINs moved but PW3 unverified must answer 6982, got {:04X} {:02x?}",
            sw, body
        );

        // A wrong admin PIN does not open it either, and burns a retry.
        assert_ne!(verify(d, 0x00, 0x83, "00000000"), SW_OK);
        let (_, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(sw, 0x6982, "a failed VERIFY does not latch: {:04X}", sw);

        // Verifying PW1 instead is not a substitute: PW1 sign and PW1 other
        // are separate latches, and neither is the admin one.
        assert_eq!(verify(d, 0x00, 0x81, NEW_PW1), SW_OK);
        let (_, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(sw, 0x6982, "PW1 does not authorise GENERATE: {:04X}", sw);

        assert_eq!(verify(d, 0x00, 0x83, NEW_PW3), SW_OK);
        let (body, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(sw, SW_OK, "PW3 verified: {:04X} {:02x?}", sw, body);
        public_key_mpi(&body);
    });
}

/// The security-posture half of the story. A host-issued re-SELECT of the
/// same AID does **not** drop the PW3 latch, because `select()`
/// (`vendor/opcard/src/command.rs:346-361`) only clears `cur_do` and
/// `keyrefs` and the dispatcher takes the same-app branch
/// (`platform/src/dispatch.rs:163-165`) which never calls `deselect()`.
///
/// The client relies on the opposite (`transport/ccid.rs:1-8`,
/// `hal/io.rs:789-799`), so every admin-gated op it pairs with a VERIFY is
/// safe here only by being *more* restrictive about nothing — the latch
/// outlives the boundary the client believes is there. Pinned because the
/// `Dispatcher` doc comment ("Host-issued SELECT resets the app's security
/// state (internal=0)", `dispatch.rs:7`) promises the client's behaviour and
/// the OpenPGP app silently does not deliver it.
#[test]
fn the_pw3_latch_survives_a_reselect_of_the_same_aid() {
    on_fresh_card_named("reselect", |d, peer| {
        lift_factory_gate_and_verify(d);
        let (before, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(sw, SW_OK);

        let (fci, sw) = apdu(d, &select_openpgp());
        assert_eq!(sw, SW_OK, "re-SELECT must answer 9000");
        assert!(
            !fci.is_empty(),
            "re-SELECT must return the synthesized FCI, not just a status word"
        );

        let (after, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(
            sw, SW_OK,
            "the PW3 latch must survive a re-SELECT of the same AID: {:04X}",
            sw
        );
        public_key_mpi(&after);
        // Different keys each time — proof the first GENERATE really ran and
        // this is not a replayed buffer.
        assert_ne!(
            public_key_mpi(&before),
            public_key_mpi(&after),
            "GENERATE must mint a fresh key each call"
        );

        // Three more times: the latch is not a one-shot that decays. There is
        // no counter on it and no timer.
        for round in 0..3 {
            assert_eq!(apdu(d, &select_openpgp()).1, SW_OK);
            let (_, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
            assert_eq!(sw, SW_OK, "round {} lost the latch: {:04X}", round, sw);
        }

        // The same-app branch never tears anything down: the peer is still
        // unselected and has been deselected zero times. This is the
        // dispatcher-level fact the latch result above depends on — if the
        // same-app path ever grew a `deselect()`, the peer count would move
        // here first and the GENERATE assertion would start failing.
        assert_eq!(
            peer.load(Ordering::SeqCst),
            0,
            "a same-app re-SELECT must not deselect anything"
        );
    });
}

/// The other half. Selecting a *different* applet does clear the latch,
/// because the dispatcher calls `deselect()` on the app it is leaving
/// (`platform/src/dispatch.rs:168-170`) and `OpenPgpApp::deselect` is a
/// `Card::reset()` (`apps/openpgp/src/device_shell.rs:614-619`), which
/// drops `volatile.user` / `volatile.admin`
/// (`vendor/opcard/src/card.rs:273-292`).
///
/// So the boundary is not SELECT at all — it is *applet switching*. The
/// observable consequence: a VERIFY'd session is good for the lifetime of
/// the applet selection, and the only host-side action that ends it is
/// selecting something else (or a card reset). That is far weaker than the
/// per-SELECT discipline the client documents, and it is the half of the
/// story a reader is most likely to get backwards.
#[test]
fn the_pw3_latch_is_cleared_by_an_applet_switch() {
    on_fresh_card_named("switch", |d, peer| {
        lift_factory_gate_and_verify(d);
        assert_eq!(apdu_read(d, &generate_apdu(CRT_SIGN)).1, SW_OK);

        // A SELECT of an unregistered AID is `6A82` and, per US-211, leaves
        // the current selection *and its security status* untouched — a
        // failed SELECT must not be mistaken for a reset.
        let (_, sw) = apdu(d, &{
            let mut a = vec![0x00u8, 0xA4, 0x04, 0x00, 0x02];
            a.extend_from_slice(&[0xDE, 0xAD]);
            a
        });
        assert_eq!(sw, 0x6A82, "an unknown AID must answer 6A82, got {:04X}", sw);
        assert_eq!(
            apdu_read(d, &generate_apdu(CRT_SIGN)).1,
            SW_OK,
            "a failed SELECT must not drop the latch"
        );

        // Away to the other applet, and back.
        let (_, sw) = apdu(d, &{
            let mut a = vec![0x00u8, 0xA4, 0x04, 0x00, OTHER_AID.len() as u8];
            a.extend_from_slice(OTHER_AID);
            a
        });
        assert_eq!(sw, SW_OK, "SELECT of the other applet must answer 9000");
        assert_eq!(
            peer.load(Ordering::SeqCst),
            0,
            "selecting an app that was not current deselects nothing"
        );
        let (_, sw) = apdu(d, &select_openpgp());
        assert_eq!(sw, SW_OK, "SELECT back must answer 9000");
        assert_eq!(
            peer.load(Ordering::SeqCst),
            1,
            "switching away must deselect the app being left, once"
        );

        let (body, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(
            sw, 0x6982,
            "an applet switch must drop the PW3 latch: {:04X} {:02x?}",
            sw, body
        );

        // Re-verifying restores it, and the pin is the *new* one — the
        // factory admin PIN must no longer work, which is what makes this a
        // security boundary rather than a bookkeeping one.
        assert_ne!(verify(d, 0x00, 0x83, "12345678"), SW_OK);
        assert_eq!(verify(d, 0x00, 0x83, NEW_PW3), SW_OK);
        let (body, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(sw, SW_OK, "re-VERIFY restores the latch: {:04X}", sw);
        public_key_mpi(&body);
    });
}

/// The third way out, and the only one a host can invoke without leaving the
/// applet: VERIFY with P1 = 0xFF and no data
/// (`vendor/opcard/src/command.rs:396-403`) clears the admin latch in place.
#[test]
fn the_pw3_latch_is_cleared_by_an_explicit_verify_reset() {
    on_fresh_card_named("reset", |d, _peer| {
        lift_factory_gate_and_verify(d);
        assert_eq!(apdu_read(d, &generate_apdu(CRT_SIGN)).1, SW_OK);

        let (body, sw) = apdu(d, &[0x00, 0x20, 0xFF, 0x83, 0x00]);
        assert_eq!(sw, SW_OK, "VERIFY reset must answer 9000, got {:04X}", sw);
        assert!(body.is_empty(), "VERIFY reset carries no data");

        let (_, sw) = apdu_read(d, &generate_apdu(CRT_SIGN));
        assert_eq!(sw, 0x6982, "the latch must be gone after VERIFY reset: {:04X}", sw);

        // A zero-length VERIFY with P1 = 0x00 is a *check*, not a reset, and
        // a still-latched card answers 9000 without any PIN — which is how a
        // client probes its own session state. Once reset, the same probe
        // reports the failure instead.
        assert_ne!(verify(d, 0x00, 0x83, ""), SW_OK);
        assert_eq!(verify(d, 0x00, 0x83, NEW_PW3), SW_OK);
        assert_eq!(
            verify(d, 0x00, 0x83, ""),
            SW_OK,
            "an empty VERIFY is a status check once the latch is set"
        );
    });
}
