//! PICOForge-COMPAT: the key-state data objects the reference client reads
//! out of the `73` (Discretionary Data Objects) sub-template of `0x6E`
//! (`picoforge/src/hal/applets/openpgp.rs:258-287`) — `0xC4` PW status,
//! `0xC5` fingerprints, `0xDE` key information, and the per-slot
//! `0xC1`-`0xC3` / `0xD6`-`0xD8` attribute and touch DOs.
//!
//! The client does not read these as a spec reader would. It reads fixed
//! offsets out of fixed-length blobs, and its presence rule for a slot is an
//! **OR** over two independent sources:
//!
//! ```text
//! present = fps.get(i*20 .. i*20+20).iter().any(|b| *b != 0)
//!          || key_info.get(i*2+1) != 0
//! ```
//!
//! Both halves matter, and neither is sufficient on its own. gpg's
//! `store_fpr` writes the per-slot `0xC7`/`0xC8`/`0xC9`, not the composite
//! `0xC5`; GENERATE and key import set `0xDE`'s status byte but leave the
//! fingerprint zero until the host writes it
//! (`vendor/opcard/src/command/gen.rs:193` — `set_key` carries the origin
//! only). A client or a card that treated either source as authoritative
//! would misreport the other's state. These tests pin the wire bytes, the
//! slot order, and both halves of the OR, so that either regression is a
//! visible failure rather than a silently wrong key list.

use fapico2_openpgp::OpenPgpApp;
use fapico2_platform::dispatch::{Dispatcher, MAX_RESPONSE, SW_OK};
use heapless::Vec as HeaplessVec;

/// SELECT AID for the OpenPGP app (short Lc, no Le) — GET DATA needs the app
/// selected before the dispatcher routes to it.
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

/// One APDU through the dispatcher; returns (body, SW).
fn apdu(dispatcher: &mut Dispatcher<1>, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(apdu, &mut resp);
    assert!(resp.len() >= 2, "response too short for {:x?}", apdu);
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    (resp[..resp.len() - 2].to_vec(), sw)
}

/// One APDU plus GET RESPONSE (INS C0) continuation while the card reports
/// `61XX` — the `0x6E` reply is far longer than one Le.
fn apdu_read(dispatcher: &mut Dispatcher<1>, first: &[u8]) -> (Vec<u8>, u16) {
    let (mut body, mut sw) = apdu(dispatcher, first);
    while sw & 0xFF00 == 0x6100 {
        let le = (sw & 0xFF) as u8;
        let (chunk, next) = apdu(dispatcher, &[0x00, 0xC0, 0x00, 0x00, le]);
        body.extend_from_slice(&chunk);
        sw = next;
    }
    (body, sw)
}

/// GET DATA (INS CA) for a one-byte tag. The tag belongs in P1-P2 per spec
/// §7.1, so `0x00 0xCA 0x00 0xC4 0x00` — never `0xCA 0x00 0xC4 0x00`, which is
/// a malformed case-3 APDU the card answers `6D00` and which reads like a
/// missing DO rather than a framing mistake.
fn get_data(dispatcher: &mut Dispatcher<1>, tag: u8) -> Vec<u8> {
    let (body, sw) = apdu_read(dispatcher, &[0x00, 0xCA, 0x00, tag, 0x00]);
    assert_eq!(sw, SW_OK, "GET DATA {:02X} must answer 9000", tag);
    body
}

/// PUT DATA (INS DA) for a simple DO. Admin-authorized: the card answers
/// `6982` until PW3 has been verified in the session.
fn put_data(dispatcher: &mut Dispatcher<1>, tag: u8, data: &[u8]) {
    let mut p = vec![0x00, 0xDA, 0x00, tag, data.len() as u8];
    p.extend_from_slice(data);
    let (body, sw) = apdu(dispatcher, &p);
    assert_eq!(
        sw, SW_OK,
        "PUT DATA {:02X} must answer 9000, got {:04x} {:02x?}",
        tag, sw, body
    );
}

fn verify_pw3(dispatcher: &mut Dispatcher<1>) {
    let (_, sw) = apdu(
        dispatcher,
        &[
            0x00, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        ],
    );
    assert_eq!(sw, SW_OK, "VERIFY PW3 (factory admin PIN) must answer 9000");
}

/// `20` bytes of `seed + i` — a per-slot fingerprint fixture that no other
/// slot shares, so a wrong slot offset cannot pass by coincidence.
fn fingerprint_fixture(seed: u8) -> [u8; 20] {
    let mut fp = [0u8; 20];
    for (i, byte) in fp.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8);
    }
    fp
}

/// BER-TLV: one `(tag, value)` pair, or `None` if `tag` is absent. Strict
/// about the declared length — these DOs are read by a client that walks
/// them field-by-field, so an overrunning length is a parse failure on the
/// client even when the card answered `9000`.
fn tlv_find(body: &[u8], tag: u8) -> Option<&[u8]> {
    let mut offset = 0;
    while offset < body.len() {
        let start = offset;
        offset += 1;
        if body[start] & 0x1F == 0x1F {
            while body[offset] & 0x80 != 0 {
                offset += 1;
            }
            offset += 1;
        }
        let found = start + 1 == offset && body[start] == tag;
        let mut length = body[offset] as usize;
        offset += 1;
        if length & 0x80 != 0 {
            let width = length & 0x7F;
            length = body[offset..offset + width]
                .iter()
                .fold(0usize, |acc, &b| acc * 256 + b as usize);
            offset += width;
        }
        assert!(
            offset + length <= body.len(),
            "TLV at {} overruns the body",
            start
        );
        if found {
            return Some(&body[offset..offset + length]);
        }
        offset += length;
    }
    None
}

/// The client's presence rule for slot `slot` (0 = Sig, 1 = Dec, 2 = Aut),
/// transcribed from `picoforge/src/hal/applets/openpgp.rs:274-275`. The
/// short-circuit `||` is the whole point: it must be true when *either*
/// source says so, so both arguments are evaluated separately below.
fn client_reports_present(fingerprints: &[u8], key_info: &[u8], slot: usize) -> bool {
    let start = slot * 20;
    let fp_non_zero = fingerprints
        .get(start..start + 20)
        .map(|fp| fp.iter().any(|&b| b != 0))
        .unwrap_or(false);
    let status_non_zero = key_info.get(slot * 2 + 1).map(|&b| b != 0).unwrap_or(false);
    fp_non_zero || status_non_zero
}

/// Boot an app over a fresh RAM trussed client, run `body`, and return its
/// verdict. Each test gets its own client so a card-shaped change in one
/// (retry counters move, keys land) cannot leak into another.
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

/// `0xC4` is the PW status bytes DO. The client gates on
/// `pw.filter(|p| p.len() >= 7)` and then reads `(p[4], p[5], p[6])` as the
/// PW1 / reset-code / PW3 retry counters — it ignores `p[0..4]`. So the
/// layout is not "7 retry counters", it is `valid-multiple, max-PW1,
/// max-RC, max-PW3` followed by the three counters, and a card that filled
/// all seven slots with counters would answer `9000` and render `(0, 0, 0)`
/// on the client with no error anywhere.
///
/// Pinned three ways: the exact 7-byte shape, the max-length fields (which
/// must be the PIN-length ceiling, not a counter), and the counters being
/// *live* — a wrong PW1 decrements `[4]` and moves nothing else.
#[test]
fn pw_status_c4_puts_the_retry_counters_in_the_last_three_bytes() {
    on_fresh_card(&format!("us151-c4-{}", std::process::id()), |d| {
        let c4 = get_data(d, 0xC4);
        assert_eq!(
            c4.len(),
            7,
            "0xC4 must be 7 bytes; the client drops a shorter one to (0,0,0): {:02x?}",
            c4
        );
        // [0] is the "PW1 valid for multiple signatures" boolean, not a count.
        assert!(c4[0] <= 0x01, "0xC4[0] is a boolean, got {:02X}", c4[0]);
        // [1..4] are the three maximum PIN lengths (127 = MAX_PIN_LENGTH),
        // and [4..7] are the three retry counters. A card that swapped the
        // halves would still return 7 bytes and 9000.
        for (index, &byte) in c4.iter().enumerate().take(4).skip(1) {
            assert_eq!(
                byte, 0x7F,
                "0xC4[{}] is a max PIN length, not a counter (a counter here \
                 shifts every value the client displays)",
                index
            );
        }
        for (index, &byte) in c4.iter().enumerate().skip(4) {
            assert!(
                byte <= 0x03,
                "0xC4[{}] must be a remaining-tries count (0..=3), got {:02X}",
                index,
                byte
            );
        }
        let before = c4;

        // A wrong PW1 burns exactly one PW1 retry and touches nothing else —
        // the proof that [4] is the PW1 counter rather than a constant.
        let (body, sw) = apdu(
            d,
            &[
                0x00, 0x20, 0x00, 0x81, 0x06, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
            ],
        );
        assert_eq!(
            sw, 0x63C2,
            "a wrong PW1 must answer 63C2 (retries exhausted)"
        );
        assert!(body.is_empty(), "63C2 carries no data");

        let after = get_data(d, 0xC4);
        assert_eq!(
            after[4],
            before[4] - 1,
            "0xC4[4] is the PW1 counter: {:02x?} -> {:02x?}",
            before,
            after
        );
        assert_eq!(
            &after[..4],
            &before[..4],
            "the max-length fields do not move with a retry"
        );
        assert_eq!(&after[5..], &before[5..], "only the PW1 counter moves");
    });
}

/// `0xC5` is a 60-byte concatenation of three 20-byte fingerprints, and the
/// client slices it positionally: `fps.get(i*20 .. i*20+20)` for
/// `[Sig, Dec, Aut]`. The card's `Fingerprints::key_offset` is Sign=0,
/// Dec=20, Aut=40 (`vendor/opcard/src/state.rs:114-137`), so the two agree —
/// but only because both happen to be in the same order. Seeding the three
/// per-slot `0xC7`/`0xC8`/`0xC9` (gpg's own `store_fpr` path) with
/// mutually distinct values is what makes an offset swap visible; an
/// all-zero `0xC5` would satisfy any layout.
#[test]
fn fingerprints_c5_slice_by_the_client_slot_order() {
    on_fresh_card(&format!("us151-c5-{}", std::process::id()), |d| {
        let (sig, dec, aut) = (
            fingerprint_fixture(0x11),
            fingerprint_fixture(0x22),
            fingerprint_fixture(0x33),
        );
        assert_ne!(sig, dec);
        assert_ne!(dec, aut);

        verify_pw3(d);
        put_data(d, 0xC7, &sig);
        put_data(d, 0xC8, &dec);
        put_data(d, 0xC9, &aut);

        let c5 = get_data(d, 0xC5);
        assert_eq!(
            c5.len(),
            60,
            "0xC5 must be exactly three 20-byte slots: {} bytes",
            c5.len()
        );
        assert_eq!(&c5[0..20], &sig, "slot 0 is the signature fingerprint");
        assert_eq!(&c5[20..40], &dec, "slot 1 is the decryption fingerprint");
        assert_eq!(
            &c5[40..60],
            &aut,
            "slot 2 is the authentication fingerprint"
        );
    });
}

/// `0xC6` (the CA fingerprints) is the *same shape* — 60 bytes, three
/// 20-byte slots — but in the **opposite** order: the card's
/// `CaFingerprints::key_offset` is Aut=0, Dec=20, Sign=40
/// (`vendor/opcard/src/state.rs:148-156`), and the `0xCA`/`0xCB`/`0xCC`
/// write handlers map to Aut/Dec/Sign
/// (`vendor/opcard/src/command/data.rs:966-968`).
///
/// This is the reason the `0xC5` offsets must never be reused for `0xC6`:
/// nothing about the two DOs distinguishes them except this order, and the
/// reference client does not read `0xC6` at all, so no host test would
/// notice a swap. Pinned here, against the same seeding path.
#[test]
fn ca_fingerprints_c6_run_the_other_slot_order() {
    on_fresh_card(&format!("us151-c6-{}", std::process::id()), |d| {
        let (ca1, ca2, ca3) = (
            fingerprint_fixture(0xAA),
            fingerprint_fixture(0xBB),
            fingerprint_fixture(0xCC),
        );

        verify_pw3(d);
        put_data(d, 0xCA, &ca1);
        put_data(d, 0xCB, &ca2);
        put_data(d, 0xCC, &ca3);

        let c6 = get_data(d, 0xC6);
        assert_eq!(c6.len(), 60, "0xC6 must be exactly three 20-byte slots");
        assert_eq!(
            &c6[0..20],
            &ca1,
            "slot 0 is the CA for the authentication key"
        );
        assert_eq!(&c6[20..40], &ca2, "slot 1 is the CA for the decryption key");
        assert_eq!(&c6[40..60], &ca3, "slot 2 is the CA for the signature key");
    });
}

/// `0xDE` is three `[key-ref, status]` pairs. The client reads only the
/// status — `key_info.get(i*2+1) != 0` — so the even bytes are invisible to
/// it, but they are the part that says *which* key a status belongs to; a
/// card that emitted three bare status bytes would still satisfy the client
/// and would report slot 0 as the decryption key.
///
/// The status vocabulary is 0 = none, 1 = generated, 2 = imported
/// (`key_info_byte`, `vendor/opcard/src/command/data.rs:691-696`). All three
/// are non-zero-presence-equivalent to the client, so the distinction is
/// pinned here rather than in the client-facing assertion.
#[test]
fn key_information_de_is_three_key_ref_status_pairs() {
    on_fresh_card(&format!("us151-de-{}", std::process::id()), |d| {
        // A factory card: the key refs are 01/02/03 (Sig/Dec/Aut, spec §7.2.18)
        // and every status is "no key".
        let de = get_data(d, 0xDE);
        assert_eq!(de.len(), 6, "0xDE must be three 2-byte pairs: {:02x?}", de);
        assert_eq!(
            &de[0..6],
            &[0x01, 0x00, 0x02, 0x00, 0x03, 0x00],
            "a factory card reports no keys in 0xDE"
        );
        for slot in 0..3 {
            assert!(
                !client_reports_present(&[0u8; 60], &de, slot),
                "a factory card has no key in slot {slot}"
            );
        }
    });
}

/// Both halves of the client's presence OR are load-bearing, and they are
/// driven by different writers:
///
/// * `0xDE`'s status is set by GENERATE and by key import, which carry the
///   key origin (`vendor/opcard/src/command/gen.rs:193`, `:239`) and
///   **never** write the fingerprint;
/// * `0xC5`'s slots are written by the host, per-slot, through
///   `0xC7`/`0xC8`/`0xC9` — which gpg does after generating, on a card whose
///   `0xC5` may still be zero.
///
/// So a card can be "present" through either source alone, and a reader that
/// trusted one of them would blank a key the other is describing. Each of
/// the four states below is built from the real write paths, not from a
/// synthesised `0xDE`.
#[test]
fn client_presence_holds_when_either_c5_or_de_says_so() {
    // (a) neither source: a factory card.
    on_fresh_card(&format!("us151-or-a-{}", std::process::id()), |d| {
        let (de, c5) = (get_data(d, 0xDE), get_data(d, 0xC5));
        assert_eq!(c5, [0u8; 60], "a factory card's 0xC5 is all zero");
        for slot in 0..3 {
            assert!(
                !client_reports_present(&c5, &de, slot),
                "slot {slot} must read absent with both sources zero"
            );
        }
    });

    // (b) 0xDE alone: an imported signature key, no host-written fingerprint.
    on_fresh_card(&format!("us151-or-b-{}", std::process::id()), |d| {
        verify_pw3(d);
        assert_eq!(
            apdu(
                d,
                &import_apdu(
                    &[0xB6, 0x00],
                    &hexkey("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"),
                    &hexkey("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"),
                )
            )
            .1,
            SW_OK,
            "the sign key import must answer 9000"
        );
        let (de, c5) = (get_data(d, 0xDE), get_data(d, 0xC5));
        assert_eq!(
            de[1], 0x02,
            "an imported key reports status 2 (imported): {:02x?}",
            de
        );
        assert_eq!(de[3], 0x00);
        assert_eq!(de[5], 0x00);
        assert_eq!(
            &c5[..20],
            &[0u8; 20],
            "import writes no fingerprint; the host does, via 0xC7"
        );
        assert!(
            client_reports_present(&c5, &de, 0),
            "0xDE alone must be enough to report slot 0 present"
        );
        assert!(
            !client_reports_present(&c5, &de, 1),
            "slot 1 has neither source"
        );
        assert!(
            !client_reports_present(&c5, &de, 2),
            "slot 2 has neither source"
        );
    });

    // (c) 0xC5 alone: a host-written decryption fingerprint, no key on the
    //     card. This is the gpg shape — `store_fpr` runs after GENKEY and is
    //     not conditional on the card knowing the key's origin — and the
    //     case a "0xDE is authoritative" reader would get wrong.
    on_fresh_card(&format!("us151-or-c-{}", std::process::id()), |d| {
        verify_pw3(d);
        put_data(d, 0xC8, &fingerprint_fixture(0x22));
        let (de, c5) = (get_data(d, 0xDE), get_data(d, 0xC5));
        assert_eq!(
            de[3], 0x00,
            "a host-written fingerprint does not create a key: {:02x?}",
            de
        );
        assert_ne!(&c5[20..40], &[0u8; 20]);
        assert!(
            client_reports_present(&c5, &de, 1),
            "0xC5 alone must be enough to report slot 1 present"
        );
    });
}

/// Everything the client descends into hangs off the `73` inside `0x6E`, and
/// the reply it walks is the *unwrapped* `0x6E` body — the card emits each
/// child's tag and value but never a `6E` wrapper
/// (`get_constructed_data`, `vendor/opcard/src/command/data.rs:511-533`).
/// A `73` that dropped a child, or carried a value differing from the
/// child's own GET DATA, would leave the client and gpg disagreeing about
/// the same card depending on which path they took.
///
/// Asserts the eight tags and the per-DO byte equality, plus the two shape
/// facts the client's fixed-offset readers depend on: `0xD6`-`0xD8` are
/// **two** bytes (UIF state, then the general-feature-management byte) and
/// the client reads only the first.
#[test]
fn key_state_dos_appear_in_the_6e_73_sub_template() {
    on_fresh_card(&format!("us151-73-{}", std::process::id()), |d| {
        verify_pw3(d);
        put_data(d, 0xC7, &fingerprint_fixture(0x11));
        put_data(d, 0xC8, &fingerprint_fixture(0x22));
        put_data(d, 0xC9, &fingerprint_fixture(0x33));
        // D6 on, D7 off, D8 permanently on: three distinct UIF states, so a
        // slot-order swap in the touch DOs cannot pass by coincidence.
        put_data(d, 0xD6, &[0x01, 0x20]);
        put_data(d, 0xD7, &[0x00, 0x20]);
        put_data(d, 0xD8, &[0x02, 0x20]);

        let app = apdu_read(d, &[0x00, 0xCA, 0x00, 0x6E, 0x00]).0;
        let disc = tlv_find(&app, 0x73).expect("0x6E carries no 73 sub-template");

        for tag in [0xC1u8, 0xC2, 0xC3, 0xC4, 0xC5, 0xDE, 0xD6, 0xD7, 0xD8] {
            let in_73 = tlv_find(disc, tag).unwrap_or_else(|| {
                panic!("the 73 sub-template carries no {:02X}: {:02x?}", tag, disc)
            });
            let direct = get_data(d, tag);
            assert_eq!(
                in_73,
                &direct[..],
                "0x{:02X} differs between the 73 sub-template and its own GET DATA",
                tag
            );
        }

        // 0xC1-0xC3 are `[algorithm-id, parameters…]`; the client maps the
        // first byte to a display label and the rest to a curve or modulus
        // size, so a zero-length attribute would render "unknown".
        for tag in [0xC1u8, 0xC2, 0xC3] {
            let attr = tlv_find(disc, tag).unwrap();
            assert!(
                !attr.is_empty(),
                "0x{:02X} carries no algorithm attribute",
                tag
            );
        }
        // 0xD6-0xD8 are `[uif-state, gfm]`. The client takes
        // `u.first()` and treats non-zero as "touch required", so the state
        // byte must come first and the GFM byte must not be read as it.
        for (tag, expected_state) in [(0xD6u8, 0x01u8), (0xD7, 0x00), (0xD8, 0x02)] {
            let uif = tlv_find(disc, tag).unwrap();
            assert_eq!(uif.len(), 2, "0x{:02X} is [uif-state, gfm]", tag);
            assert_eq!(
                uif[0], expected_state,
                "0x{:02X} uif-state is the byte the client reads",
                tag
            );
            assert_eq!(
                uif[1], 0x20,
                "0x{:02X} second byte is the GFM byte, not a second flag",
                tag
            );
        }
    });
}

fn hexkey(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn tlv(tag: &[u8], data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::from(tag);
    let len = data.len();
    if len <= 0x7f {
        buf.push(len as u8);
    } else {
        buf.push(0x81);
        buf.push(len as u8);
    }
    buf.extend_from_slice(data);
    buf
}

/// Extended-header-list key import (INS DB, P1P2 3FFF) for an Ed255 key:
/// `crt || 4D { crt, 7F48 { 92 <priv>, 99 <0x40‖point> }, 5F48 ‖ priv ‖ point }`.
fn import_apdu(crt: &[u8], private: &[u8], public: &[u8]) -> Vec<u8> {
    let mut key = Vec::from(private);
    key.push(0x40);
    key.extend_from_slice(public);
    let template = [
        0x92,
        private.len() as u8,
        0x99,
        (key.len() - private.len()) as u8,
    ];
    let mut data = Vec::from(crt);
    data.extend_from_slice(&tlv(&[0x7F, 0x48], &template));
    data.extend_from_slice(&tlv(&[0x5F, 0x48], &key));
    let blob = tlv(&[0x4D], &data);
    let mut apdu = vec![0x00, 0xDB, 0x3F, 0xFF];
    apdu.push(blob.len() as u8);
    apdu.extend_from_slice(&blob);
    apdu
}
