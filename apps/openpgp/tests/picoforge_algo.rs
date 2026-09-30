//! US-152 (PICOForge-COMPAT): the algorithm attributes the reference client
//! writes, and the curves this card is required to serve behind them.
//!
//! The client encodes a curve pick as `<algo id><curve OID>` and PUTs it to
//! `C1` (sign) / `C2` (decryption) / `C3` (authentication) before GENERATE.
//! Three properties of that encoding are not visible from the card side and
//! are pinned here, because each one is a way the pairing can silently rot:
//!
//! 1. **The client never sends the `FF` form.** It emits the bare
//!    `<id><OID>` spelling (`13 2A 86 48 CE 3D 03 01 07`), while GET DATA
//!    answers with the `…FF` public-key form. `dispatch.rs` drives both
//!    spellings, but one algorithm at a time and never the client's own ten
//!    entries; what runs here is the whole menu on all three slots with the
//!    read-back checked after every PUT, so the two-spelling contract is
//!    exercised from both ends over the whole set.
//! 2. **The DEC slot is not ECDH-only.** The client substitutes ECDSA→ECDH
//!    inside its `ec(..)` closure, so an RSA choice PUTs
//!    `01 08 00 00 20 00` to `C2` as readily as to `C1` — the "encryption
//!    slot is always EC" reading of the slot table is wrong. What the card
//!    does with that is pinned by actually GENERATEing on `B8` and reading
//!    the key back, not inferred from the attribute DO.
//! 3. **The client's OID list is a subset of what the card serves.** P-512r1
//!    is absent from the client and fails closed on the card; the boundary
//!    inside the Brainpool OID family is pinned from both sides.
//!
//! `tests/dispatch.rs` owns the per-algorithm attribute pins (the `FA` DO
//! listing, the accepted Brainpool attributes, the S-943 RSA nibble policy);
//! nothing here restates those. The helpers below are re-declared rather than
//! shared because that file is owned by another stream.

use fapico2_openpgp::OpenPgpApp;
use fapico2_platform::dispatch::{Dispatcher, MAX_RESPONSE, SW_OK};
use heapless::Vec as HeaplessVec;

// --- client-side vocabulary (picoforge `src/hal/applets/openpgp.rs`) ---------
//
// First byte of an attribute is the algorithm id: RSA 0x01, ECDH 0x12,
// ECDSA 0x13, EdDSA 0x16. The curve OID follows.
const ALGO_RSA: u8 = 0x01;
const ALGO_ECDH: u8 = 0x12;
const ALGO_ECDSA: u8 = 0x13;
const ALGO_EDDSA: u8 = 0x16;

const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];
const OID_SECP256K1: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x0A];
const OID_BP256R1: &[u8] = &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
const OID_BP384R1: &[u8] = &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];
const OID_ED25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
const OID_X25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

/// A 25519 pairing, for the slot split the client applies at choice 9:
/// Cv25519 (ECDH) on DEC, Ed25519 (EdDSA) on SIG and AUT. Built by
/// `client_choices` below rather than spelled out, so the split is the
/// client's and not a transcription of it.
fn ed25519_attr() -> Vec<u8> {
    attribute(ALGO_EDDSA, OID_ED25519)
}

fn x25519_attr() -> Vec<u8> {
    attribute(ALGO_ECDH, OID_X25519)
}

/// `<algo id><curve OID>` — the client's `ec(..)` closure verbatim.
fn attribute(id: u8, oid: &[u8]) -> Vec<u8> {
    let mut v = vec![id];
    v.extend_from_slice(oid);
    v
}

/// `<id> <modulus bits BE> <exponent bits BE> <import>` for the RSA choices.
/// The trailing import nibble is `00` (standard format) — the client's only
/// spelling, and the one S-943 pinned as accepted.
fn rsa_attr(modulus_bits: u16) -> Vec<u8> {
    vec![ALGO_RSA, (modulus_bits >> 8) as u8, modulus_bits as u8, 0x00, 0x20, 0x00]
}

/// The client's per-slot EC substitution: `0x12` on the decryption slot,
/// `0x13` everywhere else. This is the entire mechanism behind "the DEC slot
/// gets ECDH" — and, because it lives inside this one closure, the entire
/// reason the RSA choices escape it.
fn ec_attr(oid: &'static [u8], on_dec_slot: bool) -> Vec<u8> {
    attribute(if on_dec_slot { ALGO_ECDH } else { ALGO_ECDSA }, oid)
}

/// One client menu entry: `(label, choice, C1/sign, C2/dec, C3/aut)`.
type ClientChoice = (&'static str, u8, Vec<u8>, Vec<u8>, Vec<u8>);

/// The ten entries of the client's generate menu
/// (`GENERATE_ALGOS`), each with the attribute the client PUTs per slot.
///
/// Rebuilt from the client's own OID list and its own `ec(..)` closure rather
/// than transcribed, so the ECDSA/ECDH split and the RSA-are-the-same-on-all-
/// three-slots consequence cannot be introduced here by hand — a table of
/// literals would make the very property under test a property of the test.
fn client_choices() -> Vec<ClientChoice> {
    let rsa: [(&'static str, u16); 3] =
        [("RSA-2048", 2048), ("RSA-3072", 3072), ("RSA-4096", 4096)];
    let ec: [(&'static str, &'static [u8]); 6] = [
        ("ECC P-256", OID_P256),
        ("ECC P-384", OID_P384),
        ("ECC P-521", OID_P521),
        ("secp256k1", OID_SECP256K1),
        ("brainpoolP256r1", OID_BP256R1),
        ("brainpoolP384r1", OID_BP384R1),
    ];
    let mut out = Vec::new();
    for (index, (label, bits)) in rsa.into_iter().enumerate() {
        let attr = rsa_attr(bits);
        out.push((label, index as u8, attr.clone(), attr.clone(), attr));
    }
    for (index, (label, oid)) in ec.into_iter().enumerate() {
        // One menu entry, two attribute byte strings: the same curve as ECDSA
        // on SIG/AUT and as ECDH on DEC.
        out.push((
            label,
            3 + index as u8,
            ec_attr(oid, false),
            ec_attr(oid, true),
            ec_attr(oid, false),
        ));
    }
    out.push((
        "Ed25519 / Cv25519",
        9,
        ed25519_attr(),
        x25519_attr(),
        ed25519_attr(),
    ));
    out
}

/// What GET DATA answers after a client-shaped PUT.
///
/// The card stores the parsed algorithm, not the bytes, and answers from
/// `Algorithm::attributes()` (`vendor/opcard/src/types.rs`): the public-key
/// form for every EC and 25519 variant — the sent bytes plus the `FF` import
/// nibble — and the standard `N,E` spelling for RSA, which is already what
/// the client sent. Derived from the sent bytes so the two spellings cannot
/// drift apart in the table.
fn expected_read_back(sent: &[u8]) -> Vec<u8> {
    if sent[0] == ALGO_RSA {
        sent.to_vec()
    } else {
        let mut v = sent.to_vec();
        v.push(0xFF);
        v
    }
}

// --- APDU helpers -----------------------------------------------------------

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

/// PUT DATA (INS DA) of a simple DO: short Lc, **no Le** byte. The absence of
/// Le is load-bearing — an APDU carrying one is a different command to the
/// card's parser, and the client builds it this way.
fn put_data_apdu(tag_hi: u8, tag_lo: u8, data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0xDA, tag_hi, tag_lo];
    apdu.push(data.len() as u8);
    apdu.extend_from_slice(data);
    apdu
}

fn apdu(dispatcher: &mut Dispatcher<1>, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(apdu, &mut resp);
    assert!(resp.len() >= 2, "response too short for {:x?}", apdu);
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    (resp[..resp.len() - 2].to_vec(), sw)
}

/// APDU plus the `61XX`/GET RESPONSE continuation, as scd's apdu.c drains it.
/// The attribute DOs are short, but the `FA` DO is 30 records and the RSA
/// public-key templates are not, so one drain helper serves the file.
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

fn get_data_apdu(tag: u8) -> [u8; 5] {
    [0x00, 0xCA, 0x00, tag, 0x00]
}

/// Factory card + SELECT + PW3 verification. Algorithm attributes are admin
/// authorized (`write_perm` → `Admin`, `vendor/opcard/src/command/data.rs`),
/// so every PUT below needs this.
fn verified_card(dispatcher: &mut Dispatcher<1>) {
    let (_, sw) = apdu(dispatcher, &select_openpgp());
    assert_eq!(sw, SW_OK, "SELECT must answer 9000");
    let (_, sw) = apdu(
        dispatcher,
        &[0x00, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38],
    );
    assert_eq!(sw, SW_OK, "VERIFY PW3 must answer 9000");
}

/// Move PW1/PW3 off the factory defaults: GENERATE is refused while the
/// factory PINs are in force (US-912). CHANGE REFERENCE DATA keeps the admin
/// session, so the card is still attribute-writable afterwards.
fn personalize_pins(dispatcher: &mut Dispatcher<1>) {
    let (_, sw) = apdu(
        dispatcher,
        &[0x00, 0x24, 0x00, 0x81, 0x0C,
          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
    );
    assert_eq!(sw, SW_OK, "CHANGE PW1 must answer 9000");
    let (_, sw) = apdu(
        dispatcher,
        &[0x00, 0x24, 0x00, 0x83, 0x10,
          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
          0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
    );
    assert_eq!(sw, SW_OK, "CHANGE PW3 must answer 9000");
}

// ---------------------------------------------------------------------------
// The client-shaped matrix: every menu entry, every slot, PUT then read back.

/// Every attribute the client's menu can produce is accepted on all three
/// slot DOs and read back in the card's canonical spelling — for all ten
/// choices, not the handful the existing per-algorithm pins cover.
///
/// The two RSA attributes `dispatch.rs` has not driven per slot (3072, 4096)
/// are here for the same reason as the EC ones: the client offers them, so
/// "the card serves every choice the client can send" is the contract, and a
/// size that regressed out of `default_gen()` would only show up if some
/// test PUT it. `RSA_4096` is the RSA-side twin of the P-512r1 boundary: it is
/// in the client's list *and* in `default_gen()`, so it must not be confused
/// with a curve the client simply cannot ask for.
#[test]
fn client_attribute_matrix_accepted_and_read_back() {
    opcard::virt::with_ram_client("fapico2-openpgp-us152-matrix", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        for (label, choice, sig, dec, aut) in client_choices() {
            // One entry is *not* in this contract, and its exclusion is the
            // point rather than an omission. The client offers Brainpool
            // P-384r1 (choice 8); US-966 deferred that curve, so the card
            // refuses it. Asserting "the card serves every choice the client
            // can send" was true when this test was written and is no longer,
            // so the sweep is over the **served** menu and the deferred
            // entry is held out by name — with the refusal itself pinned by
            // `brainpool_p384r1_is_refused_on_every_slot`, so holding it out
            // here cannot quietly turn into not testing it at all.
            if label == "brainpoolP384r1" {
                continue;
            }
            for (tag, attr, slot) in [
                (0xC1u8, &sig, "C1/sign"),
                (0xC2, &dec, "C2/dec"),
                (0xC3, &aut, "C3/aut"),
            ] {
                let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, attr));
                assert_eq!(
                    sw, SW_OK,
                    "client choice {choice} ({label}) PUT DATA {slot} {attr:02X?} must answer \
                     9000, got {sw:04x}"
                );
                let (stored, sw) = apdu_read(&mut dispatcher, &get_data_apdu(tag));
                assert_eq!(sw, SW_OK, "GET DATA {tag:02X} must answer 9000");
                assert_eq!(
                    stored,
                    expected_read_back(attr),
                    "client choice {choice} ({label}) on {slot}: the card must read back the \
                     algorithm the client named, in the card's canonical spelling"
                );
            }
        }
    });
}

/// The client's slot substitution is real and is applied where the client
/// applies it: for one EC curve, `C2` reads back ECDH and `C1`/`C3` read back
/// ECDSA, and none of the three writes disturbs the other two.
///
/// Independence is the part worth pinning. A card that stored one algorithm
/// for all three slots would satisfy every per-algorithm attribute pin in
/// `dispatch.rs` — those write one tag at a time and only read that tag back
/// — while handing the client a key type its menu never selected.
#[test]
fn ec_attribute_is_slot_specific_and_slots_are_independent() {
    opcard::virt::with_ram_client("fapico2-openpgp-us152-slots", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // Set the same curve family on the two slots that disagree about the
        // algorithm id, then confirm neither leaked into the third.
        let ecdsa_p256 = ec_attr(OID_P256, false);
        let ecdh_p256 = ec_attr(OID_P256, true);
        for (tag, attr) in [(0xC1u8, &ecdsa_p256), (0xC2, &ecdh_p256)] {
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, attr));
            assert_eq!(sw, SW_OK, "PUT DATA {tag:02X} must answer 9000");
        }
        for (tag, want) in [(0xC1u8, &ecdsa_p256), (0xC2, &ecdh_p256)] {
            let (stored, sw) = apdu_read(&mut dispatcher, &get_data_apdu(tag));
            assert_eq!(sw, SW_OK, "GET DATA {tag:02X} must answer 9000");
            assert_eq!(
                stored,
                expected_read_back(want),
                "slot {tag:02X} must hold its own algorithm id, not the other slot's"
            );
        }
        // C3 is untouched: the factory Ed255 attribute. If the slot DO were
        // aliasing, the two writes above would have moved it to P-256.
        let (aut, sw) = apdu_read(&mut dispatcher, &get_data_apdu(0xC3));
        assert_eq!(sw, SW_OK, "GET DATA C3 must answer 9000");
        assert_eq!(
            aut,
            expected_read_back(&ed25519_attr()),
            "writing C1 and C2 must leave the authentication slot on its factory attribute"
        );
    });
}

// ---------------------------------------------------------------------------
// The DEC slot is not ECDH-only.

// The RSA attributes in `CLIENT_CHOICES` and the C2 rows of the FA DO in
// `dispatch.rs` already say the card *accepts* RSA on the decryption slot.
// What they do not say — and what the client's own flow needs — is that the
// card then *serves* it: the client PUTs the attribute and immediately
// GENERATEs on the decryption key. The answer is that the card generates a
// genuine RSA decryption key, not a refusal and not an EC key in disguise.
//
// Evidence, in `vendor/opcard/src/`:
//   * `types.rs` — `DecryptionAlgorithm` enumerates `Rsa2048/3072/4096`, so
//     `Algorithm::try_from` on the RSA bytes converts to a `DecryptionAlgorithm`
//     rather than falling through to the `AlgorithmFromAttributesError` arm.
//   * `command/data.rs` — `put_alg_attributes_dec` then applies the same
//     `ensure_alg_allowed` gate as the other two slots, and `RSA_2048` is in
//     `AllowedAlgorithms::default_gen()`.
//   * `command/gen.rs` — `gen::dec` dispatches `DecryptionAlgorithm::Rsa2048`
//     to `gen_rsa_key(.., KeyType::Dec, Mechanism::Rsa2048Pkcs1v15)`.
// `KeyType::try_from_crt` keys off the CRT tag only (`B8` = decryption), never
// off the algorithm, so nothing on the path special-cases the slot.

/// The client's RSA-2048 pick on the encryption slot, followed through to the
/// key it produces: `PUT DATA C2 = 01 08 00 00 20 00` then GENERATE on CRT
/// `B8` answers 9000 and returns a `7F49` template holding an RSA modulus and
/// exponent — a 256-byte `N` and the 3-byte `E = 0x010001` — not an ECC
/// `86 <point>`.
#[test]
fn dec_slot_rsa_attribute_generates_an_rsa_key() {
    opcard::virt::with_ram_client("fapico2-openpgp-us152-dec-rsa", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // Exactly the bytes the client builds for choice 0 on the DEC slot.
        let rsa_2k = rsa_attr(2048);
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC2, &rsa_2k));
        assert_eq!(
            sw, SW_OK,
            "PUT DATA C2 = RSA-2048 attribute must answer 9000, got {sw:04x}"
        );
        let (stored, sw) = apdu_read(&mut dispatcher, &get_data_apdu(0xC2));
        assert_eq!(sw, SW_OK, "GET DATA C2 must answer 9000");
        assert_eq!(stored, rsa_2k, "C2 must read back the RSA-2048 attribute");

        personalize_pins(&mut dispatcher);

        // GENERATE ASYMMETRIC KEY PAIR on the decryption slot (CRT B8), no Le.
        // The RSA public template is 270 bytes, so the reply is chunked.
        let mut gen = vec![0x00u8, 0x47, 0x80, 0x00, 0x02, 0xB8, 0x00];
        gen.push(0x00);
        let (body, sw) = apdu_read(&mut dispatcher, &gen);
        assert_eq!(
            sw, SW_OK,
            "GENERATE on the decryption slot with an RSA attribute must answer 9000, got {sw:04x}"
        );

        // No ECC OID anywhere: an EC key would carry `86 <len> <point>` with
        // the point opening `04 || X || Y` (or `40` for 25519).
        assert_eq!(
            body.windows(2).position(|w| w == [0x86, 0x41]),
            None,
            "the DEC slot must not answer an EC public point for an RSA attribute: {}",
            hex_str(&body)
        );
        assert_eq!(
            body.windows(2).position(|w| w == [0x2B, 0x06]),
            None,
            "the DEC slot must not answer a 25519 key for an RSA attribute: {}",
            hex_str(&body)
        );

        let (n, e) = rsa_pubkey_from_template(&body);
        assert_eq!(
            n.len(),
            256,
            "the generated modulus must be RSA-2048 sized, got {} bytes",
            n.len()
        );
        assert_eq!(e, vec![0x01, 0x00, 0x01], "the exponent must be 65537");
        // A modulus is the top bit set and is not a small integer: enough to
        // rule out the 8-byte placeholder a stub backend would hand back.
        assert_eq!(n[0] & 0x80, 0x80, "the modulus must have its top bit set");
        assert!(
            n.iter().filter(|&&b| b == 0).count() < 16,
            "the modulus must not be a mostly-zero placeholder"
        );

        // And the key is readable back through the same slot the client
        // would read it through, so the GENERATE is a durable key and not a
        // one-shot reply.
        let read = vec![0x00u8, 0x47, 0x81, 0x00, 0x02, 0xB8, 0x00, 0x00];
        let (body, sw) = apdu_read(&mut dispatcher, &read);
        assert_eq!(sw, SW_OK, "READ PUBLIC KEY (dec) must answer 9000");
        assert_eq!(
            rsa_pubkey_from_template(&body),
            (n, e),
            "the read-back decryption public key must be the one just generated"
        );
    });
}

/// The decryption slot's algorithm set is the *spec's* set — ECDH, X25519 and
/// RSA — not "whatever the signature slot accepts". EdDSA is a signature-only
/// algorithm, so the attribute the client builds for SIG/AUT at choice 9 is
/// refused on `C2`, and the X25519 attribute is refused on `C1`/`C3`.
///
/// Without this the RSA result above would read as "the DEC slot takes
/// anything": the failures are what make the three accepted families
/// meaningful.
#[test]
fn signature_only_and_ecdh_only_attributes_are_refused_on_the_other_slots() {
    opcard::virt::with_ram_client("fapico2-openpgp-us152-slot-refuse", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // EdDSA (0x16) is absent from `DecryptionAlgorithm`, so it fails the
        // attribute parse before the generation gate is even reached.
        let ed = ed25519_attr();
        let x = x25519_attr();
        for (tag, attr, name) in [(0xC1u8, &ed, "C1/sign Ed25519"), (0xC3, &ed, "C3/aut Ed25519")] {
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, attr));
            assert_eq!(sw, SW_OK, "baseline: {name} must be accepted, got {sw:04x}");
        }
        for (tag, attr, name) in [
            (0xC2u8, &ed, "C2/dec Ed25519"),
            (0xC1, &x, "C1/sign X25519"),
            (0xC3, &x, "C3/aut X25519"),
        ] {
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, attr));
            assert_eq!(
                sw, 0x6A80,
                "{name} is not in the slot's algorithm set and must be refused with 6A80, \
                 got {sw:04x}"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// P-512r1: absent from the client, refused by the card, and the boundary is
// exactly where both say it is.

/// Brainpool P-512r1 (`1.3.36.3.3.2.8.1.1.13`) in the *client's* spelling —
/// bare `<id><OID>`, no `FF` — is refused with 6A80 on all three slot DOs,
/// and no Brainpool-family attribute the client can ask for lies on the far
/// side of that line.
///
/// The two halves are the point. The client has no P-512r1 entry, so the
/// refusal is unreachable from its menu; the card has no bp512 backend, so
/// `default_gen()` omits `BRAINPOOL_P512R1` and `ensure_alg_allowed` fails
/// the PUT closed. A client that grew the curve and a card that grew a
/// backend would each show up here as a red before either reaches a host.
#[test]
fn brainpool_p512r1_is_absent_from_the_client_set_and_refused_by_the_card() {
    opcard::virt::with_ram_client("fapico2-openpgp-us152-bp512", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // The client cannot ask for it: no entry of the ten carries the
        // P-512r1 OID, on any slot. Checked on the OID tail (the client
        // attributes are `<id><OID>`), so a menu entry that swapped curve
        // while keeping the label would still be caught.
        let bp512_oid: Vec<u8> = OID_BP256R1[..8].iter().copied().chain([0x0D]).collect();
        assert_eq!(
            bp512_oid.len(),
            9,
            "the Brainpool family prefix must be 8 bytes before the size nibble"
        );
        for (label, _choice, sig, dec, aut) in client_choices() {
            for attr in [&sig, &dec, &aut] {
                assert_ne!(
                    &attr[1..],
                    bp512_oid.as_slice(),
                    "client choice {label} must not offer Brainpool P-512r1"
                );
            }
        }

        // The card refuses it, in the spelling a client would send.
        for (tag, id, slot) in [
            (0xC1u8, ALGO_ECDSA, "C1/sign"),
            (0xC2, ALGO_ECDH, "C2/dec"),
            (0xC3, ALGO_ECDSA, "C3/aut"),
        ] {
            let attr = attribute(id, &bp512_oid);
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, &attr));
            assert_eq!(
                sw, 0x6A80,
                "Brainpool P-512r1 on {slot} ({attr:02X?}) must fail closed with 6A80, \
                 got {sw:04x}"
            );
        }

        // And the served side of the family stops one step earlier: of the
        // Brainpool attributes the card advertises, the family suffix is
        // 07 or 0B, never 0D. This scan is what `dispatch.rs`'s exact-list
        // check implies; here it is stated as the client/card boundary it is.
        // And the served side of the family stops even earlier than P-512r1:
        // **P-384r1 is deferred** (US-966, `f09bc02`), so the only Brainpool
        // curve the card advertises is P-256r1, once per slot group. That is
        // a deliberate, hardware-verified deferral, not an oversight — the
        // device-path counterpart is
        // `device_pso.rs::brainpool_p384r1_is_refused_device_path`, the
        // client-side half is the test below, and the advertise/serve
        // coupling is `advertise_serve.rs`.
        let (body, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xFA, 0x00]);
        assert_eq!(sw, SW_OK, "GET DATA FA must answer 9000, got {sw:04x}");
        let mut i = 0;
        let mut brainpool_suffixes: Vec<u8> = Vec::new();
        while i + 2 <= body.len() {
            let len = body[i + 1] as usize;
            let attr = &body[i + 2..i + 2 + len];
            if attr.len() == 11 && attr[1..9] == OID_BP256R1[..8] {
                brainpool_suffixes.push(attr[9]);
            }
            i += 2 + len;
        }
        assert_eq!(
            brainpool_suffixes,
            vec![0x07, 0x07, 0x07],
            "the card must advertise exactly P-256r1 in every slot group (C1, C2, C3) \
             — and neither P-384r1 (deferred, US-966) nor P-512r1 (never implemented)"
        );
    });
}

/// The client half of the US-966 deferral, and the reason the matrix test
/// above cannot assert "every menu entry round-trips".
///
/// PicoForge *does* offer Brainpool P-384r1 in its algorithm menu (choice 8),
/// so a client can ask the card for a curve the firmware deliberately does not
/// serve. The card must answer `6A80` on every slot and leave the stored
/// attribute untouched — refusing closed rather than half-applying. Each slot
/// is seeded with a known-good P-256 attribute first, so "unchanged after the
/// refusal" is a claim about a real prior value, not about a never-written
/// default.
#[test]
fn brainpool_p384r1_is_refused_on_every_slot() {
    opcard::virt::with_ram_client("fapico2-openpgp-us152-bp384", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        let known = client_choices()
            .into_iter()
            .find(|c| c.0 == "ECC P-256")
            .expect("client_choices carries ECC P-256");
        for (tag, attr, slot) in [
            (0xC1u8, &known.2, "C1/sign"),
            (0xC2, &known.3, "C2/dec"),
            (0xC3, &known.4, "C3/aut"),
        ] {
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, attr));
            assert_eq!(sw, SW_OK, "seeding {slot} with P-256 must answer 9000");
        }

        for (tag, dec, slot) in [
            (0xC1u8, false, "C1/sign"),
            (0xC2, true, "C2/dec"),
            (0xC3, false, "C3/aut"),
        ] {
            let attr = ec_attr(OID_BP384R1, dec);
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, &attr));
            assert_eq!(
                sw, 0x6A80,
                "Brainpool P-384r1 on {slot} ({attr:02X?}) is deferred (US-966) and must fail \
                 closed with 6A80, got {sw:04x}"
            );
            let (stored, sw) = apdu_read(&mut dispatcher, &get_data_apdu(tag));
            assert_eq!(sw, SW_OK, "GET DATA {tag:02X} must answer 9000");
            assert_eq!(
                stored,
                expected_read_back(if dec { &known.3 } else { &known.2 }),
                "a refused P-384r1 PUT on {slot} must leave the stored attribute untouched"
            );
        }
    });
}

// --- 7F49 template parsing --------------------------------------------------

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Split a GENERATE / READ PUBLIC KEY reply into `(modulus, exponent)`. The
/// `N` is 256 bytes for RSA-2048, so its length is the two-byte form — the
/// one-byte form would silently mis-slice the template.
fn rsa_pubkey_from_template(body: &[u8]) -> (Vec<u8>, Vec<u8>) {
    fn take_len(data: &[u8], i: usize) -> (usize, usize) {
        match data[i] {
            l @ 0x00..=0x7f => (l as usize, i + 1),
            0x81 => (data[i + 1] as usize, i + 2),
            0x82 => (((data[i + 1] as usize) << 8) | data[i + 2] as usize, i + 3),
            b => panic!("unexpected length byte {b:02x} in template"),
        }
    }
    assert_eq!(&body[..2], &[0x7F, 0x49], "reply must open with the 7F49 template");
    let (_total, mut i) = take_len(body, 2);
    assert_eq!(body[i], 0x81, "first template member must be tag 81 (modulus)");
    i += 1;
    let (n_len, next) = take_len(body, i);
    i = next;
    let n = body[i..i + n_len].to_vec();
    i += n_len;
    assert_eq!(body[i], 0x82, "second template member must be tag 82 (exponent)");
    i += 1;
    let (e_len, next) = take_len(body, i);
    i = next;
    let e = body[i..i + e_len].to_vec();
    (n, e)
}
