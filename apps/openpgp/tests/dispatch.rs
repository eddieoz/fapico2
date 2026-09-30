//! US-331 / S-721-2 host tests: the OpenPGP app answers SELECT AID
//! `d2 76 00 01 24 01` with 9000 through the platform AID dispatcher.
//!
//! The `virt` tests run the real `opcard` over the trussed-virt client;
//! `device_openpgp_get_data_answers` (S-721-2, TDD) runs the *same*
//! `OpenPgpApp` over the S-721-1 no_std "call thyself" `SyscallRunner`
//! client on the host backend — the exact client type the device builds.

mod common;

use common::{aes256_cbc_zero_iv_encrypt, pso_encipher_apdu};
use fapico2_openpgp::OpenPgpApp;
use fapico2_platform::dispatch::{Dispatcher, MAX_RESPONSE, SW_OK};
use fapico2_platform::trusted_backend::{
    dispatch::OpcardDispatch, host::{HostPlatform, HostStore, leak_buf, mount_fs},
};
use heapless::Vec as HeaplessVec;
use hex_literal::hex;

/// Build a SELECT AID APDU (short Lc, no Le) for the OpenPGP AID.
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

#[test]
fn select_openpgp_aid_returns_9000() {
    // The trussed-virt client only lives inside this closure.
    opcard::virt::with_ram_client("fapico2-openpgp-test", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");

        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        dispatcher.dispatch(&select_openpgp(), &mut resp);

        assert!(resp.len() >= 2, "empty response from openpgp app");
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        assert_eq!(sw, SW_OK, "SELECT AID must answer 9000, got {:04x}", sw);
    });
}

#[test]
fn selected_openpgp_accepts_bare_mf_without_authorizing() {
    opcard::virt::with_ram_client("fapico2-openpgp-test", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app));
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        let mf = [0x00, 0xA4, 0x00, 0x00, 0x00];
        dispatcher.dispatch(&mf, &mut resp);
        assert_eq!(resp.as_slice(), &[0x6A, 0x82]);
        dispatcher.dispatch(&select_openpgp(), &mut resp);
        assert!(resp.ends_with(&[0x90, 0x00]));
        dispatcher.dispatch(&mf, &mut resp);
        assert_eq!(resp.as_slice(), &[0x90, 0x00]);
        dispatcher.dispatch(&[0x00, 0x20, 0x00, 0x83], &mut resp);
        assert_eq!(resp.as_slice(), &[0x63, 0xC3]);
        dispatcher.dispatch(&[0x00, 0xA4, 0x00, 0x01, 0x00], &mut resp);
        assert_eq!(resp.as_slice(), &[0x6A, 0x86]);
        dispatcher.deselect_current();
        dispatcher.dispatch(&mf, &mut resp);
        assert_eq!(resp.as_slice(), &[0x6A, 0x82]);
        dispatcher.dispatch(&select_openpgp(), &mut resp);
        dispatcher.dispatch(&mf, &mut resp);
        assert_eq!(resp.as_slice(), &[0x90, 0x00]);
    });
}

#[test]
fn unknown_aid_leaves_selection_untouched() {
    opcard::virt::with_ram_client("fapico2-openpgp-test", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app));

        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        let unknown = [0x00, 0xA4, 0x04, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        dispatcher.dispatch(&unknown, &mut resp);
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        assert_eq!(sw, 0x6A82, "unknown AID must answer 6A82");

        // A command addressed while nothing is selected must not reach the
        // OpenPGP app: dispatcher answers 6A82 (file not found) — parity
        // with the C SDK. (A 6E00 here would map to GPG_ERR_CARD in gpg's
        // scd, fire its Yubikey-manager probe, and misclassify the card —
        // see `fapico2_platform::dispatch::Dispatcher::dispatch`.)
        let mut resp2 = HeaplessVec::<u8, MAX_RESPONSE>::new();
        dispatcher.dispatch(&[0x00, 0xCA, 0x00, 0x4F, 0x00], &mut resp2);
        let sw2 = u16::from_be_bytes([resp2[resp2.len() - 2], resp2[resp2.len() - 1]]);
        assert_eq!(sw2, 0x6A82);
    });
}

/// S-721-2 (D-F, TDD): the OpenPGP app over the S-721-1 no_std
/// `SyscallRunner` client (host backend — the same `Client` type the device
/// builds) answers the three factory-card behaviors:
///
/// 1. SELECT AID → `9000` + the synthesized FCI (opcard's SELECT writes no
///    FCI; the app appends the template, which carries the `5F 52`
///    historical bytes from `opcard::Options::default()` — `pub(crate)` in
///    opcard, so pinned byte-for-byte here);
/// 2. GET DATA (tag `00 65`, INS `CA` — the OpenPGP app's GET DATA per
///    spec §7.1/§7.2.6, not the ISO `B0`) → `9000` + the factory
///    cardholder DO;
/// 3. GET CHALLENGE (8) → `9000` + exactly 8 fresh bytes, not all zero
///    (a real random byte may legitimately be 0, so all-non-zero is *not*
///    asserted) — exercises `random_bytes` through the runner, the
///    device's TRNG path.
#[test]
fn device_openpgp_get_data_answers() {
    fapico2_platform::trusted_backend::host::with_host_backend("fapico2-openpgp-test", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");

        // 1. SELECT → 9000 + FCI. The dispatcher appends the SW after
        //    `select_apdu`, so the response body is exactly the FCI.
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        dispatcher.dispatch(&select_openpgp(), &mut resp);
        assert!(resp.len() >= 2, "empty response from openpgp app");
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        assert_eq!(sw, SW_OK, "SELECT AID must answer 9000, got {:04x}", sw);
        // The US-386 shell template plus the `5F 52` historical bytes
        // (10 bytes, `Options::default()` — see device_shell.rs).
        const SELECT_FCI: &[u8] = &[
            0x62, 0x20, // FCI template (32 bytes)
            0x82, 0x11, //   FCI proprietary template (17 bytes)
            0xA5, 0x06, //     application identifier (6-byte AID)
            0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
            0x50, 0x07, //     application label (7 bytes)
            b'O', b'P', b'E', b'N', b'P', b'G', b'P',
            0x5F, 0x52, 0x0A, //   historical bytes (10 bytes)
            0x00, 0x31, 0xF5, 0x73, 0xC0, 0x01, 0x60, 0x00, 0x90, 0x00,
        ];
        assert_eq!(
            &resp[..resp.len() - 2],
            SELECT_FCI,
            "SELECT body must be the synthesized FCI (dispatcher appends the SW)"
        );

        // 2. GET DATA cardholder (tag 00 65) → 9000 + factory cardholder DO.
        //    INS 0xCA is the OpenPGP app's GET DATA (spec §7.1 table +
        //    §7.2.6 example `00 CA 00 65 00`; the C firmware and the
        //    pytest harness use the same byte). `process` writes data AND
        //    status word itself (the dispatcher appends nothing after
        //    `process`).
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        dispatcher.dispatch(&[0x00, 0xCA, 0x00, 0x65, 0x00], &mut resp);
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        assert_eq!(sw, SW_OK, "GET DATA 65 must answer 9000, got {:04x}", sw);
        // opcard returns the cardholder DO's *content* without the
        // `65 05` constructed-DO wrapper (5B name, 5F2D language, 5F35
        // PIN-status/sex byte = 0x30 on a factory card) — byte-identical to
        // the C firmware (the pytest `test_name_lang_sex` pins exactly
        // `5B 00 5F 2D 00 5F 35 01 30`, and the passing bar runs it).
        assert_eq!(
            &resp[..resp.len() - 2],
            &[0x5B, 0x00, 0x5F, 0x2D, 0x00, 0x5F, 0x35, 0x01, 0x30],
            "GET DATA 65 must return the factory cardholder DO content"
        );

        // 3. GET CHALLENGE (8 bytes) → 9000 + exactly 8 fresh bytes, not
        //    all zero (a real byte may be 0 — see the test doc comment).
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        dispatcher.dispatch(&[0x00, 0x84, 0x00, 0x00, 0x08], &mut resp);
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        assert_eq!(sw, SW_OK, "GET CHALLENGE must answer 9000, got {:04x}", sw);
        let body = &resp[..resp.len() - 2];
        assert_eq!(body.len(), 8, "GET CHALLENGE must return exactly 8 bytes");
        assert!(!body.iter().all(|&b| b == 0), "challenge must not be all-zero");
    });
}

// ---------------------------------------------------------------------------
// US-950: GET DATA FA (AlgorithmInformation, `00 CA 00 FA 00`) must describe
// *exactly* what the card accepts — nothing more (a host building gpg's
// algorithm menu out of this DO must not be handed an algorithm the card then
// refuses) and nothing less.
//
// opcard's `algo_info` walks `SignatureAlgorithm::iter_all()` under tag C1,
// `DecryptionAlgorithm::iter_all()` under C2 and
// `AuthenticationAlgorithm::iter_all()` under C3, dropping any algorithm
// whose `is_allowed(AllowedAlgorithms::default_gen())` is false. The reply
// is therefore a flat run of `tag(len) attrs` records, ten per group.
//
// The first version of this test pinned two samples out of those ~30 records
// and tolerated a malformed tail, so an implementation that dropped the whole
// C2 and C3 groups — or emitted a record whose declared length overran the
// reply — still went green. Three things fix that: the *complete* record set
// is pinned below, the parse is strict (each record must fit inside the body
// and the records must exactly tile it), and the pinned set is cross-checked
// against what the card actually accepts, so the table cannot degenerate into
// a transcript of whatever the card happens to emit today.
//
// `FACTORY_FA` is derived, not transcribed. Each entry names the algorithm
// and, in the trailing comment, the `AllowedAlgorithms` bit in `default_gen()`
// (`vendor/opcard/src/card.rs`) that admits it together with the backend that
// actually serves it:
//
//   P_256 / P_384 / P_521    NIST P-256/384/521, ECDSA and ECDH alike —
//                           trussed p256/p384/p521, in both the raw and the
//                           `…Prehashed` form `pso.rs` names.
//   RSA_2048/3072/4096       the software RSA backend (S-724). All three are
//                           in the list although opcard is built with only
//                           `rsa4096-gen`, because that feature implies the
//                           other two (`rsa4096-gen = ["rsa4096",
//                           "rsa3072-gen"]`, `rsa3072-gen = ["rsa3072",
//                           "rsa2048-gen"]`).
//   ED_25519 / X_25519       Ed255, X25519 — trussed-core.
//   SECP256K1                the software secp256k1 backend (S-724).
//   BRAINPOOL_P256R1         the software Brainpool backend (US-944).
//
// and exactly two `Algorithm` variants are absent:
// `BRAINPOOL_P512R1`, because no bp512 crate exists in the ecosystem, so no
// backend serves `Mechanism::BrainpoolP512R1{,Prehashed}` (the `pso.rs` arms
// are unreachable) and `default_gen()` omits the bit deliberately; and
// `BRAINPOOL_P384R1`, which was **in this table under US-945 and left it under
// US-966** (2026-09-27) — P-384r1 is deferred to a follow-up release for want
// of deployment pull (OpenPGP card spec v3.4 §4.4.3.10 requires only "at
// least one of this curves shall be supported", RFC 8734 deprecated Brainpool
// for TLS 1.3 "because they had little usage", no OpenPGP-card user was
// found), and **not** because it was defective — its hardware signing was
// never measured. Both absences are the entire point of US-950/US-962: the
// defect class is a mechanism reachable in the allow-list that no backend
// serves. They are pinned from both sides — the record must not be
// advertised, and a PUT DATA of it must be refused with 6A80
// (`ensure_alg_allowed`, `data.rs:1172`) — in `NEVER_SERVED` below.
const FACTORY_FA: &[(&str, u8, &[u8])] = &[
    // ---- C1 signature, SignatureAlgorithm::iter_all() ----
    ("Ed255", 0xC1, &hex!("162B06010401DA470F01FF")),                // ED_25519
    ("EcDsaP256", 0xC1, &hex!("132A8648CE3D030107FF")),               // P_256
    ("Rsa2048", 0xC1, &hex!("010800002000")),                          // RSA_2048
    ("Rsa3072", 0xC1, &hex!("010C00002000")),                          // RSA_3072
    ("Rsa4096", 0xC1, &hex!("011000002000")),                          // RSA_4096
    ("EcDsaP384", 0xC1, &hex!("132B81040022FF")),                      // P_384
    ("EcDsaP521", 0xC1, &hex!("132B81040023FF")),                      // P_521
    ("EcDsaBrainpoolP256R1", 0xC1, &hex!("132B2403030208010107FF")),  // BRAINPOOL_P256R1
    ("EcDsaSecp256k1", 0xC1, &hex!("132B8104000AFF")),                // SECP256K1
    // EcDsaBrainpoolP384R1 / EcDsaBrainpoolP512R1 — BRAINPOOL_P384R1 (deferred,
    // US-966) and BRAINPOOL_P512R1 (no backend, US-944): must be absent.
    // ---- C2 decryption, DecryptionAlgorithm::iter_all() ----
    ("X255", 0xC2, &hex!("122B060104019755010501FF")),                 // X_25519
    ("EcDhP256", 0xC2, &hex!("122A8648CE3D030107FF")),                // P_256
    ("Rsa2048", 0xC2, &hex!("010800002000")),                          // RSA_2048
    ("Rsa3072", 0xC2, &hex!("010C00002000")),                          // RSA_3072
    ("Rsa4096", 0xC2, &hex!("011000002000")),                          // RSA_4096
    ("EcDhP384", 0xC2, &hex!("122B81040022FF")),                       // P_384
    ("EcDhP521", 0xC2, &hex!("122B81040023FF")),                       // P_521
    ("EcDhBrainpoolP256R1", 0xC2, &hex!("122B2403030208010107FF")),    // BRAINPOOL_P256R1
    ("EcDhSecp256k1", 0xC2, &hex!("122B8104000AFF")),                 // SECP256K1
    // EcDhBrainpoolP384R1 / EcDhBrainpoolP512R1 — see above.
    // ---- C3 authentication, AuthenticationAlgorithm::iter_all() ----
    ("Ed255", 0xC3, &hex!("162B06010401DA470F01FF")),                // ED_25519
    ("EcDsaP256", 0xC3, &hex!("132A8648CE3D030107FF")),               // P_256
    ("Rsa2048", 0xC3, &hex!("010800002000")),                          // RSA_2048
    ("Rsa3072", 0xC3, &hex!("010C00002000")),                          // RSA_3072
    ("Rsa4096", 0xC3, &hex!("011000002000")),                          // RSA_4096
    ("EcDsaP384", 0xC3, &hex!("132B81040022FF")),                      // P_384
    ("EcDsaP521", 0xC3, &hex!("132B81040023FF")),                      // P_521
    ("EcDsaBrainpoolP256R1", 0xC3, &hex!("132B2403030208010107FF")),  // BRAINPOOL_P256R1
    ("EcDsaSecp256k1", 0xC3, &hex!("132B8104000AFF")),                // SECP256K1
    // EcDsaBrainpoolP384R1 / EcDsaBrainpoolP512R1 — see above.
];

/// The attribute spellings (ECDSA and ECDH, `_PK` form — the ones
/// `algo_info` would emit) with the group tag each belongs under, for the two
/// curves this card deliberately does not serve. None is in `FACTORY_FA`; a
/// PUT DATA of each must be refused with 6A80.
///
/// US-966 moved `BRAINPOOL_P384R1` in here. It used to be three rows of
/// `FACTORY_FA` with a positive PUT assertion — the table is what a reader
/// would consult to learn which curves the card serves, so leaving the
/// deferred curve there and expecting a reader to notice a `cfg` three files
/// away is how a deferred curve comes back by accident.
const NEVER_SERVED: &[(&str, u8, &[u8])] = &[
    ("BRAINPOOL_P384R1", 0xC1, &hex!("132B240303020801010BFF")),
    ("BRAINPOOL_P384R1", 0xC2, &hex!("122B240303020801010BFF")),
    ("BRAINPOOL_P384R1", 0xC3, &hex!("132B240303020801010BFF")),
    ("BRAINPOOL_P512R1", 0xC1, &hex!("132B240303020801010DFF")),
    ("BRAINPOOL_P512R1", 0xC2, &hex!("122B240303020801010DFF")),
    ("BRAINPOOL_P512R1", 0xC3, &hex!("132B240303020801010DFF")),
];

#[test]
fn get_data_fa_lists_only_allowed_algorithms() {
    opcard::virt::with_ram_client("fapico2-openpgp-fa-us950", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");

        // SELECT, then GET DATA FA — the FA DO is readable on a factory card
        // (no PIN verification required), like the cardholder DO above.
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        dispatcher.dispatch(&select_openpgp(), &mut resp);
        assert_eq!(
            u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]),
            SW_OK,
            "SELECT AID must answer 9000"
        );

        // The FA DO returns a run of `tag len attrs` records, one per allowed
        // algorithm per usage — 30 of them, which exceeds the short-response
        // limit, so opcard answers `6133` + GET RESPONSE (INS C0).
        // `apdu_read` drains the chunks exactly as scd's apdu.c does.
        let (body, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xFA, 0x00]);
        assert_eq!(sw, SW_OK, "GET DATA FA must answer 9000, got {:04x}", sw);
        let body = body.as_slice();

        // Strict parse. Every group tag must be C1/C2/C3, every declared
        // length must fit inside the reply, and the records must exactly tile
        // it — a `break` on an overrun here would let a truncated or
        // malformed tail pass unnoticed, which is precisely what the review
        // of this story demonstrated. (The `i + 2` loop bound is what makes
        // the tiling check below bite: it catches a trailing orphan byte that
        // is too short to start a record.)
        let mut records: Vec<(u8, &[u8])> = Vec::new();
        let mut i = 0;
        while i + 2 <= body.len() {
            let tag = body[i];
            let len = body[i + 1] as usize;
            let end = i + 2 + len;
            assert!(
                matches!(tag, 0xC1..=0xC3),
                "FA record tag {:02X} at {i} is not an algorithm group",
                tag
            );
            assert!(
                end <= body.len(),
                "FA record at {i} declares {len} bytes but only {} remain in the reply",
                body.len() - i - 2
            );
            records.push((tag, &body[i + 2..end]));
            i = end;
        }
        assert_eq!(
            i,
            body.len(),
            "FA records must exactly tile the {} byte reply, but parsing stopped at {i}",
            body.len()
        );

        // The complete expected set, in the order opcard emits it. US-966
        // moved Brainpool P-384r1 out, so the factory card answers 27 records
        // where it used to answer 30 — the count is the first thing that
        // breaks if the deferred curve comes back.
        assert_eq!(
            records.len(),
            FACTORY_FA.len(),
            "GET DATA FA must list exactly the {} algorithms a factory card accepts, got {}",
            FACTORY_FA.len(),
            records.len()
        );
        for (n, ((name, tag, attr), (got_tag, got_attr))) in
            FACTORY_FA.iter().zip(records.iter()).enumerate()
        {
            assert_eq!(
                (got_tag, got_attr),
                (tag, attr),
                "FA record {n} must be {name} (tag {tag:02X}, attrs {attr:02X?}), \
                 got tag {got_tag:02X} with attrs {got_attr:02X?}"
            );
        }

        // Nothing else: the only `Algorithm` variants `default_gen()` omits
        // are BRAINPOOL_P384R1 (deferred, US-966) and BRAINPOOL_P512R1 (no
        // backend, US-944), so none of their spellings may appear anywhere in
        // the reply.
        for (name, tag, attr) in NEVER_SERVED {
            assert!(
                !records.iter().any(|(t, a)| t == tag && *a == *attr),
                "{name} ({attr:02X?}) is not served and is refused with 6A80, so it must \
                 not be advertised under tag {tag:02X}"
            );
        }

        // Cross-check the table against behaviour rather than against itself:
        // every attribute the FA DO advertises must actually be accepted by a
        // PUT DATA of the same tag, and every curve that is not advertised
        // must be refused. PUT DATA of an algorithm attribute is
        // admin-authorized (`write_perm` → `Admin`, `data.rs:929`), so this
        // runs after the factory-card listing above has been read: verify the
        // factory PW3, then personalize (CHANGE REFERENCE DATA keeps the
        // admin session) and drive the attribute DOs.
        verified_card(&mut dispatcher);
        personalize_pins(&mut dispatcher);
        for (name, tag, attr) in FACTORY_FA {
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, *tag, attr));
            assert_eq!(
                sw, SW_OK,
                "FA advertises {name} under tag {tag:02X}, so PUT DATA of it must answer \
                 9000, got {sw:04x}"
            );
        }
        for (name, tag, attr) in NEVER_SERVED {
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, *tag, attr));
            assert_eq!(
                sw, 0x6A80,
                "{name} ({attr:02X?}) is advertised nowhere and must be refused under tag \
                 {tag:02X}, got {sw:04x}"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// S-723-A1: gpg 2.4.4 `--card-edit generate` wire-sequence replay (EPIC
// S723-REPAIR F1/F4). Replays gpg's exact APDU sequence through the platform
// AID dispatcher — the layer candidate C1 (response-size / GET RESPONSE
// mechanics on 0x6E) would fault in:
//
//   SELECT        `00 A4 04 00 06 D27600012401`
//   GET DATA 0x6E `00 CA 00 6E 00`   (short Le = 256)
//   VERIFY PW3    `00 20 00 83 08 3132333435363738`
//   GENERATE      `00 47 80 00 02 B6 00`
//
// scd's `does_key_exist` (F3/F4) needs 0xC5 present with >= 60 B inside the
// 0x6E response; `iso7816_generate_keypair` parses the GENERATE reply.
// This test lives at the dispatcher level (not `vendor/opcard/tests/`) because
// opcard's own suite is not wired in this tree (no dev-dependencies) *and* the
// transport/dispatch layer is in scope for C1.
//
// Runs on the no-rsa feature set the device build uses (apps/openpgp enables
// opcard with zero features).

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

/// PUT DATA (INS DA) for a simple DO.
fn put_data_apdu(tag_hi: u8, tag_lo: u8, data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0xDA, tag_hi, tag_lo];
    apdu.push(data.len() as u8);
    apdu.extend_from_slice(data);
    apdu
}

/// Extended-header-list key import (INS DB, P1P2 3FFF) for an ECC key.
fn import_apdu(crt: &[u8], private: &[u8], public: &[u8]) -> Vec<u8> {
    // Key: private scalar || 0x40 (uncompressed prefix) || public point.
    let mut key = Vec::from(private);
    key.push(0x40);
    key.extend_from_slice(public);
    // 7F48 template: 92 <len> (private) 99 <len> (public, with prefix).
    let mut template = vec![0x92];
    template.push(private.len() as u8);
    template.push(0x99);
    template.push((key.len() - private.len()) as u8); // 0x40 prefix + point
    let mut data = Vec::from(crt);
    data.extend_from_slice(&tlv(&[0x7F, 0x48], &template));
    data.extend_from_slice(&tlv(&[0x5F, 0x48], &key));
    let blob = tlv(&[0x4D], &data);
    let mut apdu = vec![0x00, 0xDB, 0x3F, 0xFF];
    apdu.push(blob.len() as u8);
    apdu.extend_from_slice(&blob);
    apdu
}

/// One raw APDU through the dispatcher; returns (body, SW).
fn apdu(dispatcher: &mut Dispatcher<1>, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(apdu, &mut resp);
    assert!(resp.len() >= 2, "response too short for {:x?}", apdu);
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    (resp[..resp.len() - 2].to_vec(), sw)
}

/// One APDU plus GET RESPONSE (INS C0) continuation while the card reports
/// `61XX` — the way scd's apdu.c drains a chunked reply (Le = SW2, or 256
/// when SW2 is 00). Returns the reassembled body and the final SW.
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

/// The gpg generate sequence. `keyed`: additionally build the P7-C5 card
/// shape (three ECC keys + fingerprints) before replaying.
fn run_gpg_generate_sequence(client_id: &str, keyed: bool) {
    opcard::virt::with_ram_client(client_id, |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");

        // SELECT.
        let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
        assert_eq!(sw, SW_OK, "SELECT must answer 9000");

        // GET DATA 0x6E, short Le — scd's does_key_exist (F3/F4). The reply
        // is oversized (S-723 C1), so the read follows 61XX/GET RESPONSE.
        let (body, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0x6E, 0x00]);
        assert_eq!(sw, SW_OK, "GET DATA 6E must answer 9000");
        println!("S-723: 0x6E response body = {} bytes (Le = 256)", body.len());
        let c5_at = body
            .windows(2)
            .position(|w| w == [0xC5, 0x3C])
            .unwrap_or_else(|| panic!("0x6E response lacks `C5 3C` (60 B fingerprints): {:x?}", body));
        assert!(
            body.len() >= c5_at + 2 + 60,
            "0xC5 fingerprint block truncated in 0x6E response"
        );

        // VERIFY PW3 (factory admin PIN).
        let (_, sw) = apdu(
            &mut dispatcher,
            &[0x00, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38],
        );
        assert_eq!(sw, SW_OK, "VERIFY PW3 must answer 9000");

        // US-912: GENERATE is refused while the factory PINs are in force —
        // personalize PW1/PW3 (CHANGE REFERENCE DATA keeps the admin session).
        let (_, sw) = apdu(
            &mut dispatcher,
            &[0x00, 0x24, 0x00, 0x81, 0x0C,
              0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
        );
        assert_eq!(sw, SW_OK, "CHANGE PW1 must answer 9000");
        let (_, sw) = apdu(
            &mut dispatcher,
            &[0x00, 0x24, 0x00, 0x83, 0x10,
              0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
              0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
        );
        assert_eq!(sw, SW_OK, "CHANGE PW3 must answer 9000");

        if keyed {
            // Build the P7-C5-shaped state: three ECC keys + fingerprints.
            // Ed25519 sign (RFC 8032 test vector 1), X25519 dec, Ed25519 aut
            // (RFC 8032 test vector 2).
            let (_, sw) = apdu(
                &mut dispatcher,
                &import_apdu(
                    &[0xB6, 0x00],
                    &hexkey("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"),
                    &hexkey("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"),
                ),
            );
            assert_eq!(sw, SW_OK, "import sign key must answer 9000");
            let (_, sw) = apdu(
                &mut dispatcher,
                &import_apdu(
                    &[0xB8, 0x00],
                    &hexkey("2a2cb91da5fb77b12a99c0eb872f4cdf4566b25172c1163c7da518730a6d0777"),
                    &hexkey("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
                ),
            );
            assert_eq!(sw, SW_OK, "import dec key must answer 9000");
            let (_, sw) = apdu(
                &mut dispatcher,
                &import_apdu(
                    &[0xA4, 0x00],
                    &hexkey("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
                    &hexkey("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
                ),
            );
            assert_eq!(sw, SW_OK, "import aut key must answer 9000");
            // gpg's store_fpr writes per-key fingerprints to C7/C8/C9
            // (20 B each) and generation dates to CE/CF/D0 — never the
            // composite C5 (app-openpgp.c store_fpr).
            //
            // US-972: the generation-date PUT is also where the card computes
            // the fingerprint for itself, so the 0xAB filler below is
            // deliberately *not* what survives. The card ends up holding the
            // real v4 fingerprints of the three imported keys at the date
            // below, and those are what the assertion now pins.
            for tag in [0xC7u8, 0xC8, 0xC9] {
                let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, &[0xABu8; 20]));
                assert_eq!(sw, SW_OK, "PUT DATA {tag:02x} must answer 9000");
            }
            for tag in [0xCEu8, 0xCF, 0xD0] {
                let (_, sw) =
                    apdu(&mut dispatcher, &put_data_apdu(0x00, tag, &[0x20, 0x26, 0x09, 0x19]));
                assert_eq!(sw, SW_OK, "PUT DATA {tag:02x} must answer 9000");
            }

            // does_key_exist re-read on the keyed card.
            let (body, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0x6E, 0x00]);
            assert_eq!(sw, SW_OK);
            assert!(
                body.windows(2).any(|w| w == [0xC5, 0x3C]),
                "keyed card's 0x6E must carry the 60 B 0xC5 fingerprint block"
            );
            let c5_at = body
                .windows(2)
                .position(|w| w == [0xC5, 0x3C])
                .expect("C5 tag present in 0x6E");
            // Sign / Dec / Aut: the three v4 fingerprints the card derives
            // from the imported public keys and the creation date above.
            let mut expected_c5: Vec<u8> = Vec::new();
            for h in [
                "905865fdf1bcd61c55bf2f78648cddba9a43b5c8",
                "183625976457124778b89c7277654357656abe38",
                "3acac51a02225f6a72fe9fe178148972948c5da2",
            ] {
                expected_c5.extend((0..20).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()));
            }
            assert_eq!(
                &body[c5_at + 2..c5_at + 2 + 60],
                &expected_c5[..],
                "US-972: 0x6E's C5 block must hold the fingerprints the card computed"
            );
        }

        // GENERATE — the exact final APDU gpg sends (F1: no algorithm
        // carried; the card's Ed255 attributes govern).
        let (body, sw) = apdu(&mut dispatcher, &[0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00]);
        assert_eq!(sw, SW_OK, "GENERATE must answer 9000, got {:04x}", sw);
        assert_eq!(body.len(), 37, "GENERATE reply must be 37 B");
        assert_eq!(
            &body[..5],
            &[0x7Fu8, 0x49, 0x22, 0x86, 0x20],
            "GENERATE reply must open with `7F 49 22 86 20` (djb-curve point)"
        );
        // The 32 body bytes must be a plausible Ed255 point: not all-zero,
        // not a degenerate constant pattern, and not one of the RFC 8032
        // fixture public keys imported above (a real fresh TRNG point).
        let point = &body[5..37];
        assert!(!point.iter().all(|&b| b == 0), "GENERATE point all-zero");
        assert!(!point.iter().all(|&b| b == 0xFF), "GENERATE point all-FF");
        assert!(
            point.windows(2).any(|w| w[0] != w[1]),
            "GENERATE point is a constant byte pattern"
        );
        for fixture in [
            hexkey("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"),
            hexkey("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
            hexkey("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
        ] {
            assert_ne!(point, &fixture[..], "GENERATE point must be fresh, not a fixture");
        }
    });
}

fn hexkey(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// Card shape 1: keyless (factory) card — `does_key_exist` must read the
/// 60 B all-zero 0xC5 and generation must proceed.
#[test_log::test]
fn gpg_generate_sequence_roundtrip() {
    let id = format!("fapico2-gpg-gen-{}", std::process::id());
    run_gpg_generate_sequence(&id, false);
}

/// Card shape 2: P7-C5-shaped card — ECC keys + fingerprints set (the state
/// the user's board was in, F11/F12); `--force` generation must proceed.
#[test_log::test]
fn gpg_generate_sequence_roundtrip_keyed_card() {
    let id = format!("fapico2-gpg-gen-keyed-{}", std::process::id());
    run_gpg_generate_sequence(&id, true);
}

// ---------------------------------------------------------------------------
// S-723-A2: transport-level reply sizing (candidate C1 fix). gpg's short-Le
// `00 CA 00 6E 00` (Le = 256) met a 272-byte wire reply with no `61XX`/
// GET RESPONSE chunking at the dispatcher seam, so scd's `le + 2` buffer
// truncated it (`does_key_exist` → GPG_ERR_GENERAL, EPIC F3). These tests
// pin the seam contract: honor the request Le, split the remainder as
// `61XX` (remaining count), and reassemble the full body through GET
// RESPONSE (INS C0) round-trips — the upstream opcard vpicc ResponseBuffer
// semantics, ported to the app seam (apps/openpgp/src/device_shell.rs).

/// An oversized 0x6E reply is chunked per the request Le and reassembles
/// byte-identically through GET RESPONSE, whatever the chunk boundaries.
#[test]
fn oversized_6e_chunks_per_le() {
    opcard::virt::with_ram_client("fapico2-openpgp-chunk", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
        assert_eq!(sw, SW_OK, "SELECT must answer 9000");

        // The oversized fixture: full 0x6E body drained via Le = 256
        // (256 bytes) + GET RESPONSE continuation.
        let (full, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0x6E, 0x00]);
        assert_eq!(sw, SW_OK, "GET DATA 6E must complete with 9000");
        assert!(full.len() > 256, "fixture must be oversized: {} B", full.len());

        // Le = 64: first exchange carries exactly 64 bytes + 61XX with the
        // remaining count.
        let (body, sw) = apdu(&mut dispatcher, &[0x00, 0xCA, 0x00, 0x6E, 0x40]);
        assert_eq!(body.len(), 64, "first chunk must honor Le = 64");
        let remaining = full.len() - 64;
        assert_eq!(
            sw,
            0x6100 | u16::from(remaining.min(255) as u8),
            "SW must be 61XX with the remaining count"
        );
        // Drain the rest through GET RESPONSE and reassemble.
        let mut reassembled = body;
        let mut sw = sw;
        while sw != SW_OK {
            assert_eq!(sw & 0xFF00, 0x6100, "only 61XX may extend a reply");
            let le = (sw & 0xFF) as u8;
            let (chunk, next) = apdu(&mut dispatcher, &[0x00, 0xC0, 0x00, 0x00, le]);
            reassembled.extend_from_slice(&chunk);
            sw = next;
        }
        assert_eq!(reassembled, full, "chunked reassembly must be byte-identical");
    });
}

/// A reply that fits the request Le answers 9000 in one exchange with no
/// continuation, and a fresh command restarts the reply window (Le = 0
/// means max 256).
#[test]
fn fitting_reply_answers_9000_in_one_exchange() {
    opcard::virt::with_ram_client("fapico2-openpgp-chunk-fit", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
        assert_eq!(sw, SW_OK, "SELECT must answer 9000");

        // Exact Le: the 60 B fingerprint DO with Le = 60 → 9000, 60 bytes.
        let (body, sw) = apdu(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xC5, 0x3C]);
        assert_eq!(sw, SW_OK, "exact-Le read must answer 9000, got {:04x}", sw);
        assert_eq!(body.len(), 60, "exact-Le read must carry the full DO");
        assert!(
            body.iter().all(|&b| b == 0),
            "factory fingerprints are all-zero on a keyless card"
        );

        // Le = 0 means max 256: the 9 B cardholder DO still answers 9000 in
        // one exchange (regression guard for the S-721-2-pinned shape).
        let (body, sw) = apdu(&mut dispatcher, &[0x00, 0xCA, 0x00, 0x65, 0x00]);
        assert_eq!(sw, SW_OK, "Le = 0 short reply must answer 9000");
        assert_eq!(
            body,
            vec![0x5B, 0x00, 0x5F, 0x2D, 0x00, 0x5F, 0x35, 0x01, 0x30],
            "cardholder DO shape must be unchanged"
        );
    });
}

// ---------------------------------------------------------------------------
// S-724 (supersedes the S-723-C1 / S-723-A3 ECC-only generation contract, per
// the controller directive that the card must accept RSA, secp256k1 and every
// other algorithm the stack serves): the platform dispatch now carries the
// software-RSA backend (`trussed_rsa_alloc::SoftwareRsa`, `rsa-backend`
// feature) and opcard is enabled with `rsa4096-gen`, so a PUT DATA of the
// RSA-2048 attribute triple (`01 08 00 00 20 00`) is **accepted and stored**
// (9000) — gpg's keyattr menu and Kleopatra's algorithm dropdown can switch
// the card to RSA, matching the C reference firmware (`do.c` `parse_algoinfo`
// advertises RSA 1k–4k; `cmd_keypair_gen.c` generates it). These tests pin:
//
//   1. PUT DATA of the RSA-2048 attribute for the signature DO (tag C1) is
//      accepted (9000) and stored — gpg keyattr → RSA must not bounce;
//   2. a GENERATE for the RSA-2048 signature key produces an RSA public key
//      (INS 47 read-back carries the RSA modulus format, not an ECC OID);
//   3. a valid ECC attribute (Ed255) stays accepted and stored.
//
// The virt client already routes RSA to SoftwareRsa (opcard's own virt
// dispatch), and the device path routes it through the platform
// `OpcardDispatch` `Backend::Rsa` arm — both exercise the same opcard
// request paths this test drives.

/// RSA-2048 attribute bytes (types.rs `RSA_2K_ATTRIBUTES`).
const RSA_2K_ATTR: &[u8] = &[0x01, 0x08, 0x00, 0x00, 0x20, 0x00];
/// Ed255 attribute bytes (types.rs `ED255_ATTRIBUTES_PK`).
const ED255_ATTR_PK: &[u8] = &[0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01, 0xFF];

/// Factory card + SELECT + PW3 verification (attribute PUTs are admin-authorized).
fn verified_card(dispatcher: &mut Dispatcher<1>) {
    let (_, sw) = apdu(dispatcher, &select_openpgp());
    assert_eq!(sw, SW_OK, "SELECT must answer 9000");
    let (_, sw) = apdu(
        dispatcher,
        &[0x00, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38],
    );
    assert_eq!(sw, SW_OK, "VERIFY PW3 must answer 9000");
}

/// PUT DATA of the RSA-2048 attribute for the signature DO (tag C1) must
/// answer 9000 and be stored — gpg keyattr → RSA must not bounce (S-724).
#[test]
fn put_rsa_attr_accepted_and_stored() {
    opcard::virt::with_ram_client("fapico2-openpgp-attr-rsa", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // Baseline: the factory attribute (Ed255) is stored and readable.
        let (baseline, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xC1, 0x00]);
        assert_eq!(sw, SW_OK, "GET DATA C1 must answer 9000");
        assert_eq!(baseline, ED255_ATTR_PK, "factory C1 must be Ed255 attrs");

        // gpg keyattr → RSA: `00 DA 00 C1` + `01 08 00 00 20 00` → 9000.
        let (_, sw) = apdu(
            &mut dispatcher,
            &put_data_apdu(0x00, 0xC1, RSA_2K_ATTR),
        );
        assert_eq!(
            sw, SW_OK,
            "PUT DATA RSA-2048 attribute must answer 9000, got {:04x}",
            sw
        );

        // The stored attribute is now the RSA-2048 attribute.
        let (after, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xC1, 0x00]);
        assert_eq!(sw, SW_OK, "GET DATA C1 after PUT must answer 9000");
        assert_eq!(
            after, RSA_2K_ATTR,
            "stored C1 must be the RSA-2048 attribute after PUT DATA"
        );
    });
}

/// GENERATE for the signature key after switching the attributes to RSA-2048
/// produces an RSA public key: the INS 47 read-back body starts with the
/// modulus byte format (81/82 = raw RSA), never the ECC OID prefix
/// (0x40/0x2B...) of an Ed255 key (S-724).
#[test]
fn generate_rsa_key_returns_rsa_public_key() {
    opcard::virt::with_ram_client("fapico2-openpgp-gen-rsa", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        let (_, sw) = apdu(
            &mut dispatcher,
            &put_data_apdu(0x00, 0xC1, RSA_2K_ATTR),
        );
        assert_eq!(sw, SW_OK, "PUT DATA RSA-2048 attribute must answer 9000");

        // US-912: GENERATE is refused while the factory PINs are in force —
        // personalize PW1/PW3 (CHANGE REFERENCE DATA keeps the admin session).
        let (_, sw) = apdu(
            &mut dispatcher,
            &[0x00, 0x24, 0x00, 0x81, 0x0C,
              0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
        );
        assert_eq!(sw, SW_OK, "CHANGE PW1 must answer 9000");
        let (_, sw) = apdu(
            &mut dispatcher,
            &[0x00, 0x24, 0x00, 0x83, 0x10,
              0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
              0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
        );
        assert_eq!(sw, SW_OK, "CHANGE PW3 must answer 9000");

        // GENERATE ASYMMETRIC KEY PAIR, signature key (Crt B6), no Le.
        // The RSA-2048 public template exceeds the short buffer, so the
        // reply follows 61XX/GET RESPONSE (apdu_read drains it).
        let mut gen = vec![0x00u8, 0x47, 0x80, 0x00, 0x02];
        gen.extend_from_slice(&[0xB6, 0x00]);
        gen.push(0x00);
        let (body, sw) = apdu_read(&mut dispatcher, &gen);
        assert_eq!(sw, SW_OK, "GENERATE RSA must answer 9000, got {:04x}", sw);
        assert!(
            !body.is_empty(),
            "GENERATE RSA must return the public key template"
        );
        // The response is a 7F49 template carrying the public key; the RSA
        // encoding uses `81 <len> <modulus>` (modulus byte format), while an
        // ECC key would start with the curve OID (`2B 06 01 04 01 ...` for
        // Ed255). Pin the RSA shape, not the exact modulus bytes.
        assert!(
            body.windows(3).any(|w| w[0] == 0x81 || w[0] == 0x82),
            "GENERATE RSA must carry a modulus-format public key"
        );
        assert_eq!(
            body.windows(2).position(|w| w == [0x2B, 0x06]),
            None,
            "GENERATE RSA must not return an ECC OID-encoded key"
        );
    });
}

// ---------------------------------------------------------------------------
// US-943: the RSA attribute's import-format nibble (last byte of the
// attribute — types.rs `RSA_2K_ATTRIBUTES`) has a pinned, decided policy
// ("reject-CRT", laya consultation recorded in docs/tasks/us943-rsa-nibble.md):
//
//   nibble 00 (standard)          → accepted (gpg/scdaemon's default spelling)
//   nibble 01 (standard, with n)  → accepted
//   nibble 02 (CRT)               → rejected with exactly 6A80 at PUT DATA
//   nibble 03 (CRT, with n)       → rejected with exactly 6A80 at PUT DATA
//   any other value (e.g. 04)     → rejected with exactly 6A80 at PUT DATA
//
// Rationale: the card never implements CRT private-key storage, so silently
// accepting a CRT spelling would mislead hosts. Independently of the nibble,
// key import always expects the `91/92/93` (e,p,q) template and GENERATE
// always outputs the standard `N,E` template — the nibble is irrelevant to
// runtime behavior, which is pinned by importing after a nibble-01 PUT.

/// US-943 nibble policy, virt path: 00/01 accepted (read-back is the
/// canonical standard spelling), 02/03/04 refused with 6A80 and no state
/// change; import works after a nibble-01 attribute PUT (runtime behavior
/// ignores the nibble).
#[test]
fn put_rsa_attr_nibble_policy_reject_crt() {
    opcard::virt::with_ram_client("fapico2-openpgp-attr-nibble", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // Nibble 00 — the gpg/scdaemon default spelling — is accepted and
        // read back unchanged.
        let attr_00: &[u8] = &[0x01, 0x08, 0x00, 0x00, 0x20, 0x00];
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC1, attr_00));
        assert_eq!(
            sw, SW_OK,
            "PUT DATA C1 RSA attribute nibble 00 must answer 9000, got {:04x}",
            sw
        );
        let (stored, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xC1, 0x00]);
        assert_eq!(sw, SW_OK, "GET DATA C1 after nibble-00 PUT must answer 9000");
        assert_eq!(stored, attr_00, "nibble-00 attribute must be stored as sent");

        // Nibble 01 (standard format with n) is accepted too; the card
        // stores the algorithm, not the raw bytes, so read-back is the
        // canonical standard (nibble-00) spelling.
        let attr_01: &[u8] = &[0x01, 0x08, 0x00, 0x00, 0x20, 0x01];
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC1, attr_01));
        assert_eq!(
            sw, SW_OK,
            "PUT DATA C1 RSA attribute nibble 01 must answer 9000, got {:04x}",
            sw
        );
        let (stored, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xC1, 0x00]);
        assert_eq!(sw, SW_OK, "GET DATA C1 after nibble-01 PUT must answer 9000");
        assert_eq!(
            stored, attr_00,
            "read-back must be the canonical standard attribute (nibble 00)"
        );

        // Runtime behavior ignores the nibble: key import (PUT KEY, the
        // always-e,p,q `91/92/93` template) succeeds under the nibble-01
        // attribute. (GENERATE likewise emits the standard `N,E` template —
        // pinned by `generate_rsa_key_returns_rsa_public_key` with nibble 00;
        // the stored state is the same algorithm enum either way.)
        personalize_pins(&mut dispatcher);
        let k = &*RSA_TEST_KEY;
        let (_, sw) = apdu(&mut dispatcher, &put_key_rsa_apdu(&[0xB6, 0x00], &k.e, &k.p, &k.q));
        assert_eq!(
            sw, SW_OK,
            "PUT KEY RSA (e,p,q) after nibble-01 attribute must answer 9000, got {:04x}",
            sw
        );

        // CRT (02, 03) and out-of-spec (04) nibbles are refused with exactly
        // 6A80, and the stored attribute is untouched by the refused PUT.
        for nibble in [0x02u8, 0x03, 0x04] {
            let attr_crt = [0x01u8, 0x08, 0x00, 0x00, 0x20, nibble];
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC1, &attr_crt));
            assert_eq!(
                sw, 0x6A80,
                "PUT DATA C1 RSA attribute nibble {nibble:02x} must be refused with 6A80, got {:04x}",
                sw
            );
            let (stored, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xC1, 0x00]);
            assert_eq!(sw, SW_OK, "GET DATA C1 after refused PUT must answer 9000");
            assert_eq!(
                stored, attr_00,
                "a refused PUT must leave the stored attribute unchanged"
            );
        }
    });
}

/// A valid ECC (Ed255) attribute for the signature DO is still accepted and
/// stored — the gate rejects only un-generatable algorithms.
#[test]
fn put_ecc_attr_still_accepted() {
    opcard::virt::with_ram_client("fapico2-openpgp-attr-ecc", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        let (_, sw) = apdu(
            &mut dispatcher,
            &put_data_apdu(0x00, 0xC1, ED255_ATTR_PK),
        );
        assert_eq!(sw, SW_OK, "PUT DATA Ed255 attribute must answer 9000, got {:04x}", sw);

        let (stored, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xC1, 0x00]);
        assert_eq!(sw, SW_OK, "GET DATA C1 must answer 9000");
        assert_eq!(stored, ED255_ATTR_PK, "Ed255 attribute must be stored");
    });
}

// ---------------------------------------------------------------------------
// US-945: Brainpool attributes in the AllowedAlgorithms defaults. US-944
// landed the software Brainpool backend for P-256r1 + P-384r1 only (no
// `bp512` crate exists in the ecosystem — docs/known-gate-divergences.md
// US-944 entry), so `default_gen()`/`default_import()` admit
// `BRAINPOOL_P256R1` and `BRAINPOOL_P384R1` (behind opcard's
// `brainpool-backend` feature, mirroring the `rsaXX-gen`/`rsaXX` flag
// gating) but never `BRAINPOOL_P512R1`. These tests pin:
//
//   1. PUT DATA with the Brainpool P-256r1/P-384r1 attributes is accepted on
//      every slot DO — C1 (sign, ECDSA `13…`), C2 (dec, ECDH `12…`), C3
//      (aut, ECDSA `13…`) — and read back in the PK-normalized form
//      (the `… FF` spelling, types.rs `*_BRAINPOOL_*_ATTRIBUTES_PK`);
//   2. the fail-closed gate (`ensure_alg_allowed`, command/data.rs) still
//      rejects a genuinely unknown OID with 6A80;
//   3. Brainpool P-512r1 is refused with 6A80 on every slot — the recorded
//      scope divergence (no backend), fail-closed, not an accident.

/// Brainpool attribute bytes (types.rs `*_BRAINPOOL_*_ATTRIBUTES`): tag
/// 0x13 = ECDSA, 0x12 = ECDH; curve OID prefix
/// 1.3.36.3.3.2.8.1.1 (`2B 24 03 03 02 08 01 01`), suffixed 07 (P-256r1),
/// 0B (P-384r1), 0D (P-512r1).
const ECDSA_BRAINPOOL_P256R1_ATTR: &[u8] =
    &[0x13, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
const ECDH_BRAINPOOL_P256R1_ATTR: &[u8] =
    &[0x12, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
const ECDSA_BRAINPOOL_P384R1_ATTR: &[u8] =
    &[0x13, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];
const ECDH_BRAINPOOL_P384R1_ATTR: &[u8] =
    &[0x12, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];
const ECDSA_BRAINPOOL_P512R1_ATTR: &[u8] =
    &[0x13, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D];
const ECDH_BRAINPOOL_P512R1_ATTR: &[u8] =
    &[0x12, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D];
const ECDSA_BRAINPOOL_P256R1_ATTR_PK: &[u8] =
    &[0x13, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07, 0xFF];
const ECDH_BRAINPOOL_P256R1_ATTR_PK: &[u8] =
    &[0x12, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07, 0xFF];
// US-966: the `_PK` (PK-normalized) P-384r1 spellings are gone with the
// curve. Nothing stores a P-384r1 attribute any more, so nothing asserts what
// it would normalize to; the refusal tests compare against each slot's factory
// value instead, which is the stronger statement.

/// US-945, virt path: the Brainpool P-256r1 ECDSA/ECDH attributes are
/// accepted on every slot DO and stored in the PK-normalized form.
///
/// US-966 (2026-09-27): this test used to run the same three slots for
/// P-384r1 as well. Those arms were **inverted**, not deleted: the P-384r1
/// spellings are now refused with `6A80` and leave each slot at its factory
/// value, which is asserted in
/// `put_never_served_brainpool_curves_and_unknown_oid_rejected`
/// alongside the other never-served curves. The P-256r1 arms below are
/// untouched — that is the curve US-966 kept.
#[test]
fn put_brainpool_attrs_accepted_and_stored_all_slots() {
    opcard::virt::with_ram_client("fapico2-openpgp-attr-brainpool", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        for (tag, attr, attr_pk, slot) in [
            (0xC1u8, ECDSA_BRAINPOOL_P256R1_ATTR, ECDSA_BRAINPOOL_P256R1_ATTR_PK, "C1/sign"),
            (0xC2, ECDH_BRAINPOOL_P256R1_ATTR, ECDH_BRAINPOOL_P256R1_ATTR_PK, "C2/dec"),
            (0xC3, ECDSA_BRAINPOOL_P256R1_ATTR, ECDSA_BRAINPOOL_P256R1_ATTR_PK, "C3/aut"),
        ] {
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, attr));
            assert_eq!(
                sw, SW_OK,
                "PUT DATA {slot} Brainpool attribute must answer 9000, got {:04x}",
                sw
            );
            let (stored, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, tag, 0x00]);
            assert_eq!(sw, SW_OK, "GET DATA {tag:02X} after PUT must answer 9000");
            assert_eq!(
                stored, attr_pk,
                "stored {slot} must be the PK-normalized Brainpool attribute"
            );
        }
    });
}

/// US-945/US-966, virt path: the fail-closed gate survives — the two curves
/// this card deliberately does not serve and a genuinely unknown OID are all
/// refused with 6A80 on every slot, and a refused PUT leaves the stored
/// attribute untouched.
///
/// * Brainpool P-512r1 — no backend, and never was (US-944: no `bp512` crate
///   exists in the ecosystem).
/// * Brainpool P-384r1 — served under US-945 and **deferred by US-966**
///   (2026-09-27) for want of deployment pull: OpenPGP card spec v3.4 §4.4.3.10
///   requires only that "at least one of this curves shall be supported"
///   (NIST P-256/384/521 already satisfies it), RFC 8734 deprecated Brainpool
///   for TLS 1.3 "because they had little usage … not endorsed by the IETF",
///   and no OpenPGP-card user of P-384r1 was found. It is **not** deferred
///   for being broken — its signing was never measured on hardware.
#[test]
fn put_never_served_brainpool_curves_and_unknown_oid_rejected() {
    opcard::virt::with_ram_client("fapico2-openpgp-attr-brainpool-reject", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // Per-slot factory baselines the refused PUTs must not disturb
        // (factory: C1/C3 Ed255, C2 X255).
        let mut baselines = heapless::Vec::<(u8, Vec<u8>), 3>::new();
        for tag in [0xC1u8, 0xC2, 0xC3] {
            let (stored, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, tag, 0x00]);
            assert_eq!(sw, SW_OK, "GET DATA {tag:02X} baseline must answer 9000");
            baselines.push((tag, stored)).unwrap();
        }

        // Suffix 09 in the brainpoolPxxxr1 OID family
        // (1.3.36.3.3.2.8.1.1.09) does not exist — genuinely unknown OID.
        let unknown_oid: &[u8] = &[0x13, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09];
        for (tag, data, name) in [
            (0xC1u8, ECDSA_BRAINPOOL_P512R1_ATTR, "C1/sign ECDSA P-512r1"),
            (0xC2, ECDH_BRAINPOOL_P512R1_ATTR, "C2/dec ECDH P-512r1"),
            (0xC3, ECDSA_BRAINPOOL_P512R1_ATTR, "C3/aut ECDSA P-512r1"),
            (0xC1, ECDSA_BRAINPOOL_P384R1_ATTR, "C1/sign ECDSA P-384r1 (deferred, US-966)"),
            (0xC2, ECDH_BRAINPOOL_P384R1_ATTR, "C2/dec ECDH P-384r1 (deferred, US-966)"),
            (0xC3, ECDSA_BRAINPOOL_P384R1_ATTR, "C3/aut ECDSA P-384r1 (deferred, US-966)"),
            (0xC1, unknown_oid, "C1/sign unknown OID"),
            (0xC2, unknown_oid, "C2/dec unknown OID"),
            (0xC3, unknown_oid, "C3/aut unknown OID"),
        ] {
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, data));
            assert_eq!(
                sw, 0x6A80,
                "PUT DATA {name} must be refused with 6A80, got {:04x}",
                sw
            );
            let (stored, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, tag, 0x00]);
            assert_eq!(sw, SW_OK, "GET DATA {tag:02X} after refused PUT must answer 9000");
            let baseline = &baselines.iter().find(|(t, _)| *t == tag).unwrap().1;
            assert_eq!(
                &stored, baseline,
                "a refused PUT ({name}) must leave the stored attribute unchanged"
            );
        }
    });
}

/// READ PUBLIC KEY contract (F7): with ECC attributes and no key on the
/// card, INS 47 P1=81 answers 6A88 (key reference not found) — never 6A81
/// (function not supported), which would break the "attrs say X ⇒ the key
/// can be read or is absent" contract gpg's scd relies on.
#[test]
fn read_pubkey_never_6a81_without_key() {
    opcard::virt::with_ram_client("fapico2-openpgp-readpub", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
        assert_eq!(sw, SW_OK, "SELECT must answer 9000");

        for (crt, name) in
            [(&[0xB6u8, 0x00][..], "sign"), (&[0xB8u8, 0x00][..], "dec"), (&[0xA4u8, 0x00][..], "aut")]
        {
            let mut read = vec![0x00u8, 0x47, 0x81, 0x00, 0x02];
            read.extend_from_slice(crt);
            read.push(0x00);
            let (_, sw) = apdu(&mut dispatcher, &read);
            assert!(
                sw == SW_OK || sw == 0x6A88,
                "READ PUBLIC KEY ({name}) on a keyless ECC card must answer 9000 or 6A88, got {:04x}",
                sw
            );
            assert_ne!(
                sw, 0x6A81,
                "READ PUBLIC KEY ({name}) must never answer 6A81 while attrs are ECC (F7)"
            );
        }
    });
}

/// US-711 (factory reset): [`OpenPgpApp::factory_wipe`] re-initializes the
/// card in RAM — `opcard::Card::reset` drops the volatile authentication and
/// restores the factory-default card state, so the pre-reset card state can
/// never be re-persisted by the persist gate (the durable OpenPGP secure
/// store slots are deleted by the management RESET hook itself). Here: a
/// changed PW1 stops verifying after the wipe and the factory-default PIN
/// verifies again; the wipe also clears the app dirtiness, so the persist
/// gate has nothing to flush.
#[test]
fn factory_wipe_reinitializes_card_in_ram() {
    use fapico2_platform::dispatch::App;
    use fapico2_platform::secure_store::HostSecureStore;

    opcard::virt::with_ram_client("fapico2-openpgp-factory-reset", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
        assert_eq!(sw, SW_OK, "SELECT must answer 9000");

        // Seed a volatile-authenticated session: VERIFY PW1 (the factory
        // default), then an empty VERIFY PW1 — answered 9000 because the
        // session is already validated in RAM.
        let verify_pin = |dispatcher: &mut Dispatcher<1>, pin: &[u8]| {
            let mut verify = vec![0x00u8, 0x20, 0x00, 0x81, pin.len() as u8];
            verify.extend_from_slice(pin);
            verify.push(0x00);
            apdu(dispatcher, &verify).1
        };
        assert_eq!(verify_pin(&mut dispatcher, b"123456"), SW_OK);
        let (empty, sw) = apdu(&mut dispatcher, &[0x00, 0x20, 0x00, 0x81, 0x00]);
        assert_eq!(sw, SW_OK, "empty VERIFY while authenticated must answer 9000");
        assert!(empty.is_empty(), "empty VERIFY must not carry a reply body");

        // The management RESET hook's dispatcher-level wipe (sole `&mut`
        // per app, exactly what the CCID task runs).
        dispatcher.factory_wipe_apps();

        // In-RAM re-init: the volatile authentication is gone — the same
        // empty VERIFY now answers the retry-counter status (63 xx), not
        // 9000 — and the factory-default PW1 verifies again.
        let (_, sw) = apdu(&mut dispatcher, &[0x00, 0x20, 0x00, 0x81, 0x00]);
        assert_ne!(
            sw, SW_OK,
            "the volatile PW1 authentication must be cleared by the wipe"
        );
        assert_eq!(
            verify_pin(&mut dispatcher, b"123456"),
            SW_OK,
            "the factory-default PW1 must verify after the wipe"
        );
    });

    // The persist gate has nothing to flush: the wipe cleared the app
    // dirtiness (a dirty app would ask the gate to re-persist the pre-reset
    // snapshot the wipe deleted). Fresh app + dispatcher (the first
    // dispatcher holds the registration borrow for its whole scope).
    opcard::virt::with_ram_client("fapico2-openpgp-factory-reset-dirty", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut store = HostSecureStore::new();
        App::mark_dirty(&mut app);
        assert!(App::is_dirty(&app));
        {
            let mut dispatcher: Dispatcher<1> = Dispatcher::new();
            assert!(dispatcher.register(&mut app), "register openpgp app");
            dispatcher.factory_wipe_apps();
        }
        assert!(
            !App::is_dirty(&app) && !App::persist_state(&mut app, &mut store),
            "factory_wipe must clear even a marked-dirty app"
        );
    });
}

// ---------------------------------------------------------------------------
// US-934: a stable, non-zero per-device serial number in the Application ID.
//
// GET DATA `4F` composes the AID from `opcard::Options` (vendor/opcard
// `card.rs::aid`): RID+PIX+version, manufacturer (2 B), serial (4 B),
// RFU `00 00`. This token keeps the reserved test manufacturer `00 00`
// (OQ-1) and provisions a random, persisted serial (OQ-5) at first boot;
// the serial lives in a trussed `Location::Internal` file next to the
// opcard state, so a plain reboot never changes it (the US-912 gate-flag
// durability discipline).
//
// The reboot shape here is the `pw_status_resume.rs` remount: one backing
// internal-FS buffer leaked for the process lifetime, remounted per boot
// with fresh volatile state.

/// GET DATA 4F body through a registered dispatcher: the 16-byte AID.
fn aid_of(dispatcher: &mut Dispatcher<1>) -> Vec<u8> {
    let (body, sw) = apdu(dispatcher, &[0x00, 0xCA, 0x00, 0x4F, 0x00]);
    assert_eq!(sw, SW_OK, "GET DATA 4F must answer 9000");
    assert_eq!(body.len(), 16, "AID is 16 bytes (spec §4.2.1)");
    body
}

/// Boot an OpenPGP app over a remount of `internal` (the persisted
/// internal FS) and read the AID (SELECT first — GET DATA needs the app
/// selected).
fn boot_and_read_aid(internal: *mut [u8]) -> Vec<u8> {
    let ram = HostStore::fresh();
    fapico2_platform::trusted_backend::runner::with_backend(
        HostPlatform::with_store(HostStore::new(mount_fs::<256>(internal), ram.efs, ram.vfs)),
        OpcardDispatch::new(),
        "opcard",
        |client| {
            let mut app = OpenPgpApp::new(client);
            let mut dispatcher = Dispatcher::<1>::new();
            assert!(dispatcher.register(&mut app));
            let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
            assert_eq!(sw, SW_OK, "SELECT AID must answer 9000");
            aid_of(&mut dispatcher)
        },
    )
}

#[test]
fn aid_template_conformance() {
    let internal = leak_buf(256 * 4096);
    let aid = boot_and_read_aid(internal);
    // RID D2 76, 00 01 24 01, version 03 04 (spec §4.2.1 layout intact).
    assert_eq!(&aid[..8], &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04]);
    // Manufacturer keeps the reserved test value 00 00 (OQ-1)…
    assert_eq!(&aid[8..10], &[0x00, 0x00], "manufacturer is the test value");
    // …and the AID ends with the two RFU bytes.
    assert_eq!(&aid[14..16], &[0x00, 0x00]);
}

#[test]
fn serial_is_not_all_zero_on_fresh_card() {
    let internal = leak_buf(256 * 4096);
    let aid = boot_and_read_aid(internal);
    assert_ne!(
        &aid[10..14],
        &[0x00, 0x00, 0x00, 0x00],
        "first-boot AID serial must not be all zeros"
    );
}

// ---------------------------------------------------------------------------
// US-936: CHANGE REFERENCE DATA (INS 0x24) with the old PIN omitted. When the
// reference data was already verified this session (volatile state) and the
// command data carries exactly the current PIN's length, `data` is the NEW
// PIN (spec §7.2.3 pinpad / verified-session flows). The three TDD tests run
// against the registered dispatcher, like the rest of this file.

/// VERIFY PW3 with the factory admin PIN.
fn verify_pw3(dispatcher: &mut Dispatcher<1>, pin: &[u8]) -> u16 {
    let mut apdu_bytes = vec![0x00u8, 0x20, 0x00, 0x83, pin.len() as u8];
    apdu_bytes.extend_from_slice(pin);
    apdu(dispatcher, &apdu_bytes).1
}

/// CHANGE REFERENCE DATA for PW3 with raw `data`.
fn crd_pw3(dispatcher: &mut Dispatcher<1>, data: &[u8]) -> u16 {
    let mut apdu_bytes = vec![0x00u8, 0x24, 0x00, 0x83, data.len() as u8];
    apdu_bytes.extend_from_slice(data);
    apdu(dispatcher, &apdu_bytes).1
}

const OLD_ADMIN: &[u8] = b"12345678";
const NEW_ADMIN: &[u8] = b"87654321";

/// TDD (RED first): after the Admin PIN has been verified in this session,
/// CRD(0x24, P1=0, P2=0x83, data = new PIN only) answers 9000 and VERIFY
/// with the new PIN succeeds. RED today: the new-only data is either
/// rejected by the `2 * min_len` gate (6700) or mis-split as old‖new and
/// verified as the old PIN (63C3).
#[test]
fn crd_with_only_new_pin_after_admin_verify_succeeds() {
    opcard::virt::with_ram_client("fapico2-openpgp-crd-newonly", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
        assert_eq!(sw, SW_OK, "SELECT must answer 9000");

        assert_eq!(verify_pw3(&mut dispatcher, OLD_ADMIN), SW_OK);

        let sw = crd_pw3(&mut dispatcher, NEW_ADMIN);
        assert_eq!(
            sw, SW_OK,
            "CRD with new-PIN-only after PW3 verify must answer 9000, got {:04x}",
            sw
        );

        assert_eq!(
            verify_pw3(&mut dispatcher, NEW_ADMIN),
            SW_OK,
            "the new admin PIN must verify after the change"
        );
        assert_ne!(
            verify_pw3(&mut dispatcher, OLD_ADMIN),
            SW_OK,
            "the old admin PIN must no longer verify"
        );
    });
}

/// Guard (unchanged behavior): without an admin verification the old‖new
/// shape still works, and an unverified host sending new-PIN-only data is
/// refused with the PIN unchanged. Length-leak ordering is preserved: the
/// new-only shape is only honored for a verified session, so the unverified
/// response profile stays exactly the legacy one — for the 8-byte new-only
/// data that is WrongLength (6700) from the `2 * min_len` gate, the same
/// answer any sub-16-byte data gets; answering 63C3 there instead would
/// leak the stored PIN length to unverified hosts.
#[test]
fn crd_without_admin_verify_still_requires_old_pin() {
    // old‖new still works without a prior VERIFY in the same session.
    opcard::virt::with_ram_client("fapico2-openpgp-crd-oldnew", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
        assert_eq!(sw, SW_OK, "SELECT must answer 9000");

        let mut data = Vec::from(OLD_ADMIN);
        data.extend_from_slice(NEW_ADMIN);
        let sw = crd_pw3(&mut dispatcher, &data);
        assert_eq!(sw, SW_OK, "CRD old‖new must answer 9000, got {:04x}", sw);
        assert_eq!(
            verify_pw3(&mut dispatcher, NEW_ADMIN),
            SW_OK,
            "the new admin PIN must verify after the change"
        );
    });

    // Unverified host, new-PIN-only: refused, PIN unchanged.
    opcard::virt::with_ram_client("fapico2-openpgp-crd-unverified", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
        assert_eq!(sw, SW_OK, "SELECT must answer 9000");

        let sw = crd_pw3(&mut dispatcher, NEW_ADMIN);
        assert_ne!(
            sw, SW_OK,
            "unverified CRD with new-PIN-only must be refused"
        );
        assert_eq!(
            verify_pw3(&mut dispatcher, OLD_ADMIN),
            SW_OK,
            "the admin PIN must be unchanged after the refusal"
        );
    });
}

/// Guard (length-leak ordering): short data answers WrongLength before any
/// state change — both unverified and in a verified session (where the
/// length cannot be the new-only shape).
#[test]
fn crd_short_data_is_rejected_before_new_pin_use() {
    for verified in [false, true] {
        let id = format!("fapico2-openpgp-crd-short-{}", verified);
        opcard::virt::with_ram_client(&id, |client| {
            let mut app = OpenPgpApp::new(client);
            let mut dispatcher: Dispatcher<1> = Dispatcher::new();
            assert!(dispatcher.register(&mut app), "register openpgp app");
            let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
            assert_eq!(sw, SW_OK, "SELECT must answer 9000");
            if verified {
                assert_eq!(verify_pw3(&mut dispatcher, OLD_ADMIN), SW_OK);
            }

            let sw = crd_pw3(&mut dispatcher, b"12");
            assert_eq!(
                sw, 0x6700,
                "short CRD data must answer WrongLength (verified={verified})"
            );
            assert_eq!(
                verify_pw3(&mut dispatcher, OLD_ADMIN),
                SW_OK,
                "the admin PIN must be unchanged (verified={verified})"
            );
        });
    }
}

/// US-936 OQ-3/OQ-4 at the parse seam: INS 0x21 is accepted as the spec
/// §7.2.3 alias for CHANGE REFERENCE DATA, and P1=1 (on-card PIN-pad
/// verification, not implemented at this seam) is answered with the clear
/// status ConditionsOfUseNotSatisfied (6985) instead of 6A86.
#[test]
fn crd_ins_0x21_alias_and_p1_1_clear_status() {
    opcard::virt::with_ram_client("fapico2-openpgp-crd-alias", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
        assert_eq!(sw, SW_OK, "SELECT must answer 9000");

        // P1=1 → clear status 6985 (ConditionsOfUseNotSatisfied, OQ-3).
        let (_, sw) = apdu(&mut dispatcher, &[0x00, 0x24, 0x01, 0x83, 0x00]);
        assert_eq!(
            sw, 0x6985,
            "CRD P1=1 must answer the clear ConditionsOfUseNotSatisfied, got {:04x}",
            sw
        );

        // INS 0x21 alias works end to end (OQ-4) — after VERIFY, new-only.
        assert_eq!(verify_pw3(&mut dispatcher, OLD_ADMIN), SW_OK);
        let mut apdu_bytes = vec![0x00u8, 0x21, 0x00, 0x83, NEW_ADMIN.len() as u8];
        apdu_bytes.extend_from_slice(NEW_ADMIN);
        let (_, sw) = apdu(&mut dispatcher, &apdu_bytes);
        assert_eq!(sw, SW_OK, "CRD via INS 0x21 alias must answer 9000");
        assert_eq!(
            verify_pw3(&mut dispatcher, NEW_ADMIN),
            SW_OK,
            "the new admin PIN must verify after the 0x21 change"
        );
    });
}

#[test]
fn serial_is_stable_across_boot() {
    let internal = leak_buf(256 * 4096);

    let first = boot_and_read_aid(internal);
    assert_ne!(
        &first[10..14],
        &[0x00, 0x00, 0x00, 0x00],
        "the provisioned serial must be meaningful (not zeros)"
    );
    // Boot 2: fresh volatile state over the SAME persisted internal FS.
    let second = boot_and_read_aid(internal);
    assert_eq!(
        first[10..14],
        second[10..14],
        "the serial must survive a reboot unchanged"
    );

    // Two freshly provisioned cards (separate persisted state) differ —
    // the BDD "unique per device" scenario (1/2^32 collision odds from the
    // random draw).
    let other = leak_buf(256 * 4096);
    let other_aid = boot_and_read_aid(other);
    assert_ne!(
        first[10..14], other_aid[10..14],
        "two freshly provisioned cards must get different serials"
    );
}

// ---------------------------------------------------------------------------
// US-150: the AID serial is read by hosts as packed BCD.
//
// `AID[10..14]` (§4.2.1) is four bytes of packed BCD: the client decodes it
// digit-per-nibble with no validity check, so a nibble above 9 renders as a
// garbage decimal serial even though the card considers the value valid. The
// draw therefore folds each nibble modulo ten (`device_shell::to_bcd`) —
// pinned exhaustively in the `device_shell` unit tests; what is checked here
// is that the folded value is the one that reaches the AID, and that an
// already-persisted serial is never re-folded.

/// Boot an app over `internal` after seeding the trussed serial file with
/// `serial`, then read the AID — the "card provisioned before the fold
/// existed" shape, where the stored bytes are not canonical BCD.
fn boot_with_persisted_serial(internal: *mut [u8], serial: [u8; 4]) -> Vec<u8> {
    use trussed_core::types::{Location, PathBuf};

    let ram = HostStore::fresh();
    fapico2_platform::trusted_backend::runner::with_backend(
        HostPlatform::with_store(HostStore::new(mount_fs::<256>(internal), ram.efs, ram.vfs)),
        OpcardDispatch::new(),
        "opcard",
        |mut client| {
            // The file name is `provision_serial`'s persistence contract;
            // it is repeated here so a rename of that contract fails this
            // test instead of silently re-provisioning.
            use trussed_core::FilesystemClient as _;
            let path = PathBuf::try_from("us934-serial").unwrap();
            let data = trussed_core::types::Message::try_from(serial.as_slice()).unwrap();
            trussed_core::syscall!(client.write_file(Location::Internal, path, data, None));

            let mut app = OpenPgpApp::new(client);
            let mut dispatcher = Dispatcher::<1>::new();
            assert!(dispatcher.register(&mut app));
            let (_, sw) = apdu(&mut dispatcher, &select_openpgp());
            assert_eq!(sw, SW_OK, "SELECT AID must answer 9000");
            aid_of(&mut dispatcher)
        },
    )
}

/// A serial drawn at first boot is packed BCD: every nibble of `AID[10..14]`
/// is a decimal digit. The fold itself is unit-tested over the whole byte
/// range; this pins that the AID actually carries the folded bytes.
#[test]
fn freshly_drawn_serial_is_packed_bcd() {
    // Several cards, because the draw is entropy: one card would pass by
    // luck (all eight nibbles valid by chance ≈ 2.3% of draws).
    for _ in 0..16 {
        let internal = leak_buf(256 * 4096);
        let aid = boot_and_read_aid(internal);
        for (i, byte) in aid[10..14].iter().enumerate() {
            assert!(
                byte >> 4 <= 9 && byte & 0x0F <= 9,
                "serial byte {i} is 0x{byte:02X}, not packed BCD (AID {aid:02X?})"
            );
        }
    }
}

/// A serial already on the card is its host-visible identity and is served
/// byte-for-byte, even when it is not canonical BCD: the fold applies to the
/// draw only, so a card provisioned before it existed keeps presenting its
/// stored serial until a factory wipe redraws one.
#[test]
fn persisted_serial_is_served_unchanged() {
    // Every nibble above 9 — a draw from before the fold could be any bytes.
    let stored = [0xAB, 0xCD, 0xEF, 0x9F];
    let internal = leak_buf(256 * 4096);
    let aid = boot_with_persisted_serial(internal, stored);
    assert_eq!(
        &aid[10..14],
        &stored,
        "a persisted serial must not be re-folded (AID {aid:02X?})"
    );
    // …and it stays that way across the next boot, too.
    let again = boot_and_read_aid(internal);
    assert_eq!(&again[10..14], &stored, "the stored serial must persist");
}

// ---------------------------------------------------------------------------
// S-724: secp256k1 through the OpenPGP interface. The card logic (opcard
// types.rs, `EcDsaSecp256k1`/`EcDhSecp256k1`, `AllowedAlgorithms::SECP256K1`
// in both the generation and import gates) has always been compiled in, but
// no backend served `Mechanism::Secp256k1` — GENERATE/PSO would fail at the
// trussed core (`RequestNotAvailable`). The software-secp256k1 backend
// (`vendor/trussed-secp256k1`, wired in opcard's virt dispatch here and the
// platform `OpcardDispatch` on the device path) serves it over k256. These
// tests pin:
//
//   1. PUT DATA of the secp256k1 ECDSA attribute (tag C1, `13 2B 81 04 00
//      0A` — the C reference firmware's `algorithm_attr_p256k1`) is accepted
//      and stored;
//   2. GENERATE for the secp256k1 signature key produces a real secp256k1
//      keypair: the 7F49 reply carries a 65-byte uncompressed point
//      (`86 41 04 || X || Y`), and a PSO:SIGN digest verifies against it
//      (raw `r || s`, k256 prehash verification) — never an ECC-OID or
//      Ed255-shaped reply.

/// secp256k1 ECDSA attribute bytes for the signature DO (C1): algorithm 13
/// (ECDSA), curve OID 1.3.132.0.10 (`2B 81 04 00 0A`).
const ECDSA_SECP256K1_ATTR: &[u8] = &[0x13, 0x2B, 0x81, 0x04, 0x00, 0x0A];
/// secp256k1 ECDSA attribute as read back through GET DATA (the ECC PK
/// normalization appends the `FF` suffix — types.rs
/// `ECDSA_SECP256K1_ATTRIBUTES_PK`).
const ECDSA_SECP256K1_ATTR_PK: &[u8] = &[0x13, 0x2B, 0x81, 0x04, 0x00, 0x0A, 0xFF];

/// Personalize PW1 (`654321`) and PW3 (`87654321`): GENERATE and PSO are
/// refused while the factory PINs are in force (US-912). CHANGE REFERENCE
/// DATA keeps the admin session.
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

/// Extract the 65-byte uncompressed secp256k1 point (`04 || X || Y`) from a
/// GENERATE/READ PUBLIC KEY 7F49 reply body (`7F 49 <len> 86 41 <point>`).
fn secp256k1_point_from_template(body: &[u8]) -> k256::PublicKey {
    let idx = body
        .windows(2)
        .position(|w| w == [0x86, 0x41])
        .expect("GENERATE reply must carry an 86 41 (65-byte point) public key");
    let point = &body[idx + 2..idx + 2 + 65];
    assert_eq!(point[0], 0x04, "point must be uncompressed (0x04 header)");
    k256::PublicKey::from_sec1_bytes(point).expect("GENERATE reply must be a valid secp256k1 point")
}

/// PUT DATA of the secp256k1 ECDSA attribute for the signature DO (tag C1)
/// must answer 9000 and be stored — the C-firmware attribute set joins the
/// accepted generation contract (S-724).
#[test]
fn put_secp256k1_attr_accepted_and_stored() {
    opcard::virt::with_ram_client("fapico2-openpgp-attr-secp256k1", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        let (_, sw) = apdu(
            &mut dispatcher,
            &put_data_apdu(0x00, 0xC1, ECDSA_SECP256K1_ATTR),
        );
        assert_eq!(
            sw, SW_OK,
            "PUT DATA secp256k1 attribute must answer 9000, got {:04x}",
            sw
        );

        let (after, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xC1, 0x00]);
        assert_eq!(sw, SW_OK, "GET DATA C1 after PUT must answer 9000");
        assert_eq!(
            after, ECDSA_SECP256K1_ATTR_PK,
            "stored C1 must be the secp256k1 attribute after PUT DATA"
        );
    });
}

/// GENERATE for the signature key after switching C1 to secp256k1 ECDSA
/// produces a real secp256k1 keypair: the reply carries the 65-byte
/// uncompressed point, and a PSO:SIGN digest over that key verifies with
/// k256 prehash verification (raw `r || s`) — the S-724 backend actually
/// generates and signs on the curve, not just accepting the attribute.
#[test]
fn generate_secp256k1_key_signs_verifiably() {
    use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
    use sha2::{Digest, Sha256};

    opcard::virt::with_ram_client("fapico2-openpgp-gen-secp256k1", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        let (_, sw) = apdu(
            &mut dispatcher,
            &put_data_apdu(0x00, 0xC1, ECDSA_SECP256K1_ATTR),
        );
        assert_eq!(sw, SW_OK, "PUT DATA secp256k1 attribute must answer 9000");
        personalize_pins(&mut dispatcher);

        // GENERATE ASYMMETRIC KEY PAIR, signature key (CRT B6).
        let mut gen = vec![0x00u8, 0x47, 0x80, 0x00, 0x02];
        gen.extend_from_slice(&[0xB6, 0x00]);
        gen.push(0x00);
        let (body, sw) = apdu_read(&mut dispatcher, &gen);
        assert_eq!(sw, SW_OK, "GENERATE secp256k1 must answer 9000, got {:04x}", sw);
        let public = secp256k1_point_from_template(&body);

        // PSO:SIGN with the personalized PW1 (P2=81 sign context).
        let digest: [u8; 32] = Sha256::digest(b"fapico2-s724-secp256k1").into();
        let (_, sw) = apdu(
            &mut dispatcher,
            &[0x00, 0x20, 0x00, 0x81, 0x06, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
        );
        assert_eq!(sw, SW_OK, "VERIFY PW1 (sign) must answer 9000");

        let mut sign = vec![0x00u8, 0x2A, 0x9E, 0x9A, 0x20];
        sign.extend_from_slice(&digest);
        sign.push(0x00);
        let (signature, sw) = apdu_read(&mut dispatcher, &sign);
        assert_eq!(sw, SW_OK, "PSO:SIGN secp256k1 must answer 9000, got {:04x}", sw);
        assert_eq!(signature.len(), 64, "secp256k1 signature must be raw r || s");
        let signature =
            k256::ecdsa::Signature::from_slice(&signature).expect("valid secp256k1 signature");

        let verifying = k256::ecdsa::VerifyingKey::from(&public);
        verifying
            .verify_prehash(&digest, &signature)
            .expect("PSO:SIGN signature must verify on secp256k1");

        let mut tampered = digest;
        tampered[0] ^= 1;
        assert!(
            verifying.verify_prehash(&tampered, &signature).is_err(),
            "a signature over a different digest must not verify"
        );
    });
}

// ---------------------------------------------------------------------------
// US-940: RSA PSO:SIGN verified end-to-end. The software-RSA backend
// (`trussed_rsa_alloc::SoftwareRsa` — opcard's own virt dispatch here, the
// platform `OpcardDispatch` on the device path, `tests/device_pso.rs`) signs
// the DigestInfo the host sends (`SigningKey::<Sha256>::new_unprefixed(
// ..).sign_prehash()`), i.e. PKCS#1 v1.5 over the raw APDU data: the host
// builds the full SHA-256 DigestInfo (`3031 300d ... 0420 || digest`) —
// DigestInfo generation is host-side per spec §7.2.14. PSO:SIGN replies with
// the raw signature (no TLV wrapper), exactly modulus-length bytes (256 B
// for RSA-2048). These tests verify the signature with the `rsa` crate
// against the public key the card itself reports (READ PUBLIC KEY), so RSA
// signing is proven cryptographically correct, not just shape-checked.
//
// Slot semantics (probed, then pinned below — the brief's "AUT/DEC refusal
// for RSA as observed behavior"): PSO:SIGN is bound to the SIG slot — with
// RSA keys in DEC and AUT but no SIG key it answers 6A88 (key reference not
// found); it never falls back to another slot. RSA in the AUT slot signs
// verifiably through INTERNAL AUTHENTICATE (§7.2.13), and RSA in the DEC
// slot decrypts through PSO:DECIPHER (§7.2.11) — neither is refused for
// RSA; the slots are separated by operation, not by algorithm.

use std::sync::LazyLock;

/// The deterministic RSA-2048 test key: fixed-seed keygen so failures are
/// reproducible and the (multi-second) prime search is paid once per test
/// binary. `n = p · q` is recomputed from the imported parts — the public
/// key the tests verify against is derived from exactly the (e, p, q) the
/// card received, never from the generator's own struct.
struct RsaTestKey {
    e: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    n: Vec<u8>,
}

static RSA_TEST_KEY: LazyLock<RsaTestKey> = LazyLock::new(|| {
    use rand::SeedableRng as _;
    use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};

    let mut rng = rand::rngs::StdRng::seed_from_u64(0x4641_5049_434F_3202);
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .expect("deterministic RSA-2048 keygen must succeed");
    let primes = private.primes();
    assert_eq!(primes.len(), 2, "RSA-2048 private key has exactly two primes");
    let e = private.e().to_bytes_be();
    // p and q are 128 bytes each for RSA-2048; pad defensively so the
    // template lengths stay exact.
    let pad = |mut v: Vec<u8>| -> Vec<u8> {
        while v.len() < 128 {
            v.insert(0, 0);
        }
        v
    };
    let (p, q) = (pad(primes[0].to_bytes_be()), pad(primes[1].to_bytes_be()));
    let n = (&primes[0] * &primes[1]).to_bytes_be();
    assert_eq!(n.len(), 256, "RSA-2048 modulus must be 256 bytes");
    RsaTestKey { e, p, q, n }
});

/// The public key derived from the imported (e, p, q) parts.
fn rsa_public_key() -> rsa::RsaPublicKey {
    let k = &*RSA_TEST_KEY;
    rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&k.n),
        rsa::BigUint::from_bytes_be(&k.e),
    )
    .expect("n = p·q with the 65537 exponent is a valid RSA public key")
}

/// Does `signature` verify as PKCS#1 v1.5 (SHA-256 DigestInfo prefix) over
/// `digest`? The card signs the raw DigestInfo with an *unprefixed*
/// `SigningKey`, so verification uses `VerifyingKey::<Sha256>` (whose prefix
/// is exactly that DigestInfo) over the bare 32-byte digest.
fn rsa_verifies(pub_key: &rsa::RsaPublicKey, digest: &[u8; 32], signature: &[u8]) -> bool {
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::hazmat::PrehashVerifier as _;

    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(signature) else {
        return false;
    };
    VerifyingKey::<sha2::Sha256>::new(pub_key.clone())
        .verify_prehash(digest, &signature)
        .is_ok()
}

/// SHA-256 DigestInfo over `message` (RFC 8017 §9.2 with the SHA-256
/// prefix): `30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || h`.
fn sha256_digest_info(message: &[u8]) -> [u8; 51] {
    use sha2::Digest as _;
    let digest: [u8; 32] = sha2::Sha256::digest(message).into();
    let mut info = [0u8; 51];
    info[..19].copy_from_slice(&[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, 0x05, 0x00, 0x04, 0x20,
    ]);
    info[19..].copy_from_slice(&digest);
    info
}

/// DER length field (spec §4.3.3 length encoding): short form `< 128`,
/// `81 xx`, `82 hi lo` — the form opcard's `take_len` parses.
fn der_len(len: usize) -> Vec<u8> {
    if len <= 0x7f {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

/// PUT KEY (INS DB, P1P2 3FFF) with the RSA `91/92/93` (e,p,q) template
/// (`RsaImportFormat{e,p,q}`; d/u are recomputed by the backend). The 4D DO
/// exceeds short-Lc (276 B for RSA-2048), so the APDU uses extended length
/// (3-byte Lc) — the iso7816 parser at the app seam accepts both forms.
fn put_key_rsa_apdu(crt: &[u8], e: &[u8], p: &[u8], q: &[u8]) -> Vec<u8> {
    let mut template = Vec::new();
    for (tag, part) in [(0x91u8, e), (0x92u8, p), (0x93u8, q)] {
        template.push(tag);
        template.extend_from_slice(&der_len(part.len()));
    }
    let mut key_data = Vec::from(e);
    key_data.extend_from_slice(p);
    key_data.extend_from_slice(q);

    let mut content = Vec::from(crt);
    for (tag, value) in [(&[0x7fu8, 0x48][..], template), (&[0x5fu8, 0x48][..], key_data)] {
        content.extend_from_slice(tag);
        content.extend_from_slice(&der_len(value.len()));
        content.extend_from_slice(&value);
    }

    let mut blob = vec![0x4Du8];
    blob.extend_from_slice(&der_len(content.len()));
    blob.extend_from_slice(&content);

    // Extended APDU: `00 DB 3F FF 00 <LcHi LcLo> <data>`, no Le.
    let mut apdu = vec![0x00u8, 0xDB, 0x3F, 0xFF, 0x00];
    apdu.extend_from_slice(&(blob.len() as u16).to_be_bytes());
    apdu.extend_from_slice(&blob);
    apdu
}

/// Parse the READ PUBLIC KEY 7F49 reply for an RSA key: `7F 49 <len> 81
/// <len> <n> 82 <len> <e>` (gen.rs `read_rsa_key`). Returns (n, e).
fn rsa_pubkey_from_template(body: &[u8]) -> (Vec<u8>, Vec<u8>) {
    fn take_len(data: &[u8], i: usize) -> (usize, usize) {
        match data[i] {
            l @ 0x00..=0x7f => (l as usize, i + 1),
            0x81 => (data[i + 1] as usize, i + 2),
            0x82 => (
                ((data[i + 1] as usize) << 8) | data[i + 2] as usize,
                i + 3,
            ),
            b => panic!("unexpected length byte {b:02x} in template"),
        }
    }
    assert_eq!(&body[..2], &[0x7f, 0x49], "reply must open with the 7F49 template");
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

/// PSO:SIGN (INS 2A 9E 9A) with a DigestInfo, Le = 0 (max 256 — the raw
/// signature fills it exactly).
fn pso_sign_apdu(info: &[u8; 51]) -> Vec<u8> {
    let mut apdu = vec![0x00u8, 0x2A, 0x9E, 0x9A, info.len() as u8];
    apdu.extend_from_slice(info);
    apdu.push(0x00);
    apdu
}

/// US-940 main scenario: RSA-2048 imported into the SIG slot via PUT KEY
/// (e,p,q); PSO:SIGN over a host-computed SHA-256 DigestInfo returns exactly
/// 256 raw signature bytes that verify against the card's own read-back
/// public key; a one-bit digest change or a one-bit signature change breaks
/// verification.
#[test]
fn pso_rsa_2048_signature_verifies() {
    opcard::virt::with_ram_client("fapico2-openpgp-rsa-pso", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // Switch the signature-key attribute to RSA-2048 (gpg keyattr), then
        // clear the US-912 factory gate (CRD keeps the admin session).
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC1, RSA_2K_ATTR));
        assert_eq!(sw, SW_OK, "PUT DATA RSA attribute must answer 9000");
        personalize_pins(&mut dispatcher);

        // Import (e, p, q) into the SIG slot.
        let k = &*RSA_TEST_KEY;
        let (_, sw) = apdu(&mut dispatcher, &put_key_rsa_apdu(&[0xB6, 0x00], &k.e, &k.p, &k.q));
        assert_eq!(
            sw, SW_OK,
            "PUT KEY RSA (e,p,q) must answer 9000, got {:04x}",
            sw
        );

        // The card's own read-back of the imported public key: the
        // verification base for every assertion below.
        let read = vec![0x00u8, 0x47, 0x81, 0x00, 0x02, 0xB6, 0x00, 0x00];
        let (body, sw) = apdu_read(&mut dispatcher, &read);
        assert_eq!(sw, SW_OK, "READ PUBLIC KEY must answer 9000, got {:04x}", sw);
        let (n_card, e_card) = rsa_pubkey_from_template(&body);
        assert_eq!(e_card, k.e, "read-back exponent must be the imported e");
        assert_eq!(n_card, k.n, "read-back modulus must be p·q of the imported parts");

        // PSO:SIGN needs a PW1 sign session (the new PIN, P2 = 81).
        let (_, sw) = apdu(
            &mut dispatcher,
            &[0x00, 0x20, 0x00, 0x81, 0x06, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
        );
        assert_eq!(sw, SW_OK, "VERIFY PW1 (sign) must answer 9000");

        let info = sha256_digest_info(b"fapico2-us940-rsa-pso");
        let (signature, sw) = apdu_read(&mut dispatcher, &pso_sign_apdu(&info));
        assert_eq!(sw, SW_OK, "PSO:SIGN RSA must answer 9000, got {:04x}", sw);

        // Raw signature bytes: exactly the modulus length. Any TLV wrapper
        // (7F49 template, 81/82 tags) would make the reply longer than 256.
        assert_eq!(
            signature.len(),
            256,
            "PSO:SIGN must return exactly the modulus length, no TLV wrapping"
        );

        let pub_key = rsa_public_key();
        let digest: [u8; 32] = info[19..].try_into().unwrap();
        assert!(
            rsa_verifies(&pub_key, &digest, &signature),
            "PSO:SIGN signature must verify (PKCS#1 v1.5, SHA-256 DigestInfo)"
        );

        // One flipped digest bit → the returned signature must not verify.
        let mut tampered_digest = digest;
        tampered_digest[0] ^= 1;
        assert!(
            !rsa_verifies(&pub_key, &tampered_digest, &signature),
            "the signature must not verify over a tampered digest"
        );

        // One flipped signature bit → verification must fail.
        let mut tampered_signature = signature;
        tampered_signature[128] ^= 1;
        assert!(
            !rsa_verifies(&pub_key, &digest, &tampered_signature),
            "a tampered signature must not verify"
        );
    });
}

/// US-940 slot semantics (probed behavior, pinned): with RSA-2048 imported
/// into the DEC and AUT slots but the SIG slot EMPTY,
///
/// 1. PSO:SIGN is refused with 6A88 (key reference not found) — it is bound
///    to the SIG slot and never falls back to DEC/AUT;
/// 2. the AUT slot is *not* refused for RSA: INTERNAL AUTHENTICATE returns a
///    256-byte PKCS#1 v1.5 signature that verifies against the AUT public
///    key, and refuses a tampered digest;
/// 3. the DEC slot is *not* refused for RSA: PSO:DECIPHER round-trips a
///    PKCS#1 v1.5-encrypted block to the original plaintext.
#[test]
fn rsa_slot_semantics_sig_refused_dec_aut_served() {
    use rand::SeedableRng as _;
    use rsa::Pkcs1v15Encrypt;

    opcard::virt::with_ram_client("fapico2-openpgp-rsa-slots", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // RSA-2048 attributes for all three slots; personalize (US-912).
        for tag in [0xC1u8, 0xC2, 0xC3] {
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, RSA_2K_ATTR));
            assert_eq!(sw, SW_OK, "PUT DATA {tag:02x} RSA attribute must answer 9000");
        }
        personalize_pins(&mut dispatcher);

        // Import the same deterministic key into DEC (CRT B8) and AUT
        // (CRT A4) — the SIG slot stays empty.
        let k = &*RSA_TEST_KEY;
        let (_, sw) = apdu(&mut dispatcher, &put_key_rsa_apdu(&[0xB8, 0x00], &k.e, &k.p, &k.q));
        assert_eq!(sw, SW_OK, "PUT KEY RSA DEC must answer 9000, got {:04x}", sw);
        let (_, sw) = apdu(&mut dispatcher, &put_key_rsa_apdu(&[0xA4, 0x00], &k.e, &k.p, &k.q));
        assert_eq!(sw, SW_OK, "PUT KEY RSA AUT must answer 9000, got {:04x}", sw);

        // 1. PSO:SIGN with no SIG key: refused, no fallback, no signature.
        let info = sha256_digest_info(b"fapico2-us940-slot-probe");
        let (body, sw) = apdu_read(&mut dispatcher, &pso_sign_apdu(&info));
        assert_eq!(
            sw, 0x6A88,
            "PSO:SIGN without a SIG key must answer 6A88 (key reference not found), got {:04x}",
            sw
        );
        assert!(body.is_empty(), "the refusal must not carry a signature");

        // The read-back AUT public key (equal to the DEC one — same parts).
        let read = vec![0x00u8, 0x47, 0x81, 0x00, 0x02, 0xA4, 0x00, 0x00];
        let (body, sw) = apdu_read(&mut dispatcher, &read);
        assert_eq!(sw, SW_OK, "READ PUBLIC KEY (AUT) must answer 9000");
        let (n_aut, e_aut) = rsa_pubkey_from_template(&body);
        assert_eq!(n_aut, k.n, "AUT read-back modulus must be the imported p·q");
        assert_eq!(e_aut, k.e, "AUT read-back exponent must be the imported e");
        let pub_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&n_aut),
            rsa::BigUint::from_bytes_be(&e_aut),
        )
        .expect("valid AUT public key");

        // 2. AUT slot, INTERNAL AUTHENTICATE: needs a PW1 "other" session.
        let (_, sw) = apdu(
            &mut dispatcher,
            &[0x00, 0x20, 0x00, 0x82, 0x06, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
        );
        assert_eq!(sw, SW_OK, "VERIFY PW1 (other) must answer 9000");
        let mut int_auth = vec![0x00u8, 0x88, 0x00, 0x00, info.len() as u8];
        int_auth.extend_from_slice(&info);
        int_auth.push(0x00);
        let (signature, sw) = apdu_read(&mut dispatcher, &int_auth);
        assert_eq!(sw, SW_OK, "INTERNAL AUTHENTICATE RSA must answer 9000, got {:04x}", sw);
        assert_eq!(signature.len(), 256, "INT-AUTH signature must be modulus-length");
        let digest: [u8; 32] = info[19..].try_into().unwrap();
        assert!(
            rsa_verifies(&pub_key, &digest, &signature),
            "the INT-AUTH signature must verify against the AUT public key"
        );
        let mut tampered_digest = digest;
        tampered_digest[0] ^= 1;
        assert!(
            !rsa_verifies(&pub_key, &tampered_digest, &signature),
            "the INT-AUTH signature must not verify over a tampered digest"
        );

        // 3. DEC slot, PSO:DECIPHER: `00` padding indicator || ciphertext.
        //    The cipher DO is 257 bytes → extended Lc.
        let pub_key_dec = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&k.n),
            rsa::BigUint::from_bytes_be(&k.e),
        )
        .expect("valid DEC public key");
        let plaintext = b"fapico2-us940-dec-roundtrip";
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x940);
        let ciphertext = pub_key_dec
            .encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)
            .expect("host-side PKCS#1 v1.5 encryption must succeed");
        assert_eq!(ciphertext.len(), 256);
        let mut cipher_do = vec![0x00u8, 0x2A, 0x80, 0x86, 0x00];
        let mut data = vec![0x00u8];
        data.extend_from_slice(&ciphertext);
        cipher_do.extend_from_slice(&(data.len() as u16).to_be_bytes());
        cipher_do.extend_from_slice(&data);
        let (decrypted, sw) = apdu_read(&mut dispatcher, &cipher_do);
        assert_eq!(sw, SW_OK, "PSO:DECIPHER RSA must answer 9000, got {:04x}", sw);
        assert_eq!(
            decrypted,
            plaintext.as_slice(),
            "PSO:DECIPHER must round-trip the encrypted plaintext"
        );
    });
}

// ---------------------------------------------------------------------------
// US-941: RSA PSO:DECIPHER verified end-to-end (virt path). Per §7.2.11 the
// PSO:DECIPHER data field is one leading padding-indicator byte followed by
// the ciphertext; the card strips the indicator (`pso.rs decrypt_rsa`) and
// hands the rest to the backend, which unpads PKCS#1 v1.5 *encryption*
// padding (RFC 8017 §7.2.1, EM = `00 02 PS 00 || M`). The SM routing guard
// sits before key resolution: data starting with `0x02` routes to the AES
// decipher path (the SM payload-encryption key imported via PUT DATA tag
// `00 D5`), everything else routes to RSA. The routing pins use mutually
// exclusive observables, so each test proves the route taken, not just a
// status word:
//
// - a 17-byte `0x02`-prefixed DO decrypts through AES-CBC (zero IV, no
//   padding) to host-computed exact bytes — the RSA path cannot return
//   those (it would refuse a 16-byte "ciphertext" with 6A80);
// - a 257-byte `0x00`-prefixed DO whose ciphertext fails unpadding answers
//   6A80 — the AES path would answer 9000 for that shape ((257-1) % 16 == 0).

/// PSO:DECIPHER (INS 2A 80 86) with the raw cipher DO. The DO exceeds short
/// Lc for RSA-2048 (257 B), so the APDU uses extended length (3-byte Lc);
/// no Le — the plaintext reply is shorter than the ciphertext and the
/// dispatcher sizes the response buffer itself.
fn pso_decipher_apdu(data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00u8, 0x2A, 0x80, 0x86, 0x00];
    apdu.extend_from_slice(&(data.len() as u16).to_be_bytes());
    apdu.extend_from_slice(data);
    apdu
}

/// Host-side PKCS#1 v1.5 (encryption) of `plaintext` to `n`/`e` with a
/// *fixed* padding seed (RFC 8017 §7.2.1, EM = `00 02 PS 00 || M`): the
/// block is built byte-for-byte (PS cycles over 1..=255, never 0) and
/// encrypted by raw modexp — fully deterministic, no rng in the test.
fn pkcs1v15_encrypt_fixed_ps(n: &[u8], e: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let k = n.len();
    assert_eq!(k, 256, "RSA-2048 block size expected");
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x02);
    while em.len() < k - plaintext.len() - 1 {
        em.push(((em.len() * 7) % 255 + 1) as u8);
    }
    em.push(0x00);
    em.extend_from_slice(plaintext);
    assert_eq!(em.len(), k, "EM must fill the RSA block exactly");
    let m = rsa::BigUint::from_bytes_be(&em);
    let c = m.modpow(&rsa::BigUint::from_bytes_be(e), &rsa::BigUint::from_bytes_be(n));
    let mut ct = c.to_bytes_be();
    while ct.len() < k {
        ct.insert(0, 0);
    }
    ct
}

/// AES-256-CBC decrypt with a zero IV and no padding removal — the exact
/// operation the card's AES decipher path performs (trussed `Aes256Cbc`
/// decrypt with an empty nonce → IV = 0, `NoPadding`).
fn aes256_cbc_zero_iv_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockDecrypt as _, KeyInit as _};

    let cipher = aes::Aes256::new_from_slice(key).expect("32-byte AES key");
    assert_eq!(ciphertext.len() % 16, 0, "CBC operates on whole blocks");
    let mut previous = [0u8; 16]; // zero IV
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        let mut block = aes::Block::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        for (b, p) in block.iter().zip(previous.iter()) {
            out.push(b ^ p);
        }
        previous.copy_from_slice(chunk);
    }
    out
}

/// US-941 main scenario: RSA-2048 imported into the DEC slot; the host
/// PKCS#1 v1.5-encrypts a fixed 32-byte plaintext (fixed PS, raw modexp),
/// sends PSO:DECIPHER prefixed with the `0x00` padding-indicator byte and
/// gets the plaintext back byte-exact. Malformed ciphertexts are probed and
/// pinned: a one-bit-flipped ciphertext and an 8-byte too-short payload both
/// answer 6A80 (backend unpad failure → `IncorrectDataParameter`).
///
/// - the `0x00` indicator is *semantically transparent* for RSA: a leading
///   zero byte vanishes in the backend's big-endian integer conversion, so
///   decrypting with or without the strip yields the same integer (verified
///   by mutation run — the strip matters only for the `0x02`/AES routing
///   decision, which the guard test pins);
#[test]
fn pso_rsa_2048_decipher_roundtrip() {
    opcard::virt::with_ram_client("fapico2-openpgp-rsa-dec", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // DEC slot: RSA-2048 attribute (C2), personalization (US-912),
        // import (e, p, q) into the DEC slot (CRT B8).
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC2, RSA_2K_ATTR));
        assert_eq!(sw, SW_OK, "PUT DATA RSA DEC attribute must answer 9000");
        personalize_pins(&mut dispatcher);
        let k = &*RSA_TEST_KEY;
        let (_, sw) = apdu(&mut dispatcher, &put_key_rsa_apdu(&[0xB8, 0x00], &k.e, &k.p, &k.q));
        assert_eq!(
            sw, SW_OK,
            "PUT KEY RSA DEC must answer 9000, got {:04x}",
            sw
        );

        // PSO:DECIPHER needs a PW1 "other" session (P2 = 82).
        let (_, sw) = apdu(
            &mut dispatcher,
            &[0x00, 0x20, 0x00, 0x82, 0x06, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
        );
        assert_eq!(sw, SW_OK, "VERIFY PW1 (other) must answer 9000");

        // Roundtrip: fixed 32-byte plaintext, fixed-PS PKCS#1 v1.5 block,
        // `0x00` padding-indicator leading byte (§7.2.11). 257-byte DO →
        // extended Lc.
        let plaintext = *b"fapico2-us941-dec-roundtrip!!!!!"; // exactly 32 bytes
        let ciphertext = pkcs1v15_encrypt_fixed_ps(&k.n, &k.e, &plaintext);
        let mut data = vec![0x00u8];
        data.extend_from_slice(&ciphertext);
        let (body, sw) = apdu_read(&mut dispatcher, &pso_decipher_apdu(&data));
        assert_eq!(sw, SW_OK, "PSO:DECIPHER RSA must answer 9000, got {:04x}", sw);
        assert_eq!(
            body,
            plaintext.as_slice(),
            "PSO:DECIPHER must return the original plaintext byte-exact"
        );

        // Malformed ciphertext, probed then pinned: a one-bit flip in the
        // ciphertext makes the card decrypt to a block that fails the
        // PKCS#1 v1.5 (encryption) unpad in the backend; opcard maps every
        // decrypt failure to 6A80 (`IncorrectDataParameter`). This probe
        // also pins the RSA routing direction: had the 257-byte DO routed
        // to AES ((257-1) % 16 == 0), it would have answered 9000.
        let mut tampered = ciphertext.clone();
        tampered[128] ^= 1;
        let mut data = vec![0x00u8];
        data.extend_from_slice(&tampered);
        let (body, sw) = apdu_read(&mut dispatcher, &pso_decipher_apdu(&data));
        assert_eq!(
            sw, 0x6A80,
            "a ciphertext that fails unpadding must answer 6A80, got {:04x}",
            sw
        );
        assert!(body.is_empty(), "the refusal must not carry a payload");

        // Too-short payload, probed then pinned: after the indicator strip
        // only 8 bytes remain — far short of the 256-byte RSA block; the
        // backend unpads the modexp result and fails → 6A80.
        let (_, sw) = apdu(&mut dispatcher, &pso_decipher_apdu(&[0x00; 9]));
        assert_eq!(
            sw, 0x6A80,
            "an 8-byte (too-short) ciphertext must answer 6A80, got {:04x}",
            sw
        );
    });
}

/// US-941 SM routing guard: with the RSA DEC key imported (so a route to
/// RSA was available), a decipher DO starting with `0x02` routes to the AES
/// decipher path — proven byte-exact against a host-computed AES-256-CBC
/// (zero IV, no padding) decryption using the SM key imported via PUT DATA
/// tag `00 D5`. A non-block-multiple `0x02`-prefixed payload is refused by
/// the AES path's block-size guard before any RSA resolution.
#[test]
fn decipher_routes_0x02_prefix_to_aes_sm_path() {
    opcard::virt::with_ram_client("fapico2-openpgp-dec-aes-route", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // Same DEC-slot RSA setup as the roundtrip test: the RSA route
        // exists, so only the routing guard sends `0x02` data to AES.
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC2, RSA_2K_ATTR));
        assert_eq!(sw, SW_OK, "PUT DATA RSA DEC attribute must answer 9000");
        personalize_pins(&mut dispatcher);
        let k = &*RSA_TEST_KEY;
        let (_, sw) = apdu(&mut dispatcher, &put_key_rsa_apdu(&[0xB8, 0x00], &k.e, &k.p, &k.q));
        assert_eq!(sw, SW_OK, "PUT KEY RSA DEC must answer 9000, got {:04x}", sw);

        // Import the SM payload-encryption key: PUT DATA tag `00 D5`
        // (admin-authorized) with exactly 32 bytes (AES256_KEY_LEN).
        let sm_key: [u8; 32] = core::array::from_fn(|i| (i as u8) * 7 + 1);
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xD5, &sm_key));
        assert_eq!(
            sw, SW_OK,
            "PUT DATA SM AES key (00 D5) must answer 9000, got {:04x}",
            sw
        );

        // The AES decipher path requires a PW1 "other" session (the wrapped
        // AES key is loaded under the user KEK).
        let (_, sw) = apdu(
            &mut dispatcher,
            &[0x00, 0x20, 0x00, 0x82, 0x06, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
        );
        assert_eq!(sw, SW_OK, "VERIFY PW1 (other) must answer 9000");

        // `0x02` prefix + 16 bytes ((17-1) % 16 == 0): the AES path decrypts
        // the single block with the imported SM key and zero IV — the reply
        // is byte-exact AES-CBC, which the RSA path could never produce.
        let ct_block: [u8; 16] = core::array::from_fn(|i| 0xA0 + i as u8);
        let expected = aes256_cbc_zero_iv_decrypt(&sm_key, &ct_block);
        let mut data = vec![0x02u8];
        data.extend_from_slice(&ct_block);
        let (body, sw) = apdu_read(&mut dispatcher, &pso_decipher_apdu(&data));
        assert_eq!(
            sw, SW_OK,
            "a 0x02-prefixed DO must route to the AES decipher path, got {:04x}",
            sw
        );
        assert_eq!(
            body,
            expected,
            "the AES route must decrypt with the imported SM key (zero IV, no padding)"
        );

        // Same route, error side: a payload whose length is not a block
        // multiple is refused by the AES path's length guard (6A80) — the
        // routing decision happens before any RSA key resolution.
        let (_, sw) = apdu(&mut dispatcher, &pso_decipher_apdu(&[0x02, 0x11, 0x22, 0x33]));
        assert_eq!(
            sw, 0x6A80,
            "a 0x02-prefixed non-block-multiple payload must hit the AES length guard (6A80), got {:04x}",
            sw
        );
    });
}

// ---------------------------------------------------------------------------
// US-946: Brainpool end-to-end on the virt path — the S-724 secp256k1
// lifecycle replayed over the US-944 software-Brainpool backend
// (`vendor/trussed-brainpool`, wired in opcard's virt dispatch). Scope is
// P-256r1 + P-384r1 only (P-512r1 has no backend and stays unadvertised —
// the US-945 6A80 rejection). Each curve pins:
//
//   1. attribute PUT of the ECDH+ECDSA pair (C2 dec, C1 sign) accepted and
//      read back PK-normalized;
//   2. PIN personalization (US-912 gate);
//   3. DEC key import (private scalar through the 7F48/5F48 template, the
//      card derives the public key through the backend);
//   4. SIG key GENERATE → 7F49 reply carrying the uncompressed public point;
//   5. PSO:SIGN with the curve-sized prehash (32/48 B) verifies host-side
//      with the bp* primitives; a tampered digest must not verify; a
//      wrong-sized digest is refused by the `pso.rs` data-length gate
//      (observed SW: ConditionsOfUseNotSatisfied, 6985);
//   6. PSO:DECIPHER ECDH returns the exact x-coordinate shared secret the
//      host computes with `elliptic_curve::ecdh::diffie_hellman`.

/// Brainpool attribute bytes (types.rs `*_BRAINPOOL_*_ATTRIBUTES`): tag
/// 0x13 = ECDSA (sign), 0x12 = ECDH (dec); OID suffix 07 = P-256r1,
/// 0B = P-384r1 (deferred by US-966 — the two constants below are what the
/// refusal tests name, not what the card serves).
const BP256R1_ECDSA_ATTR: &[u8] = &[0x13, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
const BP256R1_ECDH_ATTR: &[u8] = &[0x12, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
const BP384R1_ECDSA_ATTR: &[u8] = &[0x13, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];
const BP384R1_ECDH_ATTR: &[u8] = &[0x12, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];

/// Deterministic Brainpool P-256r1 scalar (top byte masked well below the
/// curve order `A9FB 57DB …`, so injection always succeeds).
fn bp256_scalar(seed: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut s: [u8; 32] = Sha256::digest(seed).into();
    s[0] &= 0x1f;
    s
}

// US-966: `bp384_scalar` (the 48-byte equivalent) is gone with the curve. Its
// only caller was the P-384r1 lifecycle suite, now inverted into
// `brainpool_p384r1_is_refused_virt`, which needs no curve arithmetic.

/// PUT KEY (INS DB, P1P2 3FFF) with the private-only ECC template the
/// card-side parser accepts (`4D <len> CRT 7F48 92 <len> 5F48 <len> <key>`);
/// opcard derives the public key from the injected scalar through the
/// backend (`derive_key`), so the reply-less 9000 also proves derivation.
fn put_key_ec_apdu(slot: u8, scalar: &[u8]) -> Vec<u8> {
    let mut data = vec![slot, 0x00];
    data.extend_from_slice(&[0x7f, 0x48, 0x02, 0x92, scalar.len() as u8]);
    data.extend_from_slice(&[0x5f, 0x48, scalar.len() as u8]);
    data.extend_from_slice(scalar);
    let mut blob = vec![0x4Du8, data.len() as u8];
    blob.extend_from_slice(&data);
    let mut apdu_bytes = vec![0x00u8, 0xDB, 0x3F, 0xFF, blob.len() as u8];
    apdu_bytes.extend_from_slice(&blob);
    apdu_bytes
}

/// Extract the uncompressed point (`04 || X || Y`) from a GENERATE/READ
/// PUBLIC KEY 7F49 reply body (`7F 49 <len> 86 <2·coord+1> <point>`).
fn brainpool_point_from_template(body: &[u8], coordinate_len: usize) -> Vec<u8> {
    let point_len = 2 * coordinate_len + 1;
    let idx = body
        .windows(2)
        .position(|w| w == [0x86, point_len as u8])
        .expect("GENERATE reply must carry an 86 <len> public key");
    let point = &body[idx + 2..idx + 2 + point_len];
    assert_eq!(point[0], 0x04, "point must be uncompressed (0x04 header)");
    point.to_vec()
}

/// The PSO:DECIPHER cipher DO for an ECDH exchange:
/// `A6 <len> 7F49 <len> 86 <len> <point>`.
fn brainpool_cipher_do(point: &[u8]) -> Vec<u8> {
    assert!(point.len() <= 0x7f, "short-form lengths assumed");
    let mut data = vec![
        0xa6u8,
        (5 + point.len()) as u8,
        0x7f,
        0x49,
        (2 + point.len()) as u8,
        0x86,
        point.len() as u8,
    ];
    data.extend_from_slice(point);
    data
}

/// VERIFY PW1 (P2 = `81` sign / `82` other) with the personalized PW1.
fn verify_pw1(dispatcher: &mut Dispatcher<1>, p2: u8) {
    let (_, sw) = apdu(
        dispatcher,
        &[0x00, 0x20, 0x00, p2, 0x06, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
    );
    assert_eq!(sw, SW_OK, "VERIFY PW1 (P2={p2:02x}) must answer 9000");
}

/// PSO:SIGN (INS 2A 9E 9A) with the raw digest as command data.
fn pso_sign_digest_apdu(digest: &[u8]) -> Vec<u8> {
    let mut apdu_bytes = vec![0x00u8, 0x2A, 0x9E, 0x9A, digest.len() as u8];
    apdu_bytes.extend_from_slice(digest);
    apdu_bytes.push(0x00);
    apdu_bytes
}

/// PSO:DECIPHER (INS 2A 80 86) with the raw cipher DO.
fn pso_decipher_ec_apdu(data: &[u8]) -> Vec<u8> {
    let mut apdu_bytes = vec![0x00u8, 0x2A, 0x80, 0x86, data.len() as u8];
    apdu_bytes.extend_from_slice(data);
    apdu_bytes.push(0x00);
    apdu_bytes
}

/// GENERATE ASYMMETRIC KEY PAIR for the signature key (CRT B6).
fn generate_sig_apdu() -> Vec<u8> {
    vec![0x00u8, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00, 0x00]
}

/// US-946, virt path: Brainpool P-256r1 lifecycle — attribute pair, DEC-key
/// import, SIG-key GENERATE, PSO:SIGN (verify + tamper + wrong-size 6985),
/// PSO:DECIPHER with the exact x-coordinate shared secret.
#[test]
fn brainpool_p256r1_generate_sign_decipher_virt() {
    use sha2::Digest as _;
    use bp256::elliptic_curve::sec1::ToSec1Point as _;
    use bp256::r1::BrainpoolP256r1;

    opcard::virt::with_ram_client("fapico2-openpgp-bp256-lifecycle", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // 1. Attribute pair: ECDSA sign (C1) + ECDH dec (C2), stored in the
        //    PK-normalized form.
        for (tag, attr, attr_pk) in [
            (0xC1u8, BP256R1_ECDSA_ATTR, &[0x13u8, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07, 0xFF][..]),
            (0xC2, BP256R1_ECDH_ATTR, &[0x12u8, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07, 0xFF][..]),
        ] {
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, attr));
            assert_eq!(sw, SW_OK, "PUT DATA {tag:02X} P-256r1 attribute must answer 9000, got {sw:04x}");
            let (stored, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, tag, 0x00]);
            assert_eq!(sw, SW_OK, "GET DATA {tag:02X} must answer 9000");
            assert_eq!(stored, attr_pk, "stored {tag:02X} must be the PK-normalized P-256r1 attribute");
        }

        // 2. PIN personalization (US-912 gate).
        personalize_pins(&mut dispatcher);

        // 3. DEC key by import (deterministic scalar; the card derives the
        //    public key through the backend).
        let dec_scalar = bp256_scalar(b"fapico2-us946-bp256-dec");
        let (_, sw) = apdu(&mut dispatcher, &put_key_ec_apdu(0xB8, &dec_scalar));
        assert_eq!(sw, SW_OK, "PUT KEY DEC P-256r1 must answer 9000, got {sw:04x}");

        // 4. SIG key by GENERATE — keygen through the Brainpool backend.
        let (body, sw) = apdu_read(&mut dispatcher, &generate_sig_apdu());
        assert_eq!(sw, SW_OK, "GENERATE P-256r1 must answer 9000, got {sw:04x}");
        let point = brainpool_point_from_template(&body, 32);
        let public = bp256::elliptic_curve::PublicKey::<BrainpoolP256r1>::from_sec1_bytes(&point)
            .expect("GENERATE reply must be a valid Brainpool P-256r1 point");
        let verifying: ecdsa::VerifyingKey<bp256::r1::BrainpoolP256r1> = (&public).into();

        // 5a. Wrong digest size first: 48 B offered to P-256r1 is refused by
        //     the pso.rs data-length gate with ConditionsOfUseNotSatisfied.
        verify_pw1(&mut dispatcher, 0x81);
        let long: [u8; 48] = core::array::from_fn(|i| i as u8);
        let (_, sw) = apdu_read(&mut dispatcher, &pso_sign_digest_apdu(&long));
        assert_eq!(
            sw, 0x6985,
            "PSO:SIGN with a 48-byte digest on P-256r1 must hit the data-length gate (6985), got {sw:04x}"
        );

        // 5b. Correct 32-byte prehash verifies; a tampered digest must not.
        let digest: [u8; 32] = sha2::Sha256::digest(b"fapico2-us946-bp256").into();
        verify_pw1(&mut dispatcher, 0x81);
        let (signature, sw) = apdu_read(&mut dispatcher, &pso_sign_digest_apdu(&digest));
        assert_eq!(sw, SW_OK, "PSO:SIGN P-256r1 must answer 9000, got {sw:04x}");
        assert_eq!(signature.len(), 64, "P-256r1 signature must be raw r || s");
        let signature =
            ecdsa::Signature::<bp256::r1::BrainpoolP256r1>::from_slice(&signature).expect("valid r || s signature");
        use ecdsa::signature::hazmat::PrehashVerifier as _;
        verifying
            .verify_prehash(&digest, &signature)
            .expect("PSO:SIGN signature must verify on Brainpool P-256r1");
        let mut tampered = digest;
        tampered[0] ^= 1;
        assert!(
            verifying.verify_prehash(&tampered, &signature).is_err(),
            "a signature over a different digest must not verify"
        );

        // 6. PSO:DECIPHER ECDH with the exact expected x-coordinate.
        let eph_scalar = bp256_scalar(b"fapico2-us946-bp256-eph");
        let eph = bp256::elliptic_curve::SecretKey::<BrainpoolP256r1>::from_bytes(&eph_scalar.into())
            .expect("deterministic ephemeral scalar");
        let eph_point = eph
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let private = bp256::elliptic_curve::SecretKey::<BrainpoolP256r1>::from_bytes(&dec_scalar.into())
            .expect("deterministic DEC scalar");
        let expected = bp256::elliptic_curve::ecdh::diffie_hellman(
            private.to_nonzero_scalar(),
            eph.public_key().as_affine(),
        )
        .raw_secret_bytes()
        .to_vec();
        assert_eq!(expected.len(), 32, "P-256r1 shared secret is the 32-byte x coordinate");

        verify_pw1(&mut dispatcher, 0x82);
        let (shared, sw) = apdu_read(
            &mut dispatcher,
            &pso_decipher_ec_apdu(&brainpool_cipher_do(&eph_point)),
        );
        assert_eq!(sw, SW_OK, "PSO:DECIPHER P-256r1 must answer 9000, got {sw:04x}");
        assert_eq!(
            shared, expected,
            "PSO:DECIPHER must return the exact ECDH x-coordinate (raw, no KDF-DO yet)"
        );
    });
}

/// US-966 (2026-09-27), virt path: Brainpool P-384r1 is **deferred**. This is
/// the inverted form of the US-946 virt-path lifecycle test it replaces; the
/// device-path counterpart is
/// `device_pso.rs::brainpool_p384r1_is_refused_device_path`.
///
/// The lifecycle this test used to pin — 48-byte scalars, 49-byte compressed /
/// 97-byte uncompressed points, a 48-byte prehash, a 96-byte signature, and an
/// exact ECDH shared secret — is unreachable now, because the attribute that
/// selects the curve is refused at PUT DATA. The assertions below pin the
/// removal instead, on the virt path, and specifically pin the two things that
/// differ from the device path and would otherwise go uncovered here:
///
///  * the refusal is `6A80` on **both** the ECDSA (C1) and ECDH (C2)
///    spellings, and the stored attribute DOs keep their factory values;
///  * a 48-byte prehash is a wrong-size digest for the one Brainpool curve
///    still served, so the `pso.rs` data-length gate answers `6985` — the
///    inverse of the arm that used to read "a 32-byte digest is wrong for
///    P-384r1".
#[test]
fn brainpool_p384r1_is_refused_virt() {
    opcard::virt::with_ram_client("fapico2-openpgp-bp384-deferred", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // Both P-384r1 spellings are refused, and neither leaves a trace.
        for (tag, attr) in [
            (0xC1u8, BP384R1_ECDSA_ATTR),
            (0xC2, BP384R1_ECDH_ATTR),
            (0xC3, BP384R1_ECDSA_ATTR),
        ] {
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, attr));
            assert_eq!(
                sw, 0x6A80,
                "PUT DATA {tag:02X} of a deferred P-384r1 attribute must be refused with \
                 6A80, got {sw:04x} — accepting it would store an algorithm no backend serves"
            );
        }
        for (tag, forbidden) in [
            (
                0xC1u8,
                &[0x13u8, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B, 0xFF][..],
            ),
            (
                0xC2,
                &[0x12u8, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B, 0xFF][..],
            ),
        ] {
            let (stored, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, tag, 0x00]);
            assert_eq!(sw, SW_OK, "GET DATA {tag:02X} must answer 9000");
            assert_ne!(
                stored, forbidden,
                "a refused P-384r1 PUT must leave {tag:02X} at its factory value"
            );
        }

        // P-256r1 — the curve US-966 kept — still serves, and a 48-byte digest
        // is now simply the wrong size for it.
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC1, BP256R1_ECDSA_ATTR));
        assert_eq!(sw, SW_OK, "P-256r1 must still be accepted, got {sw:04x}");
        personalize_pins(&mut dispatcher);
        let dec_scalar = bp256_scalar(b"fapico2-us966-bp256-dec");
        let (_, sw) = apdu(&mut dispatcher, &put_key_ec_apdu(0xB8, &dec_scalar));
        assert_eq!(sw, SW_OK, "PUT KEY DEC P-256r1 must answer 9000, got {sw:04x}");
        let (body, sw) = apdu_read(&mut dispatcher, &generate_sig_apdu());
        assert_eq!(sw, SW_OK, "GENERATE P-256r1 must answer 9000, got {sw:04x}");
        let point = brainpool_point_from_template(&body, 32);
        assert_eq!(point.len(), 65, "P-256r1 point must be 32-byte coordinates");

        verify_pw1(&mut dispatcher, 0x81);
        let long: [u8; 48] = core::array::from_fn(|i| i as u8);
        let (_, sw) = apdu_read(&mut dispatcher, &pso_sign_digest_apdu(&long));
        assert_eq!(
            sw, 0x6985,
            "a 48-byte digest is no longer the prehash size of any served Brainpool curve, \
             so the pso.rs data-length gate must answer 6985, got {sw:04x}"
        );
    });
}

// ---------------------------------------------------------------------------
// US-947: OpenPGP KDF-DO (tag F9) — structure validation at PUT DATA and a
// byte-exact GET DATA roundtrip.
//
// The verified KDF-DO layout (OpenPGP card spec 3.4 §4.3.2 + gpg
// `card-util.c gen_kdf_data` / scdaemon `pin2hash_if_kdf`) is a raw value
// (no F9 TLV prefix in the PUT/GET data) with two shapes:
//   off:  `81 01 00`                                     (3 B)
//   on:   `81 01 03` (KDF_ITERSALTED_S2K) `82 01 08|0A` (SHA-256/SHA-512)
//         `83 04` <iteration count, 4 B big-endian>
//         `84 08` <salt-U, 8 B> [`85 08` <salt-R> `86 08` <salt-S>]
//         `87 20` <32 B> `88 20` <32 B>                   (90 B or 110 B)
//
// Decisions pinned for US-947:
//   1. malformed KDF-DO at PUT DATA F9 → 6A80, state unchanged;
//   2. the card *stores* the KDF-DO and serves it back byte-exact so the
//      host can read the parameters — PSO:DECIPHER ECDH keeps returning the
//      raw shared point whatever is stored. GnuPG derives the key-encryption
//      key in software (`g10/ecdh.c` `extract_secret_x` + `derive_kek`) from
//      the raw shared point and the KDF parameter blob carried in the
//      *public key*; a card that also derived would double-derive and
//      silently fail every real gpg decryption.

/// A valid 110-byte KDF-DO in the exact layout gpg's kdf-setup writes
/// (`card-util.c gen_kdf_data`, three-salt variant): SHA-256, iteration
/// count, three 8-byte salts (84 salt-U, 85 salt-R, 86 salt-S), and the
/// 32-byte initial PW1/PW3 hashes (87/88).
fn gpg_kdf_do(count: u32, salt_u: &[u8; 8], salt_r: &[u8; 8], salt_s: &[u8; 8]) -> Vec<u8> {
    let mut d = vec![0x81, 0x01, 0x03, 0x82, 0x01, 0x08, 0x83, 0x04];
    d.extend_from_slice(&count.to_be_bytes());
    d.extend_from_slice(&[0x84, 0x08]);
    d.extend_from_slice(salt_u);
    d.extend_from_slice(&[0x85, 0x08]);
    d.extend_from_slice(salt_r);
    d.extend_from_slice(&[0x86, 0x08]);
    d.extend_from_slice(salt_s);
    d.extend_from_slice(&[0x87, 0x20]);
    d.extend_from_slice(&[0x11; 32]);
    d.extend_from_slice(&[0x88, 0x20]);
    d.extend_from_slice(&[0x22; 32]);
    d
}

/// US-947, virt path: PUT DATA F9 validates the KDF-DO structure (spec
/// 3.4 §4.3.2 / gpg kdf-setup layout) — malformed values answer 6A80 and
/// leave the stored DO byte-identical (checked before any state write) —
/// and valid values roundtrip byte-exactly through GET DATA F9.
#[test]
fn kdf_do_put_validation_and_roundtrip_virt() {
    opcard::virt::with_ram_client("fapico2-openpgp-us947-kdf-put", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // Factory default: the spec's "no KDF" form.
        let (body, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xF9, 0x00]);
        assert_eq!(sw, SW_OK, "GET DATA F9 must answer 9000");
        assert_eq!(body, &[0xF9, 0x03, 0x81, 0x01, 0x00], "factory KDF-DO default");

        // A valid PUT stores byte-exactly (raw value, no F9 prefix — the
        // form scdaemon's pin2hash_if_kdf re-reads: 90/110 B, [2] == 0x03).
        let kdf = gpg_kdf_do(0x0001_86A0, &[0xA7; 8], &[0xB7; 8], &[0xC7; 8]);
        assert_eq!(kdf.len(), 110);
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xF9, &kdf));
        assert_eq!(sw, SW_OK, "PUT DATA F9 valid KDF-DO must answer 9000, got {sw:04x}");
        let (body, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xF9, 0x00]);
        assert_eq!(sw, SW_OK);
        assert_eq!(body, kdf, "GET DATA F9 must return the stored KDF-DO byte-exact");

        // Malformed KDF-DOs → 6A80, and every one of them must leave the
        // stored DO byte-identical.
        let mut bad_mode = gpg_kdf_do(1, &[0; 8], &[0; 8], &[0; 8]);
        bad_mode[2] = 0x02; // 81 01 02: not NONE, not KDF_ITERSALTED_S2K
        let mut bad_hash = gpg_kdf_do(1, &[0; 8], &[0; 8], &[0; 8]);
        bad_hash[5] = 0x09; // 82 01 09: neither SHA-256 (08) nor SHA-512 (0A)
        let mut zero_count = gpg_kdf_do(0, &[0; 8], &[0; 8], &[0; 8]); // 83 04 00000000
        zero_count[11] = 0x00;
        let mut truncated_salt = gpg_kdf_do(1, &[0; 8], &[0; 8], &[0; 8]);
        truncated_salt.pop(); // 109 bytes: salt-R TLV runs past the end
        let mut f9_prefixed = vec![0xF9, 0x6E];
        f9_prefixed.extend_from_slice(&gpg_kdf_do(1, &[0; 8], &[0; 8], &[0; 8]));
        let mut extra_trailing = gpg_kdf_do(1, &[0; 8], &[0; 8], &[0; 8]);
        extra_trailing.push(0x00); // 111 bytes: overall length not exact
        let bad_cases: Vec<(&str, Vec<u8>)> = vec![
            ("bad mode byte", bad_mode),
            ("bad hash byte", bad_hash),
            ("zero iteration count", zero_count),
            ("truncated salt", truncated_salt),
            ("F9 TLV-prefixed form", f9_prefixed),
            ("extra trailing byte", extra_trailing),
            ("empty data", Vec::new()),
        ];
        for (name, payload) in bad_cases {
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xF9, &payload));
            assert_eq!(
                sw, 0x6A80,
                "PUT DATA F9 {name} must be rejected with 6A80, got {sw:04x}"
            );
            let (body, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xF9, 0x00]);
            assert_eq!(sw, SW_OK);
            assert_eq!(
                body, kdf,
                "rejected PUT ({name}) must leave the stored KDF-DO unchanged"
            );
        }

        // The explicit "KDF off" form (`81 01 00`, gpg kdf-setup off) is
        // valid and roundtrips byte-exactly.
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xF9, &[0x81, 0x01, 0x00]));
        assert_eq!(sw, SW_OK, "PUT DATA F9 KDF-off must answer 9000");
        let (body, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, 0xF9, 0x00]);
        assert_eq!(sw, SW_OK);
        assert_eq!(body, &[0x81, 0x01, 0x00], "KDF-off form must roundtrip byte-exact");
    });
}

/// US-947, virt path: P-256 PSO:DECIPHER ECDH with a valid KDF-DO stored
/// returns the **raw** shared point — the card stores the KDF parameters for
/// the host, it does not derive with them. The reply is byte-identical to the
/// no-KDF-DO case pinned by the US-946/earlier raw tests.
#[test]
fn kdf_do_p256_decipher_virt() {
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;
    use sha2::Digest as _;

    opcard::virt::with_ram_client("fapico2-openpgp-us947-kdf-p256", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);
        personalize_pins(&mut dispatcher);

        // DEC slot: P-256 ECDH attribute + deterministic imported scalar.
        const P256_ECDH: &[u8] = &[0x12, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC2, P256_ECDH));
        assert_eq!(sw, SW_OK, "PUT DATA C2 P-256 ECDH must answer 9000");
        let mut scalar: [u8; 32] = sha2::Sha256::digest(b"fapico2-us947-p256-dec").into();
        scalar[0] &= 0x1f; // well below the P-256 order
        let (_, sw) = apdu(&mut dispatcher, &put_key_ec_apdu(0xB8, &scalar));
        assert_eq!(sw, SW_OK, "PUT KEY DEC P-256 must answer 9000, got {sw:04x}");

        // Ephemeral exchange: raw Z the host computes.
        let eph = p256::SecretKey::from_slice(&sha2::Sha256::digest(b"fapico2-us947-p256-eph"))
            .unwrap();
        let private = p256::SecretKey::from_slice(&scalar).unwrap();
        let z = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), private.public_key().as_affine())
            .raw_secret_bytes()
            .to_vec();
        let mut data = hex!("a6467f49438641").to_vec();
        data.extend_from_slice(eph.public_key().to_encoded_point(false).as_bytes());

        // Store the KDF-DO (count = 1, salt-U = 0xA7·8) while the admin
        // session from `verified_card` is still active.
        let salt_u = [0xA7u8; 8];
        let (_, sw) = apdu(
            &mut dispatcher,
            &put_data_apdu(0x00, 0xF9, &gpg_kdf_do(1, &salt_u, &[0xB7; 8], &[0xC7; 8])),
        );
        assert_eq!(sw, SW_OK, "PUT DATA F9 must answer 9000, got {sw:04x}");

        verify_pw1(&mut dispatcher, 0x82);
        let (shared, sw) = apdu_read(&mut dispatcher, &pso_decipher_ec_apdu(&data));
        assert_eq!(sw, SW_OK, "PSO:DECIPHER P-256 (KDF-DO) must answer 9000, got {sw:04x}");
        assert_eq!(
            shared, z,
            "a stored KDF-DO must not change the raw ECDH x-coordinate"
        );
    });
}

/// US-947, virt path: same contract for secp256k1 (the S-724 backend).
#[test]
fn kdf_do_secp256k1_decipher_virt() {
    use k256::elliptic_curve::sec1::ToEncodedPoint as _;
    use sha2::Digest as _;

    opcard::virt::with_ram_client("fapico2-openpgp-us947-kdf-secp", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);
        personalize_pins(&mut dispatcher);

        const SECP_ECDH: &[u8] = &[0x12, 0x2B, 0x81, 0x04, 0x00, 0x0A];
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC2, SECP_ECDH));
        assert_eq!(sw, SW_OK, "PUT DATA C2 secp256k1 ECDH must answer 9000");
        let mut scalar: [u8; 32] = sha2::Sha256::digest(b"fapico2-us947-secp-dec").into();
        scalar[0] &= 0x1f; // well below the secp256k1 order
        let (_, sw) = apdu(&mut dispatcher, &put_key_ec_apdu(0xB8, &scalar));
        assert_eq!(sw, SW_OK, "PUT KEY DEC secp256k1 must answer 9000, got {sw:04x}");

        let eph = k256::SecretKey::from_slice(&sha2::Sha256::digest(b"fapico2-us947-secp-eph"))
            .unwrap();
        let private = k256::SecretKey::from_slice(&scalar).unwrap();
        let z = k256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), private.public_key().as_affine())
            .raw_secret_bytes()
            .to_vec();
        let mut data = hex!("a6467f49438641").to_vec();
        data.extend_from_slice(eph.public_key().to_encoded_point(false).as_bytes());

        let salt_u = [0x5Au8; 8];
        let (_, sw) = apdu(
            &mut dispatcher,
            &put_data_apdu(0x00, 0xF9, &gpg_kdf_do(1, &salt_u, &[0x6B; 8], &[0x7B; 8])),
        );
        assert_eq!(sw, SW_OK, "PUT DATA F9 must answer 9000, got {sw:04x}");

        verify_pw1(&mut dispatcher, 0x82);
        let (shared, sw) = apdu_read(&mut dispatcher, &pso_decipher_ec_apdu(&data));
        assert_eq!(sw, SW_OK, "PSO:DECIPHER secp256k1 (KDF-DO) must answer 9000, got {sw:04x}");
        assert_eq!(
            shared, z,
            "a stored KDF-DO must not change the raw ECDH x-coordinate"
        );
    });
}

/// US-947, virt path: same contract for X25519 (factory DEC attribute).
/// Fixtures mirror the pinned `pso_sign_verify_device_path` X25519 case:
/// the imported scalar is the byte-reversed, clamped RFC 7748 test-vector
/// private key, and the raw secret is computed host-side with dalek.
#[test]
fn kdf_do_x25519_decipher_virt() {
    use sha2::Digest as _;
    use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

    opcard::virt::with_ram_client("fapico2-openpgp-us947-kdf-x255", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);
        personalize_pins(&mut dispatcher);

        // Factory C2 is already X255 (CV); PUT it explicitly anyway.
        const X255_ECDH: &[u8] = &[0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC2, X255_ECDH));
        assert_eq!(sw, SW_OK, "PUT DATA C2 X25519 ECDH must answer 9000");
        let cv = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let mut cv_import = cv;
        cv_import[0] &= 248;
        cv_import[31] = (cv_import[31] & 127) | 64;
        cv_import.reverse();
        let (_, sw) = apdu(&mut dispatcher, &put_key_ec_apdu(0xB8, &cv_import));
        assert_eq!(sw, SW_OK, "PUT KEY DEC X25519 must answer 9000, got {sw:04x}");

        let eph = XStaticSecret::from(<[u8; 32]>::from(sha2::Sha256::digest(b"fapico2-us947-x255-eph")));
        let private = XStaticSecret::from(cv);
        let z = private.diffie_hellman(&XPublicKey::from(&eph)).to_bytes().to_vec();
        let mut data = hex!("a6257f49228620").to_vec();
        data.extend_from_slice(XPublicKey::from(&eph).as_bytes());

        let salt_u = [0x3Cu8; 8];
        let (_, sw) = apdu(
            &mut dispatcher,
            &put_data_apdu(0x00, 0xF9, &gpg_kdf_do(1, &salt_u, &[0x4B; 8], &[0x5B; 8])),
        );
        assert_eq!(sw, SW_OK, "PUT DATA F9 must answer 9000, got {sw:04x}");

        verify_pw1(&mut dispatcher, 0x82);
        let (shared, sw) = apdu_read(&mut dispatcher, &pso_decipher_ec_apdu(&data));
        assert_eq!(sw, SW_OK, "PSO:DECIPHER X25519 (KDF-DO) must answer 9000, got {sw:04x}");
        assert_eq!(
            shared, z,
            "a stored KDF-DO must not change the raw X25519 shared secret"
        );
    });
}

/// US-959, virt path: the RFC 6637 compact form of the X25519 external
/// public key (`0x40 || X`, 33 bytes) must reach the X25519 backend as 32
/// bytes.
///
/// The DO `86` "External Public Key" is a *tagged* point: `04 || X || Y` for
/// the NIST / secp256k1 / Brainpool curves (the tag the non-X255 branch of
/// `pso.rs` `decrypt_ec` already strips) and the compact `0x40 || X` for
/// Curve25519. gpg's own scdaemon uses both halves of that convention —
/// `scd/app-openpgp.c` `do_decipher` strips a leading tag off the host's
/// ephemeral point before building the cipher DO, and `ecc_read_pubkey`
/// prepends `0x40` to the 32-byte point the card returns in its public-key
/// DO. Before this fix the X255 branch handed all 33 bytes to
/// `trussed-0.2.0 src/mechanisms/x255.rs`, which demands exactly 32, so a
/// conformant tagged request was answered `6A80` (US-958, on hardware).
///
/// The **reply** stays the raw 32-byte x-coordinate, and that is pinned
/// deliberately, not by accident: `scd/app-openpgp.c` `do_decipher`
/// *unconditionally* prepends `0x40` to whatever the card returns for a
/// CV25519 slot, so a card that tagged its own reply would reach
/// `g10/ecdh.c` `extract_secret_x` as 34 bytes and fail its
/// `point_nbytes < nshared` guard (33 < 34) with `GPG_ERR_BAD_DATA`. The
/// raw form is also what the card's public-key DO already carries
/// (`7F49 22 86 20` + 32 bytes) and what `extract_secret_x` consumes as
/// `nshared == secret_x_size` (no prefix to strip).
#[test]
fn x25519_decipher_accepts_rfc6637_format_tag_virt() {
    use sha2::Digest as _;
    use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

    opcard::virt::with_ram_client("fapico2-openpgp-us959-x255-tag", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);
        personalize_pins(&mut dispatcher);

        // Factory C2 is already X255 (CV); PUT it explicitly anyway.
        const X255_ECDH: &[u8] = &[0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC2, X255_ECDH));
        assert_eq!(sw, SW_OK, "PUT DATA C2 X25519 ECDH must answer 9000");
        let cv = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let mut cv_import = cv;
        cv_import[0] &= 248;
        cv_import[31] = (cv_import[31] & 127) | 64;
        cv_import.reverse();
        let (_, sw) = apdu(&mut dispatcher, &put_key_ec_apdu(0xB8, &cv_import));
        assert_eq!(sw, SW_OK, "PUT KEY DEC X25519 must answer 9000, got {sw:04x}");

        let eph = XStaticSecret::from(<[u8; 32]>::from(sha2::Sha256::digest(b"fapico2-us959-x255-eph")));
        let private = XStaticSecret::from(cv);
        let z = private.diffie_hellman(&XPublicKey::from(&eph)).to_bytes().to_vec();
        assert_eq!(z.len(), 32, "the X25519 shared secret is a 32-byte x-coordinate");

        // 1. RFC 6637 compact form: `A6 26 7F49 23 86 21 40 || X`.
        let mut tagged = vec![0xa6u8, 0x26, 0x7f, 0x49, 0x23, 0x86, 0x21, 0x40];
        tagged.extend_from_slice(XPublicKey::from(&eph).as_bytes());
        verify_pw1(&mut dispatcher, 0x82);
        let (shared, sw) = apdu_read(&mut dispatcher, &pso_decipher_ec_apdu(&tagged));
        assert_eq!(
            sw, SW_OK,
            "PSO:DECIPHER with a 0x40-tagged X25519 point must answer 9000, got {sw:04x}"
        );
        assert_eq!(
            shared.len(), 32,
            "the reply must be the raw 32-byte x-coordinate, not 0x40||X: gpg's scdaemon prepends the tag itself"
        );
        assert_eq!(
            shared, z,
            "a 0x40-tagged ephemeral point must yield the same raw shared secret as the untagged one"
        );

        // 2. The untagged 32-byte form stays accepted and byte-identical
        //    (this is what gpg 2.4.4's scdaemon actually puts on the wire
        //    after its own strip) — a super-set acceptance, not a swap.
        let mut untagged = vec![0xa6u8, 0x25, 0x7f, 0x49, 0x22, 0x86, 0x20];
        untagged.extend_from_slice(XPublicKey::from(&eph).as_bytes());
        verify_pw1(&mut dispatcher, 0x82);
        let (shared, sw) = apdu_read(&mut dispatcher, &pso_decipher_ec_apdu(&untagged));
        assert_eq!(sw, SW_OK, "PSO:DECIPHER with an untagged X25519 point must answer 9000, got {sw:04x}");
        assert_eq!(shared, z, "the untagged form must keep answering the same raw secret");

        // 3. A 33-byte point that is not the `0x40` compact form is still
        //    refused: only the RFC 6637 CV25519 tag may be stripped, never
        //    an arbitrary leading octet.
        let mut wrong_tag = vec![0xa6u8, 0x26, 0x7f, 0x49, 0x23, 0x86, 0x21, 0x41];
        wrong_tag.extend_from_slice(XPublicKey::from(&eph).as_bytes());
        verify_pw1(&mut dispatcher, 0x82);
        let (_, sw) = apdu_read(&mut dispatcher, &pso_decipher_ec_apdu(&wrong_tag));
        assert_eq!(
            sw, 0x6a80,
            "a 0x41-tagged X25519 point is not the CV25519 compact form and must be refused, got {sw:04x}"
        );
    });
}

/// US-959, virt path: the NIST / secp256k1 / Brainpool branches were **not**
/// touched — the `04 || X || Y` point the card has always accepted still is,
/// and no other length is admitted. This is the "do not speculatively
/// reformat curves that already interoperate" pin: it fails if a future
/// change widens or narrows the `0x04` branch.
#[test]
fn x25519_tag_fix_leaves_uncompressed_ecc_branch_alone_virt() {
    use sha2::Digest as _;
    use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};

    opcard::virt::with_ram_client("fapico2-openpgp-us959-ecc-untouched", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);
        personalize_pins(&mut dispatcher);

        const SECP256K1: &[u8] = &[0x12, 0x2B, 0x81, 0x04, 0x00, 0x0A];
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC2, SECP256K1));
        assert_eq!(sw, SW_OK, "PUT DATA C2 secp256k1 must answer 9000");
        let mut scalar: [u8; 32] = sha2::Sha256::digest(b"fapico2-us959-secp-dec").into();
        scalar[0] &= 0x1f;
        let (_, sw) = apdu(&mut dispatcher, &put_key_ec_apdu(0xB8, &scalar));
        assert_eq!(sw, SW_OK, "PUT KEY DEC secp256k1 must answer 9000, got {sw:04x}");

        let eph = SecretKey::from_slice(&sha2::Sha256::digest(b"fapico2-us959-secp-eph")).unwrap();
        let private = SecretKey::from_slice(&scalar).unwrap();
        let z = k256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), private.public_key().as_affine())
            .raw_secret_bytes()
            .to_vec();
        let point = eph.public_key().to_encoded_point(false);
        assert_eq!(point.as_bytes().len(), 65, "uncompressed SEC1 point is 04||X||Y");

        // 1. `04 || X || Y` (65 bytes) — accepted, and the reply is still the
        //    bare 32-byte x-coordinate (gpg's scdaemon prepends `0x41`).
        let mut ok = vec![0xa6u8, 0x46, 0x7f, 0x49, 0x43, 0x86, 0x41];
        ok.extend_from_slice(point.as_bytes());
        verify_pw1(&mut dispatcher, 0x82);
        let (shared, sw) = apdu_read(&mut dispatcher, &pso_decipher_ec_apdu(&ok));
        assert_eq!(sw, SW_OK, "PSO:DECIPHER with 04||X||Y must answer 9000, got {sw:04x}");
        assert_eq!(shared, z, "the uncompressed branch must keep answering the raw x-coordinate");

        // 2. A 65-byte point without the 0x04 header is still refused.
        let mut bare = vec![0xa6u8, 0x46, 0x7f, 0x49, 0x43, 0x86, 0x41, 0x05];
        bare.extend_from_slice(&point.as_bytes()[1..]);
        verify_pw1(&mut dispatcher, 0x82);
        let (_, sw) = apdu_read(&mut dispatcher, &pso_decipher_ec_apdu(&bare));
        assert_eq!(
            sw, 0x6a80,
            "the uncompressed branch must keep requiring its 0x04 header, got {sw:04x}"
        );
    });
}

/// US-947, virt path: Brainpool P-256r1 — the US-944 backend obeys the same
/// rule (a stored KDF-DO leaves the raw shared point untouched).
#[test]
fn kdf_do_brainpool_p256r1_decipher_virt() {
    use bp256::elliptic_curve::sec1::ToSec1Point as _;
    use bp256::r1::BrainpoolP256r1;

    opcard::virt::with_ram_client("fapico2-openpgp-us947-kdf-bp256", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);
        personalize_pins(&mut dispatcher);

        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xC2, BP256R1_ECDH_ATTR));
        assert_eq!(sw, SW_OK, "PUT DATA C2 P-256r1 ECDH must answer 9000");
        let dec_scalar = bp256_scalar(b"fapico2-us947-bp256-dec");
        let (_, sw) = apdu(&mut dispatcher, &put_key_ec_apdu(0xB8, &dec_scalar));
        assert_eq!(sw, SW_OK, "PUT KEY DEC P-256r1 must answer 9000, got {sw:04x}");

        let eph = bp256::elliptic_curve::SecretKey::<BrainpoolP256r1>::from_bytes(
            &bp256_scalar(b"fapico2-us947-bp256-eph").into(),
        )
        .expect("deterministic ephemeral scalar");
        let private = bp256::elliptic_curve::SecretKey::<BrainpoolP256r1>::from_bytes(
            &dec_scalar.into(),
        )
        .expect("deterministic DEC scalar");
        let z = bp256::elliptic_curve::ecdh::diffie_hellman(
            private.to_nonzero_scalar(),
            eph.public_key().as_affine(),
        )
        .raw_secret_bytes()
        .to_vec();
        let eph_point = eph.public_key().to_sec1_point(false).as_bytes().to_vec();

        let salt_u = [0x9Du8; 8];
        let (_, sw) = apdu(
            &mut dispatcher,
            &put_data_apdu(0x00, 0xF9, &gpg_kdf_do(1, &salt_u, &[0x8B; 8], &[0x7B; 8])),
        );
        assert_eq!(sw, SW_OK, "PUT DATA F9 must answer 9000, got {sw:04x}");

        verify_pw1(&mut dispatcher, 0x82);
        let (shared, sw) = apdu_read(
            &mut dispatcher,
            &pso_decipher_ec_apdu(&brainpool_cipher_do(&eph_point)),
        );
        assert_eq!(sw, SW_OK, "PSO:DECIPHER P-256r1 (KDF-DO) must answer 9000, got {sw:04x}");
        assert_eq!(
            shared, z,
            "a stored KDF-DO must not change the raw ECDH x-coordinate"
        );
    });
}

// ---------------------------------------------------------------------------
// US-950: AES encipher/decipher roundtrip. The Extended Capabilities DO
// (GET DATA `00 C0`, first byte `0x7F`) advertises the "AES ENC/DEC" feature
// bit (`0x20`), and until this test nothing pinned the *encipher* half of
// that claim: `apps/openpgp` had PSO:DECIPHER coverage (the US-941 `0x02`
// SM routing guard) but no PSO:ENCIPHER coverage at all, so a host reading
// the DO had no evidence the forward direction worked. This closes the gap in
// both directions on one key: PUT DATA `00 D5` (the 32-byte AES-256 payload
// key, admin-authorized) → PSO:ENCIPHER (`00 2A 86 80`) → the `0x02`-prefixed
// PSO:DECIPHER route (`00 2A 80 86`) must return the plaintext byte-exact.
//
// The reply is `02 || ciphertext` (pso.rs `encipher` emits the same padding
// indicator the decipher route consumes), and both directions run under a
// zero IV with no padding — so the expected ciphertext is computed on the
// host with plain AES-256-CBC instead of trusting the round-trip identity
// itself. That matters: a pair of mutually inverse bugs (a stray IV byte
// threaded through both directions, a key-ID mix-up) would still round-trip
// but must not survive the host-computed assertion.

// `pso_encipher_apdu` and `aes256_cbc_zero_iv_encrypt` now live in
// `tests/common/mod.rs` (US-950 M3): the device-path twin in
// `device_pso.rs` must drive the identical request and the identical
// host-computed reference cipher, and a copy-pasted pair can silently drift.

#[test]
fn aes_encipher_decipher_roundtrip_virt() {
    opcard::virt::with_ram_client("fapico2-openpgp-aes-roundtrip", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);
        // US-912: PSO is refused while the factory PINs are in force; CRD
        // keeps the admin session, so the AES key import below still runs.
        personalize_pins(&mut dispatcher);

        // The AES payload key is the same 32-byte value both directions use;
        // `AES256_KEY_LEN` is 32 and `put_enc_dec_key` refuses anything else.
        let aes_key: [u8; 32] = core::array::from_fn(|i| (i as u8) * 7 + 1);

        // The AES path needs a PW1 "other" session (the wrapped AES key is
        // loaded under the user KEK of that session).
        let (_, sw) = apdu(
            &mut dispatcher,
            &[0x00, 0x20, 0x00, 0x82, 0x06, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
        );
        assert_eq!(sw, SW_OK, "VERIFY PW1 (other) must answer 9000");

        // Honesty, negative side: with no AES key provisioned the encipher
        // path must refuse (the wrapped-key load has nothing to unwrap)
        // rather than answer with a zero-key ciphertext — this is the probe
        // that shows the 9000 below comes from a real key, not a stub.
        let (_, sw) = apdu(&mut dispatcher, &pso_encipher_apdu(&[0x42; 16]));
        assert_eq!(
            sw, 0x6985,
            "PSO:ENCIPHER without an AES key must answer 6985, got {sw:04x}"
        );

        // Import the AES payload key: PUT DATA tag `00 D5`, admin-authorized.
        let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, 0xD5, &aes_key));
        assert_eq!(
            sw, SW_OK,
            "PUT DATA AES key (00 D5) must answer 9000, got {sw:04x}"
        );

        // Two blocks so the CBC chain is actually chained (a single block
        // would pass even if the IV chaining were dropped).
        let plaintext: [u8; 32] = *b"fapico2-us950-aes-roundtrip!!!!!";
        assert_eq!(plaintext.len(), 32, "plaintext must be two AES blocks");

        // Forward direction: the reply is `02 || ciphertext`, and the
        // ciphertext must be the host-computed AES-256-CBC (zero IV, no
        // padding) of the plaintext under the imported key.
        let (body, sw) = apdu_read(&mut dispatcher, &pso_encipher_apdu(&plaintext));
        assert_eq!(sw, SW_OK, "PSO:ENCIPHER must answer 9000, got {sw:04x}");
        assert_eq!(
            body.first(),
            Some(&0x02),
            "PSO:ENCIPHER must prefix the reply with the 02 padding indicator"
        );
        let ciphertext = &body[1..];
        assert_eq!(
            ciphertext,
            aes256_cbc_zero_iv_encrypt(&aes_key, &plaintext).as_slice(),
            "PSO:ENCIPHER must be AES-256-CBC under the PUT DATA D5 key, zero IV, no padding"
        );

        // Round direction: feed the card's own ciphertext back through the
        // `0x02`-prefixed decipher route — the plaintext must return
        // byte-exact.
        let (back, sw) = apdu_read(
            &mut dispatcher,
            &pso_decipher_apdu(body.as_slice()),
        );
        assert_eq!(
            sw, SW_OK,
            "PSO:DECIPHER of the enciphered DO must answer 9000, got {sw:04x}"
        );
        assert_eq!(
            back,
            plaintext.as_slice(),
            "AES ENC/DEC must roundtrip the plaintext byte-exact"
        );

        // Encipher length guard, pinned: a DO that is not a whole number of
        // blocks is refused (6A80). The order is the opposite of what an
        // earlier version of this comment claimed ("before any key work"):
        // `encipher` resolves the wrapped AES key first (`pso.rs:553-561`)
        // and only then checks the length (`pso.rs:562-565`), so this
        // assertion holds because a key *is* provisioned by this point — the
        // 6985 probe above is the same request one step earlier in the
        // function. The data field here is *not* stripped of a leading byte
        // (unlike decipher), so 17 bytes is the shortest non-multiple
        // shape.
        let (_, sw) = apdu(&mut dispatcher, &pso_encipher_apdu(&[0x42; 17]));
        assert_eq!(
            sw, 0x6A80,
            "PSO:ENCIPHER of a non-block-multiple DO must answer 6A80, got {sw:04x}"
        );
    });
}

// ---------------------------------------------------------------------------
// US-949, virt path: the AUT slot over secp256k1. The device path is pinned in
// `tests/device_pso.rs::int_auth_secp256k1_device_path`, but that runs through
// the platform `OpcardDispatch` (`Backend::Secp256k1` arm); here the reply is
// produced by opcard's *own* virt dispatch (`vendor/opcard/src/virt.rs`), whose
// `SoftwareSecp256k1` arm and reply buffer are a different code path, so the
// device test proves nothing about it. The AUT C3 attribute selects
// `Mechanism::Secp256k1Prehashed` (`pso.rs::int_aut_key_mecha_uif`) and the
// reply is a raw 64-byte `r || s` over the *supplied* digest — no re-hash.

/// INTERNAL AUTHENTICATE (INS 88) with the raw digest as command data.
fn int_auth_apdu(digest: &[u8], le: u8) -> Vec<u8> {
    let mut apdu_bytes = vec![0x00u8, 0x88, 0x00, 0x00, digest.len() as u8];
    apdu_bytes.extend_from_slice(digest);
    apdu_bytes.push(le);
    apdu_bytes
}

/// A fixed, valid secp256k1 scalar (below the curve order) for the AUT slot.
const SECP_AUT_SCALAR: [u8; 32] =
    hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464");

/// US-949, virt path: AUT slot + secp256k1 + INTERNAL AUTHENTICATE. Pins the
/// virt dispatch specifically:
///
/// 1. refused before the PW1 "other" session (6982);
/// 2. after PW1 (P2 = 82) a 64-byte raw `r || s` that verifies host-side,
///    prehashed, against the AUT public key read back from the card;
/// 3. the same request with a short Le (32) is chunked `61XX` and reassembles
///    byte-complete through GET RESPONSE;
/// 4. a tampered digest, a tampered `r` and a tampered `s` do not verify;
/// 5. a 31-byte digest is refused outright (the backend's length gate), not
///    signed.
#[test]
fn int_auth_secp256k1_virt_path() {
    use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
    use sha2::{Digest, Sha256};

    opcard::virt::with_ram_client("fapico2-openpgp-us949-int-auth", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // The authentication (C3) attribute routes the AUT slot through
        // `Mechanism::Secp256k1Prehashed`.
        let (_, sw) = apdu(
            &mut dispatcher,
            &put_data_apdu(0x00, 0xC3, ECDSA_SECP256K1_ATTR),
        );
        assert_eq!(sw, SW_OK, "PUT DATA C3 secp256k1 must answer 9000, got {sw:04x}");
        personalize_pins(&mut dispatcher);

        // Import the secp256k1 key into the AUT slot (CRT A4).
        let (_, sw) = apdu(&mut dispatcher, &put_key_ec_apdu(0xA4, &SECP_AUT_SCALAR));
        assert_eq!(sw, SW_OK, "PUT KEY AUT secp256k1 must answer 9000, got {sw:04x}");

        // The AUT public key the card reports (7F49 / 86 41 template).
        let (body, sw) = apdu_read(&mut dispatcher, &[0x00, 0x47, 0x81, 0x00, 0x02, 0xA4, 0x00, 0x00]);
        assert_eq!(sw, SW_OK, "READ PUBLIC KEY (AUT) must answer 9000, got {sw:04x}");
        let public = secp256k1_point_from_template(&body);
        let expected = k256::SecretKey::from_slice(&SECP_AUT_SCALAR)
            .expect("fixture is a valid secp256k1 scalar")
            .public_key();
        assert_eq!(
            public, expected,
            "the AUT read-back point must be the imported scalar's public key"
        );
        let verifying = k256::ecdsa::VerifyingKey::from(&public);

        let digest: [u8; 32] = Sha256::digest(b"fapico2-us949-int-auth-virt").into();

        // 1. No PW1 "other" session yet.
        let (body, sw) = apdu_read(&mut dispatcher, &int_auth_apdu(&digest, 0x00));
        assert_eq!(
            sw, 0x6982,
            "INT-AUTH without PW1-other must answer 6982, got {sw:04x}"
        );
        assert!(body.is_empty(), "the refusal must not carry a signature");

        verify_pw1(&mut dispatcher, 0x82);

        // 2. The signature itself.
        let (signature, sw) = apdu_read(&mut dispatcher, &int_auth_apdu(&digest, 0x00));
        assert_eq!(sw, SW_OK, "INT-AUTH secp256k1 must answer 9000, got {sw:04x}");
        assert_eq!(signature.len(), 64, "INT-AUTH reply must be a raw r || s pair");
        let sig = k256::ecdsa::Signature::from_slice(&signature)
            .expect("INT-AUTH reply must be a valid secp256k1 signature");
        verifying
            .verify_prehash(&digest, &sig)
            .expect("the INT-AUTH signature must verify prehashed over the digest");

        // 3. The virt reply buffer chunks a short Le and drains via 61XX.
        let (mut chunked, mut sw) = apdu(&mut dispatcher, &int_auth_apdu(&digest, 0x20));
        assert_eq!(chunked.len(), 32, "the first exchange must honor Le = 32");
        assert_eq!(
            sw,
            0x6100 | 0x20,
            "a short Le must answer 61XX with the remaining count, got {sw:04x}"
        );
        while sw & 0xFF00 == 0x6100 {
            let (chunk, next) = apdu(&mut dispatcher, &[0x00, 0xC0, 0x00, 0x00, (sw & 0xFF) as u8]);
            chunked.extend_from_slice(&chunk);
            sw = next;
        }
        assert_eq!(sw, SW_OK, "chunked INT-AUTH must complete with 9000, got {sw:04x}");
        assert_eq!(chunked.len(), 64, "the reassembled reply must be the full signature");
        let chunked_sig = k256::ecdsa::Signature::from_slice(&chunked)
            .expect("reassembled reply must be a valid secp256k1 signature");
        verifying
            .verify_prehash(&digest, &chunked_sig)
            .expect("the reassembled signature must verify too");

        // 4. Negatives: digest, r and s are each load-bearing.
        let mut tampered = digest;
        tampered[0] ^= 1;
        assert!(
            verifying.verify_prehash(&tampered, &sig).is_err(),
            "the signature must not verify over a tampered digest"
        );
        for (i, name) in [(0usize, "r"), (32, "s")] {
            let mut bad = signature.clone();
            bad[i] ^= 0x80;
            assert!(
                verifying
                    .verify_prehash(&digest, &k256::ecdsa::Signature::from_slice(&bad).unwrap())
                    .is_err(),
                "the signature must not verify with a tampered {name}"
            );
        }

        // 5. A wrong-length digest is refused, never signed. The backend's
        //    prehashed length gate refuses the sign, which opcard maps to
        //    the generic execution error (iso7816 0x6400).
        let (body, sw) = apdu_read(&mut dispatcher, &int_auth_apdu(&digest[..31], 0x00));
        assert_eq!(
            sw, 0x6400,
            "a 31-byte INT-AUTH digest must be refused, got {sw:04x}"
        );
        assert!(body.is_empty(), "the refusal must not carry a signature");
    });
}

/// US-949, virt path: the slot-misuse refusals are unaffected by the AUT work.
/// The per-slot algorithm narrowing (`types.rs` `AuthenticationAlgorithm` /
/// `SignatureAlgorithm` / `DecryptionAlgorithm`) still refuses an
/// algorithm that does not belong in that slot, and `pso.rs` still refuses to
/// INT-AUTH with a slot whose algorithm cannot sign. Pins:
///
/// 1. PUT DATA C3 (AUT) of the X25519 attribute → 6A80, nothing stored;
/// 2. PUT DATA C1 (SIG) of the X25519 attribute → 6A80, nothing stored;
/// 3. PUT DATA C2 (DEC) of the Ed255 attribute → 6A80, nothing stored;
/// 4. INT-AUTH pointed at the DEC slot (MSE mode `A4`, data `83 01 02`) while
///    C2 is the factory X25519 → 6985, even with a valid PW1-other session.
#[test]
fn slot_misuse_refusals_unaffected_virt() {
    opcard::virt::with_ram_client("fapico2-openpgp-us949-slot-misuse", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher: Dispatcher<1> = Dispatcher::new();
        assert!(dispatcher.register(&mut app), "register openpgp app");
        verified_card(&mut dispatcher);

        // X25519 ECDH attribute (algorithm 18) and the Ed25519 signature one.
        const X25519_ATTR: &[u8] = &[0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
        // The read-back form appends the `FF` usage byte (types.rs).
        const X25519_ATTR_PK: &[u8] =
            &[0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01, 0xFF];
        for (tag, attr, what) in [
            (0xC3u8, X25519_ATTR, "X25519 in the AUT slot"),
            (0xC1, X25519_ATTR, "X25519 in the SIG slot"),
            (0xC2, ED255_ATTR_PK, "Ed255 in the DEC slot"),
        ] {
            let (_, sw) = apdu(&mut dispatcher, &put_data_apdu(0x00, tag, attr));
            assert_eq!(
                sw, 0x6A80,
                "PUT DATA {tag:02x} with {what} must answer 6A80, got {sw:04x}"
            );
        }

        // Nothing was stored: C1/C3 keep the Ed25519 default, C2 the X25519
        // default (the read-back form appends the `FF` suffix).
        for (tag, expected, what) in [
            (0xC1u8, ED255_ATTR_PK, "C1"),
            (0xC2, X25519_ATTR_PK, "C2"),
            (0xC3, ED255_ATTR_PK, "C3"),
        ] {
            let (after, sw) = apdu_read(&mut dispatcher, &[0x00, 0xCA, 0x00, tag, 0x00]);
            assert_eq!(sw, SW_OK, "GET DATA {what} must answer 9000, got {sw:04x}");
            assert_eq!(
                after, expected,
                "{what} must keep its default attribute after the refused PUTs"
            );
        }

        // INT-AUTH aimed at the DEC slot, whose attribute is X25519. MSE
        // mode `A4` is the *authentication* keyref selector; its data
        // `83 01 02` names the DEC key.
        personalize_pins(&mut dispatcher);
        let (_, sw) = apdu(&mut dispatcher, &[0x00, 0x22, 0x41, 0xA4, 0x03, 0x83, 0x01, 0x02]);
        assert_eq!(sw, SW_OK, "MSE (use the DEC key for INT-AUTH) must answer 9000, got {sw:04x}");
        verify_pw1(&mut dispatcher, 0x82);
        let (body, sw) = apdu_read(&mut dispatcher, &int_auth_apdu(&[0x5A; 32], 0x00));
        assert_eq!(
            sw, 0x6985,
            "INT-AUTH with an X25519 slot algorithm must answer 6985, got {sw:04x}"
        );
        assert!(body.is_empty(), "the refusal must not carry a signature");
    });
}
