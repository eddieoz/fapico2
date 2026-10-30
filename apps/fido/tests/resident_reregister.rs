//! US-1719 — the RED device-twin suite for resident re-registration shadowing
//! (EPIC FIDO-RESIDENT-DRIFT).
//!
//! Root-cause analysis: `docs/audits/2026-10-30-wrong-key-assertion-drift.md`
//! — §1 the verdict, §8 the bench reproduction this file pins as code. The
//! defect, in the four facts that analysis verified in source: resident
//! credential IDs are **deterministic** from `(rp_id, user.id)`
//! (`device_core.rs:1381-1390`); the credential key is a **fresh TRNG scalar
//! per registration** (`device_core.rs:1356-1368`); the region backend's
//! `put` **appends without dedup** (`fido_store.rs:1002-1046`); and assertion
//! lookup takes the **first match in index order** (`fido_store.rs:781-803`).
//! Together: a re-registration for the same (rp_id, user.id) is immediately
//! shadowed by the oldest same-ID record, and *its* key signs every pinned
//! assertion — a key the RP never registered for that credential ID.
//!
//! # Why the device twin and not the host twin
//!
//! `AGENTS.md` §1: there are two `FidoApp`s, and the host twin in `app.rs`
//! replaces by ID on re-registration (`device_keystore.rs:2568-2580` — the
//! analysis §4/§6 "twin mask"). That replace is exactly what the region
//! backend lost, so a host-twin test would pass forever while hardware
//! drifts. This file therefore boots `device_app::FidoApp` over an installed
//! key region through the shared `region_boot` fixture — the shipped path —
//! and asserts `backend() == KeyRegion` first, because a snapshot-backed run
//! would mask the defect by construction.
//!
//! # Why two scenarios are `#[ignore]`
//!
//! They are the diagnosis pinned as code, not failures awaiting a fix in this
//! story: US-1719 is forbidden from fixing anything. They must stay red until
//! US-1721/US-1722 land, and the pinned-assertion failure is *the defect
//! itself* — the signature verifies under K1, the oldest record. The ignore
//! message names the stories that will turn them green; run them with
//! `--ignored` to see the reproduction.
//!
//! # The signed message
//!
//! The fixture's `make_cred`/`get_assertion` both use challenge
//! `[0xCC; 32]` as the clientDataHash, so every ES256 signature here is
//! verified over `authData ‖ [0xCC; 32]` — GA responses carry no key, so
//! each registration's public key is tracked from its own makeCredential
//! response's attestedCredentialData COSE key.

mod region_boot;

use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
use fapico2_fido::crypto;
use heapless::Vec as HV;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use region_boot::*;

/// The RP the analysis reproduces with (`docs/audits/…drift.md` §8).
const RP: &str = "localhost";

/// A fixed `user.id` for both registrations. The analysis's real-world case
/// used `keccak256("Safe Owner")`; the value does not matter, only that it is
/// byte-identical across the two registrations — that is the precondition
/// (`§1`, fact 1) that makes the derived ID collide.
const USER_ID: &[u8] = b"us1719-drift-user";

const PIN: &[u8] = b"123456";
/// The fixture's constant challenge — the clientDataHash for every MC and GA
/// here, and therefore the digest tail of every verified signature.
const CHALLENGE: [u8; 32] = [0xCCu8; 32];

/// CTAP2_ERR_CREDENTIAL_EXCLUDED.
const ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;

/// The frozen resident-ID derivation, restated from the client's side.
///
/// `device_core.rs:1381-1390` computes
/// `SHA-256("fapico2-resident-id" ‖ SHA-256(rp_id) ‖ user_handle)`; the same
/// value is recomputed here so the scenario asserts the response's ID against
/// an independent derivation rather than against itself. Every scenario
/// asserts this equality, so the suite breaks loudly if anyone touches the
/// frozen derivation — the hazard the brief calls out by name.
fn derived_resident_id() -> Vec<u8> {
    let rp_hash = crypto::sha256(RP.as_bytes());
    let mut buf = Vec::new();
    buf.extend_from_slice(b"fapico2-resident-id");
    buf.extend_from_slice(&rp_hash);
    buf.extend_from_slice(USER_ID);
    crypto::sha256(&buf).to_vec()
}

/// The credential ID, and the attested P-256 key (x, y), out of a
/// makeCredential response.
///
/// Read off the wire through the fixture's own byte readers plus one walk of
/// the attestedCredentialData tail — the COSE key lives inside `authData`, a
/// nested map inside a byte string, which is the one shape `bstr_at` cannot
/// reach on its own.
fn mc_parts(cbor: &[u8]) -> (Vec<u8> /* authData */, Vec<u8> /* cred id */, [u8; 32], [u8; 32]) {
    let ad = bstr_at(cbor, 2).expect("makeCredential reply carries authData");
    // attestedCredentialData: rpIdHash(32) flags(1) signCount(4) aaguid(16)
    // credIdLen(2) credId COSE-key — the offsets every sibling parser uses.
    let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let cred_id = ad[55..55 + id_len].to_vec();
    let cose = &ad[55 + id_len..];
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    let mut p = Parser::new(cose);
    let Item::Map(n) = p.next().unwrap() else { panic!("COSE key is a map") };
    for _ in 0..n {
        let key = match p.next().unwrap() {
            Item::U(u) => u as i64,
            Item::N(n) => n,
            other => panic!("COSE label {other:?}"),
        };
        match key {
            -2 => match p.next().unwrap() {
                Item::B(b) => x.copy_from_slice(b),
                other => panic!("x is bytes, got {other:?}"),
            },
            -3 => match p.next().unwrap() {
                Item::B(b) => y.copy_from_slice(b),
                other => panic!("y is bytes, got {other:?}"),
            },
            _ => p.skip().unwrap(),
        }
    }
    (ad.to_vec(), cred_id, x, y)
}

/// The authData and DER signature out of a getAssertion response.
///
/// Keys 2 and 3 — key 1 (the echoed credential ID, present for an allowList
/// request) is exactly the value the analysis §2/O8 flags as a request echo,
/// and it is not the thing under test here: the *signature* is.
fn ga_parts(cbor: &[u8]) -> (Vec<u8> /* authData */, Vec<u8> /* DER sig */) {
    (
        bstr_at(cbor, 2).expect("getAssertion reply carries authData"),
        bstr_at(cbor, 3).expect("getAssertion reply carries a signature"),
    )
}

/// Does `signed` verify under the P-256 key `(x, y)`?
///
/// A total answer, not an `expect`: the pinned-assertion scenario needs to
/// try each candidate key and name *which one* verified, which a panicking
/// helper cannot report.
fn verifies_under(x: [u8; 32], y: [u8; 32], signed: &[u8], sig_der: &[u8]) -> bool {
    let mut point = [0u8; 65];
    point[0] = 0x04;
    point[1..33].copy_from_slice(&x);
    point[33..65].copy_from_slice(&y);
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&point) else {
        return false;
    };
    let Ok(sig) = Signature::from_der(sig_der) else {
        return false;
    };
    vk.verify(signed, &sig).is_ok()
}

/// One resident registration through the shipped command path.
///
/// Returns the credential ID and the attested key, and asserts the
/// deterministic derivation — the precondition every scenario rests on, and
/// the loud break the brief demands if the derivation is ever touched.
fn register(device: &mut Device) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let (status, cbor) = device.make_cred(RP, USER_ID);
    assert_eq!(status, 0x00, "resident makeCredential must succeed");
    let (_ad, cred_id, x, y) = mc_parts(&cbor);
    assert_eq!(
        cred_id,
        derived_resident_id(),
        "resident ID derivation drifted from the frozen \
         SHA-256(\"fapico2-resident-id\" ‖ SHA-256(rp_id) ‖ user.id) — US-1719's fixture contract"
    );
    (cred_id, x, y)
}

/// A resident makeCredential whose excludeList names `exclude_id`.
///
/// Built locally (the fixture's `make_cred` sends no exclude list, and the
/// one-file rule of this story forbids touching `region_boot`), but with the
/// same pair numbering the fixture documents: clientDataHash(1), rp(2),
/// user(3), pubKeyCredParams(4), excludeList(5), options(7), pinUvAuthParam(8),
/// pinUvAuthProtocol(9). The exclude entry is a `{type, id}` map — a bare
/// bstr would be discarded by `device_core.rs`'s parser and the refusal would
/// never fire.
fn make_cred_excluding(device: &mut Device, exclude_id: &[u8]) -> (u8, Vec<u8>) {
    let mut r: HV<u8, 512> = HV::new();
    nh::push_map_header(&mut r, 8).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_bstr(&mut r, &CHALLENGE).unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_tstr(&mut r, RP).unwrap();
    nh::push_uint(&mut r, 3).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_bstr(&mut r, USER_ID).unwrap();
    nh::push_uint(&mut r, 4).unwrap();
    nh::push_array_header(&mut r, 1).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "type").unwrap();
    nh::push_tstr(&mut r, "public-key").unwrap();
    nh::push_tstr(&mut r, "alg").unwrap();
    nh::push_neg(&mut r, -7).unwrap();
    nh::push_uint(&mut r, 5).unwrap();
    nh::push_array_header(&mut r, 1).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "type").unwrap();
    nh::push_tstr(&mut r, "public-key").unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_bstr(&mut r, exclude_id).unwrap();
    nh::push_uint(&mut r, 7).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "rk").unwrap();
    nh::push_bool(&mut r, true).unwrap();
    nh::push_uint(&mut r, 8).unwrap();
    nh::push_bstr(&mut r, &device.pin_auth(&CHALLENGE)).unwrap();
    nh::push_uint(&mut r, 9).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    device.call(0x01, r.as_slice())
}

/// Boot the region-backed twin the way every scenario needs it: a fresh
/// region file, a PIN-set snapshot persisted, presence granted, token minted.
///
/// The lock guard and the region file are returned because both must outlive
/// the device: the provider is a process-global (`region_boot`'s module docs)
/// and the file backs the region.
fn boot_pinned_device(tag: &str) -> (MutexGuardOf, InstalledRegion, Device) {
    let guard = lock();
    let region_file = install(tag);
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    device.set_pin(PIN);
    assert!(device.persist(), "the PIN write must reach the secure store");
    assert_eq!(
        device.backend(),
        fapico2_fido::device_keystore::CredentialBackend::KeyRegion,
        "the fixture must be region-backed — a snapshot-backed run replaces by ID \
         and masks the defect by construction (analysis §4, §6)"
    );
    (guard, region_file, device)
}

/// The serialisation guard's type, named once so the scenario signatures stay
/// readable (the guard must be bound, not dropped, for the whole test body).
type MutexGuardOf = std::sync::MutexGuard<'static, ()>;

/// **US-1719 scenario 1 — RED until US-1721/US-1722.**
///
/// Two registrations for the same (rp, user.id) mint K1 and K2 under the same
/// derived credential ID; a getAssertion pinned to that ID must sign under
/// **K2** (the newest registration — CTAP 2.1 §6.1.3 overwrite semantics,
/// which the region backend does not implement) and credMgmt must list
/// **exactly one** credential for the RP.
///
/// Today the signature verifies under **K1** — the oldest same-ID record wins
/// the first-match lookup — and credMgmt lists two. That failure *is* the
/// diagnosed defect (`docs/audits/2026-10-30-wrong-key-assertion-drift.md`
/// §1), reproduced without hardware; the panic message says so in those
/// words.
#[test]
#[ignore = "RED until US-1721/US-1722 (EPIC FIDO-RESIDENT-DRIFT)"]
fn pinned_assertion_after_reregistration_signs_with_the_newest_registrations_key() {
    let (_guard, _region, mut device) = boot_pinned_device("us1719-pinned");

    // Two registrations, same RP, same user.id, rk: true.
    let (cred_id, k1x, k1y) = register(&mut device);
    let (cred_id_2, k2x, k2y) = register(&mut device);
    assert_eq!(
        cred_id, cred_id_2,
        "the deterministic derivation must produce the same ID twice — the precondition"
    );

    // getAssertion pinned to the (shared) ID.
    let (status, cbor) = device.get_assertion(RP, Some(&cred_id));
    assert_eq!(
        status, 0x00,
        "the pinned assertion must be served at all: {cbor:02x?}"
    );
    let (auth_data, sig_der) = ga_parts(&cbor);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&CHALLENGE);

    if verifies_under(k2x, k2y, &signed, &sig_der) {
        // The post-fix state — nothing more to demand of the signature, but
        // the capacity half of the contract still has to hold.
    } else if verifies_under(k1x, k1y, &signed, &sig_der) {
        panic!(
            "RED — the diagnosed defect \
             (docs/audits/2026-10-30-wrong-key-assertion-drift.md §1): the pinned \
             assertion verified under registration #1's key (K1, the OLDEST same-ID \
             record), not under the newest registration's key (K2). Re-registration \
             is shadowed by the first-match index lookup, and a key the RP never \
             registered for this credential ID is signing."
        );
    } else {
        panic!(
            "the pinned assertion verified under NEITHER registration's key — not \
             the diagnosed shape; investigate before reading this as the defect"
        );
    }

    // The capacity half: credMgmt enumerateCredsBegin lists exactly ONE
    // credential for the RP. Today it lists two — the shadowed duplicate —
    // which is the §5.1 "every re-registration silently accumulates a
    // duplicate and burns a slot" half of the same defect. totalCredentials
    // is PicoForge key 9 (AGENTS.md §2; the dialect is binding).
    let (status, cbor) = device.cm_enumerate_creds(RP);
    assert_eq!(status, 0x00, "enumerateCredsBegin must succeed: {cbor:02x?}");
    let total = uint_at(&cbor, 9).expect("totalCredentials at PicoForge key 9");
    assert_eq!(
        total, 1,
        "credMgmt must list exactly 1 credential for the RP; found {total} — \
         the shadowed duplicate of the re-registration"
    );
}

/// **US-1719 scenario 2 — part of the pinned contract; may be green today.**
///
/// The same two registrations, but the getAssertion carries an **empty**
/// allowList (discovery). Discovery enumerates the RP's credentials
/// newest-first (`device_core.rs:1750-1755`), so this may already verify
/// under K2 — the analysis §2/O1 explains why the app saw a *correct* key on
/// its immediate post-registration probe while every pinned probe drifted.
/// It is pinned anyway, ignored on the same schedule: the story's contract is
/// that *both* request shapes serve the newest record, and if it is green
/// today it must stay green through the fix.
#[test]
#[ignore = "RED until US-1721/US-1722 (EPIC FIDO-RESIDENT-DRIFT)"]
fn discovery_after_reregistration_also_serves_the_newest_record() {
    let (_guard, _region, mut device) = boot_pinned_device("us1719-discovery");

    let (_cred_id, k1x, k1y) = register(&mut device);
    let (_cred_id_2, k2x, k2y) = register(&mut device);

    // Discovery: no allowList.
    let (status, cbor) = device.get_assertion(RP, None);
    assert_eq!(
        status, 0x00,
        "the discovery assertion must be served at all: {cbor:02x?}"
    );
    let (auth_data, sig_der) = ga_parts(&cbor);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&CHALLENGE);

    if verifies_under(k2x, k2y, &signed, &sig_der) {
        // Newest-first discovery — the observed behaviour today (analysis
        // §2/O1) and the required behaviour after the fix.
    } else if verifies_under(k1x, k1y, &signed, &sig_der) {
        panic!(
            "RED — discovery served the OLDEST registration's key (K1). Discovery \
             *selects* newest-first (device_core.rs:1750-1755), but build_assertion's \
             by-ID re-fetch (device_core.rs:1859) re-resolves that ID to the first \
             index-order match — the oldest same-ID record — so both request shapes \
             collapse onto K1. See docs/audits/2026-10-30-wrong-key-assertion-drift.md §2."
        );
    } else {
        panic!(
            "the discovery assertion verified under NEITHER registration's key — not \
             the diagnosed shape; investigate before reading this as the defect"
        );
    }
}

/// **US-1719 scenario 3 — runs green immediately; the refusal already works.**
///
/// With the first registration live, a makeCredential whose excludeList names
/// the derived ID must be refused `CTAP2_ERR_CREDENTIAL_EXCLUDED` (0x19) —
/// the exclude check iterates `req.exclude` and answers on the first by-ID
/// hit (`device_core.rs:1249-1264`) — and the stored credential must still
/// sign under its own key (K1). This is the control that shows the device
/// *can* discriminate the live credential; the defect in scenarios 1–2 is not
/// a broken filter but a duplicate the client was never asked about.
#[test]
fn exclude_list_naming_the_live_credential_refuses_reregistration() {
    let (_guard, _region, mut device) = boot_pinned_device("us1719-exclude");

    // The live registration.
    let (cred_id, k1x, k1y) = register(&mut device);

    // Re-registration attempt naming it in the exclude list.
    let (status, body) = make_cred_excluding(&mut device, &cred_id);
    assert_eq!(
        status, ERR_CREDENTIAL_EXCLUDED,
        "MC with excludeCredentials naming the live credential must be refused \
         CTAP2_ERR_CREDENTIAL_EXCLUDED: {body:02x?}"
    );

    // And the stored credential is unharmed: it still signs, under K1.
    let (status, cbor) = device.get_assertion(RP, Some(&cred_id));
    assert_eq!(status, 0x00, "the stored credential must still serve: {cbor:02x?}");
    let (auth_data, sig_der) = ga_parts(&cbor);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&CHALLENGE);
    assert!(
        verifies_under(k1x, k1y, &signed, &sig_der),
        "the stored credential must still sign under K1 after the refused re-registration"
    );
}
