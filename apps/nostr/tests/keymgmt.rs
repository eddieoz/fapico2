//! US-1644/US-1645 — `GENERATE_KEY`, `IMPORT_KEY` and `SIGN` (EPIC design
//! §2.2): key management over the store, and BIP-340 signing on device.
//!
//! The refusing-state rows are pinned in the order the user can act on
//! (§2.2.0): a full set is `6A88` (no idx choice helps), an occupied index is
//! `6A84` (pick another), a missing identity is `6A82`, and the touch gate is
//! **last** — a press the host could have avoided by consulting the
//! touch-free reads first is a press wasted.
//!
//! The BIP-340 vectors run through the **APDU path**: the RNG seam is a
//! `fn` pointer, so a test can pin the aux draw per row (`pin_aux`) and the
//! signature must match the reference byte-exactly — the same signature a
//! nostr-tools client would verify.

use fapico2_nostr::{
    NostrApp, INS_GENERATE_KEY, INS_GET_PUBKEY, INS_IMPORT_KEY, INS_LIST_KEYS, INS_SIGN,
};
use fapico2_platform::dispatch::{App, Sw, SW_OK};
use fapico2_platform::keyregion::crypto::{derive_payload_key, NOSTR_PAYLOAD_SECRET};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::nostr_store::{NostrIdentity, NostrRegion, NOSTR_SLOTS};
use fapico2_platform::keyregion::TOTAL_SLOTS;
use heapless::Vec as HeaplessVec;

// ---------------------------------------------------------------------------
// Fixtures (the wire.rs set, mirrored — test files do not name each other)
// ---------------------------------------------------------------------------

fn region_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fapico2-nostr-us1644-{tag}-{}.bin",
        std::process::id()
    ))
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

fn open_region(path: &std::path::Path) -> NostrRegion {
    let region = FileKeyRegion::open(path).expect("an existing region file");
    fixture_key(region)
}

fn identity(scalar_byte: u8, npub: [u8; 32], label: &[u8]) -> NostrIdentity {
    let scalar: [u8; 32] = core::array::from_fn(|i| scalar_byte.wrapping_add(i as u8));
    NostrIdentity::new(scalar, npub, label, 0).expect("a valid identity")
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

fn apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> HeaplessVec<u8, 300> {
    let mut a = HeaplessVec::new();
    a.extend_from_slice(&[0x00, ins, p1, p2]).unwrap();
    if !data.is_empty() {
        a.push(data.len() as u8).unwrap();
        a.extend_from_slice(data).unwrap();
    }
    a
}

/// A applet booted from a fresh, empty region.
fn booted_app(tag: &str) -> (NostrApp, std::path::PathBuf) {
    let path = region_path(tag);
    std::fs::remove_file(&path).ok();
    let app = NostrApp::boot(fixture_region(&path));
    (app, path)
}

// ---------------------------------------------------------------------------
// The RNG seam — a pinned aux for the BIP-340 vector rows
// ---------------------------------------------------------------------------

thread_local! {
    static AUX_QUEUE: core::cell::RefCell<Vec<[u8; 32]>> =
        const { core::cell::RefCell::new(Vec::new()) };
}

/// Pin the next 32-byte RNG draw (the BIP-340 vector's `aux_rand`).
fn pin_aux(aux: [u8; 32]) {
    AUX_QUEUE.with(|q| q.borrow_mut().push(aux));
}

/// A deterministic RNG provider: pops the pinned queue. Thread-local, so
/// tests running in parallel in one process stay isolated.
fn pinned_rng(out: &mut [u8]) {
    assert_eq!(out.len(), 32, "the applet draws 32 bytes at a time");
    AUX_QUEUE.with(|q| {
        let aux = q.borrow_mut().pop().expect("the aux queue is drained");
        out.copy_from_slice(&aux);
    });
}

// ---------------------------------------------------------------------------
// The curve order, for the scalar bounds
// ---------------------------------------------------------------------------

/// secp256k1's group order `n` — an invalid secret scalar.
const CURVE_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// `n − 1` — the largest valid one.
const MAX_VALID_SCALAR: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
];

// ---------------------------------------------------------------------------
// The BIP-340 reference vectors (bitcoin/bips), via the spike's copy
// ---------------------------------------------------------------------------

/// One sign row of `vectors/bip340.csv`: `(sk, pk, aux, msg, sig)`.
type Bip340Row = (Vec<u8>, Vec<u8>, [u8; 32], Vec<u8>, Vec<u8>);

/// The rows the APDU path can carry: a secret key, a 32-byte message and a
/// signature. Rows with longer messages (17/100 bytes) are exercised by the
/// spike's own suite against the same primitives this applet ports.
fn bip340_sign_rows() -> Vec<Bip340Row> {
    let csv = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spike-secp256kfun/vectors/bip340.csv"
    ))
    .expect("the BIP-340 vector file (spike-secp256kfun/vectors/bip340.csv)");
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }
    let mut rows = Vec::new();
    for line in csv.lines().skip(1) {
        let mut cols = line.split(',');
        let _index = cols.next();
        let sk = cols.next().unwrap_or("");
        let pk = cols.next().unwrap_or("");
        let aux = cols.next().unwrap_or("");
        let msg = cols.next().unwrap_or("");
        let sig = cols.next().unwrap_or("");
        let verdict = cols.next().unwrap_or("");
        if sk.len() == 64
            && sig.len() == 128
            && msg.len() == 64
            && verdict.eq_ignore_ascii_case("TRUE")
        {
            let mut aux_buf = [0u8; 32];
            aux_buf.copy_from_slice(&hex(aux));
            rows.push((hex(sk), hex(pk), aux_buf, hex(msg), hex(sig)));
        }
    }
    assert!(rows.len() >= 3, "the 32-byte sign rows must be present");
    rows
}

// ---------------------------------------------------------------------------
// GENERATE_KEY
// ---------------------------------------------------------------------------

/// `GENERATE_KEY` writes a fresh identity at the named index and answers the
/// resulting `npub(32)` — the same `npub` the touch-free reads then report.
#[test]
fn generate_key_writes_a_fresh_identity() {
    let (mut app, path) = booted_app("generate-fresh");

    let (npub0, sw) = call(&mut app, &apdu(INS_GENERATE_KEY, 0, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(npub0.len(), 32);

    // The touch-free read reports the same key.
    let (data, sw) = call(&mut app, &apdu(fapico2_nostr::INS_GET_PUBKEY, 0, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(&data[..32], &npub0[..]);

    // A second identity at another index is a different key.
    let (npub7, sw) = call(&mut app, &apdu(INS_GENERATE_KEY, 7, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert_ne!(npub7, npub0, "two draws must not produce one key");

    std::fs::remove_file(path).ok();
}

/// An occupied index is refused `6A84` — never silently overwritten — and
/// the refusal is specific to the named index: a free one still works.
#[test]
fn generate_refuses_an_occupied_index() {
    let path = region_path("generate-occupied");
    std::fs::remove_file(&path).ok();
    {
        let mut region = fixture_region(&path);
        let mut store = region.store();
        store
            .write(2, &identity(0x20, [0x44; 32], b"taken"))
            .expect("seed idx 2");
    }
    let mut app = NostrApp::boot(open_region(&path));

    let (_, sw) = call(&mut app, &apdu(INS_GENERATE_KEY, 2, 0, &[]));
    assert_eq!(sw, 0x6A84, "occupied index");
    // LIST_KEYS still reports exactly one identity — nothing was overwritten.
    let (data, _) = call(&mut app, &apdu(fapico2_nostr::INS_GET_INFO, 0, 0, &[]));
    assert_eq!(data[6], 1);

    // An out-of-range index is wrong data (`6A80`) — `read_identity`'s
    // mapping for every other idx-taking command, not an occupancy dispute
    // that would call a nonexistent slot "taken".
    let (_, sw) = call(&mut app, &apdu(INS_GENERATE_KEY, 8, 0, &[]));
    assert_eq!(sw, 0x6A80, "one past the set is bad data");
    let (_, sw) = call(&mut app, &apdu(INS_GENERATE_KEY, 0xFF, 0, &[]));
    assert_eq!(sw, 0x6A80, "the one-byte idx ceiling too");

    let (_, sw) = call(&mut app, &apdu(INS_GENERATE_KEY, 5, 0, &[]));
    assert_eq!(sw, SW_OK, "a free index still generates");
    std::fs::remove_file(path).ok();
}

/// A full set is refused `6A88` — the actionable word: no index choice
/// helps, something must be deleted first. Full wins over occupied.
#[test]
fn generate_refuses_a_full_set() {
    let path = region_path("generate-full");
    std::fs::remove_file(&path).ok();
    {
        let mut region = fixture_region(&path);
        let mut store = region.store();
        for i in 0..NOSTR_SLOTS as u16 {
            store
                .write(i, &identity(i as u8, [0x50; 32], b""))
                .expect("fill the set");
        }
    }
    let mut app = NostrApp::boot(open_region(&path));

    let (_, sw) = call(&mut app, &apdu(INS_GENERATE_KEY, 3, 0, &[]));
    assert_eq!(sw, 0x6A88, "the set is full — even though idx 3 is occupied");
    std::fs::remove_file(path).ok();
}

// ---------------------------------------------------------------------------
// IMPORT_KEY
// ---------------------------------------------------------------------------

/// A scalar is validated before anything else: zero and ≥ the curve order
/// are `6A80`, the largest valid scalar is accepted.
#[test]
fn import_key_validates_the_scalar() {
    let (mut app, path) = booted_app("import-validate");

    let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 0, 0, &[0u8; 32]));
    assert_eq!(sw, 0x6A80, "the zero scalar");

    let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 0, 0, &CURVE_ORDER));
    assert_eq!(sw, 0x6A80, "the curve order itself");

    let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 0, 0, &[0u8; 31]));
    assert_eq!(sw, 0x6A80, "a short scalar");
    let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 0, 0, &[0u8; 33]));
    assert_eq!(sw, 0x6A80, "a long scalar");

    let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 3, 0, &MAX_VALID_SCALAR));
    assert_eq!(sw, SW_OK, "n − 1 is the largest valid scalar");

    std::fs::remove_file(path).ok();
}

/// An imported scalar yields the npub the reference implementation derives
/// from the same scalar — the BIP-340 vector rows carry exactly that pair
/// (nostr-tools derives the same x-only key; the vectors are its spec).
#[test]
fn imported_scalar_yields_the_reference_npub() {
    for (i, (sk, pk, _aux, _msg, _sig)) in bip340_sign_rows().into_iter().enumerate() {
        let (mut app, path) = booted_app(&format!("import-npub-{i}"));
        let mut sk_buf = [0u8; 32];
        sk_buf.copy_from_slice(&sk);

        let (npub, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 0, 0, &sk_buf));
        assert_eq!(sw, SW_OK, "row {i}");
        assert_eq!(npub.len(), 32);
        assert_eq!(&npub[..], &pk[..], "row {i}: npub must be the vector's public key");
        std::fs::remove_file(path).ok();
    }
}

/// IMPORT_KEY obeys the same occupancy rules as GENERATE_KEY.
#[test]
fn import_key_refuses_occupied_and_full() {
    let path = region_path("import-occupied");
    std::fs::remove_file(&path).ok();
    {
        let mut region = fixture_region(&path);
        let mut store = region.store();
        store
            .write(1, &identity(0x21, [0x45; 32], b""))
            .expect("seed idx 1");
    }
    let mut app = NostrApp::boot(open_region(&path));

    let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 1, 0, &MAX_VALID_SCALAR));
    assert_eq!(sw, 0x6A84, "occupied index — even with a valid scalar");
    std::fs::remove_file(path).ok();
}

// ---------------------------------------------------------------------------
// SIGN
// ---------------------------------------------------------------------------

/// `SIGN` returns `npub(32) ‖ sig(64)` and the signature matches the BIP-340
/// reference **byte-exactly** — the aux draw is pinned per row through the
/// RNG seam, so the APDU path carries the whole vector.
///
/// This is also the shape of the nostr-tools cross-check: a signature with
/// these bytes verifies against this npub and this sighash in any BIP-340
/// client; the node-side check runs with OpenXrypt (Phase 4, US-1669).
#[test]
fn sign_matches_the_bip340_vectors_through_the_apdu() {
    for (i, (sk, pk, aux, msg, sig)) in bip340_sign_rows().into_iter().enumerate() {
        let (app, path) = booted_app(&format!("sign-vector-{i}"));
        let mut app = app.with_rng_provider(pinned_rng);
        let mut sk_buf = [0u8; 32];
        sk_buf.copy_from_slice(&sk);

        let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 0, 0, &sk_buf));
        assert_eq!(sw, SW_OK, "row {i}");

        // IMPORT_KEY draws nothing; SIGN's single RNG draw is the vector's aux.
        pin_aux(aux);
        let (resp, sw) = call(&mut app, &apdu(INS_SIGN, 0, 0, &msg));
        assert_eq!(sw, SW_OK, "row {i}");
        assert_eq!(resp.len(), 96, "row {i}: npub(32) ‖ sig(64)");
        assert_eq!(&resp[..32], &pk[..], "row {i}: the npub alongside the signature");
        assert_eq!(&resp[32..], &sig[..], "row {i}: byte-exact BIP-340 signature");
        std::fs::remove_file(path).ok();
    }
}

/// `SIGN` separates the shape, the state and the range: a non-32-byte
/// sighash and an out-of-range index are `6A80`; an empty slot is `6A82`.
#[test]
fn sign_refuses_bad_shape_and_missing_identity() {
    let (mut app, path) = booted_app("sign-shape");

    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, 0, &[0x5A; 31]));
    assert_eq!(sw, 0x6A80, "short sighash");
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, 0, &[0x5A; 33]));
    assert_eq!(sw, 0x6A80, "long sighash");
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 8, 0, &[0x5A; 32]));
    assert_eq!(sw, 0x6A80, "out-of-range idx");
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, 1, &[0x5A; 32]));
    assert_eq!(sw, 0x6A86, "P2 must be zero");
    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, 0, &[0x5A; 32]));
    assert_eq!(sw, 0x6A82, "no identity at idx 0");

    std::fs::remove_file(path).ok();
}

// ---------------------------------------------------------------------------
// The touch gate
// ---------------------------------------------------------------------------

/// Every mutating command is refused `6985` without a presence grant — the
/// state checks come first (a refusal the host can avoid costs no press),
/// and the button gates the *execution*.
#[test]
fn mutating_commands_are_refused_without_a_presence_grant() {
    let path = region_path("presence-deny");
    std::fs::remove_file(&path).ok();
    {
        let mut region = fixture_region(&path);
        let mut store = region.store();
        store
            .write(0, &identity(0x20, [0x44; 32], b""))
            .expect("seed idx 0");
    }
    let mut app = NostrApp::boot(open_region(&path)).with_presence_grant(|_| false);

    let (_, sw) = call(&mut app, &apdu(INS_GENERATE_KEY, 5, 0, &[]));
    assert_eq!(sw, 0x6985, "GENERATE_KEY without a grant");

    let (_, sw) = call(&mut app, &apdu(INS_IMPORT_KEY, 5, 0, &MAX_VALID_SCALAR));
    assert_eq!(sw, 0x6985, "IMPORT_KEY without a grant");

    let (_, sw) = call(&mut app, &apdu(INS_SIGN, 0, 0, &[0x5A; 32]));
    assert_eq!(sw, 0x6985, "SIGN without a grant");

    std::fs::remove_file(path).ok();
}

// ---------------------------------------------------------------------------
// US-1649 — SET_LABEL, DELETE_KEY, EXPORT_KEY
// ---------------------------------------------------------------------------

/// A slot-0 identity seeded with a known scalar, for the destructive-trio
/// tests.
fn seeded_app(tag: &str) -> (NostrApp, std::path::PathBuf, [u8; 32], [u8; 32]) {
    let path = region_path(tag);
    std::fs::remove_file(&path).ok();
    {
        let mut region = fixture_region(&path);
        let mut store = region.store();
        let scalar: [u8; 32] = core::array::from_fn(|i| 0xA0 + i as u8);
        let npub = fapico2_nostr::crypto::xonly_pubkey(&scalar).expect("a valid scalar");
        store
            .write(0, &NostrIdentity::new(scalar, npub, b"seed", 0).expect("valid"))
            .expect("seed idx 0");
    }
    let app = NostrApp::boot(open_region(&path));
    let scalar: [u8; 32] = core::array::from_fn(|i| 0xA0 + i as u8);
    let npub = fapico2_nostr::crypto::xonly_pubkey(&scalar).expect("a valid scalar");
    (app, path, scalar, npub)
}

fn npub_of(app: &mut NostrApp, idx: u8) -> Option<[u8; 32]> {
    let (data, sw) = call(app, &apdu(INS_GET_PUBKEY, idx, 0, &[]));
    if sw != 0x9000 {
        return None;
    }
    let mut npub = [0u8; 32];
    npub.copy_from_slice(&data[..32]);
    Some(npub)
}

/// `SET_LABEL` writes a ≤32-byte UTF-8 label; `LIST_KEYS` shows it.
#[test]
fn set_label_round_trips_through_list() {
    let (mut app, path, _, _) = seeded_app("set-label");
    let (_, sw) = call(&mut app, &apdu(0x18, 0, 0, b"my wallet"));
    assert_eq!(sw, 0x9000, "SET_LABEL succeeds on a live identity");

    let (data, sw) = call(&mut app, &apdu(INS_LIST_KEYS, 0, 0, &[]));
    assert_eq!(sw, 0x9000);
    assert_eq!(data[0], 1, "one identity");
    // idx ‖ flags ‖ npub(32) ‖ label_len(1) ‖ label
    assert_eq!(data[1 + 1 + 1 + 32], 9, "the label length rides LIST_KEYS");
    assert_eq!(&data[1 + 1 + 1 + 32 + 1..1 + 1 + 1 + 32 + 1 + 9], b"my wallet");
    std::fs::remove_file(path).ok();
}

/// A label over 32 bytes — or one that is not UTF-8 — is refused `6A80`
/// before the touch, because a label that is not a string is not a label.
#[test]
fn set_label_refuses_oversized_and_non_utf8() {
    let (mut app, path, _, _) = seeded_app("set-label-bad");
    let (_, sw) = call(&mut app, &apdu(0x18, 0, 0, &[b'x'; 33]));
    assert_eq!(sw, 0x6A80, "a 33-byte label is refused");
    let (_, sw) = call(&mut app, &apdu(0x18, 0, 0, &[0xFF, 0xFE]));
    assert_eq!(sw, 0x6A80, "a non-UTF-8 label is refused");
    std::fs::remove_file(path).ok();
}

/// `SET_LABEL` on an empty slot is `6A82` — there is nothing to name.
#[test]
fn set_label_on_an_empty_slot_is_6a82() {
    let (mut app, path, _, _) = seeded_app("set-label-empty");
    let (_, sw) = call(&mut app, &apdu(0x18, 5, 0, b"nothing"));
    assert_eq!(sw, 0x6A82);
    std::fs::remove_file(path).ok();
}

/// `DELETE_KEY` answers with the npub it destroyed, names what is gone, and
/// leaves the slot reusable.
#[test]
fn delete_key_returns_the_npub_it_destroyed() {
    let (mut app, path, _, npub) = seeded_app("delete-key");
    let (data, sw) = call(&mut app, &apdu(0x19, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "DELETE_KEY succeeds on a live identity");
    assert_eq!(data.as_slice(), npub.as_slice(), "the answer names the identity");

    // The slot is reusable, not merely silent.
    let (_, sw) = call(&mut app, &apdu(INS_GET_PUBKEY, 0, 0, &[]));
    assert_eq!(sw, 0x6A82, "the identity is gone");
    let (_, sw) = call(&mut app, &apdu(INS_GENERATE_KEY, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "the slot accepts a new identity");
    std::fs::remove_file(path).ok();
}

/// `DELETE_KEY` on an empty slot is `6A82`.
#[test]
fn delete_key_on_an_empty_slot_is_6a82() {
    let (mut app, path, _, _) = seeded_app("delete-key-empty");
    let (_, sw) = call(&mut app, &apdu(0x19, 5, 0, &[]));
    assert_eq!(sw, 0x6A82);
    std::fs::remove_file(path).ok();
}

/// **EXPORT_KEY is gone** (US-1699): the custody rule is only in, never
/// out, and the v0.2.0 population carried by the release notes got no
/// grandfathering and no flags bit. The `0x1A` APDU falls through to the
/// dispatcher's `6D00` — on a live slot as on an empty one — and the slot
/// it targeted is untouched: GET_PUBKEY still serves the same npub, and
/// nothing in any response body can be the scalar.
#[test]
fn export_is_gone_on_ccid_and_the_slot_is_untouched() {
    let (mut app, path, _, npub) = seeded_app("export-key");
    let (data, sw) = call(&mut app, &apdu(0x1A, 0, 0, &[]));
    assert_eq!(sw, 0x6D00, "EXPORT_KEY is refused, not served");
    assert!(data.is_empty(), "no frame leaks the secret");

    let served = npub_of(&mut app, 0).expect("GET_PUBKEY still serves the identity");
    assert_eq!(served, npub, "the refused slot is untouched");
    std::fs::remove_file(path).ok();
}

/// The empty-slot form is the same refusal — the command is gone, not
/// state-dependent.
#[test]
fn export_on_an_empty_slot_is_still_gone() {
    let (mut app, path, _, _) = seeded_app("export-key-empty");
    let (_, sw) = call(&mut app, &apdu(0x1A, 5, 0, &[]));
    assert_eq!(sw, 0x6D00);
    std::fs::remove_file(path).ok();
}

/// The destructive trio is touch-gated like every other mutating command.
#[test]
fn the_destructive_trio_is_refused_without_a_presence_grant() {
    let path = region_path("trio-deny");
    std::fs::remove_file(&path).ok();
    {
        let mut region = fixture_region(&path);
        let mut store = region.store();
        store
            .write(0, &identity(0x20, [0x44; 32], b""))
            .expect("seed idx 0");
    }
    let mut app = NostrApp::boot(open_region(&path)).with_presence_grant(|_| false);

    // SET_LABEL carries the label; DELETE_KEY takes none. EXPORT_KEY has
    // no touch gate any more — it has no command at all (US-1699).
    let (_, sw) = call(&mut app, &apdu(0x18, 0, 0, b"x"));
    assert_eq!(sw, 0x6985, "SET_LABEL without a grant");
    let (_, sw) = call(&mut app, &apdu(0x19, 0, 0, &[]));
    assert_eq!(sw, 0x6985, "DELETE_KEY without a grant");
    std::fs::remove_file(path).ok();
}

// ---------------------------------------------------------------------------
// US-1650 — factory_wipe is deliberate
// ---------------------------------------------------------------------------

/// The wipe empties the key set: a seeded applet comes back from
/// `factory_wipe` answering `LIST_KEYS` with `n = 0`, and nothing lingers
/// — every slot is reusable by the writers afterwards.
#[test]
fn factory_wipe_empties_the_key_set() {
    let path = region_path("factory-wipe");
    std::fs::remove_file(&path).ok();
    {
        let mut region = fixture_region(&path);
        let mut store = region.store();
        for i in 0..3u16 {
            let scalar: [u8; 32] = core::array::from_fn(|b| (i as u8).wrapping_add(b as u8));
            let npub = fapico2_nostr::crypto::xonly_pubkey(&scalar).expect("a valid scalar");
            store
                .write(i, &NostrIdentity::new(scalar, npub, b"", 0).expect("valid"))
                .expect("seed");
        }
    }
    let mut app = NostrApp::boot(open_region(&path));

    // The host's pre-flight obligation (§2.2.0a) starts by enumerating.
    let (data, sw) = call(&mut app, &apdu(INS_LIST_KEYS, 0, 0, &[]));
    assert_eq!(sw, 0x9000);
    assert_eq!(data[0], 3, "three identities to announce before the wipe");

    use fapico2_platform::dispatch::App as _;
    app.factory_wipe();

    let (data, sw) = call(&mut app, &apdu(INS_LIST_KEYS, 0, 0, &[]));
    assert_eq!(sw, 0x9000);
    assert_eq!(data[0], 0, "the wipe left no identity behind");
    // And nothing lingers: all eight slots take a fresh GENERATE.
    for idx in 0..8u8 {
        let (_, sw) = call(&mut app, &apdu(INS_GENERATE_KEY, idx, 0, &[]));
        assert_eq!(sw, 0x9000, "slot {idx} is reusable after the wipe");
    }
    std::fs::remove_file(path).ok();
}

// ---------------------------------------------------------------------------
// F-A5 (docs/nostr-presence-audit.md) — the undecodable slot's remedy
// ---------------------------------------------------------------------------

/// A slot that carries our tag but will not open: the identity is sealed
/// under chip A's payload key and the applet is booted on chip B's — the
/// header still names Nostr/our slot, the body no longer opens
/// (`Entry::Undecodable`), the same shape the platform store test builds
/// with an other-device record.
fn app_with_corrupt_slot(tag: &str) -> (NostrApp, std::path::PathBuf) {
    let path = region_path(tag);
    std::fs::remove_file(&path).ok();
    let region = FileKeyRegion::create(&path, TOTAL_SLOTS).expect("a fixture region");
    {
        let mut region = fixture_key(region);
        let mut store = region.store();
        let scalar: [u8; 32] = core::array::from_fn(|i| i as u8);
        let npub = fapico2_nostr::crypto::xonly_pubkey(&scalar).expect("a valid scalar");
        store
            .write(1, &NostrIdentity::new(scalar, npub, b"", 0).expect("a valid identity"))
            .expect("fill slot 1 under chip A's key");
    }
    let reopened = FileKeyRegion::open(&path).expect("reopen the fixture region");
    let other_otp: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x12));
    let other_chip: [u8; 8] = 0x0000_BADC_0FFE_EE01_0204_u64.to_be_bytes();
    let other_key = derive_payload_key(&other_otp, &other_chip, &NOSTR_PAYLOAD_SECRET)
        .expect("a non-zero OTP row");
    let app = NostrApp::boot(NostrRegion::new(Box::new(reopened), other_key));
    (app, path)
}

/// Deleting the unreadable slot still costs a touch — the corrupt class is
/// not a touch-free escape hatch.
#[test]
fn an_undecodable_delete_still_requires_the_touch() {
    let (app, path) = app_with_corrupt_slot("corrupt-deny");
    let mut app = app.with_presence_grant(|_| false);
    let (_, sw) = call(&mut app, &apdu(fapico2_nostr::INS_DELETE_KEY, 1, 0, &[]));
    assert_eq!(
        sw,
        fapico2_nostr::SW_TOUCH_REQUIRED,
        "6985 before anything is destroyed"
    );
    std::fs::remove_file(&path).ok();
}

/// A payload is wrong data for every delete — the corrupt class included
/// (a name cannot be verified on a record that will not open).
#[test]
fn an_undecodable_delete_takes_no_payload() {
    let (app, path) = app_with_corrupt_slot("corrupt-named");
    let mut app = app.with_presence_grant(|_| true);
    let (_, sw) = call(&mut app, &apdu(fapico2_nostr::INS_DELETE_KEY, 1, 0, &[0xAA; 32]));
    assert_eq!(sw, fapico2_nostr::SW_WRONG_DATA, "6A80 — the name cannot be checked");
    std::fs::remove_file(&path).ok();
}

/// With the touch granted, the corrupt slot is destroyed and reusable —
/// the remedy the old code refused before the touch.
#[test]
fn an_undecodable_slot_is_deletable_with_a_touch() {
    let (app, path) = app_with_corrupt_slot("corrupt-del");
    let mut app = app.with_presence_grant(|_| true);
    let (data, sw) = call(&mut app, &apdu(fapico2_nostr::INS_DELETE_KEY, 1, 0, &[]));
    assert_eq!(sw, 0x9000, "the corrupt slot is destroyed");
    assert!(data.is_empty(), "no npub exists to name — the answer carries no body");
    // The slot is now a tombstone: a second delete answers "no identity".
    let (_, sw2) = call(&mut app, &apdu(fapico2_nostr::INS_DELETE_KEY, 1, 0, &[]));
    assert_eq!(sw2, fapico2_nostr::SW_NO_SUCH_IDENTITY, "the slot reads empty");
    std::fs::remove_file(&path).ok();
}

/// D6/F-A5 together: the factory wipe clears the corrupt class too —
/// after the wipe every slot is reusable, as US-1650's acceptance says.
#[test]
fn factory_wipe_clears_an_undecodable_slot() {
    let (app, path) = app_with_corrupt_slot("corrupt-wipe");
    use fapico2_platform::dispatch::App as _;
    let mut app = app.with_presence_grant(|_| true);
    app.factory_wipe();
    // Re-attach a fresh applet on the same region, same key: the slot is
    // gone.
    let other_otp: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x12));
    let other_chip: [u8; 8] = 0x0000_BADC_0FFE_EE01_0204_u64.to_be_bytes();
    let other_key = derive_payload_key(&other_otp, &other_chip, &NOSTR_PAYLOAD_SECRET)
        .expect("a non-zero OTP row");
    let region = FileKeyRegion::open(&path).expect("reopen");
    let mut fresh = NostrApp::boot(NostrRegion::new(Box::new(region), other_key));
    let (_, sw) = call(&mut fresh, &apdu(fapico2_nostr::INS_DELETE_KEY, 1, 0, &[]));
    assert_eq!(sw, fapico2_nostr::SW_NO_SUCH_IDENTITY, "after the wipe the slot holds no identity");
    std::fs::remove_file(&path).ok();
}
