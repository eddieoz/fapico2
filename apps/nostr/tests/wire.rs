//! US-1643 — the public reads (`GET_INFO`, `LIST_KEYS`, `GET_PUBKEY`) and the
//! wire cap (EPIC design §2.2, §2.2.1).
//!
//! All three commands are **touch-free** (§2.3): a client may enumerate what
//! is on the device without pressing the button. The touch-gated commands
//! (`GENERATE_KEY` onwards) stay at the US-1642 skeleton's `6D00` until their
//! own stories land.
//!
//! The wire cap is asserted against the **device** constant
//! (`fapico2_platform::ccid::message::MAX_WIRE`), not against this host's
//! `MAX_RESPONSE` (4096): `platform/src/emulation.rs:81` writes the whole
//! dispatch buffer to the socket with no size check, so the emulator cannot
//! catch a `max_plaintext` claim the wire cannot carry. Over the CCID
//! transport an over-long response produces **no frame and no status word**
//! (`firmware/src/tasks.rs` drops it with a log line) — a device that
//! silently disappears is exactly the failure this test exists to keep off
//! the wire.

use fapico2_nostr::nip44::calc_padded_len;
use fapico2_nostr::{
    bech32_npub, NostrApp, APPLET_VERSION, CAPS, INS_GET_INFO, INS_GET_PUBKEY, INS_LIST_KEYS,
    MAX_PLAINTEXT,
};
use fapico2_platform::dispatch::{App, Sw, SW_OK};
use fapico2_platform::keyregion::crypto::{derive_payload_key, NOSTR_PAYLOAD_SECRET};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::nostr_store::{NostrIdentity, NostrRegion};
use fapico2_platform::keyregion::TOTAL_SLOTS;
use heapless::Vec as HeaplessVec;

/// The **device** CCID wire cap — defined on the platform (`ccid.rs`,
/// US-1644) so this test names the device transport without a
/// `fapico2-firmware` dev-dependency: that dependency's feature set leaks
/// into any crate built alongside nostr and distorts their gates (the
/// `emulation` variant turns on `fapico2-mgmt/piv`, the `device` variant
/// turns `fapico2-mgmt` into its device shape). The firmware's reassembler
/// re-exports the same constant, so the device path has not moved.
use fapico2_platform::ccid::message::MAX_WIRE;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn region_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fapico2-nostr-us1643-{}-{tag}.bin",
        std::process::id()
    ))
}

/// A fresh, empty region over the full geometry, sealed under a stand-in
/// payload key. The device derives the key from the OTP row + chipid; the
/// stand-ins here are the same shape the platform's own keyregion tests use.
fn fixture_region(path: &std::path::Path) -> NostrRegion {
    let region = FileKeyRegion::create(path, TOTAL_SLOTS).expect("a fresh region file");
    fixture_key(region)
}

/// Reopen an existing region file (fixture parity with [`fixture_region`]).
fn open_region(path: &std::path::Path) -> NostrRegion {
    let region = FileKeyRegion::open(path).expect("an existing region file");
    fixture_key(region)
}

fn fixture_key(region: FileKeyRegion) -> NostrRegion {
    let otp_row: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x11));
    let chipid: [u8; 8] = 0x0000_BADC_0FFE_EE01_0203_u64.to_be_bytes();
    let key = derive_payload_key(&otp_row, &chipid, &NOSTR_PAYLOAD_SECRET)
        .expect("a non-zero OTP row");
    NostrRegion::new(Box::new(region), key)
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
// The wire cap (§2.2.1) — the red-first test
// ---------------------------------------------------------------------------

/// `4 + len ≤ MAX_WIRE` for every command's largest response/request, against
/// the **device** constant.
///
/// The two heavy rows are the NIP-44 pair (§2.2.1's arithmetic); the reads
/// this story ships are far below the cap and are asserted anyway so the
/// test keeps naming *every* command's worst case, not just today's.
#[test]
fn wire_fits_max_wire() {
    assert_eq!(MAX_WIRE, 10 + 2048 + 16, "the device constant itself");

    let max_pt = MAX_PLAINTEXT as usize;

    // NIP44_ENCRYPT response: 0x02 ‖ nonce(32) ‖ ct ‖ mac(32) + SW(2),
    // where the ciphertext is 1 + padded and `padded` is the
    // **chunk-rounded** `calc_padded_len` the primitive layer actually
    // applies — the naive `ct ≥ plaintext + 2` bound points the wrong
    // way, because padding jumps 1792 → 2048 at n = 1793 and a "conservative"
    // row built on it advertises plaintexts whose response is off the wire
    // (no frame, no status word — the silent-disappearance failure).
    let padded = calc_padded_len(max_pt as u64).expect("MAX_PLAINTEXT itself pads") as usize;
    let encrypt_resp = 1 + 32 + (2 + 1 + padded) + 32 + 2;
    assert!(
        4 + encrypt_resp <= MAX_WIRE,
        "NIP44_ENCRYPT's largest response ({encrypt_resp} bytes) must fit the CCID wire \
         (MAX_WIRE = {MAX_WIRE})"
    );

    // NIP44_DECRYPT request: header(4) + Lc(sender_x(32) + payload(65+ct)),
    // where the payload is ver(1) + nonce(32) + ct + mac(32) and the
    // ciphertext of the padded plaintext. The reassembler refuses the
    // whole message past MAX_WIRE, so an over-long *request* never even
    // reaches the applet.
    let ct = 1 + calc_padded_len(max_pt as u64).expect("MAX_PLAINTEXT itself pads") as usize;
    let decrypt_req = 4 + 32 + 65 + ct;
    assert!(
        4 + decrypt_req <= MAX_WIRE,
        "NIP44_DECRYPT's largest request ({decrypt_req} bytes) must fit the CCID wire \
         (MAX_WIRE = {MAX_WIRE})"
    );

    // GET_PUBKEY response: npub(32) ‖ bech32_npub(63) + SW.
    assert!(wire(32 + 63 + 2) <= MAX_WIRE);

    // LIST_KEYS response, full set: n(1) + 8 × (idx ‖ flags ‖ npub(32) ‖
    // label_len(1) ‖ label ≤ 32).
    assert!(wire(1 + 8 * (1 + 1 + 32 + 1 + 32) + 2) <= MAX_WIRE);

    // GET_INFO response: 8 bytes + SW.
    assert!(wire(8 + 2) <= MAX_WIRE);
}

/// APDU-over-CCID wire cost of a payload — a runtime function so the
/// constant-fold linter cannot swallow the comparisons below (they are the
/// point of the test, not noise).
fn wire(payload: usize) -> usize {
    4 + payload
}

/// The §2.2.1 cap is a *derived* number, not a preference. The response row
/// is `4 + (1 + 32 + 2 + 1 + calc_padded_len(n) + 32 + 2) ≤ MAX_WIRE`, and
/// `calc_padded_len` is chunk-rounded (multiples of 256 above 256 bytes), so
/// the largest n whose padded length still fits is **1792**: 1792 pads to
/// itself (response 1,859 bytes), while 1793 pads to 2048 (response 2,115
/// bytes) — off the wire at 2,074, dropped with no frame and no status word
/// while GET_INFO still advertises it. If a future change wants a different
/// value it must re-derive both rows and change this test with them.
#[test]
fn max_plaintext_is_the_design_value() {
    assert_eq!(MAX_PLAINTEXT, 1792);

    // The neighbouring value betrays the jump: one byte more plaintext
    // rounds the padding up a whole chunk and pushes the response past the
    // wire. Stated as an assert so the arithmetic is re-checked, not
    // trusted.
    let padded_next = calc_padded_len(1793).expect("legal spec length") as usize;
    let next_resp = 4 + (1 + 32 + (2 + 1 + padded_next) + 32 + 2);
    assert!(next_resp > MAX_WIRE, "1793 must be off the wire — that is the cliff the cap sits behind");
    assert_eq!(
        calc_padded_len((MAX_PLAINTEXT - 1) as u64),
        calc_padded_len(MAX_PLAINTEXT as u64),
        "MAX_PLAINTEXT must sit at the top of a padding chunk"
    );

    // The trap the cap closes: at the host's dispatch-buffer scale the
    // encrypt response would already be off the wire. Stated as an assert
    // so the test fails loudly the day someone "fixes" the constant to
    // MAX_RESPONSE instead of re-deriving the rows.
    let host_scale = 4 + 1 + 32 + 2 + 1 + calc_padded_len(4096).expect("legal") as usize + 32 + 2;
    assert!(
        host_scale > MAX_WIRE,
        "the 4096-scale response must NOT fit the wire — that is the bug the cap exists for"
    );
}

// ---------------------------------------------------------------------------
// GET_INFO
// ---------------------------------------------------------------------------

/// `applet_ver(2) ‖ caps(2) ‖ max_plaintext(2) ‖ n_identities(1) ‖ flags(1)`
/// over an empty store.
#[test]
fn get_info_layout_over_an_empty_store() {
    let (mut app, path) = booted_app("getinfo-empty");

    let (data, sw) = call(&mut app, &apdu(INS_GET_INFO, 0, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(data.len(), 8);
    assert_eq!(&data[0..2], &APPLET_VERSION);
    assert_eq!(u16::from_be_bytes([data[2], data[3]]), CAPS, "the advertised caps");
    assert_eq!(u16::from_be_bytes([data[4], data[5]]), MAX_PLAINTEXT);
    assert_eq!(data[6], 0, "no identities yet");
    assert_eq!(data[7], 0, "flags reserved");
    std::fs::remove_file(path).ok();
}

/// Wrong P1/P2 is refused `6A86` — GET_INFO takes no P1 or P2, and the
/// design's rule is that a command with a shape it does not implement says
/// so rather than answering a different question.
#[test]
fn get_info_refuses_wrong_p1_p2() {
    let (mut app, path) = booted_app("getinfo-p1");
    let (_, sw) = call(&mut app, &apdu(INS_GET_INFO, 1, 0, &[]));
    assert_eq!(sw, 0x6A86);
    let (_, sw) = call(&mut app, &apdu(INS_GET_INFO, 0, 1, &[]));
    assert_eq!(sw, 0x6A86);
    std::fs::remove_file(path).ok();
}

/// Payload on a no-data command is wrong data.
#[test]
fn get_info_refuses_payload() {
    let (mut app, path) = booted_app("getinfo-data");
    let (_, sw) = call(&mut app, &apdu(INS_GET_INFO, 0, 0, &[0x00]));
    assert_eq!(sw, 0x6A80);
    std::fs::remove_file(path).ok();
}

// ---------------------------------------------------------------------------
// LIST_KEYS
// ---------------------------------------------------------------------------

/// `n(1)` then, per key, `idx ‖ flags ‖ npub(32) ‖ label_len ‖ label`, in
/// index order, skipping every slot that does not hold a live identity.
#[test]
fn list_keys_reports_live_identities_in_index_order() {
    let path = region_path("listkeys-live");
    std::fs::remove_file(&path).ok();
    let npub_a = core::array::from_fn(|i: usize| i as u8);
    let npub_b = core::array::from_fn(|i: usize| (i as u8).wrapping_add(0x80));
    {
        let mut region = fixture_region(&path);
        let mut store = region.store();
        store
            .write(0, &identity(0x20, npub_a, b"primary"))
            .expect("write idx 0");
        store
            .write(5, &identity(0x30, npub_b, b""))
            .expect("write idx 5");
    }
    let mut app = NostrApp::boot(open_region(&path));

    let (data, sw) = call(&mut app, &apdu(INS_LIST_KEYS, 0, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(data[0], 2, "two live identities");

    // idx 0 first: idx ‖ flags ‖ npub ‖ label_len ‖ label
    assert_eq!(data[1], 0);
    assert_eq!(&data[3..35], &npub_a);
    assert_eq!(data[35], 7);
    assert_eq!(&data[36..43], b"primary");

    // idx 5 second: label_len 0.
    let off = 43;
    assert_eq!(data[off], 5);
    assert_eq!(&data[off + 2..off + 34], &npub_b);
    assert_eq!(data[off + 34], 0);
    assert_eq!(data.len(), off + 35);

    std::fs::remove_file(path).ok();
}

/// An empty store lists zero keys — an ordinary answer, not an error.
#[test]
fn list_keys_over_an_empty_store_is_zero() {
    let (mut app, path) = booted_app("listkeys-empty");
    let (data, sw) = call(&mut app, &apdu(INS_LIST_KEYS, 0, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(data, [0]);
    std::fs::remove_file(path).ok();
}

#[test]
fn list_keys_refuses_wrong_p1_p2() {
    let (mut app, path) = booted_app("listkeys-p1");
    let (_, sw) = call(&mut app, &apdu(INS_LIST_KEYS, 0, 2, &[]));
    assert_eq!(sw, 0x6A86);
    std::fs::remove_file(path).ok();
}

// ---------------------------------------------------------------------------
// GET_PUBKEY
// ---------------------------------------------------------------------------

const NPUB_VECTOR_A: [u8; 32] = [
    0x0e, 0xc2, 0x1c, 0xc7, 0x2c, 0x7a, 0xed, 0xa7, 0x8f, 0xb3, 0xfa, 0x11, 0x75, 0xcd, 0xf3, 0x2b,
    0x7c, 0xcb, 0x4f, 0x92, 0x5a, 0xbd, 0x2d, 0x05, 0x16, 0x82, 0x9b, 0xb9, 0xd3, 0x96, 0x94, 0x34,
];

/// The npub bech32 string is 63 characters and matches a vector derived from
/// the BIP-173 reference pseudocode at authoring time (the checksum property
/// was verified against the same reference).
#[test]
fn bech32_npub_matches_the_reference_vectors() {
    // vec_a (see the hex above)
    assert_eq!(
        &bech32_npub(&NPUB_VECTOR_A),
        b"npub1pmppe3ev0tk60ranlgghtn0n9d7vknujt27j6pgks2dmn5ukjs6q7m22jp"
    );
    // vec_b: 32 × 0x01
    let vec_b: [u8; 32] = [0x01; 32];
    assert_eq!(
        &bech32_npub(&vec_b),
        b"npub1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs6v6lrm"
    );
    // vec_zero
    assert_eq!(
        &bech32_npub(&[0u8; 32]),
        b"npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhntnrk"
    );
}

/// `npub(32) ‖ bech32_npub(63)` for a live identity.
#[test]
fn get_pubkey_returns_npub_and_bech32() {
    let path = region_path("getpubkey-live");
    std::fs::remove_file(&path).ok();
    {
        let mut region = fixture_region(&path);
        let mut store = region.store();
        store
            .write(3, &identity(0x40, NPUB_VECTOR_A, b"test"))
            .expect("write idx 3");
    }
    let mut app = NostrApp::boot(open_region(&path));

    let (data, sw) = call(&mut app, &apdu(INS_GET_PUBKEY, 3, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(data.len(), 95);
    assert_eq!(&data[..32], &NPUB_VECTOR_A);
    assert_eq!(&data[32..], b"npub1pmppe3ev0tk60ranlgghtn0n9d7vknujt27j6pgks2dmn5ukjs6q7m22jp");

    std::fs::remove_file(path).ok();
}

/// An index outside the 8-slot range is *bad index* (`6A80`); an in-range
/// index with no live identity is *no such identity* (`6A82`). The two are
/// different facts (§2.2.0) and a client renders them differently.
#[test]
fn get_pubkey_separates_bad_index_from_missing_identity() {
    let (mut app, path) = booted_app("getpubkey-empty");
    let (_, sw) = call(&mut app, &apdu(INS_GET_PUBKEY, 8, 0, &[]));
    assert_eq!(sw, 0x6A80);
    let (_, sw) = call(&mut app, &apdu(INS_GET_PUBKEY, 255, 0, &[]));
    assert_eq!(sw, 0x6A80);
    let (_, sw) = call(&mut app, &apdu(INS_GET_PUBKEY, 4, 0, &[]));
    assert_eq!(sw, 0x6A82);
    std::fs::remove_file(path).ok();
}

// ---------------------------------------------------------------------------
// The storeless applet answers a fault, not a fiction
// ---------------------------------------------------------------------------

/// An applet booted without its region (OTP row unavailable, recovery
/// failure) refuses the reads with `0x6F00` — it cannot report `n = 0`,
/// because that would tell a client there are no identities on a device
/// that may hold all 8.
#[test]
fn a_storeless_applet_refuses_the_reads() {
    let mut app = NostrApp::new();
    let (_, sw) = call(&mut app, &apdu(INS_GET_INFO, 0, 0, &[]));
    assert_eq!(sw, 0x6F00);
    let (_, sw) = call(&mut app, &apdu(INS_LIST_KEYS, 0, 0, &[]));
    assert_eq!(sw, 0x6F00);
    let (_, sw) = call(&mut app, &apdu(INS_GET_PUBKEY, 0, 0, &[]));
    assert_eq!(sw, 0x6F00);
}

// ---------------------------------------------------------------------------
// The touch-gated commands are still the skeleton's refusals
// ---------------------------------------------------------------------------

/// US-1643 shipped only the three reads; US-1644/45 implemented `0x13`–`0x15`,
/// US-1649 the §2.2.0a trio (`0x18`–`0x1A`), and US-1653 the NIP-44 pair
/// (`0x16`/`0x17`). Nothing between `0x10` and `0x1A` remains refused with
/// `6D00` — the pin is that the pair has *left* this test's scope: an
/// accidental dispatch edit would surface as `6D00` here before any client
/// found it.
#[test]
fn the_nip44_pair_is_no_longer_the_skeleton_refusal() {
    let (mut app, path) = booted_app("skeleton-rest");
    for ins in [0x16u8, 0x17] {
        // Wrong shape (no peer key / payload) refuses as wrong shape, not as
        // unknown-insn — the point is that the arm exists at all.
        let (_, sw) = call(&mut app, &apdu(ins, 0, 0, &[]));
        assert_ne!(sw, 0x6D00, "INS {ins:#04x} must be dispatched");
    }
    std::fs::remove_file(path).ok();
}

// ---------------------------------------------------------------------------
// US-1685 — parse_data refuses malformed Lc forms
// ---------------------------------------------------------------------------

/// A truncated extended-Lc form is a malformed APDU, not "no data": the
/// header declares 65,535 bytes and carries none, and the honest answer is a
/// status word — not `GET_INFO`'s success shape (review P2: `parse_data`
/// treated the truncation as an empty data field, so `refuse_payload`
/// passed and the command executed).
#[test]
fn a_truncated_extended_lc_form_is_refused() {
    let (mut app, path) = booted_app("truncated-ext");
    // `00 10 00 00 00 FF FF` — extended form, declares 0xFFFF, carries 0.
    let bad: HeaplessVec<u8, 300> = [0x00u8, 0x10, 0x00, 0x00, 0x00, 0xFF, 0xFF]
        .into_iter()
        .collect();
    let (_, sw) = call(&mut app, &bad);
    assert_ne!(sw, SW_OK, "a declared length the frame does not carry must not succeed");
    assert_ne!(sw, 0x6D00, "the arm exists; this is a malformed-frame refusal");
    // And a short-form Lc=0 command with trailing bytes is wrong data too —
    // the bytes after the Lc window belong to no legal form.
    let trailing: HeaplessVec<u8, 300> = [0x00u8, 0x10, 0x00, 0x00, 0x00, 0xDE, 0xAD]
        .into_iter()
        .collect();
    let (_, sw) = call(&mut app, &trailing);
    assert_ne!(sw, SW_OK, "bytes past a short-form Lc=0 window are wrong data");
    // The empty case is untouched: a well-formed Lc=0 GET_INFO still answers
    // its success shape.
    let (data, sw) = call(&mut app, &apdu(INS_GET_INFO, 0, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert!(!data.is_empty(), "GET_INFO's success shape survives");
    std::fs::remove_file(path).ok();
}

// ---------------------------------------------------------------------------
// US-1699: EXPORT_KEY is gone
// ---------------------------------------------------------------------------

/// **EXPORT_KEY is refused on the CCID channel** (US-1699): the only
/// secret-returning command the applet ever had no longer exists, so the
/// `0x1A` APDU falls through to the dispatcher's `6D00` with an empty
/// body — no code path in the applet returns `id.scalar` any more (the
/// method is deleted, and the grep for the scalar-returning responder is
/// now a grep for a name that only occurs in tests naming its absence).
/// The slot it targeted is untouched.
#[test]
fn export_is_gone_on_ccid() {
    let path = region_path("export-gone");
    std::fs::remove_file(&path).ok();
    {
        let mut region = fixture_region(&path);
        let mut store = region.store();
        store
            .write(0, &identity(0x50, [0x77; 32], b""))
            .expect("seed idx 0");
    }
    let mut app = NostrApp::boot(open_region(&path));
    let (data, sw) = call(&mut app, &apdu(0x1A, 0, 0, &[]));
    assert_eq!(sw, 0x6D00, "EXPORT_KEY is refused, not served");
    assert!(data.is_empty(), "no frame leaks the secret");
    // The refused slot is untouched: GET_PUBKEY still serves the npub.
    let (_, sw) = call(&mut app, &apdu(INS_GET_PUBKEY, 0, 0, &[]));
    assert_eq!(sw, SW_OK, "the identity behind the refused slot survives");
    std::fs::remove_file(&path).ok();
}
