//! US-173 / US-174 (EPIC `PICOForge-COMPAT`) — the RS-Key audit journal over
//! the `0x41` vendor channel: `AUDIT_READ` (`0x07`), `AUDIT_CHECKPOINT`
//! (`0x08`) and `AUDIT_CONFIG` (`0x0E`).
//!
//! # What these tests are for, and what they deliberately are not
//!
//! The journal's **state** is not tested here. Ring eviction, the epoch fold,
//! the checkpoint key and the durable commit are `vendor41_state.rs`'s
//! subject, and duplicating them would give two tests that can both pass while
//! the property they share is wrong. What is tested here is everything that
//! sits *between* the state and the wire, which is the part this story adds:
//!
//! 1. **The 20-byte record framing** — the EPIC's named test, and the field
//!    offsets and endiannesses it claims.
//! 2. **The host's own length rule** — `entries.len() == 20 × (seq_next −
//!    start)`, transcribed from `audit.rs:175-178` and applied to real emitted
//!    bytes, at every CBOR head width, including both degenerate windows.
//! 3. **The signed message**, verified as an ECDSA signature over a message
//!    this file assembles itself from the published constant. This is the test
//!    that catches the 17-vs-18 byte tag bug, and it has to be a *verification*
//!    and not a length assertion: a firmware that padded the tag to 18
//!    produces a perfectly well-formed response that only fails when someone
//!    checks the maths, and the operator's only symptom is an Audit screen
//!    saying the journal is unauthentic.
//! 4. **The gating**, split into its halves: that target 2 of `AUDIT_CONFIG`
//!    is ungated *and never looks at a MAC*, and that targets 0/1 and the
//!    other two sub-commands are gated — with the PIN-auth charging rule
//!    pinned in both directions.
//! 5. **The `m_bool` compatibility claim**, both directions: this firmware's
//!    encoder emits a real CBOR boolean, and a transcription of the client's
//!    lenient parse reads it back.
//!
//! # A word on what "the client" means in this file
//!
//! The client is Rust, in `picoforge/src/hal/fido/`, and its rule is
//! transcribed here as a literal rather than reached for through a dependency.
//! Two reasons, in order: the crate is not a dependency of this workspace, and
//! — more importantly — a test that imported the client's own `build_journal`
//! would be checking this firmware against itself on the one point where the
//! EPIC is wrong. The tag length is exactly the kind of thing two
//! implementations, each believing the other got it right, would agree on.
//! Every transcription below carries its `file:line`.

use fapico2_fido::cbor::no_heap as nh;
use fapico2_fido::crypto;
use fapico2_fido::ctap2::Ctap2Response;
use fapico2_fido::device_keystore::DeviceKeystore;
use fapico2_fido::vendor41::{
    AuditRecord, AuditWindow, Checkpoint, MseChannel, MsePoint, OrgAttestation,
    OrgAttestationView, PresenceGate, SoftLock, Subcommand, TokenAuth, VendorOps,
    AUDIT_CHECKPOINT_TAG, AUDIT_ENTRY_LEN, AUDIT_RING_MAX, P256_POINT_LEN, SIG_DER_MAX,
};
use fapico2_fido::vendor_audit::{
    audit_checkpoint, audit_config, audit_config_target, audit_read, checkpoint_challenge,
    expected_entries_len, token_or_touch_gate, write_audit_config_response, AuditResult,
    ChargePinAuth, AUDIT_CFG_DISABLE, AUDIT_CFG_ENABLE, AUDIT_CFG_STATUS, AUDIT_CHALLENGE_LEN,
    AUDIT_ENTRIES_MAX, AUDIT_EPOCH_LEN, AUDIT_READ_FRAME_MAX, REPLY_MAX,
};
use fapico2_fido::vendor_state::{with_keystore_ops, VendorSession};
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;
use p256::ecdsa::signature::Verifier as _;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type Reply = HV<u8, { REPLY_MAX }>;
type Msg = HV<u8, 192>;

/// A device keystore with the journal **enabled** and `n` records in it.
///
/// Enabling is a direct `audit_enabled = true`, which is the same durable
/// field `AUDIT_CONFIG` target 1 flips. A test that got the opt-in wrong would
/// see an empty journal here and fail every length assertion, which is the
/// right direction for a mistake to fail in.
fn journal_with(n: u32) -> DeviceKeystore {
    let mut trng = HostTrng::new();
    let mut ks = DeviceKeystore::fresh(&mut trng).expect("host TRNG");
    ks.vendor.public.audit_enabled = true;
    for i in 0..n {
        ks.vendor.public.push_audit(AuditRecord {
            // Distinct in every byte the host parses, so a field-order or
            // endianness regression cannot pass by accident.
            uptime_ms: 0x0102_0300u32.wrapping_add(i),
            event: 0x20u8.wrapping_add(i as u8),
            aux: 0x40u8.wrapping_add(i as u8),
            detail: [i as u8; 8],
        });
    }
    ks
}

/// The real device [`VendorOps`], over a throwaway snapshot.
///
/// `store: None` is the dispatcher-bridge path `grow_checked` documents, and
/// the entropy is a counter because the only entropy consumer in these tests
/// is the one-time audit checkpoint key.
fn with_ops<R>(ks: &mut DeviceKeystore, f: impl FnOnce(&mut dyn fapico2_fido::vendor_backup::BackupOps) -> R) -> R {
    let mut session = VendorSession::default();
    let mut counter = 0u8;
    let mut random = move |b: &mut [u8]| {
        for x in b.iter_mut() {
            counter = counter.wrapping_add(1);
            *x = counter;
        }
    };
    let mut store = None;
    with_keystore_ops(ks, &mut session, &mut store, &mut random, f)
}

/// A [`TokenAuth`] carrying a real `0x20` (`PERM_ACFG`) token.
fn token_auth(token: &[u8; 32]) -> TokenAuth<'_> {
    TokenAuth { token, permissions: 0x20, blocked: false }
}

/// A presence gate whose synchronous poll answers `granted`.
///
/// The `poll` arm is the host/emulation path; the device's `window_grant` arm
/// is join-only and answers `0x3B` on the first call, which is the documented
/// two-step. Testing the poll arm here is testing the same "a grant is a
/// grant" question without the retry loop.
///
/// A **function item** rather than a closure: `PresenceGate::poll` is
/// `Option<fn() -> bool>`, and a closure that captures `granted` does not
/// coerce. Two non-capturing items do.
fn presence(granted: bool) -> PresenceGate {
    fn yes() -> bool {
        true
    }
    fn no() -> bool {
        false
    }
    PresenceGate { window_grant: None, poll: Some(if granted { yes } else { no }), tag: 0 }
}

// ---------------------------------------------------------------------------
// Request builders. Raw bytes, not `cbor::encode`, because the MAC covers the
// params' *wire* bytes and a re-encoding would have to match `ciborium`'s
// canonical form byte for byte to test anything real.
// ---------------------------------------------------------------------------

/// The `subCommandParams` bytes for `AUDIT_CHECKPOINT`: `{1: <16-byte bstr>}`.
fn ckpt_params(challenge: &[u8; AUDIT_CHALLENGE_LEN]) -> Msg {
    let mut p: Msg = HV::new();
    nh::push_map_header(&mut p, 1).unwrap();
    nh::push_uint(&mut p, 1).unwrap();
    nh::push_bstr(&mut p, challenge).unwrap();
    p
}

/// The `subCommandParams` bytes for `AUDIT_CONFIG`: `{1: <uint>}`.
fn cfg_params(target: u8) -> Msg {
    let mut p: Msg = HV::new();
    nh::push_map_header(&mut p, 1).unwrap();
    nh::push_uint(&mut p, 1).unwrap();
    nh::push_uint(&mut p, target as u64).unwrap();
    p
}

/// The MAC input `verify_mac` assembles (`vendor41.rs:2793-2800`):
/// `0xFF × 32 ‖ 0x41 ‖ subCommand ‖ subCommandParams`.
///
/// Transcribed from `vendor41::verify_mac`, and the mirror of the client's
/// `ops.rs:1576-1581`. The params tail is the **serialised params value**, not
/// a re-encoding of the decoded one.
fn mac_input(sub: u8, params: &[u8]) -> Msg {
    let mut m: Msg = HV::new();
    m.resize(32, 0xFF).unwrap();
    m.extend_from_slice(&[0x41, sub]).unwrap();
    m.extend_from_slice(params).unwrap();
    m
}

fn mac_of(token: &[u8; 32], sub: u8, params: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 32];
    crypto::hmac_sha256_into(token, &mac_input(sub, params), &mut out);
    out[..16].to_vec()
}

/// The `0x41` request body. `params == None` omits key 2 entirely, which is
/// what `ops.rs:1563-1565` does for `AUDIT_READ`.
fn request(sub: u8, params: Option<&[u8]>, token: Option<&[u8; 32]>) -> Msg {
    let pairs = 1 + usize::from(params.is_some()) + 2 * usize::from(token.is_some());
    let mut b: Msg = HV::new();
    nh::push_map_header(&mut b, pairs).unwrap();
    nh::push_uint(&mut b, 1).unwrap();
    nh::push_uint(&mut b, sub as u64).unwrap();
    if let Some(p) = params {
        nh::push_uint(&mut b, 2).unwrap();
        b.extend_from_slice(p).unwrap();
    }
    if let Some(t) = token {
        nh::push_uint(&mut b, 3).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 4).unwrap();
        nh::push_bstr(&mut b, &mac_of(t, sub, params.unwrap_or(&[]))).unwrap();
    }
    b
}

// ---------------------------------------------------------------------------
// The client's rules, transcribed. `picoforge/src/hal/fido/`.
// ---------------------------------------------------------------------------

/// `audit.rs::build_journal`'s acceptance test, verbatim in behaviour
/// (`audit.rs:169-186`).
fn host_accepts_window(start: u32, seq_next: u32, entries: &[u8]) -> Result<(), String> {
    let expected = (seq_next.saturating_sub(start) as usize) * AUDIT_ENTRY_LEN;
    if !entries.len().is_multiple_of(AUDIT_ENTRY_LEN) || entries.len() != expected {
        return Err("export length does not match the window — corrupt journal?".into());
    }
    Ok(())
}

/// `audit::fold_chain` (`audit.rs:133-143`): `h = SHA-256(h ‖ entry)` per
/// **raw 20-byte** chunk, seeded with the epoch.
fn host_fold_chain(epoch: &[u8; 32], entries: &[u8]) -> [u8; 32] {
    let mut h = *epoch;
    for chunk in entries.chunks(AUDIT_ENTRY_LEN) {
        let mut buf = [0u8; 32 + AUDIT_ENTRY_LEN];
        buf[..32].copy_from_slice(&h);
        buf[32..32 + chunk.len()].copy_from_slice(chunk);
        h = crypto::sha256(&buf[..32 + chunk.len()]);
    }
    h
}

/// `audit::fingerprint` (`audit.rs:145-149`): lowercase hex of
/// `SHA-256(pubkey)[..8]` — 16 characters. The hash input is the **raw 65
/// bytes**, not its hex form; that is the trap, because a device that hashed
/// the hex would also produce 16 lowercase hex characters, and the operator's
/// pin would never match a later run.
fn host_fingerprint(pubkey: &[u8]) -> String {
    let d = crypto::sha256(pubkey);
    d[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// `audit::verify_checkpoint`'s message (`audit.rs:159-162`): the tag, then
/// head, then `seq` **little-endian**, then the challenge.
///
/// # The tag is a **literal** here, not the firmware's constant
///
/// This is the one place in the file where reaching for
/// [`AUDIT_CHECKPOINT_TAG`] would be a mistake, and the mistake is subtle
/// enough to be worth stating. If the test builds the message from the same
/// constant the firmware signs with, then a firmware that padded the tag to 18
/// produces a message the test *agrees* with, the ECDSA verification **passes**,
/// and the only thing that can fail is a length assertion. Verified: with the
/// constant mutated to 18 bytes, a constant-driven test reports
/// `left: 70, right: 69` and never reaches a cryptographic check.
///
/// The client is the ground truth — `CKPT_TAG` is a `&[u8]` at `audit.rs:17`
/// and `verify_checkpoint` extends with it verbatim at `audit.rs:160`, so it is
/// 17 bytes — and a test that derives its expectation from the thing under test
/// is not a test of that thing. So the tag is spelled out here, the
/// verification runs against it, and the constant is checked against it
/// *afterwards*, so a regression surfaces as `signature_ok: false` (the
/// operator's symptom) with the literal mismatch as the diagnosis.
fn host_checkpoint_message(head: &[u8; 32], seq: u32, challenge: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(CLIENT_CKPT_TAG);
    msg.extend_from_slice(head);
    msg.extend_from_slice(&seq.to_le_bytes());
    msg.extend_from_slice(challenge);
    msg
}

/// The client's domain separator, transcribed from
/// `picoforge/src/hal/fido/audit.rs:17`.
///
/// **17 bytes.** The EPIC's US-174 bullet says *"18 ASCII bytes, no NUL"* and
/// the count is wrong: `R S K - A U D I T - C K P T - v 1` is
/// 3+1+5+1+4+1+2 = 17. A firmware that pads to 18 because the prose says 18
/// signs a 70-byte message, no host accepts it, and the Audit screen reports
/// an unauthentic journal on a device that is correct.
const CLIENT_CKPT_TAG: &[u8] = b"RSK-AUDIT-CKPT-v1";

/// `mod.rs::m_bool` (`mod.rs:1558-1565`): a CBOR bool, or a non-zero
/// integer; **anything else, including a missing key, is `false`**.
fn host_m_bool(map: &[(u64, Option<bool>, Option<u64>)], key: u64) -> bool {
    match map.iter().find(|(k, _, _)| *k == key) {
        Some((_, Some(b), _)) => *b,
        Some((_, _, Some(n))) => *n != 0,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Response decoding.
//
// The tests decode with this crate's decoder and then re-derive the client's
// rules from the decoded values — so a round trip through one encoder/decoder
// pair is never the thing being asserted.
// ---------------------------------------------------------------------------

/// `{1: uint, 2: uint, 3: bytes(32), 4: bytes}` from an `AUDIT_READ` body.
fn parse_audit_read(body: &[u8]) -> (u32, u32, [u8; 32], Vec<u8>) {
    use nh::{Item, Parser};
    let mut p = Parser::new(body);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => panic!("the body must be a CBOR map, got {body:02x?}"),
    };
    assert_eq!(pairs, 4, "the map must have exactly the four defined keys");
    let (mut start, mut seq_next, mut epoch, mut entries) = (None, None, None, None);
    for _ in 0..pairs {
        match p.next().expect("key") {
            Item::U(1) => {
                start = Some(match p.next() {
                    Ok(Item::U(v)) => v as u32,
                    _ => panic!("key 1 must be a uint"),
                })
            }
            Item::U(2) => {
                seq_next = Some(match p.next() {
                    Ok(Item::U(v)) => v as u32,
                    _ => panic!("key 2 must be a uint"),
                })
            }
            Item::U(3) => {
                let b = mbytes(&mut p, "the epoch");
                assert_eq!(b.len(), AUDIT_EPOCH_LEN, "the epoch is 32 bytes, always");
                epoch = Some(<[u8; 32]>::try_from(b).unwrap());
            }
            Item::U(4) => entries = Some(mbytes(&mut p, "the entries").to_vec()),
            _ => panic!("unexpected key in the AUDIT_READ response"),
        }
    }
    assert_eq!(p.remaining(), 0, "no trailing bytes may follow the map");
    (
        start.expect("key 1"),
        seq_next.expect("key 2"),
        epoch.expect("key 3"),
        entries.expect("key 4"),
    )
}

/// `{1: bytes(32), 2: uint, 3: bytes, 4: bytes(65)}` from a checkpoint body.
fn parse_checkpoint(body: &[u8]) -> ([u8; 32], u32, Vec<u8>, Vec<u8>) {
    use nh::{Item, Parser};
    let mut p = Parser::new(body);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => panic!("the body must be a CBOR map, got {body:02x?}"),
    };
    assert_eq!(pairs, 4, "the map must have exactly the four defined keys");
    let (mut head, mut seq, mut sig, mut pk) = (None, None, None, None);
    for _ in 0..pairs {
        match p.next().expect("key") {
            Item::U(1) => {
                head = Some(<[u8; 32]>::try_from(mbytes(&mut p, "the head")).unwrap())
            }
            Item::U(2) => {
                seq = Some(match p.next().unwrap() {
                    Item::U(v) => v as u32,
                    _ => panic!("key 2 must be a uint"),
                })
            }
            Item::U(3) => sig = Some(mbytes(&mut p, "the signature").to_vec()),
            Item::U(4) => {
                let b = mbytes(&mut p, "the public key");
                assert_eq!(b.len(), P256_POINT_LEN, "65 bytes, always");
                pk = Some(b.to_vec());
            }
            _ => panic!("unexpected key in the checkpoint response"),
        }
    }
    assert_eq!(p.remaining(), 0, "no trailing bytes may follow the map");
    (head.expect("key 1"), seq.expect("key 2"), sig.expect("key 3"), pk.expect("key 4"))
}

fn mbytes<'a>(p: &mut nh::Parser<'a>, what: &str) -> &'a [u8] {
    match p.next() {
        Ok(nh::Item::B(b)) => b,
        _ => panic!("{what} must be a byte string"),
    }
}

/// Decodes a `{1: bool}` body into `(key, Some(bool), None)` triples and an
/// `{1: uint}` into `(key, None, Some(n))` — the two shapes `m_bool` accepts.
fn parse_config_body(body: &[u8]) -> Vec<(u64, Option<bool>, Option<u64>)> {
    use nh::{Item, Parser};
    let mut p = Parser::new(body);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => panic!("the body must be a CBOR map, got {body:02x?}"),
    };
    let mut out = Vec::new();
    for _ in 0..pairs {
        let k = match p.next().expect("key") {
            Item::U(v) => v,
            _ => panic!("key must be a uint"),
        };
        out.push(match p.next().expect("value") {
            Item::U(n) => (k, None, Some(n)),
            Item::Bool(b) => (k, Some(b), None),
            _ => panic!("the value must be a bool or a uint"),
        });
    }
    assert_eq!(p.remaining(), 0, "no trailing bytes may follow the map");
    out
}

// ---------------------------------------------------------------------------
// 1. US-173 — the 20-byte record.
// ---------------------------------------------------------------------------

/// # `audit_read_returns_20_byte_records` (the EPIC's named test — contract)
///
/// Every `AUDIT_READ` record is **20 bytes** with the field offsets and
/// endiannesses the client parses (`audit.rs:117-130`):
///
/// ```text
/// [0..4]   seq        u32 little-endian
/// [4..8]   uptime_ms  u32 little-endian
/// [8]      event      u8
/// [9]      aux        u8
/// [10..18] detail     8 raw bytes
/// [18..20] —          2 bytes the host never parses
/// ```
///
/// The last row is the one that gets missed. The client ignores it
/// (`parse_entries` reads `e[10..18]` and stops) but `fold_chain` hashes the
/// **whole 20-byte chunk** (`audit.rs:133-143`), so those two bytes are inside
/// the hash chain. They must therefore be *present* — the host's length rule
/// is `20 × (seq_next − start)` — and *deterministic*, because a device that
/// put a counter in them would fold to a head the host cannot reproduce and
/// report `head_matches: false` on an untampered journal. This test asserts
/// both: the offsets, and that the two bytes are zero on every record.
#[test]
fn audit_read_returns_20_byte_records() {
    let mut ks = journal_with(3);
    let mut out: Reply = HV::new();
    let r = with_ops(&mut ks, |ops| {
        audit_read(&request(0x07, None, None), None, presence(true), ops, &mut out)
    });
    assert_eq!(r, AuditResult::ok(), "a touch-gated read on a host that grants touch");

    let (_, seq_next, _, entries) = parse_audit_read(&out);
    assert_eq!(entries.len(), 3 * AUDIT_ENTRY_LEN, "three records, twenty bytes each");

    for (i, e) in entries.as_chunks::<AUDIT_ENTRY_LEN>().0.iter().enumerate() {
        let seq = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
        let uptime = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
        assert_eq!(seq, i as u32, "record {i}: seq is u32 **little-endian** at [0..4]");
        assert_eq!(
            uptime, 0x0102_0300u32.wrapping_add(i as u32),
            "record {i}: uptime_ms is u32 **little-endian** at [4..8]"
        );
        assert_eq!(e[8], 0x20u8.wrapping_add(i as u8), "record {i}: event at [8]");
        assert_eq!(e[9], 0x40u8.wrapping_add(i as u8), "record {i}: aux at [9]");
        assert_eq!(&e[10..18], &[i as u8; 8], "record {i}: detail at [10..18]");
        // The two bytes the host never reads, and the two it always hashes.
        assert_eq!(
            &e[18..20], &[0u8, 0u8],
            "record {i}: the trailing two bytes are never parsed, but fold_chain \
             hashes all 20 — so they must be deterministic, and zero is"
        );
    }
    assert_eq!(seq_next, 3, "seq_next is one past the last live record");
}

/// A window of N records is exactly `20 × N` bytes, and the **host's own**
/// check passes on it — at every CBOR byte-string head width, and for both
/// degenerate windows.
///
/// The point of driving N over a range rather than pinning one value is the
/// head: a definite-length byte string costs 1 byte below 24, 2 below 256 and
/// 3 below 65536, and the framing closes a gap between the streamed records
/// and the frame written around them. A head pinned at one width passes at
/// exactly one N and fails at the other two. `n = 0, 1` exercise the
/// 1-byte branch, `n = 23/24/25` the 1↔2 boundary, and `n = 51/52` the 2↔3
/// one (`AUDIT_RING_MAX` is 32, so 52 is a deliberately over-full scripted
/// window — a real one cannot reach it).
#[test]
fn a_window_of_n_records_is_exactly_twenty_n_bytes_and_the_host_accepts_it() {
    for n in [0u32, 1, 2, 12, 23, 24, 25, 32] {
        let mut ks = journal_with(n);
        let mut out: Reply = HV::new();
        let r = with_ops(&mut ks, |ops| {
            audit_read(&request(0x07, None, None), None, presence(true), ops, &mut out)
        });
        assert_eq!(r, AuditResult::ok(), "n = {n}");

        let (start, seq_next, epoch, entries) = parse_audit_read(&out);
        assert_eq!(entries.len(), n as usize * AUDIT_ENTRY_LEN, "n = {n}: 20 × N entry bytes");
        assert_eq!(start, 0, "n = {n}: nothing evicted yet, so the window starts at 0");
        assert_eq!(seq_next, n, "n = {n}: seq_next is one past the last live record");
        assert_eq!(epoch, [0u8; 32], "n = {n}: a journal below the ring size has a zero epoch");
        assert_eq!(
            expected_entries_len(&AuditWindow { start, seq_next, epoch }),
            entries.len(),
            "n = {n}: the device's own formula agrees with the bytes it emitted"
        );
        host_accepts_window(start, seq_next, &entries)
            .unwrap_or_else(|e| panic!("n = {n}: the host must accept a well-formed window: {e}"));
        // And the frame really is minimal: the whole body is the map plus its
        // four pairs, with no slack around the entries.
        assert!(
            out.len() <= AUDIT_READ_FRAME_MAX + entries.len(),
            "n = {n}: the framing is at most {AUDIT_READ_FRAME_MAX} bytes around {n} records"
        );
    }

    // The 2↔3 head boundary, driven through a scripted window because the ring
    // is only 32 slots. n = 51 → 1020 bytes (2-byte head), n = 52 → 1040 (3-byte).
    for n in [51u32, 52] {
        let bytes = (n as usize) * AUDIT_ENTRY_LEN;
        let mut ops = ScriptedOps::window(0, n, bytes);
        let mut out: Reply = HV::new();
        let r = audit_read(&request(0x07, None, None), None, presence(true), &mut ops, &mut out);
        assert_eq!(r, AuditResult::ok(), "n = {n} over a scripted window");
        let (start, seq_next, _, entries) = parse_audit_read(&out);
        assert_eq!(entries.len(), bytes);
        host_accepts_window(start, seq_next, &entries).expect("accepted");
    }
}

/// The degenerate windows. `seq_next == start` is what a fresh token has and
/// must answer with a **zero-length** `entries`; `seq_next < start` cannot
/// arise from either real implementation and, if it did, `saturating_sub` would
/// make **empty** the only legal answer (`audit.rs:175-178`).
///
/// Driven through a scripted [`VendorOps`] rather than the real state, because
/// `VendorPublic::live_start` is `audit_seq − audit_len` and cannot underflow,
/// and the decoder refuses a stored `(seq, len)` pair with `seq < len`. The
/// framing still has to be right for a window it will never be handed.
#[test]
fn the_degenerate_windows_give_a_zero_length_entries() {
    // `seq_next == start` — the empty journal, reachable in production.
    let mut ks = journal_with(0);
    let mut out: Reply = HV::new();
    with_ops(&mut ks, |ops| {
        assert_eq!(
            audit_read(&request(0x07, None, None), None, presence(true), ops, &mut out),
            AuditResult::ok()
        )
    });
    let (start, seq_next, _, entries) = parse_audit_read(&out);
    assert_eq!((start, seq_next), (0, 0));
    assert!(entries.is_empty(), "an empty journal is a zero-length byte string, not padding");
    host_accepts_window(start, seq_next, &entries).expect("the host accepts an empty window");

    // `seq_next < start` — unreachable through the real state, pinned anyway.
    for (s, sn) in [(5u32, 3u32), (1, 0), (u32::MAX, u32::MAX - 1)] {
        let mut ops = ScriptedOps::window(s, sn, 0);
        let mut out: Reply = HV::new();
        let r = audit_read(&request(0x07, None, None), None, presence(true), &mut ops, &mut out);
        assert_eq!(r, AuditResult::ok(), "start = {s}, seq_next = {sn} is answered, not refused");
        let (gs, gsn, _, entries) = parse_audit_read(&out);
        assert_eq!((gs, gsn), (s, sn), "the two numbers are reported verbatim");
        assert!(entries.is_empty(), "saturating_sub makes empty the only accepted length");
        assert_eq!(
            expected_entries_len(&AuditWindow { start: s, seq_next: sn, epoch: [0; 32] }),
            0,
            "and the device's own formula agrees"
        );
        host_accepts_window(gs, gsn, &entries)
            .unwrap_or_else(|e| panic!("start = {s}, seq_next = {sn}: {e}"));
    }

    // And the counter-case: a non-empty `entries` for a degenerate window is
    // exactly what the host calls a corrupt journal, so the framing must never
    // be the thing that produces one.
    let mut ops = ScriptedOps::window(5, 3, 20);
    let mut out: Reply = HV::new();
    let r = audit_read(&request(0x07, None, None), None, presence(true), &mut ops, &mut out);
    assert_eq!(r, AuditResult::plain(Ctap2Response::Processing));
    assert!(out.is_empty(), "and no partial body rides along behind a non-zero status");
}

/// A `VendorOps` that reports a window it does not fill is refused with a
/// status, not shipped as a reply the host will call a corrupt journal.
///
/// This is the check `audit_read` adds on top of the trait. It cannot fire
/// against either shipped implementation — they are the ones that build both
/// halves — and it is here so a *third* one cannot. The alternative is a
/// device-side inconsistency surfacing to an operator as *"export length does
/// not match the window — corrupt journal?"* (`audit.rs:184`), which accuses
/// the journal of tampering on a device that is fine.
#[test]
fn a_window_that_does_not_match_its_record_count_is_refused_not_shipped() {
    // Claims 3 records (start = 0, seq_next = 3 ⇒ 60 bytes) and writes 40.
    let mut ops = ScriptedOps::window(0, 3, 40);
    let mut out: Reply = HV::new();
    let r = audit_read(&request(0x07, None, None), None, presence(true), &mut ops, &mut out);
    assert_eq!(
        r,
        AuditResult::plain(Ctap2Response::Processing),
        "a window whose numbers and bytes disagree is a device fault, and it is loud"
    );
    assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge, "and it charges nothing");
    assert!(out.is_empty(), "no partial body may ride along behind a non-zero status");

    // The aligned case is accepted by the same path, so this is not a
    // "refuse everything" test.
    let mut ops = ScriptedOps::window(0, 3, 60);
    let mut out: Reply = HV::new();
    assert_eq!(
        audit_read(&request(0x07, None, None), None, presence(true), &mut ops, &mut out),
        AuditResult::ok()
    );
    let (_, _, _, entries) = parse_audit_read(&out);
    assert_eq!(entries.len(), 60);
}

/// The epoch round-trips at **exactly 32 bytes**, and the head the host folds
/// from `{epoch, entries}` is the head the device maintains.
///
/// The second half is the property that makes the journal tamper-evident at
/// all: `AuditVerification::authentic` is `signature_ok && head_matches`
/// (`audit.rs:82-84`), and `head_matches` compares the **host's** fold against
/// the signed `head` (`mod.rs:1624-1625`). A device that folded over anything
/// other than the bytes it returned — a different start, a different order, a
/// record with different trailing bytes — would be reported as tampered.
#[test]
fn the_epoch_round_trips_at_32_bytes_and_the_host_folds_the_same_head() {
    // Past the ring's capacity, so `epoch` is a real fold rather than zeros.
    let mut ks = journal_with(AUDIT_RING_MAX as u32 + 8);
    let device_head = ks.vendor.public.audit_head();
    let mut out: Reply = HV::new();
    let r = with_ops(&mut ks, |ops| {
        audit_read(&request(0x07, None, None), None, presence(true), ops, &mut out)
    });
    assert_eq!(r, AuditResult::ok());
    let (start, seq_next, epoch, entries) = parse_audit_read(&out);

    assert_eq!(epoch.len(), AUDIT_EPOCH_LEN, "the epoch is 32 bytes, not 31 or 33");
    assert_ne!(epoch, [0u8; 32], "40 records through a 32-slot ring must have folded an epoch");
    assert_eq!(start, 8, "eight records were evicted, so the live window starts at 8");
    assert_eq!(seq_next, 40);
    assert_eq!(entries.len(), AUDIT_RING_MAX * AUDIT_ENTRY_LEN, "the ring is full");

    host_accepts_window(start, seq_next, &entries).expect("the host accepts the window");
    assert_eq!(
        host_fold_chain(&epoch, &entries),
        device_head,
        "the host's fold over the bytes the device emitted is the head the device \
         signed — this is `head_matches`, and anything else is reported as tampering"
    );
    // The window the device would stream on its own is byte-for-byte the same
    // bytes that came back, so the fold above really is over *these* records.
    let mut direct: Reply = HV::new();
    with_ops(&mut ks, |ops| {
        ops.audit_window(&mut direct).expect("window");
    });
    assert_eq!(direct.as_slice(), entries.as_slice());
}

// ---------------------------------------------------------------------------
// 2. US-174 — the checkpoint signature.
// ---------------------------------------------------------------------------

/// # `checkpoint_signature_verifies` — and it verifies *as a signature*
///
/// This is the test the EPIC's "18 ASCII bytes" is wrong about, and it is
/// written so that being wrong fails as a **cryptographic verification**.
///
/// The message is assembled here, from the client's **literal** tag (see
/// [`CLIENT_CKPT_TAG`]), exactly as `mod.rs::verify_checkpoint` does
/// (`audit.rs:159-162`):
///
/// ```text
/// "RSK-AUDIT-CKPT-v1" (17) ‖ head(32) ‖ seq.to_le_bytes() (4) ‖ challenge(16) = 69
/// ```
///
/// and the returned DER signature is verified against the **returned** public
/// key with `p256`'s ECDSA verifier — the same algorithm as the host's
/// `ECDSA_P256_SHA256_ASN1` (`audit.rs:164`).
///
/// # Two orderings here, both load-bearing, both got wrong first
///
/// **The message uses a literal, not [`AUDIT_CHECKPOINT_TAG`].** A test that
/// derives its expectation from the constant the firmware signs with agrees
/// with a firmware that pads the tag, so the verification *passes* and only a
/// length assertion can fail. Verified experimentally: with the constant
/// mutated to 18 bytes, a constant-driven test reports `left: 70, right: 69`
/// and never reaches a cryptographic check. The client is the ground truth
/// (`audit.rs:17`, `:160`), and a test whose oracle is the thing under test is
/// not a test of it.
///
/// **The verification runs before every structural assertion.** With
/// `assert_eq!(msg.len(), 69)` first, a padded firmware still fails — but on a
/// *length*, which is the weaker claim, and it conceals the fact that the
/// signature no longer verifies. Ordering it first makes the mutation fail as
/// a *verification failure*, which is the symptom an operator actually sees
/// (`signature_ok: false` on a device that is behaving correctly). The
/// structural assertions follow, and they are what makes such a failure
/// *diagnosable* rather than merely detected.
#[test]
fn checkpoint_signature_verifies_over_the_independently_assembled_message() {
    let challenge = [0x5Au8; AUDIT_CHALLENGE_LEN];
    let params = ckpt_params(&challenge);
    let mut ks = journal_with(5);
    let mut out: Reply = HV::new();
    let r = with_ops(&mut ks, |ops| {
        audit_checkpoint(&request(0x08, Some(&params), None), None, presence(true), ops, &mut out)
    });
    assert_eq!(r, AuditResult::ok());
    let (head, seq, sig, pubkey) = parse_checkpoint(&out);

    // --- the message, assembled here and not by the firmware ---
    let msg = host_checkpoint_message(&head, seq, &challenge);

    // --- THE VERIFICATION, before any structural assertion ---
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey).expect("a 65-byte SEC1 point");
    let der = p256::ecdsa::Signature::from_der(&sig).expect("ASN.1 DER");
    vk.verify(&msg, &der)
        .expect("the signature verifies over the message the client reconstructs");

    // --- the negative controls, which make the assertion above non-vacuous ---
    //
    // The same key and the same signature, against a message one byte longer —
    // the shape the EPIC's "18 ASCII bytes" describes — and against a
    // big-endian `seq`.
    //
    // **No length assertion here on purpose.** An `assert_eq!(padded.len(), 70)`
    // would fire before the verification and the mutation would again fail as
    // a length, which is precisely the outcome the ordering above exists to
    // eliminate. A negative control's only claim is that the verification does
    // not succeed.
    let mut padded = Vec::new();
    padded.extend_from_slice(CLIENT_CKPT_TAG);
    padded.push(0x00); // the padding an "18 ASCII bytes" reading invites
    padded.extend_from_slice(&msg[CLIENT_CKPT_TAG.len()..]);
    assert!(
        vk.verify(&padded, &der).is_err(),
        "sanity: a message one byte longer must NOT verify — that is the bug the 17 \
         is there to prevent, and if it ever verified the assertion above would be vacuous"
    );
    let mut be = Vec::new();
    be.extend_from_slice(CLIENT_CKPT_TAG);
    be.extend_from_slice(&head);
    be.extend_from_slice(&seq.to_be_bytes());
    be.extend_from_slice(&challenge);
    assert!(
        vk.verify(&be, &der).is_err(),
        "sanity: seq is little-endian; big-endian must not verify either"
    );

    // --- and now the structural facts, which make a failure diagnosable ---
    //
    // The constant is checked against the client's literal here, *after* the
    // verification, so that a padded firmware fails as a signature first and
    // this is the diagnosis rather than the report.
    assert_eq!(
        AUDIT_CHECKPOINT_TAG, CLIENT_CKPT_TAG,
        "the published constant must be the client's 17-byte tag, verbatim and with \
         no NUL terminator — `audit.rs:17` defines it as a `&[u8]` and \
         `audit.rs:160` extends with it on a `&[u8]`, not a C string"
    );
    assert_eq!(
        msg.len(),
        69,
        "17 (tag) + 32 (head) + 4 (seq LE) + 16 (challenge). The EPIC says the tag \
         is 18 bytes; it is 17 (R-S-K---A-U-D-I-T---C-K-P-T---v-1) and the client \
         hashes 17. An 18-byte tag makes this 70 bytes and every checkpoint on a \
         correct device fails to verify."
    );
    let tag_len = CLIENT_CKPT_TAG.len();
    assert_eq!(&msg[..tag_len], CLIENT_CKPT_TAG, "the tag, verbatim, with no NUL terminator");
    assert_eq!(&msg[tag_len..tag_len + 32], &head[..], "then the head the response carried");
    assert_eq!(
        &msg[tag_len + 32..tag_len + 36], &seq.to_le_bytes(),
        "then seq **little-endian** — a big-endian seq signs a message no host verifies"
    );
    assert_eq!(&msg[tag_len + 36..], &challenge, "then the host's own challenge");
}

/// The signature is 70..=72 bytes of ASN.1 DER, and a `Checkpoint` outside
/// that — or carrying a point that is not `0x04`-prefixed — is refused rather
/// than shipped.
///
/// Driven through a scripted [`VendorOps`] because the arm's real signer can
/// only ever produce a well-formed signature, which is exactly the point: the
/// checks exist for a state that has one, and a test that only ever sees a
/// good one does not test them.
#[test]
fn a_signature_outside_der_bounds_or_a_non_uncompressed_point_is_refused() {
    let mut good = Checkpoint {
        head: [0x11; 32],
        seq: 3,
        sig: [0u8; SIG_DER_MAX],
        sig_len: 71,
        pubkey: [0u8; P256_POINT_LEN],
    };
    good.pubkey[0] = 0x04;

    for sig_len in [0u8, 1, 69, 73, SIG_DER_MAX as u8 + 1] {
        let mut ck = good;
        ck.sig_len = sig_len;
        let mut ops = ScriptedOps::with_checkpoint(ck);
        let mut out: Reply = HV::new();
        let r = audit_checkpoint(
            &request(0x08, Some(&ckpt_params(&[0u8; 16])), None),
            None,
            presence(true),
            &mut ops,
            &mut out,
        );
        assert_eq!(
            r,
            AuditResult::plain(Ctap2Response::Processing),
            "sig_len {sig_len} is outside 70..=72 and must be refused, not shipped"
        );
        assert!(out.is_empty(), "nothing partial behind a non-zero status");
    }
    // 70 and 72 are both legal and both accepted.
    for sig_len in [70u8, 72] {
        let mut ck = good;
        ck.sig_len = sig_len;
        let mut ops = ScriptedOps::with_checkpoint(ck);
        let mut out: Reply = HV::new();
        let r = audit_checkpoint(
            &request(0x08, Some(&ckpt_params(&[0u8; 16])), None),
            None,
            presence(true),
            &mut ops,
            &mut out,
        );
        assert_eq!(r, AuditResult::ok(), "sig_len {sig_len} is a legal DER length");
    }
    // A compressed / non-`0x04` point is refused too: the host's
    // `UnparsedPublicKey` and its fingerprint both want the uncompressed form.
    let mut ck = good;
    ck.pubkey[0] = 0x02;
    let mut ops = ScriptedOps::with_checkpoint(ck);
    let mut out: Reply = HV::new();
    let r = audit_checkpoint(
        &request(0x08, Some(&ckpt_params(&[0u8; 16])), None),
        None,
        presence(true),
        &mut ops,
        &mut out,
    );
    assert_eq!(r, AuditResult::plain(Ctap2Response::Processing), "0x04 prefix required");
}

/// The signed `head` and the host's folded head cannot disagree.
///
/// Two sub-cases, and the second is the one that matters. Nothing may be
/// appended to the journal between the read and the signature: the device
/// reads its head and its sequence **once**, inside `audit_sign_checkpoint`,
/// and returns both beside the signature ([`AuditWindow`]'s docs;
/// `vendor_state.rs`'s implementation), so the response describes the journal
/// that was signed. The test pins the *weaker and correct* claim — that the
/// response's `head` is the head that was signed — by verifying the signature
/// over the response's own `head`, and separately that a read immediately
/// before a sign folds to the same value.
#[test]
fn the_signed_head_is_the_head_the_host_folds_from_the_window() {
    let challenge = [0x11u8; AUDIT_CHALLENGE_LEN];
    let params = ckpt_params(&challenge);
    let mut ks = journal_with(4);

    // Read the window, exactly as `audit_verify` does first.
    let mut read_body: Reply = HV::new();
    with_ops(&mut ks, |ops| {
        assert_eq!(
            audit_read(&request(0x07, None, None), None, presence(true), ops, &mut read_body),
            AuditResult::ok()
        )
    });
    let (_, _, epoch, entries) = parse_audit_read(&read_body);
    let host_head = host_fold_chain(&epoch, &entries);

    // Then take the checkpoint with nothing in between: `head_matches` holds.
    let mut out: Reply = HV::new();
    with_ops(&mut ks, |ops| {
        assert_eq!(
            audit_checkpoint(
                &request(0x08, Some(&params), None),
                None,
                presence(true),
                ops,
                &mut out
            ),
            AuditResult::ok()
        )
    });
    let (head, seq, sig, pubkey) = parse_checkpoint(&out);
    assert_eq!(head, host_head, "the signed head is the host's fold of the window it holds");
    assert_eq!(seq, 4, "seq is one past the last live record at signing time");

    // And the signature really covers *that* head, so the response cannot
    // carry a `head` that was not the one signed.
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey).expect("SEC1 point");
    let der = p256::ecdsa::Signature::from_der(&sig).expect("DER");
    vk.verify(&host_checkpoint_message(&head, seq, &challenge), &der)
        .expect("the signature covers the head the response reported");

    // An append between the two would move the head — which is precisely why
    // the arm must not assemble the message from a head it read earlier.
    with_ops(&mut ks, |ops| {
        ops.audit_append(AuditRecord { event: 0x0C, ..Default::default() }).expect("append");
    });
    assert_ne!(
        ks.vendor.public.audit_head(),
        host_head,
        "an append moved the head, so a device that had read the head earlier and \
         signed it afterwards would now report `head_matches: false` — a race the \
         device closes by reading once and the arm cannot"
    );
}

/// The public key is the **65-byte uncompressed SEC1 point**, and the host's
/// fingerprint form — `hex(sha256(pubkey)[..8])` — is 16 characters computed
/// over the **raw bytes**, not over their hex.
///
/// Both halves matter because they are how an operator pins the identity
/// (`audit.rs:145-149`; `mod.rs:1626-1634` compares `expect_key` against
/// `hex(pubkey)` **or** `fingerprint(pubkey)`, lowercased). A device that
/// returned a compressed point, or a fingerprint of the hex, would produce a
/// pin no operator could ever reproduce.
#[test]
fn the_public_key_is_65_uncompressed_bytes_with_a_16_hex_fingerprint() {
    let params = ckpt_params(&[0u8; AUDIT_CHALLENGE_LEN]);
    let mut ks = journal_with(1);
    let mut out: Reply = HV::new();
    with_ops(&mut ks, |ops| {
        assert_eq!(
            audit_checkpoint(
                &request(0x08, Some(&params), None),
                None,
                presence(true),
                ops,
                &mut out
            ),
            AuditResult::ok()
        )
    });
    let (_, _, _, pubkey) = parse_checkpoint(&out);

    assert_eq!(pubkey.len(), P256_POINT_LEN, "65 bytes: 0x04 ‖ x ‖ y");
    assert_eq!(pubkey[0], 0x04, "SEC1 **uncompressed** — the host parses no other form here");
    assert!(
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey).is_ok(),
        "and it is a point on P-256, not merely 65 bytes starting 0x04"
    );

    let fp = host_fingerprint(&pubkey);
    assert_eq!(fp.len(), 16, "8 bytes of SHA-256 in hex is 16 characters");
    assert!(
        fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "lowercase hex, which is what the host lower-cases `expect_key` to: {fp}"
    );
    // The hash input is the **raw** 65 bytes. Hashing the hex instead is the
    // trap, and it is silent: it also produces 16 lowercase hex characters.
    let hex_of_point: String = pubkey.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex_of_point.len(), 130, "the full-hex form the host also accepts");
    assert_ne!(
        fp,
        host_fingerprint(hex_of_point.as_bytes()),
        "the fingerprint is over the raw point, not over its hex form"
    );
}

/// A challenge of the wrong width is refused, never truncated — a truncated
/// challenge is a *different, valid* challenge, and signing it would produce a
/// signature over a message the host will not reconstruct.
#[test]
fn the_challenge_width_is_exact() {
    for (n, expected) in [
        (0usize, Ctap2Response::InvalidLength),
        (15, Ctap2Response::InvalidLength),
        (17, Ctap2Response::InvalidLength),
        (32, Ctap2Response::InvalidLength),
    ] {
        let mut p: Msg = HV::new();
        nh::push_map_header(&mut p, 1).unwrap();
        nh::push_uint(&mut p, 1).unwrap();
        nh::push_bstr(&mut p, &[0xABu8; 32][..n]).unwrap();
        assert_eq!(
            checkpoint_challenge(&request(0x08, Some(&p), None)),
            Err(expected),
            "a {n}-byte challenge, wrapped in a real request"
        );

        // And through the arm, with the gate open.
        let mut ks = journal_with(1);
        let mut out: Reply = HV::new();
        let r = with_ops(&mut ks, |ops| {
            audit_checkpoint(
                &request(0x08, Some(&p), None),
                None,
                presence(true),
                ops,
                &mut out,
            )
        });
        assert_eq!(r.status, expected, "a {n}-byte challenge reaches the arm unchanged");
        assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge, "and charges nothing");
    }
    // A params map with no challenge at all is a *missing* parameter, which is
    // a different status from a challenge of the wrong width.
    let mut empty: Msg = HV::new();
    nh::push_map_header(&mut empty, 0).unwrap();
    let req = request(0x08, Some(&empty), None);
    assert_eq!(checkpoint_challenge(&req), Err(Ctap2Response::MissingParameter));
    // The right width round-trips, through both the decoder and the arm.
    let good = ckpt_params(&[7u8; AUDIT_CHALLENGE_LEN]);
    assert_eq!(checkpoint_challenge(&request(0x08, Some(&good), None)), Ok([7u8; AUDIT_CHALLENGE_LEN]));
}

// ---------------------------------------------------------------------------
// 3. `AUDIT_CONFIG` — three targets, two gates, one response shape.
// ---------------------------------------------------------------------------

/// Target 2 is **ungated**, reports the current state, and — the load-bearing
/// half — never looks at a `pinUvAuthParam`, so it cannot charge the PIN-auth
/// counter.
///
/// The client's `audit_status` passes `None` for the PIN
/// (`mod.rs:1647-1659`) and the constants file calls target 2 *"read-only
/// status (ungated)"* (`constants.rs:757-760`). If this path reached
/// `verify_mac` it would be an active bug, not a missed optimisation: three
/// Audit-screen reads would latch a three-strike lockout against a user who
/// failed nothing, which is the exact failure `vendor41::identity_gate`'s docs
/// describe for the benign tier.
#[test]
fn audit_config_target_2_is_ungated_and_reports_the_state() {
    // Fresh store: the journal is **off** by default — opt-in, per the client's
    // own "nothing is written to flash until it is enabled" (`mod.rs:1660-1661`).
    let mut ks = DeviceKeystore::fresh(&mut HostTrng::new()).expect("host TRNG");
    assert!(!ks.vendor.public.audit_enabled, "a fresh store has no journal");
    let status = cfg_params(AUDIT_CFG_STATUS);

    // No token at all, and a presence gate that refuses: still `0x00`.
    let mut out: Reply = HV::new();
    let r = with_ops(&mut ks, |ops| {
        audit_config(
            &request(0x0E, Some(&status), None),
            None,
            presence(false),
            ops,
            &mut out,
        )
    });
    assert_eq!(r, AuditResult::ok(), "target 2 is ungated even with no touch available");
    assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge, "and it can never charge");
    let parsed = parse_config_body(&out);
    assert_eq!(parsed, vec![(1, Some(false), None)], "the response is `{{1: false}}`");
    assert!(!host_m_bool(&parsed, 1), "and `m_bool` reads it as off");

    // A **bogus** token presented alongside: still `0x00`, still uncharged.
    // `audit_status` never sends one, so a status query that answered `0x33`
    // would be a device that broke a documented ungated call.
    let bad: [u8; 32] = [0xFF; 32];
    let mut out: Reply = HV::new();
    let r = with_ops(&mut ks, |ops| {
        let req = request(0x0E, Some(&status), Some(&bad));
        audit_config(&req, Some(token_auth(&bad)), presence(false), ops, &mut out)
    });
    assert_eq!(r, AuditResult::ok(), "a bogus token does not turn an ungated query into 0x33");
    assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge, "and it is still not charged");

    // Turn it on, then read the status back — the response carries the state
    // read back from the device, not the target that was asked for.
    with_ops(&mut ks, |ops| {
        let p = cfg_params(AUDIT_CFG_ENABLE);
        let mut o: Reply = HV::new();
        assert_eq!(
            audit_config(
                &request(0x0E, Some(&p), Some(&bad)),
                Some(token_auth(&bad)),
                presence(true),
                ops,
                &mut o
            ),
            AuditResult::ok()
        );
        assert!(host_m_bool(&parse_config_body(&o), 1));
    });
    let mut out: Reply = HV::new();
    with_ops(&mut ks, |ops| {
        assert_eq!(
            audit_config(
                &request(0x0E, Some(&status), None),
                None,
                presence(false),
                ops,
                &mut out
            ),
            AuditResult::ok()
        )
    });
    assert!(host_m_bool(&parse_config_body(&out), 1), "the state is now on");

    // And back off.
    with_ops(&mut ks, |ops| {
        let p = cfg_params(AUDIT_CFG_DISABLE);
        let mut o: Reply = HV::new();
        assert_eq!(
            audit_config(&request(0x0E, Some(&p), None), None, presence(true), ops, &mut o),
            AuditResult::ok()
        );
        assert!(!host_m_bool(&parse_config_body(&o), 1));
    });
}

/// Targets 0 and 1 **are** gated, and each refusal carries the status the
/// protocol says it does.
///
/// * no token and no touch ⇒ `0x3B` `UpRequired` — *not* `0x36`. A missing
///   token is the client's documented way to ask for a touch
///   (`ops.rs:1573-1575`), and `0x36` would send the user back to a PIN
///   prompt for a token the app never obtains.
/// * latch set ⇒ `0x34`, and **no charge**: the three strikes are already
///   spent, and `0x33` here would tell a user with a good token that it is
///   bad.
/// * a token whose MAC fails ⇒ `0x33`, and **charged** — the one chargeable
///   path in the whole module.
/// * a real token without the `acfg` bit ⇒ `0x40`, no charge.
#[test]
fn audit_config_targets_0_and_1_are_gated() {
    let p_on = cfg_params(AUDIT_CFG_ENABLE);
    let p_off = cfg_params(AUDIT_CFG_DISABLE);
    let good: [u8; 32] = [0x33; 32];

    // No token, no touch.
    let mut ks = DeviceKeystore::fresh(&mut HostTrng::new()).expect("host TRNG");
    let mut out: Reply = HV::new();
    let r = with_ops(&mut ks, |ops| {
        audit_config(
            &request(0x0E, Some(&p_on), None),
            None,
            presence(false),
            ops,
            &mut out,
        )
    });
    assert_eq!(r, AuditResult::plain(Ctap2Response::UpRequired), "0x3B, not 0x36");
    assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge, "nothing authenticated, nothing failed");
    assert!(!ks.vendor.public.audit_enabled, "and nothing was written");

    // No token, touch granted.
    let mut out: Reply = HV::new();
    with_ops(&mut ks, |ops| {
        assert_eq!(
            audit_config(
                &request(0x0E, Some(&p_on), None),
                None,
                presence(true),
                ops,
                &mut out
            ),
            AuditResult::ok()
        )
    });
    assert!(ks.vendor.public.audit_enabled, "the touch was the authority and it landed");

    // Latch set, with a token that would otherwise verify.
    let mut out: Reply = HV::new();
    let mut ks2 = DeviceKeystore::fresh(&mut HostTrng::new()).expect("host TRNG");
    let blocked = TokenAuth { token: &good, permissions: 0x20, blocked: true };
    let r = with_ops(&mut ks2, |ops| {
        audit_config(
            &request(0x0E, Some(&p_on), Some(&good)),
            Some(blocked),
            presence(true),
            ops,
            &mut out,
        )
    });
    assert_eq!(r, AuditResult::plain(Ctap2Response::PinAuthBlocked), "0x34");
    assert_eq!(
        r.charge_pin_auth, ChargePinAuth::NoCharge,
        "the latch has already spent its three strikes; charging would move 0x34 \
         to 0x33 and claim a good token is bad"
    );
    assert!(!ks2.vendor.public.audit_enabled, "a latched PIN does not change the journal");

    // A presented token that fails its MAC — the ONE chargeable failure.
    //
    // The request is MAC'd with `good` and the *wrong* token is presented, so
    // the mismatch is real. Signing and verifying with the same key would test
    // nothing, and a test that quietly does so is worse than no test.
    let mut out: Reply = HV::new();
    let r = with_ops(&mut ks2, |ops| {
        let wrong: [u8; 32] = [0x11; 32];
        let req = request(0x0E, Some(&p_on), Some(&good));
        audit_config(&req, Some(token_auth(&wrong)), presence(true), ops, &mut out)
    });
    assert_eq!(r.status, Ctap2Response::PinAuthInvalid, "0x33");
    assert_eq!(
        r.charge_pin_auth, ChargePinAuth::Charge,
        "a pinUvAuthParam was supplied and did not verify"
    );
    assert!(!ks2.vendor.public.audit_enabled, "a failed MAC writes nothing");

    // A real token, but without the `acfg` bit.
    let mut out: Reply = HV::new();
    let r = with_ops(&mut ks2, |ops| {
        let weak = TokenAuth { token: &good, permissions: 0x04, blocked: false };
        audit_config(
            &request(0x0E, Some(&p_off), Some(&good)),
            Some(weak),
            presence(true),
            ops,
            &mut out,
        )
    });
    assert_eq!(r, AuditResult::plain(Ctap2Response::UnauthorizedPermission), "0x40");
    assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge, "the token was real; only the bit was wrong");

    // The happy path: a real `0x20` token and a real MAC, no touch available.
    let mut out: Reply = HV::new();
    with_ops(&mut ks2, |ops| {
        assert_eq!(
            audit_config(
                &request(0x0E, Some(&p_on), Some(&good)),
                Some(token_auth(&good)),
                presence(false),
                ops,
                &mut out
            ),
            AuditResult::ok(),
            "a token is strictly stronger than a touch, so no touch is demanded"
        )
    });
    assert!(ks2.vendor.public.audit_enabled);
}

/// A token is never asked to also produce a touch, and a touch is never asked
/// to also produce a token.
///
/// This is the union gate's whole content, asserted from both sides because
/// either half alone compiles and passes a one-directional test.
#[test]
fn the_gate_accepts_either_authority_and_demands_only_one() {
    let good: [u8; 32] = [0x77; 32];
    let params = cfg_params(AUDIT_CFG_STATUS);

    // Token, no touch available: admitted.
    assert_eq!(
        token_or_touch_gate(
            Subcommand::AuditConfig,
            &request(0x0E, Some(&params), Some(&good)),
            Some(token_auth(&good)),
            presence(false)
        ),
        Ok(())
    );
    // No token, touch available: admitted.
    assert_eq!(
        token_or_touch_gate(
            Subcommand::AuditConfig,
            &request(0x0E, Some(&params), None),
            None,
            presence(true)
        ),
        Ok(())
    );
    // Neither: `0x3B`.
    assert_eq!(
        token_or_touch_gate(
            Subcommand::AuditConfig,
            &request(0x0E, Some(&params), None),
            None,
            presence(false)
        ),
        Err(AuditResult::plain(Ctap2Response::UpRequired))
    );
    // Token present but the MAC is wrong: `0x33` and charged. The request is
    // MAC'd with `good`; the `wrong` token is what is presented.
    let wrong: [u8; 32] = [0x99; 32];
    assert_eq!(
        token_or_touch_gate(
            Subcommand::AuditConfig,
            &request(0x0E, Some(&params), Some(&good)),
            Some(token_auth(&wrong)),
            presence(true)
        ),
        Err(AuditResult::charge(Ctap2Response::PinAuthInvalid))
    );
}

/// The no-charge property of the touch path is a *design* claim, so it is
/// pinned as one: a **malformed** request presented with no token must be
/// refused for its own shape, never for its auth — and a request carrying a
/// garbage `pinUvAuthParam` must not be charged either.
///
/// The second is the sharp one. A tokenless caller is the client's normal
/// shape, so nothing verifies its param; if something did, a broken client
/// would burn a strike per read, and three of those is a power cycle.
#[test]
fn the_touch_path_charges_nothing_ever() {
    let mut with_garbage_param: Msg = HV::new();
    nh::push_map_header(&mut with_garbage_param, 5).unwrap();
    nh::push_uint(&mut with_garbage_param, 1).unwrap();
    nh::push_uint(&mut with_garbage_param, 0x07).unwrap();
    nh::push_uint(&mut with_garbage_param, 3).unwrap();
    nh::push_uint(&mut with_garbage_param, 1).unwrap();
    nh::push_uint(&mut with_garbage_param, 4).unwrap();
    nh::push_bstr(&mut with_garbage_param, &[0xDE; 16]).unwrap();

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("not CBOR at all", vec![0xFF, 0xFF, 0xFF]),
        ("a map with no sub-command", vec![0xA0]),
        ("a map with a wrong-typed sub-command", vec![0xA1, 0x01, 0x40]),
        (
            "a well-formed request with a garbage pinUvAuthParam",
            with_garbage_param.to_vec(),
        ),
    ];
    for (what, data) in cases {
        // Tokenless: the param is never looked at, so the request is judged on
        // its own shape and its `subCommand` is found or not.
        let r = token_or_touch_gate(Subcommand::AuditRead, &data, None, presence(true));
        assert_eq!(r, Ok(()), "{what}: a tokenless request is never refused for its param");

        // With a token and the latch set: 0x34, uncharged.
        let blocked = token_or_touch_gate(
            Subcommand::AuditRead,
            &data,
            Some(TokenAuth { token: &[0u8; 32], permissions: 0x20, blocked: true }),
            presence(true),
        );
        assert_eq!(
            blocked,
            Err(AuditResult::plain(Ctap2Response::PinAuthBlocked)),
            "{what}: and the latch refuses it with 0x34"
        );
    }
}

/// All three `AUDIT_*` sub-commands use the same union gate, so a touch-gated
/// arm on any of them answers `0x3B` and no token is ever demanded from a
/// caller that has one to give.
///
/// `0x3B` is not a dead end, and that is a property of `PresenceGate` rather
/// than of this module: on the device the `window_grant` arm is **join-only**,
/// so the first call is refused, the HID task opens a user-presence window,
/// streams keepalives and re-drives the whole command, and the second call
/// consumes the press. Same two-step `makeCredential` uses, same one
/// `config_write`'s presence tier uses, and the 32-second client timeout
/// (`ops.rs:1598`) is what lets it fit.
#[test]
fn all_three_audit_subcommands_use_the_same_union_gate() {
    for sub in [Subcommand::AuditRead, Subcommand::AuditCheckpoint, Subcommand::AuditConfig] {
        let bare = request(sub.byte(), None, None);
        assert_eq!(
            token_or_touch_gate(sub, &bare, None, presence(false)),
            Err(AuditResult::plain(Ctap2Response::UpRequired)),
            "{sub:?} is presence-gated when no token is held"
        );
        assert_eq!(
            token_or_touch_gate(sub, &bare, None, presence(true)),
            Ok(()),
            "{sub:?} is satisfied by a touch"
        );
    }
}

/// An unrecognised `AUDIT_CONFIG` target is refused, and refused with nothing
/// written.
///
/// Same reasoning and same status as `vendor41::config_write`'s unknown
/// target: the three `RSKEY_*_AUDIT_*` target bytes are the only ones the
/// protocol defines, and a `0x00` over a fourth would be a success nobody
/// asked for. The client propagates a non-zero status rather than rendering a
/// false success (`vendor_map`, `mod.rs:1533-1542`).
#[test]
fn audit_config_refuses_an_unrecognised_target() {
    for target in [3u8, 4, 0xFF] {
        let mut ks = journal_with(1);
        let before = ks.vendor.public.audit_enabled;
        let p = cfg_params(target);
        let mut out: Reply = HV::new();
        let r = with_ops(&mut ks, |ops| {
            audit_config(
                &request(0x0E, Some(&p), None),
                None,
                presence(true),
                ops,
                &mut out,
            )
        });
        assert_eq!(r, AuditResult::plain(Ctap2Response::InvalidParameter), "target {target}");
        assert_eq!(ks.vendor.public.audit_enabled, before, "and nothing was written");
    }
    // A target that does not fit in a `u8` is an `InvalidParameter` from the
    // decoder, not a truncation to a target that *does* — `0x100` truncating
    // to 0 would be "disable the journal" for a request that never said so.
    // Wrapped in a real request, because the target lives under `subCommandParams`.
    let mut wide: Msg = HV::new();
    nh::push_map_header(&mut wide, 1).unwrap();
    nh::push_uint(&mut wide, 1).unwrap();
    nh::push_uint(&mut wide, 0x100).unwrap();
    let req = request(0x0E, Some(&wide), None);
    assert_eq!(audit_config_target(&req), Err(Ctap2Response::InvalidParameter));
    // A params map with no key 1 at all is a *missing* parameter, which is a
    // different status from a value the profile does not accept.
    let mut empty: Msg = HV::new();
    nh::push_map_header(&mut empty, 0).unwrap();
    let req = request(0x0E, Some(&empty), None);
    assert_eq!(audit_config_target(&req), Err(Ctap2Response::MissingParameter));
    // And no `subCommandParams` at all.
    assert_eq!(
        audit_config_target(&request(0x0E, None, None)),
        Err(Ctap2Response::MissingParameter)
    );
    // The three real ones all decode.
    for t in [AUDIT_CFG_DISABLE, AUDIT_CFG_ENABLE, AUDIT_CFG_STATUS] {
        assert_eq!(audit_config_target(&request(0x0E, Some(&cfg_params(t)), None)), Ok(t));
    }
}

// ---------------------------------------------------------------------------
// 4. The `m_bool` compatibility claim, both directions.
// ---------------------------------------------------------------------------

/// # The `m_bool` compatibility claim
///
/// `mod.rs:1558-1565`:
/// ```text
/// fn m_bool(m, k) -> bool {
///   match m.get(k) { Some(Value::Bool(b)) => *b, Some(Value::Integer(n)) => *n != 0, _ => false }
/// }
/// ```
///
/// Three things follow, and each is asserted here:
///
/// 1. **The encoder emits a CBOR bool** — major type 7, simple value 20/21
///    (`0xF4` / `0xF5`). That is the first arm of `m_bool`'s match, and it is
///    the form that cannot be misread by anything that is not `m_bool`. The
///    client's leniency means `1`/`0` would also parse, so the claim under
///    test is the narrow one: what goes on the wire is a bool.
/// 2. **`1` and `0` would also have parsed.** Asserted so the compatibility is
///    recorded rather than assumed, and so a future "optimisation" to an
///    integer is caught as a deliberate change.
/// 3. **A missing key is `false`.** So key 1 is emitted on *every* success,
///    including the success that reports `false`: a reply that omitted it
///    would be indistinguishable from "the journal is off", and there would be
///    no way for the client to tell "off" from "this firmware does not
///    implement `AUDIT_CONFIG`".
#[test]
fn the_config_response_is_a_cbor_bool_and_m_bool_would_read_it_back() {
    for enabled in [true, false] {
        let mut out: Reply = HV::new();
        write_audit_config_response(&mut out, enabled).expect("fits");
        // (1) A real CBOR boolean, and nothing else: `a1 01 f5` / `a1 01 f4`.
        let want: &[u8] = if enabled { &[0xA1, 0x01, 0xF5] } else { &[0xA1, 0x01, 0xF4] };
        assert_eq!(out.as_slice(), want, "map(1) ‖ key 1 ‖ CBOR bool");
        assert_eq!(out.len(), 3, "three bytes, always");

        // (2) The client's lenient form: a CBOR bool is read as itself.
        let parsed = parse_config_body(&out);
        assert_eq!(host_m_bool(&parsed, 1), enabled, "m_bool reads `Some(Bool(b))` as `b`");
        assert_eq!(parsed, vec![(1, Some(enabled), None)], "and it is a bool, not an integer");

        // (3) The *same* map with the value written as 1/0, which `m_bool`'s
        // second arm also accepts. Recorded, not used.
        let mut int_body: Reply = HV::new();
        nh::push_map_header(&mut int_body, 1).unwrap();
        nh::push_uint(&mut int_body, 1).unwrap();
        nh::push_uint(&mut int_body, u64::from(enabled)).unwrap();
        assert_eq!(
            host_m_bool(&parse_config_body(&int_body), 1),
            enabled,
            "and so would 1/0, which is why a missing key is the only real hazard"
        );

        // (3b) The missing-key case, which is why key 1 is never omitted.
        assert!(
            !host_m_bool(&[], 1),
            "a missing key reads as `false` — a reply that omitted key 1 could not \
             be told apart from 'the journal is off'"
        );
        assert!(
            !host_m_bool(&[(1, None, None)], 1),
            "and so does a key present with an unreadable value"
        );
    }
}

// ---------------------------------------------------------------------------
// The published bounds.
// ---------------------------------------------------------------------------

/// The widths and bounds this module publishes are the protocol's.
///
/// `AUDIT_ENTRIES_MAX` is *this* module's claim — the product with
/// `AUDIT_RING_MAX` — and it is the one a reader would otherwise have to take
/// on trust: 32 × 20 = 640, which is why the framing uses a 64-byte scratch
/// and the reply is a `CTAP2_MAX_MSG` one.
#[test]
fn the_published_bounds_are_the_protocols_ones() {
    assert_eq!(AUDIT_ENTRY_LEN, 20, "audit.rs:14");
    assert_eq!(AUDIT_RING_MAX, 32, "the journal ring");
    assert_eq!(P256_POINT_LEN, 65, "0x04 ‖ x ‖ y");
    assert_eq!(SIG_DER_MAX, 72, "SEQUENCE {{INTEGER,INTEGER}} with two ≤33-byte integers");
    assert_eq!(AUDIT_EPOCH_LEN, 32, "the epoch, exactly");
    assert_eq!(AUDIT_CHALLENGE_LEN, 16, "mod.rs:1604");
    assert_eq!(AUDIT_ENTRIES_MAX, 640, "32 records × 20 bytes");
    // `const { assert!(..) }` rather than a runtime `assert!`: these are
    // compile-time facts, and saying so means the compiler checks them
    // on every build rather than only when this test happens to run.
    const { assert!(AUDIT_READ_FRAME_MAX >= 60 && AUDIT_READ_FRAME_MAX < 128) };
    const { assert!(REPLY_MAX > AUDIT_READ_FRAME_MAX + AUDIT_ENTRIES_MAX) };
    assert_eq!(AUDIT_CFG_DISABLE, 0, "constants.rs:757-760");
    assert_eq!(AUDIT_CFG_ENABLE, 1);
    assert_eq!(AUDIT_CFG_STATUS, 2);
    // The sub-command bytes, from the same constants block.
    assert_eq!(Subcommand::AuditRead.byte(), 0x07, "RSKEY_VENDOR_AUDIT_READ");
    assert_eq!(Subcommand::AuditCheckpoint.byte(), 0x08, "RSKEY_VENDOR_AUDIT_CHECKPOINT");
    assert_eq!(Subcommand::AuditConfig.byte(), 0x0E, "RSKEY_VENDOR_AUDIT_CONFIG");
    // And the tag, which is the whole point.
    assert_eq!(AUDIT_CHECKPOINT_TAG, b"RSK-AUDIT-CKPT-v1");
    assert_eq!(AUDIT_CHECKPOINT_TAG.len(), 17, "audit.rs:17 — 17, not the EPIC's 18");
}

// ---------------------------------------------------------------------------
// The scripted `VendorOps`, for the windows and checkpoints the real state
// cannot produce.
// ---------------------------------------------------------------------------

/// A [`VendorOps`] whose audit methods are scripted, so a test can present a
/// window the real implementations cannot build (`seq_next < start`), a window
/// it deliberately fills wrongly, and a `Checkpoint` with a signature width or
/// a point prefix no real signer would emit.
///
/// Every other method is inert and refuses, because none of these tests
/// touches the seed, the lock or the org attestation, and a real
/// implementation behind them would be state these tests do not set up. That
/// is stated rather than hidden: the point of this type is the audit methods,
/// and a test that grew a dependency on the rest would be testing the wrong
/// thing.
struct ScriptedOps {
    window: AuditWindow,
    /// The exact bytes `audit_window` appends. Deliberately independent of
    /// `window`, so a mismatch between the declared window and the emitted
    /// record count can be presented.
    ///
    /// A `Vec` because a scripted window is allowed to be **larger** than the
    /// 32-slot ring (`n = 51`, `n = 52` exercise the 2↔3-byte CBOR head
    /// boundary) and the point of the type is to reach framings the real state
    /// cannot. The firmware side is `no_std` and heapless; this is a host test
    /// double, and the boundary it exists to cross is the reply buffer's.
    records: Vec<u8>,
    enabled: bool,
    /// The `Checkpoint` `audit_sign_checkpoint` hands back.
    checkpoint: Option<Checkpoint>,
}

impl ScriptedOps {
    fn window(start: u32, seq_next: u32, write: usize) -> Self {
        Self {
            window: AuditWindow { start, seq_next, epoch: [0xEE; 32] },
            records: vec![0u8; write],
            enabled: false,
            checkpoint: None,
        }
    }

    fn with_checkpoint(ck: Checkpoint) -> Self {
        let mut s = Self::window(0, 0, 0);
        s.checkpoint = Some(ck);
        s
    }
}

impl VendorOps for ScriptedOps {
    fn export_sealed(&self) -> bool {
        false
    }
    fn random_bytes(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = 0x5A;
        }
    }
    fn master_seed(&self) -> Option<[u8; 32]> {
        None
    }
    fn set_master_seed(&mut self, _seed: [u8; 32]) -> Result<(), Ctap2Response> {
        Err(Ctap2Response::NotAllowed)
    }
    fn soft_lock(&self) -> SoftLock {
        SoftLock::default()
    }
    fn set_soft_lock(&mut self, _lock: SoftLock) -> Result<(), Ctap2Response> {
        Err(Ctap2Response::NotAllowed)
    }
    fn unlocked_this_power_cycle(&self) -> bool {
        false
    }
    fn set_unlocked_this_power_cycle(&mut self, _unlocked: bool) {}
    fn mse_establish(
        &mut self,
        _host_x: [u8; 32],
        _host_y: [u8; 32],
        _out: &mut MsePoint,
    ) -> Result<(), Ctap2Response> {
        Err(Ctap2Response::NotAllowed)
    }
    fn mse_channel(&self, _out: &mut MseChannel) -> Result<(), Ctap2Response> {
        Err(Ctap2Response::NotAllowed)
    }
    fn audit_enabled(&self) -> bool {
        self.enabled
    }
    fn set_audit_enabled(&mut self, enabled: bool) -> Result<(), Ctap2Response> {
        self.enabled = enabled;
        Ok(())
    }
    fn audit_append(&mut self, _record: AuditRecord) -> Result<(), Ctap2Response> {
        Ok(())
    }
    fn audit_window(
        &self,
        out: &mut HV<u8, { fapico2_fido::CTAP2_MAX_MSG }>,
    ) -> Result<AuditWindow, Ctap2Response> {
        // **Append**, which is the trait's contract and what both shipped
        // implementations do. `resize_default` would *truncate* when the
        // scripted window is empty, which is how a zero-record window would
        // destroy the caller's framing reservation instead of testing it.
        out.extend_from_slice(&self.records)
            .map_err(|_| Ctap2Response::LimitExceeded)?;
        Ok(self.window)
    }
    fn audit_sign_checkpoint(
        &mut self,
        challenge: &[u8; 16],
        out: &mut Checkpoint,
    ) -> Result<(), Ctap2Response> {
        let ck = self.checkpoint.ok_or(Ctap2Response::NotAllowed)?;
        *out = ck;
        let _ = challenge;
        Ok(())
    }
    fn org_attestation(&self) -> OrgAttestationView<'_> {
        OrgAttestationView { scalar: None, chain: &[] }
    }
    fn set_org_attestation(&mut self, _att: OrgAttestation) -> Result<(), Ctap2Response> {
        Err(Ctap2Response::NotAllowed)
    }
}
