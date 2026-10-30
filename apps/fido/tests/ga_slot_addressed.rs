//! US-1723 — getAssertion signs the record the match step found
//! (EPIC FIDO-RESIDENT-DRIFT).
//!
//! Root-cause analysis: `docs/audits/2026-10-30-wrong-key-assertion-drift.md`.
//! The defect shape this story closes: the GA match step (allowList) resolves
//! an ID through the **RP-qualified** locator and holds a `(cred, slot)` pair,
//! but `build_assertion` then **re-fetches the same ID with `rp_id_hash:
//! None`** (`device_core.rs` → `CredentialIdLocator::locate`'s structural
//! walk, `fido_store.rs:756-779`) and signs whatever that walk finds first.
//! The two walks are not the same walk:
//!
//! * the match step's candidates are the entries whose index tag
//!   authenticates the *request's* RP hash;
//! * the re-fetch's candidates are the first `MAX_RP_CREDENTIALS` (16,
//!   `fido_store.rs:533`) Fido-domain entries in index ordinal order, whatever
//!   RP they belong to.
//!
//! So the re-fetch can serve a record the match step never found — analysis
//! §2/O2 ("the RP-qualified match step and the None-RP re-fetch walk the same
//! ordinal order, so they agree on which duplicate serves" — they agree only
//! when the candidate sets coincide). The fix threads the match step's slot
//! into `build_assertion`, opens that slot directly, and re-verifies the
//! opened record's `(rp_id_hash, credential_id)` against the request before
//! signing — the fail-closed invariant restated at the only place that
//! matters (a mismatch answers `CTAP2_ERR_NO_CREDENTIALS`: absence, not
//! fault, per US-1573's distinction).
//!
//! # Why the device twin
//!
//! `AGENTS.md` §1: the host twin (`app.rs`) is snapshot-array-addressed — its
//! match step keeps the whole `StoredCredential` and hands the object itself
//! to `build_assertion`, so it has no by-ID re-fetch to remove. A host-twin
//! test would pass forever while hardware serves the wrong record. This file
//! boots `device_app::FidoApp` over an installed key region through the
//! shared `region_boot` fixture and asserts `backend() == KeyRegion` first.
//!
//! # The fixtures are written through the region API, not through MC
//!
//! The pattern `platform/tests/nostr_store.rs` established: records built
//! with the applet's own codec (`DeviceCredential` → `RegionCredentials::put`)
//! directly into the region file, bypassing makeCredential. That is the only
//! way to place same-ID records under two different RPs (scenario 1) or at an
//! index ordinal beyond 16 (scenario 2) — the shipped MC path overwrites
//! same-ID registrations (US-1722) and so never produces either shape.
//!
//! # No PIN in this suite
//!
//! The GA scenarios need no clientPIN: on a PIN-less device GA runs
//! token-less (`uv == false`, `alwaysUv` false), every fixture credential
//! carries `cred_protect: 0`, so no request here sends a pinUvAuthParam. The
//! suite pins slot-addressing, not the UV policy (`tests/uv.rs` owns that).

mod region_boot;

use fapico2_fido::cbor::no_heap as nh;
use fapico2_fido::crypto;
use heapless::Vec as HV;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use region_boot::*;

/// The RP the target records belong to.
const RP: &str = "us1723.example";
/// A second RP — the decoy record's (scenario 1) and every filler
/// credential's (scenario 2). Distinct from [`RP`] in every byte.
const OTHER: &str = "us1723-other.example";

/// The fixture's constant challenge — the clientDataHash of every GA here,
/// and therefore the digest tail of every verified signature.
const CHALLENGE: [u8; 32] = [0xCCu8; 32];

/// CTAP2_ERR_NO_CREDENTIALS — the fail-closed answer.
const ERR_NO_CREDENTIALS: u8 = 0x2E;

/// A deterministic P-256 scalar for fixture key `tag`.
///
/// SHA-256 output is uniform over [0, 2^256); the probability of landing on
/// or above the secp256k1… (P-256) group order is ~2^-128, and
/// `p256::SecretKey::from_slice` below refuses an invalid scalar loudly
/// rather than silently, so a degenerate fixture cannot pass unnoticed.
fn scalar(tag: &[u8]) -> [u8; 32] {
    crypto::sha256(tag)
}

/// A resident `DeviceCredential` for `(id, rp)` under private key `key`,
/// written straight into the region — byte-for-byte a record the device
/// would write, sealed under the applet's own keys (`region_keys`).
///
/// The public key is derived from the private scalar so every signature this
/// suite verifies is verified against the key the record really carries.
fn region_record(id: &[u8], rp: &str, key: [u8; 32], counter: u32) -> DeviceCredential {
    let sk = p256::SecretKey::from_slice(&key).expect("a valid P-256 scalar");
    let pk = crypto::public_key_bytes(&sk.public_key());
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&pk[1..33]);
    y.copy_from_slice(&pk[33..65]);
    let mut cred = DeviceCredential {
        credential_id: HV::new(),
        public_key: DeviceCoseKey::es256(x, y),
        private_key: PrivateScalar::from_bytes(key),
        rp_id_hash: crypto::sha256(rp.as_bytes()),
        rp_id: HV::new(),
        user_handle: HV::new(),
        user_name: HV::new(),
        user_display_name: HV::new(),
        cred_protect: 0,
        large_blob_key: None,
        hmac_secret: HV::new(),
        cred_blob: HV::new(),
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: true,
        algorithm: -7,
        counter,
        revoked: false,
        expires_at: None,
    };
    cred.credential_id.extend_from_slice(id).unwrap();
    cred.rp_id.extend_from_slice(rp.as_bytes()).unwrap();
    cred.user_handle.extend_from_slice(b"us1723-user").unwrap();
    cred.user_name.extend_from_slice(b"us1723").unwrap();
    cred
}

/// A fixture credential ID: deterministic, and distinct per `tag`.
fn fixture_id(tag: &[u8]) -> Vec<u8> {
    crypto::sha256(tag).to_vec()
}

/// The authData and DER signature out of a getAssertion response.
///
/// Keys 2 and 3 — key 1 is the echoed credential descriptor map, read
/// separately by [`echoed_id`].
fn ga_parts(cbor: &[u8]) -> (Vec<u8> /* authData */, Vec<u8> /* DER sig */) {
    (
        bstr_at(cbor, 2).expect("getAssertion reply carries authData"),
        bstr_at(cbor, 3).expect("getAssertion reply carries a signature"),
    )
}

/// The credential ID the response echoes, out of the descriptor map at key 1.
///
/// The response's credential ID is an **echo of the request entry**, not a
/// read-back of the served record (analysis §2/O8) — US-1723 changes which
/// RECORD is opened, never the wire layout, so this echo must stay
/// byte-identical to the requested ID. Read off the wire through the local
/// byte readers below plus one nested-map step, in the style of
/// `region_boot::enumerate_rps_id`.
fn echoed_id(cbor: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    let (major, pairs) = cbor_head(cbor, &mut i)?;
    if major != 5 {
        return None;
    }
    for _ in 0..pairs {
        let (km, k) = cbor_head(cbor, &mut i)?;
        if km != 0 {
            return None;
        }
        let value_at = i;
        cbor_skip(cbor, &mut i)?;
        if k != 1 {
            continue;
        }
        // The value is the PublicKeyCredentialDescriptor map
        // {"id": bstr, "type": tstr} — "id" first, in wire order.
        let mut j = value_at;
        let (vm, inner_pairs) = cbor_head(cbor, &mut j)?;
        if vm != 5 {
            return None;
        }
        for _ in 0..inner_pairs {
            let (ikm, ilen) = cbor_head(cbor, &mut j)?;
            if ikm != 3 {
                // Not a text-string key: skip key and value, keep walking.
                cbor_skip(cbor, &mut j)?;
                cbor_skip(cbor, &mut j)?;
                continue;
            }
            let key_end = j.checked_add(ilen as usize)?;
            let is_id = cbor.get(j..key_end) == Some(&b"id"[..]);
            j = key_end;
            if is_id {
                let (tm, tlen) = cbor_head(cbor, &mut j)?;
                if tm != 2 {
                    return None;
                }
                let end = j.checked_add(tlen as usize)?;
                return cbor.get(j..end).map(|b| b.to_vec());
            }
            cbor_skip(cbor, &mut j)?; // the value of a key that is not "id"
        }
        return None;
    }
    None
}

/// Does `signed` verify under the P-256 key `key`?
fn verifies_under(key: [u8; 32], signed: &[u8], sig_der: &[u8]) -> bool {
    let sk = match p256::SecretKey::from_slice(&key) {
        Ok(sk) => sk,
        Err(_) => return false,
    };
    let pk = crypto::public_key_bytes(&sk.public_key());
    let mut point = [0u8; 65];
    point[0] = 0x04;
    point[1..33].copy_from_slice(&pk[1..33]);
    point[33..65].copy_from_slice(&pk[33..65]);
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&point) else {
        return false;
    };
    let Ok(sig) = Signature::from_der(sig_der) else {
        return false;
    };
    vk.verify(signed, &sig).is_ok()
}

/// Boot the region-backed twin: fresh region, presence granted, no PIN.
///
/// Returns the keys the applet derives for this store — the same
/// derivation the command path uses, so fixture records sealed under them
/// open under the shipped path — plus the lock guard and region file, which
/// must outlive the device (the provider is a process-global,
/// `region_boot`'s module docs).
fn boot_device(
    tag: &str,
) -> (
    std::sync::MutexGuard<'static, ()>,
    InstalledRegion,
    Device,
    RegionKeys,
) {
    let guard = lock();
    let region_file = install(tag);
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    assert_eq!(
        device.backend(),
        fapico2_fido::device_keystore::CredentialBackend::KeyRegion,
        "the fixture must be region-backed — a snapshot-backed run replaces by \
         ID and has no structural walk to depend on by construction"
    );
    let keys = device.with_store(|store| {
        let ks = DeviceKeystore::load(store).expect("readable").expect("snapshot present");
        region_keys(store, &ks)
    });
    (guard, region_file, device, keys)
}

/// Write `creds` into the region file in order, through the applet's own
/// codec. Write order is index order: each `put` takes the earliest free
/// cell, so ordinal == write order for a fresh region.
fn write_records(region_file: &InstalledRegion, keys: &RegionKeys, creds: &[DeviceCredential]) {
    region_file.with(|region| {
        let mut store = RegionCredentials::new(region, keys);
        for (n, cred) in creds.iter().enumerate() {
            store
                .put(&nonce(n as u32 + 1), cred)
                .expect("fixture record must commit");
        }
    });
}

/// A getAssertion request without a clientPIN leg: `rpId` (1),
/// `clientDataHash` (2), `allowList` (3) — CTAP 2.1 §6.2's key numbering,
/// which is the reverse of makeCredential's. allowList entries are
/// `{type, id}` maps, not bare byte strings (`device_core.rs::parse_ga`
/// discards anything else).
fn get_assertion_pinned(device: &mut Device, rp: &str, id: &[u8]) -> (u8, Vec<u8>) {
    let mut r: HV<u8, 512> = HV::new();
    nh::push_map_header(&mut r, 3).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, rp).unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    nh::push_bstr(&mut r, &CHALLENGE).unwrap();
    nh::push_uint(&mut r, 3).unwrap();
    nh::push_array_header(&mut r, 1).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "type").unwrap();
    nh::push_tstr(&mut r, "public-key").unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_bstr(&mut r, id).unwrap();
    device.call(0x02, r.as_slice())
}

/// **US-1723 scenario 1 — the match step's slot is the signed slot.**
///
/// Three records, written in index order through the region API:
///
/// | ordinal | record | RP | key |
/// |---|---|---|---|
/// | 0 | decoy: SAME credential ID, DIFFERENT RP | `OTHER` | `K_DECOY` |
/// | 1 | `S_old`: the target ID, the request's RP | `RP` | `K_OLD` |
/// | 2 | `S_new`: the target ID, the request's RP | `RP` | `K_NEW` |
///
/// The allowList match step resolves the ID **RP-qualified**: its candidates
/// are only the `RP` entries, so it resolves the same-ID duplicate by the
/// epic's one ordering rule — **last index-order match = newest written**
/// (US-1724; before that story it found `S_old`, the first match) — and holds
/// its slot. The contract under test is US-1723's and is unchanged: the
/// signed record is the one the match step resolved — now `S_new`, so `K_NEW`
/// signs and `K_OLD` must not — with the opened record's
/// `(rp_id_hash, credential_id)` re-verified against the request before
/// signing.
///
/// What the decoy buys: it is precisely a record whose **ID matches but whose
/// `rp_id_hash` does not**, sitting at an earlier index ordinal — a shape the
/// old None-RP re-fetch served (its structural walk takes the first 16 Fido
/// entries whatever their RP). That makes the fail-closed re-check
/// observable: this test fails if the implementation signs a record whose
/// `(rp_id_hash, credential_id)` does not match the request.
///
/// What the test pins, precisely:
/// 1. the assertion is served at all;
/// 2. authData's `rpIdHash` (bytes 0..32) equals `SHA-256(RP)` — the
///    request's RP, i.e. the served record's RP was re-verified against the
///    request;
/// 3. the signature verifies under `K_NEW` — the record the match step
///    resolved under US-1724's newest-wins ordering — and NOT under `K_OLD`
///    (the oldest copy, which the pre-US-1724 first-match walk used to
///    serve) nor `K_DECOY`;
/// 4. the response's ID echo is byte-identical to the requested ID (wire
///    conventions frozen, `AGENTS.md` §2).
///
/// The `credential_id` half of the re-check is pinned structurally rather
/// than observably: every record this fixture can reach for the request
/// carries the requested ID (the locator's probe byte-compares IDs), so a
/// wrong-ID open cannot arise here without a corrupt medium — the re-check
/// for that case is restated at the signing site and answers
/// `NO_CREDENTIALS`, and scenario 2 pins the reachable part of that path.
#[test]
fn the_match_steps_slot_is_the_signed_slot() {
    let (_guard, region_file, mut device, keys) = boot_device("us1723-slotted");

    let id = fixture_id(b"us1723 same-id");
    let k_old = scalar(b"us1723 K_old");
    let k_new = scalar(b"us1723 K_new");
    let k_decoy = scalar(b"us1723 K_decoy");

    // Index order = write order: decoy first, then S_old, then S_new.
    write_records(
        &region_file,
        &keys,
        &[
            region_record(&id, OTHER, k_decoy, 900),
            region_record(&id, RP, k_old, 10),
            region_record(&id, RP, k_new, 20),
        ],
    );

    let (status, cbor) = get_assertion_pinned(&mut device, RP, &id);
    assert_eq!(
        status, 0x00,
        "the pinned assertion must be served at all: {cbor:02x?}"
    );

    let (auth_data, sig_der) = ga_parts(&cbor);
    let target_hash = crypto::sha256(RP.as_bytes());
    assert_eq!(
        &auth_data[0..32],
        &target_hash[..],
        "authData must carry the REQUEST's rpIdHash — a record for another RP \
         ({OTHER}) must never be opened for this request, which is what the \
         None-RP re-fetch serves today (analysis §2/O2)"
    );

    let mut signed = auth_data.clone();
    signed.extend_from_slice(&CHALLENGE);
    assert!(
        verifies_under(k_new, &signed, &sig_der),
        "the assertion must sign with the key of the record the MATCH STEP \
         resolved — under US-1724's ordering rule that is the NEWEST same-ID \
         record (S_new, K_new), the same one discovery lists last and \
         overwrite replaces"
    );
    assert!(
        !verifies_under(k_old, &signed, &sig_der),
        "the OLDEST same-ID copy (K_old) must never sign — the first-match \
         resolution US-1724 replaced served exactly that"
    );
    assert!(
        !verifies_under(k_decoy, &signed, &sig_der),
        "the decoy record (same ID, other RP, earlier ordinal) must never sign"
    );

    assert_eq!(
        echoed_id(&cbor).as_deref(),
        Some(id.as_slice()),
        "the response's credential ID is a byte-identical echo of the request \
         entry — the wire layout is frozen (AGENTS.md §2); US-1723 changes \
         which record is opened, not the response shape"
    );
}

/// **US-1723 scenario 2 — GA no longer depends on the 16-candidate
/// structural walk.**
///
/// The bound being exceeded: `MAX_RP_CREDENTIALS = 16`
/// (`fido_store.rs:533`), as applied by `CredentialIdLocator::locate`'s
/// **`rp_id_hash: None` branch** — the structural walk
/// (`fido_store.rs:756-779`) takes the first 16 Fido-domain entries in index
/// ordinal order and probes no further. The RP-qualified branch is NOT
/// exceeded here: each fixture credential is the only entry for its own RP,
/// so `index::lookup_all` finds the target wherever it sits — which is what
/// lets this test isolate the re-fetch as the sole failure point.
///
/// Seventeen credentials for seventeen assorted RPs (distinct `rp_id_hash`
/// values, so no per-RP window confounds the walk), written in order; the
/// target is the seventeenth — index ordinal 16, one past the walk's cap. A
/// getAssertion pinning its ID: the match step finds it, the re-fetch
/// reports it `Absent`, and the command answers `CTAP2_ERR_NO_CREDENTIALS`
/// — fail-closed (analysis §5 hazard 2), but wrong: the credential is there
/// and was matched.
#[test]
fn ga_no_longer_depends_on_the_16candidate_structural_walk() {
    let (_guard, region_file, mut device, keys) = boot_device("us1723-beyond16");

    // Seventeen assorted-RP credentials; the target is written LAST, so its
    // index ordinal (16, zero-based) is the first one the structural walk
    // cannot reach.
    const COUNT: u32 = 17;
    let target_ordinal: u32 = COUNT - 1;
    let target_rp = format!("us1723-rp-{target_ordinal}.example");
    let target_id = fixture_id(format!("us1723-id-{target_ordinal}").as_bytes());
    let target_key = scalar(b"us1723 K_beyond16");

    let mut creds: Vec<DeviceCredential> = Vec::new();
    for n in 0..COUNT {
        if n == target_ordinal {
            creds.push(region_record(&target_id, &target_rp, target_key, 100 + n));
        } else {
            let rp = format!("us1723-rp-{n}.example");
            let id = fixture_id(format!("us1723-id-{n}").as_bytes());
            creds.push(region_record(&id, &rp, scalar(format!("us1723 K fill {n}").as_bytes()), 100 + n));
        }
    }
    write_records(&region_file, &keys, &creds);

    let (status, cbor) = get_assertion_pinned(&mut device, &target_rp, &target_id);
    assert_eq!(
        status, 0x00,
        "a credential the match step found must be served even when its index \
         ordinal exceeds the None-RP walk's 16-candidate cap \
         (MAX_RP_CREDENTIALS, fido_store.rs:533): {cbor:02x?} \
         (0x{ERR_NO_CREDENTIALS:02x} here is the fail-closed wrong answer)"
    );

    let (auth_data, sig_der) = ga_parts(&cbor);
    let target_hash = crypto::sha256(target_rp.as_bytes());
    assert_eq!(
        &auth_data[0..32],
        &target_hash[..],
        "the served record must be the target's — the request's own RP"
    );
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&CHALLENGE);
    assert!(
        verifies_under(target_key, &signed, &sig_der),
        "the assertion must sign with the target record's own key"
    );
}

// ---------------------------------------------------------------------------
// Local CBOR byte readers
// ---------------------------------------------------------------------------

/// The CBOR major type and argument of the item starting at `i`.
///
/// A local copy of `region_boot`'s reader of the same name — that one is
/// private to the fixture module (each integration test compiles it
/// separately, and this story's one-file rule forbids widening it), and a
/// wire-format assertion must not ride the implementation's parser
/// (`region_boot`'s comment on the same function gives the full reason).
fn cbor_head(b: &[u8], i: &mut usize) -> Option<(u8, u64)> {
    let b0 = *b.get(*i)?;
    *i += 1;
    let major = b0 >> 5;
    let arg = match b0 & 0x1F {
        0..=23 => u64::from(b0 & 0x1F),
        24 => {
            let v = u64::from(*b.get(*i)?);
            *i += 1;
            v
        }
        25 => {
            let v = u16::from_be_bytes([*b.get(*i)?, *b.get(*i + 1)?]);
            *i += 2;
            u64::from(v)
        }
        26 => {
            let v = u32::from_be_bytes([
                *b.get(*i)?, *b.get(*i + 1)?, *b.get(*i + 2)?, *b.get(*i + 3)?,
            ]);
            *i += 4;
            u64::from(v)
        }
        27 => {
            let tail: [u8; 8] = b.get(*i..*i + 8)?.try_into().ok()?;
            *i += 8;
            u64::from_be_bytes(tail)
        }
        _ => return None,
    };
    Some((major, arg))
}

/// Step `i` past exactly one CBOR item.
fn cbor_skip(b: &[u8], i: &mut usize) -> Option<()> {
    let (major, arg) = cbor_head(b, i)?;
    match major {
        0 | 1 => {}
        2 | 3 => {
            *i = i.checked_add(arg as usize)?;
            if *i > b.len() {
                return None;
            }
        }
        4 => {
            for _ in 0..arg {
                cbor_skip(b, i)?;
            }
        }
        5 => {
            for _ in 0..arg {
                cbor_skip(b, i)?;
                cbor_skip(b, i)?;
            }
        }
        6 => {
            cbor_skip(b, i)?;
            cbor_skip(b, i)?;
        }
        7 => match arg {
            20..=23 => {}
            25 => *i = i.checked_add(2)?,
            26 => *i = i.checked_add(4)?,
            27 => *i = i.checked_add(8)?,
            _ => {}
        },
        _ => return None,
    }
    Some(())
}
