//! US-1725 — RP-known lookups never use the RP-blind structural walk
//! (EPIC FIDO-RESIDENT-DRIFT).
//!
//! The None-RP by-ID probe (`CredentialIdLocator` with `rp_id_hash: None`,
//! `fido_store.rs:756-779`) walks the FIDO domain **structurally** and stops at
//! `MAX_RP_CREDENTIALS` = 16 entries *whatever RP they belong to*
//! (`fido_store.rs:533`). A caller that KNOWS the RP must never reach for it:
//! with more than 16 FIDO entries on the device, a credential past the
//! 16-ordinal window is invisible to the walk even though it exists — the
//! analysis doc's §5.2 hazard
//! (`docs/audits/2026-10-30-wrong-key-assertion-drift.md`).
//!
//! Three call sites had the disease; this file pins all three:
//!
//! 1. **The makeCredential exclude loop** (`device_core.rs`, "Exclude list"):
//!    with 17+ credentials, `excludeCredentials` naming a credential beyond
//!    the window was answered "absent" and the registration silently
//!    proceeded — the client's re-registration signal was swallowed.
//! 2. **The migration collision probe** (`device_keystore.rs::
//!    contains_credential`): the same walk, threaded its own record's
//!    `rp_id_hash` so a migrating credential past the window is answered
//!    `Present` (idempotent) rather than re-written. Behavioural scenarios
//!    live in `snapshot_migration.rs`; this story's change is thread-the-hash.
//! 3. **The credMgmt per-credential response** (`cm_cred_response`): the
//!    enumeration opens the record RP-qualified, then the response re-fetched
//!    it by ID with `None` — with >16 FIDO entries the device answered
//!    `CTAP2_ERR_NO_CREDENTIALS` for a credential its own enumeration had
//!    just listed.
//!
//! # Which bound the fixture exceeds, and which it deliberately does not
//!
//! The 18 credentials below are spread over 17 distinct RPs (16 bulk RPs with
//! one credential each, then two for the target RP). That exceeds the
//! **global** 16-ordinal window of the None-RP structural walk while keeping
//! every single RP far inside the RP-qualified path's own window —
//! `lookup_all` matches only entries whose tag authenticates the handed hash,
//! so `MAX_RP_CREDENTIALS` bounds it **per RP** (16 per RP, not 16 total), and
//! `slots_for_rp`'s enumeration window is `MAX_ENUMERATED_SLOTS` = 32 per RP.
//! A fixture that pushed one RP past 16 would confound the two bounds and
//! could fail even after the fix — the qualification is what is under test
//! here, not the per-RP window.
//!
//! # Harness
//!
//! `region_boot`'s device twin — the shipped path (`AGENTS.md` §1). The
//! credentials are written **through the region API directly** (the same
//! `RegionCredentials::put` + applet codec discipline
//! `region_boot::Device::enroll_directly` uses): walking 17 makeCredential
//! handshakes through the fixture would make the test about the handshake,
//! and the direct write puts each record at a known index ordinal (write
//! order = index order on a fresh region), which is what makes "the 17th
//! registered" a property of the fixture rather than of allocator timing.

mod region_boot;

use fapico2_fido::cbor::no_heap as nh;
use fapico2_fido::crypto;
use heapless::Vec as HV;
use region_boot::*;

/// The RP the 17th-registered credential belongs to — the one every scenario
/// makes its request against.
const RP_R: &str = "rp-r.us1725.example";

/// The `user.id` the makeCredential scenarios present.
const USER_ID: &[u8] = b"us1725-user";

const PIN: &[u8] = b"123456";

/// CTAP2_ERR_CREDENTIAL_EXCLUDED.
const ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
/// CTAP2_ERR_NO_CREDENTIALS — this firmware's corrected status table
/// (`ctap2.rs`: "The previous table was off by one across 0x2B..0x2D").
const ERR_NO_CREDENTIALS: u8 = 0x2E;
/// CTAP2_ERR_NOT_ALLOWED — a GetNext with no pending enumeration.
const ERR_NOT_ALLOWED: u8 = 0x30;

/// The fixture credential registered `n`-th (0-based): one bulk RP per
/// ordinal below 16, then the target RP.
///
/// Built on the shared `credential(n, true)` fixture with `rp_id` /
/// `rp_id_hash` / `user_handle` overridden, so the record is a real
/// `DeviceCredential` encoded by the applet's own codec — same discipline as
/// `region_boot::credential`, with the RP this file's scenarios need. The
/// credential ID stays the shared fixture's `credential_id(n)`, which is what
/// the exclude list names and what the credMgmt responses must carry.
fn fixture_cred(n: u32, rp: &str) -> DeviceCredential {
    let mut cred = credential(n, true);
    cred.rp_id_hash = crypto::sha256(rp.as_bytes());
    cred.rp_id.clear();
    cred.rp_id.extend_from_slice(rp.as_bytes()).unwrap();
    cred.user_handle.clear();
    cred.user_handle.extend_from_slice(&[n as u8; 8]).unwrap();
    cred
}

/// The ID of the `n`-th fixture credential, as the client names it.
fn fixture_id(n: u32) -> Vec<u8> {
    credential_id(n).to_vec()
}

/// The 18-credential fixture: 16 bulk RPs (one credential each) written
/// first, then two credentials for [`RP_R`]. The 17th-registered credential
/// (index 16) belongs to [`RP_R`] — the brief's precondition. On a fresh
/// region write order is index order, so both [`RP_R`] records sit past the
/// None-RP walk's 16-ordinal window and inside every RP-qualified window.
fn seed_region(device: &mut Device, region_file: &InstalledRegion) {
    let keys = device.with_store(|store| {
        let ks = DeviceKeystore::load(store).expect("readable").expect("snapshot present");
        region_keys(store, &ks)
    });
    region_file.with(|region| {
        let mut creds = RegionCredentials::new(region, &keys);
        for n in 0..16u32 {
            let rp = format!("bulk-{n}.us1725.example");
            creds
                .put(&nonce(n), &fixture_cred(n, &rp))
                .expect("bulk credential must enrol directly");
        }
        creds
            .put(&nonce(16), &fixture_cred(16, RP_R))
            .expect("the 17th credential (rp R) must enrol directly");
        creds
            .put(&nonce(17), &fixture_cred(17, RP_R))
            .expect("the 18th credential (rp R) must enrol directly");
    });
}

/// Boot the region-backed twin the way every scenario needs it: a fresh
/// region file seeded with the 18-credential fixture, a PIN-set snapshot
/// persisted, presence granted, token minted. The lock guard and the region
/// file must outlive the device.
fn boot_seeded(tag: &str) -> (std::sync::MutexGuard<'static, ()>, InstalledRegion, Device) {
    let guard = lock();
    let region_file = install(tag);
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    device.set_pin(PIN);
    assert!(device.persist(), "the PIN write must reach the secure store");
    assert_eq!(
        device.backend(),
        fapico2_fido::device_keystore::CredentialBackend::KeyRegion,
        "the fixture must be region-backed — a snapshot-backed run consults the \
         resident array and cannot exhibit the structural-walk bound"
    );
    seed_region(&mut device, &region_file);
    (guard, region_file, device)
}

/// A resident makeCredential for `rp` whose excludeCredentials names
/// `exclude_id` — the same `{type, id}` map shape
/// `mc_overwrite.rs::make_cred_excluding` established (a bare bstr would be
/// discarded by the parser and the refusal would never fire).
fn make_cred_excluding(device: &mut Device, rp: &str, exclude_id: &[u8]) -> (u8, Vec<u8>) {
    let challenge = [0xCCu8; 32];
    let mut r: HV<u8, 512> = HV::new();
    nh::push_map_header(&mut r, 8).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_bstr(&mut r, &challenge).unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_tstr(&mut r, rp).unwrap();
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
    nh::push_bstr(&mut r, &device.pin_auth(&challenge)).unwrap();
    nh::push_uint(&mut r, 9).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    device.call(0x01, r.as_slice())
}

/// credMgmt `enumerateCredentialsGetNextCredential` — the unauthenticated
/// `{1: 0x05}` request both dialects send (`credmgmt_ctap2_spec.rs` is the
/// reference for the shape; the enumeration already pending on the channel
/// routes it).
fn cm_creds_next(device: &mut Device) -> (u8, Vec<u8>) {
    let mut r: HV<u8, 256> = HV::new();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_uint(&mut r, 0x05).unwrap();
    device.call(0x0A, r.as_slice())
}

/// The `credentialId` (PicoForge key 7) out of a per-credential response.
///
/// The value is a **PublicKeyCredentialDescriptor map** — `{type: "public-key",
/// id: bstr}` (`device_core.rs::cm_cred_response` builds it that way, the
/// CTAP §6.8.2 shape) — not a bare byte string, so the value's own map has to
/// be walked for the `"id"` entry. Same hand-rolled wire reader
/// `region_boot` documents for its `uint_at`/`bstr_at`: the implementation's
/// parser cannot be shared without losing the ability to tell an
/// implementation bug from a test bug.
fn cm_cred_id(cbor: &[u8]) -> Option<Vec<u8>> {
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
        if k != 7 {
            continue;
        }
        let mut j = value_at;
        let (vm, inner_pairs) = cbor_head(cbor, &mut j)?;
        if vm != 5 {
            return None;
        }
        for _ in 0..inner_pairs {
            // The descriptor's keys are text strings ("id", "type"); a tstr's
            // head does not consume its content bytes, so the content is
            // sliced here and the value starts at the key's end.
            let (ikm, ilen) = cbor_head(cbor, &mut j)?;
            if ikm != 3 {
                return None;
            }
            let key_end = j.checked_add(ilen as usize)?;
            let key = cbor.get(j..key_end)?;
            j = key_end;
            if key != b"id" {
                cbor_skip(cbor, &mut j)?;
                continue;
            }
            let (tm, tlen) = cbor_head(cbor, &mut j)?;
            if tm != 2 {
                return None;
            }
            let end = j.checked_add(tlen as usize)?;
            return cbor.get(j..end).map(|b| b.to_vec());
        }
        return None;
    }
    None
}

/// The CBOR major type and argument of the item starting at `i`.
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

/// **US-1725 scenario 1 — the exclude list detects a credential beyond the
/// 16-ordinal window.**
///
/// The 17th-registered credential belongs to [`RP_R`]; a makeCredential for
/// [`RP_R`] whose excludeCredentials names its ID must be refused
/// `CTAP2_ERR_CREDENTIAL_EXCLUDED` (0x19). Before the fix the exclude check
/// walked the None-RP structural window (16 entries, this credential is the
/// 17th FIDO record), read `Absent`, and the registration silently
/// proceeded.
#[test]
fn exclude_list_detects_a_credential_beyond_the_16ordinal_window() {
    let (_guard, _region_file, mut device) = boot_seeded("us1725-exclude-17th");

    let (status, cbor) = make_cred_excluding(&mut device, RP_R, &fixture_id(16));
    assert_eq!(
        status, ERR_CREDENTIAL_EXCLUDED,
        "an excludeCredentials entry naming a credential past the 16-ordinal \
         window must still be honoured: {cbor:02x?}"
    );
}

/// **US-1725 scenario 2 — the same request without the exclude list still
/// succeeds.**
///
/// The control half of the pair: the fixture itself must not be what breaks
/// registration. Kept un-ignored and expected green before and after the fix.
#[test]
fn the_same_request_without_the_exclude_list_still_succeeds() {
    let (_guard, _region_file, mut device) = boot_seeded("us1725-exclude-control");

    let (status, cbor) = device.make_cred(RP_R, USER_ID);
    assert_eq!(
        status, 0x00,
        "registration without an exclude list must succeed on the same fixture: {cbor:02x?}"
    );
}

/// **US-1725 scenario 3 — the credMgmt per-credential response resolves
/// RP-qualified.**
///
/// With >16 FIDO entries, `enumerateCredsBegin` for [`RP_R`] lists its two
/// credentials through the RP-qualified `slots_for_rp` — and then the
/// response builder re-fetched each by ID through the None-RP walk, past
/// which they sit, answering `CTAP2_ERR_NO_CREDENTIALS` (0x2E on this
/// firmware's corrected status table) for a credential the enumeration
/// itself had just listed. Both the Begin's first response and the GetNext
/// continuation must succeed and carry the fixture IDs (PicoForge dialect,
/// `AGENTS.md` §2).
#[test]
fn credmgmt_per_credential_response_resolves_beyond_the_16ordinal_window() {
    let (_guard, _region_file, mut device) = boot_seeded("us1725-cm-percred-17th");

    let (begin_status, begin) = device.cm_enumerate_creds(RP_R);
    assert_eq!(
        begin_status, 0x00,
        "enumerateCredsBegin must succeed — its own enumeration is RP-qualified \
         and both rp-R records are inside every per-RP window: {begin:02x?}"
    );
    let first_id = cm_cred_id(&begin).expect("the first response carries credentialId");
    assert_eq!(
        first_id,
        fixture_id(17),
        "newest first: the 18th-registered rp-R credential is served first"
    );

    let (next_status, next) = cm_creds_next(&mut device);
    assert_eq!(
        next_status, 0x00,
        "enumerateCredentialsGetNextCredential must succeed — the response \
         re-fetch must not answer NoCredentials for a credential past the \
         None-RP walk's 16-ordinal window: {next:02x?}"
    );
    let second_id = cm_cred_id(&next).expect("the next response carries credentialId");
    assert_eq!(second_id, fixture_id(16), "the 17th-registered credential follows");

    // And the enumeration is then exhausted: a third Next is NotAllowed
    // (the pending state died with its last credential).
    let (extra_status, _extra) = cm_creds_next(&mut device);
    assert_eq!(
        extra_status, ERR_NOT_ALLOWED,
        "the enumeration served exactly the two rp-R credentials"
    );

    // A genuine miss still fails closed exactly as before: an RP with no
    // credentials gets NoCredentials from the Begin itself — the
    // qualification must not turn "nothing there" into something else.
    let (missing_status, missing) = device.cm_enumerate_creds("absent.us1725.example");
    assert_eq!(
        missing_status, ERR_NO_CREDENTIALS,
        "a credential-less RP must still answer NoCredentials: {missing:02x?}"
    );
}
