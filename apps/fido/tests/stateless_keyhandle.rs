//! US-714 (POLISH-PUB): stateless U2F key handles — C parity.
//!
//! C reference (`pico-fido2/src/fido/cmd_register.c:74` →
//! `fido.c::derive_key`, `cmd_authenticate.c` → `verify_key`): a U2F key
//! handle is 64 bytes — 32 bytes of HKDF-salt "key path" plus a 32-byte
//! HMAC-SHA256 tag over `appId ‖ path` keyed by the derived private scalar.
//! The private key is re-derived from the device master at authentication,
//! so a non-resident registration consumes **no** store slot (C parity:
//! unlimited non-resident credentials).
//!
//! Before US-714 every Rust U2F REGISTER persisted a `DeviceCredential`,
//! permanently eating a chunked store part with no credMgmt visibility.
//! These tests pin the new contract on the device command path
//! (`FidoApp::process_u2f_with_store`) and the host twin
//! (`process_u2f_apdu`), keeping the US-701 twins in sync.

use fapico2_fido::FidoApp;
use fapico2_platform::dispatch::App as _;
use fapico2_platform::secure_store::chunked;
use fapico2_platform::secure_store::rp2350::Rp2350SecureStore;
use fapico2_platform::secure_store::SecureStore;
use fapico2_platform::trng::HostTrng;

const CTAP2_MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;
const U2F_SW_OK: [u8; 2] = [0x90, 0x00];
const U2F_SW_WRONG_DATA: [u8; 2] = [0x6A, 0x80];
const U2F_SW_CONDS_NOT_SATISFIED: [u8; 2] = [0x69, 0x85];
/// C `KEY_HANDLE_LEN` (fido.h:36) = KEY_PATH_LEN (32) + SHA-256 tag (32).
const KEY_HANDLE_LEN: usize = 64;

fn sw(reply: &[u8]) -> [u8; 2] {
    [reply[reply.len() - 2], reply[reply.len() - 1]]
}

/// U2F REGISTER APDU: `00 01 00 00 40 ‖ client_param(32) ‖ app_param(32)`.
fn register_apdu(client: u8) -> Vec<u8> {
    let mut apdu = vec![0x00, 0x01, 0x00, 0x00, 0x40];
    apdu.extend_from_slice(&[client; 32]);
    apdu.extend_from_slice(&[0xA0; 32]); // app_param
    apdu
}

/// U2F AUTHENTICATE APDU: `00 02 P1 00 Lc ‖ client(32) ‖ app(32) ‖ kh_len ‖ kh`.
fn authenticate_apdu(client: u8, kh: &[u8], p1: u8) -> Vec<u8> {
    let mut apdu = vec![0x00, 0x02, p1, 0x00, (64 + 1 + kh.len()) as u8];
    apdu.extend_from_slice(&[client; 32]);
    apdu.extend_from_slice(&[0xA0; 32]);
    apdu.push(kh.len() as u8);
    apdu.extend_from_slice(kh);
    apdu
}

/// Key handle out of a U2F register reply
/// (`05 ‖ pub(65) ‖ kh_len(1) ‖ kh ‖ cert ‖ sig`).
fn key_handle_of(reply: &[u8]) -> Vec<u8> {
    let kh_len = reply[66] as usize;
    reply[67..67 + kh_len].to_vec()
}

/// Drive one U2F command through the device path and the persist gate,
/// exactly as the HID serve loop does (process, then durable-before-ack).
fn u2f_and_persist(
    app: &mut FidoApp,
    store: &mut Rp2350SecureStore,
    apdu: &[u8],
) -> (Vec<u8>, bool) {
    let mut out = heapless::Vec::<u8, CTAP2_MAX_MSG>::new();
    let n = app.process_u2f_with_store(apdu, &mut out, Some(store));
    let reply = out.as_slice()[..n].to_vec();
    let wrote = app.persist_if_dirty(store);
    (reply, wrote)
}

/// Number of physical part slots the `fido.keystore.v1` chunked family
/// occupies (both rewrite buffers — an orphan would show up here).
fn keystore_parts(store: &Rp2350SecureStore) -> usize {
    let mut count = 0;
    for buf in 0..2u8 {
        for index in 0..chunked::MAX_PARTS {
            if let Some((pk, pklen)) = chunked::physical_part_key(b"fido.keystore.v1", buf, index) {
                if store.contains(&pk[..pklen]) {
                    count += 1;
                }
            }
        }
    }
    count
}

/// HEADLINE (US-714): a U2F register must leave the secure store untouched —
/// no new credential, no chunked part, no occupancy, nothing to persist.
/// The authentication of the returned stateless handle works and costs only
/// the global-counter bump (same part count, same occupancy).
#[test]
fn u2f_register_leaves_no_store_part() {
    let mut trng = HostTrng::new();
    let mut store = Rp2350SecureStore::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();
    // A fresh boot persists its snapshot but leaves the gate dirty by
    // design (persist() writes; persist_if_dirty clears); drain it so the
    // register's no-write contract is measurable.
    assert!(app.persist_if_dirty(&mut store), "boot drains one dirty snapshot");
    assert!(!app.persist_if_dirty(&mut store), "boot leaves a clean gate");

    let parts_before = keystore_parts(&store);
    let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let occ_before = {
        store.partition_image(&mut img).unwrap();
        u32::from_le_bytes([img[4], img[5], img[6], img[7]]) as usize
    };

    let (reply, wrote) = u2f_and_persist(&mut app, &mut store, &register_apdu(0x42));
    assert_eq!(reply[0], 0x05, "U2F register must succeed");
    assert_eq!(sw(&reply), U2F_SW_OK, "status word");
    assert!(!wrote, "register: the store must not be written at all");
    assert!(!app.is_dirty(), "register: no dirty state may be latched");
    assert_eq!(
        app.keystore().cred_count(),
        0,
        "register: no store credential may be created (RED: was 1)"
    );
    assert_eq!(keystore_parts(&store), parts_before, "register: no new chunked part");
    let occ_after = {
        store.partition_image(&mut img).unwrap();
        u32::from_le_bytes([img[4], img[5], img[6], img[7]]) as usize
    };
    assert_eq!(occ_after, occ_before, "register: store occupancy unchanged");

    // The handle is the C-format 64-byte stateless handle.
    let kh = key_handle_of(&reply);
    assert_eq!(kh.len(), KEY_HANDLE_LEN, "handle must be the C 64-byte format");

    // Authentication re-derives the key — still no credential in the store.
    let (auth, wrote) = u2f_and_persist(
        &mut app,
        &mut store,
        &authenticate_apdu(0x42, &kh, 0x03),
    );
    assert_eq!(sw(&auth), U2F_SW_OK, "stateless authenticate must succeed");
    assert_eq!(auth[0], 0x01, "user presence byte");
    // US-1011: the global counter is batched, so a single authenticate inside
    // an open window does NOT rewrite the keystore at all. That is a stronger
    // form of the property this test has always pinned (a U2F authenticate
    // adds nothing to the store) — `counter_batching.rs` counts the
    // rewrites the window does cost.
    //
    // **Window position.** The register above is a stateless registration and
    // writes nothing, and the boot's own persist closed the window, so this
    // authenticate is the *first* bump in an **empty** window — not merely one
    // inside an open one, which is what "inside an open window" alone would
    // leave the reader assuming. The assertion is `!wrote`, so it holds at
    // any non-closing position, but it is worth stating: a future edit that
    // drove the window to `INTERVAL - 1` first would be testing a different
    // claim (whether the window-closing write happens to be skipped at this
    // occupancy) rather than this one. The position is recorded here so that
    // change is a deliberate one.
    assert!(
        !wrote,
        "auth: a batched counter bump must not write the store at all"
    );
    assert_eq!(app.keystore().cred_count(), 0, "auth must not backfill a credential");
    assert_eq!(keystore_parts(&store), parts_before, "auth: part count unchanged");
    let occ_after = {
        store.partition_image(&mut img).unwrap();
        u32::from_le_bytes([img[4], img[5], img[6], img[7]]) as usize
    };
    assert_eq!(occ_after, occ_before, "auth: occupancy unchanged");

    // Two consecutive authenticates must count monotonically.
    let (auth2, _) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(0x42, &kh, 0x03));
    assert_eq!(sw(&auth2), U2F_SW_OK);
    let c1 = u32::from_be_bytes([auth[1], auth[2], auth[3], auth[4]]);
    let c2 = u32::from_be_bytes([auth2[1], auth2[2], auth2[3], auth2[4]]);
    assert_eq!(c2, c1 + 1, "stateless counter increments");
}

/// The global counter must not go backwards across a reboot — the property
/// US-714's review called CRITICAL, and the one a **batched** counter (US-1011)
/// has to keep.
///
/// US-714's original defect was ordering: the pre-fix code assigned
/// `cred_counter = next` only *after* `persist()`, so the durable snapshot
/// kept the old counter while the reply signed `next`; after a reboot the
/// counter regressed and the same value was signed again (signatures are not
/// a counter domain: replaying a value breaks monotonicity). US-1011 changes
/// the *stronger* version of that guarantee into a bounded one — the reply
/// signs a value that is not yet durable — and US-1012 buys the property back
/// by starting every restore a whole window above the durable image, so a
/// power cut can only skip forward.
///
/// So the assertion here is **strictly greater**, not "+1": the exact gap is
/// US-1012's slack and is pinned exhaustively (at every point of the window)
/// in `counter_monotonic.rs`. This test keeps the coarse, human-readable
/// version of the same property for the CTAP1 path.
#[test]
fn global_counter_never_repeats_across_a_reboot() {
    let mut trng = HostTrng::new();
    let mut store = Rp2350SecureStore::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();
    let _ = app.persist_if_dirty(&mut store);

    let (reply, _) = u2f_and_persist(&mut app, &mut store, &register_apdu(0x33));
    let kh = key_handle_of(&reply);

    let (auth1, _wrote1) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(0x33, &kh, 0x03));
    assert_eq!(sw(&auth1), U2F_SW_OK);
    let c1 = u32::from_be_bytes([auth1[1], auth1[2], auth1[3], auth1[4]]);

    // Reboot from the durable partition image — what a power cycle sees.
    let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let len = store.partition_image(&mut img).unwrap();
    let mut restored = Rp2350SecureStore::new();
    restored.from_partition_image(&img[..len]);
    let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();

    let (auth2, _) = u2f_and_persist(&mut app2, &mut restored, &authenticate_apdu(0x33, &kh, 0x03));
    assert_eq!(sw(&auth2), U2F_SW_OK, "handle still authenticates after reboot");
    let c2 = u32::from_be_bytes([auth2[1], auth2[2], auth2[3], auth2[4]]);
    assert!(
        c2 > c1,
        "post-reboot counter {c2} must be strictly greater than the {c1} \
         signed before the reboot (RED: c2 == c1 means the same value was \
         signed twice, which is the clone-detection failure US-714 fixed and \
         US-1012 has to preserve under batching)"
    );
}

/// Check-only (P1=0x07) validates a stateless handle without user presence:
/// CONDITIONS_NOT_SATISFIED when the tag verifies, WRONG_DATA when it
/// doesn't (C: `cmd_authenticate` P1=CHECK_ONLY returns the same pair).
#[test]
fn stateless_check_only_and_rejection_are_panic_free() {
    let mut trng = HostTrng::new();
    let mut store = Rp2350SecureStore::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();

    let (reply, _) = u2f_and_persist(&mut app, &mut store, &register_apdu(1));
    let kh = key_handle_of(&reply);

    let (valid, _) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(1, &kh, 0x07));
    assert_eq!(
        sw(&valid),
        U2F_SW_CONDS_NOT_SATISFIED,
        "check-only with a valid stateless handle"
    );

    // Corrupted tag: constant-time mismatch → WRONG_DATA, never a panic.
    let mut bad = kh.clone();
    bad[63] ^= 0x01;
    let (r1, _) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(1, &bad, 0x07));
    assert_eq!(sw(&r1), U2F_SW_WRONG_DATA, "bad tag must be WRONG_DATA");
    let (r2, _) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(1, &bad, 0x03));
    assert_eq!(sw(&r2), U2F_SW_WRONG_DATA, "bad tag must be WRONG_DATA (enforce)");

    // A stateless-shaped handle with an all-zero tag region and a
    // zero-filled 64-byte handle: same contract.
    let mut zero = vec![0u8; KEY_HANDLE_LEN];
    zero[3] = 0x80; // make it stateless-shaped (every path word MSB set)
    let (r3, _) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(1, &zero, 0x03));
    assert_eq!(sw(&r3), U2F_SW_WRONG_DATA);
    let (r4, _) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(1, &zero, 0x07));
    assert_eq!(sw(&r4), U2F_SW_WRONG_DATA);

    // Bound discipline (US-701): short handles never panic.
    for len in [0usize, 32, 63, 65, 255] {
        let mut short = vec![0x80u8; len];
        if len >= 4 {
            for w in short.as_chunks_mut::<4>().0 {
                w[3] = 0x80;
            }
        }
        let (r, _) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(1, &short, 0x03));
        assert!(r.len() >= 2, "len {len}: a status word must always come back");
    }
}

/// A stateless handle authenticates on a **fresh boot** from the same store
/// image — the private key is re-derived from the persisted device master,
/// no store lookup needed (the C-parity core of the story).
#[test]
fn stateless_auth_survives_reboot() {
    let mut trng = HostTrng::new();
    let mut store = Rp2350SecureStore::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();
    // Drain the boot-time dirty snapshot (persist() writes but only
    // persist_if_dirty clears the gate).
    let _ = app.persist_if_dirty(&mut store);

    let (reply, wrote) = u2f_and_persist(&mut app, &mut store, &register_apdu(7));
    assert_eq!(sw(&reply), U2F_SW_OK);
    assert!(!wrote, "register must not write the store");
    let kh = key_handle_of(&reply);

    let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let len = store.partition_image(&mut img).unwrap();
    let mut restored = Rp2350SecureStore::new();
    restored.from_partition_image(&img[..len]);
    let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();
    assert_eq!(app2.keystore().cred_count(), 0, "still no stored credential");

    let (auth, wrote2) = u2f_and_persist(&mut app2, &mut restored, &authenticate_apdu(7, &kh, 0x03));
    assert_eq!(sw(&auth), U2F_SW_OK, "stateless handle must auth after reboot");
    assert!(wrote2, "counter bump persists on the restored store");
}

/// Legacy (pre-US-714) store-backed U2F handles keep authenticating: the
/// store lookup runs first for handles without the stateless shape.
#[test]
fn legacy_store_backed_handle_still_auths() {
    use fapico2_fido::device_keystore::{DeviceCoseKey, DeviceCredential};
    let mut trng = HostTrng::new();
    let mut store = Rp2350SecureStore::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();

    // A legacy U2F credential: random 32-byte id, store-backed.
    let mut id = heapless::Vec::<u8, 64>::new();
    id.extend_from_slice(&[0x5Au8; 32]).unwrap();
    let cred = DeviceCredential {
        credential_id: id,
        public_key: DeviceCoseKey::es256([1; 32], [2; 32]),
        private_key: [0x0B; 32], // valid non-zero P-256 scalar
        rp_id_hash: [0xA0; 32],
        rp_id: heapless::Vec::new(),
        user_handle: heapless::Vec::new(),
        user_name: heapless::Vec::new(),
        user_display_name: heapless::Vec::new(),
        cred_protect: 0,
        large_blob_key: None,
        hmac_secret: heapless::Vec::new(),
        cred_blob: heapless::Vec::new(),
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: false,
        algorithm: -7,
        counter: 0,
        revoked: false,
        expires_at: None,
    };
    app.keystore().store_credential(cred).unwrap();

    let kh32 = [0x5Au8; 32].to_vec();
    let (auth, _) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(9, &kh32, 0x03));
    assert_eq!(sw(&auth), U2F_SW_OK, "legacy handle must keep authenticating");

    // And a stateless handle still resolves on the same app.
    let (reply, _) = u2f_and_persist(&mut app, &mut store, &register_apdu(9));
    let kh = key_handle_of(&reply);
    let (auth2, _) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(9, &kh, 0x03));
    assert_eq!(sw(&auth2), U2F_SW_OK, "stateless and legacy coexist");
}

/// Host twin parity (US-701 lesson): the host U2F path registers statelessly
/// too — no `StoredCredential` lands in the keystore and the handle
/// authenticates.
#[test]
fn host_twin_register_leaves_keystore_empty() {
    use fapico2_fido::attestation::AttestationIdentity;
    use fapico2_fido::keystore::{Keystore, MemoryKeystore};
    use fapico2_fido::process_u2f_apdu;

    let mut ks = MemoryKeystore::new();
    // US-916: the host register path signs with a minted per-device identity.
    let att = AttestationIdentity::generate_host();
    let mut apdu = vec![0x00, 0x01, 0x00, 0x00, 0x40];
    apdu.extend_from_slice(&[0x11u8; 32]); // client param
    apdu.extend_from_slice(&[0xA0u8; 32]); // app param
    let resp = process_u2f_apdu(&apdu, &mut ks, || true, &att)
        .expect("host register must succeed");
    assert_eq!(resp[0], 0x05);
    let kh = key_handle_of(&resp);
    assert_eq!(kh.len(), KEY_HANDLE_LEN);
    assert_eq!(ks.cred_count(), 0, "RED: host register persisted a credential");

    // Authenticate the stateless handle through the host path.
    let mut auth = vec![0x00, 0x02, 0x03, 0x00, (64 + 1 + kh.len()) as u8];
    auth.extend_from_slice(&[0x11u8; 32]);
    auth.extend_from_slice(&[0xA0u8; 32]);
    auth.push(kh.len() as u8);
    auth.extend_from_slice(&kh);
    let resp = process_u2f_apdu(&auth, &mut ks, || true, &att)
        .expect("host stateless auth must succeed");
    assert_eq!(resp[0], 0x01, "user presence byte");
    assert_eq!(ks.cred_count(), 0, "auth must not backfill a credential");
}
