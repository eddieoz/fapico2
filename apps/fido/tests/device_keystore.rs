//! S-701-3 TDD: the no-heap device credential keystore.

use fapico2_fido::device_keystore::{
    DeviceCoseKey, DeviceCredential, DeviceKeystore, PrivateScalar, COUNTER_PERSIST_INTERVAL,
};
use fapico2_fido::keystore;
use fapico2_platform::secure_store::{chunked, HostSecureStore, SecureStore};
use fapico2_platform::store_v3::emulation_store_key;
use fapico2_platform::trng::HostTrng;

/// US-911: the store key the emulation secure partition seals the snapshot's
/// sensitive fields with (the sealed-format marker dispatches the parse).
fn store_key() -> [u8; 32] {
    emulation_store_key()
}

fn sample_cred(id: &[u8]) -> DeviceCredential {
    let mut c = DeviceCredential {
        credential_id: heapless::Vec::new(),
        public_key: DeviceCoseKey::es256([7u8; 32], [9u8; 32]),
        private_key: PrivateScalar::from_bytes([0x42u8; 32]),
        rp_id_hash: [0x33u8; 32],
        rp_id: heapless::Vec::new(),
        user_handle: heapless::Vec::new(),
        user_name: heapless::Vec::new(),
        user_display_name: heapless::Vec::new(),
        cred_protect: 2,
        large_blob_key: Some([0x55u8; 32]),
        hmac_secret: heapless::Vec::new(),
        cred_blob: heapless::Vec::new(),
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: true,
        algorithm: -7,
        counter: 3,
        revoked: false,
        expires_at: None,
    };
    c.credential_id.extend_from_slice(id).unwrap();
    c.rp_id.extend_from_slice(b"example.com").unwrap();
    c.user_handle.extend_from_slice(b"user-handle-01").unwrap();
    c.user_name.extend_from_slice(b"ada").unwrap();
    c.hmac_secret.extend_from_slice(&[0x77u8; 32]).unwrap();
    c
}

/// A device-persisted snapshot parses with the HOST snapshot codec — the
/// CBOR map format is shared, so host and device snapshots interchange.
#[test]
fn snapshot_written_on_device_loads_on_host() {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();

    let mut ks = DeviceKeystore::fresh(&mut trng).expect("host TRNG");
    ks.store_credential(sample_cred(b"cred-1")).unwrap();
    ks.store_credential(sample_cred(b"cred-2")).unwrap();
    ks.pin_state.retries = 5;
    ks.pin_state.pin_hash = Some([0xA5u8; 16]);
    ks.cred_counter = 42;
    ks.persist(&mut store).unwrap();

    // Read the raw snapshot bytes back through the chunked layer.
    let mut bytes = [0u8; chunked::MAX_LOGICAL_LEN];
    let n = chunked::read_chunked(&mut store, b"fido.keystore.v1", &mut bytes).unwrap();

    // Host parse: same credentials, PIN state and counter. US-911: the
    // device-sealed fields open under the same emulation store key.
    if keystore::snapshot::parse(&bytes[..n], Some(&store_key())).is_none() {
        // Diagnose with the no-heap parser.
        let p = fapico2_fido::cbor::no_heap::Parser::new(&bytes[..n]);
        let _ = p;
        panic!("host codec refuses the device snapshot; first bytes: {:02x?}", &bytes[..40.min(n)]);
    }
    let (auth, creds, _max) =
        keystore::snapshot::parse(&bytes[..n], Some(&store_key()))
            .expect("host codec parses the device snapshot");
    assert_eq!(creds.len(), 2);
    assert_eq!(creds[0].credential_id, b"cred-1".to_vec());
    assert_eq!(creds[1].counter, 3);
    assert_eq!(creds[1].rp_id.as_deref(), Some("example.com"));
    assert!(creds[1].resident);
    assert_eq!(creds[1].private_key, vec![0x42u8; 32]);
    assert_eq!(auth.pin_state.retries, 5);
    assert_eq!(auth.pin_state.pin_hash, Some([0xA5u8; 16]));
    assert_eq!(auth.cred_counter, 42);
}

/// And the reverse direction: a HOST-written snapshot loads on the device
/// keystore with identical model state.
#[test]
fn snapshot_written_on_host_loads_on_device() {
    use fapico2_fido::keystore::{AuthState, Keystore, MemoryKeystore, PinState, StoredCredential};

    let mut store = HostSecureStore::new();
    let mut host = MemoryKeystore::new();
    host.store_credential(StoredCredential {
        credential_id: b"host-cred".to_vec(),
        public_key: fapico2_fido::keystore::CosePublicKey::es256([1u8; 32], [2u8; 32]),
        private_key: vec![0x24u8; 32],
        rp_id_hash: [0x10u8; 32],
        rp_id: Some("host.example".to_string()),
        user_handle: b"uh".to_vec(),
        user_name: Some("host user".to_string()),
        user_display_name: None,
        cred_protect: 1,
        large_blob_key: None,
        hmac_secret: None,
        cred_blob: None,
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: true,
        algorithm: -7,
        counter: 9,
        revoked: false,
        expires_at: None,
    })
    .unwrap();
    host.get_pin_state_mut().retries = 3;
    host.get_pin_state_mut().pin_hash = Some([0x0Fu8; 16]);
    let auth_state = AuthState {
        pin_state: PinState {
            retries: 3,
            pin_hash: Some([0x0Fu8; 16]),
            ..PinState::default()
        },
        ..AuthState::default()
    };
    let creds: Vec<StoredCredential> = host.list_credentials().into_iter().cloned().collect();
    let snap = keystore::snapshot::encode(&auth_state, &creds, 256, Some(&store_key()));
    store.write(b"fido.keystore.v1", &snap).unwrap();

    // The device keystore must parse the plain-slot host snapshot.
    let mut bytes = [0u8; 16 * 1024];
    let n = store.read(b"fido.keystore.v1", &mut bytes).unwrap();
    let ks = DeviceKeystore::from_cbor(&bytes[..n], Some(&store_key()))
        .expect("device parses the host snapshot");
    assert_eq!(ks.cred_count(), 1);
    let c = ks.get_credential(b"host-cred").unwrap();
    assert_eq!(c.counter, 9);
    assert_eq!(c.rp_id.as_slice(), b"host.example");
    assert_eq!(c.private_key, PrivateScalar::from_bytes([0x24u8; 32]));
    assert_eq!(ks.pin_state.retries, 3);
    assert_eq!(ks.pin_state.pin_hash, Some([0x0Fu8; 16]));
}

/// BDD (host): Given a credential registered in the device keystore **when**
/// the store image is rebooted **then** the credential and PIN retry counter
/// persisted.
#[test]
fn reboot_preserves_credentials_and_pin_retries() {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut ks = DeviceKeystore::fresh(&mut trng).expect("host TRNG");
    ks.store_credential(sample_cred(b"persist-1")).unwrap();
    ks.pin_state.retries = 6;
    ks.pin_state.pin_hash = Some([0x11u8; 16]);
    ks.persist(&mut store).unwrap();

    // Power down: partition image snapshot, everything dropped.
    let image = store.partition_image();
    drop(store);
    drop(ks);

    // Reboot.
    let mut restored = HostSecureStore::new();
    restored.from_partition_image(&image);
    let ks = DeviceKeystore::load(&mut restored).unwrap().expect("snapshot present");
    assert_eq!(ks.cred_count(), 1);
    assert!(ks.get_credential(b"persist-1").is_some());
    assert_eq!(ks.pin_state.retries, 6, "PIN retry counter persisted");
    assert_eq!(ks.pin_state.pin_hash, Some([0x11u8; 16]));
}

/// A snapshot that exists but does not parse is an error — never silently
/// treated as fresh (FX-440 parity: the corrupt store must not be
/// overwritten by a boot).
#[test]
fn corrupt_snapshot_is_refused() {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let ks = DeviceKeystore::fresh(&mut trng).expect("host TRNG");
    ks.persist(&mut store).unwrap();

    // Overwrite the (single-part) snapshot with garbage payload that is
    // still a well-formed chunked part record.
    let mut bytes = [0u8; 512];
    let n = store.read(b"fido.keystore.v1.p000", &mut bytes).unwrap();
    // Keep the 16-byte part header, corrupt the CBOR payload.
    for b in &mut bytes[16..n] {
        *b = 0xFF;
    }
    store.write(b"fido.keystore.v1.p000", &bytes[..n]).unwrap();

    match DeviceKeystore::load(&mut store) {
        Err(fapico2_platform::secure_store::SecureStoreError::Corrupt) => {}
        other => panic!("corrupt snapshot must be refused, got {other:?}"),
    }
}

/// US-910 (review, device codec): the no-heap PIN-state decoder must refuse
/// a stretched record claiming more verifier iterations than the device
/// ever derives (`PIN_VERIFIER_ROUNDS`) — the verifier runs one SHA-256
/// round per iteration, so a crafted snapshot could wedge the PIN path for
/// hours. Corrupt input is refused, never truncated.
#[test]
fn oversized_pin_iter_record_refused_by_device_codec() {
    use fapico2_fido::cbor::no_heap;

    // Minimal auth map: {1: pin-state map {14: fmt, 15: salt, 16: iter},
    // 2: counter} — exactly the key numbering decode_pairs consumes.
    fn auth_with_iter(iter: u64) -> heapless::Vec<u8, 128> {
        let mut pin: heapless::Vec<u8, 64> = heapless::Vec::new();
        no_heap::push_map_header(&mut pin, 3).unwrap();
        no_heap::push_uint(&mut pin, 14).unwrap();
        no_heap::push_uint(&mut pin, 1).unwrap();
        no_heap::push_uint(&mut pin, 15).unwrap();
        no_heap::push_bstr(&mut pin, &[0x11u8; 16]).unwrap();
        no_heap::push_uint(&mut pin, 16).unwrap();
        no_heap::push_uint(&mut pin, iter).unwrap();

        let mut auth: heapless::Vec<u8, 128> = heapless::Vec::new();
        no_heap::push_map_header(&mut auth, 2).unwrap();
        no_heap::push_uint(&mut auth, 1).unwrap();
        auth.extend_from_slice(&pin).unwrap();
        no_heap::push_uint(&mut auth, 2).unwrap();
        no_heap::push_uint(&mut auth, 0).unwrap();
        auth
    }

    // Top-level snapshot: {1: [max_creds, auth, creds]} (plaintext form).
    fn snapshot_with_iter(iter: u64) -> heapless::Vec<u8, 256> {
        let auth = auth_with_iter(iter);
        let (ub, un) = no_heap::uint_bytes(256);
        let mut creds: heapless::Vec<u8, 8> = heapless::Vec::new();
        no_heap::push_array_header(&mut creds, 0).unwrap();
        let mut out: heapless::Vec<u8, 256> = heapless::Vec::new();
        no_heap::push_map_header(&mut out, 1).unwrap();
        no_heap::push_uint(&mut out, 1).unwrap();
        no_heap::push_array_header(&mut out, 3).unwrap();
        no_heap::push_bstr(&mut out, &ub[..un]).unwrap();
        no_heap::push_bstr(&mut out, &auth).unwrap();
        no_heap::push_bstr(&mut out, &creds).unwrap();
        out
    }

    for iter in [
        u64::from(fapico2_fido::crypto::PIN_VERIFIER_ROUNDS) + 1,
        u64::from(u32::MAX),
    ] {
        assert!(
            DeviceKeystore::from_cbor(&snapshot_with_iter(iter), None).is_none(),
            "device codec must refuse pin_iter {iter}"
        );
    }
    let ks = DeviceKeystore::from_cbor(
        &snapshot_with_iter(u64::from(fapico2_fido::crypto::PIN_VERIFIER_ROUNDS)),
        None,
    )
    .expect("PIN_VERIFIER_ROUNDS itself loads");
    assert_eq!(ks.pin_state.pin_iter, fapico2_fido::crypto::PIN_VERIFIER_ROUNDS);
    assert_eq!(ks.pin_state.pin_salt, Some([0x11; 16]));
}

/// FidoApp::boot restores the keystore with the hkey (US-387 seam extended).
#[cfg(feature = "device")]
#[test]
fn fido_boot_restores_keystore_and_hkey() {
    use fapico2_fido::FidoApp;

    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut app1 = FidoApp::boot(&mut trng, &mut store).unwrap();
    app1.keystore().store_credential(sample_cred(b"boot-cred")).unwrap();
    assert!(app1.persist_if_dirty(&mut store), "dirty keystore persists");
    assert!(!app1.persist_if_dirty(&mut store), "clean keystore is a no-op");
    let hkey1 = app1.hkey().to_bytes();

    let image = store.partition_image();
    drop(store);
    drop(app1);

    let mut restored = HostSecureStore::new();
    restored.from_partition_image(&image);
    let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();
    assert_eq!(app2.hkey().to_bytes().as_slice(), hkey1.as_slice());
    assert_eq!(app2.keystore().cred_count(), 1);
    assert!(app2.keystore().get_credential(b"boot-cred").is_some());
}

// ---------------------------------------------------------------------------
// US-911: the sensitive snapshot fields are AEAD-sealed under the store key.
// ---------------------------------------------------------------------------

/// Return `true` when `needle` occurs anywhere in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// (a) A persisted snapshot carries NO plaintext key bytes for any enrolled
/// credential (private key, hmac-secret, largeBlob key, device_random), and
/// the sealed values still parse back with the store key (metadata and
/// getAssertion-relevant fields intact).
#[test]
fn us911_sealed_snapshot_carries_no_plaintext_secrets() {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut ks = DeviceKeystore::fresh(&mut trng).expect("host TRNG");
    let mut cred = sample_cred(b"cred-1");
    cred.cred_blob.extend_from_slice(b"user-verifyable-blob").unwrap();
    ks.store_credential(cred).unwrap();
    let device_random = ks.device_random;
    ks.persist(&mut store).unwrap();

    // Read the RAW snapshot bytes back through the chunked layer.
    let mut bytes = [0u8; chunked::MAX_LOGICAL_LEN];
    let n = chunked::read_chunked(&mut store, b"fido.keystore.v1", &mut bytes).unwrap();
    let raw = &bytes[..n];

    // None of the sensitive plaintext byte strings may appear.
    assert!(!contains(raw, &[0x42u8; 32]), "plaintext private key leaked");
    assert!(!contains(raw, &[0x77u8; 32]), "plaintext hmac-secret leaked");
    assert!(!contains(raw, &[0x55u8; 32]), "plaintext large_blob_key leaked");
    assert!(!contains(raw, &device_random), "plaintext device_random leaked");
    assert!(!contains(raw, b"user-verifyable-blob"), "plaintext cred_blob leaked");
    // Metadata stays plaintext for enumeration.
    assert!(contains(raw, b"example.com"), "rpId must stay plaintext");
    assert!(contains(raw, b"user-handle-01"), "user id must stay plaintext");

    // The sealed values still parse back: every GA/metadata field intact.
    let (auth, creds, _max) =
        keystore::snapshot::parse(raw, Some(&store_key())).expect("sealed snapshot parses");
    assert_eq!(creds.len(), 1);
    let c = &creds[0];
    assert!(!c.revoked);
    assert_eq!(c.private_key, vec![0x42u8; 32]);
    assert_eq!(c.hmac_secret.as_deref(), Some(&[0x77u8; 32][..]));
    assert_eq!(c.large_blob_key, Some([0x55u8; 32]));
    assert_eq!(c.cred_blob.as_deref(), Some(b"user-verifyable-blob".as_slice()));
    assert_eq!(c.rp_id.as_deref(), Some("example.com"));
    assert_eq!(c.cred_protect, 2);
    assert_eq!(auth.device_random, device_random, "device_random round-trips sealed");
}

/// (b) A snapshot round trip (device persist → reboot → load) preserves
/// signing: the loaded credential produces the identical assertion
/// signature over the same challenge (deterministic ECDSA), so a reboot
/// cannot change what the RP verifies.
#[test]
fn us911_sealed_snapshot_round_trip_preserves_signing() {
    use fapico2_fido::crypto;

    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut ks = DeviceKeystore::fresh(&mut trng).expect("host TRNG");
    let (sk, pk) = crypto::generate_p256_keypair();
    let pk_bytes = crypto::public_key_bytes(&pk);
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&pk_bytes[1..33]);
    y.copy_from_slice(&pk_bytes[33..65]);
    let mut cred = sample_cred(b"sign-cred");
    cred.private_key = PrivateScalar::from_bytes(sk.to_bytes().into());
    cred.public_key = DeviceCoseKey::es256(x, y);
    ks.store_credential(cred).unwrap();
    ks.persist(&mut store).unwrap();

    // Sign before the reboot (what getAssertion would produce).
    let challenge = [0xABu8; 64];
    let sig_before = crypto::p256_sign_bytes(&sk, &challenge);

    // Power down / reboot: the sealed snapshot comes back through the
    // partition image.
    let image = store.partition_image();
    drop(store);
    drop(ks);
    let mut restored = HostSecureStore::new();
    restored.from_partition_image(&image);
    let ks2 = DeviceKeystore::load(&mut restored).unwrap().expect("snapshot present");
    let cred2 = ks2.get_credential(b"sign-cred").expect("credential survives");
    let sk2 = crypto::secret_key_from_bytes(cred2.private_key.expose()).expect("key reloads");
    let sig_after = crypto::p256_sign_bytes(&sk2, &challenge);
    assert_eq!(sig_before, sig_after, "assertion signature must survive the sealed round trip");
    // Metadata intact for enumeration.
    assert_eq!(cred2.rp_id.as_slice(), b"example.com");
    // US-1012: `load` is the RESTORE path, and a restore starts a whole
    // counter window above the durable image — that is what stops a batched
    // counter from repeating a value after a power cut. A credential stored
    // at 3 therefore comes back at 3 + COUNTER_PERSIST_INTERVAL. The decoder
    // (`from_cbor`) is the one that reports the stored bytes unchanged.
    assert_eq!(cred2.counter, 3 + COUNTER_PERSIST_INTERVAL as u32);
    assert!(!cred2.revoked);
}

/// (c) A credential whose ciphertext fails to open is REVOKED (dead), not
/// zeroed: the plaintext metadata survives for enumeration, the secret
/// fields are unusable, and the other credential is untouched.
#[test]
fn us911_corrupt_ciphertext_field_revokes_entry_keeps_metadata() {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut ks = DeviceKeystore::fresh(&mut trng).expect("host TRNG");
    let mut c1 = sample_cred(b"cred-1");
    c1.private_key = PrivateScalar::from_bytes([0x42u8; 32]);
    let mut c2 = sample_cred(b"cred-2");
    c2.private_key = PrivateScalar::from_bytes([0x43u8; 32]);
    ks.store_credential(c1).unwrap();
    ks.store_credential(c2).unwrap();
    ks.persist(&mut store).unwrap();

    let mut bytes = [0u8; chunked::MAX_LOGICAL_LEN];
    let n = chunked::read_chunked(&mut store, b"fido.keystore.v1", &mut bytes).unwrap();
    // Corrupt ONE byte inside cred-1's sealed private-key ciphertext: the
    // bstr header `[0x03, 0x58, 0x3C]` (key 3, bstr of 32 + 28 bytes)
    // locates the first credential's field.
    let needle = [0x03u8, 0x58, 0x3C];
    let pos = bytes[..n]
        .windows(3)
        .position(|w| w == needle)
        .expect("sealed private-key field located");
    bytes[pos + 3] ^= 0x01;

    // The snapshot still parses (the device_random master opened fine) and
    // the entry is dead, not zeroed.
    let ks2 = DeviceKeystore::from_cbor(&bytes[..n], Some(&store_key()))
        .expect("snapshot parses with a killed credential");
    let dead = ks2.get_credential(b"cred-1").unwrap();
    assert!(dead.revoked, "the failing credential is marked dead");
    assert_eq!(dead.credential_id.as_slice(), b"cred-1", "metadata kept");
    assert_eq!(dead.rp_id.as_slice(), b"example.com", "metadata kept");
    assert_eq!(dead.cred_protect, 2, "metadata kept");
    assert_eq!(dead.user_name.as_slice(), b"ada", "metadata kept");
    assert!(
        dead.private_key.is_zero(),
        "the secret is unusable — US-1550: a revoked credential's scalar must be wiped, not just \
         left unused"
    );
    assert!(dead.hmac_secret.is_empty());
    assert!(dead.large_blob_key.is_none());
    // The untouched credential is fully alive.
    let alive = ks2.get_credential(b"cred-2").unwrap();
    assert!(!alive.revoked);
    assert_eq!(alive.private_key, PrivateScalar::from_bytes([0x43u8; 32]));
    // Enumeration (host codec) still lists both metadata records.
    let (_auth, creds, _max) =
        keystore::snapshot::parse(&bytes[..n], Some(&store_key())).expect("host parse");
    assert_eq!(creds.len(), 2);
    assert!(creds[0].revoked);
    assert!(!creds[1].revoked);
}

/// (d) A snapshot sealed under a DIFFERENT store key fails closed: the
/// whole snapshot is refused (Corrupt — the auth-level fields cannot open),
/// never partially decrypted garbage.
#[test]
fn us911_wrong_store_key_refuses_whole_snapshot() {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut ks = DeviceKeystore::fresh(&mut trng).expect("host TRNG");
    ks.store_credential(sample_cred(b"cred-1")).unwrap();
    ks.persist(&mut store).unwrap();

    let mut bytes = [0u8; chunked::MAX_LOGICAL_LEN];
    let n = chunked::read_chunked(&mut store, b"fido.keystore.v1", &mut bytes).unwrap();

    let wrong_key = [0xEEu8; 32];
    assert!(
        DeviceKeystore::from_cbor(&bytes[..n], Some(&wrong_key)).is_none(),
        "wrong store key must fail the whole snapshot"
    );
    assert!(
        keystore::snapshot::parse(&bytes[..n], Some(&wrong_key)).is_none(),
        "host parse must refuse under the wrong store key"
    );
    // The right key still opens it.
    assert!(DeviceKeystore::from_cbor(&bytes[..n], Some(&store_key())).is_some());
}

/// The host FILE keystore is sealed too: its on-disk snapshot carries no
/// plaintext credential keys (the file stands in for the secure partition).
#[test]
fn us911_file_keystore_snapshot_is_sealed() {
    use fapico2_fido::keystore::{CosePublicKey, FileKeystore, Keystore, StoredCredential};

    let path = std::env::temp_dir().join(format!(
        "fapico2_test_us911_sealed_{}.cbor",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    {
        let mut ks = FileKeystore::load_or_create(path.clone()).unwrap();
        ks.store_credential(StoredCredential {
            credential_id: b"sealed-cred".to_vec(),
            public_key: CosePublicKey::es256([1u8; 32], [2u8; 32]),
            private_key: vec![0x42u8; 32],
            rp_id_hash: [3u8; 32],
            rp_id: Some("example.com".to_string()),
            user_handle: b"uh".to_vec(),
            user_name: None,
            user_display_name: None,
            cred_protect: 0,
            large_blob_key: Some([0x55u8; 32]),
            hmac_secret: Some(vec![0x77u8; 32]),
            cred_blob: None,
            third_party_payment: false,
            pin_complexity_policy: false,
            resident: true,
            algorithm: -7,
            counter: 0,
            revoked: false,
            expires_at: None,
        })
        .unwrap();
    }
    let raw = std::fs::read(&path).unwrap();
    assert!(!contains(&raw, &[0x42u8; 32]), "plaintext private key in the host file");
    assert!(!contains(&raw, &[0x55u8; 32]), "plaintext large_blob_key in the host file");
    assert!(!contains(&raw, &[0x77u8; 32]), "plaintext hmac-secret in the host file");
    assert!(contains(&raw, b"example.com"), "rpId stays plaintext");

    // The file reloads with every value intact.
    let ks = FileKeystore::load_or_create(path.clone()).unwrap();
    let cred = ks.get_credential(b"sealed-cred").unwrap();
    assert_eq!(cred.private_key, vec![0x42u8; 32]);
    assert_eq!(cred.large_blob_key, Some([0x55u8; 32]));
    assert_eq!(cred.hmac_secret.as_deref(), Some(&[0x77u8; 32][..]));
    let _ = std::fs::remove_file(&path);
}
