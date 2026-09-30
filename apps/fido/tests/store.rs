//! Tests for fapico2-fido keystore.

#[test]
fn test_store_and_reload_credential() {
    use fapico2_fido::keystore::{Keystore, MemoryKeystore, StoredCredential, CosePublicKey};

    let mut ks = MemoryKeystore::new();
    let cred = StoredCredential {
        credential_id: b"test_cred".to_vec(),
        public_key: CosePublicKey::es256([1u8; 32], [2u8; 32]),
        private_key: vec![0u8; 32],
        rp_id_hash: [3u8; 32],
        rp_id: None,
        user_handle: b"user".to_vec(),
        user_name: Some("Alice".to_string()),
        user_display_name: Some("Alice Display".to_string()),
        cred_protect: 0,
        large_blob_key: None,
        hmac_secret: None,
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: true,
        algorithm: -7,
        counter: 0,
        revoked: false,
        expires_at: None,
        cred_blob: None,
    };

    ks.store_credential(cred.clone()).unwrap();
    assert_eq!(ks.cred_count(), 1);

    let loaded = ks.get_credential(b"test_cred").unwrap();
    assert_eq!(loaded.cred_protect, 0);
    assert!(loaded.resident);
    assert_eq!(loaded.algorithm, -7);
    assert_eq!(loaded.counter, 0);
}

#[test]
fn test_delete_credential() {
    use fapico2_fido::keystore::{Keystore, MemoryKeystore, StoredCredential, CosePublicKey};

    let mut ks = MemoryKeystore::new();
    let cred = StoredCredential {
        credential_id: b"test_cred".to_vec(),
        public_key: CosePublicKey::es256([1u8; 32], [2u8; 32]),
        private_key: vec![0u8; 32],
        rp_id_hash: [3u8; 32],
        rp_id: None,
        user_handle: b"user".to_vec(),
        user_name: None,
        user_display_name: None,
        cred_protect: 0,
        large_blob_key: None,
        hmac_secret: None,
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: true,
        algorithm: -7,
        counter: 0,
        revoked: false,
        expires_at: None,
        cred_blob: None,
    };

    ks.store_credential(cred).unwrap();
    assert_eq!(ks.cred_count(), 1);
    ks.delete_credential(b"test_cred").unwrap();
    assert_eq!(ks.cred_count(), 0);
}

#[test]
fn test_list_credentials_by_rp() {
    use fapico2_fido::keystore::{Keystore, MemoryKeystore, StoredCredential, CosePublicKey};

    let mut ks = MemoryKeystore::new();
    let rp1 = [1u8; 32];
    let rp2 = [2u8; 32];

    ks.store_credential(StoredCredential {
        credential_id: b"cred1".to_vec(),
        public_key: CosePublicKey::es256([1u8; 32], [2u8; 32]),
        private_key: vec![0u8; 32],
        rp_id_hash: rp1,
        rp_id: None,
        user_handle: b"u1".to_vec(),
        user_name: None,
        user_display_name: None,
        cred_protect: 0,
        large_blob_key: None,
        hmac_secret: None,
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: true,
        algorithm: -7,
        counter: 0,
        revoked: false,
        expires_at: None,
        cred_blob: None,
    }).unwrap();

    ks.store_credential(StoredCredential {
        credential_id: b"cred2".to_vec(),
        public_key: CosePublicKey::es256([3u8; 32], [4u8; 32]),
        private_key: vec![0u8; 32],
        rp_id_hash: rp2,
        rp_id: None,
        user_handle: b"u2".to_vec(),
        user_name: None,
        user_display_name: None,
        cred_protect: 0,
        large_blob_key: None,
        hmac_secret: None,
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: true,
        algorithm: -7,
        counter: 0,
        revoked: false,
        expires_at: None,
        cred_blob: None,
    }).unwrap();

    assert_eq!(ks.list_credentials_by_rp(&rp1).len(), 1);
    assert_eq!(ks.list_credentials_by_rp(&rp2).len(), 1);
    assert_eq!(ks.list_credentials_by_rp(&[0u8; 32]).len(), 0);
}

#[test]
fn getinfo_response_size() {
    let info = fapico2_fido::ctap2::Ctap2Info::default();
    let cbor_value = info.to_cbor();
    let data = fapico2_fido::cbor::encode(&cbor_value);
    eprintln!("getInfo response size: {} bytes, max_msg_size: {}", data.len(), info.max_msg_size);
    assert!(data.len() <= info.max_msg_size, "getInfo response {} exceeds max_msg_size {}", data.len(), info.max_msg_size);
}

#[test]
fn test_snapshot_round_trip_all_fields() {
    use fapico2_fido::keystore::{FileKeystore, Keystore, StoredCredential, CosePublicKey};

    let path = std::env::temp_dir().join(format!(
        "fapico2_test_snapshot_{}.cbor",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    let large_blob_key: Option<[u8; 32]> = Some([0xAA; 32]);
    let hmac_secret = Some(b"hmac-secret-bytes-here--------".to_vec());
    let cred_blob = Some(b"the-credential-blob".to_vec());
    let large_blob_array = Some(vec![1u8, 2, 3, 4, 5]);
    let vault_state = Some(vec![9u8; 40]);

    {
        let mut ks = FileKeystore::load_or_create(path.clone()).unwrap();
        ks.store_credential(StoredCredential {
            credential_id: b"rt_cred".to_vec(),
            public_key: CosePublicKey::es256([1u8; 32], [2u8; 32]),
            private_key: vec![0u8; 32],
            rp_id_hash: [3u8; 32],
            rp_id: Some("example.com".to_string()),
            user_handle: b"user".to_vec(),
            user_name: Some("Alice".to_string()),
            user_display_name: None,
            cred_protect: 2,
            large_blob_key,
            hmac_secret: hmac_secret.clone(),
            cred_blob: cred_blob.clone(),
            third_party_payment: true,
            pin_complexity_policy: false,
            resident: true,
            algorithm: -7,
            counter: 42,
            revoked: false,
            expires_at: None,
        })
        .unwrap();
        let auth = ks.get_auth_state_mut();
        auth.large_blob_array = large_blob_array.clone();
        auth.vault_state = vault_state.clone();
        ks.save_auth_state().unwrap();
    }

    let ks = FileKeystore::load_or_create(path.clone()).unwrap();
    let cred = ks.get_credential(b"rt_cred").expect("credential survives restart");
    assert_eq!(cred.large_blob_key, large_blob_key, "large_blob_key must round-trip");
    assert_eq!(cred.hmac_secret, hmac_secret, "hmac_secret must round-trip");
    assert_eq!(cred.cred_blob, cred_blob, "cred_blob must round-trip");
    assert_eq!(cred.cred_protect, 2);
    assert_eq!(cred.counter, 42);
    assert!(cred.third_party_payment);

    let auth = ks.get_auth_state();
    assert_eq!(auth.large_blob_array, large_blob_array, "large_blob_array must round-trip");
    assert_eq!(auth.vault_state, vault_state, "vault_state must round-trip");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_corrupt_keystore_is_refused_not_reset() {
    use fapico2_fido::keystore::{FileKeystore, Keystore, StoredCredential, CosePublicKey};

    let path = std::env::temp_dir().join(format!(
        "fapico2_test_corrupt_{}.cbor",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    {
        let mut ks = FileKeystore::load_or_create(path.clone()).unwrap();
        ks.store_credential(StoredCredential {
            credential_id: b"cc".to_vec(),
            public_key: CosePublicKey::es256([1u8; 32], [2u8; 32]),
            private_key: vec![0u8; 32],
            rp_id_hash: [3u8; 32],
            rp_id: None,
            user_handle: b"u".to_vec(),
            user_name: None,
            user_display_name: None,
            cred_protect: 0,
            large_blob_key: None,
            hmac_secret: None,
            cred_blob: None,
            third_party_payment: false,
            pin_complexity_policy: false,
            resident: false,
            algorithm: -7,
            counter: 0,
            revoked: false,
            expires_at: None,
        })
        .unwrap();
    }

    // Corrupt the file (truncate mid-way).
    let bytes = std::fs::read(&path).unwrap();
    let truncated = &bytes[..bytes.len() / 2];
    std::fs::write(&path, truncated).unwrap();

    // Loading must fail, not silently reset.
    assert!(
        FileKeystore::load_or_create(path.clone()).is_err(),
        "corrupt snapshot must be refused"
    );
    // The corrupt file must be untouched.
    assert_eq!(std::fs::read(&path).unwrap(), truncated);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_pin_state_malformed_hash_is_parse_error() {
    use fapico2_fido::cbor::Value;
    use fapico2_fido::keystore::PinState;

    // Build a PinState CBOR with a pin hash of the wrong length (15 bytes).
    let bad = Value::M(vec![(Value::U(11), Value::B(vec![0xABu8; 15]))]);
    assert!(
        PinState::from_cbor_for_test(&bad).is_none(),
        "malformed pin hash must be a parse error, not \"no PIN set\""
    );
    // A well-formed 16-byte hash still parses.
    let good = Value::M(vec![(Value::U(11), Value::B(vec![0xABu8; 16]))]);
    let ps = PinState::from_cbor_for_test(&good).expect("well-formed hash parses");
    assert_eq!(ps.pin_hash.unwrap(), [0xABu8; 16]);
}
