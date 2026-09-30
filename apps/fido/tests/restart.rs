//! Restart / persistence acceptance tests for US-322 (FX-410).

use fapico2_fido::keystore::{
    FileKeystore, Keystore, StoredCredential, CosePublicKey,
};

fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("fapico2_restart_{}_{}.cbor", name, std::process::id()))
}

fn sample_credential() -> StoredCredential {
    StoredCredential {
        credential_id: b"restart_cred".to_vec(),
        public_key: CosePublicKey::es256([1u8; 32], [2u8; 32]),
        private_key: vec![0u8; 32],
        rp_id_hash: fapico2_fido::crypto::sha256(b"example.com"),
        rp_id: Some("example.com".to_string()),
        user_handle: b"user_id".to_vec(),
        user_name: Some("A. User".to_string()),
        user_display_name: None,
        cred_protect: 1,
        large_blob_key: Some([0x5A; 32]),
        hmac_secret: Some(b"hmac-secret-state-bytes......".to_vec()),
        cred_blob: Some(b"cred-blob-payload".to_vec()),
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: true,
        algorithm: -7,
        counter: 7,
        revoked: false,
        expires_at: None,
    }
}

#[test]
fn test_credential_and_config_survive_reopen() {
    let path = temp_path("full");
    let _ = std::fs::remove_file(&path);

    {
        let mut ks = FileKeystore::load_or_create(path.clone()).unwrap();
        ks.store_credential(sample_credential()).unwrap();
        {
            let pin = ks.get_pin_state_mut();
            // SHA-256("12345678")[:16] — the shape a real PIN would store.
            pin.pin_hash = Some(fapico2_fido::crypto::sha256(b"12345678")[..16]
                .try_into()
                .unwrap());
            pin.retries = 5;
            pin.min_pin_length = 6;
            pin.min_pin_rp_ids = vec!["example.com".to_string()];
            pin.always_uv = true;
            pin.enterprise_attestation = true;
            pin.enterprise_rp_ids = vec!["example.com".to_string()];
            pin.pin_complexity_policy = true;
        }
        let _ = ks.save_pin_state();
    }
    // Keystore dropped here — simulating a process restart.

    let ks = FileKeystore::load_or_create(path.clone()).unwrap();

    // Credential present with its state intact.
    let cred = ks
        .get_credential(b"restart_cred")
        .expect("credential must survive restart");
    assert_eq!(cred.counter, 7);
    assert_eq!(cred.cred_protect, 1);
    assert_eq!(cred.hmac_secret, Some(b"hmac-secret-state-bytes......".to_vec()));

    // PIN state identical.
    let pin = ks.get_pin_state();
    assert_eq!(
        pin.pin_hash,
        Some(fapico2_fido::crypto::sha256(b"12345678")[..16].try_into().unwrap())
    );
    assert_eq!(pin.retries, 5, "retry counter must be unchanged");
    assert_eq!(pin.min_pin_length, 6);
    assert_eq!(pin.min_pin_rp_ids, vec!["example.com".to_string()]);
    assert!(pin.always_uv, "alwaysUv flag must survive restart");
    assert!(
        pin.enterprise_attestation,
        "enterprise attestation flag must survive restart"
    );
    assert_eq!(pin.enterprise_rp_ids, vec!["example.com".to_string()]);
    assert!(pin.pin_complexity_policy);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_keystore_file_is_never_left_as_partial_tmp() {
    // After persist, no stale .tmp sidecar may remain (atomic rename).
    let path = temp_path("tmpclean");
    let _ = std::fs::remove_file(&path);
    let tmp = path.with_extension("tmp");

    let mut ks = FileKeystore::load_or_create(path.clone()).unwrap();
    ks.store_credential(sample_credential()).unwrap();

    assert!(!tmp.exists(), "atomic persist must clean up the .tmp file");
    assert!(path.exists());
    let _ = std::fs::remove_file(&path);
}
