//! US-910: salted, stretched FIDO PIN verifier.
//!
//! The stored snapshot must never contain the bare `SHA256(PIN)[..16]`
//! (unsalted, unstretched — one offline table breaks every device). The
//! verifier is `SHA256` iterated over a per-device TRNG salt with domain
//! separation, stored `[salt, iter, verifier]` next to the format flag.
//! Legacy (unsalted) records migrate to the stretched format on the next
//! *successful* PIN verification; a wrong PIN never migrates and keeps
//! burning the durable retry budget.

mod common;

use common::*;
use fapico2_fido::app::FidoApp;
use fapico2_fido::cbor::{self, Value};
use fapico2_fido::crypto;
use fapico2_fido::keystore::{FileKeystore, Keystore};

const PIN_INVALID: u8 = 0x31;

fn temp_path(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("us910-{}-{}.fido", std::process::id(), tag));
    let _ = std::fs::remove_file(&p);
    p
}

/// True if any 16-byte window of `bytes` equals `needle`.
fn contains_window(bytes: &[u8], needle: &[u8]) -> bool {
    if needle.len() > bytes.len() {
        return false;
    }
    bytes.windows(needle.len()).any(|w| w == needle)
}

fn wrong_pin_attempt<K: Keystore>(app: &mut FidoApp<K>, client: &PinClient) -> u8 {
    let wrong = crypto::pin_hash(b"0000");
    let pin_hash_enc = crypto::pin_encrypt(2, &client.enc_key, &wrong);
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(2)),
        (Value::U(0x02), Value::U(0x05)),
        (Value::U(0x03), client.client_cose()),
        (Value::U(0x06), Value::B(pin_hash_enc)),
    ]));
    app.process_ctap2(0x06, &req, [1, 2, 3, 4])[0]
}

/// Seed a legacy (pre-US-910) unsalted record into the keystore snapshot.
fn seed_legacy(path: &std::path::Path) {
    let mut ks = FileKeystore::load_or_create(path.to_path_buf()).unwrap();
    ks.get_pin_state_mut().pin_hash = Some(crypto::pin_hash(PIN.as_bytes()));
    ks.save_pin_state().unwrap();
}

#[test]
fn set_pin_emits_salted_stretched_verifier() {
    let path = temp_path("emit");
    let mut app = FidoApp::with_keystore(FileKeystore::load_or_create(path.clone()).unwrap());
    let client = PinClient::new(&mut app);
    client.set_pin(&mut app);

    // The stored snapshot must not contain SHA256(PIN)[..16] for any PIN
    // the test tried (RED requirement from the brief).
    let bytes = std::fs::read(&path).expect("snapshot file readable");
    for pin in [PIN.as_bytes(), b"0000", b"12345678"] {
        assert!(
            !contains_window(&bytes, &crypto::pin_hash(pin)),
            "snapshot contains the unstretched SHA256(PIN)[..16]"
        );
    }

    // New-format fields present: format flag, TRNG salt, iteration count.
    drop(app);
    let ks = FileKeystore::load_or_create(path.clone()).unwrap();
    let state = ks.get_pin_state();
    assert_eq!(state.pin_verifier_format, 1, "stretched format flag");
    let salt = state.pin_salt.expect("salt stored");
    assert_eq!(salt.len(), 16);
    assert_eq!(state.pin_iter, crypto::PIN_VERIFIER_ROUNDS);

    // And the stored verifier is exactly the stretched derivation.
    let stored = state.pin_hash.expect("verifier present");
    let pin_hash = crypto::pin_hash(PIN.as_bytes());
    assert_eq!(
        stored,
        crypto::pin_verifier_stretched(&pin_hash, &salt, crypto::PIN_VERIFIER_ROUNDS),
        "stored verifier = stretch(salt, SHA256(PIN)[..16])"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn verification_survives_reboot() {
    let path = temp_path("reboot");
    let mut app = FidoApp::with_keystore(FileKeystore::load_or_create(path.clone()).unwrap());
    let client = PinClient::new(&mut app);
    client.set_pin(&mut app);

    // Emulator restart: reload from the persisted snapshot.
    drop(app);
    let mut app = FidoApp::with_keystore(FileKeystore::load_or_create(path.clone()).unwrap());
    let client = PinClient::new(&mut app);

    // Correct PIN still verifies across the reboot.
    assert!(client.get_token(&mut app, 0x05, None, None).is_ok());
    // Wrong PIN still fails.
    assert_eq!(wrong_pin_attempt(&mut app, &client), PIN_INVALID);

    let _ = std::fs::remove_file(&path);
}

/// US-910 (review): a snapshot claiming more verifier iterations than the
/// device ever derives (`PIN_VERIFIER_ROUNDS`) would wedge the PIN path —
/// the verifier runs one SHA-256 round per iteration, so 2^32-1 rounds is
/// hours of compute. Corrupt input is refused, never truncated.
#[test]
fn oversized_pin_iter_snapshot_is_refused() {
    use fapico2_fido::keystore::PinState;

    let stretched = |iter: u64| {
        Value::M(vec![
            (Value::U(14), Value::U(1)),
            (Value::U(15), Value::B(vec![0x11; 16])),
            (Value::U(16), Value::U(iter)),
        ])
    };
    for iter in [
        u64::from(crypto::PIN_VERIFIER_ROUNDS) + 1,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
    ] {
        assert!(
            PinState::from_cbor_for_test(&stretched(iter)).is_none(),
            "pin_iter {iter} must be refused at load"
        );
    }
    // The exact derived count is still the legitimate value.
    let state = PinState::from_cbor_for_test(&stretched(u64::from(crypto::PIN_VERIFIER_ROUNDS)))
        .expect("PIN_VERIFIER_ROUNDS itself loads");
    assert_eq!(state.pin_iter, crypto::PIN_VERIFIER_ROUNDS);
    assert_eq!(state.pin_salt, Some([0x11; 16]));
}

#[test]
fn legacy_migrates_on_success_never_on_failure() {
    let path = temp_path("migrate");
    seed_legacy(&path);
    let mut app = FidoApp::with_keystore(FileKeystore::load_or_create(path.clone()).unwrap());
    let client = PinClient::new(&mut app);

    // Wrong PIN against the legacy record: fails, does NOT migrate, and
    // burns the durable retry budget (no free tries during migration).
    assert_eq!(wrong_pin_attempt(&mut app, &client), PIN_INVALID);
    {
        let bytes = std::fs::read(&path).unwrap();
        let legacy = crypto::pin_hash(PIN.as_bytes());
        assert!(
            contains_window(&bytes, &legacy),
            "wrong PIN must not migrate the legacy record"
        );
    }
    let retries_after_wrong = {
        let ks = FileKeystore::load_or_create(path.clone()).unwrap();
        ks.get_pin_state().retries
    };
    assert!(retries_after_wrong < 8, "wrong PIN burns a retry");

    // Correct PIN: succeeds and migrates in place.
    assert!(client.get_token(&mut app, 0x05, None, None).is_ok());
    let state = {
        let ks = FileKeystore::load_or_create(path.clone()).unwrap();
        ks.get_pin_state().clone()
    };
    assert_eq!(state.pin_verifier_format, 1, "migrated on success");
    let salt = state.pin_salt.expect("salt stored by migration");
    assert_eq!(state.pin_iter, crypto::PIN_VERIFIER_ROUNDS);

    // The migrated snapshot no longer contains the bare hash.
    let bytes = std::fs::read(&path).unwrap();
    let legacy = crypto::pin_hash(PIN.as_bytes());
    assert!(
        !contains_window(&bytes, &legacy),
        "migrated snapshot must not contain the unstretched hash"
    );
    // And the verifier really is the stretched form of the same PIN.
    let pin_hash = crypto::pin_hash(PIN.as_bytes());
    assert_eq!(
        state.pin_hash.unwrap(),
        crypto::pin_verifier_stretched(&pin_hash, &salt, crypto::PIN_VERIFIER_ROUNDS)
    );

    // The migrated record still verifies (stretched path) across reload.
    drop(app);
    let mut app = FidoApp::with_keystore(FileKeystore::load_or_create(path.clone()).unwrap());
    let client = PinClient::new(&mut app);
    assert!(client.get_token(&mut app, 0x05, None, None).is_ok());
    assert_eq!(wrong_pin_attempt(&mut app, &client), PIN_INVALID);

    let _ = std::fs::remove_file(&path);
}
