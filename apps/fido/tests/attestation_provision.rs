//! US-916: per-device attestation identity provisioning.
//!
//! The repo-committed attestation statics (`attestation_key.bin` +
//! `attestation_cert.der`, `include_bytes!`-ed) are gone: the identity is
//! minted on the device from the platform TRNG at first boot, self-signed
//! on the device, and persisted through the platform secure store (v3-AEAD
//! sealed). These tests pin the provisioning contract on the device app
//! (`FidoApp::boot`, which compiles on host against `HostTrng` +
//! `Rp2350SecureStore`):
//!
//! * two fresh stores produce two DIFFERENT attestation keys AND certs;
//! * the boot-persisted identity survives a partition-image restart and
//!   still signs a registration correctly — the registration signature
//!   verifies against the persisted cert's public key;
//! * a corrupt stored entry fails the boot CLOSED (`Corrupt`) instead of
//!   silently regenerating — only `NotFound` triggers provisioning.

use fapico2_fido::FidoApp;
use fapico2_fido::attestation::{ATTEST_CERT_SLOT, ATTEST_KEY_SLOT};
use fapico2_platform::secure_store::SecureStore;
use fapico2_platform::secure_store::chunked;
use fapico2_platform::secure_store::rp2350::Rp2350SecureStore;
use fapico2_platform::trng::HostTrng;

const CTAP2_MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;

/// Fresh store + one boot → provisioned identity (NotFound ⇒ provision).
fn provisioned_app(trng: &mut HostTrng) -> (Rp2350SecureStore, FidoApp) {
    let mut store = Rp2350SecureStore::new();
    let app = FidoApp::boot(trng, &mut store).unwrap();
    (store, app)
}

/// Restart through a partition image (US-915 sealed snapshot): the same
/// store's sealed image restored into a fresh store object.
fn restart_store(store: &Rp2350SecureStore) -> Rp2350SecureStore {
    let mut img = [0u8; Rp2350SecureStore::SEALED_PARTITION_IMAGE_MAX];
    let len = store.partition_image(&mut img).unwrap();
    let mut restored = Rp2350SecureStore::new();
    restored.from_partition_image(&img[..len]);
    restored
}

/// HEADLINE (US-916): two fresh stores → two different attestation keys AND
/// certs. No device ever ships another device's identity.
#[test]
fn two_fresh_stores_produce_distinct_identities() {
    let mut trng = HostTrng::new();
    let (_s1, app1) = provisioned_app(&mut trng);
    let (_s2, app2) = provisioned_app(&mut trng);

    let k1 = app1.attestation().key().to_bytes();
    let k2 = app2.attestation().key().to_bytes();
    assert_ne!(k1.as_slice(), k2.as_slice(), "keys must be per-device");

    let c1 = app1.attestation().cert_bytes();
    let c2 = app2.attestation().cert_bytes();
    // DER SEQUENCEs, bounded, and distinct (unique TRNG serial + key).
    assert_eq!(c1[0], 0x30);
    assert_eq!(c2[0], 0x30);
    assert!(c1.len() < fapico2_fido::attestation::ATTEST_CERT_MAX);
    assert_ne!(c1, c2, "certs must be per-device (serial + key)");
}

/// US-916 headline: the boot-persisted identity survives a restart (reload
/// from the store) and still signs a registration correctly — the U2F
/// registration signature verifies against the persisted cert's public key.
#[test]
fn boot_persisted_identity_survives_restart_and_still_signs() {
    let mut trng = HostTrng::new();
    let (store, app1) = provisioned_app(&mut trng);

    let key1 = app1.attestation().key().to_bytes();
    let cert1 = app1.attestation().cert_bytes().to_vec();

    let mut restored = restart_store(&store);
    let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();
    assert_eq!(
        app2.attestation().key().to_bytes().as_slice(),
        key1.as_slice(),
        "the provisioned key must be reloaded, not regenerated"
    );
    assert_eq!(app2.attestation().cert_bytes(), cert1.as_slice());

    // Drive one U2F REGISTER through the device path (the cert-carrying
    // reply) and verify the signature against the persisted cert's key.
    let client = [0x11u8; 32];
    let app_param = [0xA0u8; 32];
    let mut apdu = vec![0x00, 0x01, 0x00, 0x00, 0x40];
    apdu.extend_from_slice(&client);
    apdu.extend_from_slice(&app_param);
    let mut out = heapless::Vec::<u8, CTAP2_MAX_MSG>::new();
    let n = app2.process_u2f_with_store(&apdu, &mut out, Some(&mut restored));
    let reply = &out.as_slice()[..n];

    // Reply: 0x05 ‖ pub(65) ‖ kh_len(1) ‖ kh ‖ cert ‖ sig(DER).
    assert_eq!(reply[0], 0x05);
    let kh_len = reply[66] as usize;
    let cert_start = 67 + kh_len;
    let cert_len = app2.attestation().cert_bytes().len();
    assert_eq!(
        &reply[cert_start..cert_start + cert_len],
        cert1.as_slice(),
        "the reply must carry the persisted (not regenerated) cert"
    );
    let pub_key = &reply[1..66];
    // The device reply ends with a 2-byte SW (the reply's last two bytes
    // are the status word, per the U2F APDU convention).
    let sig = &reply[cert_start + cert_len..reply.len() - 2];

    // Extract the ATTESTATION public key from the persisted cert's SPKI
    // (the credential's own key is what got signed over, but the
    // registration signature itself is the ATTESTATION key's).
    let att_pub = cert_spki_point(cert1.as_slice());
    assert_eq!(att_pub.len(), 65);

    // Verify: 0x00 ‖ app_param ‖ client_param ‖ kh ‖ pub over ES256.
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    let vk = VerifyingKey::from(
        &p256::PublicKey::from_sec1_bytes(&att_pub).expect("valid SEC1 point"),
    );
    let mut sign_base = Vec::with_capacity(1 + 32 + 32 + kh_len + 65);
    sign_base.push(0x00);
    sign_base.extend_from_slice(&app_param);
    sign_base.extend_from_slice(&client);
    sign_base.extend_from_slice(&reply[67..cert_start]);
    sign_base.extend_from_slice(pub_key);
    let sig = Signature::from_der(sig).expect("DER signature");
    vk.verify(&sign_base, &sig)
        .expect("registration signature verifies against the persisted cert key");
}

/// Minimal DER walk of a self-signed cert: Certificate → tbsCertificate →
/// the 7th element (subjectPublicKeyInfo) → BIT STRING → the uncompressed
/// 65-byte SEC1 point (used by the restart test to verify the registration
/// signature against the cert's own key).
fn cert_spki_point(cert: &[u8]) -> Vec<u8> {
    fn elem(data: &[u8], pos: &mut usize) -> (u8, Vec<u8>) {
        let tag = data[*pos];
        *pos += 1;
        let mut len = data[*pos] as usize;
        *pos += 1;
        if len & 0x80 != 0 {
            let n = len & 0x7F;
            len = 0;
            for _ in 0..n {
                len = (len << 8) | data[*pos] as usize;
                *pos += 1;
            }
        }
        let content = data[*pos..*pos + len].to_vec();
        *pos += len;
        (tag, content)
    }

    // Certificate SEQUENCE.
    let mut pos = 0;
    let (0x30, cert_content) = elem(cert, &mut pos) else {
        panic!("cert must be a SEQUENCE");
    };
    // tbsCertificate = first element of the certificate content.
    let mut cpos = 0;
    let (0x30, tbs) = elem(&cert_content, &mut cpos) else {
        panic!("tbsCertificate must be a SEQUENCE");
    };
    // Walk the TBS elements: [0] version, INTEGER serial, SEQ alg,
    // SEQ issuer, SEQ validity, SEQ subject, SEQ spki.
    let mut tpos = 0;
    let mut elems: Vec<(u8, Vec<u8>)> = Vec::new();
    while tpos < tbs.len() {
        elems.push(elem(&tbs, &mut tpos));
    }
    assert_eq!(elems.len(), 7, "tbsCertificate must have 7 elements");
    let spki = &elems[6].1;
    // SPKI: SEQ alg, BIT STRING point.
    let mut spos = 0;
    let (_, alg) = elem(spki, &mut spos);
    assert_eq!(alg[0], 0x06, "algorithm OID");
    let (0x03, bit_string) = elem(spki, &mut spos) else {
        panic!("SPKI point must be a BIT STRING");
    };
    assert_eq!(bit_string[0], 0, "no unused bits");
    bit_string[1..].to_vec()
}

/// Fail-closed: a stored scalar that is not a valid P-256 key (torn /
/// attacker-flipped slot) must fail the boot with `Corrupt` — NEVER
/// silently regenerate a new identity (only `NotFound` provisions).
#[test]
fn corrupt_key_slot_fails_closed() {
    let mut trng = HostTrng::new();
    let (mut store, _app) = provisioned_app(&mut trng);
    store.write(ATTEST_KEY_SLOT, &[0xFFu8; 32]).unwrap();
    assert!(
        matches!(
            FidoApp::boot(&mut trng, &mut store),
            Err(fapico2_platform::secure_store::SecureStoreError::Corrupt)
        ),
        "invalid stored scalar must be Corrupt, not regenerated"
    );
}

/// Fail-closed: a corrupt cert part record (CRC failure inside the chunked
/// slot) must also fail the boot with `Corrupt` — the key/cert pair is
/// provisioned atomically, so a half-readable pair is never served.
#[test]
fn corrupt_cert_record_fails_closed() {
    let mut trng = HostTrng::new();
    let (mut store, _app) = provisioned_app(&mut trng);
    let (pk, pklen) = chunked::physical_part_key(ATTEST_CERT_SLOT, 0, 0).unwrap();
    let mut garbage = [0x5Au8; chunked::PART_HEADER_LEN + 32];
    garbage[15] = 0x00; // guarantee the CRC32 check trips
    store.write(&pk[..pklen], &garbage).unwrap();
    assert!(
        matches!(
            FidoApp::boot(&mut trng, &mut store),
            Err(fapico2_platform::secure_store::SecureStoreError::Corrupt)
        ),
        "corrupt cert record must be Corrupt, not regenerated"
    );
}
