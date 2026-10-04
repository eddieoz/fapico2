mod common;

use common::{aes256_cbc_zero_iv_encrypt, pso_encipher_apdu};
use ed25519_dalek::Verifier;
use fapico2_openpgp::{OPENPGP_AID, OpenPgpApp};
use fapico2_platform::dispatch::{Dispatcher, MAX_RESPONSE};
use fapico2_platform::trusted_backend::host::with_host_backend;
use hex_literal::hex;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256, Sha384};

fn command(
    dispatcher: &mut Dispatcher<'_, 1>,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    sw: u16,
) -> Vec<u8> {
    let mut apdu = vec![0, ins, p1, p2];
    if !data.is_empty() {
        apdu.push(u8::try_from(data.len()).unwrap());
        apdu.extend_from_slice(data);
    }
    apdu.push(0);
    let mut response = heapless::Vec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(&apdu, &mut response);
    assert!(response.len() >= 2);
    let body_len = response.len() - 2;
    assert_eq!(
        u16::from_be_bytes(response[body_len..].try_into().unwrap()),
        sw,
        "INS={ins:02x} P1={p1:02x} P2={p2:02x}"
    );
    response[..body_len].to_vec()
}

const ED: &[u8] = &hex!("162b06010401da470f01");
const CV: &[u8] = &hex!("122b060104019755010501");
const P256_SIGN: &[u8] = &hex!("132a8648ce3d030107");
const P256_DEC: &[u8] = &hex!("122a8648ce3d030107");
const RSA: &[u8] = &hex!("010800002000");
/// The factory ECC attributes in `_PK` (public-key + usage) form, as a card
/// reads them back: Ed255 under C1/C3, X255 under C2.
const ED_PK: &[u8] = &hex!("162b06010401da470f01ff");
const CV_PK: &[u8] = &hex!("122b060104019755010501ff");

fn import(dispatcher: &mut Dispatcher<'_, 1>, slot: u8, secret: &[u8; 32]) {
    let mut template = vec![
        0x4d, 0x2a, slot, 0, 0x7f, 0x48, 2, 0x92, 0x20, 0x5f, 0x48, 0x20,
    ];
    template.extend_from_slice(secret);
    command(dispatcher, 0xdb, 0x3f, 0xff, &template, 0x9000);
}

fn reselect(dispatcher: &mut Dispatcher<'_, 1>) {
    dispatcher.deselect_current();
    command(dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
}

#[test]
fn pso_sign_verify_device_path() {
    // Fixtures and prehashed input match tests/test_openpgp_pso.py.
    let ed = hex!("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
    let cv = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let p256 = [
        hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"),
        hex!("c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433"),
        hex!("0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813"),
    ];
    let mut cv_import = cv;
    cv_import[0] &= 248;
    cv_import[31] = (cv_import[31] & 127) | 64;
    cv_import.reverse();
    for is_p256 in [false, true] {
        with_host_backend("opcard", |client| {
            let mut app = OpenPgpApp::new(client);
            let mut dispatcher = Dispatcher::<1>::new();
            assert!(dispatcher.register(&mut app));
            command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
            // US-912: PSO/GENKEY are refused while the factory PINs are in
            // force — personalize PW1/PW3 first, then use the new PINs.
            command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
            command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
            command(&mut dispatcher, 0xda, 0, 0xc1, ED, 0x6982);
            command(&mut dispatcher, 0x47, 0x80, 0, &[0xb6, 0], 0x6982);
            command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
            let attrs = if is_p256 {
                [P256_SIGN, P256_DEC, P256_SIGN]
            } else {
                [ED, CV, ED]
            };
            let secrets = if is_p256 { p256 } else { [ed, cv_import, ed] };
            for (i, slot) in [0xb6, 0xb8, 0xa4].into_iter().enumerate() {
                command(&mut dispatcher, 0xda, 0, 0xc1 + i as u8, attrs[i], 0x9000);
                import(&mut dispatcher, slot, &secrets[i]);
            }
            let digest = Sha256::digest(b"This is a test message.");
            for (mode, ins, p1, p2, index) in [(0x81, 0x2a, 0x9e, 0x9a, 0), (0x82, 0x88, 0, 0, 2)] {
                reselect(&mut dispatcher);
                command(&mut dispatcher, ins, p1, p2, &digest, 0x6982);
                command(
                    &mut dispatcher,
                    0x20,
                    0,
                    if mode == 0x81 { 0x82 } else { 0x81 },
                    b"654321",
                    0x9000,
                );
                command(&mut dispatcher, ins, p1, p2, &digest, 0x6982);
                command(&mut dispatcher, 0x20, 0, mode, b"654321", 0x9000);
                let signature = command(&mut dispatcher, ins, p1, p2, &digest, 0x9000);
                assert_eq!(signature.len(), 64);
                let mut tampered = digest;
                tampered[0] ^= 1;
                if is_p256 {
                    let private = p256::ecdsa::SigningKey::from_slice(&secrets[index]).unwrap();
                    let signature = p256::ecdsa::Signature::from_slice(&signature).unwrap();
                    private
                        .verifying_key()
                        .verify_prehash(&digest, &signature)
                        .unwrap();
                    assert!(
                        private
                            .verifying_key()
                            .verify_prehash(&tampered, &signature)
                            .is_err()
                    );
                } else {
                    let key = ed25519_dalek::SigningKey::from_bytes(&ed).verifying_key();
                    let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
                    key.verify(&digest, &signature).unwrap();
                    assert!(key.verify(&tampered, &signature).is_err());
                }
            }
            let (data, expected) = if is_p256 {
                let eph = p256::SecretKey::from_slice(&Sha256::digest(b"eph")).unwrap();
                let private = p256::SecretKey::from_slice(&p256[1]).unwrap();
                let shared = p256::ecdh::diffie_hellman(
                    eph.to_nonzero_scalar(),
                    private.public_key().as_affine(),
                );
                let mut data = hex!("a6467f49438641").to_vec();
                data.extend_from_slice(eph.public_key().to_encoded_point(false).as_bytes());
                (data, shared.raw_secret_bytes().to_vec())
            } else {
                let eph = x25519_dalek::StaticSecret::from(<[u8; 32]>::from(Sha256::digest(
                    b"fapico2-s721-3-eph",
                )));
                let private = x25519_dalek::StaticSecret::from(cv);
                let mut data = hex!("a6257f49228620").to_vec();
                data.extend_from_slice(x25519_dalek::PublicKey::from(&eph).as_bytes());
                (
                    data,
                    private
                        .diffie_hellman(&x25519_dalek::PublicKey::from(&eph))
                        .as_bytes()
                        .to_vec(),
                )
            };
            reselect(&mut dispatcher);
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x6982);
            command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x6982);
            command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
            assert_eq!(
                command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x9000),
                expected
            );
            reselect(&mut dispatcher);
            command(&mut dispatcher, 0x20, 0, 0x81, b"000000", 0x63c2);
            command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x6982);
            command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
        });
    }
}

/// S-724: secp256k1 end-to-end on the device path (platform
/// `OpcardDispatch` → software-secp256k1 backend, `vendor/trussed-secp256k1`
/// over k256). Mirrors `pso_sign_verify_device_path` for the bitcoin curve:
/// the C-firmware attribute pair (`algorithm_attr_p256k1`), key import,
/// GENERATE (keygen + public derivation + serialize through the backend),
/// PSO:SIGN verified against the generated point, and PSO:DECIPHER ECDH
/// with exact shared-secret bytes.
#[test]
fn pso_secp256k1_device_path() {
    use k256::ecdsa::signature::hazmat::PrehashVerifier as K256PrehashVerifier;
    use k256::elliptic_curve::sec1::ToEncodedPoint as _;

    const SECP_SIGN: &[u8] = &hex!("132b8104000a");
    const SECP_DEC: &[u8] = &hex!("122b8104000a");
    // Valid secp256k1 scalars (any 32-byte value below the curve order; the
    // P-256 test fixtures already qualify).
    let secp = [
        hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"),
        hex!("c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433"),
        hex!("0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813"),
    ];
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        // US-912: personalize first; the admin session carries through the
        // CHANGE REFERENCE DATA.
        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
        // C1/C2 attributes: secp256k1 ECDSA (sign) + ECDH (dec).
        command(&mut dispatcher, 0xda, 0, 0xc1, SECP_SIGN, 0x9000);
        command(&mut dispatcher, 0xda, 0, 0xc2, SECP_DEC, 0x9000);
        // Confidentiality key by import (known scalar → exact ECDH bytes).
        import(&mut dispatcher, 0xb8, &secp[1]);
        // Signature key by GENERATE — keygen/derive/serialize through the
        // secp256k1 backend on the device dispatch.
        let gen = command(&mut dispatcher, 0x47, 0x80, 0, &[0xb6, 0], 0x9000);
        let idx = gen
            .windows(2)
            .position(|w| w == [0x86, 0x41])
            .expect("GENERATE reply must carry an 86 41 public key");
        assert_eq!(gen[idx + 2], 0x04, "secp256k1 point must be uncompressed");
        let public = k256::PublicKey::from_sec1_bytes(&gen[idx + 2..idx + 2 + 65])
            .expect("GENERATE reply must be a valid secp256k1 point");

        let digest = Sha256::digest(b"This is a test message.");
        // PSO:SIGN refused without PW1, then answers a verifying signature.
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x6982);
        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
        let signature = command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
        assert_eq!(signature.len(), 64);
        let signature =
            k256::ecdsa::Signature::from_slice(&signature).expect("valid secp256k1 signature");
        let verifying = k256::ecdsa::VerifyingKey::from(&public);
        K256PrehashVerifier::verify_prehash(&verifying, &digest, &signature)
            .expect("PSO:SIGN signature must verify on secp256k1");
        let mut tampered = digest;
        tampered[0] ^= 1;
        assert!(K256PrehashVerifier::verify_prehash(&verifying, &tampered, &signature).is_err());

        // PSO:DECIPHER ECDH with exact expected shared secret.
        let eph = k256::SecretKey::from_slice(&Sha256::digest(b"eph")).unwrap();
        let private = k256::SecretKey::from_slice(&secp[1]).unwrap();
        let shared = k256::ecdh::diffie_hellman(
            eph.to_nonzero_scalar(),
            private.public_key().as_affine(),
        );
        let mut data = hex!("a6467f49438641").to_vec();
        data.extend_from_slice(eph.public_key().to_encoded_point(false).as_bytes());
        let expected = shared.raw_secret_bytes().to_vec();
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x6982);
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        assert_eq!(command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x9000), expected);
    });
}

/// US-949: the AUT slot over secp256k1 — INTERNAL AUTHENTICATE signs the
/// incoming digest *prehashed* (the C3 authentication attribute selects
/// `Mechanism::Secp256k1Prehashed` via `int_aut_key_mecha_uif`) and returns a
/// raw r‖s signature that verifies host-side against the AUT public key; the
/// operation is refused before the PW1 "other" session, and a tampered digest
/// does not verify.
#[test]
fn int_auth_secp256k1_device_path() {
    use k256::ecdsa::signature::hazmat::PrehashVerifier as K256PrehashVerifier;
    use k256::SecretKey;

    const SECP_C3: &[u8] = &hex!("132b8104000a");
    // A valid secp256k1 scalar (below the curve order); the same value the
    // PSO:SIGN test uses for its signature key, so the expected public point
    // is computed directly rather than read back.
    let aut_scalar: [u8; 32] = hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464");

    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);

        // US-912: personalize — change the factory PINs so INT-AUTH is not
        // refused by the factory-default gate (pw1/pw3 must both be changed).
        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);

        // US-949: set the authentication (C3) attribute to secp256k1 ECDSA,
        // which is what routes the AUT slot through Secp256k1Prehashed.
        command(&mut dispatcher, 0xda, 0, 0xc3, SECP_C3, 0x9000);

        // Import the secp256k1 key into the AUT slot (CRT A4). The AUT keyref
        // defaults to KeyRef::Aut, so no MANAGE SECURITY ENVIRONMENT is needed.
        import(&mut dispatcher, 0xa4, &aut_scalar);

        // The expected secp256k1 public key for the known scalar.
        let secret = SecretKey::from_slice(&aut_scalar).expect("valid secp256k1 scalar");
        let public = secret.public_key();

        // A valid 32-byte digest; INT-AUTH signs it prehashed (no re-hash).
        let digest = Sha256::digest(b"fapico2-us949-int-auth");

        // Refused without the PW1 "other" session (SecurityStatusNotSatisfied).
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x88, 0, 0, &digest, 0x6982);

        // Verify PW1 in the "other" role (P2=0x82) — the INT-AUTH gate.
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        let signature = command(&mut dispatcher, 0x88, 0, 0, &digest, 0x9000);
        assert_eq!(signature.len(), 64, "raw secp256k1 signature is r || s");
        let sig = k256::ecdsa::Signature::from_slice(&signature)
            .expect("valid raw secp256k1 signature");

        // Host-side prehashed verification against the AUT public key.
        let verifying = k256::ecdsa::VerifyingKey::from(&public);
        K256PrehashVerifier::verify_prehash(&verifying, &digest, &sig)
            .expect("INT-AUTH signature must verify over the signed digest");

        // A tampered digest must not verify against the same signature.
        let mut tampered = digest;
        tampered[0] ^= 1;
        assert!(
            K256PrehashVerifier::verify_prehash(&verifying, &tampered, &sig).is_err(),
            "the signature must not verify over a tampered digest"
        );
    });
}

#[test]
fn legacy_empty_card_migrates_without_resetting_pin() {
    use fapico2_platform::trusted_backend::{
        dispatch::OpcardDispatch,
        host::{HostPlatform, HostStore, leak_buf, mount_fs},
        runner::with_backend,
    };
    for custom in [false, true] {
        let internal = leak_buf(256 * 4096);
        for cycle in 0..3 {
            let ram = HostStore::fresh();
            with_backend(
                HostPlatform::with_store(HostStore::new(
                    mount_fs::<256>(internal),
                    ram.efs,
                    ram.vfs,
                )),
                OpcardDispatch::new(),
                "opcard",
                |client| {
                    let mut app = OpenPgpApp::new(client);
                    let mut dispatcher = Dispatcher::<1>::new();
                    assert!(dispatcher.register(&mut app));
                    command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
                    if cycle == 0 {
                        command(&mut dispatcher, 0x20, 0, 0x83, b"12345678", 0x9000);
                        // S-724 (supersedes the S-723-A3 fail-closed gate):
                        // RSA-2048 attribute writes are accepted and stored —
                        // the card interface can again produce the C-firmware
                        // RSA shape, so the migration path must carry it
                        // across reload cycles untouched. `custom` still
                        // overrides C1 with a P256 attribute to pin attribute
                        // persistence over an accepted-then-replaced write.
                        for tag in [0xc1, 0xc2, 0xc3] {
                            command(&mut dispatcher, 0xda, 0, tag, RSA, 0x9000);
                        }
                        if custom {
                            command(&mut dispatcher, 0xda, 0, 0xc1, P256_SIGN, 0x9000);
                        }
                        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
                        // US-912: clear the factory-default gate for PW3 too,
                        // so GENKEY is served on the reloaded card.
                        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
                    } else {
                        // US-962 (I1) supersedes the S-724 expectation that
                        // the RSA triple survives a reload untouched. A card
                        // that says RSA-2048 in C1/C2/C3 and holds no key is
                        // *wedged*, not customized: measured on the RP2350,
                        // on-card RSA-2048 GENERATE runs into a PC/SC
                        // transaction timeout after ~1750 s, while the
                        // allow-list still accepts the attribute, so the
                        // host commits to a capability the card cannot
                        // deliver. The restored scrub reverts that keyless
                        // state to the factory ECC defaults.
                        //
                        // The `custom` card is the counter-case that proves
                        // the scrub is not a blanket revert: its C1 is P-256
                        // (and, from cycle 1, it holds a generated key), so
                        // the triple is not all-RSA, nothing is scrubbed, and
                        // C2/C3 keep their RSA attributes verbatim. The P-256
                        // C1 reads back in PK form, with the 0xFF suffix.
                        for (tag, factory) in [(0xc1, ED_PK), (0xc2, CV_PK), (0xc3, ED_PK)] {
                            let expected: Vec<u8> = if !custom {
                                factory.to_vec()
                            } else if tag == 0xc1 {
                                let mut p256 = P256_SIGN.to_vec();
                                p256.push(0xff);
                                p256
                            } else {
                                RSA.to_vec()
                            };
                            assert_eq!(
                                command(&mut dispatcher, 0xca, 0, tag, &[], 0x9000),
                                expected,
                                "tag {tag:02x} must read back as expected after the reload"
                            );
                        }
                        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
                        if cycle == 1 && custom {
                            command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
                            command(&mut dispatcher, 0x47, 0x80, 0, &[0xb6, 0], 0x9000);
                        }
                    }
                },
            );
        }
    }
}

/// S-912: pre-gate snapshots (no `pw1_changed`/`pw3_changed` members in the
/// persistent CBOR) must derive the gate flags from the PINs actually
/// stored — a personalized legacy card is never gated, a factory card is
/// never freed. The snapshot is produced by byte surgery on a fresh card
/// image because the card interface cannot produce flag-less states.
#[test]
fn legacy_snapshot_pin_gate_flags_derive_from_stored_pins() {
    use fapico2_platform::trusted_backend::{
        dispatch::OpcardDispatch,
        host::{HostPlatform, HostStore, leak_buf, mount_fs},
        runner::with_backend,
    };
    use trussed_core::types::PathBuf;

    // Remove one `"pw1_changed"/"pw3_changed": F4/F5` member from the flat
    // CBOR map (0x6B is the definite-length text-string header of the key,
    // F4/F5 the boolean value), mimicking a pre-US-912 snapshot where the
    // fields did not exist.
    fn strip_flag(data: &[u8], name: &[u8]) -> Vec<u8> {
        let mut needle = vec![0x6b];
        needle.extend_from_slice(name);
        let hit = (0..data.len().saturating_sub(needle.len()))
            .find(|i| {
                data[*i..*i + needle.len()] == needle[..]
                    && matches!(data[*i + needle.len()], 0xf4 | 0xf5)
            })
            .unwrap_or_else(|| panic!("flag {name:?} not found in snapshot"));
        let mut out = data.to_vec();
        out.drain(hit..hit + needle.len() + 1);
        // Map header: short count (0xA0..0xB7) or 0xB8 + count byte —
        // the removed member leaves it one short.
        if out[0] == 0xb8 {
            out[1] -= 1;
        } else {
            assert!((0xa0..0xb8).contains(&out[0]));
            out[0] -= 1;
        }
        out
    }

    for personalize in [true, false] {
        let internal = leak_buf(256 * 4096);
        let ram = HostStore::fresh();
        let store = || {
            HostPlatform::with_store(HostStore::new(
                mount_fs::<256>(internal),
                ram.efs,
                ram.vfs,
            ))
        };
        // Session A: create the card; personalize both PINs when asked.
        with_backend(store(), OpcardDispatch::new(), "opcard", |client| {
            let mut app = OpenPgpApp::new(client);
            let mut dispatcher = Dispatcher::<1>::new();
            assert!(dispatcher.register(&mut app));
            command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
            if personalize {
                command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
                command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
            } else {
                // Materialize the persistent state (VERIFY saves pin lengths).
                command(&mut dispatcher, 0x20, 0, 0x83, b"12345678", 0x9000);
            }
        });
        // Session B: rewrite persistent-state.cbor as a pre-US-912 snapshot.
        with_backend(store(), OpcardDispatch::new(), "opcard", |mut client| {
            use trussed_core::FilesystemClient;
            use trussed_core::types::Location;
            use trussed_core::{config::MAX_MESSAGE_LENGTH, types::Bytes};
            let path = PathBuf::try_from("persistent-state.cbor").unwrap();
            let reply = trussed_core::try_syscall!(
                client.read_file(Location::Internal, path.clone())
            )
            .unwrap_or_else(|err| panic!("read failed: {err:?}"));
            let stripped = strip_flag(&strip_flag(&reply.data, b"pw1_changed"), b"pw3_changed");
            let stripped: Bytes<MAX_MESSAGE_LENGTH> =
                Bytes::try_from(&stripped[..]).unwrap();
            trussed_core::syscall!(
                client.write_file(Location::Internal, path, stripped, None)
            );

        });
        // Session C: fresh app over the legacy snapshot.
        with_backend(store(), OpcardDispatch::new(), "opcard", |client| {
            let mut app = OpenPgpApp::new(client);
            let mut dispatcher = Dispatcher::<1>::new();
            assert!(dispatcher.register(&mut app));
            command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
            if personalize {
                // Derivation lifted the gate: the stored PINs are non-default.
                command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
                command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
                command(&mut dispatcher, 0x47, 0x80, 0, &[0xb6, 0], 0x9000);
            } else {
                // Derivation kept the gate armed: factory PINs still in force.
                command(&mut dispatcher, 0x20, 0, 0x83, b"12345678", 0x9000);
                command(&mut dispatcher, 0x47, 0x80, 0, &[0xb6, 0], 0x6985);
            }
        });
    }
}

/// US-912 review: RESET RETRY COUNTER replaces PW1 without going through
/// CHANGE REFERENCE DATA, so the factory-default gate must be re-derived
/// from the actual new PIN in BOTH RRC paths. Resetting PW1 to the factory
/// default re-arms the gate (key operations refused with 6985); resetting
/// to a non-default PIN leaves it free. PW3 is untouched by RRC.
#[test]
fn rrc_rearms_factory_default_gate() {
    let ed = hex!("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
    let digest = Sha256::digest(b"This is a test message.");
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        // Personalize both PINs through CRD so the gate starts free, verify
        // PW3, and enroll a resetting code (admin-authorized PUT DATA).
        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
        command(&mut dispatcher, 0xda, 0, 0xd3, b"12345678", 0x9000);

        // RC path: RRC sets PW1 back to the FACTORY default.
        let mut rrc = b"12345678".to_vec();
        rrc.extend_from_slice(b"123456");
        command(&mut dispatcher, 0x2c, 0, 0x81, &rrc, 0x9000);
        // The stored PIN really is the shipped default...
        command(&mut dispatcher, 0x20, 0, 0x81, b"123456", 0x9000);
        // ...yet key operations are refused: the gate re-armed (was the
        // US-912 review R5 chain re-entered through the recovery path).
        command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x6985);

        // RC path: RRC to a NON-default PIN frees the gate again.
        let mut rrc = b"12345678".to_vec();
        rrc.extend_from_slice(b"654321");
        command(&mut dispatcher, 0x2c, 0, 0x81, &rrc, 0x9000);
        command(&mut dispatcher, 0xda, 0, 0xc1, ED, 0x9000);
        import(&mut dispatcher, 0xb6, &ed);
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
        let signature = command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
        assert_eq!(signature.len(), 64);

        // PW3 path: RRC to the factory default re-arms the gate as well.
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
        command(&mut dispatcher, 0x2c, 2, 0x81, b"123456", 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x81, b"123456", 0x9000);
        command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x6985);
    });
}

#[test]
fn factory_ecc_generation_device_path() {
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        // US-912: GENKEY is refused while the factory PINs are in force.
        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
        for slot in [0xb8, 0xb6, 0xa4] {
            let public = command(&mut dispatcher, 0x47, 0x80, 0, &[slot, 0], 0x9000);
            assert_eq!(&public[..5], &[0x7f, 0x49, 0x22, 0x86, 0x20]);
            assert_eq!(public.len(), 37);
            let digest = Sha256::digest(b"This is a test message.");
            if slot == 0xb8 {
                command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
                let secret = x25519_dalek::StaticSecret::from([42; 32]);
                let mut data = hex!("a6257f49228620").to_vec();
                data.extend_from_slice(x25519_dalek::PublicKey::from(&secret).as_bytes());
                let shared = command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x9000);
                let peer =
                    x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(&public[5..]).unwrap());
                assert_eq!(shared, secret.diffie_hellman(&peer).as_bytes());
            } else {
                let mode = if slot == 0xb6 { 0x81 } else { 0x82 };
                command(&mut dispatcher, 0x20, 0, mode, b"654321", 0x9000);
                let (ins, p1, p2) = if slot == 0xb6 {
                    (0x2a, 0x9e, 0x9a)
                } else {
                    (0x88, 0, 0)
                };
                let signature = command(&mut dispatcher, ins, p1, p2, &digest, 0x9000);
                let key = ed25519_dalek::VerifyingKey::from_bytes(public[5..].try_into().unwrap())
                    .unwrap();
                key.verify(
                    &digest,
                    &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
                )
                .unwrap();
            }
        }
    });
}

// ---------------------------------------------------------------------------
// US-940: RSA PSO:SIGN verified end-to-end on the device path — the platform
// `OpcardDispatch` (`Backend::Rsa` → `trussed_rsa_alloc::SoftwareRsa`) is the
// exact backend the RP2350 build serves RSA with. The card signs the
// DigestInfo the host sends (PKCS#1 v1.5 over the raw APDU data, backend
// `SigningKey::<Sha256>::new_unprefixed(..).sign_prehash()`), so the host
// builds the full SHA-256 DigestInfo — DigestInfo generation is host-side
// per spec §7.2.14. PSO:SIGN replies with raw signature bytes (no TLV
// wrapper), exactly modulus-length (256 B for RSA-2048), verified with the
// `rsa` crate against the public key read back from the card.
//
// Slot semantics (probed, then pinned — the brief's "AUT/DEC refusal for
// RSA as observed behavior"): PSO:SIGN is bound to the SIG slot — with RSA
// keys in DEC and AUT but no SIG key it answers 6A88 and never falls back.
// RSA in the AUT slot signs verifiably through INTERNAL AUTHENTICATE
// (§7.2.13); RSA in the DEC slot decrypts through PSO:DECIPHER (§7.2.11) —
// neither is refused for RSA; slots are separated by operation, not by
// algorithm.

use std::sync::LazyLock;

/// The deterministic RSA-2048 test key: fixed-seed keygen so failures are
/// reproducible and the prime search is paid once per test binary. `n = p·q`
/// is recomputed from the imported parts — the verification base is exactly
/// the (e, p, q) the card received, never the generator's own struct.
struct RsaTestKey {
    e: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    n: Vec<u8>,
}

static RSA_TEST_KEY: LazyLock<RsaTestKey> = LazyLock::new(|| {
    use rand::SeedableRng as _;
    use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};

    let mut rng = rand::rngs::StdRng::seed_from_u64(0x4641_5049_434F_3202);
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .expect("deterministic RSA-2048 keygen must succeed");
    let primes = private.primes();
    assert_eq!(primes.len(), 2, "RSA-2048 private key has exactly two primes");
    let e = private.e().to_bytes_be();
    // p and q are 128 bytes each for RSA-2048; pad defensively so the
    // template lengths stay exact.
    let pad = |mut v: Vec<u8>| -> Vec<u8> {
        while v.len() < 128 {
            v.insert(0, 0);
        }
        v
    };
    let (p, q) = (pad(primes[0].to_bytes_be()), pad(primes[1].to_bytes_be()));
    let n = (&primes[0] * &primes[1]).to_bytes_be();
    assert_eq!(n.len(), 256, "RSA-2048 modulus must be 256 bytes");
    RsaTestKey { e, p, q, n }
});

/// PKCS#1 v1.5 (SHA-256 DigestInfo prefix) verification of a raw signature
/// against a public key derived from `n`/`e`. The card signs the raw
/// DigestInfo with an *unprefixed* `SigningKey`, so verification uses
/// `VerifyingKey::<Sha256>` (whose prefix is exactly that DigestInfo) over
/// the bare 32-byte digest.
fn rsa_verifies(n: &[u8], e: &[u8], digest: &[u8; 32], signature: &[u8]) -> bool {
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::hazmat::PrehashVerifier as _;

    let pub_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_bytes_be(e),
    )
    .expect("n = p·q with the 65537 exponent is a valid RSA public key");
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(signature) else {
        return false;
    };
    VerifyingKey::<sha2::Sha256>::new(pub_key)
        .verify_prehash(digest, &signature)
        .is_ok()
}

/// SHA-256 DigestInfo over `message` (RFC 8017 §9.2 with the SHA-256
/// prefix): `30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || h`.
fn sha256_digest_info(message: &[u8]) -> [u8; 51] {
    let digest: [u8; 32] = Sha256::digest(message).into();
    let mut info = [0u8; 51];
    info[..19].copy_from_slice(&[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, 0x05, 0x00, 0x04, 0x20,
    ]);
    info[19..].copy_from_slice(&digest);
    info
}

/// DER length field (spec §4.3.3 length encoding): short form `< 128`,
/// `81 xx`, `82 hi lo` — the form opcard's `take_len` parses.
fn der_len(len: usize) -> Vec<u8> {
    if len <= 0x7f {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

/// One raw APDU (extended length where needed) through the dispatcher,
/// returning (body, SW) without asserting the status word — for the
/// `61XX`/GET RESPONSE continuation the status word itself drives.
fn dispatch_apdu(dispatcher: &mut Dispatcher<'_, 1>, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut response = heapless::Vec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(apdu, &mut response);
    assert!(response.len() >= 2, "empty response for {:02x?}", &apdu[..8]);
    let body_len = response.len() - 2;
    let sw = u16::from_be_bytes(response[body_len..].try_into().unwrap());
    (response[..body_len].to_vec(), sw)
}

/// One raw APDU (extended length where needed) through the dispatcher.
fn command_apdu(dispatcher: &mut Dispatcher<'_, 1>, apdu: &[u8], sw: u16) -> Vec<u8> {
    let mut response = heapless::Vec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(apdu, &mut response);
    assert!(response.len() >= 2, "empty response for {:02x?}", &apdu[..8]);
    let body_len = response.len() - 2;
    assert_eq!(
        u16::from_be_bytes(response[body_len..].try_into().unwrap()),
        sw,
        "PUT KEY/PSO raw APDU"
    );
    response[..body_len].to_vec()
}

/// PUT KEY (INS DB, P1P2 3FFF) with the RSA `91/92/93` (e,p,q) template
/// (`RsaImportFormat{e,p,q}`; d/u are recomputed by the backend). The 4D DO
/// exceeds short-Lc (276 B for RSA-2048), so the APDU uses extended length
/// (3-byte Lc) — the iso7816 parser at the app seam accepts both forms.
fn put_key_rsa_apdu(crt: &[u8], e: &[u8], p: &[u8], q: &[u8]) -> Vec<u8> {
    let mut template = Vec::new();
    for (tag, part) in [(0x91u8, e), (0x92u8, p), (0x93u8, q)] {
        template.push(tag);
        template.extend_from_slice(&der_len(part.len()));
    }
    let mut key_data = Vec::from(e);
    key_data.extend_from_slice(p);
    key_data.extend_from_slice(q);

    let mut content = Vec::from(crt);
    for (tag, value) in [(&[0x7fu8, 0x48][..], template), (&[0x5fu8, 0x48][..], key_data)] {
        content.extend_from_slice(tag);
        content.extend_from_slice(&der_len(value.len()));
        content.extend_from_slice(&value);
    }
    let mut blob = vec![0x4Du8];
    blob.extend_from_slice(&der_len(content.len()));
    blob.extend_from_slice(&content);

    let mut apdu = vec![0x00u8, 0xDB, 0x3F, 0xFF, 0x00];
    apdu.extend_from_slice(&(blob.len() as u16).to_be_bytes());
    apdu.extend_from_slice(&blob);
    apdu
}

/// Parse the READ PUBLIC KEY 7F49 reply for an RSA key: `7F 49 <len> 81
/// <len> <n> 82 <len> <e>` (gen.rs `read_rsa_key`). Returns (n, e).
fn rsa_pubkey_from_template(body: &[u8]) -> (Vec<u8>, Vec<u8>) {
    fn take_len(data: &[u8], i: usize) -> (usize, usize) {
        match data[i] {
            l @ 0x00..=0x7f => (l as usize, i + 1),
            0x81 => (data[i + 1] as usize, i + 2),
            0x82 => (
                ((data[i + 1] as usize) << 8) | data[i + 2] as usize,
                i + 3,
            ),
            b => panic!("unexpected length byte {b:02x} in template"),
        }
    }
    assert_eq!(&body[..2], &[0x7f, 0x49], "reply must open with the 7F49 template");
    let (_total, mut i) = take_len(body, 2);
    assert_eq!(body[i], 0x81, "first template member must be tag 81 (modulus)");
    i += 1;
    let (n_len, next) = take_len(body, i);
    i = next;
    let n = body[i..i + n_len].to_vec();
    i += n_len;
    assert_eq!(body[i], 0x82, "second template member must be tag 82 (exponent)");
    i += 1;
    let (e_len, next) = take_len(body, i);
    i = next;
    let e = body[i..i + e_len].to_vec();
    (n, e)
}

/// READ PUBLIC KEY (INS 47 P1=81) for `crt`; the ~270-byte RSA template
/// exceeds Le = 0 (256), so the reply arrives chunked and the `61XX`/
/// GET RESPONSE continuation is drained here (S-723-A2 seam semantics).
fn read_rsa_pubkey(dispatcher: &mut Dispatcher<'_, 1>, crt: u8) -> (Vec<u8>, Vec<u8>) {
    let apdu = vec![0x00u8, 0x47, 0x81, 0x00, 0x02, crt, 0x00];
    let (mut body, mut sw) = dispatch_apdu(dispatcher, &apdu);
    while sw & 0xFF00 == 0x6100 {
        let le = (sw & 0xFF) as u8;
        let (chunk, next) = dispatch_apdu(dispatcher, &[0x00, 0xC0, 0x00, 0x00, le]);
        body.extend_from_slice(&chunk);
        sw = next;
    }
    assert_eq!(sw, 0x9000, "READ PUBLIC KEY must complete with 9000");
    rsa_pubkey_from_template(&body)
}

/// US-940, device path: RSA-2048 imported into the SIG slot via PUT KEY
/// (e,p,q); PSO:SIGN over a host-computed SHA-256 DigestInfo returns exactly
/// 256 raw signature bytes that verify against the card's own read-back
/// public key; a one-bit digest change or a one-bit signature change breaks
/// verification. Slot semantics probed and pinned: PSO:SIGN without a SIG
/// key answers 6A88; RSA AUT signs verifiably (INT-AUTH); RSA DEC decrypts
/// (PSO:DECIPHER round-trip).
#[test]
fn pso_rsa_2048_device_path() {
    use rand::SeedableRng as _;
    use rsa::Pkcs1v15Encrypt;

    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"12345678", 0x9000);

        // RSA-2048 attributes for all three slots, then clear the US-912
        // factory gate (CRD keeps the admin session).
        for tag in [0xc1, 0xc2, 0xc3] {
            command(&mut dispatcher, 0xda, 0, tag, RSA, 0x9000);
        }
        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);

        // SIG slot: import (e, p, q).
        let k = &*RSA_TEST_KEY;
        command_apdu(
            &mut dispatcher,
            &put_key_rsa_apdu(&[0xB6, 0x00], &k.e, &k.p, &k.q),
            0x9000,
        );

        // The card's own read-back of the imported public key.
        let (n_card, e_card) = read_rsa_pubkey(&mut dispatcher, 0xb6);
        assert_eq!(e_card, k.e, "read-back exponent must be the imported e");
        assert_eq!(n_card, k.n, "read-back modulus must be p·q of the imported parts");

        // PSO:SIGN needs a PW1 sign session (the new PIN, P2 = 81).
        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);

        let info = sha256_digest_info(b"fapico2-us940-rsa-device");
        let signature = command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &info, 0x9000);

        // Raw signature bytes: exactly the modulus length. Any TLV wrapper
        // (7F49 template, 81/82 tags) would make the reply longer than 256.
        assert_eq!(
            signature.len(),
            256,
            "PSO:SIGN must return exactly the modulus length, no TLV wrapping"
        );
        let digest: [u8; 32] = info[19..].try_into().unwrap();
        assert!(
            rsa_verifies(&k.n, &k.e, &digest, &signature),
            "PSO:SIGN signature must verify (PKCS#1 v1.5, SHA-256 DigestInfo)"
        );

        // One flipped digest bit → the returned signature must not verify.
        let mut tampered_digest = digest;
        tampered_digest[0] ^= 1;
        assert!(
            !rsa_verifies(&k.n, &k.e, &tampered_digest, &signature),
            "the signature must not verify over a tampered digest"
        );

        // One flipped signature bit → verification must fail.
        let mut tampered_signature = signature.clone();
        tampered_signature[128] ^= 1;
        assert!(
            !rsa_verifies(&k.n, &k.e, &digest, &tampered_signature),
            "a tampered signature must not verify"
        );

        // --- Slot semantics on a fresh card: DEC and AUT RSA, SIG empty. ---
        with_host_backend("opcard", |client| {
            let mut app = OpenPgpApp::new(client);
            let mut dispatcher = Dispatcher::<1>::new();
            assert!(dispatcher.register(&mut app));
            command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
            command(&mut dispatcher, 0x20, 0, 0x83, b"12345678", 0x9000);
            for tag in [0xc1, 0xc2, 0xc3] {
                command(&mut dispatcher, 0xda, 0, tag, RSA, 0x9000);
            }
            command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
            command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
            // Import into DEC (CRT B8) and AUT (CRT A4); SIG stays empty.
            command_apdu(
                &mut dispatcher,
                &put_key_rsa_apdu(&[0xB8, 0x00], &k.e, &k.p, &k.q),
                0x9000,
            );
            command_apdu(
                &mut dispatcher,
                &put_key_rsa_apdu(&[0xA4, 0x00], &k.e, &k.p, &k.q),
                0x9000,
            );

            // 1. PSO:SIGN with no SIG key: refused (6A88), no fallback.
            let info = sha256_digest_info(b"fapico2-us940-slot-probe");
            command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &info, 0x6a88);

            // The read-back AUT public key.
            let (n_aut, e_aut) = read_rsa_pubkey(&mut dispatcher, 0xa4);
            assert_eq!(n_aut, k.n, "AUT read-back modulus must be the imported p·q");
            assert_eq!(e_aut, k.e, "AUT read-back exponent must be the imported e");

            // 2. AUT slot, INTERNAL AUTHENTICATE: needs a PW1 "other" session.
            command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
            let signature = command(&mut dispatcher, 0x88, 0, 0, &info, 0x9000);
            assert_eq!(signature.len(), 256, "INT-AUTH signature must be modulus-length");
            let digest: [u8; 32] = info[19..].try_into().unwrap();
            assert!(
                rsa_verifies(&n_aut, &e_aut, &digest, &signature),
                "the INT-AUTH signature must verify against the AUT public key"
            );
            let mut tampered_digest = digest;
            tampered_digest[0] ^= 1;
            assert!(
                !rsa_verifies(&n_aut, &e_aut, &tampered_digest, &signature),
                "the INT-AUTH signature must not verify over a tampered digest"
            );

            // 3. DEC slot, PSO:DECIPHER: `00` padding indicator || ciphertext
            //    (257-byte DO → extended Lc).
            let pub_key = rsa::RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(&k.n),
                rsa::BigUint::from_bytes_be(&k.e),
            )
            .expect("valid DEC public key");
            let plaintext = b"fapico2-us940-dec-roundtrip";
            let mut rng = rand::rngs::StdRng::seed_from_u64(0x940);
            let ciphertext = pub_key
                .encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)
                .expect("host-side PKCS#1 v1.5 encryption must succeed");
            assert_eq!(ciphertext.len(), 256);
            let mut data = vec![0x00u8];
            data.extend_from_slice(&ciphertext);
            let mut apdu = vec![0x00u8, 0x2A, 0x80, 0x86, 0x00];
            apdu.extend_from_slice(&(data.len() as u16).to_be_bytes());
            apdu.extend_from_slice(&data);
            let decrypted = command_apdu(&mut dispatcher, &apdu, 0x9000);
            assert_eq!(
                decrypted,
                plaintext.as_slice(),
                "PSO:DECIPHER must round-trip the encrypted plaintext"
            );
        });
    });
}

// ---------------------------------------------------------------------------
// US-941: RSA PSO:DECIPHER verified end-to-end on the device path — the
// platform `OpcardDispatch` (`Backend::Rsa` → `trussed_rsa_alloc::SoftwareRsa`)
// and the Core backend for AES are the exact pair the RP2350 build serves
// decipher with. Per §7.2.11 the PSO:DECIPHER data field is one leading
// padding-indicator byte followed by the ciphertext; the card strips the
// indicator (`pso.rs decrypt_rsa`) and unpads PKCS#1 v1.5 *encryption*
// padding (RFC 8017 §7.2.1, EM = `00 02 PS 00 || M`). The SM routing guard
// sits before key resolution: `0x02`-prefixed data routes to the AES
// decipher path (SM key imported via PUT DATA tag `00 D5`), everything else
// routes to RSA. The routing pins use mutually exclusive observables, so
// each test proves the route taken, not just a status word:
//
// - a 17-byte `0x02`-prefixed DO decrypts through AES-CBC (zero IV, no
//   padding) to host-computed exact bytes — the RSA path cannot return
//   those (it would refuse a 16-byte "ciphertext" with 6A80);
// - a 257-byte `0x00`-prefixed DO whose ciphertext fails unpadding answers
//   6A80 — the AES path would answer 9000 for that shape ((257-1) % 16 == 0).

/// PSO:DECIPHER (INS 2A 80 86) with the raw cipher DO. The DO exceeds short
/// Lc for RSA-2048 (257 B), so the APDU uses extended length (3-byte Lc);
/// no Le — the plaintext reply is shorter than the ciphertext.
fn pso_decipher_apdu(data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00u8, 0x2A, 0x80, 0x86, 0x00];
    apdu.extend_from_slice(&(data.len() as u16).to_be_bytes());
    apdu.extend_from_slice(data);
    apdu
}

/// Host-side PKCS#1 v1.5 (encryption) of `plaintext` to `n`/`e` with a
/// *fixed* padding seed (RFC 8017 §7.2.1, EM = `00 02 PS 00 || M`): the
/// block is built byte-for-byte (PS cycles over 1..=255, never 0) and
/// encrypted by raw modexp — fully deterministic, no rng in the test.
fn pkcs1v15_encrypt_fixed_ps(n: &[u8], e: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let k = n.len();
    assert_eq!(k, 256, "RSA-2048 block size expected");
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x02);
    while em.len() < k - plaintext.len() - 1 {
        em.push(((em.len() * 7) % 255 + 1) as u8);
    }
    em.push(0x00);
    em.extend_from_slice(plaintext);
    assert_eq!(em.len(), k, "EM must fill the RSA block exactly");
    let m = rsa::BigUint::from_bytes_be(&em);
    let c = m.modpow(&rsa::BigUint::from_bytes_be(e), &rsa::BigUint::from_bytes_be(n));
    let mut ct = c.to_bytes_be();
    while ct.len() < k {
        ct.insert(0, 0);
    }
    ct
}

/// AES-256-CBC decrypt with a zero IV and no padding removal — the exact
/// operation the card's AES decipher path performs (trussed `Aes256Cbc`
/// decrypt with an empty nonce → IV = 0, `NoPadding`).
fn aes256_cbc_zero_iv_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockDecrypt as _, KeyInit as _};

    let cipher = aes::Aes256::new_from_slice(key).expect("32-byte AES key");
    assert_eq!(ciphertext.len() % 16, 0, "CBC operates on whole blocks");
    let mut previous = [0u8; 16]; // zero IV
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        let mut block = aes::Block::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        for (b, p) in block.iter().zip(previous.iter()) {
            out.push(b ^ p);
        }
        previous.copy_from_slice(chunk);
    }
    out
}

/// US-941, device path: RSA-2048 imported into the DEC slot; the host
/// PKCS#1 v1.5-encrypts a fixed 32-byte plaintext (fixed PS, raw modexp),
/// sends PSO:DECIPHER prefixed with the `0x00` padding-indicator byte and
/// gets the plaintext back byte-exact. Malformed ciphertexts are probed and
/// pinned (6A80). The SM routing guard is pinned from both directions: a
/// `0x02`-prefixed DO decrypts byte-exact through AES (the imported SM key,
/// zero IV) and a non-block-multiple `0x02` payload hits the AES length
/// guard (6A80).
///
/// - the `0x00` indicator is *semantically transparent* for RSA: a leading
///   zero byte vanishes in the backend's big-endian integer conversion, so
///   decrypting with or without the strip yields the same integer (verified
///   by mutation run — the strip matters only for the `0x02`/AES routing
///   decision, which the guard test pins);
#[test]
fn pso_rsa_2048_decipher_device_path() {
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"12345678", 0x9000);

        // DEC slot: RSA-2048 attribute (C2), personalization (US-912; CRD
        // keeps the admin session), import (e, p, q) into DEC (CRT B8).
        command(&mut dispatcher, 0xda, 0, 0xc2, RSA, 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
        let k = &*RSA_TEST_KEY;
        command_apdu(
            &mut dispatcher,
            &put_key_rsa_apdu(&[0xB8, 0x00], &k.e, &k.p, &k.q),
            0x9000,
        );

        // Import the SM payload-encryption key: PUT DATA tag `00 D5`
        // (admin-authorized) with exactly 32 bytes (AES256_KEY_LEN).
        let sm_key: [u8; 32] = core::array::from_fn(|i| (i as u8) * 7 + 1);
        command(&mut dispatcher, 0xda, 0, 0xd5, &sm_key, 0x9000);

        // PSO:DECIPHER needs a PW1 "other" session (P2 = 82); the wrapped
        // AES key is loaded under the user KEK of that session.
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);

        // Roundtrip: fixed 32-byte plaintext, fixed-PS PKCS#1 v1.5 block,
        // `0x00` padding-indicator leading byte. 257-byte DO → extended Lc.
        let plaintext = *b"fapico2-us941-dec-roundtrip!!!!!"; // exactly 32 bytes
        let ciphertext = pkcs1v15_encrypt_fixed_ps(&k.n, &k.e, &plaintext);
        let mut data = vec![0x00u8];
        data.extend_from_slice(&ciphertext);
        let decrypted = command_apdu(&mut dispatcher, &pso_decipher_apdu(&data), 0x9000);
        assert_eq!(
            decrypted,
            plaintext.as_slice(),
            "PSO:DECIPHER must return the original plaintext byte-exact"
        );

        // Malformed ciphertext, probed then pinned: a one-bit flip in the
        // ciphertext makes the card decrypt to a block that fails the
        // PKCS#1 v1.5 (encryption) unpad in the backend; opcard maps every
        // decrypt failure to 6A80 (`IncorrectDataParameter`). This probe
        // also pins the RSA routing direction: had the 257-byte DO routed
        // to AES ((257-1) % 16 == 0), it would have answered 9000.
        let mut tampered = ciphertext.clone();
        tampered[128] ^= 1;
        let mut data = vec![0x00u8];
        data.extend_from_slice(&tampered);
        command_apdu(&mut dispatcher, &pso_decipher_apdu(&data), 0x6a80);

        // Too-short payload, probed then pinned: after the indicator strip
        // only 8 bytes remain — far short of the 256-byte RSA block; the
        // backend unpads the modexp result and fails → 6A80.
        command_apdu(&mut dispatcher, &pso_decipher_apdu(&[0x00; 9]), 0x6a80);

        // SM routing guard, AES side: `0x02` prefix + 16 bytes
        // ((17-1) % 16 == 0) decrypts byte-exact through AES-CBC with the
        // imported SM key and zero IV — a reply the RSA path could never
        // produce for a 16-byte "ciphertext".
        let ct_block: [u8; 16] = core::array::from_fn(|i| 0xA0 + i as u8);
        let expected = aes256_cbc_zero_iv_decrypt(&sm_key, &ct_block);
        let mut data = vec![0x02u8];
        data.extend_from_slice(&ct_block);
        let body = command_apdu(&mut dispatcher, &pso_decipher_apdu(&data), 0x9000);
        assert_eq!(
            body,
            expected,
            "the AES route must decrypt with the imported SM key (zero IV, no padding)"
        );

        // SM routing guard, same route from the error side: a payload whose
        // length is not a block multiple is refused by the AES path's length
        // guard (6A80) — the routing decision happens before any RSA key
        // resolution.
        let data = vec![0x02u8, 0x11, 0x22, 0x33];
        command_apdu(&mut dispatcher, &pso_decipher_apdu(&data), 0x6a80);
    });
}

// ---------------------------------------------------------------------------
// US-943: RSA attribute import-format nibble policy (reject-CRT decision,
// docs/tasks/us943-rsa-nibble.md) — device path (`OpcardDispatch` backend).
// Nibbles 00/01 (standard formats) are accepted at PUT DATA; CRT (02, 03)
// and out-of-spec (04) nibbles are refused with exactly 6A80 and leave the
// stored attribute untouched. Import always expects the `91/92/93` (e,p,q)
// template and GENERATE always outputs the standard `N,E` template
// regardless of the nibble.

#[test]
fn put_rsa_attr_nibble_policy_device_path() {
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"12345678", 0x9000);

        // Nibble 00 (gpg/scdaemon default): accepted, stored as sent.
        let attr_00: &[u8] = &hex!("010800002000");
        command(&mut dispatcher, 0xda, 0, 0xc1, attr_00, 0x9000);
        let stored = command(&mut dispatcher, 0xca, 0, 0xc1, &[], 0x9000);
        assert_eq!(stored, attr_00, "nibble-00 attribute must be stored as sent");

        // Nibble 01 (standard with n): accepted; read-back is the canonical
        // standard spelling (the card stores the algorithm, not raw bytes).
        let attr_01: &[u8] = &hex!("010800002001");
        command(&mut dispatcher, 0xda, 0, 0xc1, attr_01, 0x9000);
        let stored = command(&mut dispatcher, 0xca, 0, 0xc1, &[], 0x9000);
        assert_eq!(
            stored, attr_00,
            "read-back must be the canonical standard attribute (nibble 00)"
        );

        // CRT (02, 03) and out-of-spec (04): refused with exactly 6A80,
        // stored attribute unchanged.
        for nibble in [0x02u8, 0x03, 0x04] {
            let mut attr = attr_00.to_vec();
            *attr.last_mut().unwrap() = nibble;
            command(&mut dispatcher, 0xda, 0, 0xc1, &attr, 0x6a80);
            let stored = command(&mut dispatcher, 0xca, 0, 0xc1, &[], 0x9000);
            assert_eq!(
                stored, attr_00,
                "a refused PUT (nibble {nibble:02x}) must leave the stored attribute unchanged"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// US-945: Brainpool attributes in the AllowedAlgorithms defaults — device
// path (`OpcardDispatch` host backend). US-944's software backend serves
// P-256r1 (no bp512 crate exists — docs/known-gate-divergences.md
// US-944), so the P-256r1 attribute PUT is accepted and read back in the
// PK-normalized (`… FF`) form, while P-512r1 is refused with 6A80 by the
// fail-closed gate (the recorded divergence, not an accident).
//
// US-966 (2026-09-27): the P-384r1 arm that used to sit between the two is
// now a refusal. P-384r1 is deferred to a follow-up release for want of
// deployment pull, and the assertion for a removed algorithm has to be that
// it is *gone* — silently dropping the arm would leave the curve untested,
// which is how a regression slips back through. The P-256r1 arm below is
// deliberately left exactly as it was: US-966 kept that curve.

#[test]
fn put_brainpool_attr_device_path() {
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"12345678", 0x9000);

        // Brainpool P-256r1 ECDSA attribute (C1/sign): accepted, read back
        // PK-normalized.
        let attr_bp256: &[u8] = &hex!("132b2403030208010107");
        command(&mut dispatcher, 0xda, 0, 0xc1, attr_bp256, 0x9000);
        let stored = command(&mut dispatcher, 0xca, 0, 0xc1, &[], 0x9000);
        assert_eq!(
            stored,
            &hex!("132b2403030208010107ff"),
            "stored C1 must be the PK-normalized Brainpool P-256r1 attribute"
        );

        // US-966: Brainpool P-384r1 is no longer served, so the attribute is
        // refused with 6A80 on every usage tag — not accepted with 9000 the
        // way it was under US-945.
        for (tag, attr) in [
            (0xc1u8, &hex!("132b240303020801010b")[..]),
            (0xc2u8, &hex!("122b240303020801010b")[..]),
            (0xc3u8, &hex!("132b240303020801010b")[..]),
        ] {
            command(&mut dispatcher, 0xda, 0, tag, attr, 0x6a80);
        }
        // The refused PUTs left the stored C1 attribute alone.
        let stored = command(&mut dispatcher, 0xca, 0, 0xc1, &[], 0x9000);
        assert_eq!(
            stored,
            attr_bp256_pk(),
            "refused P-384r1 PUTs must leave the stored C1 attribute unchanged"
        );

        // Brainpool P-512r1: no backend — refused with 6A80, and the stored
        // C1 attribute is untouched by the refused PUT.
        command(&mut dispatcher, 0xda, 0, 0xc1, &hex!("132b240303020801010d"), 0x6a80);
        let stored = command(&mut dispatcher, 0xca, 0, 0xc1, &[], 0x9000);
        assert_eq!(
            stored, attr_bp256_pk(),
            "a refused PUT must leave the stored attribute unchanged"
        );
    });
}

fn attr_bp256_pk() -> Vec<u8> {
    hex!("132b2403030208010107ff").to_vec()
}

// ---------------------------------------------------------------------------
// US-946: Brainpool end-to-end on the device path (platform `OpcardDispatch`
// → the US-944 software-Brainpool backend, `vendor/trussed-brainpool`).
// Mirrors `pso_secp256k1_device_path` for P-256r1 (P-512r1 stays
// unadvertised — no backend; US-945 pins its 6A80 rejection). Each curve
// pins the full lifecycle: attribute PUT (ECDSA sign + ECDH dec pair), PIN
// personalization, DEC-key import (private scalar; the card derives the
// public key), SIG-key GENERATE (7F49 with the uncompressed point),
// PSO:SIGN with the curve-sized prehash (host-verified with the bp*
// primitives + tamper negative), the `pso.rs` data-length gate (wrong-size
// digest → 6985, observed), and PSO:DECIPHER ECDH returning the exact
// x-coordinate shared secret.
//
// US-966 (2026-09-27): this suite was executed with **both** P-256r1 and
// P-384r1. P-384r1 is now deferred and its lifecycle test is inverted into
// `brainpool_p384r1_is_refused_device_path` below — same test, same dispatch,
// opposite assertion. The P-256r1 suite below is unchanged.

/// Brainpool attribute bytes (types.rs `*_BRAINPOOL_*_ATTRIBUTES`).
const BP256R1_SIGN_ATTR: &[u8] = &hex!("132b2403030208010107");
const BP256R1_DEC_ATTR: &[u8] = &hex!("122b2403030208010107");
/// US-966: kept as byte constants because the refusal test still needs to
/// name the exact spellings it is refusing. The `bp384` crate behind them is
/// gone from this crate's dev-dependencies.
const BP384R1_SIGN_ATTR: &[u8] = &hex!("132b240303020801010b");
const BP384R1_DEC_ATTR: &[u8] = &hex!("122b240303020801010b");

/// PUT KEY (INS DB, P1P2 3FFF) with the private-only ECC template
/// (`4D <len> CRT 7F48 92 <len> 5F48 <len> <scalar>`); opcard derives the
/// public key from the injected scalar through the backend.
fn import_ec(dispatcher: &mut Dispatcher<'_, 1>, slot: u8, scalar: &[u8]) {
    let mut data = vec![slot, 0];
    data.extend_from_slice(&[0x7f, 0x48, 0x02, 0x92, scalar.len() as u8]);
    data.extend_from_slice(&[0x5f, 0x48, scalar.len() as u8]);
    data.extend_from_slice(scalar);
    let mut blob = vec![0x4d, data.len() as u8];
    blob.extend_from_slice(&data);
    command(dispatcher, 0xdb, 0x3f, 0xff, &blob, 0x9000);
}

/// Deterministic Brainpool P-256r1 scalar (top byte masked well below the
/// curve order `A9FB 57DB …`).
fn bp256_scalar(seed: &[u8]) -> [u8; 32] {
    let mut s: [u8; 32] = Sha256::digest(seed).into();
    s[0] &= 0x1f;
    s
}

// US-966: `bp384_scalar` (the 48-byte equivalent, over Sha384) is gone with the
// curve. It had exactly one caller — the P-384r1 lifecycle suite — and a
// scalar generator for a curve nothing signs is not something to keep alive
// for a future release; restoring it is one function.

/// US-946, device path: Brainpool P-256r1 lifecycle.
#[test]
fn pso_brainpool_p256r1_device_path() {
    use bp256::r1::BrainpoolP256r1;
    use bp256::elliptic_curve::sec1::ToSec1Point as _;
    use ecdsa::signature::hazmat::PrehashVerifier as _;

    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        // US-912: personalize first; the admin session carries through the
        // CHANGE REFERENCE DATA.
        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
        // Attribute pair: secp256k1-style C1 (sign) / C2 (dec) PUTs.
        command(&mut dispatcher, 0xda, 0, 0xc1, BP256R1_SIGN_ATTR, 0x9000);
        command(&mut dispatcher, 0xda, 0, 0xc2, BP256R1_DEC_ATTR, 0x9000);

        // DEC key by import (known scalar → exact ECDH bytes later).
        let dec_scalar = bp256_scalar(b"fapico2-us946-bp256-dec");
        import_ec(&mut dispatcher, 0xb8, &dec_scalar);

        // SIG key by GENERATE — keygen/derive/serialize through the
        // Brainpool backend on the device dispatch.
        let gen = command(&mut dispatcher, 0x47, 0x80, 0, &[0xb6, 0], 0x9000);
        let idx = gen
            .windows(2)
            .position(|w| w == [0x86, 0x41])
            .expect("GENERATE reply must carry an 86 41 (65-byte point) public key");
        assert_eq!(gen[idx + 2], 0x04, "point must be uncompressed");
        let public = bp256::elliptic_curve::PublicKey::<BrainpoolP256r1>::from_sec1_bytes(
            &gen[idx + 2..idx + 2 + 65],
        )
        .expect("GENERATE reply must be a valid Brainpool P-256r1 point");
        let verifying = ecdsa::VerifyingKey::<BrainpoolP256r1>::from(&public);

        // PSO:SIGN refused without PW1, then answers a verifying signature.
        reselect(&mut dispatcher);
        let digest = Sha256::digest(b"This is a test message.");
        command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x6982);
        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);

        // Wrong digest size (48 B offered to P-256r1): the pso.rs
        // data-length gate answers ConditionsOfUseNotSatisfied.
        let long: [u8; 48] = core::array::from_fn(|i| i as u8);
        command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &long, 0x6985);

        // The refused attempt still ends the sign session (pso.rs clears it
        // after the length gate), so VERIFY again before the real sign.
        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
        let signature = command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
        assert_eq!(signature.len(), 64);
        let signature =
            ecdsa::Signature::<BrainpoolP256r1>::from_slice(&signature).expect("valid r || s");
        verifying
            .verify_prehash(&digest, &signature)
            .expect("PSO:SIGN signature must verify on Brainpool P-256r1");
        let mut tampered = digest;
        tampered[0] ^= 1;
        assert!(verifying.verify_prehash(&tampered, &signature).is_err());

        // PSO:DECIPHER ECDH with exact expected shared secret (raw
        // x-coordinate — no KDF-DO yet, US-947).
        let eph_scalar = bp256_scalar(b"fapico2-us946-bp256-eph");
        let eph = bp256::elliptic_curve::SecretKey::<BrainpoolP256r1>::from_bytes(&eph_scalar.into())
            .expect("deterministic ephemeral scalar");
        let private =
            bp256::elliptic_curve::SecretKey::<BrainpoolP256r1>::from_bytes(&dec_scalar.into())
                .expect("deterministic DEC scalar");
        let expected = bp256::elliptic_curve::ecdh::diffie_hellman(
            private.to_nonzero_scalar(),
            eph.public_key().as_affine(),
        )
        .raw_secret_bytes()
        .to_vec();
        assert_eq!(expected.len(), 32);
        let eph_point = eph.public_key().to_sec1_point(false).as_bytes().to_vec();
        let mut data = hex!("a6467f49438641").to_vec();
        data.extend_from_slice(&eph_point);
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x6982);
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x9000),
            expected
        );
    });
}

/// US-966 (2026-09-27), device path: Brainpool P-384r1 is **deferred**, and
/// this test is the inverted form of the US-946 P-384r1 lifecycle test it
/// replaces. The lifecycle it used to pin — 48-byte scalars, 97-byte
/// uncompressed points, a 48-byte prehash, a 96-byte signature, an exact ECDH
/// shared secret, and a 32-byte digest refused with 6985 — cannot be exercised
/// any more, because the attribute that selects the curve is refused at PUT.
///
/// What replaces it is the assertion that matters for a *removed* algorithm,
/// and it is deliberately more than "the old test is gone":
///
///  1. a P-384r1 attribute is refused `6A80` on all three usage tags;
///  2. the refusal leaves the stored attribute at its default, so a later
///     GENERATE runs under a curve the card does serve;
///  3. the 48-byte prehash the P-384r1 path needed is no longer a valid
///     digest size for *any* curve this card serves — the 6985 arm survives
///     in its inverted form, which is the one part of the old test that still
///     describes reachable behaviour;
///  4. `GET DATA FA` carries no P-384r1 record.
///
/// Points 1–2 are also pinned independently by `put_brainpool_attr_device_path`
/// (attribute shape) and by `advertise_serve.rs::DEFERRED` (the FA side,
/// read off the real device dispatch). This test adds point 3, which only
/// exists at the PSO layer.
#[test]
fn brainpool_p384r1_is_refused_device_path() {
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);

        // (1) Every P-384r1 spelling is refused. Under US-945 these three PUTs
        //     answered 9000 and the attributes were stored PK-normalized.
        for (tag, attr) in [
            (0xc1u8, BP384R1_SIGN_ATTR),
            (0xc2u8, BP384R1_DEC_ATTR),
            (0xc3u8, BP384R1_SIGN_ATTR),
        ] {
            command(&mut dispatcher, 0xda, 0, tag, attr, 0x6a80);
        }

        // (2) …and the stored attributes are still the factory defaults, not
        //     a half-written P-384r1 attribute.
        let stored = command(&mut dispatcher, 0xca, 0, 0xc1, &[], 0x9000);
        assert!(
            stored != hex!("132b240303020801010bff").as_slice(),
            "C1 must not have been rewritten to a P-384r1 attribute by a refused PUT"
        );

        // The card is still a working P-256r1 signer — the removal took the
        // curve, not the Brainpool backend.
        command(&mut dispatcher, 0xda, 0, 0xc1, BP256R1_SIGN_ATTR, 0x9000);
        import_ec(&mut dispatcher, 0xb8, &bp256_scalar(b"fapico2-us966-bp256-dec"));
        let gen = command(&mut dispatcher, 0x47, 0x80, 0, &[0xb6, 0], 0x9000);
        let idx = gen
            .windows(2)
            .position(|w| w == [0x86, 0x41])
            .expect("GENERATE must still answer a 65-byte P-256r1 point");
        assert_eq!(gen[idx + 2], 0x04, "point must be uncompressed");

        // (3) The 48-byte prehash the deferred P-384r1 path would have used is
        //     now a wrong-size digest for the only Brainpool curve served, so
        //     the pso.rs data-length gate answers 6985. Under US-946 this same
        //     48 bytes was the *correct* prehash for the selected curve.
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
        let digest48: [u8; 48] = Sha384::digest(b"This is a test message.").into();
        command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest48, 0x6985);
        // …and the 32-byte P-256r1 prehash still signs.
        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
        let digest32 = Sha256::digest(b"This is a test message.");
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest32, 0x9000).len(),
            64,
            "P-256r1 — the curve US-966 kept — must still produce a signature"
        );
    });
}

// ---------------------------------------------------------------------------
// US-947: KDF-DO (tag F9) on the device path (platform `OpcardDispatch` →
// the S-721-1 `SyscallRunner` client on the host backend).
//
// Structure/validation contract mirrors the virt-path tests in `dispatch.rs`
// (`kdf_do_put_validation_and_roundtrip_virt` et al.): gpg kdf-setup layout
// (90/110 B, `81 01 03 82 01 08|0A 83 04 <count> 84 08 <salt-U> … 87 20 <32>
// 88 20 <32>`), malformed PUT → 6A80 with the stored DO unchanged, and a
// byte-exact GET roundtrip. With a valid KDF-DO stored, PSO:DECIPHER ECDH
// still returns the **raw** shared point — the card stores the KDF
// parameters so the host can read them back and derive, because gpg derives
// the key-encryption key in software (`g10/ecdh.c` `derive_kek`). The
// pre-existing raw assertions above (no KDF-DO stored) are unchanged and
// keep passing.

/// A valid 110-byte KDF-DO in the exact layout gpg's kdf-setup writes
/// (duplicated from `dispatch.rs` — the test files share no module).
fn gpg_kdf_do(count: u32, salt_u: &[u8; 8], salt_r: &[u8; 8], salt_s: &[u8; 8]) -> Vec<u8> {
    gpg_kdf_do_with(count, salt_u, salt_r, salt_s, &[0x11; 32], &[0x22; 32])
}

/// The same TLV as [`gpg_kdf_do`], with the two 32-byte `87`/`88` blocks
/// (gpg writes the default-PIN derivations there) supplied explicitly. The
/// US-948 removal test needs two KDF-DOs that differ in *every* field, so
/// the KEK/IV material is a parameter there.
fn gpg_kdf_do_with(
    count: u32,
    salt_u: &[u8; 8],
    salt_r: &[u8; 8],
    salt_s: &[u8; 8],
    kek: &[u8; 32],
    iv: &[u8; 32],
) -> Vec<u8> {
    let mut d = vec![0x81, 0x01, 0x03, 0x82, 0x01, 0x08, 0x83, 0x04];
    d.extend_from_slice(&count.to_be_bytes());
    d.extend_from_slice(&[0x84, 0x08]);
    d.extend_from_slice(salt_u);
    d.extend_from_slice(&[0x85, 0x08]);
    d.extend_from_slice(salt_r);
    d.extend_from_slice(&[0x86, 0x08]);
    d.extend_from_slice(salt_s);
    d.extend_from_slice(&[0x87, 0x20]);
    d.extend_from_slice(kek);
    d.extend_from_slice(&[0x88, 0x20]);
    d.extend_from_slice(iv);
    d
}

/// Every secret-bearing field of a KDF-DO built by [`gpg_kdf_do_with`], in
/// one iterator: the three 8-byte salts and the two 32-byte `87`/`88`
/// blocks. US-948's replacement test uses it to assert that none of the
/// retired value's material survives anywhere the card still serves.
fn kdf_do_secrets<'a>(
    salts: &'a [[u8; 8]; 3],
    kek: &'a [u8; 32],
    iv: &'a [u8; 32],
) -> Vec<&'a [u8]> {
    salts
        .iter()
        .map(|s| s.as_slice())
        .chain([kek.as_slice(), iv.as_slice()])
        .collect()
}

/// True when `haystack` contains `secret` as a contiguous window.
fn contains_window(haystack: &[u8], secret: &[u8]) -> bool {
    haystack.windows(secret.len()).any(|w| w == secret)
}

/// Personalize a freshly selected card and install a P-256 ECDH key in
/// the DEC slot (B8).
///
/// US-912 refuses PSO/GENKEY while the factory PINs are in force, so the
/// two CRDs and the admin VERIFY have to come first; every US-947/US-948
/// P-256 case on this path starts exactly this way.
fn personalize_p256_dec(dispatcher: &mut Dispatcher<'_, 1>, scalar: &[u8; 32]) {
    command(dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
    command(dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
    command(dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
    command(dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
    command(dispatcher, 0xda, 0, 0xc2, P256_DEC, 0x9000);
    import(dispatcher, 0xb8, scalar);
}

/// The deterministic P-256 ECDH fixture shared by every US-947/US-948
/// P-256 case on this path.
///
/// `prefix` seeds two separate derivations — the card's private scalar
/// (`<prefix>-dec`) and the ephemeral key (`<prefix>-eph`) — so each test
/// gets its own key pair from a stable, reproducible label. The APDU body
/// carries the *generator point* as the ephemeral public key, i.e. an
/// ephemeral private key of 1, so `raw_z` can be recomputed here straight
/// from the scalar and the assertions stay independent of the firmware.
struct P256EcdhFixture {
    scalar: [u8; 32],
    /// PSO:DECIPHER body: `A6 46 <len> 7F 49 43 86 41 || 04 || G`
    body: Vec<u8>,
    /// The raw ECDH x-coordinate the card must return, computed here.
    raw_z: Vec<u8>,
}

fn p256_ecdh_fixture(prefix: &str) -> P256EcdhFixture {
    let mut scalar: [u8; 32] = Sha256::digest(format!("{prefix}-dec").as_bytes()).into();
    scalar[0] &= 0x1f; // well below the P-256 group order
    let eph = p256::SecretKey::from_slice(&Sha256::digest(format!("{prefix}-eph").as_bytes()))
        .expect("ephemeral scalar must be a valid P-256 scalar");
    let private = p256::SecretKey::from_slice(&scalar).expect("card scalar must be valid");
    let raw_z = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), private.public_key().as_affine())
        .raw_secret_bytes()
        .to_vec();
    let mut body = hex!("a6467f49438641").to_vec();
    body.extend_from_slice(eph.public_key().to_encoded_point(false).as_bytes());
    P256EcdhFixture { scalar, body, raw_z }
}

/// US-947, device path: per curve (P-256, secp256k1, X25519) — a valid
/// KDF-DO stored through PUT DATA F9 leaves PSO:DECIPHER ECDH on the raw
/// shared point; malformed KDF-DO PUTs are rejected with 6A80 without
/// touching the stored DO; GET DATA F9 roundtrips byte-exactly.
#[test]
fn pso_kdf_do_device_path() {
    const SECP_DEC: &[u8] = &hex!("122b8104000a");
    // --- P-256 -------------------------------------------------------------
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        let fx = p256_ecdh_fixture("fapico2-us947-p256");
        personalize_p256_dec(&mut dispatcher, &fx.scalar);
        let (z, data) = (fx.raw_z.clone(), fx.body.clone());

        // Malformed first: 6A80, and the factory default DO is untouched.
        command(&mut dispatcher, 0xda, 0, 0xf9, &[0x81, 0x01, 0x02], 0x6a80);
        command(&mut dispatcher, 0xda, 0, 0xf9, &[], 0x6a80);
        let mut truncated = gpg_kdf_do(1, &[0xA7; 8], &[0xB7; 8], &[0xC7; 8]);
        truncated.pop();
        command(&mut dispatcher, 0xda, 0, 0xf9, &truncated, 0x6a80);
        assert_eq!(
            command(&mut dispatcher, 0xca, 0, 0xf9, &[], 0x9000),
            &[0xF9, 0x03, 0x81, 0x01, 0x00]
        );

        // Valid KDF-DO (admin session from the PW3 verify above)…
        let salt_u = [0xA7u8; 8];
        let kdf = gpg_kdf_do(1, &salt_u, &[0xB7; 8], &[0xC7; 8]);
        command(&mut dispatcher, 0xda, 0, 0xf9, &kdf, 0x9000);
        // …roundtrips byte-exactly.
        assert_eq!(command(&mut dispatcher, 0xca, 0, 0xf9, &[], 0x9000), kdf);

        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x9000),
            z,
            "a stored KDF-DO must not change the raw ECDH x-coordinate"
        );
    });

    // --- secp256k1 ---------------------------------------------------------
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
        command(&mut dispatcher, 0xda, 0, 0xc2, SECP_DEC, 0x9000);
        let scalar: [u8; 32] = Sha256::digest(b"fapico2-us947-secp-dec").into();
        let mut scalar = scalar;
        scalar[0] &= 0x1f;
        import(&mut dispatcher, 0xb8, &scalar);

        let eph = k256::SecretKey::from_slice(&Sha256::digest(b"fapico2-us947-secp-eph")).unwrap();
        let private = k256::SecretKey::from_slice(&scalar).unwrap();
        let z = k256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), private.public_key().as_affine())
            .raw_secret_bytes()
            .to_vec();
        let mut data = hex!("a6467f49438641").to_vec();
        data.extend_from_slice(eph.public_key().to_encoded_point(false).as_bytes());

        let salt_u = [0x5Au8; 8];
        command(&mut dispatcher, 0xda, 0, 0xf9, &gpg_kdf_do(1, &salt_u, &[0x6B; 8], &[0x7B; 8]), 0x9000);

        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x9000),
            z,
            "a stored KDF-DO must not change the raw ECDH x-coordinate"
        );
    });

    // --- X25519 ------------------------------------------------------------
    // Fixtures mirror the pinned X25519 case in `pso_sign_verify_device_path`.
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
        command(&mut dispatcher, 0xda, 0, 0xc2, CV, 0x9000);
        let cv = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let mut cv_import = cv;
        cv_import[0] &= 248;
        cv_import[31] = (cv_import[31] & 127) | 64;
        cv_import.reverse();
        import(&mut dispatcher, 0xb8, &cv_import);

        let eph = x25519_dalek::StaticSecret::from(<[u8; 32]>::from(Sha256::digest(
            b"fapico2-us947-x255-eph",
        )));
        let private = x25519_dalek::StaticSecret::from(cv);
        let z = private
            .diffie_hellman(&x25519_dalek::PublicKey::from(&eph))
            .as_bytes()
            .to_vec();
        let mut data = hex!("a6257f49228620").to_vec();
        data.extend_from_slice(x25519_dalek::PublicKey::from(&eph).as_bytes());

        let salt_u = [0x3Cu8; 8];
        command(&mut dispatcher, 0xda, 0, 0xf9, &gpg_kdf_do(1, &salt_u, &[0x4B; 8], &[0x5B; 8]), 0x9000);

        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x9000),
            z,
            "a stored KDF-DO must not change the raw X25519 shared secret"
        );
    });
}

/// US-959, device path: the RFC 6637 compact form of the X25519 external
/// public key (`0x40 || X`, 33 bytes) must be accepted and must reach the
/// X25519 backend as 32 bytes — the failure US-958 recorded on the live
/// RP2350 as `6A80` from `us958-decipher-0x40-probe.py`.
///
/// The reply stays the **raw** 32-byte x-coordinate, pinned deliberately:
/// gpg's scdaemon (`scd/app-openpgp.c` `do_decipher`) unconditionally
/// prepends `0x40` to a CV25519 slot's decipher reply, so a card that
/// tagged its own reply would hand `g10/ecdh.c` `extract_secret_x` 34 bytes
/// and trip its `point_nbytes < nshared` (33 < 34) `GPG_ERR_BAD_DATA`
/// guard. `ecc_read_pubkey` is the mirror image for the public-key DO —
/// the card answers `7F49 22 86 20` + 32 bytes and gpg adds the tag.
///
/// Fixture mirrors the pinned X25519 case in `pso_sign_verify_device_path`.
#[test]
fn x25519_decipher_accepts_rfc6637_format_tag_device_path() {
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
        command(&mut dispatcher, 0xda, 0, 0xc2, CV, 0x9000);
        let cv = hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let mut cv_import = cv;
        cv_import[0] &= 248;
        cv_import[31] = (cv_import[31] & 127) | 64;
        cv_import.reverse();
        import(&mut dispatcher, 0xb8, &cv_import);

        let eph = x25519_dalek::StaticSecret::from(<[u8; 32]>::from(Sha256::digest(
            b"fapico2-us959-x255-eph",
        )));
        let private = x25519_dalek::StaticSecret::from(cv);
        let z = private
            .diffie_hellman(&x25519_dalek::PublicKey::from(&eph))
            .as_bytes()
            .to_vec();

        // 1. RFC 6637 compact form: `A6 26 7F49 23 86 21 40 || X`.
        let mut tagged = hex!("a6267f4923862140").to_vec();
        tagged.extend_from_slice(x25519_dalek::PublicKey::from(&eph).as_bytes());
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        let shared = command(&mut dispatcher, 0x2a, 0x80, 0x86, &tagged, 0x9000);
        assert_eq!(
            shared.len(),
            32,
            "the reply must be the raw 32-byte x-coordinate, not 0x40||X: gpg's scdaemon prepends the tag itself"
        );
        assert_eq!(
            shared, z,
            "a 0x40-tagged ephemeral point must yield the same raw shared secret as the untagged one"
        );

        // 2. The untagged 32-byte form stays accepted and byte-identical —
        //    a super-set acceptance, not a swap.
        let mut untagged = hex!("a6257f49228620").to_vec();
        untagged.extend_from_slice(x25519_dalek::PublicKey::from(&eph).as_bytes());
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &untagged, 0x9000),
            z,
            "the untagged form must keep answering the same raw secret"
        );

        // 3. A 33-byte point that is not the `0x40` compact form is still
        //    refused: only the RFC 6637 CV25519 tag may be stripped.
        let mut wrong_tag = hex!("a6267f4923862141").to_vec();
        wrong_tag.extend_from_slice(x25519_dalek::PublicKey::from(&eph).as_bytes());
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        command(&mut dispatcher, 0x2a, 0x80, 0x86, &wrong_tag, 0x6a80);
    });
}

// US-948: KDF-DO (tag F9) *storage* behavior on the device path.
//
// US-947 pinned the protocol contract (structure validation, roundtrip);
// US-948 pins the storage contract the spec 3.4 §4.3.3 ("F9 shall be stored
// in non-volatile memory") requires:
//   1. reboot survival — the stored KDF-DO must come back byte-exactly after
//      a simulated power cycle (fresh app over the same persistent store, the
//      `device_pso.rs` reboot-store shape);
//   2. removal — the only gpg-visible removal is PUT DATA F9 = `81 01 00`
//      (kdf-setup off): the DO reads back as stored, and the decipher stays
//      on the raw shared point;
//   3. replacement — overwriting a stored KDF-DO retires the previous one:
//      none of the old salt / KEK / IV material is reachable from anything
//      the card will return, before or after a reboot
//      (`kdf_do_replace_retires_previous_material_device_path`);
//   4. storage-file removal (defensive probe) — with the backing `kdf_do`
//      file deleted at the trussed layer, GET DATA F9 answers the factory
//      default (`F9 03 81 01 00`).
//
// What "removed"/"retired" means here, precisely: the card stops *serving*
// the old value — GET DATA F9 answers with the new one and the old material
// appears in no response the card produces. It is **not** a claim about
// flash forensics. trussed's `remove_file` and its whole-file overwrite are
// logical operations that free littlefs2 blocks; they do not physically
// erase the flash, so an attacker with a raw flash dump could still find
// the old bytes in unallocated blocks. A physical-wipe guarantee would need
// an explicit erase pass over the freed blocks, which this stack does not
// provide.
//
// `HostStore::fresh()` is built *inside* the `store` closure, one leaked
// littlefs2 pair per simulated boot — the shape `pw_status_resume.rs:59`
// uses. Hoisting it out would share the RAM filesystem across all three
// boots, and a KDF-DO written to `Location::Volatile` would then still be
// there after the "reboot": the test would go green while proving nothing
// about non-volatility.

/// US-948, device path: KDF-DO survives a simulated reboot (fresh
/// `OpenPgpApp` over the same persistent store, three sessions) and PUT
/// `81 01 00` (gpg `kdf-setup off`) takes it out of service.
#[test]
fn kdf_do_reboot_survival_and_removal_device_path() {
    use fapico2_platform::trusted_backend::{
        dispatch::OpcardDispatch,
        host::{HostPlatform, HostStore, leak_buf, mount_fs},
        runner::with_backend,
    };

    let internal = leak_buf(256 * 4096);
    let store = || {
        let ram = HostStore::fresh();
        HostPlatform::with_store(HostStore::new(
            mount_fs::<256>(internal),
            ram.efs,
            ram.vfs,
        ))
    };

    // Fixtures mirror the pinned P-256 case in `pso_kdf_do_device_path`.
    let fx = p256_ecdh_fixture("fapico2-us948-p256");
    let (scalar, data, z) = (fx.scalar, fx.body, fx.raw_z);

    let salt_u = [0xE1u8; 8];
    let kdf = gpg_kdf_do(0x0001_86A0, &salt_u, &[0xE2; 8], &[0xE3; 8]);
    assert_eq!(kdf.len(), 110);

    // Session A: personalize, store the KDF-DO, check it roundtrips and the
    // decipher stays on the raw shared point within the same power cycle.
    with_backend(store(), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        personalize_p256_dec(&mut dispatcher, &scalar);
        command(&mut dispatcher, 0xda, 0, 0xf9, &kdf, 0x9000);
        assert_eq!(command(&mut dispatcher, 0xca, 0, 0xf9, &[], 0x9000), kdf);
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x9000),
            z,
            "a stored KDF-DO must not change the raw ECDH x-coordinate"
        );
    });

    // Session B: simulated reboot — fresh app over the same persistent
    // store, fresh RAM filesystem. The KDF-DO must return byte-exactly and
    // the decipher must still be raw (no re-PUT happened).
    with_backend(store(), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0xca, 0, 0xf9, &[], 0x9000),
            kdf,
            "KDF-DO must survive a reboot byte-exactly (spec 3.4 §4.3.3)"
        );
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x9000),
            z,
            "the raw decipher output must be identical after the reboot"
        );
    });

    // Session C: removal — PUT DATA F9 = `81 01 00` (gpg kdf-setup off) is
    // the only card-level removal path; it must store verbatim (read back
    // byte-exactly) and must leave the decipher on the raw shared point.
    with_backend(store(), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
        command(&mut dispatcher, 0xda, 0, 0xf9, &[0x81, 0x01, 0x00], 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0xca, 0, 0xf9, &[], 0x9000),
            vec![0x81, 0x01, 0x00],
            "KDF-off PUT must read back verbatim (stored, not deleted)"
        );
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x9000),
            z,
            "KDF-off must keep the raw shared secret"
        );
    });
}

/// **Acceptance criterion 3: a key GENERATED on the device survives a power
/// cycle, on the GENERATE path.**
///
/// The reboot test above proves the **import** path. `device_boot_order.rs`
/// — which the epic cites for criterion 3 — proves neither: it replays a
/// captured C-flash image and reads a **migrated** key. So the generate path had
/// no evidence at all, and this is it.
///
/// The question it asks is the one that was open: `gen.rs` creates the private
/// key at `Location::Volatile` (`vfs`, RAM, formatted on every boot), while the
/// public key and the state file are on flash. Does the card still sign after
/// the RAM filesystem dies?
///
/// It does, and not by accident. `State::set_key` ChaChaPoly-wraps the volatile
/// key with the PW1-derived user key into `signing_key.bin` **on flash** and
/// then `clear`s the plaintext handle (`state.rs:573-591`); the load path is the
/// mirror (`state.rs:640-692`). The plaintext therefore exists in RAM only
/// between GENERATE and the wrap, and again between VERIFY and the signature.
///
/// Two boots over one persistent store, a **fresh** RAM filesystem for the
/// second, and the signature is verified against the public key the first boot
/// returned — so a card that silently re-keyed, or served a stale public key,
/// fails here rather than passing on a matching length.
#[test]
fn a_generated_key_survives_a_power_cycle_on_the_generate_path() {
    use fapico2_platform::trusted_backend::{
        dispatch::OpcardDispatch,
        host::{HostPlatform, HostStore, leak_buf, mount_fs},
        runner::with_backend,
    };

    use k256::ecdsa::signature::hazmat::PrehashVerifier as K256PrehashVerifier;

    const SECP_SIGN: &[u8] = &hex!("132b8104000a");

    let internal = leak_buf(256 * 4096);
    let store = || {
        let ram = HostStore::fresh();
        HostPlatform::with_store(HostStore::new(
            mount_fs::<256>(internal),
            ram.efs,
            ram.vfs,
        ))
    };

    // Session A: personalize, then GENERATE the signing key on the device.
    let public = with_backend(store(), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
        command(&mut dispatcher, 0xda, 0, 0xc1, SECP_SIGN, 0x9000);

        let gen = command(&mut dispatcher, 0x47, 0x80, 0, &[0xb6, 0], 0x9000);
        let idx = gen
            .windows(2)
            .position(|w| w == [0x86, 0x41])
            .expect("GENERATE reply must carry an 86 41 public key");
        assert_eq!(gen[idx + 2], 0x04, "secp256k1 point must be uncompressed");
        let public = k256::PublicKey::from_sec1_bytes(&gen[idx + 2..idx + 2 + 65])
            .expect("GENERATE reply must be a valid secp256k1 point");

        // It signs in the same power cycle, so a later failure is the reboot's
        // doing and not a key that never worked.
        let digest = Sha256::digest(b"This is a test message.");
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x6982);
        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
        let signature = command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
        assert_eq!(signature.len(), 64, "a raw secp256k1 signature, not a DER one");
        let verifying = k256::ecdsa::VerifyingKey::from(&public);
        K256PrehashVerifier::verify_prehash(
            &verifying,
            &digest,
            &k256::ecdsa::Signature::from_slice(&signature).expect("valid secp256k1 signature"),
        )
        .expect("a generated key must sign in the power cycle that made it");

        public.to_encoded_point(false).as_bytes().to_vec()
    });

    // Session B: simulated reboot — fresh app, fresh RAM filesystem, same
    // persistent store. The key must still sign, with the same key.
    with_backend(store(), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);

        // READ PUBLIC KEY must return the key generated before the reboot.
        let read = command(&mut dispatcher, 0x47, 0x81, 0, &[0xb6, 0], 0x9000);
        let idx = read
            .windows(2)
            .position(|w| w == [0x86, 0x41])
            .expect("READ PUBLIC KEY reply must carry an 86 41 public key");
        assert_eq!(
            &read[idx + 2..idx + 2 + 65],
            &public[..],
            "the key after the reboot must be the key before it. A card that re-keyed, or that \
             served a stale public key, is not what this test is looking for",
        );

        // …and the private half still signs.
        let digest = Sha256::digest(b"This is a test message.");
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x6982);
        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
        let signature = command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
        let verifying = k256::ecdsa::VerifyingKey::from(
            &k256::PublicKey::from_sec1_bytes(&public).expect("valid point"),
        );
        K256PrehashVerifier::verify_prehash(
            &verifying,
            &digest,
            &k256::ecdsa::Signature::from_slice(&signature).expect("valid secp256k1 signature"),
        )
        .expect("a key GENERATED before the reboot must still sign after it");
    });
}

/// US-948, device path (defensive probe): the KDF-DO lives in the
/// `Location::Internal` file `kdf_do` — this test pins that by deleting
/// that exact file at the trussed layer and requiring GET DATA F9 to answer
/// the factory default (`F9 03 81 01 00`, the only DO with a default value),
/// the branch of `ArbitraryDO::load` taken when the file is missing.
#[test]
fn kdf_do_file_removal_falls_back_to_factory_default_device_path() {
    use fapico2_platform::trusted_backend::{
        dispatch::OpcardDispatch,
        host::{HostPlatform, HostStore, leak_buf, mount_fs},
        runner::with_backend,
    };
    use trussed_core::types::{Location, PathBuf};

    let internal = leak_buf(256 * 4096);
    let store = || {
        let ram = HostStore::fresh();
        HostPlatform::with_store(HostStore::new(
            mount_fs::<256>(internal),
            ram.efs,
            ram.vfs,
        ))
    };

    let fx = p256_ecdh_fixture("fapico2-us948-p256-file");
    let (scalar, data, z) = (fx.scalar, fx.body, fx.raw_z);

    let salt_u = [0xF1u8; 8];

    // Session A: store a valid KDF-DO.
    with_backend(store(), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        personalize_p256_dec(&mut dispatcher, &scalar);
        command(&mut dispatcher, 0xda, 0, 0xf9, &gpg_kdf_do(1, &salt_u, &[0xF2; 8], &[0xF3; 8]), 0x9000);
    });

    // Session B: delete the backing `kdf_do` file at the trussed layer
    // (storage-level removal; there is no card-level APDU that deletes a DO).
    with_backend(store(), OpcardDispatch::new(), "opcard", |mut client| {
        use trussed_core::FilesystemClient as _;
        let path = PathBuf::try_from("kdf_do").unwrap();
        trussed_core::syscall!(client.remove_file(Location::Internal, path));
    });

    // Session C: fresh app over the emptied store — factory default form on
    // GET, raw shared secret on decipher.
    with_backend(store(), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0xca, 0, 0xf9, &[], 0x9000),
            hex!("F903810100").to_vec(),
            "deleted KDF-DO file must answer the factory default form"
        );
        reselect(&mut dispatcher);
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x9000),
            z,
            "no stored KDF-DO must answer the raw shared secret"
        );
    });
}

/// US-948, device path: **replacement retires the previous KDF-DO.** The
/// review of this story noted that the "removal" requirement was only half
/// pinned — the old test asserted only that PUT DATA F9 = `81 01 00` reads
/// back verbatim, which proves the *off form* is stored, not that the
/// 110-byte value it replaced is gone. This one stores a full 110-byte
/// KDF-DO, overwrites it with a second one that differs in every field
/// (count, all three salts, KEK, IV), and requires that the first one's
/// material is not reachable from anything the card will serve — checked
/// live, after a simulated reboot, and against the backing file's own bytes
/// at the trussed layer.
///
/// Scope, stated precisely so the test is not read as a flash guarantee:
/// it pins *logical* removal. trussed's `remove_file`, and the whole-file
/// overwrite a second PUT DATA F9 performs, free littlefs2 blocks and
/// replace the file's contents; they do **not** physically erase the flash.
/// The old KDF-DO is therefore not proven unrecoverable from a raw flash
/// dump — nothing in this stack offers a secure-erase primitive, and a
/// physical-wipe guarantee would be a separate, larger story. What *is*
/// pinned is that the card never serves it again: no response, and no
/// surviving file content, contains any of the retired value's material.
#[test]
fn kdf_do_replace_retires_previous_material_device_path() {
    use fapico2_platform::trusted_backend::{
        dispatch::OpcardDispatch,
        host::{HostPlatform, HostStore, leak_buf, mount_fs},
        runner::with_backend,
    };
    use trussed_core::types::{Location, PathBuf};

    let internal = leak_buf(256 * 4096);
    let store = || {
        let ram = HostStore::fresh();
        HostPlatform::with_store(HostStore::new(
            mount_fs::<256>(internal),
            ram.efs,
            ram.vfs,
        ))
    };

    // Two 110-byte KDF-DOs with nothing in common, so "the old material is
    // gone" is checkable field by field rather than as one opaque blob.
    let old_salts: [[u8; 8]; 3] = [[0xA1; 8], [0xB1; 8], [0xC1; 8]];
    let old_kek = [0x5Au8; 32];
    let old_iv = [0xA5u8; 32];
    let old = gpg_kdf_do_with(0x0001_86A0, &old_salts[0], &old_salts[1], &old_salts[2],
                              &old_kek, &old_iv);
    let new = gpg_kdf_do(0x0002_0BB8, &[0xD7; 8], &[0xE7; 8], &[0xF7; 8]);
    assert_eq!(old.len(), 110);
    assert_eq!(new.len(), 110);
    let retired = kdf_do_secrets(&old_salts, &old_kek, &old_iv);
    // The two values must actually differ everywhere the test later probes,
    // otherwise "the retired material is gone" would be vacuously true.
    assert_ne!(old, new);
    for secret in &retired {
        assert!(
            !contains_window(&new, secret),
            "the replacement fixture must not share material with the retired one"
        );
    }

    // Assert that none of the retired KDF-DO's secret material survives as a
    // contiguous window in `haystack`, and that the value is a full 110-byte
    // KDF-DO rather than a truncated remnant.
    let assert_retired = |haystack: &[u8], context: &str| {
        assert_eq!(haystack.len(), 110, "{context}: served value is not a full KDF-DO");
        for secret in &retired {
            assert!(
                !contains_window(haystack, secret),
                "{context}: retired KDF-DO material ({:02x?}…) is still reachable",
                &secret[..4]
            );
        }
    };

    // Session A: personalize and store the first KDF-DO.
    with_backend(store(), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        let fx = p256_ecdh_fixture("fapico2-us948-p256-repl");
        personalize_p256_dec(&mut dispatcher, &fx.scalar);
        command(&mut dispatcher, 0xda, 0, 0xf9, &old, 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0xca, 0, 0xf9, &[], 0x9000),
            old,
            "the first KDF-DO must be served back before it is replaced"
        );
    });

    // Session B: overwrite it. The serving session must return the new
    // value and nothing of the old one.
    with_backend(store(), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
        command(&mut dispatcher, 0xda, 0, 0xf9, &new, 0x9000);
        let served = command(&mut dispatcher, 0xca, 0, 0xf9, &[], 0x9000);
        assert_eq!(served, new, "GET DATA F9 must answer the replacement value");
        assert_retired(&served, "immediately after the PUT");
    });

    // Session C: the backing file itself must hold only the new value —
    // the replacement is a whole-file overwrite, not an in-place edit that
    // leaves the retired bytes behind in the stored blob.
    with_backend(store(), OpcardDispatch::new(), "opcard", |mut client| {
        use trussed_core::FilesystemClient as _;
        let path = PathBuf::try_from("kdf_do").unwrap();
        let stored = trussed_core::syscall!(client.read_file(Location::Internal, path)).data;
        assert_eq!(
            stored.as_slice(),
            new.as_slice(),
            "the stored kdf_do file must hold only the new value"
        );
        for secret in &retired {
            assert!(
                !contains_window(&stored, secret),
                "the stored kdf_do file still contains retired KDF-DO material"
            );
        }
    });

    // Session D: reboot — the retired value must not resurface from a
    // stale block once the filesystem is remounted over the same flash.
    with_backend(store(), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        let served = command(&mut dispatcher, 0xca, 0, 0xf9, &[], 0x9000);
        assert_eq!(served, new, "the replacement value must survive the reboot");
        assert_retired(&served, "after the reboot");
    });
}

// ---------------------------------------------------------------------------
// US-950, device path: the AES encipher/decipher roundtrip over the S-721-1
// no_std `SyscallRunner` client on the host backend — the exact client type
// the RP2350 device builds. The virt-path twin
// (`dispatch.rs::aes_encipher_decipher_roundtrip_virt`) pins the algorithm;
// this one pins the *dispatch* claim: `Mechanism::Aes256Cbc` has no arm in
// the platform's `OpcardDispatch` (it falls through to the trussed core
// backend, `dispatch.rs::BACKENDS` last entry), so a device build could in
// principle reach PSO:ENCIPHER and get a backend error while the virt path
// — which routes through opcard's own virt dispatch — stayed green. The
// Extended Capabilities DO (GET DATA `00 C0`, first byte `0x7F`) advertises
// the "AES ENC/DEC" bit (`0x20`) to every host regardless of path, so the
// device path has to honour it too.

// `pso_encipher_apdu` and `aes256_cbc_zero_iv_encrypt` come from
// `tests/common/mod.rs` (US-950 M3) — the virt twin in `dispatch.rs` must
// drive the identical request against the identical host-computed reference
// cipher, and a copy-pasted pair can silently drift.

#[test]
fn aes_encipher_decipher_roundtrip_device_path() {
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x83, b"12345678", 0x9000);

        // US-912: PSO is refused while the factory PINs are in force; the
        // CRD pair personalizes PW1/PW3 and keeps the admin session, so the
        // PUT DATA D5 import below still runs authorized.
        command(&mut dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
        command(&mut dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);

        // Honesty, negative side: with no AES key provisioned the encipher
        // path must refuse (the wrapped-key load has nothing to unwrap)
        // rather than answer with a zero-key ciphertext. The device path
        // needs this probe specifically — it is the path that must survive
        // the `OpcadDispatch` fallthrough for `Mechanism::Aes256Cbc`, so a
        // stub there (or a fallthrough reported as success) would be
        // invisible to the forward roundtrip alone. The virt twin pins the
        // same 6985 at the same point.
        command_apdu(&mut dispatcher, &pso_encipher_apdu(&[0x42; 16]), 0x6985);

        // Same 32-byte AES-256 payload key the virt twin imports.
        let aes_key: [u8; 32] = core::array::from_fn(|i| (i as u8) * 7 + 1);
        command(&mut dispatcher, 0xda, 0, 0xd5, &aes_key, 0x9000);

        // Two blocks so the CBC chain is actually chained (a single block
        // would pass even if the IV chaining were dropped).
        let plaintext: [u8; 32] = *b"fapico2-us950-aes-roundtrip!!!!!";
        let body = command_apdu(&mut dispatcher, &pso_encipher_apdu(&plaintext), 0x9000);
        assert_eq!(
            body.first(),
            Some(&0x02),
            "PSO:ENCIPHER must prefix the reply with the 02 padding indicator"
        );
        assert_eq!(
            &body[1..],
            aes256_cbc_zero_iv_encrypt(&aes_key, &plaintext).as_slice(),
            "PSO:ENCIPHER must be AES-256-CBC under the PUT DATA D5 key, zero IV, no padding"
        );

        // Round direction: the card's own `02 || ciphertext` fed back
        // through the decipher route returns the plaintext byte-exact.
        let back = command_apdu(&mut dispatcher, &pso_decipher_apdu(&body), 0x9000);
        assert_eq!(
            back,
            plaintext.as_slice(),
            "AES ENC/DEC must roundtrip the plaintext byte-exact on the device path"
        );

        // Encipher length guard, pinned: a DO that is not a whole number of
        // blocks is refused (6A80). The order is the opposite of what an
        // earlier version of this comment claimed ("before any key work"):
        // `encipher` resolves the wrapped AES key first (`pso.rs:553-561`)
        // and only then checks the length (`pso.rs:562-565`), so this
        // assertion holds because a key *is* provisioned by this point — the
        // 6985 probe above is the same request one step earlier in the
        // function. Unlike decipher the data field is *not* stripped of a
        // leading byte, so 17 bytes is the shortest non-multiple shape.
        command_apdu(&mut dispatcher, &pso_encipher_apdu(&[0x42; 17]), 0x6a80);
    });
}
