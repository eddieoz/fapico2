// SPDX-License-Identifier: GPL-3.0-or-later
//
// fapico2 S-724: software secp256k1 trussed backend. Original fapico2 work —
// the crypto follows the same RustCrypto elliptic-curve 0.13 APIs trussed's
// own p384/p521 mechanisms use (`vendor`-style parity with
// `trussed-rsa-alloc::SoftwareRsa`, which serves the RSA side of S-724).
//
//! Software secp256k1 backend for trussed.
//!
//! Serves the `Mechanism::Secp256k1` (key generation, public-key derivation,
//! ECDH agreement, import) and `Mechanism::Secp256k1Prehashed` (ECDSA over a
//! 32-byte digest) requests opcard issues for the OpenPGP
//! `EcDsaSecp256k1` / `EcDhSecp256k1` algorithm attributes — the `13 2B 81 04
//! 00 0A` / `12 2B 81 04 00 0A` DOs the C reference firmware serves through
//! mbedtls (`pico-openpgp/src/openpgp/do.c` `algorithm_attr_p256k1`,
//! `openpgp.c` `MBEDTLS_ECP_DP_SECP256K1`).
//!
//! Wire contract (mirrors trussed's own NIST-curve mechanisms, which opcard
//! was written against):
//!
//! * secrets are stored as the 32-byte big-endian scalar (`Secrecy::Secret`,
//!   `Kind::Secp256k1`);
//! * public keys are stored as SEC1 **compressed** points (33 bytes,
//!   `Secrecy::Public`, `Kind::Secp256k1`);
//! * `KeySerialization::Raw` means the **untagged** `X || Y` affine pair in
//!   both directions (opcard strips/prepends the `0x04` header itself);
//! * `SignatureSerialization::Raw` means the **untagged** `r || s` pair;
//! * ECDH `agree` stores the 32-byte x coordinate as
//!   `Kind::Shared(32)`.
//!
//! The backend is `no_std` and allocation-free: k256's signing/agreement
//! paths run on the stack, so — unlike the S-724 RSA side
//! (`trussed-rsa-alloc` over the arm static heap) — no heap is involved on
//! the device.

#![no_std]

use k256::ecdh::diffie_hellman;
use k256::ecdsa::signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};
use k256::ecdsa::signature::{RandomizedSigner, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{EncodedPoint, PublicKey, SecretKey};
use trussed::backend::Backend;
use trussed::key;
use trussed::platform::Platform;
use trussed::service::ServiceResources;
use trussed::store::Keystore;
use trussed::types::CoreContext;
use trussed_core::api::{reply, request, Reply, Request};
use trussed_core::types::{
    Bytes, KeyId, KeySerialization, Mechanism, SerializedKey, Signature as RawSignature,
    SignatureSerialization,
};
use trussed_core::Error;

/// The secp256k1 coordinate size (bytes).
const COORDINATE_SIZE: usize = 32;
/// The size of a stored secret (the scalar).
const SECRET_SIZE: usize = 32;
/// Cap for a serialized (compressed or not) SEC1 point.
const POINT_SIZE: usize = 2 * COORDINATE_SIZE + 1;

/// Mechanisms served by this backend.
pub const MECHANISMS: &[Mechanism] = &[Mechanism::Secp256k1, Mechanism::Secp256k1Prehashed];

/// Trussed [`Backend`] implementation adding secp256k1 support.
///
/// This implementation is done in software (the k256 crate) and needs no
/// allocator.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
pub struct SoftwareSecp256k1;

/// Whether the mechanism is the prehashed (digest-input) ECDSA variant.
fn prehashed_from_mechanism(mechanism: Mechanism) -> Result<bool, Error> {
    match mechanism {
        Mechanism::Secp256k1 => Ok(false),
        Mechanism::Secp256k1Prehashed => Ok(true),
        _ => Err(Error::RequestNotAvailable),
    }
}

fn load_secret_key(keystore: &mut impl Keystore, key_id: &KeyId) -> Result<SecretKey, Error> {
    let secret_scalar: [u8; SECRET_SIZE] = keystore
        .load_key(key::Secrecy::Secret, Some(key::Kind::Secp256k1), key_id)?
        .material
        .as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    SecretKey::from_bytes((&secret_scalar).into()).map_err(|_| Error::InternalError)
}

fn load_public_key(keystore: &mut impl Keystore, key_id: &KeyId) -> Result<PublicKey, Error> {
    let serialized_public_key = keystore
        .load_key(key::Secrecy::Public, Some(key::Kind::Secp256k1), key_id)?
        .material;

    PublicKey::from_sec1_bytes(&serialized_public_key).map_err(|_| Error::InternalError)
}

fn to_sec1_bytes(public_key: &PublicKey) -> Bytes<POINT_SIZE> {
    let encoded_point: EncodedPoint = public_key.to_encoded_point(true);
    Bytes::try_from(encoded_point.as_bytes()).expect("compressed secp256k1 point is 33 bytes")
}

fn generate_key(
    keystore: &mut impl Keystore,
    request: &request::GenerateKey,
) -> Result<reply::GenerateKey, Error> {
    let private_key = SecretKey::random(keystore.rng());

    let key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Secret,
        key::Info::from(key::Kind::Secp256k1).with_local_flag(),
        &private_key.to_bytes(),
    )?;

    Ok(reply::GenerateKey { key: key_id })
}

fn derive_key(
    keystore: &mut impl Keystore,
    request: &request::DeriveKey,
) -> Result<reply::DeriveKey, Error> {
    let secret_key = load_secret_key(keystore, &request.base_key)?;
    let public_key = secret_key.public_key();

    let public_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Public,
        key::Kind::Secp256k1,
        &to_sec1_bytes(&public_key),
    )?;

    Ok(reply::DeriveKey { key: public_id })
}

fn deserialize_key(
    keystore: &mut impl Keystore,
    request: &request::DeserializeKey,
) -> Result<reply::DeserializeKey, Error> {
    let public_key = match request.format {
        KeySerialization::Raw => {
            if request.serialized_key.len() != 2 * COORDINATE_SIZE {
                return Err(Error::InvalidSerializedKey);
            }

            let mut serialized_key = [4u8; POINT_SIZE];
            serialized_key[1..].copy_from_slice(&request.serialized_key[..2 * COORDINATE_SIZE]);

            PublicKey::from_sec1_bytes(&serialized_key).map_err(|_| Error::InvalidSerializedKey)?
        }
        KeySerialization::Sec1 => {
            PublicKey::from_sec1_bytes(&request.serialized_key)
                .map_err(|_| Error::InvalidSerializedKey)?
        }
        _ => return Err(Error::InvalidSerializationFormat),
    };

    let public_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Public,
        key::Kind::Secp256k1,
        &to_sec1_bytes(&public_key),
    )?;

    Ok(reply::DeserializeKey { key: public_id })
}

fn serialize_key(
    keystore: &mut impl Keystore,
    request: &request::SerializeKey,
) -> Result<reply::SerializeKey, Error> {
    let key_id = request.key;

    let public_key = load_public_key(keystore, &key_id)?;

    let serialized_key = match request.format {
        KeySerialization::Raw => {
            let affine_point = public_key.to_encoded_point(false);
            let mut serialized_key = SerializedKey::new();
            serialized_key
                .extend_from_slice(affine_point.x().ok_or(Error::InternalError)?)
                .map_err(|_| Error::InternalError)?;
            serialized_key
                .extend_from_slice(affine_point.y().ok_or(Error::InternalError)?)
                .map_err(|_| Error::InternalError)?;
            serialized_key
        }
        KeySerialization::Sec1 => {
            let mut serialized_key = SerializedKey::new();
            serialized_key
                .extend_from_slice(&to_sec1_bytes(&public_key))
                .map_err(|_| Error::InternalError)?;
            serialized_key
        }
        _ => return Err(Error::InvalidSerializationFormat),
    };

    Ok(reply::SerializeKey { serialized_key })
}

fn unsafe_inject_key(
    keystore: &mut impl Keystore,
    request: &request::UnsafeInjectKey,
) -> Result<reply::UnsafeInjectKey, Error> {
    if request.raw_key.len() != SECRET_SIZE {
        return Err(Error::InvalidSerializedKey);
    }

    let mut secret_scalar = [0u8; SECRET_SIZE];
    secret_scalar.copy_from_slice(&request.raw_key);
    let secret_key =
        SecretKey::from_bytes((&secret_scalar).into()).map_err(|_| Error::InvalidSerializedKey)?;

    let info = key::Info {
        flags: key::Flags::SENSITIVE,
        kind: key::Kind::Secp256k1,
    };

    keystore
        .store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            info,
            &secret_key.to_bytes(),
        )
        .map(|key| reply::UnsafeInjectKey { key })
}

fn sign(
    keystore: &mut impl Keystore,
    request: &request::Sign,
    prehashed: bool,
) -> Result<reply::Sign, Error> {
    let key_id = request.key;

    let secret_key = load_secret_key(keystore, &key_id)?;
    let signing_key = SigningKey::from(secret_key);
    let signature: Signature = if prehashed {
        if request.message.len() != COORDINATE_SIZE {
            return Err(Error::InvalidSerializedRequest);
        }
        signing_key
            .sign_prehash_with_rng(keystore.rng(), &request.message)
            .map_err(|_| Error::InvalidSerializedRequest)?
    } else {
        signing_key.sign_with_rng(keystore.rng(), &request.message)
    };

    let serialized_signature = match request.format {
        SignatureSerialization::Asn1Der => {
            let der = signature.to_der();
            RawSignature::try_from(der.as_bytes())
                .map_err(|_| Error::InvalidSerializationFormat)?
        }
        SignatureSerialization::Raw => RawSignature::try_from(&*signature.to_bytes())
            .map_err(|_| Error::InvalidSerializationFormat)?,
        _ => {
            return Err(Error::InvalidSerializationFormat);
        }
    };

    Ok(reply::Sign {
        signature: serialized_signature,
    })
}

fn verify(
    keystore: &mut impl Keystore,
    request: &request::Verify,
    prehashed: bool,
) -> Result<reply::Verify, Error> {
    if !matches!(request.format, SignatureSerialization::Raw) {
        return Err(Error::InvalidSerializationFormat);
    }
    if request.signature.len() != 2 * COORDINATE_SIZE {
        return Err(Error::WrongSignatureLength);
    }

    let key_id = request.key;

    let public_key = load_public_key(keystore, &key_id)?;
    let verifying_key: VerifyingKey = public_key.into();

    let signature =
        Signature::from_slice(&request.signature).map_err(|_| Error::InvalidSerializedRequest)?;

    let valid = if prehashed {
        // Secp256k1Prehashed: `message` is the 32-byte digest; verify it
        // directly against the raw r‖s signature (no re-hashing), mirroring
        // the `sign_prehash_with_rng` path in `sign`.
        if request.message.len() != COORDINATE_SIZE {
            return Err(Error::InvalidSerializedRequest);
        }
        verifying_key.verify_prehash(&request.message, &signature).is_ok()
    } else {
        verifying_key.verify(&request.message, &signature).is_ok()
    };
    Ok(reply::Verify { valid })
}

fn agree(
    keystore: &mut impl Keystore,
    request: &request::Agree,
) -> Result<reply::Agree, Error> {
    let private_id = request.private_key;
    let public_id = request.public_key;

    let secret_key = load_secret_key(keystore, &private_id)?;
    let public_key = load_public_key(keystore, &public_id)?;

    let shared_secret: [u8; COORDINATE_SIZE] = (*diffie_hellman(
        secret_key.to_nonzero_scalar(),
        public_key.as_affine(),
    )
    .raw_secret_bytes())
    .into();

    let flags = if request.attributes.serializable {
        key::Flags::SERIALIZABLE
    } else {
        key::Flags::empty()
    };
    let info = key::Info {
        kind: key::Kind::Shared(shared_secret.len()),
        flags,
    };

    let key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Secret,
        info,
        &shared_secret,
    )?;

    Ok(reply::Agree {
        shared_secret: key_id,
    })
}

fn exists(
    keystore: &mut impl Keystore,
    request: &request::Exists,
) -> Result<reply::Exists, Error> {
    let key_id = request.key;
    let exists = keystore.exists_key(key::Secrecy::Secret, Some(key::Kind::Secp256k1), &key_id);
    Ok(reply::Exists { exists })
}

impl Backend for SoftwareSecp256k1 {
    type Context = ();
    fn request<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        let mut keystore = resources.keystore(core_ctx.path.clone())?;
        match request {
            Request::DeriveKey(req) => {
                if prehashed_from_mechanism(req.mechanism)? {
                    return Err(Error::MechanismInvalid);
                }
                derive_key(&mut keystore, req).map(Reply::DeriveKey)
            }
            Request::DeserializeKey(req) => {
                if prehashed_from_mechanism(req.mechanism)? {
                    return Err(Error::MechanismInvalid);
                }
                deserialize_key(&mut keystore, req).map(Reply::DeserializeKey)
            }
            Request::SerializeKey(req) => {
                if prehashed_from_mechanism(req.mechanism)? {
                    return Err(Error::MechanismInvalid);
                }
                serialize_key(&mut keystore, req).map(Reply::SerializeKey)
            }
            Request::GenerateKey(req) => {
                if prehashed_from_mechanism(req.mechanism)? {
                    return Err(Error::MechanismInvalid);
                }
                generate_key(&mut keystore, req).map(Reply::GenerateKey)
            }
            Request::Sign(req) => {
                let prehashed = prehashed_from_mechanism(req.mechanism)?;
                sign(&mut keystore, req, prehashed).map(Reply::Sign)
            }
            Request::Verify(req) => {
                let prehashed = prehashed_from_mechanism(req.mechanism)?;
                verify(&mut keystore, req, prehashed).map(Reply::Verify)
            }
            Request::Agree(req) => {
                if prehashed_from_mechanism(req.mechanism)? {
                    return Err(Error::MechanismInvalid);
                }
                agree(&mut keystore, req).map(Reply::Agree)
            }
            Request::UnsafeInjectKey(req) => {
                if prehashed_from_mechanism(req.mechanism)? {
                    return Err(Error::MechanismInvalid);
                }
                unsafe_inject_key(&mut keystore, req).map(Reply::UnsafeInjectKey)
            }
            Request::Exists(req) => {
                prehashed_from_mechanism(req.mechanism)?;
                exists(&mut keystore, req).map(Reply::Exists)
            }
            _ => Err(Error::RequestNotAvailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng as _;
    use trussed_core::api::request;
    use trussed_core::types::{
        KeyId, KeySerialization, Location, Mechanism, SignatureSerialization, StorageAttributes,
    };

    const CAP: usize = 16;

    /// A single stored key. `Material` is a heapless `Bytes`, so the slot
    /// array is built with `from_fn` rather than a `[; N]` repeat.
    struct Slot {
        secrecy: trussed::key::Secrecy,
        id: KeyId,
        kind: trussed::key::Kind,
        material: trussed::key::Material,
    }

    /// In-memory [`Keystore`] double — deterministic key IDs, no
    /// persistence, fixed-capacity scan. Only what the backend touches.
    struct FakeKeystore {
        rng: rand_chacha::ChaCha8Rng,
        slots: [Option<Slot>; CAP],
        count: usize,
        counter: u8,
    }

    impl FakeKeystore {
        fn new(seed: u8) -> Self {
            Self {
                rng: rand_chacha::ChaCha8Rng::from_seed([seed; 32]),
                slots: core::array::from_fn(|_| None),
                count: 0,
                counter: 1,
            }
        }

        fn next_id(&mut self) -> KeyId {
            let id = KeyId::from_special(self.counter);
            self.counter += 1;
            id
        }

        fn secret_material(&self, id: &KeyId) -> [u8; 32] {
            let material = self
                .slots
                .iter()
                .flatten()
                .find(|s| s.secrecy == trussed::key::Secrecy::Secret && s.id == *id)
                .expect("injected key present")
                .material
                .as_slice();
            material.try_into().expect("secp256k1 scalar is 32 bytes")
        }
    }

    impl trussed::store::Keystore for FakeKeystore {
        fn store_key(
            &mut self,
            _location: Location,
            secrecy: trussed::key::Secrecy,
            info: impl Into<trussed::key::Info>,
            material: &[u8],
        ) -> trussed_core::Result<KeyId> {
            let info = info.into();
            let key_material = trussed::key::Material::try_from(material)
                .map_err(|_| Error::InternalError)?;
            let id = self.next_id();
            let idx = self.count;
            self.count += 1;
            self.slots[idx] = Some(Slot {
                secrecy,
                id,
                kind: info.kind,
                material: key_material,
            });
            Ok(id)
        }

        fn exists_key(
            &self,
            secrecy: trussed::key::Secrecy,
            kind: Option<trussed::key::Kind>,
            id: &KeyId,
        ) -> bool {
            self.slots.iter().flatten().any(|s| {
                s.secrecy == secrecy && s.id == *id && kind.is_none_or(|q| q == s.kind)
            })
        }

        fn key_info(&self, secrecy: trussed::key::Secrecy, id: &KeyId) -> Option<trussed::key::Info> {
            self.slots
                .iter()
                .flatten()
                .find(|s| s.secrecy == secrecy && s.id == *id)
                .map(|s| trussed::key::Info { flags: trussed::key::Flags::empty(), kind: s.kind })
        }

        fn delete_key(&self, _id: &KeyId) -> bool {
            false
        }

        fn clear_key(&self, _id: &KeyId) -> bool {
            false
        }

        fn delete_all(&self, _location: Location) -> trussed_core::Result<usize> {
            Ok(0)
        }

        fn load_key(
            &self,
            secrecy: trussed::key::Secrecy,
            kind: Option<trussed::key::Kind>,
            id: &KeyId,
        ) -> trussed_core::Result<trussed::key::Key> {
            self.slots
                .iter()
                .flatten()
                .find(|s| s.secrecy == secrecy && s.id == *id && kind.is_none_or(|q| q == s.kind))
                .map(|s| trussed::key::Key {
                    flags: trussed::key::Flags::empty(),
                    kind: s.kind,
                    material: s.material.clone(),
                })
                .ok_or(Error::NoSuchKey)
        }

        fn overwrite_key(
            &self,
            _location: Location,
            _secrecy: trussed::key::Secrecy,
            _kind: trussed::key::Kind,
            _id: &KeyId,
            _material: &[u8],
        ) -> trussed_core::Result<()> {
            Err(Error::InternalError)
        }

        fn rng(&mut self) -> &mut rand_chacha::ChaCha8Rng {
            &mut self.rng
        }

        fn location(&self, _secrecy: trussed::key::Secrecy, _id: &KeyId) -> Option<Location> {
            None
        }
    }

    fn storage() -> StorageAttributes {
        StorageAttributes::new().set_persistence(Location::Volatile)
    }

    fn inject(ks: &mut FakeKeystore, scalar: &[u8; 32]) -> KeyId {
        let req = request::UnsafeInjectKey {
            mechanism: Mechanism::Secp256k1,
            // `&[u8; 32]` → `Bytes` is infallible; the `try_from(..).unwrap()`
            // spelling trips `clippy::unnecessary_fallible_conversions`.
            raw_key: trussed_core::types::SerializedKey::from(scalar),
            attributes: storage(),
            format: KeySerialization::Raw,
        };
        unsafe_inject_key(ks, &req).unwrap().key
    }

    /// Derive the public key of an injected secret (what opcard does for the
    /// AUT slot before any `Verify` request).
    fn derive_public(ks: &mut FakeKeystore, key_id: KeyId) -> KeyId {
        derive_key(
            ks,
            &request::DeriveKey {
                mechanism: Mechanism::Secp256k1,
                base_key: key_id,
                additional_data: None,
                attributes: storage(),
            },
        )
        .unwrap()
        .key
    }

    /// A prehashed `Verify` over a `(digest, signature, public key)` triple.
    fn verify_prehashed(
        ks: &mut FakeKeystore,
        public_id: KeyId,
        digest: &[u8],
        signature: &RawSignature,
    ) -> Result<reply::Verify, Error> {
        let req = request::Verify {
            mechanism: Mechanism::Secp256k1Prehashed,
            key: public_id,
            message: trussed_core::types::Message::try_from(digest).unwrap(),
            signature: signature.clone(),
            format: SignatureSerialization::Raw,
        };
        verify(ks, &req, true)
    }

    /// US-949: the Secp256k1Prehashed `Verify` request now succeeds (the
    /// `RequestNotAvailable` refusal was removed) and rejects a tampered
    /// digest, a tampered `r`, a tampered `s` and the wrong public key; a
    /// wrong-length digest is rejected with the *length* error specifically.
    /// Cross-checked against the k256 primitives.
    #[test]
    fn verify_prehashed_succeeds_and_rejects_tampered() {
        let mut ks = FakeKeystore::new(7);
        let n = COORDINATE_SIZE;

        let scalar = [7u8; 32];
        let key_id = inject(&mut ks, &scalar);
        // `verify` loads the stored *public* key, so derive it first (as
        // opcard does for the AUT slot) before any verify request.
        let public_id = derive_public(&mut ks, key_id);
        let mut digest = [0u8; 32];
        for (i, b) in digest.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        let sign_req = request::Sign {
            mechanism: Mechanism::Secp256k1Prehashed,
            key: key_id,
            message: trussed_core::types::Message::from(&digest),
            format: SignatureSerialization::Raw,
        };
        let raw_sig = sign(&mut ks, &sign_req, true).unwrap().signature;
        assert_eq!(raw_sig.len(), 2 * n, "raw secp256k1 signature is r || s");

        assert!(
            verify_prehashed(&mut ks, public_id, &digest, &raw_sig).unwrap().valid,
            "a valid prehashed signature must verify"
        );

        // Tampered digest must not verify.
        let mut tampered = digest;
        tampered[0] ^= 1;
        assert!(
            !verify_prehashed(&mut ks, public_id, &tampered, &raw_sig).unwrap().valid,
            "a tampered digest must fail verification"
        );

        // Tampered `r` (first 32 B of `r || s`) must not verify.
        let mut sig_bytes: [u8; 2 * COORDINATE_SIZE] = raw_sig.as_slice().try_into().unwrap();
        sig_bytes[0] ^= 0x80;
        assert!(
            !verify_prehashed(&mut ks, public_id, &digest, &RawSignature::from(&sig_bytes))
                .unwrap()
                .valid,
            "a tampered r must fail verification"
        );

        // Tampered `s` (last 32 B) must not verify.
        let mut sig_bytes: [u8; 2 * COORDINATE_SIZE] = raw_sig.as_slice().try_into().unwrap();
        sig_bytes[n] ^= 0x80;
        assert!(
            !verify_prehashed(&mut ks, public_id, &digest, &RawSignature::from(&sig_bytes))
                .unwrap()
                .valid,
            "a tampered s must fail verification"
        );

        // The right signature under the wrong public key must not verify.
        let other_key = inject(&mut ks, &[8u8; 32]);
        let other_public = derive_public(&mut ks, other_key);
        assert!(
            !verify_prehashed(&mut ks, other_public, &digest, &raw_sig).unwrap().valid,
            "a signature must not verify under an unrelated public key"
        );

        // A wrong-length digest is rejected by the *length* gate, not by a
        // parse failure and not by a silent `valid: false`. The signature
        // here is the genuinely-signed one above, so the only thing that can
        // reject this request is the gate: deleting it lets k256 return
        // `valid: false` and this assertion fails. (The gate shares
        // `InvalidSerializedRequest` with the `r‖s` parse gate — a distinct
        // variant would move the device text by 8 B and force a UF2 +
        // size-report refresh, so the pairing carries the discrimination.)
        verify_prehashed(&mut ks, public_id, &digest[..n - 1], &raw_sig)
            .expect_err("a short digest must be rejected outright, not signed as false");

        // Cross-check against the k256 primitives directly.
        let secret = SecretKey::from_bytes(&ks.secret_material(&key_id).into()).unwrap();
        let verifying = VerifyingKey::from(secret.public_key());
        let parsed = Signature::from_slice(&raw_sig).expect("parses as raw secp256k1 sig");
        verifying
            .verify_prehash(&digest, &parsed)
            .expect("backend prehashed signature verified by k256 primitives");
    }

    /// US-949 (regression): the non-prehashed `Verify` path is unchanged —
    /// a raw sign still verifies with `prehashed = false`.
    #[test]
    fn verify_non_prehashed_still_works() {
        let mut ks = FakeKeystore::new(11);
        let key_id = inject(&mut ks, &[9u8; 32]);
        let public_id = derive_public(&mut ks, key_id);

        // A concrete `[u8; N]`, so the `Message` conversion is infallible.
        let message = *b"fapico2-secp256k1-prehashed-off";
        let sign_req = request::Sign {
            mechanism: Mechanism::Secp256k1,
            key: key_id,
            message: trussed_core::types::Message::from(&message),
            format: SignatureSerialization::Raw,
        };
        let raw_sig = sign(&mut ks, &sign_req, false).unwrap().signature;

        let verify_req = request::Verify {
            mechanism: Mechanism::Secp256k1,
            key: public_id,
            message: trussed_core::types::Message::from(&message),
            signature: raw_sig,
            format: SignatureSerialization::Raw,
        };
        assert!(
            verify(&mut ks, &verify_req, false).unwrap().valid,
            "the non-prehashed verify path must still succeed"
        );
    }
}
