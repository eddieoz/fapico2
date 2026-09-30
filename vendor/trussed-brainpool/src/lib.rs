// SPDX-License-Identifier: GPL-3.0-or-later
//
// fapico2 US-944: software Brainpool trussed backend. Original fapico2 work —
// the crypto rides the bp256 crate (RustCrypto, elliptic-curve 0.14
// line) with the same request/response contract as the k256-based
// `trussed-secp256k1` backend (S-724). US-966 (2026-09-27) removed the
// P-384r1 half; see "P-384r1 is deferred" below.
//
//! Software Brainpool backend for trussed.
//!
//! Serves the `Mechanism::BrainpoolP256R1` (key generation, public-key
//! derivation, ECDH agreement, import) and
//! `Mechanism::BrainpoolP256R1Prehashed` (ECDSA over a 32-byte digest)
//! requests opcard issues for the OpenPGP Brainpool P-256r1 algorithm
//! attribute — the `2B 24 03 03 02 08 01 01 07` OID the C reference
//! firmware serves through mbedtls (`pico-openpgp/src/openpgp/do.c`,
//! `MBEDTLS_ECP_DP_BRAINPOOL_P256R1`).
//!
//! # P-384r1 is deferred (US-966, 2026-09-27)
//!
//! US-944 built this backend for **P-256r1 and P-384r1**, and US-945/946
//! shipped and verified both. US-966 — a post-close change to the
//! `EPIC-crypto-completion` epic, whose 28 stories had already closed
//! `Done-with-divergences` — removes the P-384r1 half and keeps P-256r1. The
//! reason is **deployment pull, not flash cost**:
//!
//! * OpenPGP card spec v3.4 §4.4.3.10 *recommends* the Brainpool curves but
//!   requires only that "at least one of this curves shall be supported",
//!   which NIST P-256/384/521 already satisfies. P-384r1 is never singled
//!   out.
//! * RFC 8734 deprecated Brainpool for TLS 1.3 "because they had little usage
//!   … not endorsed by the IETF"; every Brainpool row in the IANA TLS
//!   registry is `Recommended = N`.
//! * No OpenPGP-card user of P-384r1 was found, and the host stacks disagree:
//!   GnuPG's curve table carries Brainpool, OpenSC's card drivers have none.
//!
//! What P-384r1 is **not** being deferred for:
//!
//! * **Not for being defective.** The 14.47 s P-384r1 failure in the US-954
//!   hardware run is a host-side PC/SC transaction ceiling, not a broken
//!   implementation: it recurs identically for RSA-4096 GENERATE while a
//!   *longer* 8.19 s NIST-P-384 GENERATE succeeds. P-384r1 **signing was
//!   never measured**. It worked on the host (US-946) and is deferred for
//!   lack of users.
//! * **Not for the flash it saved.** The `19.7 %` `.text` row in
//!   `docs/size-report.md` is labelled "`p384` + `bp384`", and `p384` is the
//!   **NIST** P-384 crate, independently advertised and untouched by this
//!   change. The measured per-crate saving is in the US-966 section of that
//!   document.
//!
//! # `Mechanism::BrainpoolP512R1` was never served
//!
//! No `bp512` crate exists in the Rust ecosystem (checked 2026-09-26), and
//! hand-rolling P-512r1 field arithmetic was rejected on
//! security-conservatism grounds. P-512r1 requests fall through this backend
//! to Core and error; US-945/946 keep the algorithm unadvertised. See
//! `docs/tasks/known-gate-divergences.md`.
//!
//! Wire contract (mirrors `trussed-secp256k1` and trussed's own NIST-curve
//! mechanisms, which opcard was written against):
//!
//! * secrets are stored as the N-byte big-endian scalar (`Secrecy::Secret`,
//!   `Kind::BrainpoolP256R1`);
//! * public keys are stored as SEC1 **compressed** points (33 bytes,
//!   `Secrecy::Public`);
//! * `KeySerialization::Raw` means the **untagged** `X || Y` affine pair in
//!   both directions (opcard strips/prepends the `0x04` header itself);
//! * `SignatureSerialization::Raw` means the **untagged** `r || s` pair;
//! * ECDH `agree` stores the N-byte x coordinate as `Kind::Shared(N)`.
//!
//! The backend is `no_std` and allocation-free: bp256's signing/agreement
//! paths run on the stack (fiat-crypto field arithmetic, primeorder point
//! arithmetic), so — like the secp256k1 backend and unlike the S-724 RSA side
//! — no heap is involved on the device.
//!
//! Note on the dependency line: there is no bp* release on the
//! elliptic-curve 0.13 line k256 uses, so this crate rides elliptic-curve
//! 0.14 / ecdsa 0.17 / rand_core 0.10 alongside. The only seam where that
//! shows is RNG trait versions — trussed's keystore hands out a rand_core 0.6
//! ChaCha8 RNG, which [`TrussedRng`] adapts to the rand_core 0.10
//! `TryCryptoRng` surface the bp*/ecdsa-0.17 signing calls require.

#![no_std]

#[cfg(test)]
extern crate std;

use bp256::r1::BrainpoolP256r1;
use rand_core_010 as rc10;
use trussed::backend::Backend;
use trussed::platform::Platform;
use trussed::service::ServiceResources;
use trussed::types::CoreContext;
use trussed_core::api::{Reply, Request};
use trussed_core::types::Mechanism;
use trussed_core::Error;

/// Which Brainpool mechanism a request targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CurveSelection {
    P256,
    P256Prehashed,
}

/// Classify a served mechanism; anything else yields
/// [`Error::RequestNotAvailable`] so the dispatcher falls through.
///
/// US-966: `Mechanism::BrainpoolP384R1{,Prehashed}` is in that "anything
/// else" set. The variant exists (opcard's `trussed-core` enables
/// `brainpoolp384r1` so the fail-closed `Algorithm` gate can name it), but
/// this backend no longer serves it and there is no `bp384` crate in the
/// dependency graph to serve it with.
fn select_mechanism(mechanism: Mechanism) -> Result<CurveSelection, Error> {
    match mechanism {
        Mechanism::BrainpoolP256R1 => Ok(CurveSelection::P256),
        Mechanism::BrainpoolP256R1Prehashed => Ok(CurveSelection::P256Prehashed),
        _ => Err(Error::RequestNotAvailable),
    }
}

/// Adapter from the trussed keystore's rand_core 0.6 RNG to the rand_core
/// 0.10 `TryCryptoRng` surface the bp*/ecdsa-0.17 signing calls require.
/// Infallible by construction (the underlying RNG is).
struct TrussedRng<'a, R>(&'a mut R)
where
    R: rand_core::CryptoRng + rand_core::RngCore;

impl<R> rc10::TryRng for TrussedRng<'_, R>
where
    R: rand_core::CryptoRng + rand_core::RngCore,
{
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

impl<R> rc10::TryCryptoRng for TrussedRng<'_, R> where R: rand_core::CryptoRng + rand_core::RngCore {}

/// Instantiate the per-curve (concrete) operations for one Brainpool curve.
/// Everything is expanded concretely — the elliptic-curve 0.14 SEC1 surface
/// (`ModulusSize`, `FromSec1Point`, `ToSec1Point`) is not provable for a
/// generic curve parameter.
macro_rules! brainpool_curve {
    ($mod_name:ident, $curve:ident, $coordinate_size:expr, $kind:expr $(,)?) => {
        mod $mod_name {
            use super::$curve;
            use super::TrussedRng;
            use elliptic_curve::ecdh::diffie_hellman;
            use elliptic_curve::sec1::ToSec1Point;
            use elliptic_curve::{Generate, PublicKey, SecretKey};
            use ecdsa::signature::hazmat::RandomizedPrehashSigner;
            use ecdsa::signature::{RandomizedSigner, Verifier};
            use trussed::key;
            use trussed::store::Keystore;
            use trussed_core::api::{reply, request};
            use trussed_core::types::{
                KeyId, KeySerialization, SerializedKey, Signature as RawSignature,
                SignatureSerialization,
            };
            use trussed_core::Error;

            /// The curve's coordinate/scalar size in bytes.
            pub(super) const COORDINATE_SIZE: usize = $coordinate_size;

            type Curve = $curve;
            /// The curve's scalar, serialized.
            type FieldBytes = elliptic_curve::FieldBytes<Curve>;

            fn load_secret_key(
                keystore: &mut impl Keystore,
                key_id: &KeyId,
            ) -> Result<SecretKey<Curve>, Error> {
                let key = keystore.load_key(key::Secrecy::Secret, Some($kind), key_id)?;
                let scalar_bytes = key.material.as_slice();
                if scalar_bytes.len() != COORDINATE_SIZE {
                    return Err(Error::InternalError);
                }
                let mut field_bytes = FieldBytes::default();
                field_bytes.copy_from_slice(scalar_bytes);
                SecretKey::<Curve>::from_bytes(&field_bytes).map_err(|_| Error::InternalError)
            }

            fn load_public_key(
                keystore: &mut impl Keystore,
                key_id: &KeyId,
            ) -> Result<PublicKey<Curve>, Error> {
                let key = keystore.load_key(key::Secrecy::Public, Some($kind), key_id)?;
                PublicKey::<Curve>::from_sec1_bytes(&key.material)
                    .map_err(|_| Error::InternalError)
            }

            /// The stored encoding of a public key: SEC1 compressed.
            fn sec1_point(
                public_key: &PublicKey<Curve>,
            ) -> elliptic_curve::sec1::Sec1Point<Curve> {
                public_key.to_sec1_point(true)
            }

            pub(super) fn generate_key(
                keystore: &mut impl Keystore,
                req: &request::GenerateKey,
            ) -> Result<reply::GenerateKey, Error> {
                let private_key =
                    SecretKey::<Curve>::generate_from_rng(&mut TrussedRng(keystore.rng()));

                let key_id = keystore.store_key(
                    req.attributes.persistence,
                    key::Secrecy::Secret,
                    key::Info::from($kind).with_local_flag(),
                    &private_key.to_bytes(),
                )?;

                Ok(reply::GenerateKey { key: key_id })
            }

            pub(super) fn derive_key(
                keystore: &mut impl Keystore,
                req: &request::DeriveKey,
            ) -> Result<reply::DeriveKey, Error> {
                let secret_key = load_secret_key(keystore, &req.base_key)?;
                let public_key = secret_key.public_key();

                let public_id = keystore.store_key(
                    req.attributes.persistence,
                    key::Secrecy::Public,
                    $kind,
                    sec1_point(&public_key).as_bytes(),
                )?;

                Ok(reply::DeriveKey { key: public_id })
            }

            pub(super) fn deserialize_key(
                keystore: &mut impl Keystore,
                req: &request::DeserializeKey,
            ) -> Result<reply::DeserializeKey, Error> {
                let public_key = match req.format {
                    KeySerialization::Raw => {
                        if req.serialized_key.len() != 2 * COORDINATE_SIZE {
                            return Err(Error::InvalidSerializedKey);
                        }

                        let mut serialized_key = [0u8; 2 * COORDINATE_SIZE + 1];
                        serialized_key[0] = 0x04;
                        serialized_key[1..].copy_from_slice(&req.serialized_key[..2 * COORDINATE_SIZE]);

                        PublicKey::<Curve>::from_sec1_bytes(&serialized_key)
                            .map_err(|_| Error::InvalidSerializedKey)?
                    }
                    KeySerialization::Sec1 => {
                        PublicKey::<Curve>::from_sec1_bytes(&req.serialized_key)
                            .map_err(|_| Error::InvalidSerializedKey)?
                    }
                    _ => return Err(Error::InvalidSerializationFormat),
                };

                let public_id = keystore.store_key(
                    req.attributes.persistence,
                    key::Secrecy::Public,
                    $kind,
                    sec1_point(&public_key).as_bytes(),
                )?;

                Ok(reply::DeserializeKey { key: public_id })
            }

            pub(super) fn serialize_key(
                keystore: &mut impl Keystore,
                req: &request::SerializeKey,
            ) -> Result<reply::SerializeKey, Error> {
                let key_id = req.key;
                let public_key = load_public_key(keystore, &key_id)?;

                let serialized_key = match req.format {
                    KeySerialization::Raw => {
                        let affine_point = public_key.to_sec1_point(false);
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
                            .extend_from_slice(sec1_point(&public_key).as_bytes())
                            .map_err(|_| Error::InternalError)?;
                        serialized_key
                    }
                    _ => return Err(Error::InvalidSerializationFormat),
                };

                Ok(reply::SerializeKey { serialized_key })
            }

            pub(super) fn unsafe_inject_key(
                keystore: &mut impl Keystore,
                req: &request::UnsafeInjectKey,
            ) -> Result<reply::UnsafeInjectKey, Error> {
                if req.raw_key.len() != COORDINATE_SIZE {
                    return Err(Error::InvalidSerializedKey);
                }

                let mut secret_scalar = FieldBytes::default();
                secret_scalar.copy_from_slice(&req.raw_key);
                let secret_key =
                    SecretKey::<Curve>::from_bytes(&secret_scalar)
                        .map_err(|_| Error::InvalidSerializedKey)?;

                let info = key::Info {
                    flags: key::Flags::SENSITIVE,
                    kind: $kind,
                };

                keystore
                    .store_key(
                        req.attributes.persistence,
                        key::Secrecy::Secret,
                        info,
                        &secret_key.to_bytes(),
                    )
                    .map(|key| reply::UnsafeInjectKey { key })
            }

            pub(super) fn sign(
                keystore: &mut impl Keystore,
                req: &request::Sign,
                prehashed: bool,
            ) -> Result<reply::Sign, Error> {
                let key_id = req.key;

                let secret_key = load_secret_key(keystore, &key_id)?;
                let signing_key = ecdsa::SigningKey::<Curve>::from(secret_key);
                let signature: ecdsa::Signature<Curve> = if prehashed {
                    if req.message.len() != COORDINATE_SIZE {
                        return Err(Error::InvalidSerializedRequest);
                    }
                    signing_key
                        .sign_prehash_with_rng(&mut TrussedRng(keystore.rng()), &req.message)
                        .map_err(|_| Error::InvalidSerializedRequest)?
                } else {
                    signing_key.sign_with_rng(&mut TrussedRng(keystore.rng()), &req.message)
                };

                let serialized_signature = match req.format {
                    SignatureSerialization::Asn1Der => {
                        let der = signature.to_der();
                        RawSignature::try_from(der.as_bytes())
                            .map_err(|_| Error::InvalidSerializationFormat)?
                    }
                    SignatureSerialization::Raw => RawSignature::try_from(
                        signature.to_bytes().as_slice(),
                    )
                    .map_err(|_| Error::InvalidSerializationFormat)?,
                    _ => {
                        return Err(Error::InvalidSerializationFormat);
                    }
                };

                Ok(reply::Sign { signature: serialized_signature })
            }

            pub(super) fn verify(
                keystore: &mut impl Keystore,
                req: &request::Verify,
            ) -> Result<reply::Verify, Error> {
                if !matches!(req.format, SignatureSerialization::Raw) {
                    return Err(Error::InvalidSerializationFormat);
                }
                if req.signature.len() != 2 * COORDINATE_SIZE {
                    return Err(Error::WrongSignatureLength);
                }

                let key_id = req.key;

                let public_key = load_public_key(keystore, &key_id)?;
                let verifying_key: ecdsa::VerifyingKey<Curve> = public_key.into();

                let signature = ecdsa::Signature::<Curve>::from_slice(&req.signature)
                    .map_err(|_| Error::InvalidSerializedRequest)?;

                let valid = verifying_key.verify(&req.message, &signature).is_ok();
                Ok(reply::Verify { valid })
            }

            pub(super) fn agree(
                keystore: &mut impl Keystore,
                req: &request::Agree,
            ) -> Result<reply::Agree, Error> {
                let private_id = req.private_key;
                let public_id = req.public_key;

                let secret_key = load_secret_key(keystore, &private_id)?;
                let public_key = load_public_key(keystore, &public_id)?;

                let shared = diffie_hellman(
                    secret_key.to_nonzero_scalar(),
                    public_key.as_affine(),
                );
                let mut shared_secret = [0u8; COORDINATE_SIZE];
                shared_secret.copy_from_slice(shared.raw_secret_bytes());
                drop(shared);

                let flags = if req.attributes.serializable {
                    key::Flags::SERIALIZABLE
                } else {
                    key::Flags::empty()
                };
                let info = key::Info {
                    kind: key::Kind::Shared(shared_secret.len()),
                    flags,
                };

                let key_id = keystore.store_key(
                    req.attributes.persistence,
                    key::Secrecy::Secret,
                    info,
                    &shared_secret,
                )?;

                Ok(reply::Agree { shared_secret: key_id })
            }

            pub(super) fn exists(
                keystore: &mut impl Keystore,
                req: &request::Exists,
            ) -> Result<reply::Exists, Error> {
                let key_id = req.key;
                let exists = keystore.exists_key(key::Secrecy::Secret, Some($kind), &key_id);
                Ok(reply::Exists { exists })
            }
        }
    };
}

brainpool_curve!(p256, BrainpoolP256r1, 32, key::Kind::BrainpoolP256R1);

/// Mechanisms served by this backend.
///
/// US-966: this list is the backend's *served* half, and it is deliberately
/// short. P-384r1 is deferred (crate docs) and P-512r1 never existed; neither
/// appears here in any configuration, because there is no feature that could
/// add them back. `mechanisms_exclude_deferred_curves` pins the absence.
pub const MECHANISMS: &[Mechanism] = &[
    Mechanism::BrainpoolP256R1,
    Mechanism::BrainpoolP256R1Prehashed,
];

/// Trussed [`Backend`] implementation adding Brainpool P-256r1 support.
///
/// This implementation is done in software (the `bp256` crate) and needs no
/// allocator. `Mechanism::BrainpoolP384R1` is not served (deferred by US-966)
/// and `Mechanism::BrainpoolP512R1` never was (no `bp512` crate exists — see
/// the crate docs and `docs/tasks/known-gate-divergences.md`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
pub struct SoftwareBrainpool;

impl Backend for SoftwareBrainpool {
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
            Request::GenerateKey(req) => match select_mechanism(req.mechanism)? {
                CurveSelection::P256 => {
                    p256::generate_key(&mut keystore, req).map(Reply::GenerateKey)
                }
                CurveSelection::P256Prehashed => Err(Error::MechanismInvalid),
            },
            Request::DeriveKey(req) => match select_mechanism(req.mechanism)? {
                CurveSelection::P256 => p256::derive_key(&mut keystore, req).map(Reply::DeriveKey),
                CurveSelection::P256Prehashed => Err(Error::MechanismInvalid),
            },
            Request::DeserializeKey(req) => match select_mechanism(req.mechanism)? {
                CurveSelection::P256 => {
                    p256::deserialize_key(&mut keystore, req).map(Reply::DeserializeKey)
                }
                CurveSelection::P256Prehashed => Err(Error::MechanismInvalid),
            },
            Request::SerializeKey(req) => match select_mechanism(req.mechanism)? {
                CurveSelection::P256 => {
                    p256::serialize_key(&mut keystore, req).map(Reply::SerializeKey)
                }
                CurveSelection::P256Prehashed => Err(Error::MechanismInvalid),
            },
            Request::UnsafeInjectKey(req) => match select_mechanism(req.mechanism)? {
                CurveSelection::P256 => {
                    p256::unsafe_inject_key(&mut keystore, req).map(Reply::UnsafeInjectKey)
                }
                CurveSelection::P256Prehashed => Err(Error::MechanismInvalid),
            },
            Request::Sign(req) => match select_mechanism(req.mechanism)? {
                CurveSelection::P256 => p256::sign(&mut keystore, req, false).map(Reply::Sign),
                CurveSelection::P256Prehashed => {
                    p256::sign(&mut keystore, req, true).map(Reply::Sign)
                }
            },
            Request::Verify(req) => match select_mechanism(req.mechanism)? {
                CurveSelection::P256 => p256::verify(&mut keystore, req).map(Reply::Verify),
                CurveSelection::P256Prehashed => {
                    // Prehashed verification is not part of the opcard
                    // contract (INTERNAL AUTHENTICATE only signs).
                    Err(Error::RequestNotAvailable)
                }
            },
            Request::Agree(req) => match select_mechanism(req.mechanism)? {
                CurveSelection::P256 => p256::agree(&mut keystore, req).map(Reply::Agree),
                CurveSelection::P256Prehashed => Err(Error::MechanismInvalid),
            },
            Request::Exists(req) => match select_mechanism(req.mechanism)? {
                CurveSelection::P256 => p256::exists(&mut keystore, req).map(Reply::Exists),
                CurveSelection::P256Prehashed => Err(Error::MechanismInvalid),
            },
            _ => Err(Error::RequestNotAvailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod support {
        use super::select_mechanism;
        use rand_chacha::ChaCha8Rng;
        use rand_core::SeedableRng as _;
        use std::vec::Vec;
        use trussed::key::{self, Flags, Info, Material};
        use trussed::store::Keystore;
        use trussed_core::types::{KeyId, Location, Mechanism, StorageAttributes};
        use trussed_core::{Error, Result};

        /// Minimal in-memory [`Keystore`] double: deterministic key IDs, no
        /// persistence, backed by a linear scan. Only what the backend uses.
        pub(super) struct FakeKeystore {
            rng: ChaCha8Rng,
            keys: Vec<(key::Secrecy, KeyId, key::Key)>,
            counter: u8,
        }

        impl FakeKeystore {
            pub(super) fn new(seed: u8) -> Self {
                Self {
                    rng: ChaCha8Rng::from_seed([seed; 32]),
                    keys: Vec::new(),
                    counter: 1,
                }
            }

            fn next_id(&mut self) -> KeyId {
                let id = KeyId::from_special(self.counter);
                self.counter += 1;
                id
            }

            pub(super) fn secret_material(&self, id: &KeyId) -> Vec<u8> {
                self.keys
                    .iter()
                    .find(|(secrecy, key_id, _)| {
                        *secrecy == key::Secrecy::Secret && key_id == id
                    })
                    .map(|(_, _, key)| key.material.as_slice().to_vec())
                    .unwrap()
            }
        }

        impl Keystore for FakeKeystore {
            fn store_key(
                &mut self,
                _location: Location,
                secrecy: key::Secrecy,
                info: impl Into<Info>,
                material: &[u8],
            ) -> Result<KeyId> {
                let mut info = info.into();
                if secrecy == key::Secrecy::Secret {
                    info.flags |= Flags::SENSITIVE;
                }
                let key = key::Key {
                    flags: info.flags,
                    kind: info.kind,
                    material: Material::try_from(material).map_err(|_| Error::InternalError)?,
                };
                let id = self.next_id();
                self.keys.push((secrecy, id, key));
                Ok(id)
            }

            fn exists_key(
                &self,
                secrecy: key::Secrecy,
                kind: Option<key::Kind>,
                id: &KeyId,
            ) -> bool {
                self.keys.iter().any(|(s, i, k)| {
                    *s == secrecy && i == id && kind.is_none_or(|kind| kind == k.kind)
                })
            }

            fn key_info(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<Info> {
                self.keys
                    .iter()
                    .find(|(s, i, _)| *s == secrecy && i == id)
                    .map(|(_, _, k)| Info { flags: k.flags, kind: k.kind })
            }

            fn delete_key(&self, _id: &KeyId) -> bool {
                false
            }

            fn clear_key(&self, _id: &KeyId) -> bool {
                false
            }

            fn delete_all(&self, _location: Location) -> Result<usize> {
                Ok(0)
            }

            fn load_key(
                &self,
                secrecy: key::Secrecy,
                kind: Option<key::Kind>,
                id: &KeyId,
            ) -> Result<key::Key> {
                self.keys
                    .iter()
                    .find(|(s, i, k)| {
                        *s == secrecy && i == id && kind.is_none_or(|kind| kind == k.kind)
                    })
                    .map(|(_, _, k)| k.clone())
                    .ok_or(Error::NoSuchKey)
            }

            fn overwrite_key(
                &self,
                _location: Location,
                _secrecy: key::Secrecy,
                _kind: key::Kind,
                _id: &KeyId,
                _material: &[u8],
            ) -> Result<()> {
                Err(Error::InternalError)
            }

            fn rng(&mut self) -> &mut ChaCha8Rng {
                &mut self.rng
            }

            fn location(&self, _secrecy: key::Secrecy, _id: &KeyId) -> Option<Location> {
                None
            }
        }

        pub(super) fn storage() -> StorageAttributes {
            StorageAttributes::new().set_persistence(Location::Volatile)
        }

        /// Deterministic test scalar of the given curve size: small,
        /// non-zero, below the curve order.
        pub(super) fn test_scalar(size: usize, salt: u8) -> Vec<u8> {
            (0..size)
                .map(|i| ((i as u8 + salt) % 13) + 1)
                .collect()
        }

        /// US-966: P-384r1 moved from the served set to the *deferred* set, so
        /// the assertion about it is inverted rather than deleted — the failure
        /// this test exists to catch is a deferred curve quietly becoming
        /// servable again. P-512r1 has been unserved since US-944 (no bp512
        /// crate); so is everything else this backend does not own.
        ///
        /// `brainpoolp384r1`/`brainpoolp512r1` are enabled under
        /// `[dev-dependencies]` in Cargo.toml precisely so these variants can
        /// be named here at all.
        #[test]
        fn selection_rejects_unserved_mechanisms() {
            assert!(select_mechanism(Mechanism::BrainpoolP256R1).is_ok());
            assert!(select_mechanism(Mechanism::BrainpoolP256R1Prehashed).is_ok());
            assert_eq!(
                select_mechanism(Mechanism::BrainpoolP384R1),
                Err(Error::RequestNotAvailable),
                "Brainpool P-384r1 is deferred by US-966; this backend must not \
                 accept it in any configuration"
            );
            assert_eq!(
                select_mechanism(Mechanism::BrainpoolP384R1Prehashed),
                Err(Error::RequestNotAvailable),
                "the prehashed P-384r1 form is deferred with the curve (US-966)"
            );
            assert_eq!(
                select_mechanism(Mechanism::BrainpoolP512R1),
                Err(Error::RequestNotAvailable)
            );
            assert_eq!(
                select_mechanism(Mechanism::Secp256k1),
                Err(Error::RequestNotAvailable)
            );
            assert_eq!(
                select_mechanism(Mechanism::P256),
                Err(Error::RequestNotAvailable)
            );
        }
    }

    /// US-966: the *served* list must not name a deferred curve.
    ///
    /// This is the second half of the removal assertion, and it is deliberately
    /// not the same check as `selection_rejects_unserved_mechanisms` above:
    /// that one reads the classifier, this one reads the list the platform
    /// dispatch and any capability report would consult. A P-384r1 mechanism
    /// could be absent from the classifier's accepted set and still present
    /// here, which is a different bug with a different blast radius.
    #[test]
    fn mechanisms_exclude_deferred_curves() {
        assert!(
            MECHANISMS.contains(&Mechanism::BrainpoolP256R1),
            "P-256r1 stays served — it is the curve US-966 kept"
        );
        for deferred in [
            Mechanism::BrainpoolP384R1,
            Mechanism::BrainpoolP384R1Prehashed,
            Mechanism::BrainpoolP512R1,
        ] {
            assert!(
                !MECHANISMS.contains(&deferred),
                "{deferred:?} is deferred and must not appear in MECHANISMS"
            );
        }
        assert_eq!(
            MECHANISMS.len(),
            2,
            "MECHANISMS must be exactly the two P-256r1 forms"
        );
    }

    /// Per-curve test suite, expanded concretely for each curve.
    macro_rules! curve_tests {
        (
            $mod_name:ident,
            $curve_mod:ident,
            $curve:ident,
            $bp:ident,
            $mechanism:expr,
            $mechanism_prehashed:expr $(,)?
        ) => {
            mod $mod_name {
                use super::support::{storage, test_scalar, FakeKeystore};
                use crate::$curve_mod;
                use elliptic_curve::ecdh::diffie_hellman;
                use elliptic_curve::sec1::ToSec1Point;
                use ecdsa::signature::{Verifier as _, hazmat::PrehashVerifier as _};
                use elliptic_curve::SecretKey;
                use trussed::key::{self, Flags};
                use trussed::store::Keystore as _;
                use trussed_core::api::request;
                use trussed_core::types::{
                    KeyId, KeySerialization, Location, Mechanism, SerializedKey,
                    Signature as RawSignature, SignatureSerialization, StorageAttributes,
                };

                use $bp::r1::$curve;

                type FieldBytes = elliptic_curve::FieldBytes<$curve>;

                fn field_bytes(material: &[u8]) -> FieldBytes {
                    assert_eq!(material.len(), $curve_mod::COORDINATE_SIZE);
                    let mut fb = FieldBytes::default();
                    fb.copy_from_slice(material);
                    fb
                }

                /// Parse a raw (untagged r||s) signature into the bp*
                /// signature type.
                fn raw_signature(raw: &[u8]) -> ecdsa::Signature<$curve> {
                    let n = $curve_mod::COORDINATE_SIZE;
                    assert_eq!(raw.len(), 2 * n);
                    let mut r = FieldBytes::default();
                    let mut s = FieldBytes::default();
                    r.copy_from_slice(&raw[..n]);
                    s.copy_from_slice(&raw[n..]);
                    ecdsa::Signature::from_scalars(r, s).unwrap()
                }

                fn inject_request(scalar: &[u8]) -> request::UnsafeInjectKey {
                    request::UnsafeInjectKey {
                        mechanism: $mechanism,
                        raw_key: SerializedKey::try_from(scalar).unwrap(),
                        attributes: storage(),
                        format: KeySerialization::Raw,
                    }
                }

                #[test]
                fn keygen_derive_deterministic() {
                    let mut ks1 = FakeKeystore::new(7);
                    let mut ks2 = FakeKeystore::new(7);

                    let req = request::GenerateKey {
                        mechanism: $mechanism,
                        attributes: storage(),
                    };
                    let k1 = $curve_mod::generate_key(&mut ks1, &req).unwrap().key;
                    let k2 = $curve_mod::generate_key(&mut ks2, &req).unwrap().key;

                    // Same-seed RNGs must produce the same secret material.
                    assert_eq!(ks1.secret_material(&k1), ks2.secret_material(&k2));
                    let n = $curve_mod::COORDINATE_SIZE;
                    assert_eq!(ks1.secret_material(&k1).len(), n);

                    // The secret is stored under the curve's kind, LOCAL +
                    // SENSITIVE.
                    let info = ks1.key_info(key::Secrecy::Secret, &k1).unwrap();
                    assert_eq!(info.kind, kind());
                    assert!(info.flags.contains(Flags::LOCAL));
                    assert!(info.flags.contains(Flags::SENSITIVE));

                    // Derive the public key; check size, kind and equality
                    // with the bp* crate's own public-key derivation.
                    let derive = request::DeriveKey {
                        mechanism: $mechanism,
                        base_key: k1,
                        additional_data: None,
                        attributes: storage(),
                    };
                    let public_id = $curve_mod::derive_key(&mut ks1, &derive).unwrap().key;
                    let public = ks1
                        .load_key(
                            key::Secrecy::Public,
                            Some(kind()),
                            &public_id,
                        )
                        .unwrap();
                    // Stored compressed: 0x02/0x03 tag + one coordinate.
                    assert_eq!(public.material.len(), n + 1);

                    let secret =
                        SecretKey::<$curve>::from_bytes(&field_bytes(&ks1.secret_material(&k1)))
                            .unwrap();
                    let expected = secret.public_key().to_sec1_point(true);
                    assert_eq!(public.material.as_slice(), expected.as_bytes());

                    // Serialize the public key Raw (X || Y) and Sec1
                    // (compressed).
                    let ser_raw = request::SerializeKey {
                        mechanism: $mechanism,
                        key: public_id,
                        format: KeySerialization::Raw,
                    };
                    let raw = $curve_mod::serialize_key(&mut ks1, &ser_raw)
                        .unwrap()
                        .serialized_key;
                    assert_eq!(raw.len(), 2 * n);

                    let ser_sec1 = request::SerializeKey {
                        mechanism: $mechanism,
                        key: public_id,
                        format: KeySerialization::Sec1,
                    };
                    let sec1 = $curve_mod::serialize_key(&mut ks1, &ser_sec1)
                        .unwrap()
                        .serialized_key;
                    // Compressed SEC1: 0x02/0x03 tag + one coordinate.
                    assert_eq!(sec1.len(), n + 1);
                    assert_eq!(sec1.as_slice(), public.material.as_slice());

                    // Raw import of the same X||Y pair must land on the
                    // same point.
                    let de = request::DeserializeKey {
                        mechanism: $mechanism,
                        serialized_key: SerializedKey::try_from(raw.as_slice()).unwrap(),
                        format: KeySerialization::Raw,
                        attributes: storage(),
                    };
                    let imported_id = $curve_mod::deserialize_key(&mut ks1, &de).unwrap().key;
                    let imported = ks1
                        .load_key(key::Secrecy::Public, Some(kind()), &imported_id)
                        .unwrap();
                    assert_eq!(imported.material, public.material);

                    // Exists reports the secret.
                    let exists_req = request::Exists {
                        mechanism: $mechanism,
                        key: k1,
                    };
                    assert!($curve_mod::exists(&mut ks1, &exists_req).unwrap().exists);
                }

                #[test]
                fn sign_verify_roundtrip() {
                    let mut ks = FakeKeystore::new(11);
                    let n = $curve_mod::COORDINATE_SIZE;

                    let gen = request::GenerateKey {
                        mechanism: $mechanism,
                        attributes: storage(),
                    };
                    let key_id = $curve_mod::generate_key(&mut ks, &gen).unwrap().key;
                    // The backend's verify loads the stored public key, so
                    // derive it (as opcard does) before verifying.
                    let public_id = $curve_mod::derive_key(
                        &mut ks,
                        &request::DeriveKey {
                            mechanism: $mechanism,
                            base_key: key_id,
                            additional_data: None,
                            attributes: storage(),
                        },
                    )
                    .unwrap()
                    .key;

                    // Hash-then-sign over a message; Raw (r||s) verifies
                    // through the backend; Asn1Der yields a DER SEQUENCE.
                    let msg = trussed_core::types::Message::try_from(
                        b"fapico2 brainpool sign/verify roundtrip".as_slice(),
                    )
                    .unwrap();
                    let sign_raw = request::Sign {
                        mechanism: $mechanism,
                        key: key_id,
                        message: msg.clone(),
                        format: SignatureSerialization::Raw,
                    };
                    let raw_sig = $curve_mod::sign(&mut ks, &sign_raw, false)
                        .unwrap()
                        .signature;
                    assert_eq!(raw_sig.len(), 2 * n);

                    let verify_req = request::Verify {
                        mechanism: $mechanism,
                        key: public_id,
                        message: msg.clone(),
                        signature: RawSignature::try_from(raw_sig.as_slice()).unwrap(),
                        format: SignatureSerialization::Raw,
                    };
                    assert!($curve_mod::verify(&mut ks, &verify_req).unwrap().valid);

                    // A tampered message must not verify.
                    let mut tampered = msg.clone();
                    tampered[0] ^= 0x01;
                    let verify_bad = request::Verify {
                        mechanism: $mechanism,
                        key: public_id,
                        message: tampered,
                        signature: RawSignature::try_from(raw_sig.as_slice()).unwrap(),
                        format: SignatureSerialization::Raw,
                    };
                    assert!(!$curve_mod::verify(&mut ks, &verify_bad).unwrap().valid);

                    // Asn1Der format: DER SEQUENCE tag.
                    let sign_der = request::Sign {
                        mechanism: $mechanism,
                        key: key_id,
                        message: msg.clone(),
                        format: SignatureSerialization::Asn1Der,
                    };
                    let der_sig = $curve_mod::sign(&mut ks, &sign_der, false)
                        .unwrap()
                        .signature;
                    assert!(der_sig.len() > 2 * n / 3);
                    assert_eq!(der_sig[0], 0x30);

                    // Cross-check against the bp* crate primitives: the
                    // backend's raw signature parses into a bp* signature
                    // the bp* VerifyingKey accepts.
                    let secret = SecretKey::<$curve>::from_bytes(&field_bytes(
                        &ks.secret_material(&key_id),
                    ))
                    .unwrap();
                    let verifying = ecdsa::VerifyingKey::<$curve>::from(secret.public_key());
                    let parsed = raw_signature(&raw_sig);
                    verifying
                        .verify(&msg, &parsed)
                        .expect("backend signature verified by bp* primitives");

                    // And a directly-constructed bp* SigningKey signs
                    // something the bp* VerifyingKey accepts (primitives
                    // sanity).
                    use ecdsa::signature::Signer as _;
                    let signing = ecdsa::SigningKey::<$curve>::from(secret);
                    let direct_sig: ecdsa::Signature<$curve> = signing.sign(&msg);
                    verifying.verify(&msg, &direct_sig).expect("bp* primitives verify");
                }

                #[test]
                fn sign_verify_prehashed() {
                    let mut ks = FakeKeystore::new(13);
                    let n = $curve_mod::COORDINATE_SIZE;

                    let gen = request::GenerateKey {
                        mechanism: $mechanism,
                        attributes: storage(),
                    };
                    let key_id = $curve_mod::generate_key(&mut ks, &gen).unwrap().key;

                    let mut digest = [0u8; 64];
                    for (i, b) in digest.iter_mut().take(n).enumerate() {
                        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
                    }
                    let sign_pre = request::Sign {
                        mechanism: $mechanism_prehashed,
                        key: key_id,
                        message: trussed_core::types::Message::try_from(&digest[..n])
                            .unwrap(),
                        format: SignatureSerialization::Raw,
                    };
                    let raw_sig = $curve_mod::sign(&mut ks, &sign_pre, true)
                        .unwrap()
                        .signature;
                    assert_eq!(raw_sig.len(), 2 * n);

                    // Wrong digest length must be rejected.
                    let sign_bad = request::Sign {
                        mechanism: $mechanism_prehashed,
                        key: key_id,
                        message: trussed_core::types::Message::try_from(&digest[..n - 1])
                            .unwrap(),
                        format: SignatureSerialization::Raw,
                    };
                    assert!($curve_mod::sign(&mut ks, &sign_bad, true).is_err());

                    // Verify the prehashed signature against the bp*
                    // primitives directly (the backend itself refuses
                    // prehashed verification).
                    let secret = SecretKey::<$curve>::from_bytes(&field_bytes(
                        &ks.secret_material(&key_id),
                    ))
                    .unwrap();
                    let verifying = ecdsa::VerifyingKey::<$curve>::from(secret.public_key());
                    let parsed = raw_signature(&raw_sig);
                    verifying
                        .verify_prehash(&digest[..n], &parsed)
                        .expect("prehashed signature verified by bp* primitives");
                }

                #[test]
                fn ecdh_against_primitives() {
                    let mut ks = FakeKeystore::new(17);
                    let n = $curve_mod::COORDINATE_SIZE;

                    // Inject two scalars, derive both publics.
                    let s1 = test_scalar(n, 1);
                    let s2 = test_scalar(n, 5);
                    let inj1 = inject_request(&s1);
                    let inj2 = inject_request(&s2);
                    let private1 = $curve_mod::unsafe_inject_key(&mut ks, &inj1)
                        .unwrap()
                        .key;
                    let private2 = $curve_mod::unsafe_inject_key(&mut ks, &inj2)
                        .unwrap()
                        .key;

                    let derive = |ks: &mut FakeKeystore, base: KeyId| {
                        $curve_mod::derive_key(
                            ks,
                            &request::DeriveKey {
                                mechanism: $mechanism,
                                base_key: base,
                                additional_data: None,
                                attributes: storage(),
                            },
                        )
                        .unwrap()
                        .key
                    };
                    let public1 = derive(&mut ks, private1);
                    let public2 = derive(&mut ks, private2);

                    // Agree(1, 2) via the backend.
                    let agree_req = request::Agree {
                        mechanism: $mechanism,
                        private_key: private1,
                        public_key: public2,
                        attributes: StorageAttributes::new()
                            .set_persistence(Location::Volatile)
                            .set_serializable(true),
                    };
                    let shared_id = $curve_mod::agree(&mut ks, &agree_req)
                        .unwrap()
                        .shared_secret;

                    let shared = ks
                        .load_key(
                            key::Secrecy::Secret,
                            Some(key::Kind::Shared(n)),
                            &shared_id,
                        )
                        .unwrap();
                    assert_eq!(shared.material.len(), n);
                    // Serializable agreement results carry SERIALIZABLE.
                    assert!(shared.flags.contains(Flags::SERIALIZABLE));

                    // Compare against the bp* crate's own diffie_hellman.
                    let sk1 = SecretKey::<$curve>::from_bytes(&field_bytes(
                        &ks.secret_material(&private1),
                    ))
                    .unwrap();
                    let sk2 = SecretKey::<$curve>::from_bytes(&field_bytes(
                        &ks.secret_material(&private2),
                    ))
                    .unwrap();
                    let expected =
                        diffie_hellman(sk1.to_nonzero_scalar(), sk2.public_key().as_affine());
                    assert_eq!(
                        shared.material.as_slice(),
                        expected.raw_secret_bytes().as_slice()
                    );

                    // The other side agrees on the same secret (symmetry
                    // smoke).
                    let agree_rev = request::Agree {
                        mechanism: $mechanism,
                        private_key: private2,
                        public_key: public1,
                        attributes: storage(),
                    };
                    let shared_rev = $curve_mod::agree(&mut ks, &agree_rev)
                        .unwrap()
                        .shared_secret;
                    let shared_rev = ks
                        .load_key(
                            key::Secrecy::Secret,
                            Some(key::Kind::Shared(n)),
                            &shared_rev,
                        )
                        .unwrap();
                    assert_eq!(shared.material, shared_rev.material);
                }

                fn kind() -> key::Kind {
                    // US-966: only P-256r1 remains, so this is no longer a
                    // branch — it used to fall through to
                    // `key::Kind::BrainpoolP384R1` for the 48-byte suite.
                    assert_eq!(
                        $curve_mod::COORDINATE_SIZE,
                        32,
                        "P-384r1 is deferred (US-966); a curve test other than \
                         P-256r1 has no crate behind it"
                    );
                    key::Kind::BrainpoolP256R1
                }
            }
        };
    }

    // US-966: the P-384r1 suite that used to be instantiated here is gone
    // with the curve. The removal is asserted from the outside by
    // `selection_rejects_unserved_mechanisms` and
    // `mechanisms_exclude_deferred_curves` above, and end-to-end by
    // `apps/openpgp/tests/device_pso.rs`
    // (`brainpool_p384r1_is_refused_device_path`), so the curve does not
    // simply stop being covered.
    curve_tests!(
        p256_tests,
        p256,
        BrainpoolP256r1,
        bp256,
        Mechanism::BrainpoolP256R1,
        Mechanism::BrainpoolP256R1Prehashed,
    );
}
