//! Per-device attestation identity provisioning (US-916).
//!
//! The "packed" attestation statement format (CTAP2 makeCredential) and the
//! U2F registration path sign with an attestation key and return the matching
//! certificate in the `x5c` array. Historically that identity was a
//! repo-committed static pair (`attestation_key.bin` + `attestation_cert.der`,
//! `include_bytes!`-ed into every image) — the SAME key and cert shipped in
//! every device, in the repository, and in every firmware image.
//!
//! **US-916 replaces that with a per-device identity minted on the device:**
//!
//! * On the first boot with no `fido.attestation.v1.key` slot, a fresh P-256
//!   key is generated from the platform TRNG (US-380 sole randomness source),
//!   a minimal self-signed certificate is built **on the device**
//!   ([`crate::attestation_cert`], TRNG serial, sha256WithECDSA), and BOTH
//!   are persisted to the platform [`SecureStore`] — which is v3-AEAD-sealed
//!   automatically (US-915). Subsequent boots load the identity from the
//!   store.
//!
//! * Fail-closed: ONLY a `NotFound` key slot triggers provisioning. Any
//!   stored-but-invalid material (scalar that is not a valid P-256 key, cert
//!   record failing its CRC / chunked validation, wrong sizes) surfaces as
//!   [`SecureStoreError::Corrupt`] and the boot fails — a corrupt identity is
//!   never silently regenerated, mirroring the `hkey` boot contract (a
//!   silently rotated attestation key would break relying parties' trust in
//!   credentials already signed by the old identity).
//!
//! * Persistence commit discipline: on a fresh device the certificate is
//!   written first and the 32-byte scalar last — the scalar slot is the
//!   provisioning commit point (its `NotFound` is what triggers
//!   provisioning), so a crash between the two writes leaves the device in
//!   the "fresh" state (the orphaned cert generation is simply superseded by
//!   the next boot's new generation in the chunked double-buffer). If either
//!   write fails, `boot` fails (all-or-nothing — no half-provisioned
//!   identity is ever served).
//!
//! # Shared-attestation assumptions this BREAKS (by design)
//!
//! With the static pair, every token in a fleet attested identically, which
//! enabled several (questionable) conveniences:
//!
//! * **Fleet-wide trust**: a relying party could pin the single well-known
//!   cert and treat "signed by it" as "genuine fapico2 hardware". Per-device
//!   keys mean each device's cert is its own — trust in a *device class*
//!   would need a real PKI (batch attestation roots, directed RPC, or an
//!   enrollment service), none of which this firmware implements.
//! * **Batch revocation**: one repo-level key compromise invalidated every
//!   device at once. Per-device keys cannot be revoked centrally; a
//!   compromised device's identity lives and dies with that device.
//! * **Privacy / linkability**: the static cert made every device
//!   indistinguishable; the per-device cert (unique TRNG serial, unique key)
//!   makes each device's attestation DISTINCT across RPs and registrations.
//!   That is the privacy price of per-device provisioning — documented here
//!   and in [`crate::attestation_cert`] because the cert is now minted, not
//!   shipped.
//!
//! The cert buffer is sized by [`ATTEST_CERT_MAX`]; the DER is persisted
//! through the chunked API (`fapico2_platform::secure_store::chunked`)
//! because the device physical slot value cap is 512 B and future shape
//! changes must not depend on that bound (logical chunked cap: 5,952 B — US-1010;
//! see `fapico2_platform::secure_store::chunked::MAX_PARTS` for why that is the
//! ceiling and not 8,432 B).

use p256::SecretKey;

use fapico2_platform::secure_store::{chunked, SecureStore, SecureStoreError};
use fapico2_platform::trng::Trng;

/// Plain (32-byte) slot holding the attestation private scalar.
pub const ATTEST_KEY_SLOT: &[u8] = b"fido.attestation.v1.key";
/// Chunked slot holding the self-signed attestation certificate (DER).
pub const ATTEST_CERT_SLOT: &[u8] = b"fido.attestation.v1.cert";

/// Upper bound of a generated attestation certificate (see
/// [`crate::attestation_cert::CERT_MAX`]).
pub const ATTEST_CERT_MAX: usize = crate::attestation_cert::CERT_MAX;

/// The provisioned per-device attestation identity: the signing key plus its
/// self-signed certificate (DER, ≤ [`ATTEST_CERT_MAX`] bytes).
///
/// Cached in the app structs (device [`crate::FidoApp`] after
/// [`provision`]/`boot`; host twin at construction) the same way `hkey` is,
/// so the U2F register and makeCredential paths sign with the loaded
/// identity instead of a repo static.
#[derive(Debug, Clone)]
pub struct AttestationIdentity {
    key: SecretKey,
    cert: heapless::Vec<u8, ATTEST_CERT_MAX>,
}

impl AttestationIdentity {
    /// The attestation signing key (the private scalar).
    pub fn key(&self) -> &SecretKey {
        &self.key
    }

    /// The self-signed attestation certificate (DER bytes).
    pub fn cert_bytes(&self) -> &[u8] {
        &self.cert
    }

    /// Mint a fresh identity: TRNG key + on-device self-signed cert with a
    /// TRNG serial. Generic over the platform [`Trng`] so the same seam the
    /// rest of the app uses (US-380 sole randomness source) feeds the key
    /// generation and the serial — every entropy byte comes from the TRNG.
    pub fn generate_from(trng: &mut impl Trng) -> Self {
        let mut adapter = crate::crypto::TrngAdapter(trng);
        let key = SecretKey::random(&mut adapter);
        // The builder is statically bounded (CERT_MAX = 512; worst case
        // ≈ 320 B) — an overflow here is a programming error, so it panics
        // instead of corrupting an identity.
        let cert = crate::attestation_cert::build_self_signed(&key, &mut adapter)
            .expect("attestation cert builder overflowed its static bound");
        Self { key, cert }
    }

    /// Host convenience: mint an identity from the platform TRNG (the host
    /// OS-entropy stand-in). Used by the host twin (`app::FidoApp`) which
    /// has no store to persist through — host apps get a fresh identity per
    /// construction; persistence is the device `boot` contract.
    #[cfg(feature = "host")]
    pub fn generate_host() -> Self {
        let mut trng = fapico2_platform::trng::HostTrng::new();
        Self::generate_from(&mut trng)
    }
}

/// Load the per-device attestation identity from `store`, provisioning
/// (generate + self-sign + persist) only when the key slot is `NotFound`.
///
/// The return value is consumed by `FidoApp::boot` (device) — an `Err` is
/// fatal by policy: a corrupt identity must fail the boot, never silently
/// regenerate (see the module docs).
///
/// US-956: `#[inline(never)]` — the fresh-provision arm inlines the whole
/// self-sign path (P-256 `SecretKey::public_key`, `p256_sign_der_into`, the
/// DER/TLV writer, `crypto_bigint`'s `to_be_byte_array`). Merged into
/// `FidoApp::boot_in_place` that scalar arithmetic held a ~32 KiB frame
/// reservation on the boot-path call chain — LLVM reserves the union over
/// *all* arms, so the restore arm (the one that runs on every boot after the
/// first) paid for the fresh arm's scratch too. Walled here, the two arms
/// keep separate reservations and the caller's own frame shrinks to what it
/// actually holds (the `AttestationIdentity` return value).
#[inline(never)]
pub fn provision<R: Trng>(
    trng: &mut R,
    store: &mut dyn SecureStore,
) -> Result<AttestationIdentity, SecureStoreError> {
    let mut buf = [0u8; 32];
    match store.read(ATTEST_KEY_SLOT, &mut buf) {
        Ok(32) => {
            // A stored scalar must be a valid P-256 key (0 < k < n); an
            // attacker-flipped or torn slot is Corrupt, never regenerated.
            let key = SecretKey::from_slice(&buf).map_err(|_| SecureStoreError::Corrupt)?;
            let mut cert_buf = [0u8; ATTEST_CERT_MAX];
            let n = match chunked::read_chunked(store, ATTEST_CERT_SLOT, &mut cert_buf) {
                // Key present + cert absent/unreadable = Corrupt (fail
                // closed): the pair is provisioned atomically by design.
                Err(SecureStoreError::NotFound) | Err(SecureStoreError::Corrupt) => {
                    return Err(SecureStoreError::Corrupt)
                }
                Err(e) => return Err(e),
                Ok(n) => n,
            };
            if n == 0 || n > ATTEST_CERT_MAX || cert_buf[0] != 0x30 {
                return Err(SecureStoreError::Corrupt);
            }
            let mut cert = heapless::Vec::new();
            cert.extend_from_slice(&cert_buf[..n])
                .map_err(|_| SecureStoreError::Corrupt)?;
            Ok(AttestationIdentity { key, cert })
        }
        // Present but wrong size (torn/garbage slot) — fail closed.
        Ok(_) => Err(SecureStoreError::Corrupt),
        // Fresh device: mint + persist. Cert first, scalar last (commit
        // point) — see the module docs for the crash windows.
        Err(SecureStoreError::NotFound) => {
            let identity = AttestationIdentity::generate_from(trng);
            chunked::write_chunked(store, ATTEST_CERT_SLOT, identity.cert_bytes())?;
            store.write(ATTEST_KEY_SLOT, identity.key().to_bytes().as_slice())?;
            Ok(identity)
        }
        // Anything else (AEAD/MAC failure = wrong-key store entry, flash
        // errors, ...) propagates — the boot fails closed.
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fapico2_platform::secure_store::HostSecureStore;
    use fapico2_platform::trng::HostTrng;

    #[test]
    fn provision_is_fresh_then_stable_and_parses() {
        let mut trng = HostTrng::new();
        let mut store = HostSecureStore::new();
        let a = provision(&mut trng, &mut store).expect("fresh provision");
        assert_eq!(a.cert_bytes()[0], 0x30, "DER SEQUENCE");
        assert!(a.cert_bytes().len() < ATTEST_CERT_MAX);
        let b = provision(&mut trng, &mut store).expect("reload");
        assert_eq!(a.key().to_bytes().as_slice(), b.key().to_bytes().as_slice());
        assert_eq!(a.cert_bytes(), b.cert_bytes());
    }
}
