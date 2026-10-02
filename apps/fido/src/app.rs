//! FIDO2 app that speaks CTAP2 over HID.
//!
//! CTAP2 makeCredential / getAssertion / getNextAssertion / credMgmt follow
//! the validation order of the reference C firmware (cbor_make_credential.c,
//! cbor_get_assertion.c, cbor_cred_mgmt.c): canonical key-order checks,
//! strict type checks, and the spec's required-field rules.

use crate::attestation::AttestationIdentity;
use crate::cbor;
use crate::ctap2::{Ctap2Info, Ctap2Response, CONFIG_CREDENTIAL_EXPIRE, CONFIG_CREDENTIAL_REVOKE};
use crate::crypto;
use crate::keystore::{CosePublicKey, Keystore, MemoryKeystore, StoredCredential};
use crate::pin::PinProtocol;
use crate::vault;
use crate::AAGUID;
use crate::DEFAULT_MAX_CRED_BLOB_LENGTH;
use crate::DEFAULT_MAX_RPIDS_MINPIN_LENGTH;
use crate::FidoError;
use p256::SecretKey;

// ------------------------------------------------------------------
// CTAP2 makeCredential request
// ------------------------------------------------------------------

struct McRequest {
    client_data_hash: Vec<u8>,
    rp_id: String,
    user_handle: Vec<u8>,
    user_name: String,
    user_display_name: String,
    pubkey_creds: Vec<PubKeyCredParam>,
    exclude_list: Vec<CredDescriptor>,
    options: McOptions,
    pin_uv_auth_param: Option<Vec<u8>>,
    pin_uv_protocol: u8,
    /// Parsed extension inputs (thirdPartyPayment, etc.).
    extensions: McExtensions,
    /// enterpriseAttestation request parameter (key 0x0A): 1 = full,
    /// 2 = vendor-facilitated.
    enterprise_attestation: Option<u8>,
}

/// hmac-secret getAssertion input (CTAP2.1 §6.7).
#[derive(Debug, Clone)]
struct HmacSecretInput {
    /// Client's ephemeral public key for ECDH with the device hkey.
    key_agreement: Vec<u8>,
    salt_enc: Vec<u8>,
    salt_auth: Vec<u8>,
    /// pinUvAuth protocol used to protect the salts (1 or 2).
    protocol: u8,
}

#[derive(Debug, Default)]
struct McExtensions {
    third_party_payment: bool,
    /// hmac-secret makeCredential input: request the extension (bool true).
    hmac_secret: bool,
    /// hmac-secret getAssertion input: encrypted salts to derive outputs for.
    hmac_secret_input: Option<HmacSecretInput>,
    /// hmac-secret-mc makeCredential input: salts to derive outputs for at
    /// registration time (CTAP2.1 §6.7.1).
    hmac_secret_mc: Option<HmacSecretInput>,
    /// minPinLength extension input: if true, reflect current min PIN length
    /// in the authData extensions output (when the RP is in the allowlist).
    min_pin_length: bool,
    /// pinComplexityPolicy extension input: if true and the policy is
    /// enabled, reflect it in the authData extensions output.
    pin_complexity_policy: bool,
    /// credBlob extension input: the blob to store on the credential.
    /// If longer than max_cred_blob_length, the blob is rejected (output
    /// credBlob=false). None when extension not requested.
    cred_blob: Option<Vec<u8>>,
    /// getCredBlob input: if true, return the stored credBlob in assertion.
    get_cred_blob: bool,
    /// credentialProtectionPolicy: 0=none, 1=optional, 2=optionalWithList, 3=required.
    cred_protect: u8,
    /// largeBlobKey extension input (FX-414): request a per-credential large
    /// blob key (makeCredential) or echo the stored one (getAssertion).
    large_blob_key: bool,
}

struct PubKeyCredParam {
    type_: String,
    alg: i64,
}

struct CredDescriptor {
    type_: String,
    id: Vec<u8>,
}

#[derive(Default)]
struct McOptions {
    rk: Option<bool>,
    up: Option<bool>,
    uv: Option<bool>,
    present: bool,
}


// ------------------------------------------------------------------
// CTAP2 getAssertion request
// ------------------------------------------------------------------

struct GaRequest {
    rp_id: String,
    client_data_hash: Vec<u8>,
    allow_list: Vec<CredDescriptor>,
    options: GaOptions,
    pin_uv_auth_param: Option<Vec<u8>>,
    pin_uv_protocol: u8,
    /// Parsed extension inputs.
    extensions: McExtensions,
}

#[derive(Default)]
struct GaOptions {
    rk: Option<bool>,
    up: Option<bool>,
    uv: Option<bool>,
    present: bool,
}


// ------------------------------------------------------------------
// credMgmt request
// ------------------------------------------------------------------

/// Which CBOR dialect a credentialManagement request arrived in.
///
/// Two are in the wild and they are *not* interchangeable:
///
/// * **PicoForge** — the first-party management client. Key `0x02` holds a
///   *map* of sub-command parameters, `pinUvAuthProtocol` sits at `0x03` and
///   `pinUvAuthParam` at `0x04`. Sub-commands `0x01`/`0x02` are
///   getCredsMetadata / enumerateRpsBegin. This is the layout this code was
///   originally written against and it must keep working byte for byte.
/// * **CTAP2** — what every third-party client speaks (ykman, Yubico
///   Authenticator, browsers). Keys are flat: `0x02` pinUvAuthProtocol,
///   `0x03` pinUvAuthParam, `0x04` rpIdHash, `0x05` credentialID,
///   `0x06` user. Sub-commands `0x01`/`0x02` are enumerateRPsBegin /
///   getCredsMetadata — the *reverse* of PicoForge's.
///
/// The two are told apart by the CBOR type of key `0x02`: PicoForge puts a
/// map there, CTAP2 puts an integer. The layouts never collide on that key
/// and both clients always set it, so it is a sound discriminator with no
/// negotiation needed.
///
/// The response key sets genuinely collide (PicoForge `0x04` is rpIdHash,
/// CTAP2 `0x04` is userID; PicoForge `0x07` is credentialID, CTAP2 `0x07`
/// is totalRPs), so a merged map is impossible — each dialect must be
/// answered in its own shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CmDialect {
    PicoForge,
    // Spec is the safe default: an unrecognised request is far more
    // likely to come from a third-party client than from PicoForge.
    #[default]
    Ctap2,
}

/// Canonical sub-command identity, independent of the wire dialect.
///
/// These are the CTAP2 §12.1.6 values. PicoForge swaps the first two; the
/// parser maps a PicoForge wire value onto these before anything downstream
/// looks at it, so the dispatch below needs no dialect branches.
const CM_GET_METADATA: u8 = 0x02;
const CM_ENUMERATE_RPS_BEGIN: u8 = 0x01;
const CM_ENUMERATE_RPS_NEXT: u8 = 0x03;
const CM_ENUMERATE_CREDS_BEGIN: u8 = 0x04;
const CM_ENUMERATE_CREDS_NEXT: u8 = 0x05;
const CM_DELETE_CRED: u8 = 0x06;
const CM_UPDATE_USER: u8 = 0x07;

struct CmRequest {
    /// Canonical sub-command (see the `CM_*` constants), not the wire byte.
    subcommand: u8,
    /// The byte as it arrived on the wire. The pinUvAuth message is signed
    /// over the wire value in *both* dialects, so it must be preserved
    /// separately from the canonical one.
    wire_subcommand: u8,
    dialect: CmDialect,
    pin_uv_protocol: u8,
    pin_uv_auth_param: Option<Vec<u8>>,
    rp_id_hash: Option<Vec<u8>>,
    cred_id: Option<CredDescriptor>,
    user: Option<CmUser>,
    // The PicoForge sub-command parameter map is NOT retained here. This twin
    // rebuilds the signed params from the fields parsed out of that map (see
    // the auth_data arm), so storing a verbatim copy would be write-only. The
    // device twin, which signs the raw bytes, keeps its own copy — the split
    // is deliberate and pinned by
    // `device_full_set.rs::device_twin_credmgmt_mac_scope_differs_from_host_for_0x01_and_0x02`.
    /// CTAP2 only: the credentialID and user maps exactly as received.
    /// CTAP2 signs those maps verbatim, so a re-encode could diverge from
    /// what the client actually signed (key order included).
    raw_cred_cbor: Option<Vec<u8>>,
    raw_user_cbor: Option<Vec<u8>>,
}

struct CmUser {
    id: Vec<u8>,
    name: String,
    display_name: String,
}

// ------------------------------------------------------------------
// credMgmt enumeration state
// ------------------------------------------------------------------

#[derive(Debug, Default)]
struct CmRpState {
    rps: Vec<(String, [u8; 32])>,
    cursor: usize,
    channel: [u8; 4],
    /// Dialect of the `enumerateRpsBegin` that armed this enumeration.
    /// A Next request is `{1: 0x03}` and nothing else in *both* dialects —
    /// the Next sub-commands carry no `pinUvAuthParam` — so it cannot be
    /// classified from its own bytes and is answered in the dialect that
    /// started the enumeration.
    dialect: CmDialect,
}

#[derive(Debug, Default)]
struct CmCredState {
    creds: Vec<StoredCredential>,
    cursor: usize,
    channel: [u8; 4],
    /// See [`CmRpState::dialect`].
    dialect: CmDialect,
}

// ------------------------------------------------------------------
// FIDO app state
// ------------------------------------------------------------------

/// FidoApp holds the keystore, the persistent ECDH key-agreement key, the
/// raw pin token, and volatile getAssertion state for getNextAssertion.
pub struct FidoApp<K: Keystore = MemoryKeystore> {
    keystore: K,
    /// Persistent P-256 key agreement key (ECDH `hkey`).
    hkey: SecretKey,
    /// US-916: the per-device attestation identity (TRNG-minted key +
    /// on-device self-signed cert). The host twin has no secure store to
    /// persist through, so it mints a fresh identity per construction; the
    /// device `boot` provisioning contract lives in `device_app.rs`.
    attestation: AttestationIdentity,
    /// US-176: the RS-Key `0x41` **volatile** state — the "unlocked this
    /// power cycle" flag and the current MSE channel.
    ///
    /// On the app and not in the keystore, and that is the whole point: the
    /// durable half is [`crate::vendor_state::VendorState`] inside `keystore`,
    /// and putting these two beside it would make "this power cycle" survive
    /// the power cycle it is named after. Cleared wherever this app already
    /// simulates one.
    vendor_session: crate::vendor_state::VendorSession,
    /// Raw pin token issued by getPinToken (for verifying pinUvAuthParam
    /// in makeCredential / getAssertion).
    pin_token: Option<Vec<u8>>,
    /// Permissions associated with the current pin_token (bitmask).
    /// AUTHENTICATOR_CFG (0x20) is required for config commands.
    pin_token_permissions: u8,
    /// RP ID the current token is bound to (present when the token request
    /// carried the rpId parameter). makeCredential/getAssertion must present
    /// the same RP.
    pin_token_rp_id: Option<String>,
    /// Volatile state for get_next_assertion: credentials matched by the
    /// last getAssertion, and a cursor index.
    ga_state: Option<GaState>,
    /// Current HID channel id (set on every command). Used to enforce that
    /// get_next_assertion is called on the same channel.
    current_channel: [u8; 4],
    /// Volatile credMgmt enumeration state for enumerate_rps begin/next.
    cm_rp_state: Option<CmRpState>,
    /// Volatile credMgmt enumeration state for enumerate_creds begin/next.
    cm_cred_state: Option<CmCredState>,
    /// Which CBOR dialect the credMgmt command being served arrived in; the
    /// response encoders read it (the PicoForge and CTAP2 key sets collide,
    /// so a request must be answered in the shape its sender asked in).
    cm_dialect: CmDialect,
    /// Volatile largeBlobs (0x0C) write buffer: total length and the
    /// fragments accumulated so far. Committed to the keystore only when the
    /// full payload (with trailing checksum) has arrived and verifies.
    lb_pending: Option<LbPending>,
    /// Pending vault enrollment (vendor 0x05 ENROLL_BEGIN state).
    vault_pending: Option<VaultPending>,
    /// Enterprise attestation mode (toggled by Config ENABLE_ENTERPRISE_ATT).
    /// When enabled, makeCredential uses enterprise attestation. Stored in
    /// keystore pin state for persistence across reboot.
    enterprise_attestation: bool,
}

/// Holds the credentials matched by a getAssertion so getNextAssertion can
/// walk them.
struct GaState {
    credentials: Vec<StoredCredential>,
    cursor: usize,
    client_data_hash: Vec<u8>,
    uv: bool,
    do_up: bool,
    /// Total number of matching credentials (for numberOfCredentials field).
    total: usize,
    /// HID channel of the original getAssertion (getNextAssertion must match).
    channel: [u8; 4],
    /// Whether the original request included the thirdPartyPayment extension.
    has_extensions: bool,
    /// Whether the original request included getCredBlob.
    get_cred_blob: bool,
    /// hmac-secret input carried from the original getAssertion so
    /// getNextAssertion assertions also carry the extension.
    hmac_secret_input: Option<HmacSecretInput>,
    /// Whether the original getAssertion requested the largeBlobKey extension.
    large_blob_key: bool,
}

const MAX_CREDENTIAL_COUNT_IN_LIST: usize = 64;

/// Maximum size of the committed large-blob array (FX-414; matches the
/// 1024-byte default used by the reference firmware).
const MAX_LARGE_BLOB_ARRAY: usize = 1024;

/// Pending largeBlobs write transaction.
struct LbPending {
    total: usize,
    buf: Vec<u8>,
}

/// Pending vault enrollment: device X448 secret/public and the challenge.
struct VaultPending {
    secret: [u8; 56],
    public: [u8; 56],
    challenge: [u8; 32],
}

/// The default (empty) large-blob array: an empty CBOR array followed by the
/// first 16 bytes of its SHA-256 checksum.
fn default_large_blob_array() -> Vec<u8> {
    let mut arr = cbor::encode(&cbor::Value::A(vec![]));
    let digest = crypto::sha256(&arr);
    arr.extend_from_slice(&digest[..16]);
    arr
}

/// Derive the per-credential large blob key, following the C firmware's
/// SLIP-0022-style HMAC chain (credential_derive_large_blob_key).
fn derive_large_blob_key(device_key: &[u8; 32], cred_id: &[u8]) -> [u8; 32] {
    let k = crypto::hmac_sha256(device_key, b"SLIP-0022");
    let k = crypto::hmac_sha256(&k, cred_id);
    let k = crypto::hmac_sha256(&k, b"largeBlobKey");
    crypto::hmac_sha256(&k, cred_id)
}

/// US-424 (SECURE-PERSIST): the host FIDO app joins the platform persist gate
/// through the small [`fapico2_platform::persist::Persist`] trait directly — it
/// is not a dispatcher `App` (it serves over CTAP-HID, not AID-SELECT).
///
/// Device parity: the device shell (`device_app.rs`) persists through the
/// *shared* platform `SecureStore` (the RP2350 secure partition). The host
/// app has no such shared medium — its durable medium is the keystore file
/// (or RAM for `MemoryKeystore`), written per US-322/FX-409/410. So the
/// shared `store` is untouched by this impl: `persist_dirty` flushes through
/// the app's OWN keystore and, for current keystores, returns `false`, so
/// [`fapico2_platform::persist::persist_one`] returns before any
/// snapshot/program. The CCID apps' state needs no refresh on the HID arm —
/// HID commands never mutate it — and is covered by the CCID arm's own
/// `persist_apps` call. This is what lets the emulator's CTAP-HID serve loop
/// call the same [`fapico2_platform::persist::persist_one`] gate the CCID arm
/// uses, giving device/emulation durable-before-ack parity (US-424).
impl<K: Keystore> fapico2_platform::persist::Persist for FidoApp<K> {
    /// Flush the app's durable state through its own keystore medium. Returns
    /// `true` iff durable bytes were written this call (a `FileKeystore` write
    /// landed on disk). The shared `store` is not the FIDO medium, so it is
    /// not touched here.
    fn persist_dirty(&mut self, _store: &mut dyn fapico2_platform::secure_store::SecureStore) -> bool {
        self.keystore.persist_if_dirty()
    }

    /// Re-mark dirty (the gate's sink-failure path). Documented no-op: the host
    /// keystore has no retry dirty flag — its file write (or RAM for
    /// `MemoryKeystore`) *is* its durable medium, so a failed partition-image
    /// program leaves the keystore in its last-flushed state and the gate's
    /// shared-store snapshot/program covers the CCID apps' state, not the FIDO
    /// keystore file.
    fn mark_dirty(&mut self) {}

    /// US-427: never left dirty — the host keystore has no buffered durable
    /// state (`FileKeystore` writes its durable medium, the keystore file,
    /// inline on every mutation; `MemoryKeystore` has no durable medium), so
    /// there is nothing for this gate to flush and no dirty flag to carry
    /// between commands. Whether a failed inline write surfaces as a CTAP
    /// error is each command's own contract — the gate on this path cannot
    /// observe it and has no retry state to leave behind. A `false` from
    /// the gate here is therefore always "no durable change needed", never
    /// "persist failed" — the transport may answer the success reply.
    fn is_dirty(&self) -> bool {
        false
    }
}

impl<K: Keystore> FidoApp<K> {
    /// Create a new FIDO app with the given keystore.
    pub fn with_keystore(k: K) -> Self {
        let (secret, _public) = crypto::generate_p256_keypair();
        // US-916: mint a fresh per-device attestation identity (TRNG key +
        // on-device self-signed cert) — see `crate::attestation`.
        let attestation = AttestationIdentity::generate_host();
        Self {
            keystore: k,
            hkey: secret,
            attestation,
            vendor_session: crate::vendor_state::VendorSession::default(),
            pin_token: None,
            pin_token_permissions: 0,
            pin_token_rp_id: None,
            ga_state: None,
            current_channel: [0; 4],
            cm_rp_state: None,
            cm_cred_state: None,
            cm_dialect: CmDialect::default(),
            lb_pending: None,
            vault_pending: None,
            enterprise_attestation: false,
        }
    }

    /// Clear volatile session state (called on new HID client connection
    /// to simulate a power-cycle / USB reconnect).
    pub fn clear_session_state(&mut self) {
        self.keystore.clear_session_state();
        self.pin_token = None;
        self.pin_token_permissions = 0;
        self.pin_token_rp_id = None;
        self.ga_state = None;
        self.lb_pending = None;
        self.vault_pending = None;
        // US-176: the `0x41` volatile half. This method is where the host
        // simulates a power cycle for a new client, so clearing it here is what
        // makes "unlocked this power cycle" mean the same thing on the host as
        // it does on the board. Leaving it set would let a second client
        // inherit the first one's unlocked seed.
        self.vendor_session.clear();
        // Reload persistent enterprise-attestation flag from keystore.
        self.enterprise_attestation = self.keystore.get_pin_state().enterprise_attestation;
    }

    /// Whether the currently presented token grants `perm`. A token minted via
    /// the legacy getPinToken (subcommand 0x05, permissions 0) is valid for
    /// makeCredential and getAssertion only (CTAP2.1 §6.5.5.4).
    fn token_allows(&self, perm: u8) -> bool {
        match self.pin_token_permissions {
            0 => perm == PERM_MC || perm == PERM_GA,
            p => p & perm != 0,
        }
    }

    /// The current pinUvAuth token as the RS-Key `0x41` channel wants it — a
    /// 32-byte key, the permission byte it was minted with, and the
    /// PIN-auth lockout latch — or `None` when no token is held.
    ///
    /// The 32-byte narrowing is the same one `authenticator_config` does for
    /// its own MAC: this app stores the token as a `Vec`, and the RS-Key
    /// channel fixes the width at `&[u8; 32]`. A token **shorter** than 32
    /// bytes yields `None`, which every consumer treats as "no token" — the
    /// safe direction, since an unreadable token authorises nothing. A token
    /// **longer** than 32 bytes does *not* yield `None`: `get(..32)` succeeds
    /// and the leading 32 bytes are used, which is truncation rather than
    /// rejection. No caller here can mint one — `clientPin` returns exactly 32
    /// bytes — so the two cases are not distinguished, and this says so rather
    /// than claiming a check the code does not make.
    ///
    /// US-176: this takes **fields**, not `&self`. It was a `&self` method and
    /// the `0x41` dispatch arm could not use it: the arm has to hold the
    /// returned `TokenAuth` (which borrows `pin_token`) across the construction
    /// of a `&mut self.keystore` and a `&mut self.vendor_session`, and a
    /// whole-`&self` borrow covers both of those. Three field reads compose;
    /// one `&self` does not. The body is unchanged.
    fn token_auth(
        pin_token: &[Option<Vec<u8>>],
        permissions: u8,
        needs_power_cycle: bool,
    ) -> Option<crate::vendor41::TokenAuth<'_>> {
        let bytes: &[u8] = pin_token.first()?.as_ref()?.get(..32)?;
        let token: &[u8; 32] = bytes.try_into().ok()?;
        Some(crate::vendor41::TokenAuth {
            token,
            permissions,
            // The same latch `verify_token` gates on. Handed across because
            // the `0x41` seam bypasses `verify_token`; see `TokenAuth`.
            blocked: needs_power_cycle,
        })
    }

    /// The keystore — the host twin of `device_app::FidoApp::keystore`, added
    /// so a test can observe PIN state (the `needs_power_cycle` latch) that
    /// the command path sets but does not otherwise expose.
    pub fn keystore(&mut self) -> &mut K {
        &mut self.keystore
    }

    /// Whether the token's bound rpId (if any) matches the requesting RP.
    fn token_rp_id_ok(&self, rp_id: &str) -> bool {
        match &self.pin_token_rp_id {
            Some(bound) => bound == rp_id,
            None => true,
        }
    }

    /// Record a pinUvAuthParam verification failure (FX-406). The third
    /// consecutive failure blocks PIN auth until power cycle
    /// (CTAP2.1 §6.5.7). Returns the CTAP2 error code to respond with.
    fn note_pin_auth_failure(&mut self) -> u8 {
        let blocked = {
            let s = self.keystore.get_pin_state_mut();
            s.auth_failures = s.auth_failures.saturating_add(1);
            if s.auth_failures >= 3 {
                // US-909: the latch is durable — persist it.
                s.needs_power_cycle = true;
                let _ = self.keystore.save_pin_state();
                true
            } else {
                false
            }
        };
        if blocked {
            Ctap2Response::PinAuthBlocked.code()
        } else {
            Ctap2Response::PinAuthInvalid.code()
        }
    }

    /// Record a successful pinUvAuthParam verification (resets the counter).
    fn note_pin_auth_success(&mut self) {
        self.keystore.get_pin_state_mut().auth_failures = 0;
    }

    /// Derive the hmac-secret outputs for encrypted salts (CTAP2.1 §6.7).
    /// The credential random is device-keyed (C parity: `key_seed` derived),
    /// so re-registration on the same device yields the same secret; the UV
    /// half is used when UV was performed.
    fn derive_hmac_output(
        &self,
        hs: &HmacSecretInput,
        uv: bool,
    ) -> Result<Vec<u8>, u8> {
        let client_pub = match crypto::parse_cose_ec2_p256(
            &hs.key_agreement[..32],
            &hs.key_agreement[32..],
        ) {
            Some(p) => p,
            // An unusable key agreement means the saltAuth check cannot
            // possibly pass: report an authentication failure.
            None => return Err(Ctap2Response::PinAuthInvalid.code()),
        };
        let raw = crypto::ecdh_shared_secret(&self.hkey, &client_pub);
        let (hmac_key, enc_key): ([u8; 32], [u8; 32]) = if hs.protocol == 1 {
            let k = crypto::derive_shared_secret_v1(&raw);
            (k, k)
        } else {
            let shared = crypto::derive_shared_secret_v2(&raw);
            let mut hk = [0u8; 32];
            let mut ek = [0u8; 32];
            hk.copy_from_slice(&shared[..32]);
            ek.copy_from_slice(&shared[32..]);
            (hk, ek)
        };
        if !crypto::pin_verify_auth(hs.protocol, &hmac_key, &hs.salt_enc, &hs.salt_auth) {
            return Err(Ctap2Response::PinAuthInvalid.code());
        }
        let salt_dec = match hs.protocol {
            1 => crypto::pin_decrypt_v1(&enc_key, &hs.salt_enc),
            _ => crypto::pin_decrypt_v2(&enc_key, &hs.salt_enc),
        };
        let salt_dec = match salt_dec {
            Some(s) => s,
            None => return Err(Ctap2Response::InvalidParameter.code()),
        };
        let hkey_bytes = self.hkey.to_bytes();
        let crd = if uv {
            crypto::hmac_sha256(&hkey_bytes, b"fapico2-hmac-cred-random-uv")
        } else {
            crypto::hmac_sha256(&hkey_bytes, b"fapico2-hmac-cred-random")
        };
        let mut out = crypto::hmac_sha256(&crd, &salt_dec[..32]).to_vec();
        if salt_dec.len() >= 64 {
            let out2 = crypto::hmac_sha256(&crd, &salt_dec[32..64]);
            out.extend_from_slice(&out2);
        }
        Ok(match hs.protocol {
            1 => crypto::pin_encrypt_v1(&enc_key, &out),
            _ => crypto::pin_encrypt_v2(&enc_key, &out),
        })
    }

    /// Process a U2F APDU (CTAP1 over HID CTAPHID_MSG).
    pub fn process_u2f(&mut self, apdu: &[u8]) -> Vec<u8> {
        // US-908: the host/emulation default presence source auto-acks
        // (parity with the device build default), keeping the existing
        // suites green; the gate itself lives in the U2F twins.
        let (data, status) = match crate::u2f::process_u2f_apdu(apdu, &mut self.keystore, || true, &self.attestation) {
            Ok(data) => (data, crate::u2f::U2fStatus::NoError.code()),
            Err(status) => (vec![], status.code()),
        };
        let mut resp = data;
        resp.extend_from_slice(&status.to_be_bytes());
        resp
    }

    /// Process a CTAP2 command.
    pub fn process_ctap2(&mut self, command: u8, data: &[u8], channel: [u8; 4]) -> Vec<u8> {
        self.current_channel = channel;
        // CTAP2.1 §6.9: any non-credMgmt command invalidates a pending
        // credMgmt enumeration (enumerateRps/ enumerateCreds begin..next).
        if command != 0x0A {
            self.cm_rp_state = None;
            self.cm_cred_state = None;
        }
        match command {
            0x04 => self.get_info(),
            0x06 => self.client_pin(data),
            0x01 => self.make_credential(data),
            0x02 => self.get_assertion(data),
            0x07 => {
                self.keystore.reset().map_err(|_| FidoError::Internal).ok();
                self.pin_token = None;
                self.ga_state = None;
                vec![Ctap2Response::Ok.code()]
            }
            0x08 => self.get_next_assertion(),
            0x0A => self.cred_mgmt(data),
            0x0B => self.authenticator_selection(),
            0x0C => self.large_blobs(data),
            0x0D => self.authenticator_config(data),
            // US-106: the RS-Key vendor channel (PicoForge framing C) — the
            // first payload byte of a standard 0x90 CBOR frame. NOT the vendor
            // vault below: that one is reached through the CTAPHID frame CMD
            // byte in `firmware/src/tasks.rs`, a different frame and a
            // different field, so the two cannot alias (its sub-command `1` is
            // STATUS here, whereas `1` is MSE in RS-Key). Every sub-command is
            // a NOT_ALLOWED stub until Phase I implements it; `vendor41` owns
            // both the sub-command set and the shrink-to-empty discipline.
            //
            // US-112: the caller's pinUvAuth token is handed down as
            // `TokenAuth`, and the outcome can ask this app to charge a
            // rejected MAC against its three-strike counter. Neither is
            // consulted while every sub-command is still a stub — this arm
            // still answers `0x30` to every request, and
            // `tests/vendor41.rs::vendor41_permission_gate_is_not_yet_wired_into_the_stubs`
            // pins that with a real `0x20` token in hand.
            crate::vendor41::CMD => {
                // US-114: the `0x41` response is `status || CBOR`, so this
                // arm has somewhere to put a body.
                //
                // The `body` buffer is local and starts empty, so — unlike the
                // device path, where `out` is the reused `HID_RESP` — there
                // is nothing stale for `finish_reply` to prepend to. The
                // clear is left to `finish_reply` anyway, so that the two
                // paths cannot disagree about when a body is discarded.
                let mut body: heapless::Vec<u8, { crate::CTAP2_MAX_MSG }> = heapless::Vec::new();
                // US-115: the host stack has no presence probe to hand down —
                // it has never had one, and `PresenceGate`'s `Default` resolves
                // through `default_user_present`, which auto-acks on host. So a
                // benign-tier `CONFIG_WRITE` on this path is *not* a test of the
                // presence tier; `config_write_rejected_without_presence`
                // drives `vendor41::config_write` with an explicit probe for
                // exactly that reason. What this path does test is the identity
                // tier and the commit.
                //
                // US-176: `ops` is the Phase I state seam, and the two call
                // sites are the only two places this app has to be taught
                // about it. It borrows the auth state and the volatile session
                // separately from the keystore that owns them, so the commit
                // still happens through `save_auth_state` below — the host
                // contract `vendor41::handle` documents, unchanged.
                let outcome = {
                    let auth = Self::token_auth(
                        std::slice::from_ref(&self.pin_token),
                        self.pin_token_permissions,
                        self.keystore.get_pin_state().needs_power_cycle,
                    );
                    let phy = self.keystore.get_auth_state().phy;
                    let mut ops = crate::vendor_state::MemoryVendorOps::new(
                        &mut self.keystore,
                        &mut self.vendor_session,
                    );
                    crate::vendor41::handle(
                        data,
                        auth,
                        &phy,
                        crate::vendor41::PresenceGate::default(),
                        &mut body,
                        &mut ops,
                    )
                };
                let mut status = if outcome.pin_auth_failure {
                    // Reuse the existing private latch, so the third strike
                    // still answers `0x34` and `needs_power_cycle` is still
                    // persisted the one way this app persists it.
                    self.note_pin_auth_failure()
                } else {
                    outcome.status.code()
                };
                // US-115: the record `config_write` proposed, made durable
                // before the `0x00` goes out. The host's contract is the
                // weaker one its other `cfg_*` handlers keep — mutate, then
                // `save_auth_state`, and report a save failure as a failure —
                // because the host has no store borrow here at all. It is still
                // *before* the ack, which is the property US-115 asks for; the
                // device path's `grow_checked` is the transactional version and
                // is what the RP2350 actually relies on. See `vendor41::handle`
                // for why the commit is here and not in the sub-command arm.
                if let Some(next) = outcome.phy {
                    self.keystore.get_auth_state_mut().phy = next;
                    if self.keystore.save_auth_state().is_err() {
                        status = Ctap2Response::KeyStoreFull.code();
                    }
                }
                // Shared with the device path so the two cannot drift, and so
                // this path's reply gets the same full-buffer refusal the
                // device's does — even though the host's own `Vec` is grown
                // with room to spare and could not have failed.
                crate::vendor41::finish_reply(&mut body, status);
                // `body` now holds the whole `status || CBOR` reply.
                body.to_vec()
            }
            _ => vec![Ctap2Response::InvalidCommand.code()],
        }
    }

    // ------------------------------------------------------------------
    // Vendor vault protocol (CTAPHID vendor 0x41, function 0x05)
    // ------------------------------------------------------------------

    /// Handle the vault vendor function. `data` is the CBOR request:
    /// {1: subcommand, 2: params, 3: pinUvAuthProtocol, 4: pinUvAuthParam}.
    /// Response: status byte followed by the CBOR result map (if any).
    pub fn process_vendor_vault(&mut self, data: &[u8]) -> Vec<u8> {
        let (value, _) = match cbor::decode(data) {
            Ok(v) => v,
            Err(_) => return vec![Ctap2Response::InvalidCbor.code()],
        };
        let map = match &value {
            cbor::Value::M(m) => m,
            _ => return vec![Ctap2Response::InvalidCbor.code()],
        };
        let mut subcommand: Option<u8> = None;
        let mut params: Option<Vec<u8>> = None;
        let mut protocol: u8 = 1;
        let mut param: Option<Vec<u8>> = None;
        for (k, v) in map {
            match k {
                cbor::Value::U(0x01) => {
                    if let Ok(u) = cbor_get_uint(v) {
                        subcommand = Some(u as u8);
                    }
                }
                cbor::Value::U(0x02) => {
                    if let cbor::Value::M(_) = v {
                        params = Some(cbor::encode(v));
                    }
                }
                cbor::Value::U(0x03) => {
                    if let Ok(p) = cbor_get_uint(v) {
                        protocol = p as u8;
                    }
                }
                cbor::Value::U(0x04) => {
                    if let Ok(p) = cbor_get_bytes(v) {
                        param = Some(p);
                    }
                }
                _ => {}
            }
        }
        let subcommand = match subcommand {
            Some(s) => s,
            None => return vec![Ctap2Response::MissingParameter.code()],
        };

        // Every subcommand except STATUS requires a PIN-authorized token.
        if subcommand != 0x01 {
            let param = match param {
                Some(p) => p,
                None => return vec![Ctap2Response::PuatRequired.code()],
            };
            if self.pin_token.is_none() {
                return vec![Ctap2Response::PinAuthInvalid.code()];
            }
            if !self.token_allows(PERM_ACFG) && !self.token_allows(PERM_CM) {
                return vec![Ctap2Response::UnauthorizedPermission.code()];
            }
            let token = self.pin_token.as_ref().unwrap();
            let token_arr: [u8; 32] = token
                .get(..32)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0u8; 32]);
            let msg = vault::auth_message(subcommand, params.as_deref().unwrap_or(&[]));
            if !crypto::pin_verify_auth(protocol, &token_arr, &msg, &param) {
                return vec![self.note_pin_auth_failure()];
            }
            self.note_pin_auth_success();
        }

        match subcommand {
            // STATUS: enrolled vault id (or empty).
            0x01 => {
                let status = self.keystore.get_auth_state().vault_state.clone();
                let vault_id = status.unwrap_or_default();
                vault::ok_response(vec![(cbor::Value::U(0x01), cbor::Value::B(vault_id))])
            }
            // ENROLL_BEGIN: fresh X448 keypair + challenge.
            0x02 => {
                let mut secret_bytes = [0u8; 56];
                fapico2_platform::trng::random_bytes_into(&mut secret_bytes);
                let secret = match x448::Secret::from_bytes(&secret_bytes) {
                    Some(s) => s,
                    None => return vec![Ctap2Response::Processing.code()],
                };
                let public = x448::PublicKey::from(&secret);
                let mut challenge = [0u8; vault::ENROLL_CHALLENGE_BYTES];
                fapico2_platform::trng::random_bytes_into(&mut challenge);
                let mut pub_bytes = [0u8; 56];
                pub_bytes.copy_from_slice(public.as_bytes());
                self.vault_pending = Some(VaultPending {
                    secret: *secret.as_bytes(),
                    public: pub_bytes,
                    challenge,
                });
                vault::ok_response(vec![
                    (cbor::Value::U(0x01), cbor::Value::B(pub_bytes.to_vec())),
                    (cbor::Value::U(0x02), cbor::Value::B(challenge.to_vec())),
                ])
            }
            // ENROLL_FINISH: decrypt the enrollment packet and store the
            // derived vault id.
            0x03 => {
                let pending = match self.vault_pending.take() {
                    Some(p) => p,
                    None => return vec![Ctap2Response::NotAllowed.code()],
                };
                let packet = match &params {
                    Some(_) => match map.iter().find(|(k, _)| matches!(k, cbor::Value::U(0x02))) {
                        Some((_, cbor::Value::M(pm))) => {
                            match pm.iter().find(|(k, _)| matches!(k, cbor::Value::U(0x01))) {
                                Some((_, cbor::Value::B(b))) => b.clone(),
                                _ => return vec![Ctap2Response::InvalidParameter.code()],
                            }
                        }
                        _ => return vec![Ctap2Response::InvalidParameter.code()],
                    },
                    None => return vec![Ctap2Response::InvalidParameter.code()],
                };
                if packet.len() < 2 + 12 + 16 {
                    return vec![Ctap2Response::InvalidParameter.code()];
                }
                let cert_len = u16::from_be_bytes([packet[0], packet[1]]) as usize;
                if packet.len() < 2 + cert_len + vault::NONCE_BYTES + 16 {
                    return vec![Ctap2Response::InvalidParameter.code()];
                }
                let cert = &packet[2..2 + cert_len];
                let nonce = &packet[2 + cert_len..2 + cert_len + vault::NONCE_BYTES];
                let ciphertext = &packet[2 + cert_len + vault::NONCE_BYTES..];
                let cert_public = match vault::x448_public_from_cert(cert) {
                    Some(k) => k,
                    None => return vec![Ctap2Response::InvalidParameter.code()],
                };
                let peer = match x448::PublicKey::from_bytes(&cert_public) {
                    Some(k) => k,
                    None => return vec![Ctap2Response::InvalidParameter.code()],
                };
                let secret = match x448::Secret::from_bytes(&pending.secret) {
                    Some(s) => s,
                    None => return vec![Ctap2Response::Processing.code()],
                };
                let shared = match secret.to_diffie_hellman(&peer) {
                    Some(s) => s,
                    None => return vec![Ctap2Response::InvalidParameter.code()],
                };
                let mut info = Vec::new();
                info.extend_from_slice(vault::ENROLL_INFO);
                info.extend_from_slice(&pending.challenge);
                info.extend_from_slice(&cert_public);
                info.extend_from_slice(&pending.public);
                let session_key = vault::enrollment_session_key(
                    shared.as_bytes(),
                    &pending.challenge,
                    &cert_public,
                    &pending.public,
                );
                let (kvault, _label) =
                    match vault::decrypt_enrollment_packet(&session_key, nonce, ciphertext, &info)
                    {
                        Some(v) => v,
                        None => return vec![Ctap2Response::IntegrityFailure.code()],
                    };
                let vault_id = vault::vault_id(&kvault);
                {
                    let s = self.keystore.get_auth_state_mut();
                    s.vault_state = Some(vault_id.to_vec());
                }
                self.keystore
                    .save_auth_state()
                    .map_err(|_| FidoError::Internal)
                    .ok();
                vault::ok_response(vec![
                    (cbor::Value::U(0x01), cbor::Value::B(vault_id.to_vec())),
                ])
            }
            // EXPORT / IMPORT need a sealed hardware vault; without one the
            // commands fail (clients only require "no pin → error").
            0x04 | 0x05 => vec![Ctap2Response::NotAllowed.code()],
            // UNENROLL: explicit opt-in erasure of the vault.
            0x06 => {
                {
                    let s = self.keystore.get_auth_state_mut();
                    s.vault_state = None;
                }
                self.keystore
                    .save_auth_state()
                    .map_err(|_| FidoError::Internal)
                    .ok();
                vec![Ctap2Response::Ok.code()]
            }
            _ => vec![Ctap2Response::InvalidSubcommand.code()],
        }
    }

    /// authenticatorSelection (CTAP2.1 §6.3 / FX-415). Returns CTAP2_OK
    /// immediately, with no touch.
    ///
    /// US-1514 corrected the comment that used to sit here, which was wrong
    /// in both halves. It said "the reference C firmware auto-accepts
    /// selection **in emulation**" — the reference's gate is disarmed in its
    /// *default build*, not only under emulation: `cbor_selection.c` does call
    /// `wait_button_pressed()`, but the `force_button_wait = true` that
    /// disarms `button_wait_start()`'s auto-complete branch
    /// (`pico-keys-sdk/src/button.c:113`) sits inside
    /// `#ifdef FORCE_BUTTON_WAIT`, a CMake option that is off unless
    /// requested. And it said a hardware build would time out to
    /// `ACTION_TIMEOUT` (0x3A) — the reference returns
    /// `CTAP2_ERR_USER_ACTION_TIMEOUT` = **0x2F** on timeout and
    /// `CTAP2_ERR_OPERATION_DENIED` = 0x27 on cancel. 0x3A is not what a
    /// gated selection answers anywhere, and `Ctap2Response::ActionTimeout`
    /// is accordingly still produced nowhere in this tree.
    ///
    /// The gate is still worth having and is still not implemented; see
    /// `device_core::handle_authenticator_selection` for why it cannot be
    /// added to this twin alone, and note that adding it would need the
    /// transport (`firmware/src/tasks.rs`) to put `0x0B` in
    /// `presence_windowed` — otherwise the `UpRequired` this returns would
    /// never open a window and would go out as a bare error to a client
    /// that turns every non-zero status into a `CtapError`.
    fn authenticator_selection(&mut self) -> Vec<u8> {
        vec![Ctap2Response::Ok.code()]
    }

    // ------------------------------------------------------------------
    // largeBlobs (CTAP2.1 §6.10 / FX-414)
    // ------------------------------------------------------------------

    fn large_blobs(&mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return vec![Ctap2Response::MissingParameter.code()];
        }
        let (value, _) = match cbor::decode(data) {
            Ok(v) => v,
            Err(_) => return vec![Ctap2Response::InvalidCbor.code()],
        };
        let map = match &value {
            cbor::Value::M(m) => m,
            _ => return vec![Ctap2Response::InvalidCbor.code()],
        };
        let mut get: Option<usize> = None;
        let mut set: Option<Vec<u8>> = None;
        let mut offset: usize = 0;
        let mut length: Option<usize> = None;
        let mut param: Option<Vec<u8>> = None;
        let mut protocol: u8 = 1;
        for (k, v) in map {
            match k {
                cbor::Value::U(0x01) => match cbor_get_uint(v) {
                    Ok(g) => get = Some(g as usize),
                    Err(_) => return vec![Ctap2Response::InvalidParameter.code()],
                },
                cbor::Value::U(0x02) => match cbor_get_bytes(v) {
                    Ok(s) => set = Some(s),
                    Err(_) => return vec![Ctap2Response::InvalidParameter.code()],
                },
                cbor::Value::U(0x03) => match cbor_get_uint(v) {
                    Ok(o) => offset = o as usize,
                    Err(_) => return vec![Ctap2Response::InvalidParameter.code()],
                },
                cbor::Value::U(0x04) => match cbor_get_uint(v) {
                    Ok(l) => length = Some(l as usize),
                    Err(_) => return vec![Ctap2Response::InvalidParameter.code()],
                },
                cbor::Value::U(0x05) => match cbor_get_bytes(v) {
                    Ok(p) => param = Some(p),
                    Err(_) => return vec![Ctap2Response::InvalidParameter.code()],
                },
                cbor::Value::U(0x06) => match cbor_get_uint(v) {
                    Ok(p) => protocol = p as u8,
                    Err(_) => return vec![Ctap2Response::InvalidParameter.code()],
                },
                _ => {}
            }
        }

        if let Some(fragment) = set {
            // Writing requires a pinUvAuthToken with the lbf permission; the
            // pinUvAuthParam is computed over 0xff*32 || 0x0c00 || offset ||
            // SHA-256(fragment) (CTAP2.1 §6.10.1).
            let param = match param {
                Some(p) => p,
                None => return vec![Ctap2Response::PuatRequired.code()],
            };
            if protocol != 1 && protocol != 2 {
                return vec![Ctap2Response::InvalidParameter.code()];
            }
            if self.pin_token.is_none() {
                return vec![Ctap2Response::PinAuthInvalid.code()];
            }
            if !self.token_allows(PERM_LBF) {
                return vec![Ctap2Response::PinAuthInvalid.code()];
            }
            let token = self.pin_token.as_ref().unwrap();
            let token_arr: [u8; 32] = token
                .get(..32)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0u8; 32]);
            let mut msg = vec![0xffu8; 32];
            msg.extend_from_slice(&[0x0c, 0x00]);
            msg.extend_from_slice(&(offset as u32).to_le_bytes());
            msg.extend_from_slice(&crypto::sha256(&fragment));
            if !crypto::pin_verify_auth(protocol, &token_arr, &msg, &param) {
                return vec![self.note_pin_auth_failure()];
            }
            self.note_pin_auth_success();
            // Fragment assembly: the first fragment (offset 0) carries the
            // total payload length; fragments must arrive in order.
            if offset == 0 {
                let total = match length {
                    Some(l) if l > 16 && l <= MAX_LARGE_BLOB_ARRAY => l,
                    _ => return vec![Ctap2Response::InvalidParameter.code()],
                };
                if fragment.len() > total {
                    return vec![Ctap2Response::InvalidParameter.code()];
                }
                self.lb_pending = Some(LbPending {
                    total,
                    buf: fragment,
                });
            } else {
                let pending = match self.lb_pending.as_mut() {
                    Some(p) => p,
                    None => return vec![Ctap2Response::InvalidParameter.code()],
                };
                if offset != pending.buf.len()
                    || pending.buf.len() + fragment.len() > pending.total
                {
                    return vec![Ctap2Response::InvalidParameter.code()];
                }
                pending.buf.extend_from_slice(&fragment);
            }
            // Commit only when the full payload (data + 16-byte checksum) has
            // arrived and verifies; intermediate reads still see the old
            // array.
            if self
                .lb_pending
                .as_ref()
                .is_some_and(|p| p.buf.len() == p.total)
            {
                let pending = self.lb_pending.take().unwrap();
                let (payload, check) = pending.buf.split_at(pending.buf.len() - 16);
                if crypto::sha256(payload)[..16] != *check {
                    return vec![Ctap2Response::IntegrityFailure.code()];
                }
                {
                    let s = self.keystore.get_auth_state_mut();
                    s.large_blob_array = Some(pending.buf);
                }
                self.keystore
                    .save_auth_state()
                    .map_err(|_| FidoError::Internal)
                    .ok();
            }
            return vec![Ctap2Response::Ok.code()];
        }

        // Read: return the requested chunk of the large-blob array (an empty
        // array is reported as the default empty-array-with-checksum blob).
        let get = match get {
            Some(g) => g,
            None => return vec![Ctap2Response::InvalidParameter.code()],
        };
        let auth = self.keystore.get_auth_state();
        let arr = auth
            .large_blob_array
            .clone()
            .unwrap_or_else(default_large_blob_array);
        if offset >= arr.len() {
            return vec![Ctap2Response::InvalidParameter.code()];
        }
        let end = (offset + get).min(arr.len());
        let resp = cbor::Value::M(vec![(
            cbor::Value::U(0x01),
            cbor::Value::B(arr[offset..end].to_vec()),
        )]);
        let mut out = vec![Ctap2Response::Ok.code()];
        out.extend_from_slice(&cbor::encode(&resp));
        out
    }

    // ------------------------------------------------------------------
    // getInfo
    // ------------------------------------------------------------------

    fn get_info(&self) -> Vec<u8> {
        let mut info = Ctap2Info::default();
        // Encrypted-state fields (IV(16) || AES-CBC ct(16)): a fresh IV per
        // call, but the encrypted plaintext is deterministic — derived from
        // the keystore's persisted device random. The credential-store state
        // additionally binds the credential counter, so its decrypted value
        // is stable across consecutive getInfo calls and changes only when
        // credentials are added or removed.
        let auth = self.keystore.get_auth_state();
        let key = crypto::hmac_sha256(b"fapico2-encStateKey", &auth.device_random);
        let mut state_data = auth.device_random.to_vec();
        state_data.extend_from_slice(&auth.cred_counter.to_le_bytes());
        let state_pt = crypto::hmac_sha256(b"fapico2-credStoreState", &state_data);
        let state_pt = &state_pt[..16];
        let iv = crypto::random_bytes::<16>();
        // `.clear()` first: `Ctap2Info::default()` already carries the 32
        // zero placeholder bytes, so extending onto it yields a 64-byte field
        // (32 zeros || IV || ciphertext) where CTAP2.1 §5.1.2 requires exactly
        // 32. `device_core.rs::get_info` — the hardware path — has always
        // *assigned* a freshly built vec and never hit this; only this path,
        // which the emulation binary and therefore every pytest suite runs,
        // did. Clearing makes the two encoders agree by construction.
        info.enc_cred_store_state.clear();
        info.enc_cred_store_state.extend_from_slice(&iv).ok();
        info.enc_cred_store_state
            .extend_from_slice(&crypto::aes_cbc_encrypt(&key, &iv, state_pt))
            .ok();
        let id_pt = crypto::hmac_sha256(b"fapico2-encIdentifier", &auth.device_random);
        let id_pt = &id_pt[..16];
        let iv2 = crypto::random_bytes::<16>();
        info.enc_identifier.clear();
        info.enc_identifier.extend_from_slice(&iv2).ok();
        info.enc_identifier
            .extend_from_slice(&crypto::aes_cbc_encrypt(&key, &iv2, id_pt))
            .ok();
        // clientPin option: per CTAP2 spec, the key is always present (it
        // indicates PIN capability); its value reflects whether a PIN is
        // currently set. This lets python-fido2's ClientPin constructor
        // detect PIN support before any PIN is configured.
        let pin_state = self.keystore.get_pin_state();
        let pin_set = pin_state.pin_hash.is_some();
        info.set_option("clientPin", pin_set);
        // US-1512: the capability half of the PIN/UV pair, set from the same
        // shared helper the device twin uses so the two cannot drift — the
        // rule is at `ctap2::pin_uv_auth_token_available`.
        info.set_option(
            "pinUvAuthToken",
            crate::ctap2::pin_uv_auth_token_available(pin_state.blocked, pin_state.needs_power_cycle),
        );
        // authnrCfg is advertised by the reference firmware.
        info.set_option("authnrCfg", true);
        // Enterprise attestation is implemented (FX-408): Config 0x01 enables
        // it, MC key 0x0A requests it, setEnterpriseRPIDList (Config 0x04)
        // manages the list.
        info.set_option("enterpriseAttestation", true);
        // alwaysUv reflects the current config state (toggled by Config 0x02).
        info.set_option("alwaysUv", pin_state.always_uv);
        // Dynamic state fields.
        info.force_pin_change = pin_state.force_pin_change;
        info.pin_complexity_policy = Some(pin_state.pin_complexity_policy);
        let cbor_value = info.to_cbor();
        let data = cbor::encode(&cbor_value);
        let mut resp = vec![Ctap2Response::Ok.code()];
        resp.extend_from_slice(&data);
        resp
    }

    // ------------------------------------------------------------------
    // clientPin
    // ------------------------------------------------------------------

    fn client_pin(&mut self, data: &[u8]) -> Vec<u8> {
        // Split-borrow: pin the mutable keystore and immutable hkey.
        let FidoApp {
            keystore,
            hkey,
            pin_token,
            pin_token_permissions,
            pin_token_rp_id,
            ..
        } = self;
        // Extract the token scope (permissions bitmask + bound rpId) from
        // the request before processing.
        let (permissions, rp_id) = parse_client_pin_token_scope(data);
        let mut pin = PinProtocol::new(keystore, hkey);
        match pin.process(data) {
            Ok(output) => {
                if let Some(token) = output.raw_pin_token {
                    *pin_token = Some(token);
                    *pin_token_permissions = permissions;
                    *pin_token_rp_id = rp_id;
                }
                let cbor_data = crate::pin::encode_client_pin_response(&output.response);
                let mut resp = vec![Ctap2Response::Ok.code()];
                resp.extend_from_slice(&cbor_data);
                resp
            }
            Err(e) => vec![e.to_ctap_error()],
        }
    }

    // ------------------------------------------------------------------
    // makeCredential (CTAP2 / US-316)
    // ------------------------------------------------------------------

    fn make_credential(&mut self, data: &[u8]) -> Vec<u8> {
        let req = match parse_mc_request(data) {
            Ok(r) => r,
            Err(e) => return vec![e.to_ctap_error()],
        };

        let pin_set = self.keystore.get_pin_state().pin_hash.is_some();

        // clientDataHash must be exactly 32 bytes (SHA-256 of clientDataJSON).
        if req.client_data_hash.len() != 32 {
            return vec![Ctap2Response::InvalidLength.code()];
        }

        // 2) Algorithm selection: first supported param with type=="public-key".
        // This is checked BEFORE the PIN/PUAT check (matching the reference C
        // firmware) so that UNSUPPORTED_ALGORITHM is returned even when a PIN
        // is set but no pinUvAuthParam is provided.
        let mut alg: i64 = 0;
        for p in &req.pubkey_creds {
            if p.type_ != "public-key" {
                continue;
            }
            if supports_algorithm(p.alg) {
                alg = p.alg;
                break;
            }
        }
        if alg == 0 {
            return vec![Ctap2Response::UnsupportedAlgorithm.code()];
        }

        // 1) PIN / pinUvAuth handling.
        let mut uv = false;
        if let Some(ref param) = req.pin_uv_auth_param {
            if !pin_set {
                return vec![Ctap2Response::PinNotSet.code()];
            }
            if self.keystore.get_pin_state().needs_power_cycle {
                return vec![Ctap2Response::PinAuthBlocked.code()];
            }
            if param.is_empty() {
                return vec![Ctap2Response::PinAuthInvalid.code()];
            }
            if req.pin_uv_protocol != 1 && req.pin_uv_protocol != 2 {
                return vec![Ctap2Response::InvalidParameter.code()];
            }
            if self.pin_token.is_none() {
                return vec![Ctap2Response::PinAuthInvalid.code()];
            }
            let token = self.pin_token.as_ref().unwrap();
            let token_arr: [u8; 32] = token
                .get(..32)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0u8; 32]);
            if !crypto::pin_verify_auth(
                req.pin_uv_protocol,
                &token_arr,
                &req.client_data_hash,
                param,
            ) {
                return vec![self.note_pin_auth_failure()];
            }
            self.note_pin_auth_success();
            // Permission scoping (FX-405): makeCredential requires the mc bit.
            if !self.token_allows(PERM_MC) {
                return vec![Ctap2Response::PinAuthInvalid.code()];
            }
            // A token bound to an rpId must not be used for another RP.
            if !self.token_rp_id_ok(&req.rp_id) {
                return vec![Ctap2Response::PinAuthInvalid.code()];
            }
            uv = true;
        }

        // 8.1 rule: if PIN set and no pinUvAuthParam and options.uv != false → PUAT_REQUIRED.
        if pin_set && req.pin_uv_auth_param.is_none()
            && (!req.options.present || req.options.uv != Some(false)) {
                return vec![Ctap2Response::PuatRequired.code()];
            }

        // 3) Exclude list: if any resident credential matches, CREDENTIAL_EXCLUDED.
        for desc in &req.exclude_list {
            if desc.type_ != "public-key" {
                continue;
            }
            if desc.id.is_empty() {
                continue;
            }
            if let Some(cred) = self.keystore.get_credential(&desc.id) {
                // Revoked credentials are not excluded (they're gone).
                if cred.revoked {
                    continue;
                }
                // credProtect UV_REQUIRED credentials are excluded only when UV done.
                if cred.cred_protect == 3 && !uv {
                    continue;
                }
                return vec![Ctap2Response::CredentialExcluded.code()];
            }
        }

        // 4) User presence. In emulation we always succeed; set UP flag.
        // US-1526: MC `up:false` → INVALID_OPTION. The decision, the
        // argument and what would have to change to relax it are written out
        // in full on the device twin's copy of this check
        // (`device_core.rs`, `make_credential_inner`, "THE `up` POLICY,
        // decided" — reference C parity at
        // `pico-fido/src/fido/cbor_make_credential.c:387`). This is the
        // second copy of one policy in two files; the full text lives on the
        // twin that actually ships, and this line says where. The pair must
        // not be relaxed independently — that is the defect US-1514 was
        // filed for.
        if req.options.present
            && req.options.up == Some(false) {
                return vec![Ctap2Response::InvalidOption.code()];
            }
        // options.uv = true: UV must actually be performed. With a pin token
        // (uv already true) we're done; without one it is a hard error.
        if req.options.uv == Some(true) && !uv {
            return vec![Ctap2Response::PuatRequired.code()];
        }
        // alwaysUv (Config 0x02): UV is mandatory for makeCredential even
        // when the client did not request it.
        if !uv && self.keystore.get_pin_state().always_uv {
            return vec![Ctap2Response::PuatRequired.code()];
        }

        // 5) Generate a keypair for the requested algorithm.
        // US-1007: a source that cannot produce entropy now answers here
        // with a clean CTAP error instead of spinning in the curve crate's
        // rejection sampler. `Other` (0x7F) rather than a policy-sounding
        // code: nothing was denied and nothing was tampered with — the
        // authenticator simply had no fresh bytes to give, and a client that
        // retries on `Other` is the behaviour a transient peripheral starve
        // should provoke.
        let (priv_bytes, cose_key) = match generate_alg_keypair(alg) {
            Ok(kp) => kp,
            Err(_) => return vec![Ctap2Response::Other.code()],
        };
        let cose_pubkey = encode_cose_pubkey(&cose_key);

        // Credential ID. For resident keys, derive a stable id from rp+user+priv;
        // for non-resident, use a random id.
        let rp_id_hash = crypto::sha256(req.rp_id.as_bytes());
        let cred_id = if req.options.rk == Some(true) {
            credential_derive_resident_id(&rp_id_hash, &req.user_handle)
        } else {
            crypto::random_vec(32)
        };

        // largeBlobKey (FX-414): only meaningful for resident credentials
        // (the key is derived, not random, so it is stable across resets).
        if req.extensions.large_blob_key && req.options.rk != Some(true) {
            return vec![Ctap2Response::InvalidOption.code()];
        }
        let large_blob_key = if req.extensions.large_blob_key {
            Some(derive_large_blob_key(self.hkey.to_bytes().as_ref(), &cred_id))
        } else {
            None
        };

        // Attested credential data: aaguid(16) + credIdLen(2) + credId + COSE pubkey.
        let att_cred_data = build_attested_cred_data(&cred_id, &cose_pubkey);

        // Flags: UP(0x01) | AT(0x040), plus UV(0x04) when PIN verified and
        // ED(0x80) when extensions are present.
        let mut flags: u8 = 0x01 | 0x40;
        if uv {
            flags |= 0x04;
        }
        // Determine which extensions appear in the authData output.
        let pin_state = self.keystore.get_pin_state();
        let min_pin_for_rp = if req.extensions.min_pin_length {
            // The minPinLength extension reflects the configured min PIN length
            // when the RP is in the allowlist (empty list = all RPs).
            let rp_matches = pin_state.min_pin_rp_ids.is_empty()
                || pin_state.min_pin_rp_ids.iter().any(|id| id == &req.rp_id);
            if rp_matches {
                Some(pin_state.min_pin_length)
            } else {
                None
            }
        } else {
            None
        };
        let show_pin_complexity =
            req.extensions.pin_complexity_policy && pin_state.pin_complexity_policy;
        // credBlob: store the blob if it fits within max_cred_blob_length.
        let cred_blob_input = req.extensions.cred_blob.clone();
        let cred_blob_to_store = match &cred_blob_input {
            Some(blob) if blob.len() <= DEFAULT_MAX_CRED_BLOB_LENGTH => {
                Some(blob.clone())
            }
            _ => None,
        };
        let cred_blob_stored = cred_blob_to_store.is_some();

        // Compute has_extensions AFTER credBlob so the ED flag is set correctly.
        let has_extensions = req.extensions.third_party_payment
            || min_pin_for_rp.is_some()
            || show_pin_complexity
            || cred_blob_input.is_some()
            || req.extensions.hmac_secret
            || req.extensions.hmac_secret_mc.is_some()
            || req.extensions.large_blob_key
            || req.extensions.cred_protect > 0;
        if has_extensions {
            flags |= 0x80; // ED: extension data present
        }
        let sign_count = {
            let s = self.keystore.get_auth_state();
            s.cred_counter
        };
        let mut auth_data =
            build_auth_data(&rp_id_hash, flags, sign_count, Some(&att_cred_data));

        // Append extension data (CBOR map) when the ED flag is set.
        if has_extensions {
            let mut ext_map: Vec<(cbor::Value, cbor::Value)> = vec![];
            if req.extensions.third_party_payment {
                ext_map.push((
                    cbor::Value::T("thirdPartyPayment".to_string()),
                    cbor::Value::Bool(true),
                ));
            }
            if let Some(min_len) = min_pin_for_rp {
                ext_map.push((
                    cbor::Value::T("minPinLength".to_string()),
                    cbor::Value::U(min_len as u64),
                ));
            }
            if show_pin_complexity {
                ext_map.push((
                    cbor::Value::T("pinComplexityPolicy".to_string()),
                    cbor::Value::Bool(true),
                ));
            }
            if req.extensions.cred_protect > 0 {
                ext_map.push((
                    cbor::Value::T("credProtect".to_string()),
                    cbor::Value::U(req.extensions.cred_protect as u64),
                ));
            }
            if req.extensions.hmac_secret {
                ext_map.push((
                    cbor::Value::T("hmac-secret".to_string()),
                    cbor::Value::Bool(true),
                ));
            }
            if let Some(hs) = &req.extensions.hmac_secret_mc {
                match self.derive_hmac_output(hs, uv) {
                    Ok(enc) => ext_map.push((
                        cbor::Value::T("hmac-secret-mc".to_string()),
                        cbor::Value::B(enc),
                    )),
                    Err(code) => return vec![code],
                }
            }
            if cred_blob_input.is_some() {
                ext_map.push((
                    cbor::Value::T("credBlob".to_string()),
                    cbor::Value::Bool(cred_blob_stored),
                ));
            }
            if req.extensions.large_blob_key {
                ext_map.push((
                    cbor::Value::T("largeBlobKey".to_string()),
                    cbor::Value::Bool(true),
                ));
            }
            if !ext_map.is_empty() {
                let ext_cbor = cbor::encode(&cbor::Value::M(ext_map));
                auth_data.extend_from_slice(&ext_cbor);
            }
        }

        // 6) Store the credential.
        let cred = StoredCredential {
            credential_id: cred_id.clone(),
            public_key: cose_key,
            private_key: priv_bytes,
            rp_id_hash,
            rp_id: Some(req.rp_id.clone()),
            user_handle: req.user_handle,
            user_name: if req.user_name.is_empty() {
                None
            } else {
                Some(req.user_name)
            },
            user_display_name: if req.user_display_name.is_empty() {
                None
            } else {
                Some(req.user_display_name)
            },
            cred_protect: req.extensions.cred_protect,
            large_blob_key,
            hmac_secret: None,
            cred_blob: cred_blob_to_store,
            third_party_payment: req.extensions.third_party_payment,
            pin_complexity_policy: false,
            resident: req.options.rk == Some(true),
            algorithm: alg as i32,
            counter: sign_count,
            revoked: false,
            expires_at: None,
        };
        // Increment the persistent signature counter BEFORE the persist
        // point (store_credential snapshots to disk in FileKeystore), so the
        // persisted counter includes this registration (FX-409).
        {
            let s = self.keystore.get_auth_state_mut();
            s.cred_counter = s.cred_counter.wrapping_add(1);
        }
        if let Err(e) = self.keystore.store_credential(cred) {
            return vec![match e {
                crate::keystore::KeystoreError::Full => Ctap2Response::KeyStoreFull.code(),
                _ => Ctap2Response::NotAllowed.code(),
            }];
        }

        // Enterprise attestation (CTAP2.1 §8.4 / FX-408): the EP flag (0x02)
        // is set in the authData flags byte; the statement format remains
        // "packed" (enterprise attestation semantics).
        if let Some(ep_att) = req.enterprise_attestation {
            if !self.enterprise_attestation {
                return vec![Ctap2Response::UnauthorizedPermission.code()];
            }
            if ep_att == 2 {
                let state = self.keystore.get_pin_state();
                let listed = state.enterprise_rp_ids.iter().any(|r| r == &req.rp_id);
                if !listed {
                    return vec![Ctap2Response::NotAllowed.code()];
                }
            }
            // epAtt == 1 (full): applies to any RP.
            auth_data[32] |= 0x02;
        }

        // 7) Attestation statement — "packed" format with x5c.
        // Sign over authenticatorData || clientDataHash using the per-device
        // attestation key (US-916).
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&req.client_data_hash);
        let signature = crypto::p256_sign_bytes(self.attestation.key(), &signed_data);

        let att_stmt = cbor::Value::M(vec![
            (cbor::Value::T("alg".to_string()), cbor::Value::N(-7)), // alg: ES256
            (cbor::Value::T("sig".to_string()), cbor::Value::B(signature)),
            (
                cbor::Value::T("x5c".to_string()),
                cbor::Value::A(vec![cbor::Value::B(
                    self.attestation.cert_bytes().to_vec(),
                )]),
            ),
        ]);
        let response_map = vec![
            (cbor::Value::U(0x01), cbor::Value::T("packed".to_string())), // fmt
            (cbor::Value::U(0x02), cbor::Value::B(auth_data)),            // authData
            (cbor::Value::U(0x03), att_stmt),                             // attStmt
        ];
        let mut response_map = response_map;
        // largeBlobKey (response key 0x05) when the extension was requested.
        if let Some(ref lbk) = large_blob_key {
            response_map.push((cbor::Value::U(0x05), cbor::Value::B(lbk.to_vec())));
        }
        let response = cbor::Value::M(response_map);
        let encoded = cbor::encode(&response);
        let mut resp = vec![Ctap2Response::Ok.code()];
        resp.extend_from_slice(&encoded);
        resp
    }

    // ------------------------------------------------------------------
    // getAssertion (CTAP2 / US-317)
    // ------------------------------------------------------------------

    fn get_assertion(&mut self, data: &[u8]) -> Vec<u8> {
        let req = match parse_ga_request(data) {
            Ok(r) => r,
            Err(e) => return vec![e.to_ctap_error()],
        };

        let pin_set = self.keystore.get_pin_state().pin_hash.is_some();
        let mut uv = false;

        if let Some(ref param) = req.pin_uv_auth_param {
            if !pin_set {
                return vec![Ctap2Response::PinNotSet.code()];
            }
            if param.is_empty() {
                return vec![Ctap2Response::PinAuthInvalid.code()];
            }
            if req.pin_uv_protocol != 1 && req.pin_uv_protocol != 2 {
                return vec![Ctap2Response::InvalidParameter.code()];
            }
            if self.pin_token.is_none() {
                return vec![Ctap2Response::PinAuthInvalid.code()];
            }
            let token = self.pin_token.as_ref().unwrap();
            let token_arr: [u8; 32] = token
                .get(..32)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0u8; 32]);
            if !crypto::pin_verify_auth(
                req.pin_uv_protocol,
                &token_arr,
                &req.client_data_hash,
                param,
            ) {
                return vec![self.note_pin_auth_failure()];
            }
            self.note_pin_auth_success();
            // Permission scoping (FX-405): getAssertion requires the ga bit.
            if !self.token_allows(PERM_GA) {
                return vec![Ctap2Response::PinAuthInvalid.code()];
            }
            if !self.token_rp_id_ok(&req.rp_id) {
                return vec![Ctap2Response::PinAuthInvalid.code()];
            }
            uv = true;
        }

        // options validation (P3-17: up=false + uv=true is a legal
        // combination; uv=true simply requires a PUAT).
        if req.options.uv == Some(true) && !uv {
            return vec![Ctap2Response::PuatRequired.code()];
        }
        // alwaysUv (Config 0x02): UV is mandatory for getAssertion.
        if !uv && self.keystore.get_pin_state().always_uv {
            return vec![Ctap2Response::PuatRequired.code()];
        }
        // hmac-secret with silent authentication is not allowed (C parity).
        // US-1526: the device twin has this same check
        // (`device_core.rs`, `handle_get_assertion`, under "US-1526:
        // getAssertion `up:false` is SERVED"), and the reasoning — the
        // reference's one rejected combination, at
        // `pico-fido/src/fido/cbor_get_assertion.c:324` — is written out
        // there. The brief for this story suggested only the host twin had
        // it; it does not, and `tests/up_policy.rs` pins the agreement so the
        // question does not reopen.
        if req.options.up == Some(false) && req.extensions.hmac_secret_input.is_some() {
            return vec![Ctap2Response::InvalidOption.code()];
        }

        // Determine whether to set the UP flag. options.up == false means
        // "silent" authentication: do not perform UP and do not set the flag.
        // options.up == true or absent → perform UP and set the flag.
        let do_up = req.options.up != Some(false);

        // Determine which credentials match.
        let rp_id_hash = crypto::sha256(req.rp_id.as_bytes());
        let mut matched = Vec::new();

        if !req.allow_list.is_empty() {
            // allowList filtering: only credentials in the list that belong to this rp.
            for desc in &req.allow_list {
                if desc.type_ != "public-key" {
                    continue;
                }
                if let Some(cred) = self.keystore.get_credential(&desc.id) {
                    // Revoked credentials are not matchable.
                    if cred.revoked {
                        continue;
                    }
                    // credProtect REQUIRED credentials are not returned without UV.
                    if cred.cred_protect == 3 && !uv {
                        continue;
                    }
                    if cred.rp_id_hash == rp_id_hash {
                        matched.push(cred.clone());
                    }
                    continue;
                }
                // US-714 interop: a U2F key handle is *stateless* — the
                // private key is re-derived at assertion time and no keystore
                // entry is ever created (see `u2f::u2f_register`). So a CTAP2
                // allowList carrying a U2F handle missed the lookup above and
                // answered NO_CREDENTIALS, which is why
                // `test_authenticate_ctap1_through_ctap2` — register over U2F,
                // assert over CTAP2, the interop real authenticators perform —
                // could never pass.
                //
                // `verify_handle` re-derives the key AND authenticates the
                // handle's appId tag in constant time, so an arbitrary 64-byte
                // blob cannot become an assertion key: a forged handle fails
                // the tag check and is skipped, exactly as the U2F AUTHENTICATE
                // path already treats it (u2f.rs, `stateless_valid`).
                //
                // Semantics deliberately inherited from U2F: `resident` is false
                // (never discoverable — there is no stored record to enumerate),
                // `user_handle` is empty (U2F carries no user identity), and
                // the signature counter is the keystore-wide one, which the U2F
                // path already treats as the global counter.
                if let Some(cred) =
                    self.stateless_u2f_credential_for(&desc.id, &rp_id_hash)
                {
                    matched.push(cred);
                }
            }
        } else {
            // No allowList: enumerate all *resident* credentials for this rp.
            // The reference firmware returns them in reverse storage order
            // (newest first), so we reverse the list to match.
            let mut creds: Vec<StoredCredential> = self
                .keystore
                .list_credentials_by_rp(&rp_id_hash)
                .into_iter()
                // Without UV, credentials with credProtect >= 2
                // (optionalWithCredentialIDList and required) are withheld
                // from discoverable enumeration (CTAP2.1 §6.4.2).
                .filter(|c| c.resident && !c.revoked && (uv || c.cred_protect < 2))
                .cloned()
                .collect();
            creds.reverse();
            matched = creds;
        }

        if matched.is_empty() {
            return vec![Ctap2Response::NoCredentials.code()];
        }

        if !req.allow_list.is_empty() {
            // CTAP2: when an allowList is provided, the authenticator returns
            // exactly ONE matching credential. No getNextAssertion follows.
            let first = matched.remove(0);
            self.ga_state = None;
            self.build_assertion(first, &req.client_data_hash, uv, do_up, 1, &req.extensions)
        } else {
            // No allowList: discoverable-credential lookup. Return the first
            // and stash the rest for get_next_assertion.
            let first = matched.remove(0);
            let total = matched.len() + 1;
            let assertion = self.build_assertion(
                first,
                &req.client_data_hash,
                uv,
                do_up,
                total,
                &req.extensions,
            );
            if matched.is_empty() {
                self.ga_state = None;
            } else {
                self.ga_state = Some(GaState {
                    credentials: matched,
                    cursor: 0,
                    client_data_hash: req.client_data_hash,
                    uv,
                    do_up,
                    total,
                    channel: self.current_channel,
                    has_extensions: req.extensions.third_party_payment,
                    get_cred_blob: req.extensions.get_cred_blob,
                    hmac_secret_input: req.extensions.hmac_secret_input.clone(),
                    large_blob_key: req.extensions.large_blob_key,
                });
            }
            assertion
        }
    }

    fn get_next_assertion(&mut self) -> Vec<u8> {
        // CTAP2 spec: getNextAssertion MUST be on the same channel as the
        // original getAssertion, otherwise return NOT_ALLOWED.
        if let Some(ref state) = self.ga_state {
            if state.channel != self.current_channel {
                return vec![Ctap2Response::NotAllowed.code()];
            }
        }
        // Extract the data we need from ga_state, then drop the borrow
        // before calling build_assertion (which needs &mut self).
        let (cred, client_data_hash, uv, do_up, total, is_last, tp_pay, get_blob, hmac_in, lbk) = {
            let state = match self.ga_state.as_mut() {
                Some(s) => s,
                // No pending getAssertion sequence: NOT_ALLOWED, not
                // NO_CREDENTIALS (finding 14).
                None => return vec![Ctap2Response::NotAllowed.code()],
            };
            if state.cursor >= state.credentials.len() {
                self.ga_state = None;
                return vec![Ctap2Response::NoCredentials.code()];
            }
            let cred = state.credentials[state.cursor].clone();
            state.cursor += 1;
            let is_last = state.cursor >= state.credentials.len();
            (
                cred,
                state.client_data_hash.clone(),
                state.uv,
                state.do_up,
                state.total,
                is_last,
                state.has_extensions,
                state.get_cred_blob,
                state.hmac_secret_input.clone(),
                state.large_blob_key,
            )
        };
        // Reconstruct the extensions for getNextAssertion.
        let exts = McExtensions {
            third_party_payment: tp_pay,
            get_cred_blob: get_blob,
            hmac_secret_input: hmac_in,
            large_blob_key: lbk,
            ..Default::default()
        };
        let assertion = self.build_assertion(cred, &client_data_hash, uv, do_up, total, &exts);
        if is_last {
            self.ga_state = None;
        }
        assertion
    }

    /// Re-derive a U2F (stateless) credential for CTAP2 assertion.
    ///
    /// US-714 made U2F registration stateless: the key handle encodes the key's
    /// derivation path plus a tag over the requesting RP, and **no keystore
    /// entry is created**. A CTAP2 `allowList` therefore cannot find such a
    /// handle through `keystore::get_credential`, and a credential registered
    /// over U2F was unassertable over CTAP2 — the interop
    /// `test_authenticate_ctap1_through_ctap2` performs, and that real
    /// authenticators perform.
    ///
    /// Returns `None` unless the handle is well-formed **and** its tag
    /// authenticates against `rp_id_hash`, so a caller cannot turn an
    /// arbitrary blob into an assertion key by naming it in an allowList.
    ///
    /// `Ok(None)`-style refusals are deliberate: the caller treats "not a
    /// credential for this RP" and "not a credential at all" identically,
    /// which is what `NO_CREDENTIALS` already reports.
    fn stateless_u2f_credential_for(
        &mut self,
        handle: &[u8],
        rp_id_hash: &[u8; 32],
    ) -> Option<StoredCredential> {
        if !crate::stateless::is_stateless(handle) {
            return None;
        }
        let master = crate::stateless::master_from_device_random(
            &self.keystore.get_auth_state().device_random,
        );
        // Constant-time tag check; a handle minted for a different RP fails
        // here and is skipped rather than signed.
        if !crate::stateless::verify_handle(master.bytes(), rp_id_hash, handle) {
            return None;
        }
        let scalar = crate::stateless::derive_scalar(master.bytes(), handle)?;
        let secret = crypto::secret_key_from_bytes(scalar.bytes())?;
        let pk = crypto::public_key_bytes(&secret.public_key());
        // Uncompressed SEC1 point: 0x04 || X(32) || Y(32).
        let (x, y) = pk.get(1..65).and_then(|c| {
            let (x, y) = c.split_at(32);
            Some((<[u8; 32]>::try_from(x).ok()?, <[u8; 32]>::try_from(y).ok()?))
        })?;

        Some(StoredCredential {
            credential_id: handle.to_vec(),
            public_key: CosePublicKey::es256(x, y),
            private_key: scalar.bytes().to_vec(),
            rp_id_hash: *rp_id_hash,
            rp_id: None,
            // U2F carries no user identity: the registration predates CTAP2's
            // user entity, and asserting one must not invent a handle.
            user_handle: Vec::new(),
            user_name: None,
            user_display_name: None,
            cred_protect: 0,
            large_blob_key: None,
            hmac_secret: None,
            cred_blob: None,
            third_party_payment: false,
            pin_complexity_policy: false,
            // Stateless handles have no stored record, so they are never
            // discoverable — they can only be named explicitly in an
            // allowList, which is the only path that reaches this.
            resident: false,
            algorithm: -7,
            // U2F has no per-credential counter; the U2F AUTHENTICATE path uses
            // the keystore-wide one, and `build_assertion` reads this field.
            counter: self.keystore.get_auth_state().cred_counter,
            revoked: false,
            // U2F registration cannot express an expiry.
            expires_at: None,
        })
    }

    /// Build a getAssertion CBOR response for the given credential.
    fn build_assertion(
        &mut self,
        mut cred: StoredCredential,
        client_data_hash: &[u8],
        uv: bool,
        do_up: bool,
        // total: Total number of matching credentials. When > 1, the response
        // includes numberOfCredentials (CBOR key 0x05) set to this value.
        total: usize,
        // exts: the parsed getAssertion extension inputs.
        exts: &McExtensions,
    ) -> Vec<u8> {
        // hmac-secret (CTAP2.1 §6.7): verify saltAuth, decrypt the salts and
        // derive the outputs with the device-keyed credential random.
        let hmac_output: Option<Vec<u8>> = match &exts.hmac_secret_input {
            Some(hs) => match self.derive_hmac_output(hs, uv) {
                Ok(enc) => Some(enc),
                Err(code) => return vec![code],
            },
            None => None,
        };
        // Determine which extensions appear in the output.
        let has_extensions = exts.third_party_payment
            || exts.get_cred_blob
            || hmac_output.is_some();
        // UP flag is set only when user presence is requested (do_up).
        // options.up == false → silent authentication, no UP flag.
        let mut flags: u8 = 0;
        if do_up {
            flags |= 0x01; // UP
        }
        if uv {
            flags |= 0x04; // UV
        }
        if has_extensions {
            flags |= 0x80; // ED: extension data present
        }
        let sign_count = cred.counter.wrapping_add(1);
        let mut auth_data = build_auth_data(&cred.rp_id_hash, flags, sign_count, None);
        // Append extension data (CBOR map) when the ED flag is set.
        if has_extensions {
            let mut ext_map: Vec<(cbor::Value, cbor::Value)> = vec![];
            if exts.third_party_payment {
                ext_map.push((
                    cbor::Value::T("thirdPartyPayment".to_string()),
                    cbor::Value::Bool(true),
                ));
            }
            if let Some(enc) = hmac_output {
                ext_map.push((
                    cbor::Value::T("hmac-secret".to_string()),
                    cbor::Value::B(enc),
                ));
            }
            if exts.get_cred_blob {
                // Return the stored credBlob (empty if none stored).
                ext_map.push((
                    cbor::Value::T("credBlob".to_string()),
                    cbor::Value::B(cred.cred_blob.clone().unwrap_or_default()),
                ));
            }
            if !ext_map.is_empty() {
                let ext_cbor = cbor::encode(&cbor::Value::M(ext_map));
                auth_data.extend_from_slice(&ext_cbor);
            }
        }

        // Sign over authData || clientDataHash.
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(client_data_hash);
        let signature = match sign_with_alg(cred.algorithm, &cred.private_key, &signed_data) {
            Some(sig) => sig,
            None => return vec![Ctap2Response::InvalidCommand.code()],
        };

        // Persist the incremented counter.
        cred.counter = sign_count;
        let cred_id = cred.credential_id.clone();
        let large_blob_key = cred.large_blob_key;
        let user_handle = cred.user_handle.clone();
        let _user_name = cred.user_name.clone();
        let _user_display_name = cred.user_display_name.clone();
        let is_resident = cred.resident;
        let _ = self.keystore.store_credential(cred);
        {
            let s = self.keystore.get_auth_state_mut();
            s.cred_counter = s.cred_counter.max(sign_count);
        }

        // credential descriptor (key 0x01).
        let cred_descriptor = cbor::Value::M(vec![
            (cbor::Value::T("type".to_string()), cbor::Value::T("public-key".to_string())),
            (cbor::Value::T("id".to_string()), cbor::Value::B(cred_id.clone())),
        ]);

        // user (key 0x04) — only present when the credential has a user handle
        // and this is the sole or first assertion of a non-allowList flow.
        let mut response_map: Vec<(cbor::Value, cbor::Value)> = vec![
            (cbor::Value::U(0x01), cred_descriptor),
            (cbor::Value::U(0x02), cbor::Value::B(auth_data)),
            (cbor::Value::U(0x03), cbor::Value::B(signature)),
        ];

        // Include user entity for resident credentials (rk=true), matching
        // the reference C firmware which keys off the credential's resident
        // flag, not the presence of an allowList in the request.
        if is_resident && !user_handle.is_empty() {
            let user_entity = cbor::Value::M(vec![
                (cbor::Value::T("id".to_string()), cbor::Value::B(user_handle)),
            ]);
            response_map.push((cbor::Value::U(0x04), user_entity));
        }

        // numberOfCredentials (key 0x05) when more than one credential matched.
        if total > 1 {
            response_map.push((cbor::Value::U(0x05), cbor::Value::U(total as u64)));
        }

        // largeBlobKey (response key 0x07) when the client requested the
        // extension and the credential carries a key (FX-414).
        if exts.large_blob_key {
            if let Some(lbk) = large_blob_key {
                response_map.push((cbor::Value::U(0x07), cbor::Value::B(lbk.to_vec())));
            }
        }

        let response = cbor::Value::M(response_map);
        let encoded = cbor::encode(&response);
        let mut resp = vec![Ctap2Response::Ok.code()];
        resp.extend_from_slice(&encoded);
        resp
    }

    // ------------------------------------------------------------------
    // credMgmt (CTAP2 / US-320)
    // ------------------------------------------------------------------

    fn cred_mgmt(&mut self, data: &[u8]) -> Vec<u8> {
        let req = match parse_cm_request(data) {
            Ok(r) => r,
            Err(e) => return vec![e.to_ctap_error()],
        };

        let pin_set = self.keystore.get_pin_state().pin_hash.is_some();

        // subcommands that don't require PIN auth: 0x03 (enumerateRpsNext),
        // 0x05 (enumerateCredsNext). Everything else needs a pinUvAuthParam.
        let needs_pincmd = !matches!(req.subcommand, 0x03 | 0x05);

        if needs_pincmd {
            let param = match req.pin_uv_auth_param {
                Some(p) => p,
                None => return vec![Ctap2Response::PuatRequired.code()],
            };
            if req.pin_uv_protocol != 1 && req.pin_uv_protocol != 2 {
                return vec![Ctap2Response::InvalidParameter.code()];
            }
            // A PIN is not the only way to be authorised: a factory-fresh key
            // has none, and CTAP2 expects a pinUvAuthToken minted from built-in
            // user verification to stand in for it. Gating on "a PIN is set"
            // alone left such a key unable to use credentialManagement at all,
            // so the real requirement — a live token — is checked instead.
            // Nothing is weakened: the token is still verified below, and one
            // can only exist if a token sub-command succeeded (0x06 only after
            // a user-presence grant). With neither, this is still PinNotSet.
            if !pin_set && self.pin_token.is_none() {
                return vec![Ctap2Response::PinNotSet.code()];
            }
            if self.keystore.get_pin_state().needs_power_cycle {
                return vec![Ctap2Response::PinAuthBlocked.code()];
            }
            if self.pin_token.is_none() {
                return vec![Ctap2Response::PinAuthInvalid.code()];
            }
            let token = self.pin_token.as_ref().unwrap();
            let token_arr: [u8; 32] = token
                .get(..32)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0u8; 32]);
// The signed message is over the *wire* sub-command byte in both dialects,
            // never the canonical one: PicoForge signs its own numbering.
            let mut auth_data = vec![req.wire_subcommand];
            match req.dialect {
                // PicoForge: `subCommand ‖ CBOR(subCommandParams)`.
                //
                // Deliberately rebuilt from the parsed fields rather than
                // taken verbatim from the received map: for `0x01`/`0x02` this
                // yields no params, so a client that also sent
                // subCommandParams has them fall outside the signed scope and
                // is still accepted.
                // The device twin is stricter — it signs the raw bytes
                // whenever any were sent — and
                // `device_full_set.rs::device_twin_credmgmt_mac_scope_differs_from_host_for_0x01_and_0x02`
                // pins that split. Both halves must survive this change.
                CmDialect::PicoForge => {
                    let params_cbor = match req.subcommand {
                        CM_ENUMERATE_CREDS_BEGIN => {
                            // params = {0x01: rpIdHash}
                            req.rp_id_hash.as_ref().map(|h| {
                                cbor::encode(&cbor::Value::M(vec![(
                                    cbor::Value::U(0x01),
                                    cbor::Value::B(h.clone()),
                                )]))
                            })
                        }
                        CM_DELETE_CRED => {
                            // params = {0x02: credId}
                            req.cred_id.as_ref().map(|desc| {
                                let cred_id_map = cbor::Value::M(vec![
                                    (cbor::Value::T("type".to_string()), cbor::Value::T("public-key".to_string())),
                                    (cbor::Value::T("id".to_string()), cbor::Value::B(desc.id.clone())),
                                ]);
                                cbor::encode(&cbor::Value::M(vec![(
                                    cbor::Value::U(0x02),
                                    cred_id_map,
                                )]))
                            })
                        }
                        CM_UPDATE_USER => {
                            // params = {0x02: credId, 0x03: user}
                            if let (Some(desc), Some(user)) = (&req.cred_id, &req.user) {
                                let cred_id_map = cbor::Value::M(vec![
                                    (cbor::Value::T("type".to_string()), cbor::Value::T("public-key".to_string())),
                                    (cbor::Value::T("id".to_string()), cbor::Value::B(desc.id.clone())),
                                ]);
                                let mut user_entries: Vec<(cbor::Value, cbor::Value)> = vec![
                                    (cbor::Value::T("id".to_string()), cbor::Value::B(user.id.clone())),
                                ];
                                if !user.name.is_empty() {
                                    user_entries.push((cbor::Value::T("name".to_string()), cbor::Value::T(user.name.clone())));
                                }
                                if !user.display_name.is_empty() {
                                    user_entries.push((cbor::Value::T("displayName".to_string()), cbor::Value::T(user.display_name.clone())));
                                }
                                let user_map = cbor::Value::M(user_entries);
                                Some(cbor::encode(&cbor::Value::M(vec![
                                    (cbor::Value::U(0x02), cred_id_map),
                                    (cbor::Value::U(0x03), user_map),
                                ])))
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };
                    if let Some(params) = params_cbor {
                        auth_data.extend_from_slice(&params);
                    }
                }
                // CTAP2 §12.1.6 signs the parameters the sub-command carries,
                // concatenated in spec order. The credentialID and user bytes
                // are taken exactly as received — a client signs the encoding
                // it sent, key order included, so re-encoding could diverge.
                CmDialect::Ctap2 => match req.subcommand {
                    CM_ENUMERATE_CREDS_BEGIN => {
                        if let Some(h) = req.rp_id_hash.as_ref() {
                            auth_data.extend_from_slice(h);
                        }
                    }
                    CM_DELETE_CRED => {
                        if let Some(raw) = req.raw_cred_cbor.as_ref() {
                            auth_data.extend_from_slice(raw);
                        }
                    }
                    CM_UPDATE_USER => {
                        if let Some(raw) = req.raw_cred_cbor.as_ref() {
                            auth_data.extend_from_slice(raw);
                        }
                        if let Some(raw) = req.raw_user_cbor.as_ref() {
                            auth_data.extend_from_slice(raw);
                        }
                    }
                    _ => {}
                },
            }
            if !crypto::pin_verify_auth(req.pin_uv_protocol, &token_arr, &auth_data, &param) {
                return vec![self.note_pin_auth_failure()];
            }
            self.note_pin_auth_success();
            // Permission scoping (FX-405): credMgmt requires the cm bit
            // (the persistent-cm vendor extension also grants it).
            if !self.token_allows(PERM_CM | PERM_CM_PERSISTENT) {
                return vec![Ctap2Response::PinAuthInvalid.code()];
            }
        }

        // The response encoders key off the dialect: the PicoForge and CTAP2
        // key sets collide, so a request has to be answered in the shape its
        // sender asked in.
        self.cm_dialect = req.dialect;
        let result = match req.subcommand {
            CM_GET_METADATA => self.cm_get_metadata(),
            CM_ENUMERATE_RPS_BEGIN => self.cm_enumerate_rps_begin(),
            CM_ENUMERATE_RPS_NEXT => self.cm_enumerate_rps_next(),
            CM_ENUMERATE_CREDS_BEGIN => {
                let hash = match req.rp_id_hash.as_deref() {
                    Some(h) if h.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(h);
                        arr
                    }
                    _ => return vec![Ctap2Response::MissingParameter.code()],
                };
                self.cm_enumerate_creds_begin(&hash)
            }
            CM_ENUMERATE_CREDS_NEXT => self.cm_enumerate_creds_next(),
            CM_DELETE_CRED => self.cm_delete_cred(req.cred_id),
            CM_UPDATE_USER => self.cm_update_user(req.cred_id, req.user),
            _ => vec![Ctap2Response::InvalidCommand.code()],
        };
        // Any non-NULL command (except the enumerate next commands) resets
        // the enumeration state if it doesn't start a new one.
        result
    }

    // ------------------------------------------------------------------
    // authenticatorConfig (CTAP2 / US-321)
    // ------------------------------------------------------------------

    fn authenticator_config(&mut self, data: &[u8]) -> Vec<u8> {
        let req = match parse_config_request(data) {
            Ok(r) => r,
            Err(e) => return vec![e.to_ctap_error()],
        };

        // PIN auth is required for all config subcommands.
        let pin_set = self.keystore.get_pin_state().pin_hash.is_some();
        if !pin_set {
            return vec![Ctap2Response::PinNotSet.code()];
        }
        if self.keystore.get_pin_state().needs_power_cycle {
            return vec![Ctap2Response::PinAuthBlocked.code()];
        }
        if self.pin_token.is_none() {
            return vec![Ctap2Response::PinAuthInvalid.code()];
        }
        // Config commands require the AUTHENTICATOR_CFG permission (0x20).
        const AUTHENTICATOR_CFG_PERM: u8 = 0x20;
        if self.pin_token_permissions & AUTHENTICATOR_CFG_PERM == 0 {
            return vec![Ctap2Response::PinAuthInvalid.code()];
        }
        if req.pin_uv_protocol != 1 && req.pin_uv_protocol != 2 {
            return vec![Ctap2Response::InvalidParameter.code()];
        }
        // Verify pinUvAuthParam over 0xff*32 + 0x0d + sub_cmd + cbor(params).
        let token = self.pin_token.as_ref().unwrap();
        let token_arr: [u8; 32] = token
            .get(..32)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0u8; 32]);
        let mut auth_msg = vec![0xffu8; 32];
        auth_msg.push(0x0d); // CTAP2 CMD.CONFIG
        auth_msg.push(req.sub_cmd);
        if let Some(ref params) = req.params {
            auth_msg.extend_from_slice(&cbor::encode(params));
        }
        if !crypto::pin_verify_auth(req.pin_uv_protocol, &token_arr, &auth_msg, &req.pin_uv_auth_param)
        {
            return vec![self.note_pin_auth_failure()];
        }
        self.note_pin_auth_success();

        match req.sub_cmd {
            0x01 => self.cfg_enable_enterprise_attestation(),
            0x02 => self.cfg_toggle_always_uv(),
            0x03 => self.cfg_set_min_pin_length(&req.params),
            0x04 => self.cfg_set_enterprise_rp_ids(&req.params),
            // US-170: `data`, not just `req.params`, because the RS-Key
            // soft-lock arms re-verify the `0x0D` MAC over the **borrowed
            // wire span** and a decoded `cbor::Value` is not that span. See
            // `cfg_vendor_prototype`'s note on the re-encoding above.
            0xFF => self.cfg_vendor_prototype(data, &req.params),
            _ => vec![Ctap2Response::InvalidSubcommand.code()],
        }
    }

    fn cfg_enable_enterprise_attestation(&mut self) -> Vec<u8> {
        let s = self.keystore.get_pin_state_mut();
        s.enterprise_attestation = true;
        self.enterprise_attestation = true;
        let _ = self.keystore.save_pin_state();
        vec![Ctap2Response::Ok.code()]
    }

    fn cfg_toggle_always_uv(&mut self) -> Vec<u8> {
        let s = self.keystore.get_pin_state_mut();
        s.always_uv = !s.always_uv;
        let _ = self.keystore.save_pin_state();
        vec![Ctap2Response::Ok.code()]
    }

    fn cfg_set_min_pin_length(&mut self, params: &Option<cbor::Value>) -> Vec<u8> {
        let params = match params {
            Some(p) => p,
            None => return vec![Ctap2Response::MissingParameter.code()],
        };
        let map = match params {
            cbor::Value::M(m) => m,
            _ => return vec![Ctap2Response::InvalidParameter.code()],
        };

        // Read params by key. Keep new_min as u64 for range checks before casting.
        let new_min_raw = map
            .iter()
            .find(|(k, _)| matches!(k, cbor::Value::U(0x01)))
            .and_then(|(_, v)| match v {
                cbor::Value::U(u) => Some(*u),
                _ => None,
            });
        let rp_ids: Option<Vec<String>> = map
            .iter()
            .find(|(k, _)| matches!(k, cbor::Value::U(0x02)))
            .and_then(|(_, v)| match v {
                cbor::Value::A(arr) => {
                    let mut ids = Vec::new();
                    for item in arr {
                        if let cbor::Value::T(s) = item {
                            ids.push(s.clone());
                        } else {
                            return None;
                        }
                    }
                    Some(ids)
                }
                _ => None,
            });
        let force_change_pin: bool = map
            .iter()
            .find(|(k, _)| matches!(k, cbor::Value::U(0x03)))
            .and_then(|(_, v)| match v {
                cbor::Value::Bool(b) => Some(*b),
                _ => None,
            })
            .unwrap_or(false);
        let pin_complexity_policy: bool = map
            .iter()
            .find(|(k, _)| matches!(k, cbor::Value::U(0x04)))
            .and_then(|(_, v)| match v {
                cbor::Value::Bool(b) => Some(*b),
                _ => None,
            })
            .unwrap_or(false);

        // Validate PIN complexity policy support.
        if pin_complexity_policy {
            // The authenticator supports setting it (reflected in getInfo).
        }

        // maxRPIDsForSetMinPINLength limit.
        if let Some(ref ids) = rp_ids {
            if ids.len() > DEFAULT_MAX_RPIDS_MINPIN_LENGTH {
                return vec![Ctap2Response::LimitExceeded.code()];
            }
        }

        let s = self.keystore.get_pin_state_mut();
        if let Some(new_min_raw) = new_min_raw {
            // Validate range before casting: must be 4..=63.
            const MAX_PIN: u64 = 63;
            const MIN_PIN: u64 = 4;
            if !(MIN_PIN..=MAX_PIN).contains(&new_min_raw) {
                return vec![Ctap2Response::PinPolicyViolation.code()];
            }
            let new_min = new_min_raw as u8;
            // Cannot lower the min PIN length below the current setting.
            if new_min < s.min_pin_length {
                return vec![Ctap2Response::PinPolicyViolation.code()];
            }
            s.min_pin_length = new_min;
            // Raising min_pin_length above the current PIN length (8) forces
            // a PIN change. PIN is "12345678" = 8 codepoints.
            const CURRENT_PIN_LEN: u8 = 8;
            if new_min > CURRENT_PIN_LEN {
                s.force_pin_change = true;
            }
        }
        if let Some(ids) = rp_ids {
            s.min_pin_rp_ids = ids;
        }
        s.pin_complexity_policy = pin_complexity_policy;
        if force_change_pin {
            s.force_pin_change = true;
        }
        let _ = self.keystore.save_pin_state();
        vec![Ctap2Response::Ok.code()]
    }

    /// Config setEnterpriseRPIDList (0x04): params {0x01: [rpId, ...]}.
    fn cfg_set_enterprise_rp_ids(&mut self, params: &Option<cbor::Value>) -> Vec<u8> {
        let params = match params {
            Some(p) => p,
            None => return vec![Ctap2Response::MissingParameter.code()],
        };
        let map = match params {
            cbor::Value::M(m) => m,
            _ => return vec![Ctap2Response::InvalidParameter.code()],
        };
        let ids: Vec<String> = match map
            .iter()
            .find(|(k, _)| matches!(k, cbor::Value::U(0x01)))
            .map(|(_, v)| v)
        {
            Some(cbor::Value::A(arr)) => {
                let mut out = Vec::new();
                for item in arr {
                    if let cbor::Value::T(s) = item {
                        out.push(s.clone());
                    } else {
                        return vec![Ctap2Response::InvalidParameter.code()];
                    }
                }
                out
            }
            _ => return vec![Ctap2Response::InvalidParameter.code()],
        };
        {
            let s = self.keystore.get_pin_state_mut();
            s.enterprise_rp_ids = ids;
        }
        let _ = self.keystore.save_pin_state();
        vec![Ctap2Response::Ok.code()]
    }

    /// The host `0xFF` (`VendorPrototype`) handler — the **only** place the
    /// host answers a sub-command-`0xFF` request.
    ///
    /// `data` is the whole `0x0D` body (the map after the opcode byte) and
    /// `params` is its decoded key 2. Both are needed, and neither alone is
    /// enough, which is why this function grew a parameter rather than
    /// re-deriving one:
    ///
    /// * `params` is what the four arms below have always wanted — it is a
    ///   decoded map, so the id and the payload are trivially readable.
    /// * `data` is what the RS-Key soft-lock arms need, because
    ///   [`crate::vendor_lock::lock_engage`] / [`crate::vendor_lock::lock_release`]
    ///   verify the `0x0D` MAC over the **borrowed wire span** and re-read the
    ///   vendor id and the sealed blob out of those same bytes.
    fn cfg_vendor_prototype(&mut self, data: &[u8], params: &Option<cbor::Value>) -> Vec<u8> {
        let params = match params {
            Some(p) => p,
            None => return vec![Ctap2Response::MissingParameter.code()],
        };
        let map = match params {
            cbor::Value::M(m) => m,
            _ => return vec![Ctap2Response::InvalidParameter.code()],
        };
        // The first param (key 0x01) is the vendor subcommand id.
        let vendor_cmd = match map
            .iter()
            .find(|(k, _)| matches!(k, cbor::Value::U(0x01)))
            .and_then(|(_, v)| match v {
                cbor::Value::U(u) => Some(*u),
                _ => None,
            }) {
            Some(c) => c,
            None => return vec![Ctap2Response::MissingParameter.code()],
        };

        match vendor_cmd {
            CONFIG_CREDENTIAL_REVOKE => self.cfg_revoke_credential(map),
            CONFIG_CREDENTIAL_EXPIRE => self.cfg_expire_credential(map),
            // US-113: the pico-fido legacy physical-config ids join the two
            // credential ids *in this same match* rather than in a parallel
            // `0xFF` arm. `cfg_vendor_prototype` IS the host `0xFF` handler —
            // `authenticator_config` already routes sub-command `0xFF` here —
            // so a second arm would have had to be a second `match` over the
            // same map, and the two would then disagree about which ids
            // exist. The EPIC's claim that the host twin "already has" this
            // framing was wrong: this match is what it grew, and the EPIC's
            // line numbers pointed at the credential handler it could not
            // have been.
            id if crate::vendorff::SUPPORTED_IDS.iter().any(|(_, v)| *v == id) => {
                self.cfg_physical_config(id, params)
            }
            // US-170: the RS-Key soft-lock pair, in the **same** match for the
            // reason the `vendorff` arm above states: this function *is* the
            // `0xFF` handler, so a second `match` over the same map would be a
            // second answer to "which vendor ids exist", and the two would be
            // free to disagree. Order is not load-bearing — the three id sets
            // are 64-bit and pairwise disjoint, pinned by
            // `tests/vendor_lock.rs::no_rs_key_lock_id_collides_with_a_vendorff_or_credential_id`
            // — so this is readability, not correctness.
            crate::vendor_lock::AUT_ENABLE => self.cfg_vendor_lock(data, true),
            crate::vendor_lock::AUT_DISABLE => self.cfg_vendor_lock(data, false),
            _ => vec![Ctap2Response::InvalidParameter.code()],
        }
    }

    /// US-170: run one `authenticatorConfig` soft-lock arm on the host stack.
    ///
    /// `engage` selects between [`crate::vendor_lock::lock_engage`] and
    /// [`crate::vendor_lock::lock_release`]; it is a parameter rather than two
    /// near-identical bodies because the *only* thing that differs between the
    /// two call sites is that one word, and a duplicated body is a second place
    /// for the `Outcome` → status → latch translation below to be wrong.
    ///
    /// ## The three borrows, and why they compose
    ///
    /// Identical in shape to the `0x41` arm at `app.rs:599-618`: `auth`
    /// borrows `self.pin_token` immutably while `MemoryVendorOps::new` takes
    /// `&mut self.keystore` and `&mut self.vendor_session`. Those are three
    /// *different fields* of this struct, which is the only reason a `&mut self`
    /// method can hold all three at once — a whole-app borrow would collide
    /// with `auth` and there would be no second session to invent, so this is
    /// the same seam the `0x41` path already has rather than a new one.
    ///
    /// ## The gate is not re-run here, and the arm re-runs it anyway
    ///
    /// `authenticator_config` has already checked a set PIN, the power-cycle
    /// latch, a live token and `PERM_ACFG` (`app.rs:1946-1962`), and verified
    /// the `0x0D` MAC. `lock_engage` / `lock_release` do not know that and
    /// verify it again against the raw span — which is the point: their gate
    /// is the *wire* gate, and the one above is a gate over a re-encoding (see
    /// the ⚠️ note below). Both are the same arithmetic on canonical input, so
    /// on a PicoForge request the second is a no-op; on a request that is not
    /// canonical it is the one that is right.
    ///
    /// ⚠️ **The re-encoding above is the host's weak spot, and it is left
    /// alone on purpose.** `authenticator_config` builds the MAC message from
    /// `cbor::encode(params)` — a re-serialisation of a *decoded* map, which
    /// sorts keys and rewrites every head canonically. That agrees with the
    /// client only while the client also sends canonical bytes, which
    /// PicoForge does (its params are a `BTreeMap` value the `cbor` crate
    /// serialised). A non-canonical `0xFF` request therefore gets `0x33` from
    /// `authenticator_config` **before** this function is entered, and the
    /// soft-lock arms never see it — which is a real limitation of the host
    /// path, reported rather than fixed here, because fixing it changes what
    /// the `vendorff` and credential arms accept too and belongs in its own
    /// story. The device path (`device_core.rs`) does **not** have this
    /// weakness: it MACs `&data[s..e]`, the client's own bytes.
    ///
    /// `pin_auth_failure` is still honoured rather than assumed unreachable.
    /// On canonical input it is — but a gate that has its charging decision
    /// dropped on the floor because the caller believed it could not fire is
    /// the exact shape of a counter that silently stops counting.
    fn cfg_vendor_lock(&mut self, data: &[u8], engage: bool) -> Vec<u8> {
        let outcome = {
            let auth = Self::token_auth(
                std::slice::from_ref(&self.pin_token),
                self.pin_token_permissions,
                self.keystore.get_pin_state().needs_power_cycle,
            );
            let mut ops = crate::vendor_state::MemoryVendorOps::new(
                &mut self.keystore,
                &mut self.vendor_session,
            );
            if engage {
                crate::vendor_lock::lock_engage(&mut ops, data, auth)
            } else {
                crate::vendor_lock::lock_release(&mut ops, data, auth)
            }
        };
        if outcome.pin_auth_failure {
            // The same `note_pin_auth_failure` the `0x41` arm uses, so the
            // third strike still answers `0x34` and `needs_power_cycle` is
            // persisted the one way this app persists it.
            return vec![self.note_pin_auth_failure()];
        }
        // `Outcome::phy` is never set by these two arms — the lock record is
        // committed inside `MemoryVendorOps`, whose `commit` is the host's
        // documented mutate-then-`save_auth_state` contract — so there is
        // nothing for the `0x41` arm's `outcome.phy` commit to do here.
        vec![outcome.status.code()]
    }

    /// Apply one `vendorPrototype` physical-config id and persist it.
    ///
    /// The id arrives as a bare `u64` because the credential arms above match
    /// on it directly; re-decoding the CBOR map through
    /// [`crate::vendorff::PhyCommand`] is what keeps the *value* rules in one
    /// place, so the host and device paths cannot drift on which key
    /// (`0x02`/`0x03`/`0x04`) a given CBOR type is read from.
    ///
    /// Durability: the host stack has no store borrow in this call, so this
    /// uses the mutate-then-save discipline every other `cfg_*` handler here
    /// uses. The host is the emulation binary's stack — `firmware/src/tasks.rs`
    /// runs its own durable-before-ack gate against the `0x41` channel — so
    /// "durable before the reply" is enforced by the device path, not here.
    /// This path's contract is the weaker, honest one: the change is written
    /// to the keystore before the `0x00` goes out, and a failed
    /// `save_auth_state` is reported as a failure rather than swallowed.
    fn cfg_physical_config(&mut self, id: u64, params: &cbor::Value) -> Vec<u8> {
        // Re-encode the map and decode it through the shared rule, so the host
        // reads exactly the pair the device reads rather than a second
        // hand-rolled traversal of the same CBOR. `id` came from the same map
        // the outer `cfg_vendor_prototype` scanned, so a re-decode that finds
        // a *different* id is not reachable from a well-formed request — the
        // check is here because the cost of a decode that returns someone
        // else's command is writing someone else's configuration.
        let cmd = match crate::vendorff::PhyCommand::decode(&cbor::encode(params)) {
            Ok(c) if c.id == id => c,
            Ok(_) => return vec![Ctap2Response::InvalidParameter.code()],
            Err(e) => return vec![e.code()],
        };
        if let Err(e) = crate::vendorff::validate(&cmd) {
            return vec![e.code()];
        }
        {
            let auth = self.keystore.get_auth_state_mut();
            if let Err(e) = crate::vendorff::apply(&mut auth.phy, &cmd) {
                return vec![e.code()];
            }
        }
        match self.keystore.save_auth_state() {
            Ok(()) => vec![Ctap2Response::Ok.code()],
            // `KeyStoreFull` is the closest existing code for "the write did
            // not land": the configured value is still in memory, so the
            // honest answer is a failure, not an `Ok` the caller would read as
            // durable.
            Err(_) => vec![Ctap2Response::KeyStoreFull.code()],
        }
    }

    /// Revoke a credential identified by slot index (param 0x03) or by
    /// credential id (param 0x02). Having both is INVALID_PARAMETER.
    /// Returns NO_CREDENTIALS if no match.
    fn cfg_revoke_credential(&mut self, map: &[(cbor::Value, cbor::Value)]) -> Vec<u8> {
        let has_id = map.iter().any(|(k, _)| matches!(k, cbor::Value::U(0x02)));
        let has_slot = map.iter().any(|(k, _)| matches!(k, cbor::Value::U(0x03)));
        // Mutually exclusive: cannot specify both credential id and slot.
        if has_id && has_slot {
            return vec![Ctap2Response::InvalidParameter.code()];
        }
        // Id-based: param 0x02 is the credential id.
        if has_id {
            let id = match map
                .iter()
                .find(|(k, _)| matches!(k, cbor::Value::U(0x02)))
                .and_then(|(_, v)| match v {
                    cbor::Value::B(b) => Some(b.clone()),
                    _ => None,
                }) {
                Some(id) => id,
                None => return vec![Ctap2Response::InvalidParameter.code()],
            };
            return match self.keystore.get_credential_mut(&id) {
                Some(cred) => {
                    cred.revoked = true;
                    // Persist the mutation (FX-409).
                    let _ = self.keystore.save_auth_state();
                    vec![Ctap2Response::Ok.code()]
                }
                None => vec![Ctap2Response::NoCredentials.code()],
            };
        }
        // Slot-based: param 0x03 is a resident-credential index.
        let slot = match map
            .iter()
            .find(|(k, _)| matches!(k, cbor::Value::U(0x03)))
            .and_then(|(_, v)| match v {
                cbor::Value::U(u) => Some(*u as usize),
                _ => None,
            }) {
            Some(s) => s,
            None => return vec![Ctap2Response::InvalidParameter.code()],
        };
        // Collect resident credentials in storage order; the slot indexes them.
        let resident_ids: Vec<Vec<u8>> = self
            .keystore
            .list_credentials()
            .into_iter()
            .filter(|c| c.resident)
            .map(|c| c.credential_id.clone())
            .collect();
        if slot >= resident_ids.len() {
            return vec![Ctap2Response::NoCredentials.code()];
        }
        let id = &resident_ids[slot];
        match self.keystore.get_credential_mut(id) {
            Some(cred) => {
                cred.revoked = true;
                // Persist the mutation (FX-409).
                let _ = self.keystore.save_auth_state();
                vec![Ctap2Response::Ok.code()]
            }
            None => vec![Ctap2Response::NoCredentials.code()],
        }
    }

    /// Set credential expiration. Requires a 4-byte timestamp in param 0x02.
    fn cfg_expire_credential(&mut self, map: &[(cbor::Value, cbor::Value)]) -> Vec<u8> {
        let ts_bytes = match map
            .iter()
            .find(|(k, _)| matches!(k, cbor::Value::U(0x02)))
            .and_then(|(_, v)| match v {
                cbor::Value::B(b) => Some(b.clone()),
                _ => None,
            }) {
            Some(b) => b,
            None => return vec![Ctap2Response::InvalidParameter.code()],
        };
        if ts_bytes.len() != 4 {
            return vec![Ctap2Response::InvalidParameter.code()];
        }
        let _timestamp = u32::from_be_bytes([ts_bytes[0], ts_bytes[1], ts_bytes[2], ts_bytes[3]]);
        // Slot-based target (param 0x03).
        let slot = match map
            .iter()
            .find(|(k, _)| matches!(k, cbor::Value::U(0x03)))
            .and_then(|(_, v)| match v {
                cbor::Value::U(u) => Some(*u as usize),
                _ => None,
            }) {
            Some(s) => s,
            None => return vec![Ctap2Response::MissingParameter.code()],
        };
        let resident_ids: Vec<Vec<u8>> = self
            .keystore
            .list_credentials()
            .into_iter()
            .filter(|c| c.resident)
            .map(|c| c.credential_id.clone())
            .collect();
        if slot >= resident_ids.len() {
            return vec![Ctap2Response::NoCredentials.code()];
        }
        let id = &resident_ids[slot];
        match self.keystore.get_credential_mut(id) {
            Some(cred) => {
                cred.expires_at = Some(_timestamp);
                // Persist the mutation (FX-409).
                let _ = self.keystore.save_auth_state();
                vec![Ctap2Response::Ok.code()]
            }
            None => vec![Ctap2Response::NoCredentials.code()],
        }
    }

    fn cm_get_metadata(&self) -> Vec<u8> {
        let existing = self.keystore.cred_count();
        let remaining = self.keystore.max_remaining_creds();
        let response = cbor::Value::M(vec![
            (cbor::Value::U(0x01), cbor::Value::U(existing as u64)),
            (cbor::Value::U(0x02), cbor::Value::U(remaining as u64)),
            // C firmware parity: total capacity of the credential store.
            (
                cbor::Value::U(0x03),
                cbor::Value::U((existing + remaining) as u64),
            ),
        ]);
        let encoded = cbor::encode(&response);
        let mut resp = vec![Ctap2Response::Ok.code()];
        resp.extend_from_slice(&encoded);
        resp
    }

    fn collect_rps(&self) -> Vec<(String, [u8; 32])> {
        let mut rps: Vec<(String, [u8; 32])> = Vec::new();
        for cred in self.keystore.list_credentials() {
            if !cred.resident || cred.revoked {
                continue;
            }
            if rps.iter().any(|(_, h)| *h == cred.rp_id_hash) {
                continue;
            }
            let rp_id = cred.rp_id.clone().unwrap_or_default();
            rps.push((rp_id, cred.rp_id_hash));
        }
        rps
    }

    fn cm_enumerate_rps_begin(&mut self) -> Vec<u8> {
        let rps = self.collect_rps();
        if rps.is_empty() {
            return vec![Ctap2Response::NoCredentials.code()];
        }
        let total = rps.len();
        let rp = &rps[0];
        let rp_map = cbor::Value::M(vec![
            (cbor::Value::T("id".to_string()), cbor::Value::T(rp.0.clone())),
        ]);
        // CTAP2 §12.1.6 numbers these rp(1) ‖ rpID(2) ‖ totalRPs(7);
        // PicoForge numbers the same three things 3/4/5. The sets collide, so
        // each sender gets its own shape — a client that cannot find keys
        // 1/2/7 has nothing to render, which is what left the Slots and
        // Passkeys screens spinning forever.
        let (k_rp, k_id, k_total) = match self.cm_dialect {
            CmDialect::Ctap2 => (0x01u64, 0x02, 0x07),
            CmDialect::PicoForge => (0x03, 0x04, 0x05),
        };
        let mut map: Vec<(cbor::Value, cbor::Value)> = vec![
            (cbor::Value::U(k_rp), rp_map),
            (cbor::Value::U(k_id), cbor::Value::B(rp.1.to_vec())),
        ];
        // Always include TOTAL_RPS so enumerate_rps() can determine the count.
        map.push((cbor::Value::U(k_total), cbor::Value::U(total as u64)));
        // Stash remaining RPs for enumerate_rps_next.
        self.cm_rp_state = Some(CmRpState {
            rps,
            cursor: 1,
            channel: self.current_channel,
            dialect: self.cm_dialect,
        });
        let response = cbor::Value::M(map);
        let encoded = cbor::encode(&response);
        let mut resp = vec![Ctap2Response::Ok.code()];
        resp.extend_from_slice(&encoded);
        resp
    }

    fn cm_enumerate_rps_next(&mut self) -> Vec<u8> {
        // Extract data, then drop the borrow before building the response.
        let (rp_id, rp_id_hash, is_last, dialect) = {
            let state = match self.cm_rp_state.as_mut() {
                Some(s) => s,
                None => return vec![Ctap2Response::NotAllowed.code()],
            };
            // CTAP2 spec: next commands must be on the same channel.
            if state.channel != self.current_channel {
                return vec![Ctap2Response::NotAllowed.code()];
            }
            if state.cursor >= state.rps.len() {
                self.cm_rp_state = None;
                return vec![Ctap2Response::NotAllowed.code()];
            }
            let rp = &state.rps[state.cursor];
            state.cursor += 1;
            let is_last = state.cursor >= state.rps.len();
            (rp.0.clone(), rp.1, is_last, state.dialect)
        };
        // `{1: 0x03}` is byte-identical in both dialects, so the request
        // cannot be classified; the enumeration it continues decides.
        self.cm_dialect = dialect;
        let rp_map = cbor::Value::M(vec![
            (cbor::Value::T("id".to_string()), cbor::Value::T(rp_id)),
        ]);
        // Only the Begin response carries totalRps; the Next response is the
        // two-key shape in each dialect's own numbering.
        let (k_rp, k_id) = match self.cm_dialect {
            CmDialect::Ctap2 => (0x01u64, 0x02),
            CmDialect::PicoForge => (0x03, 0x04),
        };
        let map: Vec<(cbor::Value, cbor::Value)> = vec![
            (cbor::Value::U(k_rp), rp_map),
            (cbor::Value::U(k_id), cbor::Value::B(rp_id_hash.to_vec())),
        ];
        if is_last {
            self.cm_rp_state = None;
        }
        let response = cbor::Value::M(map);
        let encoded = cbor::encode(&response);
        let mut resp = vec![Ctap2Response::Ok.code()];
        resp.extend_from_slice(&encoded);
        resp
    }

    fn cm_enumerate_creds_begin(&mut self, rp_id_hash: &[u8; 32]) -> Vec<u8> {
        let mut creds: Vec<StoredCredential> = self
            .keystore
            .list_credentials_by_rp(rp_id_hash)
            .into_iter()
            .filter(|c| c.resident && !c.revoked)
            .cloned()
            .collect();
        // Reverse to match the reference firmware's newest-first ordering.
        creds.reverse();
        if creds.is_empty() {
            return vec![Ctap2Response::NoCredentials.code()];
        }
        // Cap the response batch at maxCredsInList (FX-411 pagination).
        creds.truncate(MAX_CREDENTIAL_COUNT_IN_LIST);
        let total = creds.len();
        let cred = &creds[0];
        let response = self.cm_cred_response(cred, total);
        // Stash remaining creds for enumerate_creds_next.
        self.cm_cred_state = Some(CmCredState {
            creds,
            cursor: 1,
            channel: self.current_channel,
            dialect: self.cm_dialect,
        });
        response
    }

    fn cm_enumerate_creds_next(&mut self) -> Vec<u8> {
        // Extract the data we need, then drop the borrow before calling
        // cm_cred_response (which needs &self).
        let (cred, total, is_last, dialect) = {
            let state = match self.cm_cred_state.as_mut() {
                Some(s) => s,
                None => return vec![Ctap2Response::NotAllowed.code()],
            };
            // CTAP2 spec: next commands must be on the same channel.
            if state.channel != self.current_channel {
                return vec![Ctap2Response::NotAllowed.code()];
            }
            if state.cursor >= state.creds.len() {
                self.cm_cred_state = None;
                return vec![Ctap2Response::NotAllowed.code()];
            }
            let cred = state.creds[state.cursor].clone();
            state.cursor += 1;
            let is_last = state.cursor >= state.creds.len();
            (cred, state.creds.len(), is_last, state.dialect)
        };
        // `{1: 0x05}` is byte-identical in both dialects, so the request
        // cannot be classified; the enumeration it continues decides.
        self.cm_dialect = dialect;
        let response = self.cm_cred_response(&cred, total);
        if is_last {
            self.cm_cred_state = None;
        }
        response
    }

    fn cm_cred_response(&self, cred: &StoredCredential, total: usize) -> Vec<u8> {
        let pk = &cred.public_key;
        let cose_key = cbor::Value::M(vec![
            (cbor::Value::U(1), cbor::Value::U(pk.kty as u64)),       // kty
            (cbor::Value::U(3), cbor::Value::N(pk.alg as i64)),      // alg
            (cbor::Value::N(-1), cbor::Value::N(p256_curve(pk.alg))), // crv
            (cbor::Value::N(-2), cbor::Value::B(pk.x.clone().unwrap_or_default())),
            (cbor::Value::N(-3), cbor::Value::B(pk.y.clone().unwrap_or_default())),
        ]);
        let cred_id_map = cbor::Value::M(vec![
            (cbor::Value::T("type".to_string()), cbor::Value::T("public-key".to_string())),
            (cbor::Value::T("id".to_string()), cbor::Value::B(cred.credential_id.clone())),
        ]);
        let mut user_entries: Vec<(cbor::Value, cbor::Value)> = vec![
            (cbor::Value::T("id".to_string()), cbor::Value::B(cred.user_handle.clone())),
        ];
        if let Some(ref name) = cred.user_name {
            user_entries.push((cbor::Value::T("name".to_string()), cbor::Value::T(name.clone())));
        }
        if let Some(ref display_name) = cred.user_display_name {
            user_entries
                .push((cbor::Value::T("displayName".to_string()), cbor::Value::T(display_name.clone())));
        }
        let user = cbor::Value::M(user_entries);
        // CTAP2 §12.1.6 numbers these 1/2/3/4/5/6/7; PicoForge numbers the
        // same seven things 6/7/8/9/0x0A/0x0B/0x0C. The sets overlap (key 6
        // is `user` to PicoForge, `largeBlobKey` to CTAP2), so one response
        // cannot satisfy both.
        let (k_user, k_cred, k_pk, k_total, k_protect, k_blob) = match self.cm_dialect {
            CmDialect::Ctap2 => (0x01u64, 0x02, 0x03, 0x04, 0x05, 0x06),
            CmDialect::PicoForge => (0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B),
        };
        let k_tpp = match self.cm_dialect {
            CmDialect::Ctap2 => 0x07u64,
            CmDialect::PicoForge => 0x0C,
        };
        let mut map: Vec<(cbor::Value, cbor::Value)> = vec![
            (cbor::Value::U(k_user), user),
            (cbor::Value::U(k_cred), cred_id_map),
            (cbor::Value::U(k_pk), cose_key),
        ];
        // Always include TOTAL_CREDENTIALS so callers can distinguish a
        // single-result response from a paginated one.
        map.push((cbor::Value::U(k_total), cbor::Value::U(total as u64)));
        // credProtect policy when set (FX-411).
        if cred.cred_protect > 0 {
            map.push((
                cbor::Value::U(k_protect),
                cbor::Value::U(cred.cred_protect as u64),
            ));
        }
        // largeBlobKey when the credential carries one (FX-411).
        if let Some(ref k) = cred.large_blob_key {
            map.push((cbor::Value::U(k_blob), cbor::Value::B(k.to_vec())));
        }
        // Include thirdPartyPayment flag (key 0x0C) when set.
        if cred.third_party_payment {
            map.push((cbor::Value::U(k_tpp), cbor::Value::Bool(true)));
        }
        let response = cbor::Value::M(map);
        let encoded = cbor::encode(&response);
        let mut resp = vec![Ctap2Response::Ok.code()];
        resp.extend_from_slice(&encoded);
        resp
    }

    fn cm_delete_cred(&mut self, cred_id: Option<CredDescriptor>) -> Vec<u8> {
        let desc = match cred_id {
            Some(c) => c,
            None => return vec![Ctap2Response::MissingParameter.code()],
        };
        if desc.id.is_empty() {
            return vec![Ctap2Response::MissingParameter.code()];
        }
        match self.keystore.delete_credential(&desc.id) {
            Ok(()) => vec![Ctap2Response::Ok.code()],
            Err(crate::keystore::KeystoreError::NotFound) => {
                vec![Ctap2Response::NoCredentials.code()]
            }
            Err(_) => vec![Ctap2Response::InvalidCommand.code()],
        }
    }

    fn cm_update_user(
        &mut self,
        cred_id: Option<CredDescriptor>,
        user: Option<CmUser>,
    ) -> Vec<u8> {
        let desc = match cred_id {
            Some(c) => c,
            None => return vec![Ctap2Response::MissingParameter.code()],
        };
        let user = match user {
            Some(u) => u,
            None => return vec![Ctap2Response::MissingParameter.code()],
        };
        let cred = match self.keystore.get_credential_mut(&desc.id) {
            Some(c) => c,
            None => return vec![Ctap2Response::NoCredentials.code()],
        };
        // The user id cannot change (it's part of the credential identity).
        if cred.user_handle != user.id && !cred.user_handle.is_empty() {
            return vec![Ctap2Response::InvalidParameter.code()];
        }
        cred.user_name = if user.name.is_empty() {
            cred.user_name.clone()
        } else {
            Some(user.name)
        };
        cred.user_display_name = if user.display_name.is_empty() {
            cred.user_display_name.clone()
        } else {
            Some(user.display_name)
        };
        vec![Ctap2Response::Ok.code()]
    }
}

impl FidoApp<MemoryKeystore> {
    /// Create a new FIDO app with an in-memory keystore.
    pub fn new() -> Self {
        Self::with_keystore(MemoryKeystore::new())
    }
}

impl Default for FidoApp<MemoryKeystore> {
    fn default() -> Self {
        Self::new()
    }
}

// ------------------------------------------------------------------
// Algorithm support
// ------------------------------------------------------------------

/// Returns true if the given COSE algorithm is supported for key generation.
fn supports_algorithm(alg: i64) -> bool {
    // ES256 (-7) and ESP256 (-9) both map to P-256 ECDSA; ESP256 is needed
    // for test_curve_explicit_algorithm_is_preserved which sends alg=-9 and
    // expects it preserved in the credential's COSE key. ES384 (-35), ES512
    // (-36) and EdDSA (-8) match the C firmware's advertised set.
    alg == -7 || alg == -9 || alg == -35 || alg == -36 || alg == -8
}

/// Generate a credential keypair for the given COSE algorithm. Returns the
/// private key scalar bytes and the COSE public key.
/// Generate the credential keypair for `alg`.
///
/// # US-1007: fallible and bounded, on every arm
///
/// Each of the four curves carries its **own** unbounded rejection sampler
/// over the infallible [`crate::crypto::TrngRng`] — `SigningKey::random`
/// for the NIST curves, `generate` for Ed25519. A starved source makes all
/// four spin forever, so a fix that converted only the P-256 arm would have
/// left three arms of the same request able to wedge. Every arm therefore
/// draws through [`crypto::try_fill_valid`], which caps the rejection at
/// [`crypto::KEYGEN_MAX_ATTEMPTS`] and returns a `KeygenError` the caller
/// turns into a CTAP status instead of a silent hang.
///
/// The key material accepted is unchanged: each arm's `accept` predicate is
/// that curve's own `from_slice`/`from_bytes`, the same validity rule the
/// curve's own sampler applies, so a key produced here is one the original
/// would have produced.
fn generate_alg_keypair(alg: i64) -> Result<(Vec<u8>, CosePublicKey), crypto::KeygenError> {
    match alg {
        -8 => {
            // Ed25519 has no rejection step — every 32-byte string is a
            // valid scalar, and `SigningKey::generate` is one raw
            // `fill_bytes`. So there is nothing to cap here; what the
            // starved source *does* produce is a fixed, perfectly valid key
            // that the device would then hand to every relying party as
            // though it were unique. The fix is therefore the honest
            // refusal alone: one fallible draw, no retry loop, and no key
            // at all when the source has nothing to give.
            let mut seed = [0u8; 32];
            rand_core::RngCore::try_fill_bytes(
                &mut crate::crypto::TrngRng,
                &mut seed,
            )
            .map_err(|_| crypto::KeygenError::Starved)?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            let vk = sk.verifying_key().to_bytes();
            Ok((sk.to_bytes().to_vec(), CosePublicKey::eddsa(vk)))
        }
        -35 => {
            let mut seed = [0u8; 48];
            crypto::try_fill_valid(
                &mut crate::crypto::TrngRng,
                &mut seed,
                |b| p384::ecdsa::SigningKey::from_slice(b).is_ok(),
            )?;
            let sk = p384::ecdsa::SigningKey::from_slice(&seed)
                .map_err(|_| crypto::KeygenError::AttemptsExhausted)?;
            let pk = p384::ecdsa::VerifyingKey::from(&sk).to_encoded_point(false);
            let cose = CosePublicKey {
                kty: 2,
                alg: -35,
                crv: Some(2),
                x: Some(pk.x().unwrap().to_vec()),
                y: Some(pk.y().unwrap().to_vec()),
                n: None,
                e: None,
                okp_key: None,
            };
            Ok((sk.to_bytes().to_vec(), cose))
        }
        -36 => {
            // P-521's scalar is 66 bytes = 528 bits, but the prime field is
            // 521 bits. A uniformly random draw is therefore a valid scalar
            // only when its top 7 bits are clear — measured at 0.007875 over
            // 200,000 draws (1 in 127). Against `KEYGEN_MAX_ATTEMPTS` = 8 that
            // is a 6.1 % success rate, which is the long-standing
            // `test_algorithms[-36]` flake: `AttemptsExhausted` surfaced as
            // CTAP 0x7F, indistinguishable from an entropy-starved device.
            //
            // Masking the overflow bits makes acceptance ~1 by construction, so
            // the sampler spends one draw instead of ~127. P-256 (32 B) and
            // P-384 (48 B) need no mask — their draws are exactly field-sized.
            //
            // The mask does not *replace* the validity check: values in
            // [n, 2^521) are still rejected, and `try_fill_valid` still bounds
            // that residual (a fraction ~2^-262 of draws) instead of spinning.
            let mut seed = [0u8; 66];
            crypto::try_fill_valid(
                &mut crate::crypto::TrngRng,
                &mut seed,
                |b| {
                    if b.len() != 66 {
                        return false;
                    }
                    let mut m = [0u8; 66];
                    m.copy_from_slice(b);
                    m[0] &= 0x01; // 528 bits -> 521: keep only bit 520
                    p521::ecdsa::SigningKey::from_slice(&m).is_ok()
                },
            )?;
            // Re-derive from the masked seed. The predicate above masks a
            // *copy* (a closure cannot hand the masked value back), so the
            // masked bytes are what must be used, not the raw draw.
            let mut masked = seed;
            masked[0] &= 0x01;
            let sk = p521::ecdsa::SigningKey::from_slice(&masked)
                .map_err(|_| crypto::KeygenError::AttemptsExhausted)?;
            let pk = p521::ecdsa::VerifyingKey::from(&sk).to_encoded_point(false);
            let cose = CosePublicKey {
                kty: 2,
                alg: -36,
                crv: Some(3),
                x: Some(pk.x().unwrap().to_vec()),
                y: Some(pk.y().unwrap().to_vec()),
                n: None,
                e: None,
                okp_key: None,
            };
            Ok((sk.to_bytes().to_vec(), cose))
        }
        a => {
            let (secret, public) =
                crypto::try_generate_p256_keypair(&mut crate::crypto::TrngRng)?;
            let pub_bytes = crypto::public_key_bytes(&public);
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            x.copy_from_slice(&pub_bytes[1..33]);
            y.copy_from_slice(&pub_bytes[33..65]);
            Ok((secret.to_bytes().to_vec(), CosePublicKey::ec2(a as i32, x, y)))
        }
    }
}

/// Sign data with a credential's private key per its COSE algorithm.
/// ECDSA signatures are returned DER-encoded (matching p256_sign_bytes);
/// EdDSA as the 64-byte raw signature.
fn sign_with_alg(alg: i32, private_key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    match alg {
        -8 => {
            use ed25519_dalek::Signer as _;
            let sk = ed25519_dalek::SigningKey::from_bytes(private_key.try_into().ok()?);
            Some(sk.sign(data).to_bytes().to_vec())
        }
        -35 => {
            use p384::ecdsa::signature::Signer as _;
            let sk = p384::ecdsa::SigningKey::from_slice(private_key).ok()?;
            let sig: p384::ecdsa::Signature = sk.sign(data);
            Some(sig.to_der().as_bytes().to_vec())
        }
        -36 => {
            use p521::ecdsa::signature::Signer as _;
            let sk = p521::ecdsa::SigningKey::from_slice(private_key).ok()?;
            let sig: p521::ecdsa::Signature = sk.sign(data);
            Some(sig.to_der().as_bytes().to_vec())
        }
        _ => {
            let secret = crypto::secret_key_from_bytes(private_key)?;
            Some(crypto::p256_sign_bytes(&secret, data))
        }
    }
}

/// Encode a COSE public key with the canonical labels (1 kty, 3 alg,
/// -1 crv, -2 x, -3 y) used in attested credential data.
fn encode_cose_pubkey(key: &CosePublicKey) -> Vec<u8> {
    let mut entries = vec![
        (cbor::Value::U(1), cbor::Value::U(key.kty as u64)),
        (cbor::Value::U(3), cbor::Value::N(key.alg as i64)),
    ];
    if let Some(crv) = key.crv {
        entries.push((cbor::Value::N(-1), cbor::Value::U(crv as u64)));
    }
    if let Some(ref x) = key.x {
        entries.push((cbor::Value::N(-2), cbor::Value::B(x.clone())));
    }
    if let Some(ref y) = key.y {
        entries.push((cbor::Value::N(-3), cbor::Value::B(y.clone())));
    }
    cbor::encode(&cbor::Value::M(entries))
}

/// Map a COSE algorithm to its COSE crv value (for credMgmt enumerate response).
fn p256_curve(alg: i32) -> i64 {
    match alg {
        -7 => 1,  // P-256
        -8 => 6,  // Ed25519
        -35 => 2, // P-384
        -36 => 3, // P-521
        -47 => 8, // secp256k1
        _ => 1,
    }
}

/// Derive a stable resident-credential ID from rp_id_hash + user_handle.
fn credential_derive_resident_id(rp_id_hash: &[u8; 32], user_handle: &[u8]) -> Vec<u8> {
    // Match the C firmware's resident derivation: SHA-256 over a domain
    // separator + rp_id_hash + user_handle, so re-registration on the same
    // RP + user derives the same id.
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"fapico2-resident-id");
    h.update(rp_id_hash);
    h.update(user_handle);
    h.finalize().to_vec()
}

// ------------------------------------------------------------------
// CBOR request parsing
// ------------------------------------------------------------------

/// Parse the hmac-secret / hmac-secret-mc input map:
/// {1: keyAgreement(COSE EC2), 2: saltEnc, 3: saltAuth, 4: pinUvAuthProtocol}
/// (CTAP2.1 §6.7).
fn parse_hmac_secret_input(hm: &[(cbor::Value, cbor::Value)]) -> Result<HmacSecretInput, FidoError> {
    let get_val = |key: i64| -> Option<&cbor::Value> {
        hm.iter()
            .find(|(k, _)| matches!(k, cbor::Value::U(u) if *u as i64 == key))
            .map(|(_, v)| v)
    };
    let get_b = |key: i64| -> Option<Vec<u8>> {
        get_val(key).and_then(|v| match v {
            cbor::Value::B(b) => Some(b.clone()),
            _ => None,
        })
    };
    let get_u = |key: i64| -> Option<u64> {
        get_val(key).and_then(|v| match v {
            cbor::Value::U(u) => Some(*u),
            _ => None,
        })
    };
    // keyAgreement is a COSE EC2 key: {1: 2, 3: -25, -1: 1, -2: x, -3: y}
    let key_agreement = match get_val(1) {
        Some(cbor::Value::M(cose)) => {
            let coord = |neg_key: i64| -> Option<Vec<u8>> {
                cose.iter()
                    .find(|(k, _)| matches!(k, cbor::Value::N(n) if *n == neg_key))
                    .and_then(|(_, v)| match v {
                        cbor::Value::B(b) => Some(b.clone()),
                        _ => None,
                    })
            };
            let x = coord(-2).ok_or(FidoError::MissingParameter)?;
            let y = coord(-3).ok_or(FidoError::MissingParameter)?;
            let mut ka = x;
            ka.extend_from_slice(&y);
            ka
        }
        _ => return Err(FidoError::MissingParameter),
    };
    let salt_enc = get_b(2).ok_or(FidoError::MissingParameter)?;
    let salt_auth = get_b(3).ok_or(FidoError::MissingParameter)?;
    let protocol = get_u(4).ok_or(FidoError::MissingParameter)? as u8;
    if protocol != 1 && protocol != 2 {
        return Err(FidoError::InvalidParameter);
    }
    // C parity: 32/64 ct bytes (v1) or 48/80 (v2, IV-prefixed);
    // saltAuth is 16 (v1) or 32 bytes.
    let ok_len = match protocol {
        1 => (salt_enc.len() == 32 || salt_enc.len() == 64) && salt_auth.len() == 16,
        _ => (salt_enc.len() == 48 || salt_enc.len() == 80) && salt_auth.len() == 32,
    };
    if !ok_len {
        return Err(FidoError::InvalidLength);
    }
    Ok(HmacSecretInput {
        key_agreement,
        salt_enc,
        salt_auth,
        protocol,
    })
}

/// Parse a makeCredential request with strict CTAP2 validation.
///
/// Validation rules (from the CTAP2 spec and the reference C firmware):
/// - CBOR keys must appear in strictly increasing canonical order; keys
///   1..=4 must be present.
/// - clientDataHash (1): bstr
/// - rp (2): map { "id": tstr, "name": tstr }
/// - user (3): map { "id": bstr, "name": tstr, "displayName": tstr }
/// - pubKeyCredParams (4): array of map { "type": tstr, "alg": int }
/// - excludeList (5): array of map { "type": tstr, "id": bstr }
/// - options (6): map { "rk"/"up"/"uv": bool }
/// - pinUvAuthParam (8): bstr, pinUvAuthProtocol (9): uint
fn parse_mc_request(data: &[u8]) -> Result<McRequest, FidoError> {
    if data.is_empty() {
        return Err(FidoError::MissingParameter);
    }
    let (value, _) = cbor::decode(data).map_err(|_| FidoError::Cbor)?;
    let map = match &value {
        cbor::Value::M(m) => m,
        _ => return Err(FidoError::Cbor),
    };

    let mut expected_key: u64 = 1;
    let mut client_data_hash = Vec::new();
    let mut rp_id = String::new();
    let mut user_handle = Vec::new();
    let mut user_name = String::new();
    let mut user_display_name = String::new();
    let mut pubkey_creds: Vec<PubKeyCredParam> = Vec::new();
    let mut exclude_list: Vec<CredDescriptor> = Vec::new();
    let mut options = McOptions::default();
    let mut pin_uv_auth_param = None;
    let mut pin_uv_protocol: u8 = 2;
    let mut enterprise_attestation: Option<u8> = None;
    let mut extensions = McExtensions::default();

    for (key, val) in map {
        let key_u = match key {
            cbor::Value::U(u) => *u,
            cbor::Value::N(n) if *n < 0 => {
                // Negative keys are not valid in CTAP2 requests.
                return Err(FidoError::InvalidCbor);
            }
            _ => return Err(FidoError::Cbor),
        };
        // Canonical order check: keys 1..=4 must appear in order.
        if key_u <= 4 && key_u != expected_key {
            return Err(FidoError::MissingParameter);
        }
        if key_u < expected_key {
            return Err(FidoError::InvalidCbor);
        }
        expected_key = key_u.saturating_add(1);

        match key_u {
            0x01 => {
                // clientDataHash: bstr
                client_data_hash = cbor_get_bytes(val)?;
            }
            0x02 => {
                // rp: map { "id": tstr (required), "name": tstr (optional) }
                let rp_map = cbor_get_map(val)?;
                rp_id = cbor_get_map_text(rp_map, "id")?;
                // "name" is optional but must be a valid text string if present.
                let _ = cbor_get_map_text_opt(rp_map, "name")?;
            }
            0x03 => {
                // user: map { "id": bstr (required), "name": tstr, "displayName": tstr }
                let user_map = cbor_get_map(val)?;
                user_handle = cbor_get_map_bytes(user_map, "id")?;
                user_name = cbor_get_map_text_opt(user_map, "name")?.unwrap_or_default();
                user_display_name =
                    cbor_get_map_text_opt(user_map, "displayName")?.unwrap_or_default();
            }
            0x04 => {
                // pubKeyCredParams: array of { "type": tstr, "alg": int }.
                // Malformed entries map to INVALID_CBOR (matching the reference
                // firmware which surfaces CBOR parse errors for bad cred params).
                let arr = cbor_get_array(val)?;
                for item in arr {
                    let m = cbor_get_map(item)?;
                    // "type" missing or malformed → INVALID_CBOR (0x12).
                    let type_ = cbor_get_map_text(m, "type").map_err(|_| FidoError::InvalidCbor)?;
                    // "alg" wrong type (e.g. text) → CBOR_UNEXPECTED_TYPE (0x11);
                    // "alg" missing → INVALID_CBOR (0x12).
                    let alg = match cbor_get_map_int(m, "alg") {
                        Ok(a) => a,
                        Err(FidoError::CborUnexpectedType) => return Err(FidoError::CborUnexpectedType),
                        Err(_) => return Err(FidoError::InvalidCbor),
                    };
                    pubkey_creds.push(PubKeyCredParam { type_, alg });
                }
                // An empty array is treated as "no params provided" → MISSING_PARAMETER.
                if pubkey_creds.is_empty() {
                    return Err(FidoError::MissingParameter);
                }
            }
            0x05 => {
                // excludeList: array of { "type": tstr, "id": bstr }.
                // Type mismatches here map to INVALID_CBOR (0x12) to match
                // the reference firmware's behaviour.
                let arr = cbor_get_array(val)?;
                for item in arr {
                    let m = cbor_get_map(item)?;
                    let type_ = cbor_get_map_text(m, "type")
                        .map_err(|_| FidoError::InvalidCbor)?;
                    let id =
                        cbor_get_map_bytes(m, "id").map_err(|_| FidoError::InvalidCbor)?;
                    exclude_list.push(CredDescriptor { type_, id });
                }
            }
            0x06 => {
                // extensions: map of extension identifiers to inputs.
                let m = cbor_get_map(val)?;
                for (k, v) in m {
                    if let cbor::Value::T(s) = k {
                        let b = matches!(v, cbor::Value::Bool(true));
                        match s.as_str() {
                            "thirdPartyPayment" => extensions.third_party_payment = b,
                            "minPinLength" => extensions.min_pin_length = b,
                            "pinComplexityPolicy" => extensions.pin_complexity_policy = b,
                            "credBlob" => {
                                // credBlob input is a byte string to store.
                                if let cbor::Value::B(blob) = v {
                                    extensions.cred_blob = Some(blob.clone());
                                }
                            }
                            "hmac-secret" => {
                                extensions.hmac_secret = matches!(v, cbor::Value::Bool(true));
                            }
                            "largeBlobKey" => {
                                extensions.large_blob_key = matches!(v, cbor::Value::Bool(true));
                            }
                            "hmac-secret-mc" => {
                                if let cbor::Value::M(hm) = v {
                                    extensions.hmac_secret_mc =
                                        Some(parse_hmac_secret_input(hm)?);
                                }
                            }
                            "credentialProtectionPolicy" | "credProtect" => {
                                // credProtect policy: 1=optional, 2=optionalWithList,
                                // 3=required. Accept integer or boolean true (=optional).
                                let policy = match v {
                                    cbor::Value::U(u) => {
                                        if *u > 3 {
                                            return Err(FidoError::InvalidParameter);
                                        }
                                        *u as u8
                                    }
                                    cbor::Value::N(n) => {
                                        if *n < 1 || *n > 3 {
                                            return Err(FidoError::InvalidParameter);
                                        }
                                        *n as u8
                                    }
                                    cbor::Value::Bool(true) => 1,
                                    _ => 0,
                                };
                                extensions.cred_protect = policy;
                            }
                            _ => {}
                        }
                    }
                }
            }
            0x07 => {
                // options: map
                options.present = true;
                let m = cbor_get_map(val)?;
                for (k, v) in m {
                    if let cbor::Value::T(s) = k {
                        let b = matches!(v, cbor::Value::Bool(true));
                        match s.as_str() {
                            "rk" => options.rk = Some(b),
                            "up" => options.up = Some(b),
                            "uv" => options.uv = Some(b),
                            _ => {}
                        }
                    }
                }
            }
            0x08 => {
                pin_uv_auth_param = Some(cbor_get_bytes(val)?);
            }
            0x09 => {
                pin_uv_protocol = cbor_get_uint(val)? as u8;
            }
            0x0A => {
                let ep = cbor_get_uint(val)?;
                if ep != 1 && ep != 2 {
                    return Err(FidoError::InvalidParameter);
                }
                enterprise_attestation = Some(ep as u8);
            }
            _ => {
                // Ignore unknown keys.
            }
        }
    }

    // Required-field checks. CTAP2 spec requires clientDataHash (1), rp (2),
    // user (3), and pubKeyCredParams (4) to all be present.
    if client_data_hash.is_empty() {
        return Err(FidoError::MissingParameter);
    }
    if rp_id.is_empty() {
        return Err(FidoError::MissingParameter);
    }
    if user_handle.is_empty() {
        return Err(FidoError::MissingParameter);
    }
    if pubkey_creds.is_empty() {
        return Err(FidoError::MissingParameter);
    }

    Ok(McRequest {
        client_data_hash,
        rp_id,
        user_handle,
        user_name,
        user_display_name,
        pubkey_creds,
        exclude_list,
        options,
        pin_uv_auth_param,
        pin_uv_protocol,
        extensions,
        enterprise_attestation,
    })
}

/// Parse a getAssertion request with CTAP2 validation.
fn parse_ga_request(data: &[u8]) -> Result<GaRequest, FidoError> {
    if data.is_empty() {
        return Err(FidoError::MissingParameter);
    }
    let (value, _) = cbor::decode(data).map_err(|_| FidoError::Cbor)?;
    let map = match &value {
        cbor::Value::M(m) => m,
        _ => return Err(FidoError::Cbor),
    };

    let mut expected_key: u64 = 1;
    let mut rp_id = String::new();
    let mut client_data_hash = Vec::new();
    let mut allow_list: Vec<CredDescriptor> = Vec::new();
    let mut options = GaOptions::default();
    let mut pin_uv_auth_param = None;
    let mut pin_uv_protocol: u8 = 2;
    let mut extensions = McExtensions::default();

    for (key, val) in map {
        let key_u = match key {
            cbor::Value::U(u) => *u,
            cbor::Value::N(n) if *n < 0 => return Err(FidoError::InvalidCbor),
            _ => return Err(FidoError::Cbor),
        };
        if key_u <= 2 && key_u != expected_key {
            return Err(FidoError::MissingParameter);
        }
        if key_u < expected_key {
            return Err(FidoError::InvalidCbor);
        }
        expected_key = key_u.saturating_add(1);

        match key_u {
            0x01 => {
                // rpId: tstr
                rp_id = cbor_get_text(val)?;
            }
            0x02 => {
                // clientDataHash: bstr
                client_data_hash = cbor_get_bytes(val)?;
            }
            0x03 => {
                // allowList: array of { "type": tstr, "id": bstr }
                let arr = cbor_get_array(val)?;
                for item in arr {
                    let m = cbor_get_map(item)?;
                    let type_ = cbor_get_map_text(m, "type")?;
                    let id = cbor_get_map_bytes(m, "id")?;
                    allow_list.push(CredDescriptor { type_, id });
                }
            }
            0x04 => {
                // extensions: map of extension identifiers to inputs.
                let m = cbor_get_map(val)?;
                for (k, v) in m {
                    if let cbor::Value::T(s) = k {
                        let b = matches!(v, cbor::Value::Bool(true));
                        match s.as_str() {
                            "thirdPartyPayment" => extensions.third_party_payment = b,
                            // The CTAP2.1 spec names the getAssertion input
                            // "getCredBlob", but python-fido2 (the gate
                            // client) sends "credBlob": true — accept both.
                            "credBlob" | "getCredBlob" => {
                                extensions.get_cred_blob = !matches!(v, cbor::Value::Bool(false));
                            }
                            "hmac-secret" => {
                                if let cbor::Value::M(hm) = v {
                                    extensions.hmac_secret_input =
                                        Some(parse_hmac_secret_input(hm)?);
                                }
                            }
                            "largeBlobKey" => {
                                extensions.large_blob_key = matches!(v, cbor::Value::Bool(true));
                            }
                            _ => {}
                        }
                    }
                }
            }
            0x05 => {
                options.present = true;
                let m = cbor_get_map(val)?;
                for (k, v) in m {
                    if let cbor::Value::T(s) = k {
                        let b = matches!(v, cbor::Value::Bool(true));
                        match s.as_str() {
                            "rk" => options.rk = Some(b),
                            "up" => options.up = Some(b),
                            "uv" => options.uv = Some(b),
                            _ => {}
                        }
                    }
                }
            }
            0x06 => {
                pin_uv_auth_param = Some(cbor_get_bytes(val)?);
            }
            0x07 => {
                pin_uv_protocol = cbor_get_uint(val)? as u8;
            }
            _ => {}
        }
    }

    if rp_id.is_empty() {
        return Err(FidoError::MissingParameter);
    }
    if client_data_hash.is_empty() {
        return Err(FidoError::MissingParameter);
    }

    Ok(GaRequest {
        rp_id,
        client_data_hash,
        allow_list,
        options,
        pin_uv_auth_param,
        pin_uv_protocol,
        extensions,
    })
}

/// pinUvAuthToken permission bits (CTAP2.1 §6.5.5.4).
pub const PERM_MC: u8 = 0x01;
pub const PERM_GA: u8 = 0x02;
pub const PERM_CM: u8 = 0x04;
pub const PERM_BE: u8 = 0x08;
pub const PERM_LBF: u8 = 0x10;
pub const PERM_ACFG: u8 = 0x20;
/// Vendor extension (python-fido2 ClientPin.PERMISSION.PERSISTENT_CREDENTIAL_MGMT).
pub const PERM_CM_PERSISTENT: u8 = 0x40;

/// Extract the token scope (permissions bitmask CBOR key 0x09, bound rpId
/// key 0x0A) from a clientPin request. Permissions default to 0 (legacy
/// getPinToken semantics: valid for makeCredential/getAssertion only).
fn parse_client_pin_token_scope(data: &[u8]) -> (u8, Option<String>) {
    if data.is_empty() {
        return (0, None);
    }
    let (value, _) = match cbor::decode(data) {
        Ok(v) => v,
        Err(_) => return (0, None),
    };
    let map = match &value {
        cbor::Value::M(m) => m,
        _ => return (0, None),
    };
    let permissions = map
        .iter()
        .find(|(k, _)| matches!(k, cbor::Value::U(0x09)))
        .and_then(|(_, v)| match v {
            cbor::Value::U(u) => Some(*u as u8),
            _ => None,
        })
        .unwrap_or(0);
    let rp_id = map
        .iter()
        .find(|(k, _)| matches!(k, cbor::Value::U(0x0A)))
        .and_then(|(_, v)| match v {
            cbor::Value::T(s) => Some(s.clone()),
            _ => None,
        });
    (permissions, rp_id)
}



/// Parse a credMgmt request.
fn parse_cm_request(data: &[u8]) -> Result<CmRequest, FidoError> {
    if data.is_empty() {
        return Err(FidoError::MissingParameter);
    }
    let (value, _) = cbor::decode(data).map_err(|_| FidoError::Cbor)?;
    let map = match &value {
        cbor::Value::M(m) => m,
        _ => return Err(FidoError::Cbor),
    };

    let find = |key: u64| map.iter().find(|(k, _)| matches!(k, cbor::Value::U(u) if *u == key));
    let is_int = |v: &cbor::Value| matches!(v, cbor::Value::U(_) | cbor::Value::N(_));
    let is_map = |v: &cbor::Value| matches!(v, cbor::Value::M(_));

    // Dialect detection. The two layouts reuse the same key numbers for
    // different fields, so key *types* are what separate them:
    //
    //   key 0x02 -> PicoForge: a map (subCommandParams)
    //               CTAP2:     an integer (pinUvAuthProtocol)
    //
    // PicoForge omits key 0x02 entirely when a sub-command takes no
    // parameters, so that alone is not enough. Its pinUvAuthProtocol always
    // sits at key 0x03 as an integer, whereas CTAP2's key 0x03 is
    // pinUvAuthParam — a byte string. Checking both makes the
    // classification total: no request is left ambiguous, and no client is
    // misread as the other dialect.
    let dialect = match (find(0x02), find(0x03)) {
        (Some((_, v)), _) if is_map(v) => CmDialect::PicoForge,
        (_, Some((_, v))) if is_int(v) => CmDialect::PicoForge,
        (Some((_, v)), _) if is_int(v) => CmDialect::Ctap2,
        _ => CmDialect::Ctap2,
    };

    let mut expected_key: u64 = 1;
    let mut wire_subcommand: u8 = 0;
    let mut pin_uv_protocol: u8 = 2;
    let mut pin_uv_auth_param = None;
    let mut rp_id_hash = None;
    let mut cred_id = None;
    let mut user = None;
    let mut raw_cred_cbor = None;
    let mut raw_user_cbor = None;

    for (key, val) in map {
        let key_u = match key {
            cbor::Value::U(u) => *u,
            cbor::Value::N(n) if *n < 0 => return Err(FidoError::InvalidCbor),
            _ => return Err(FidoError::Cbor),
        };
        if key_u == 1 && wire_subcommand == 0 {
            // OK, subcommand is key 1.
        } else if dialect == CmDialect::PicoForge && key_u < expected_key {
            // CTAP2 places no ordering requirement on its map, so this
            // strictness is kept only where it already applied.
            return Err(FidoError::InvalidCbor);
        }
        expected_key = key_u.saturating_add(1);

        match dialect {
            // PicoForge: sub-params nested under key 0x02, protocol at
            // 0x03, pinUvAuthParam at 0x04.
            CmDialect::PicoForge => match key_u {
                0x01 => wire_subcommand = cbor_get_uint(val)? as u8,
                0x03 => pin_uv_protocol = cbor_get_uint(val)? as u8,
                0x04 => pin_uv_auth_param = Some(cbor_get_bytes(val)?),
                0x02 => {
                    // The map is walked into the typed fields below; this
                    // twin does not retain a verbatim copy, because it
                    // rebuilds the signed params from those fields instead.
                    let m = cbor_get_map(val)?;
                    for (k, v) in m {
                        let sub = match k {
                            cbor::Value::U(u) => *u,
                            _ => continue,
                        };
                        match sub {
                            0x01 => {
                                // rpIdHash
                                let b = cbor_get_bytes(v)?;
                                rp_id_hash = Some(b);
                            }
                            0x02 => {
                                // credentialId { "type": tstr, "id": bstr }
                                let cm = cbor_get_map(v)?;
                                let type_ =
                                    cbor_get_map_text_opt(cm, "type")?.unwrap_or_default();
                                let id = cbor_get_map_bytes(cm, "id")?;
                                cred_id = Some(CredDescriptor { type_, id });
                            }
                            0x03 => {
                                // user { "id": bstr, "name": tstr, "displayName": tstr }
                                let um = cbor_get_map(v)?;
                                let uid = cbor_get_map_bytes(um, "id")?;
                                let name = cbor_get_map_text_opt(um, "name")?.unwrap_or_default();
                                let display_name =
                                    cbor_get_map_text_opt(um, "displayName")?.unwrap_or_default();
                                user = Some(CmUser {
                                    id: uid,
                                    name,
                                    display_name,
                                });
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            },
            // CTAP2 §12.1.6: flat keys, no nesting.
            CmDialect::Ctap2 => match key_u {
                0x01 => wire_subcommand = cbor_get_uint(val)? as u8,
                0x02 => pin_uv_protocol = cbor_get_uint(val)? as u8,
                0x03 => pin_uv_auth_param = Some(cbor_get_bytes(val)?),
                0x04 => rp_id_hash = Some(cbor_get_bytes(val)?),
                0x05 => {
                    raw_cred_cbor = Some(cbor::encode(val));
                    let cm = cbor_get_map(val)?;
                    let type_ = cbor_get_map_text_opt(cm, "type")?.unwrap_or_default();
                    let id = cbor_get_map_bytes(cm, "id")?;
                    cred_id = Some(CredDescriptor { type_, id });
                }
                0x06 => {
                    raw_user_cbor = Some(cbor::encode(val));
                    let um = cbor_get_map(val)?;
                    let uid = cbor_get_map_bytes(um, "id")?;
                    let name = cbor_get_map_text_opt(um, "name")?.unwrap_or_default();
                    let display_name =
                        cbor_get_map_text_opt(um, "displayName")?.unwrap_or_default();
                    user = Some(CmUser {
                        id: uid,
                        name,
                        display_name,
                    });
                }
                _ => {}
            },
        }
    }

    if wire_subcommand == 0 {
        return Err(FidoError::MissingParameter);
    }

    // PicoForge numbers getCredsMetadata 0x01 and enumerateRpsBegin 0x02;
    // CTAP2 numbers them the other way round. Everything downstream works
    // in the canonical CTAP2 numbering, so PicoForge's pair is swapped here
    // and nowhere else.
    let subcommand = match (dialect, wire_subcommand) {
        (CmDialect::PicoForge, 0x01) => CM_GET_METADATA,
        (CmDialect::PicoForge, 0x02) => CM_ENUMERATE_RPS_BEGIN,
        (_, w) => w,
    };

    Ok(CmRequest {
        subcommand,
        wire_subcommand,
        dialect,
        pin_uv_protocol,
        pin_uv_auth_param,
        rp_id_hash,
        cred_id,
        user,
        raw_cred_cbor,
        raw_user_cbor,
    })
}

/// Parsed authenticatorConfig request.
struct ConfigRequest {
    sub_cmd: u8,
    params: Option<cbor::Value>,
    pin_uv_protocol: u8,
    pin_uv_auth_param: Vec<u8>,
}

/// Parse an authenticatorConfig (0x0D) request.
///
/// CBOR keys: 0x01 subCommand (uint), 0x02 subCommandParams (map, optional),
/// 0x03 pinUvAuthProtocol (uint), 0x04 pinUvAuthParam (bstr).
fn parse_config_request(data: &[u8]) -> Result<ConfigRequest, FidoError> {
    if data.is_empty() {
        return Err(FidoError::MissingParameter);
    }
    let (value, _) = cbor::decode(data).map_err(|_| FidoError::Cbor)?;
    let map = match &value {
        cbor::Value::M(m) => m,
        _ => return Err(FidoError::Cbor),
    };

    let mut sub_cmd: u8 = 0;
    let mut params = None;
    let mut pin_uv_protocol: u8 = 2;
    let mut pin_uv_auth_param = Vec::new();

    for (key, val) in map {
        let key_u = match key {
            cbor::Value::U(u) => *u,
            _ => return Err(FidoError::Cbor),
        };
        match key_u {
            0x01 => sub_cmd = cbor_get_uint(val).map_err(|_| FidoError::InvalidParameter)? as u8,
            0x02 => params = Some(val.clone()),
            0x03 => pin_uv_protocol = cbor_get_uint(val).map_err(|_| FidoError::InvalidParameter)? as u8,
            0x04 => pin_uv_auth_param = cbor_get_bytes(val)?,
            _ => {}
        }
    }

    if sub_cmd == 0 {
        return Err(FidoError::MissingParameter);
    }

    Ok(ConfigRequest {
        sub_cmd,
        params,
        pin_uv_protocol,
        pin_uv_auth_param,
    })
}

// ------------------------------------------------------------------
// CBOR field helpers
// ------------------------------------------------------------------

fn cbor_get_bytes(val: &cbor::Value) -> Result<Vec<u8>, FidoError> {
    match val {
        cbor::Value::B(b) => Ok(b.clone()),
        _ => Err(FidoError::CborUnexpectedType),
    }
}

fn cbor_get_text(val: &cbor::Value) -> Result<String, FidoError> {
    match val {
        cbor::Value::T(s) => Ok(s.clone()),
        _ => Err(FidoError::CborUnexpectedType),
    }
}

fn cbor_get_uint(val: &cbor::Value) -> Result<u64, FidoError> {
    match val {
        cbor::Value::U(u) => Ok(*u),
        _ => Err(FidoError::CborUnexpectedType),
    }
}

fn cbor_get_int(val: &cbor::Value) -> Result<i64, FidoError> {
    match val {
        cbor::Value::U(u) => Ok(*u as i64),
        cbor::Value::N(n) => Ok(*n),
        _ => Err(FidoError::CborUnexpectedType),
    }
}

fn cbor_get_map(val: &cbor::Value) -> Result<&[(cbor::Value, cbor::Value)], FidoError> {
    match val {
        cbor::Value::M(m) => Ok(m.as_slice()),
        _ => Err(FidoError::CborUnexpectedType),
    }
}

fn cbor_get_array(val: &cbor::Value) -> Result<&[cbor::Value], FidoError> {
    match val {
        cbor::Value::A(a) => Ok(a.as_slice()),
        _ => Err(FidoError::CborUnexpectedType),
    }
}

/// Look up a required text field in a CBOR map. Returns an error if the
/// field is missing OR if its value is not a text string (strict typing).
fn cbor_get_map_text(map: &[(cbor::Value, cbor::Value)], field: &str) -> Result<String, FidoError> {
    match map
        .iter()
        .find(|(k, _)| matches!(k, cbor::Value::T(t) if t == field))
    {
        Some((_, v)) => cbor_get_text(v),
        None => Err(FidoError::MissingParameter),
    }
}

/// Look up an optional text field. Returns Ok(None) only if the key is
/// absent; returns an error if the key is present but the type is wrong.
fn cbor_get_map_text_opt(
    map: &[(cbor::Value, cbor::Value)],
    field: &str,
) -> Result<Option<String>, FidoError> {
    match map
        .iter()
        .find(|(k, _)| matches!(k, cbor::Value::T(t) if t == field))
    {
        Some((_, v)) => cbor_get_text(v).map(Some),
        None => Ok(None),
    }
}

/// Look up a required byte-string field. Strict: errors on missing or wrong type.
fn cbor_get_map_bytes(map: &[(cbor::Value, cbor::Value)], field: &str) -> Result<Vec<u8>, FidoError> {
    match map
        .iter()
        .find(|(k, _)| matches!(k, cbor::Value::T(t) if t == field))
    {
        Some((_, v)) => cbor_get_bytes(v),
        None => Err(FidoError::MissingParameter),
    }
}


/// Look up a required integer field. Strict: errors on missing or wrong type.
fn cbor_get_map_int(map: &[(cbor::Value, cbor::Value)], field: &str) -> Result<i64, FidoError> {
    match map
        .iter()
        .find(|(k, _)| matches!(k, cbor::Value::T(t) if t == field))
    {
        Some((_, v)) => cbor_get_int(v),
        None => Err(FidoError::MissingParameter),
    }
}

// ------------------------------------------------------------------
// Authenticator data + COSE helpers
// ------------------------------------------------------------------

/// Build attested credential data: aaguid(16) + credIdLen(2) + credId + COSE pubkey.
fn build_attested_cred_data(cred_id: &[u8], cose_pubkey: &[u8]) -> Vec<u8> {
    let mut acd = Vec::with_capacity(16 + 2 + cred_id.len() + cose_pubkey.len());
    acd.extend_from_slice(&AAGUID);
    acd.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    acd.extend_from_slice(cred_id);
    acd.extend_from_slice(cose_pubkey);
    acd
}

/// Build authenticator data.
///
/// Layout: rpIdHash(32) + flags(1) + signCount(4) + [attestedCredentialData].
fn build_auth_data(
    rp_id_hash: &[u8; 32],
    flags: u8,
    sign_count: u32,
    att_cred_data: Option<&[u8]>,
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(37 + att_cred_data.map(|d| d.len()).unwrap_or(0));
    ad.extend_from_slice(rp_id_hash);
    ad.push(flags);
    ad.extend_from_slice(&sign_count.to_be_bytes());
    if let Some(acd) = att_cred_data {
        ad.extend_from_slice(acd);
    }
    ad
}
