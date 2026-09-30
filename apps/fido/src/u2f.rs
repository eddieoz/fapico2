//! U2F (CTAP1) fallback implementation.
//!
//! U2F commands arrive as CTAPHID_MSG (0x03) HID frames carrying a U2F APDU.
//! This module implements the U2F REGISTER, AUTHENTICATE, and VERSION
//! commands. Since US-714 (POLISH-PUB) registrations are STATELESS (C
//! parity, `cmd_register.c` → `derive_key`): the key handle is a random
//! 32-byte HKDF-salt path plus an HMAC tag binding the appId, and the
//! private key is re-derived from the device master at authentication —
//! no keystore entry is consumed. Legacy store-backed handles (pre-US-714)
//! keep authenticating through the keystore lookup.

use crate::attestation::AttestationIdentity;
use crate::crypto;
use crate::keystore::Keystore;
use crate::stateless;

/// U2F command codes (INS byte).
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum U2fCommand {
    Register = 0x01,
    Authenticate = 0x02,
    Version = 0x03,
}

/// U2F status codes (APDU response).
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum U2fStatus {
    NoError = 0x9000,
    WrongData = 0x6A80,
    SecurityStatusNotSatisfied = 0x6982,
    ConditionsNotSatisfied = 0x6985,
    InsNotSupported = 0x6D00,
    ClaNotSupported = 0x6E00,
    WrongLength = 0x6700,
    /// US-908: enforce-mode AUTHENTICATE without a presence grant — the
    /// CTAP1 `NOT_PRESENT` error byte (0x07) as the response payload.
    NotPresent = 0x0700,
}

impl U2fStatus {
    pub fn code(self) -> u16 {
        self as u16
    }
}

/// U2F version string.
pub const U2F_VERSION: &str = "U2F_V2";

/// US-714: derive a stateless U2F key handle from the keystore's per-device
/// random (host twin of the device register path). Returns
/// `(scalar, key_handle)`; the caller builds the public key from the scalar
/// and drops it (zeroized on drop).
fn stateless_handle(
    keystore: &dyn Keystore,
    app_param: &[u8],
) -> Option<(stateless::StatelessScalar, [u8; stateless::KEY_HANDLE_LEN])> {
    let master = stateless::master_from_device_random(&keystore.get_auth_state().device_random);
    let mut path = crypto::random_bytes::<{ stateless::KEY_PATH_LEN }>();
    for word in path.as_chunks_mut::<4>().0 {
        word[3] |= 0x80; // C: val |= 0x80000000 (LE word, MSB set)
    }
    let scalar = stateless::derive_scalar_from_path(&master, &path);
    // Validate the scalar is a usable P-256 key (≈2⁻³² chance of ≥ curve
    // order); the caller re-derives the key pair itself.
    if p256::SecretKey::from_slice(scalar.bytes()).is_err() {
        return None;
    }
    let mut app_id = [0u8; 32];
    app_id.copy_from_slice(app_param);
    let tag = stateless::handle_tag(&scalar, &app_id, &path);
    let mut handle = [0u8; stateless::KEY_HANDLE_LEN];
    handle[..stateless::KEY_PATH_LEN].copy_from_slice(&path);
    handle[stateless::KEY_PATH_LEN..].copy_from_slice(&tag);
    Some((scalar, handle))
}

/// Process a U2F APDU and return the response bytes (without status word).
///
/// The APDU format is: CLA INS P1 P2 0x00 LenHI LenLO ...data... 0x00 0x00
/// The response is: ...data... STATUS_HI STATUS_LO
pub fn process_u2f_apdu(
    data: &[u8],
    keystore: &mut dyn Keystore,
    user_present: impl Fn() -> bool,
    attestation: &AttestationIdentity,
) -> Result<Vec<u8>, U2fStatus> {
    if data.len() < 5 {
        return Err(U2fStatus::WrongLength);
    }
    let cla = data[0];
    let ins = data[1];
    let p1 = data[2];
    let _p2 = data[3];

    if cla != 0x00 {
        return Err(U2fStatus::ClaNotSupported);
    }

    // Parse LC: short form is a single byte at data[4]; extended length is
    // 0x00 || LenHI || LenLO (the U2F harness uses both).
    let (lc, hdr): (usize, usize) = if data.len() == 5 {
        (0, 5)
    } else if data[4] == 0x00 {
        if data.len() < 7 {
            return Err(U2fStatus::WrongLength);
        }
        (u16::from_be_bytes([data[5], data[6]]) as usize, 7)
    } else {
        (data[4] as usize, 5)
    };
    let apdu_data = if data.len() >= hdr + lc {
        &data[hdr..hdr + lc]
    } else {
        &data[hdr..]
    };

    match ins {
        0x01 => u2f_register(apdu_data, keystore, &user_present, attestation),
        0x02 => u2f_authenticate(apdu_data, p1, keystore, &user_present),
        0x03 => u2f_version(apdu_data),
        0xA4 if p1 == 0x04 => select_aid(apdu_data),
        _ => Err(U2fStatus::InsNotSupported),
    }
}

/// FIDO Alliance management AID (SELECT over CTAPHID_MSG).
const MANAGEMENT_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// SELECT AID (INS 0xA4, P1 0x04): acknowledge the FIDO management AID with
/// 9000. No application state is changed, so a subsequent INIT re-arms U2F.
fn select_aid(data: &[u8]) -> Result<Vec<u8>, U2fStatus> {
    if data == MANAGEMENT_AID {
        Ok(vec![])
    } else {
        Err(U2fStatus::InsNotSupported)
    }
}

fn u2f_register(
    data: &[u8],
    keystore: &mut dyn Keystore,
    user_present: &impl Fn() -> bool,
    attestation: &AttestationIdentity,
) -> Result<Vec<u8>, U2fStatus> {
    // REGISTER: client_param(32) || app_param(32)
    if data.len() < 64 {
        return Err(U2fStatus::WrongLength);
    }
    let client_param = &data[0..32];
    let app_param = &data[32..64];

    // US-908: a silent register must never mint a key handle nor emit an
    // attestation signature. No grant ⇒ SW_CONDITIONS_NOT_SATISFIED (C
    // `cmd_register.c` parity); the attestation path is unchanged.
    if !user_present() {
        return Err(U2fStatus::ConditionsNotSatisfied);
    }

    // US-714 (C parity): stateless key handle — the private key is
    // re-derived at authentication, so no keystore entry is created.
    let (scalar, cred_id) =
        stateless_handle(keystore, app_param).ok_or(U2fStatus::WrongData)?;
    let sk = p256::SecretKey::from_slice(scalar.bytes()).map_err(|_| U2fStatus::WrongData)?;
    let pub_bytes = crypto::public_key_bytes(&sk.public_key());
    // `scalar` (StatelessScalar) zeroizes on drop here.

    // Build response: 0x05 || pub_key(65) || key_handle_len(1) || key_handle
    let mut resp = Vec::with_capacity(1 + 65 + 1 + cred_id.len());
    resp.push(0x05); // reserved byte
    resp.extend_from_slice(&pub_bytes);
    resp.push(cred_id.len() as u8);
    resp.extend_from_slice(&cred_id);

    // Attestation certificate + signature (US-916: the per-device identity
    // provisioned at boot — no repo static any more).
    resp.extend_from_slice(attestation.cert_bytes());

    // Sign over: 0x00 || app_param || client_param || key_handle || public_key
    // (per the U2F spec, the key handle length byte is NOT included).
    let mut sign_base = Vec::with_capacity(1 + 32 + 32 + cred_id.len() + 65);
    sign_base.push(0x00);
    sign_base.extend_from_slice(app_param);
    sign_base.extend_from_slice(client_param);
    sign_base.extend_from_slice(&cred_id);
    sign_base.extend_from_slice(&pub_bytes);

    let signature = crypto::p256_sign_bytes(attestation.key(), &sign_base);
    resp.extend_from_slice(&signature);

    Ok(resp)
}

fn u2f_authenticate(
    data: &[u8],
    p1: u8,
    keystore: &mut dyn Keystore,
    user_present: &impl Fn() -> bool,
) -> Result<Vec<u8>, U2fStatus> {
    // AUTHENTICATE: client_param(32) || app_param(32) || key_handle_len(1) || key_handle
    if data.len() < 65 {
        return Err(U2fStatus::WrongLength);
    }
    let client_param = &data[0..32];
    let app_param = &data[32..64];
    let key_handle_len = data[64] as usize;
    if data.len() < 65 + key_handle_len {
        return Err(U2fStatus::WrongLength);
    }
    let key_handle = &data[65..65 + key_handle_len];

    // US-714: stateless handles verify their appId tag in constant time and
    // re-derive the key; the legacy store-backed path handles everything else
    // (pre-US-714 handles, and store-backed CTAP2 credentials driven over U2F).
    let master = stateless::master_from_device_random(&keystore.get_auth_state().device_random);
    let mut app_id = [0u8; 32];
    app_id.copy_from_slice(app_param);
    let stateless_valid = stateless::verify_handle(&master, &app_id, key_handle);

    if p1 == 0x07 {
        // Check-only: per the U2F spec, CONDITIONS_NOT_SATISFIED (0x6985)
        // when the key handle is valid, WRONG_DATA (0x6A80) when not.
        let legacy_valid = keystore
            .get_credential(key_handle)
            .map(|c| c.rp_id_hash == app_param)
            .unwrap_or(false);
        if legacy_valid || stateless_valid {
            Err(U2fStatus::ConditionsNotSatisfied)
        } else {
            Err(U2fStatus::WrongData)
        }
    } else if stateless_valid {
        // Stateless enforce (C `verify_key` path): sign with the
        // re-derived scalar. The keystore-wide counter serves as the global
        // U2F signature counter (C `ef_counter` parity — a stateless
        // credential has no stored per-credential counter).
        // Persist-or-revert, mirroring the device twin's
        // `bump_global_counter_checked` (review minor). The clause after the
        // dash used to read "the reply signs the durable counter", which was
        // true before US-1011 and is **false now**: the keystore-wide counter
        // is batched on the same window as the per-credential one, so on all
        // but every `COUNTER_PERSIST_INTERVAL`-th call this returns a value
        // that is in RAM only. What still holds is the revert — on save
        // *failure* the bump rolls back, so the reply never signs a value
        // that outlives the store. Non-repetition across a power cut comes
        // from US-1012's forward-only restore, not from durability; see
        // `device_keystore::bump_global_counter_checked`, which warns about
        // the same assumption in the same words.
        // US-908: enforce mode signs only with a presence grant. No grant
        // ⇒ the CTAP1 NOT_PRESENT error byte (0x07); nothing signs and the
        // counter never moves. Check-only above stays side-effect-free.
        if !user_present() {
            return Err(U2fStatus::NotPresent);
        }
        let counter = {
            let next = keystore.get_auth_state().cred_counter.wrapping_add(1);
            keystore.get_auth_state_mut().cred_counter = next;
            if keystore.save_auth_state().is_ok() {
                next
            } else {
                keystore.get_auth_state_mut().cred_counter = next.wrapping_sub(1);
                next.wrapping_sub(1)
            }
        };

        // Build response: user_presence(1) || counter(4) || signature
        let mut resp = Vec::with_capacity(1 + 4 + 128);
        resp.push(0x01); // user presence
        resp.extend_from_slice(&counter.to_be_bytes());

        // Signature over: app_param(32) || user_presence(1) || counter(4) || client_param(32)
        let mut sign_base = Vec::with_capacity(1 + 32 + 4 + 32);
        sign_base.extend_from_slice(app_param);
        sign_base.push(0x01);
        sign_base.extend_from_slice(&counter.to_be_bytes());
        sign_base.extend_from_slice(client_param);

        let mut path = [0u8; stateless::KEY_PATH_LEN];
        path.copy_from_slice(&key_handle[..stateless::KEY_PATH_LEN]);
        let scalar = stateless::derive_scalar_from_path(&master, &path);
        let secret = crypto::secret_key_from_bytes(scalar.bytes());
        match secret {
            Some(s) => {
                let signature = crypto::p256_sign_bytes(&s, &sign_base);
                resp.extend_from_slice(&signature);
            }
            None => return Err(U2fStatus::WrongData),
        }

        Ok(resp)
    } else {
        // Legacy store-backed enforce path.
        let cred = keystore.get_credential(key_handle).cloned();
        let mut cred = match cred {
            Some(c) => c,
            None => return Err(U2fStatus::WrongData),
        };
        // Verify app_param matches.
        if cred.rp_id_hash != app_param {
            return Err(U2fStatus::WrongData);
        }

        // credProtect=3 (UV REQUIRED) credentials are unusable over U2F,
        // which has no user-verification semantics.
        if cred.cred_protect == 3 {
            return Err(U2fStatus::SecurityStatusNotSatisfied);
        }

        // US-908: same presence gate as the stateless path — no grant, no
        // signature, no counter move.
        if !user_present() {
            return Err(U2fStatus::NotPresent);
        }

        // Increment counter.
        let counter = cred.counter.wrapping_add(1);
        cred.counter = counter;
        let _cred_id = cred.credential_id.clone();
        // Clone the private key before moving `cred` into the keystore.
        let private_key = cred.private_key.clone();
        let _ = keystore.store_credential(cred);

        // Build response: user_presence(1) || counter(4) || signature
        let mut resp = Vec::with_capacity(1 + 4 + 128);
        resp.push(0x01); // user presence
        resp.extend_from_slice(&counter.to_be_bytes());

        // Signature over: app_param(32) || user_presence(1) || counter(4) || client_param(32)
        let mut sign_base = Vec::with_capacity(1 + 32 + 4 + 32);
        sign_base.extend_from_slice(app_param);
        sign_base.push(0x01);
        sign_base.extend_from_slice(&counter.to_be_bytes());
        sign_base.extend_from_slice(client_param);

        let secret = crypto::secret_key_from_bytes(&private_key);
        match secret {
            Some(s) => {
                let signature = crypto::p256_sign_bytes(&s, &sign_base);
                resp.extend_from_slice(&signature);
            }
            None => return Err(U2fStatus::WrongData),
        }

        Ok(resp)
    }
}

fn u2f_version(_data: &[u8]) -> Result<Vec<u8>, U2fStatus> {
    Ok(U2F_VERSION.as_bytes().to_vec())
}
