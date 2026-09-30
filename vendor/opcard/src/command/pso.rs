// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use iso7816::Status;

use trussed_core::config::MAX_MESSAGE_LENGTH;
use trussed_core::types::*;
use trussed_core::{syscall, try_syscall};

use crate::card::LoadedContext;
use crate::state::KeyRef;
use crate::tlv::get_do;
use crate::types::*;

// US-914: operation tags for the touch-to-sign presence grant — the
// INS/P1/P2 triple of the gated key operation packed big-endian into the
// 32-bit grant tag, so a grant is bound to the *pending operation*.
pub const PRESENCE_TAG_PSO_SIGN: u32 = 0x002A_9E9A;
/// US-914: PSO:DECIPHER (`2A 80 86`).
pub const PRESENCE_TAG_PSO_DECIPHER: u32 = 0x002A_8086;
/// US-926 device consent rule: INTERNAL AUTHENTICATE (`88`; P1/P2 are
/// `00 00` on the wire — the tag pins the operation, not the parameters).
pub const PRESENCE_TAG_INT_AUTH: u32 = 0x0088_0000;

/// US-914: the presence-confirmation seam — post-authorization and
/// immediately before key material is used. The presence source
/// (`Options::presence_grant`, the device touch-to-sign wiring) is
/// authoritative for the ENABLED path only — the user's UIF flag for the
/// operation gates the whole check first: `Disabled` (the factory and
/// vendor-card default) signs off immediately with no prompt, matching
/// upstream opcard semantics and OpenPGP spec §7.2.13. (US-936-followup
/// 2026-09-25: an always-consulted grant previously demanded a physical
/// press for every PSO even with UIF off, and stock gpg `generate` — 3
/// on-card PSO:SIGN self/binding signatures — failed at
/// make_keysig_packet unless the user pressed the button once per
/// signature; scdaemon rendered the refusals as "Bad PIN".) When granted,
/// the touch wait can only be offered for commands that already passed
/// the authorization checks (factory gate, PW1 session, key resolution) —
/// a hostile host cannot hold the touch prompt open with APDUs that
/// cannot succeed. `None` keeps the upstream semantics: the `uif`-gated
/// UI prompt (host and emulation UIs auto-ack).
fn confirm_user_presence<T: crate::card::Client>(
    ctx: LoadedContext<'_, T>,
    key: KeyType,
    tag: u32,
) -> Result<(), Status> {
    if !ctx.state.persistent.uif(key).is_enabled() {
        return Ok(());
    }
    if let Some(grant) = ctx.options.presence_grant {
        return if grant(tag) {
            Ok(())
        } else {
            warn!("User presence confirmation refused");
            Err(Status::SecurityStatusNotSatisfied)
        };
    }
    prompt_uif(ctx)
}

fn prompt_uif<T: crate::card::Client>(ctx: LoadedContext<'_, T>) -> Result<(), Status> {
    let success = ctx
        .backend
        .confirm_user_present()
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?;
    if !success {
        warn!("User presence confirmation timed out");
        // FIXME SecurityRelatedIssues (0x6600 is not available?)
        Err(Status::SecurityStatusNotSatisfied)
    } else {
        Ok(())
    }
}

// § 7.2.10
pub fn sign<T: crate::card::Client>(mut ctx: LoadedContext<'_, T>) -> Result<(), Status> {
    // US-912: PSO:SIGN is refused while the factory-default PINs are still
    // in force.
    if ctx.state.persistent.factory_defaults_in_force() {
        warn!("PSO:SIGN refused: factory-default PINs still in force");
        return Err(Status::ConditionsOfUseNotSatisfied);
    }
    let key_id = ctx
        .state
        .key_id(ctx.backend.client_mut(), KeyType::Sign, ctx.options.storage)?;

    // US-914: the touch wait sits after the authorization checks (factory
    // gate, key resolution) and before the sign counter and key use.
    confirm_user_presence(ctx.lend(), KeyType::Sign, PRESENCE_TAG_PSO_SIGN)?;
    let sign_result = ctx
        .state
        .persistent
        .increment_sign_count(ctx.backend.client_mut(), ctx.options.storage)
        .map_err(|_err| {
            error!("Failed to increment sign count");
            Status::UnspecifiedPersistentExecutionError
        })
        .and_then(|_| match ctx.state.persistent.sign_alg() {
            SignatureAlgorithm::Ed255 => sign_ec(ctx.lend(), key_id, Mechanism::Ed255),
            SignatureAlgorithm::EcDsaP256 => {
                if ctx.data.len() != 32 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::P256Prehashed)
            }
            SignatureAlgorithm::EcDsaP384 => {
                if ctx.data.len() != 48 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::P384Prehashed)
            }
            SignatureAlgorithm::EcDsaP521 => {
                if ctx.data.len() != 64 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::P521Prehashed)
            }
            SignatureAlgorithm::EcDsaBrainpoolP256R1 => {
                if ctx.data.len() != 32 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::BrainpoolP256R1Prehashed)
            }
            SignatureAlgorithm::EcDsaBrainpoolP384R1 => {
                if ctx.data.len() != 48 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::BrainpoolP384R1Prehashed)
            }
            SignatureAlgorithm::EcDsaBrainpoolP512R1 => {
                if ctx.data.len() != 64 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::BrainpoolP512R1Prehashed)
            }
            SignatureAlgorithm::EcDsaSecp256k1 => {
                if ctx.data.len() != 32 {
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                sign_ec(ctx.lend(), key_id, Mechanism::Secp256k1Prehashed)
            }
            SignatureAlgorithm::Rsa2048 => sign_rsa(ctx.lend(), key_id, Mechanism::Rsa2048Pkcs1v15),
            SignatureAlgorithm::Rsa3072 => sign_rsa(ctx.lend(), key_id, Mechanism::Rsa3072Pkcs1v15),
            SignatureAlgorithm::Rsa4096 => sign_rsa(ctx.lend(), key_id, Mechanism::Rsa4096Pkcs1v15),
        });

    if !ctx.state.persistent.pw1_valid_multiple() {
        ctx.state.volatile.clear_sign(ctx.backend.client_mut())
    }
    sign_result
}

fn sign_ec<T: crate::card::Client>(
    mut ctx: LoadedContext<'_, T>,
    key_id: KeyId,
    mechanism: Mechanism,
) -> Result<(), Status> {
    if ctx.data.len() > MAX_MESSAGE_LENGTH {
        error!("Attempt to sign more than 1Kb of data");
        return Err(Status::NotEnoughMemory);
    }

    let signature = try_syscall!(ctx.backend.client_mut().sign(
        mechanism,
        key_id,
        ctx.data,
        SignatureSerialization::Raw
    ))
    .map_err(|_err| {
        error!("Failed to sign data: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .signature;
    ctx.reply.expand(&signature)
}

fn sign_rsa<T: crate::card::Client>(
    mut ctx: LoadedContext<'_, T>,
    key_id: KeyId,
    mechanism: Mechanism,
) -> Result<(), Status> {
    let signature = try_syscall!(ctx.backend.client_mut().sign(
        mechanism,
        key_id,
        ctx.data,
        SignatureSerialization::Raw
    ))
    .map_err(|_err| {
        error!("Failed to sign data: {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .signature;
    ctx.reply.expand(&signature)
}

enum RsaOrEcc {
    Rsa,
    Ecc,
}

fn int_aut_key_mecha_uif<T: crate::card::Client>(
    mut ctx: LoadedContext<'_, T>,
) -> Result<(KeyId, Mechanism, bool, RsaOrEcc), Status> {
    let (key_type, (mechanism, key_kind)) = match ctx.state.volatile.keyrefs.internal_aut {
        KeyRef::Aut => (
            KeyType::Aut,
            match ctx.state.persistent.aut_alg() {
                AuthenticationAlgorithm::EcDsaP256 => (Mechanism::P256Prehashed, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::EcDsaP384 => (Mechanism::P384Prehashed, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::EcDsaP521 => (Mechanism::P521Prehashed, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::EcDsaBrainpoolP256R1 => {
                    (Mechanism::BrainpoolP256R1Prehashed, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::EcDsaBrainpoolP384R1 => {
                    (Mechanism::BrainpoolP384R1Prehashed, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::EcDsaBrainpoolP512R1 => {
                    (Mechanism::BrainpoolP512R1Prehashed, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::EcDsaSecp256k1 => {
                    (Mechanism::Secp256k1Prehashed, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::Ed255 => (Mechanism::Ed255, RsaOrEcc::Ecc),

                AuthenticationAlgorithm::Rsa2048 => (Mechanism::Rsa2048Pkcs1v15, RsaOrEcc::Rsa),
                AuthenticationAlgorithm::Rsa3072 => (Mechanism::Rsa3072Pkcs1v15, RsaOrEcc::Rsa),
                AuthenticationAlgorithm::Rsa4096 => (Mechanism::Rsa4096Pkcs1v15, RsaOrEcc::Rsa),
            },
        ),
        KeyRef::Dec => (
            KeyType::Dec,
            match ctx.state.persistent.dec_alg() {
                DecryptionAlgorithm::X255 => {
                    warn!("Attempt to authenticate with X25519 key");
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }
                DecryptionAlgorithm::EcDhP256 => (Mechanism::P256Prehashed, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhP384 => (Mechanism::P384Prehashed, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhP521 => (Mechanism::P521Prehashed, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhBrainpoolP256R1 => {
                    (Mechanism::BrainpoolP256R1Prehashed, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::EcDhBrainpoolP384R1 => {
                    (Mechanism::BrainpoolP384R1Prehashed, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::EcDhBrainpoolP512R1 => {
                    (Mechanism::BrainpoolP512R1Prehashed, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::EcDhSecp256k1 => {
                    (Mechanism::Secp256k1Prehashed, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::Rsa2048 => (Mechanism::Rsa2048Pkcs1v15, RsaOrEcc::Rsa),
                DecryptionAlgorithm::Rsa3072 => (Mechanism::Rsa3072Pkcs1v15, RsaOrEcc::Rsa),
                DecryptionAlgorithm::Rsa4096 => (Mechanism::Rsa4096Pkcs1v15, RsaOrEcc::Rsa),
            },
        ),
    };

    match (mechanism, ctx.data.len()) {
        (Mechanism::P256Prehashed, 32)
        | (Mechanism::P384Prehashed, 48)
        | (Mechanism::P521Prehashed, 64) => {}
        (Mechanism::P256Prehashed, _)
        | (Mechanism::P384Prehashed, _)
        | (Mechanism::P521Prehashed, _) => {
            warn!(
                "Attempt to sign with invalind data length: {:?} {}",
                mechanism,
                ctx.data.len()
            );
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        _ => {}
    }

    Ok((
        ctx.state
            .key_id(ctx.backend.client_mut(), key_type, ctx.options.storage)?,
        mechanism,
        ctx.state.persistent.uif(key_type).is_enabled(),
        key_kind,
    ))
}

// § 7.2.13
pub fn internal_authenticate<T: crate::card::Client>(
    mut ctx: LoadedContext<'_, T>,
) -> Result<(), Status> {
    // US-926: INT-AUTH is refused outright while the factory-default PINs
    // are still in force — the default PIN would re-arm the PW1 session
    // trivially, so the volatile gate alone is not enough.
    if ctx.state.persistent.factory_defaults_in_force() {
        warn!("INT-AUTH refused: factory-default PINs still in force");
        return Err(Status::ConditionsOfUseNotSatisfied);
    }
    if !ctx.state.volatile.other_verified() {
        warn!("Attempt to sign without PW1 verified");
        return Err(Status::SecurityStatusNotSatisfied);
    }

    let (key_id, mechanism, _uif, key_kind) = int_aut_key_mecha_uif(ctx.lend())?;
    // US-914: touch wait after the PW1-other session check and key
    // resolution, before the key material is used.
    confirm_user_presence(ctx.lend(), KeyType::Aut, PRESENCE_TAG_INT_AUTH)?;

    match key_kind {
        RsaOrEcc::Ecc => sign_ec(ctx, key_id, mechanism),
        RsaOrEcc::Rsa => sign_rsa(ctx, key_id, mechanism),
    }
}

fn decipher_key_mecha_uif<T: crate::card::Client>(
    mut ctx: LoadedContext<'_, T>,
) -> Result<(KeyId, Mechanism, bool, RsaOrEcc), Status> {
    let (key_type, (mechanism, key_kind)) = match ctx.state.volatile.keyrefs.pso_decipher {
        KeyRef::Dec => (
            KeyType::Dec,
            match ctx.state.persistent.dec_alg() {
                DecryptionAlgorithm::X255 => (Mechanism::X255, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhP256 => (Mechanism::P256, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhP384 => (Mechanism::P384, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhP521 => (Mechanism::P521, RsaOrEcc::Ecc),
                DecryptionAlgorithm::EcDhBrainpoolP256R1 => {
                    (Mechanism::BrainpoolP256R1, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::EcDhBrainpoolP384R1 => {
                    (Mechanism::BrainpoolP384R1, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::EcDhBrainpoolP512R1 => {
                    (Mechanism::BrainpoolP512R1, RsaOrEcc::Ecc)
                }
                DecryptionAlgorithm::EcDhSecp256k1 => (Mechanism::Secp256k1, RsaOrEcc::Ecc),
                DecryptionAlgorithm::Rsa2048 => (Mechanism::Rsa2048Pkcs1v15, RsaOrEcc::Rsa),
                DecryptionAlgorithm::Rsa3072 => (Mechanism::Rsa3072Pkcs1v15, RsaOrEcc::Rsa),
                DecryptionAlgorithm::Rsa4096 => (Mechanism::Rsa4096Pkcs1v15, RsaOrEcc::Rsa),
            },
        ),
        KeyRef::Aut => (
            KeyType::Aut,
            match ctx.state.persistent.aut_alg() {
                AuthenticationAlgorithm::EcDsaP256 => (Mechanism::P256, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::EcDsaP384 => (Mechanism::P384, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::EcDsaP521 => (Mechanism::P521, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::EcDsaBrainpoolP256R1 => {
                    (Mechanism::BrainpoolP256R1, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::EcDsaBrainpoolP384R1 => {
                    (Mechanism::BrainpoolP384R1, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::EcDsaBrainpoolP512R1 => {
                    (Mechanism::BrainpoolP512R1, RsaOrEcc::Ecc)
                }
                AuthenticationAlgorithm::EcDsaSecp256k1 => (Mechanism::Secp256k1, RsaOrEcc::Ecc),
                AuthenticationAlgorithm::Ed255 => {
                    warn!("Attempt to decipher with Ed255 key");
                    return Err(Status::ConditionsOfUseNotSatisfied);
                }

                AuthenticationAlgorithm::Rsa2048 => (Mechanism::Rsa2048Pkcs1v15, RsaOrEcc::Rsa),
                AuthenticationAlgorithm::Rsa3072 => (Mechanism::Rsa3072Pkcs1v15, RsaOrEcc::Rsa),
                AuthenticationAlgorithm::Rsa4096 => (Mechanism::Rsa4096Pkcs1v15, RsaOrEcc::Rsa),
            },
        ),
    };

    Ok((
        ctx.state
            .key_id(ctx.backend.client_mut(), key_type, ctx.options.storage)?,
        mechanism,
        ctx.state.persistent.uif(key_type).is_enabled(),
        key_kind,
    ))
}

// § 7.2.11
pub fn decipher<T: crate::card::Client>(mut ctx: LoadedContext<'_, T>) -> Result<(), Status> {
    // US-912: PSO:DECIPHER is refused while the factory-default PINs are
    // still in force.
    if ctx.state.persistent.factory_defaults_in_force() {
        warn!("PSO:DECIPHER refused: factory-default PINs still in force");
        return Err(Status::ConditionsOfUseNotSatisfied);
    }
    if !ctx.state.volatile.other_verified() {
        warn!("Attempt to sign without PW1 verified");
        return Err(Status::SecurityStatusNotSatisfied);
    }

    if ctx.data.is_empty() {
        return Err(Status::IncorrectDataParameter);
    }
    if ctx.data[0] == 0x02 {
        return decipher_aes(ctx);
    }

    let (key_id, mechanism, _uif, key_kind) = decipher_key_mecha_uif(ctx.lend())?;
    // US-914: touch wait after the PW1-other session check and key
    // resolution, before the key material is used.
    confirm_user_presence(ctx.lend(), KeyType::Dec, PRESENCE_TAG_PSO_DECIPHER)?;
    match key_kind {
        RsaOrEcc::Ecc => decrypt_ec(ctx, key_id, mechanism),
        RsaOrEcc::Rsa => decrypt_rsa(ctx, key_id, mechanism),
    }
}

fn decrypt_rsa<T: crate::card::Client>(
    mut ctx: LoadedContext<'_, T>,
    private_key: KeyId,
    mechanism: Mechanism,
) -> Result<(), Status> {
    if ctx.data.is_empty() {
        return Err(Status::IncorrectDataParameter);
    }
    let plaintext = try_syscall!(ctx.backend.client_mut().decrypt(
        mechanism,
        private_key,
        &ctx.data[1..],
        &[],
        &[],
        &[]
    ))
    .map_err(|_err| {
        error!("Failed to decrypt data: {_err:?}");
        Status::IncorrectDataParameter
    })?
    .plaintext
    .ok_or_else(|| {
        warn!("No plaintext");
        Status::IncorrectDataParameter
    })?;
    ctx.reply.expand(&plaintext)
}

fn decrypt_ec<T: crate::card::Client>(
    mut ctx: LoadedContext<'_, T>,
    private_key: KeyId,
    mechanism: Mechanism,
) -> Result<(), Status> {
    // Cipher DO - Public key DO - External public key
    const DATA_PATH: &[u16] = &[0xA6, 0x7F49, 0x86];
    let data = get_do(DATA_PATH, ctx.data).ok_or_else(|| {
        warn!("Failed to parse serialized key DOs");
        Status::IncorrectDataParameter
    })?;
    if data.is_empty() {
        warn!("Seriliazed key is not long enough");
        return Err(Status::IncorrectDataParameter);
    }

    // The "External Public Key" DO (86) carries a *tagged* EC point, and the
    // tag depends on the curve:
    //
    //   * 04 || X || Y  — uncompressed SEC1, for every curve with real
    //     field-element pairs (NIST, secp256k1, Brainpool). Already
    //     stripped below.
    //   * 40 || X       — the RFC 6637 compact form (gpg's "djb tweak") for
    //     Curve25519, whose point is a bare 32-byte x-coordinate with no
    //     partner y.
    //
    // trussed's X25519 deserializer accepts exactly 32 bytes and rejects
    // anything else, so the `0x40` has to come off here — before the
    // backend — or a conformant tagged request is answered
    // IncorrectDataParameter (6A80). US-958 hit exactly that on the live
    // RP2350; `docs/tasks/evidence/us959/probe-tag.py` is the host
    // reproducer (6A80 with the tag, 9000 without — see
    // `x25519-tag-probe-prefix.txt` / `-postfix.txt`).
    //
    // Both wire forms are accepted — the tagged one above and the bare
    // 32-byte one, which is what gpg 2.4.4's scdaemon actually puts on the
    // wire after its own strip (`scd/app-openpgp.c` `do_decipher`:
    // "Skip the prefix. It may be 0x40 (in new format), or MPI head of 0x00
    // (in old format)"). Any other leading octet is *not* stripped: a
    // wrong tag must not be silently reinterpreted as part of the point.
    let serialized_key = if matches!(mechanism, Mechanism::X255) {
        if data.len() == 33 && data[0] == 0x40 {
            // `40 || X`, 33 bytes: the RFC 6637 compact form.
            &data[1..]
        } else if data.len() == 32 {
            // Bare 32-byte x-coordinate.
            data
        } else {
            warn!("X25519 external public key is neither `40 || X` nor a bare 32-byte point");
            return Err(Status::IncorrectDataParameter);
        }
    } else {
        if data[0] != 0x04 {
            warn!("Seriliazed isn't in raw format");
            return Err(Status::IncorrectDataParameter);
        }
        // Does not panic because of the previous `is_empty` check
        &data[1..]
    };

    let pubk_id = try_syscall!(ctx.backend.client_mut().deserialize_key(
        mechanism,
        serialized_key,
        KeySerialization::Raw,
        StorageAttributes::new().set_persistence(Location::Volatile),
    ))
    .map_err(|_err| {
        error!("Failed to deserialize data: {_err:?}");
        Status::IncorrectDataParameter
    })?
    .key;
    let res = try_syscall!(ctx.backend.client_mut().agree(
        mechanism,
        private_key,
        pubk_id,
        StorageAttributes::new()
            .set_persistence(Location::Volatile)
            .set_serializable(true),
    ));

    try_syscall!(ctx.backend.client_mut().delete(pubk_id)).map_err(|_err| {
        error!("Failed to delete key {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?;

    let shared_secret = res
        .map_err(|_err| {
            error!("Failed to derive secret {_err:?}");
            Status::UnspecifiedNonpersistentExecutionError
        })?
        .shared_secret;

    let data = try_syscall!(ctx.backend.client_mut().serialize_key(
        Mechanism::SharedSecret,
        shared_secret,
        KeySerialization::Raw,
    ))
    .map_err(|_err| {
        error!("Failed to serialize secret {_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?
    .serialized_key;

    try_syscall!(ctx.backend.client_mut().delete(shared_secret)).map_err(|_err| {
        error!("Failed to delete shared secret{_err:?}");
        Status::UnspecifiedNonpersistentExecutionError
    })?;

    // The KDF-DO (F9) is stored and served back byte-exact, but it is *not*
    // applied here: gpg derives the key-encryption key in software from the
    // raw shared point (g10/ecdh.c `extract_secret_x` + `derive_kek`, with
    // the KDF parameter blob built from the public key), so a card that also
    // derived would double-derive. The reply is the raw shared point.
    //
    // The reply is *untagged* for every curve, which is load-bearing and the
    // mirror image of the input-side strip above: gpg's scdaemon adds the
    // format tag itself on the way back (`scd/app-openpgp.c` `do_decipher`
    // unconditionally prepends `0x40` for a CV25519 slot, and `0x41` for any
    // other ECC slot whose reply length is even; `ecc_read_pubkey` does the
    // same for the public-key DO, which is why this card answers
    // `7F49 22 86 20` + 32 bytes there). A card that tagged its own reply
    // would therefore hand `extract_secret_x` `0x40 || 0x40 || X` (34
    // bytes) and trip its `point_nbytes < nshared` guard (33 < 34) with
    // GPG_ERR_BAD_DATA. The raw 32-byte x-coordinate also matches
    // `extract_secret_x`'s `nshared == secret_x_size` fast path, which
    // takes the bytes as-is.
    ctx.reply.expand(&data)
}

fn decipher_aes<T: crate::card::Client>(mut ctx: LoadedContext<'_, T>) -> Result<(), Status> {
    let key_id = ctx
        .state
        .volatile
        .aes_key_id(ctx.backend.client_mut(), ctx.options.storage)
        .map_err(|_err| {
            warn!("Failed to load aes key: {:?}", _err);
            Status::ConditionsOfUseNotSatisfied
        })?;

    if (ctx.data.len() - 1) % 16 != 0 {
        warn!("Attempt to decipher with AES with length not a multiple of block size");
        return Err(Status::IncorrectDataParameter);
    }

    // US-914: the AES path bypasses the ECC/RSA seam below, but it still
    // uses key material — the touch wait goes here too, before the decrypt.
    confirm_user_presence(ctx.lend(), KeyType::Dec, PRESENCE_TAG_PSO_DECIPHER)?;

    let plaintext = syscall!(ctx.backend.client_mut().decrypt(
        Mechanism::Aes256Cbc,
        key_id,
        &ctx.data[1..],
        &[], // No AAD
        &[], // Zero IV
        &[]  // No authentication tag
    ))
    .plaintext
    .ok_or_else(|| {
        warn!("Failed decryption");
        Status::UnspecifiedCheckingError
    })?;
    ctx.reply.expand(&plaintext)
}

pub fn encipher<T: crate::card::Client>(mut ctx: LoadedContext<'_, T>) -> Result<(), Status> {
    let key_id = ctx
        .state
        .volatile
        .aes_key_id(ctx.backend.client_mut(), ctx.options.storage)
        .map_err(|_err| {
            warn!("Failed to load aes key: {:?}", _err);
            Status::ConditionsOfUseNotSatisfied
        })?;

    if ctx.data.len() % 16 != 0 {
        warn!("Attempt to encipher with AES with length not a multiple of block size");
        return Err(Status::IncorrectDataParameter);
    }

    let plaintext = syscall!(ctx.backend.client_mut().encrypt(
        Mechanism::Aes256Cbc,
        key_id,
        ctx.data,
        &[],
        None
    ))
    .ciphertext;
    ctx.reply.expand(&[0x02])?;
    ctx.reply.expand(&plaintext)
}
