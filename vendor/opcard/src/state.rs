// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use core::mem::take;

use heapless_bytes::Bytes;
use hex_literal::hex;
use iso7816::Status;
use littlefs2_core::{path, Path, PathBuf};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_repr::{Deserialize_repr, Serialize_repr};

use trussed_chunked::utils::{write_all, EncryptionData};
use trussed_core::api::reply::Metadata;
use trussed_core::config::MAX_MESSAGE_LENGTH;
use trussed_core::types::{
    KeyId, KeySerialization, Location, Mechanism, Message, StorageAttributes,
};
use trussed_core::{syscall, try_syscall};

use crate::card::reply::Reply;
use crate::command::{Password, PasswordMode};
use crate::error::Error;
use crate::types::*;
use crate::utils::serde_bytes;

/// Maximum supported length for PW1 and PW3
pub const MAX_PIN_LENGTH: usize = 127;
pub const MIN_LENGTH_RESET_CODE: usize = 8;
pub const MIN_LENGTH_ADMIN_PIN: usize = 8;
pub const MIN_LENGTH_USER_PIN: usize = 6;

/// Default value for PW1
pub const DEFAULT_USER_PIN: &[u8] = b"123456";
/// Default value for PW3
pub const DEFAULT_ADMIN_PIN: &[u8] = b"12345678";

pub const MAX_GENERIC_LENGTH: usize = 4096;
/// Big endian encoding of [MAX_GENERIC_LENGTH](MAX_GENERIC_LENGTH)
pub const MAX_GENERIC_LENGTH_BE: [u8; 2] = (MAX_GENERIC_LENGTH as u16).to_be_bytes();

pub const SIGNING_KEY_PATH: &Path = path!("signing_key.bin");
pub const DEC_KEY_PATH: &Path = path!("conf_key.bin");
pub const AUTH_KEY_PATH: &Path = path!("auth_key.bin");
pub const AES_KEY_PATH: &Path = path!("aes_key.bin");

macro_rules! enum_u8 {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $($(#[$attr:meta])? $var:ident = $num:expr),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        #[repr(u8)]
        $vis enum $name {
            $(
                $(#[$attr])?
                $var = $num,
            )*
        }

        impl TryFrom<u8> for $name {
            type Error = Status;
            fn try_from(val: u8) -> ::core::result::Result<Self, Status> {
                match val {
                    $(
                        $num => Ok($name::$var),
                    )*
                    _ => Err(Status::KeyReferenceNotFound)
                }
            }
        }
    }
}

macro_rules! concatenated_key_newtype {
    (
        $(#[$outer:meta])*
        $vis:vis struct $name:ident ($inner_vis:vis [u8; $N:literal]);
    ) => {
        $(#[$outer])*
        $vis struct $name($inner_vis [u8; $N]);

        impl Default for $name {
            fn default() -> $name {
                $name([0;$N])
            }
        }

        impl $name {
            pub fn key_part_mut(&mut self, key: KeyType) -> &mut [u8] {
                let offset = self.key_offset(key);
                &mut self.0[offset..][..$N/3]
            }
        }

        // Custom (De)Serialize impls using serde_bytes
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serde_bytes::serialize(&self.0, serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                serde_bytes::deserialize(deserializer).map($name)
            }
        }

    }
}

concatenated_key_newtype! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct Fingerprints(pub [u8; 60]);
}

concatenated_key_newtype! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct CaFingerprints(pub [u8; 60]);
}

concatenated_key_newtype! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct KeyGenDates(pub [u8; 12]);
}

impl Fingerprints {
    fn key_offset(&self, for_key: KeyType) -> usize {
        match for_key {
            KeyType::Sign => 0,
            KeyType::Dec => 20,
            KeyType::Aut => 40,
        }
    }
}

impl KeyGenDates {
    fn key_offset(&self, for_key: KeyType) -> usize {
        match for_key {
            KeyType::Sign => 0,
            KeyType::Dec => 4,
            KeyType::Aut => 8,
        }
    }
}

impl CaFingerprints {
    fn key_offset(&self, for_key: KeyType) -> usize {
        match for_key {
            KeyType::Sign => 40,
            KeyType::Dec => 20,
            KeyType::Aut => 0,
        }
    }
}

/// Life cycle status byte, see § 6
#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub enum LifeCycle {
    Initialization = 0x03,
    Operational = 0x05,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    // Persistent state may not be loaded, or may error when loaded
    pub persistent: Option<Persistent>,
    pub volatile: Volatile,
}

impl State {
    /// Loads the persistent state from flash
    pub fn load<'s, T: crate::card::Client>(
        &'s mut self,
        client: &mut T,
        storage: Location,
    ) -> Result<LoadedState<'s>, Error> {
        // This would be the correct way but it doesn't compile because of
        // https://github.com/rust-lang/rust/issues/47680 (I think)
        //if let Some(persistent) = self.persistent.as_mut() {
        //    Ok(LoadedState {
        //        persistent,
        //        volatile: &mut self.volatile,
        //    })
        //} else {
        //    Ok(LoadedState {
        //        persistent: self.persistent.insert(Persistent::load(client)?),
        //        volatile: &mut self.volatile,
        //    })
        //}

        if self.persistent.is_none() {
            self.persistent = Some(Persistent::load(client, storage)?);
        }

        #[allow(clippy::unwrap_used)]
        Ok(LoadedState {
            persistent: self.persistent.as_mut().unwrap(),
            volatile: &mut self.volatile,
        })
    }

    const LIFECYCLE_PATH: &'static Path = path!("lifecycle.empty");
    fn lifecycle_path() -> PathBuf {
        PathBuf::from(Self::LIFECYCLE_PATH)
    }
    pub fn lifecycle<T: crate::card::Client>(client: &mut T, storage: Location) -> LifeCycle {
        match try_syscall!(client.entry_metadata(storage, Self::lifecycle_path())) {
            Ok(Metadata { metadata: Some(_) }) => LifeCycle::Initialization,
            _ => LifeCycle::Operational,
        }
    }

    pub fn terminate_df<T: crate::card::Client>(
        client: &mut T,
        storage: Location,
    ) -> Result<(), Status> {
        try_syscall!(client.write_file(storage, Self::lifecycle_path(), Bytes::new(), None,))
            .map(|_| {})
            .map_err(|_err| {
                error!("Failed to write lifecycle: {_err:?}");
                Status::UnspecifiedPersistentExecutionError
            })
    }

    pub fn activate_file<T: crate::card::Client>(
        client: &mut T,
        storage: Location,
    ) -> Result<(), Status> {
        try_syscall!(client.remove_file(storage, Self::lifecycle_path(),)).ok();
        // Errors can happen because of the removal of all files before the call to activate_file
        // so they are silenced
        Ok(())
    }
}

#[derive(Debug)]
pub struct LoadedState<'s> {
    pub persistent: &'s mut Persistent,
    pub volatile: &'s mut Volatile,
}

impl LoadedState<'_> {
    /// Lend the state
    ///
    /// The resulting `LoadedState` has a shorter lifetime than the original one, meaning that it
    /// can be passed by value to other functions and the original state can then be used again
    pub fn lend(&mut self) -> LoadedState<'_> {
        LoadedState {
            persistent: self.persistent,
            volatile: self.volatile,
        }
    }

    pub fn verify_pin<T: crate::card::Client>(
        &mut self,
        client: &mut T,
        storage: Location,
        value: &[u8],
        password: PasswordMode,
    ) -> Result<(), Error> {
        let pin = Bytes::try_from(value).map_err(|_| {
            warn!("Attempt to verify pin that is too long");
            Error::InvalidPin
        })?;
        let key_exists = match password {
            PasswordMode::Pw1Sign | PasswordMode::Pw1Other => self.volatile.user_kek(),
            PasswordMode::Pw3 => self.volatile.admin_kek(),
        };
        let pin_id: Password = password.into();

        let checked_key = if let Some(k) = key_exists {
            // If the pin key is alraedy available, don't derive it again to save memory
            let res = try_syscall!(client.check_pin(pin_id, pin.clone())).map_err(|_err| {
                error!("Failed to verify pin: {:?}", _err);
                Error::InvalidPin
            })?;

            if !res.success {
                return Err(Error::InvalidPin);
            }
            k
        } else {
            try_syscall!(client.get_pin_key(pin_id, pin.clone()))
                .map_err(|_err| {
                    error!("Failed to verify pin: {:?}", _err);
                    Error::InvalidPin
                })?
                .result
                .ok_or(Error::InvalidPin)?
        };

        match password {
            PasswordMode::Pw1Sign => self.volatile.user.verify_sign(checked_key),
            PasswordMode::Pw1Other => self.volatile.user.verify_other(checked_key),
            PasswordMode::Pw3 => self.volatile.admin.verify(checked_key),
        };

        // Reset the pin length in case it was incorrect due to the lack of atomicity of operations.
        self.persistent
            .set_pin_len(client, storage, pin.len(), pin_id)?;
        Ok(())
    }

    pub fn check_pin<T: crate::card::Client>(
        &mut self,
        client: &mut T,
        value: &[u8],
        password: Password,
    ) -> Result<KeyId, Error> {
        let pin = Bytes::try_from(value).map_err(|_| {
            warn!("Attempt to verify pin that is too long");
            Error::InvalidPin
        })?;
        try_syscall!(client.get_pin_key(password, pin))
            .map_err(|_err| Error::InvalidPin)?
            .result
            .ok_or(Error::InvalidPin)
    }

    fn get_user_key<T: crate::card::Client>(
        &mut self,
        client: &mut T,
        storage: Location,
    ) -> Result<KeyId, Error> {
        let admin_key = self.volatile.admin_kek().ok_or(Error::InvalidPin)?;
        match load_if_exists(client, storage, &PathBuf::from(ADMIN_USER_KEY_BACKUP))? {
            Some(user_wrapped) => {
                let user_key = try_syscall!(client.unwrap_key(
                    Mechanism::Chacha8Poly1305,
                    admin_key,
                    user_wrapped,
                    ADMIN_USER_KEY_BACKUP.as_str().as_bytes(),
                    &[],
                    StorageAttributes::new().set_persistence(Location::Volatile)
                ))
                .map_err(|_err| {
                    error!("Failed to unwrap backup user key: {:?}", _err);
                    Error::Internal
                })?
                .key
                .ok_or_else(|| {
                    error!("Failed to unwrap backup user key");
                    Error::Internal
                })?;
                Ok(user_key)
            }
            None if self.persistent.migration_source.is_some() => {
                // Compatibility PW1 and PW3 share a stable KEK, but callers own
                // and delete the returned handle; never return the cached handle.
                let wrapped = try_syscall!(client.wrap_key(
                    Mechanism::Chacha8Poly1305,
                    admin_key,
                    admin_key,
                    ADMIN_USER_KEY_BACKUP.as_str().as_bytes(),
                    None,
                ))
                .map_err(|_| Error::Internal)?
                .wrapped_key;
                try_syscall!(client.unwrap_key(
                    Mechanism::Chacha8Poly1305,
                    admin_key,
                    wrapped,
                    ADMIN_USER_KEY_BACKUP.as_str().as_bytes(),
                    &[],
                    StorageAttributes::new().set_persistence(Location::Volatile),
                ))
                .map_err(|_| Error::Internal)?
                .key
                .ok_or(Error::Internal)
            }
            None => Err(Error::Loading),
        }
    }

    fn get_user_key_from_rc<T: crate::card::Client>(
        &mut self,
        client: &mut T,
        storage: Location,
        rc_key: KeyId,
    ) -> Result<KeyId, Error> {
        let user_wrapped = match load_if_exists(client, storage, &PathBuf::from(RC_USER_KEY_BACKUP))? {
            Some(wrapped) => wrapped,
            None if self.persistent.migration_source.is_some() => {
                // Captured RC authentication returns native_openpgp_wrapping_key
                // from the migration authority, not a native RC credential. Clone
                // that authenticated KEK into an independently owned user handle.
                try_syscall!(client.wrap_key(
                    Mechanism::Chacha8Poly1305,
                    rc_key,
                    rc_key,
                    RC_USER_KEY_BACKUP.as_str().as_bytes(),
                    None,
                ))
                .map_err(|_| Error::Internal)?
                .wrapped_key
            }
            None => return Err(Error::Loading),
        };
        let user_key = try_syscall!(client.unwrap_key(
            Mechanism::Chacha8Poly1305,
            rc_key,
            user_wrapped,
            RC_USER_KEY_BACKUP.as_str().as_bytes(),
            &[],
            StorageAttributes::new().set_persistence(Location::Volatile)
        ))
        .map_err(|_err| {
            error!("Failed to unwrap backup key from rc: {:?}", _err);
            Error::Internal
        })?
        .key
        .ok_or_else(|| {
            error!("Failed to unwrap backup key from rc");
            Error::Internal
        })?;
        Ok(user_key)
    }

    pub fn reset_user_code_with_pw3<T: crate::card::Client>(
        &mut self,
        client: &mut T,
        storage: Location,
        new_value: &[u8],
    ) -> Result<(), Error> {
        let user_key = self.get_user_key(client, storage)?;
        let new_pin = Bytes::try_from(new_value).map_err(|_| Error::InvalidPin)?;
        syscall!(client.set_pin_with_key(Password::Pw1, new_pin, Some(3), user_key));
        // US-912: RRC replaces PW1, so the factory-default gate must track the
        // new PIN — resetting to the shipped default re-arms the gate even
        // though `change_reference_data` was never used. (PW3 is untouched
        // here and is not part of the gate change.)
        self.persistent.pw1_changed = Some(new_value != DEFAULT_USER_PIN);
        self.persistent
            .set_pin_len(client, storage, new_value.len(), Password::Pw1)?;
        syscall!(client.delete(user_key));
        Ok(())
    }

    pub fn reset_user_code_with_rc<T: crate::card::Client>(
        &mut self,
        client: &mut T,
        storage: Location,
        new_value: &[u8],
        rc_key: KeyId,
    ) -> Result<(), Error> {
        let user_key = self.get_user_key_from_rc(client, storage, rc_key)?;
        let new_pin = Bytes::try_from(new_value).map_err(|_| Error::InvalidPin)?;
        syscall!(client.set_pin_with_key(Password::Pw1, new_pin, Some(3), user_key));
        // US-912: the RC path is the low-trust recovery path — an RC holder
        // can set PW1 back to the factory default, so the gate must re-arm
        // exactly as in `reset_user_code_with_pw3` / `change_reference_data`.
        self.persistent.pw1_changed = Some(new_value != DEFAULT_USER_PIN);
        self.persistent
            .set_pin_len(client, storage, new_value.len(), Password::Pw1)?;
        syscall!(client.delete(user_key));
        Ok(())
    }

    pub fn set_reset_code<T: crate::card::Client>(
        &mut self,
        client: &mut T,
        storage: Location,
        new_value: &[u8],
    ) -> Result<(), Error> {
        let new_pin = Bytes::try_from(new_value).map_err(|_| Error::InvalidPin)?;
        syscall!(client.set_pin(Password::ResetCode, new_pin.clone(), Some(3), true));
        self.persistent
            .set_pin_len(client, storage, new_pin.len(), Password::ResetCode)?;
        #[allow(clippy::expect_used)]
        let rc_key = syscall!(client.get_pin_key(Password::ResetCode, new_pin))
            .result
            .expect("New pin should not fail");

        let user_key = self.get_user_key(client, storage)?;
        let wrapped_user_key = syscall!(client.wrap_key(
            Mechanism::Chacha8Poly1305,
            rc_key,
            user_key,
            RC_USER_KEY_BACKUP.as_str().as_bytes(),
            None,
        ))
        .wrapped_key;
        syscall!(client.write_file(
            storage,
            PathBuf::from(RC_USER_KEY_BACKUP),
            wrapped_user_key,
            None
        ));
        syscall!(client.delete(user_key));
        syscall!(client.delete(rc_key));

        Ok(())
    }

    pub fn set_aes_key<T: crate::card::Client>(
        &mut self,
        new: KeyId,
        client: &mut T,
        storage: Location,
    ) -> Result<(), Error> {
        self.volatile.user.0.clear_aes_cached(client);
        let user_kek = self.get_user_key(client, storage)?;
        syscall!(client.wrap_key_to_file(
            Mechanism::Chacha8Poly1305,
            user_kek,
            new,
            PathBuf::from(AES_KEY_PATH),
            storage,
            AES_KEY_PATH.as_str().as_bytes()
        ));
        syscall!(client.delete(new));
        Ok(())
    }

    /// New contains (private key, (public key, KeyOrigin))
    pub fn set_key<T: crate::card::Client>(
        &mut self,
        ty: KeyType,
        new: Option<(KeyId, (KeyId, KeyOrigin))>,
        client: &mut T,
        storage: Location,
    ) -> Result<(), Error> {
        let path_str = ty.path();
        let origin = self.persistent.key_data_mut(ty);
        let path = PathBuf::from(path_str);

        let (new_id, new_origin) = match (new, &origin) {
            (None, Some((k, _))) => {
                // Copying for borrow checker
                let pub_key = *k;
                *origin = None;
                // fapico2: removal must also clear the key's fingerprint and
                // generation-date slots (spec §4.4.3), as `remove_key` does.
                self.persistent
                    .fingerprints
                    .key_part_mut(ty)
                    .copy_from_slice(&[0; 20]);
                self.persistent
                    .keygen_dates
                    .key_part_mut(ty)
                    .copy_from_slice(&[0; 4]);
                self.persistent.save(client, storage)?;
                try_syscall!(client.remove_file(storage, path)).ok();
                try_syscall!(client.delete(pub_key)).map_err(|_err| {
                    error!("Failed to delete key");
                    Error::Saving
                })?;
                return Ok(());
            }
            (None, None) => return Ok(()),

            // In this case we want to avoid storing old information with a new key, or vice-versa
            (Some((new_id, new_origin)), Some((k, _))) => {
                // Copying for borrow checker
                let pub_key = *k;
                *origin = None;
                self.persistent.save(client, storage)?;
                try_syscall!(client.delete(pub_key)).map_err(|_err| {
                    error!("Failed to delete key");
                    Error::Saving
                })?;
                (new_id, new_origin)
            }
            (Some((new_id, new_origin)), None) => (new_id, new_origin),
        };

        self.volatile.user.0.clear_cached(client, ty);

        let user_kek = self.get_user_key(client, storage)?;

        syscall!(client.wrap_key_to_file(
            Mechanism::Chacha8Poly1305,
            user_kek,
            new_id,
            path,
            storage,
            path_str.as_str().as_bytes()
        ));

        let private_to_change = match ty {
            KeyType::Sign => &mut self.persistent.signing_private_to_delete,
            KeyType::Dec => &mut self.persistent.confidentiality_private_to_delete,
            KeyType::Aut => &mut self.persistent.aut_private_to_delete,
        };

        // Delete the old private key metadata (that was only ever deleted with `clear`)
        if let Some(id) = private_to_change.take() {
            syscall!(client.delete(id));
        }

        *private_to_change = Some(new_id);
        syscall!(client.clear(new_id));
        syscall!(client.delete(user_kek));
        *self.persistent.key_data_mut(ty) = Some(new_origin);

        // fapico2 (US-972): a new key must never inherit the fingerprint of
        // the one it replaces. The slot is *cleared* rather than filled here
        // because a v4 fingerprint hashes the creation timestamp, and the
        // card does not have it yet at GENERATE — measured on hardware, the
        // host supplies the date afterwards with `PUT DATA CE/CF/D0`. Until
        // then "none" is the only honest value; a carried-over fingerprint is
        // the stale-but-believed answer US-972 exists to remove. The slot is
        // recomputed in `set_keygen_date`, the moment the date arrives.
        self.persistent
            .fingerprints
            .key_part_mut(ty)
            .copy_from_slice(&[0; 20]);

        if matches!(ty, KeyType::Sign) {
            self.persistent.sign_count = 0;
        }
        self.persistent.save(client, storage)?;
        Ok(())
    }

    /// Avoid having too many RSA keys in volatile storage
    fn limit_cache_size(
        client: &mut impl crate::card::Client,
        keys: &mut [(&mut Option<KeyId>, bool)],
    ) {
        for key in keys
            .iter_mut()
            .filter_map(|(k, is_rsa)| if *is_rsa { Some(k.take()) } else { None })
            .flatten()
        {
            syscall!(client.clear(key));
        }
    }

    /// Returns the requested key
    pub fn key_id(
        &mut self,
        client: &mut impl crate::card::Client,
        key: KeyType,
        storage: Location,
    ) -> Result<KeyId, Status> {
        use KeyType as K;
        use UserVerifiedInner as V;

        if self.persistent.public_key_id(key).is_none() {
            return Err(Status::KeyReferenceNotFound);
        }

        // Self::limit_cache_size is there to avoid having multiple keys in the volatile storage.
        // RSA keys can be up 2.3KB out of the total 8KiB.
        // With 3 keys this gets us very close to being full, especially with the added overhead of littlefs metadata
        //
        // Therefore we never cache more than 1 key
        match (&mut self.volatile.user.0, key) {
            (V::None, _) => Err(Status::SecurityStatusNotSatisfied),
            (V::Sign(user_kek, cache) | V::OtherAndSign(user_kek, cache), K::Sign) => {
                Self::limit_cache_size(
                    client,
                    &mut [
                        (&mut cache.dec, self.persistent.dec_alg.is_rsa()),
                        (&mut cache.aut, self.persistent.aut_alg.is_rsa()),
                    ],
                );
                Volatile::load_or_get_key(
                    client,
                    *user_kek,
                    &mut cache.sign,
                    SIGNING_KEY_PATH,
                    storage,
                )
            }
            (V::Other(user_kek, cache) | V::OtherAndSign(user_kek, cache), K::Aut) => {
                Self::limit_cache_size(
                    client,
                    &mut [
                        (&mut cache.sign, self.persistent.sign_alg.is_rsa()),
                        (&mut cache.dec, self.persistent.dec_alg.is_rsa()),
                    ],
                );
                Volatile::load_or_get_key(client, *user_kek, &mut cache.aut, AUTH_KEY_PATH, storage)
            }
            (V::Other(user_kek, cache) | V::OtherAndSign(user_kek, cache), K::Dec) => {
                Self::limit_cache_size(
                    client,
                    &mut [
                        (&mut cache.sign, self.persistent.sign_alg.is_rsa()),
                        (&mut cache.aut, self.persistent.aut_alg.is_rsa()),
                    ],
                );
                Volatile::load_or_get_key(client, *user_kek, &mut cache.dec, DEC_KEY_PATH, storage)
            }
            _ => Err(Status::SecurityStatusNotSatisfied),
        }
    }
}

enum_u8! {
    #[derive(Clone, Debug, Eq, PartialEq, Copy, Deserialize_repr, Serialize_repr, Default)]
    pub enum Sex {
        #[default]
        NotKnown = 0x30,
        Male = 0x31,
        Female = 0x32,
        NotApplicable = 0x39,
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum KeyOrigin {
    /// From GENERATE ASYMETRIC KEYPAIR
    Generated,
    Imported,
}

/// Authenticated source signing identity supplied by the migration adapter.
/// The point is the 64-byte raw P-256 public point (without SEC1's 04 byte).
#[derive(Clone, Copy, Debug)]
pub struct MigrationSigningIdentity<'a> {
    pub point: &'a [u8; 64],
    pub fingerprint: &'a [u8; 20],
    pub date: &'a [u8; 4],
    pub count: u32,
}

/// Native cardholder and unencrypted private DOs from an authenticated capture.
#[derive(Clone, Copy, Debug, Default)]
pub struct MigrationProfile<'a> {
    /// ISO language pairs (at most eight bytes).
    pub language: &'a [u8],
    /// ISO sex byte: ASCII 0, 1, 2 or 9; absent means unknown.
    pub sex: Option<u8>,
    /// Unencrypted private-use DO 0101.
    pub private_use_1: Option<&'a [u8]>,
    /// Unencrypted private-use DO 0102.
    pub private_use_2: Option<&'a [u8]>,
}

/// Authenticated X25519 decryption identity supplied by the migration adapter.
#[derive(Clone, Copy, Debug)]
pub struct MigrationDecryptionIdentity<'a> {
    /// Raw 32-byte Montgomery public key.
    pub public: &'a [u8; 32],
    /// OpenPGP decryption-key fingerprint.
    pub fingerprint: &'a [u8; 20],
    /// OpenPGP decryption-key generation date.
    pub date: &'a [u8; 4],
}

/// Authenticated P-256 authentication identity supplied by the migration adapter.
#[derive(Clone, Copy, Debug)]
pub struct MigrationAuthenticationIdentity<'a> {
    /// Raw 64-byte P-256 point, without SEC1's 04 byte.
    pub point: &'a [u8; 64],
    /// OpenPGP authentication-key fingerprint.
    pub fingerprint: &'a [u8; 20],
    /// OpenPGP authentication-key generation date.
    pub date: &'a [u8; 4],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Persistent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    migration_source: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    migration_profile_version: Option<u8>,
    pw1_valid_multiple: bool,
    /// US-912: PW1 has been changed away from the factory default. `None`
    /// marks a pre-gate snapshot whose flag is derived from the stored PIN
    /// when the state is loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pw1_changed: Option<bool>,
    /// US-912: PW3 has been changed away from the factory default. `None`
    /// marks a pre-gate snapshot whose flag is derived from the stored PIN
    /// when the state is loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pw3_changed: Option<bool>,
    user_pin_len: u8,
    admin_pin_len: u8,
    reset_code_pin_len: Option<u8>,
    /// (public_key, origin)
    signing_key: Option<(KeyId, KeyOrigin)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_private_to_delete: Option<KeyId>,
    /// (public_key, origin)
    confidentiality_key: Option<(KeyId, KeyOrigin)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confidentiality_private_to_delete: Option<KeyId>,
    /// (public_key, origin)
    aut_key: Option<(KeyId, KeyOrigin)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aut_private_to_delete: Option<KeyId>,
    sign_alg: SignatureAlgorithm,
    dec_alg: DecryptionAlgorithm,
    aut_alg: AuthenticationAlgorithm,
    fingerprints: Fingerprints,
    ca_fingerprints: CaFingerprints,
    keygen_dates: KeyGenDates,

    cardholder_name: Bytes<39>,
    cardholder_sex: Sex,
    language_preferences: Bytes<8>,
    sign_count: u32,
    uif_sign: Uif,
    uif_dec: Uif,
    uif_aut: Uif,
}

/// User pin key wrapped by the resetting code key
const RC_USER_KEY_BACKUP: &Path = path!("rc-user-pin-key.bin");
/// User pin key wrapped by the admin key
const ADMIN_USER_KEY_BACKUP: &Path = path!("admin-user-pin-key.bin");

impl Persistent {
    const FILENAME: &'static Path = path!("persistent-state.cbor");

    // § 4.3
    const MAX_RETRIES: u8 = 3;

    #[allow(clippy::unwrap_used)]
    fn default() -> Self {
        Self {
            migration_source: None,
            migration_profile_version: None,
            reset_code_pin_len: None,
            pw1_valid_multiple: false,
            pw1_changed: Some(false),
            pw3_changed: Some(false),
            admin_pin_len: DEFAULT_ADMIN_PIN.len() as u8,
            user_pin_len: DEFAULT_USER_PIN.len() as u8,
            cardholder_name: Bytes::new(),
            cardholder_sex: Sex::default(),
            language_preferences: Bytes::new(),
            sign_count: 0,
            signing_key: None,
            signing_private_to_delete: None,
            confidentiality_key: None,
            confidentiality_private_to_delete: None,
            aut_key: None,
            aut_private_to_delete: None,
            sign_alg: SignatureAlgorithm::default(),
            dec_alg: DecryptionAlgorithm::default(),
            aut_alg: AuthenticationAlgorithm::default(),
            fingerprints: Fingerprints::default(),
            ca_fingerprints: CaFingerprints::default(),
            keygen_dates: KeyGenDates::default(),
            uif_sign: Uif::Disabled,
            uif_dec: Uif::Disabled,
            uif_aut: Uif::Disabled,
        }
    }

    /// Initialize public migration state without invoking factory PIN setup.
    /// Existing state is accepted only for an identical migration source, and
    /// is never rewritten. Validation and occupied checks precede every write.
    pub(crate) fn restore_metadata<T: crate::card::Client>(
        client: &mut T,
        storage: Location,
        source: [u8; 32],
        name: &[u8],
        user_pin_len: u8,
        admin_pin_len: u8,
        reset_code_pin_len: Option<u8>,
        signing: Option<MigrationSigningIdentity<'_>>,
        decryption: Option<MigrationDecryptionIdentity<'_>>,
        authentication: Option<MigrationAuthenticationIdentity<'_>>,
        profile: MigrationProfile<'_>,
    ) -> Result<(), Error> {
        let sex = Sex::try_from(profile.sex.unwrap_or(b'0')).map_err(|_| Error::Loading)?;
        // Beyond one chunked Message the backend stages through extra writes
        // whose failure can strand earlier DOs; admit at most one full chunk
        // per DO (migration-only limit; native PUT DATA keeps its own bound).
        if name.len() > 39 || profile.language.len() > 8 || profile.language.len() % 2 != 0
            || profile.private_use_1.is_some_and(|v| v.len() > 1024)
            || profile.private_use_2.is_some_and(|v| v.len() > 1024) {
            return Err(Error::Loading);
        }
        if let Some(data) = load_if_exists(client, storage, &Self::path())? {
            let existing: Self = cbor_smol::cbor_deserialize(&data)
                .map_err(|_| Error::Loading)?;
            return if existing.migration_source == Some(source) {
                // Live DOs belong to the user after installation. Only durable
                // source-bound evidence may authorize a read-only resume.
                match existing.migration_profile_version {
                    Some(1) => Ok(()),
                    None if profile.language.is_empty()
                        && profile.sex.is_none()
                        && profile.private_use_1.is_none()
                        && profile.private_use_2.is_none() => Ok(()),
                    _ => Err(Error::Loading),
                }
            } else {
                Err(Error::Loading)
            };
        }
        for password in [Password::Pw1, Password::Pw3, Password::ResetCode] {
            if try_syscall!(client.has_pin(password)).map_err(|_| Error::Loading)?.has_pin {
                return Err(Error::Loading);
            }
        }
        for path in [SIGNING_KEY_PATH, DEC_KEY_PATH, AUTH_KEY_PATH, AES_KEY_PATH,
            ADMIN_USER_KEY_BACKUP, RC_USER_KEY_BACKUP]
        {
            if load_if_exists(client, storage, &PathBuf::from(path))?.is_some() {
                return Err(Error::Loading);
            }
        }
        if let Some(rc_len) = reset_code_pin_len {
            if !(MIN_LENGTH_RESET_CODE..=MAX_PIN_LENGTH).contains(&(rc_len as usize)) {
                return Err(Error::InvalidPin);
            }
        }
        if !(MIN_LENGTH_USER_PIN..=MAX_PIN_LENGTH).contains(&(user_pin_len as usize))
            || !(MIN_LENGTH_ADMIN_PIN..=MAX_PIN_LENGTH).contains(&(admin_pin_len as usize))
        {
            return Err(Error::InvalidPin);
        }
        let mut state = Self::default();
        state.cardholder_name = Bytes::try_from(name).map_err(|_| Error::Loading)?;
        state.language_preferences = Bytes::try_from(profile.language).map_err(|_| Error::Loading)?;
        state.cardholder_sex = sex;
        state.user_pin_len = user_pin_len;
        state.admin_pin_len = admin_pin_len;
        // The ResetCode length is a public DO fact; its verification stays
        // migration-owned (see the RC dispatch branch). Without a captured RC
        // verifier there is no RC credential to split against.
        state.reset_code_pin_len = reset_code_pin_len;
        state.migration_source = Some(source);
        // US-912: migration PINs are user-supplied, never the factory
        // defaults — the factory-PIN gate does not apply to migrated cards.
        // [restore_migration_pin] additionally derives the PW1 flag from the
        // PIN actually stored, so a factory-default migration PIN keeps the
        // gate armed.
        state.pw1_changed = Some(true);
        state.pw3_changed = Some(true);
        if let Some(signing) = signing {
            if signing.count > 0x00ff_ffff {
                return Err(Error::Loading);
            }
            let public = try_syscall!(client.deserialize_key(
                Mechanism::P256,
                signing.point,
                trussed_core::types::KeySerialization::Raw,
                StorageAttributes::new().set_persistence(storage),
            )).map_err(|_| Error::Loading)?.key;
            state.signing_key = Some((public, KeyOrigin::Imported));
            state.sign_alg = SignatureAlgorithm::EcDsaP256;
            state.fingerprints.0[..20].copy_from_slice(signing.fingerprint);
            state.keygen_dates.0[..4].copy_from_slice(signing.date);
            state.sign_count = signing.count;
        }
        if let Some(decryption) = decryption {
            let public = try_syscall!(client.deserialize_key(
                Mechanism::X255,
                decryption.public,
                trussed_core::types::KeySerialization::Raw,
                StorageAttributes::new().set_persistence(storage),
            )).map_err(|_| Error::Loading)?.key;
            state.confidentiality_key = Some((public, KeyOrigin::Imported));
            state.dec_alg = DecryptionAlgorithm::X255;
            state.fingerprints.key_part_mut(KeyType::Dec).copy_from_slice(decryption.fingerprint);
            state.keygen_dates.key_part_mut(KeyType::Dec).copy_from_slice(decryption.date);
        }
        if let Some(authentication) = authentication {
            let public = try_syscall!(client.deserialize_key(
                Mechanism::P256,
                authentication.point,
                trussed_core::types::KeySerialization::Raw,
                StorageAttributes::new().set_persistence(storage),
            )).map_err(|_| Error::Loading)?.key;
            state.aut_key = Some((public, KeyOrigin::Imported));
            state.aut_alg = AuthenticationAlgorithm::EcDsaP256;
            state.fingerprints.key_part_mut(KeyType::Aut).copy_from_slice(authentication.fingerprint);
            state.keygen_dates.key_part_mut(KeyType::Aut).copy_from_slice(authentication.date);
        }
        for (object, value) in [(ArbitraryDO::PrivateUse1, profile.private_use_1),
            (ArbitraryDO::PrivateUse2, profile.private_use_2)] {
            if let Some(value) = value { object.save(client, storage, value, None)?; }
        }
        state.migration_profile_version = Some(1);
        state.save(client, storage)
    }

    // Shared native derive/compare seam. On success the caller owns the
    // volatile derived handle; on refusal this helper deletes it.
    fn derive_matching_migration_public<T: crate::card::Client>(
        client: &mut T, mechanism: Mechanism, private: KeyId, expected: &[u8],
    ) -> Result<KeyId, Error> {
        let derived = try_syscall!(client.derive_key(
            mechanism, private, None,
            StorageAttributes::new().set_persistence(Location::Volatile),
        )).map_err(|_| Error::Loading)?.key;
        let actual = try_syscall!(client.serialize_key(
            mechanism, derived, trussed_core::types::KeySerialization::Raw,
        ));
        if actual.is_ok_and(|reply| reply.serialized_key.as_slice() == expected) {
            Ok(derived)
        } else {
            try_syscall!(client.delete(derived)).map_err(|_| Error::Saving)?;
            Err(Error::Loading)
        }
    }

    /// Validate captured identity using only volatile native key handles. No
    /// persistent key files or ready markers are touched, even on success.
    pub(crate) fn validate_migration_key<T: crate::card::Client>(
        client: &mut T, mechanism: Mechanism, scalar: &[u8; 32], expected: &[u8],
    ) -> Result<(), Error> {
        let private = try_syscall!(client.unsafe_inject_key(
            mechanism, scalar, Location::Volatile, trussed_core::types::KeySerialization::Raw,
        )).map_err(|_| Error::Loading)?.key;
        let result = Self::derive_matching_migration_public(client, mechanism, private, expected);
        // Attempt both deletions even if one fails.
        let derived_cleanup = match result.as_ref() {
            Ok(derived) => try_syscall!(client.delete(*derived)).map(|_| ()).map_err(|_| Error::Saving),
            Err(_) => Ok(()),
        };
        let private_cleanup = try_syscall!(client.delete(private)).map_err(|_| Error::Saving);
        derived_cleanup?;
        private_cleanup?;
        result.map(|_| ())
    }

    /// Import only into source-owned public state. The separate completion record
    /// survives later user key deletion and prevents resurrecting the old key.
    pub(crate) fn restore_migration_key<T: crate::card::Client>(
        client: &mut T,
        storage: Location,
        source: [u8; 32],
        scalar: &[u8; 32],
        wrapping_key: &[u8; 32],
        key_type: KeyType,
    ) -> Result<(), Error> {
        use trussed_core::types::KeySerialization;
        let data = load_if_exists(client, storage, &Self::path())?.ok_or(Error::Loading)?;
        let state: Self = cbor_smol::cbor_deserialize(&data).map_err(|_| Error::Loading)?;
        if state.migration_source != Some(source) {
            return Err(Error::Loading);
        }
        let (mechanism, done, algorithm_matches) = match key_type {
            KeyType::Sign => (Mechanism::P256, path!("migration-signing-ready"),
                state.sign_alg == SignatureAlgorithm::EcDsaP256),
            KeyType::Dec => (Mechanism::X255, path!("migration-decryption-ready"),
                state.dec_alg == DecryptionAlgorithm::X255),
            KeyType::Aut => (Mechanism::P256, path!("migration-authentication-ready"),
                state.aut_alg == AuthenticationAlgorithm::EcDsaP256),
        };
        let done = PathBuf::from(done);
        if let Some(record) = load_if_exists(client, storage, &done)? {
            return if record.as_slice() == source { Ok(()) } else { Err(Error::Loading) };
        }
        if !algorithm_matches { return Err(Error::Loading); }
        let key_path = key_type.path();
        let public = state.public_key_id(key_type).ok_or(Error::Loading)?;
        let expected = try_syscall!(client.serialize_key(mechanism, public, KeySerialization::Raw))
            .map_err(|_| Error::Loading)?.serialized_key;
        let mut private_id = None;
        let mut derived_id = None;
        let mut kek_id = None;
        let result = (|| {
            let private = try_syscall!(client.unsafe_inject_key(
                mechanism, scalar, Location::Volatile, KeySerialization::Raw,
            )).map_err(|_| Error::Loading)?.key;
            private_id = Some(private);
            let derived = Self::derive_matching_migration_public(client, mechanism, private, &expected)?;
            derived_id = Some(derived);
            let kek = try_syscall!(client.unsafe_inject_key(
                Mechanism::Aes256Cbc, wrapping_key, Location::Volatile, KeySerialization::Raw,
            )).map_err(|_| Error::Loading)?.key;
            kek_id = Some(kek);
            let path = PathBuf::from(key_path);
            if load_if_exists(client, storage, &path)?.is_some() {
                // Recover only an authenticated prior write, never replace an
                // occupied file. Validate its public identity before completion.
                let old = try_syscall!(client.unwrap_key_from_file(
                    Mechanism::Chacha8Poly1305, kek, path.clone(), storage,
                    Location::Volatile, key_path.as_str().as_bytes(),
                )).map_err(|_| Error::Loading)?.key.ok_or(Error::Loading)?;
                try_syscall!(client.delete(private)).map_err(|_| Error::Loading)?;
                private_id = Some(old);
                try_syscall!(client.delete(derived)).map_err(|_| Error::Loading)?;
                derived_id = None;
                let old_public = try_syscall!(client.derive_key(
                    mechanism, old, None,
                    StorageAttributes::new().set_persistence(Location::Volatile),
                )).map_err(|_| Error::Loading)?.key;
                derived_id = Some(old_public);
                let actual = try_syscall!(client.serialize_key(mechanism, old_public, KeySerialization::Raw))
                    .map_err(|_| Error::Loading)?.serialized_key;
                if actual != expected { return Err(Error::Loading); }
            } else {
                try_syscall!(client.wrap_key_to_file(
                    Mechanism::Chacha8Poly1305, kek, private, path, storage,
                    key_path.as_str().as_bytes(),
                )).map_err(|_| Error::Saving)?;
            }
            try_syscall!(client.write_file(storage, done, Bytes::from(&source), None))
                .map_err(|_| Error::Saving)?;
            Ok(())
        })();
        for key in [private_id, derived_id, kek_id].into_iter().flatten() {
            if try_syscall!(client.delete(key)).is_err() { return Err(Error::Saving); }
        }
        result
    }

    pub(crate) fn migration_pin_ready<T: crate::card::Client>(
        client: &mut T,
        storage: Location,
        source: [u8; 32],
    ) -> Result<bool, Error> {
        let data = load_if_exists(client, storage, &Self::path())?.ok_or(Error::Loading)?;
        let state: Self = cbor_smol::cbor_deserialize(&data).map_err(|_| Error::Loading)?;
        if state.migration_source != Some(source) {
            return Err(Error::Loading);
        }
        match load_if_exists(client, storage, &PathBuf::from(path!("migration-pw1-ready")))? {
            Some(record) if record.as_slice() == source => Ok(true),
            Some(_) => Err(Error::Loading),
            None => Ok(false),
        }
    }

    /// Convert only source-owned state, preserving the supplied wrapping key.
    /// An occupied native PIN without the completion record is never reset,
    /// including after interrupted conversion; recovery then fails closed.
    pub(crate) fn restore_migration_pin<T: crate::card::Client>(
        client: &mut T,
        storage: Location,
        source: [u8; 32],
        pin: &[u8],
        maximum: u8,
        wrapping_key: &[u8; 32],
    ) -> Result<(), Error> {
        if Self::migration_pin_ready(client, storage, source)? { return Ok(()); }
        let ready = load_if_exists(client, storage, &PathBuf::from(path!("migration-signing-ready")))?
            .ok_or(Error::Loading)?;
        if ready.as_slice() != source || maximum == 0 {
            return Err(Error::Loading);
        }
        for password in [Password::Pw1, Password::Pw3, Password::ResetCode] {
            if try_syscall!(client.has_pin(password)).map_err(|_| Error::Loading)?.has_pin {
                return Err(Error::Loading);
            }
        }
        let pin: trussed_auth::Pin = pin.try_into().map_err(|_| Error::InvalidPin)?;
        let key = try_syscall!(client.unsafe_inject_key(
            Mechanism::Aes256Cbc, wrapping_key, Location::Volatile,
            trussed_core::types::KeySerialization::Raw,
        )).map_err(|_| Error::Loading)?.key;
        let result = try_syscall!(client.set_pin_with_key(
            Password::Pw1,
            pin.clone(),
            Some(maximum),
            key,
        ))
        .map_err(|_| Error::Saving);
        let cleanup = try_syscall!(client.delete(key)).map_err(|_| Error::Saving);
        result?;
        cleanup?;
        // US-912: derive the PW1 gate flag from the PIN actually stored — a
        // factory-default migration PIN keeps the factory-PIN gate armed.
        let state_data =
            load_if_exists(client, storage, &Self::path())?.ok_or(Error::Loading)?;
        let mut state: Self =
            cbor_smol::cbor_deserialize(&state_data).map_err(|_| Error::Loading)?;
        state.pw1_changed = Some(&pin[..] != DEFAULT_USER_PIN);
        state.save(client, storage)?;
        try_syscall!(client.write_file(storage, PathBuf::from(path!("migration-pw1-ready")),
            Bytes::from(&source), None)).map_err(|_| Error::Saving)?;
        Ok(())
    }

    pub fn public_key_id(&self, ty: KeyType) -> Option<KeyId> {
        match ty {
            KeyType::Sign => self.signing_key.map(|(pubkey, _)| pubkey),
            KeyType::Aut => self.aut_key.map(|(pubkey, _)| pubkey),
            KeyType::Dec => self.confidentiality_key.map(|(pubkey, _)| pubkey),
        }
    }

    fn path() -> PathBuf {
        PathBuf::from(Self::FILENAME)
    }

    fn key_data_mut(&mut self, ty: KeyType) -> &mut Option<(KeyId, KeyOrigin)> {
        match ty {
            KeyType::Sign => &mut self.signing_key,
            KeyType::Aut => &mut self.aut_key,
            KeyType::Dec => &mut self.confidentiality_key,
        }
    }

    fn init_pins<T: crate::card::Client>(client: &mut T, location: Location) -> Result<(), Error> {
        #[allow(clippy::unwrap_used)]
        let default_user_pin = Bytes::try_from(DEFAULT_USER_PIN).unwrap();
        #[allow(clippy::unwrap_used)]
        let default_admin_pin = Bytes::try_from(DEFAULT_ADMIN_PIN).unwrap();

        // If PINs are already there when initializing, it likely means that the state was corrupted rather than absent.
        // In that case, we wait for the user to explicitely factory-reset the device to avoid risking loosing data.
        // See https://github.com/Nitrokey/opcard-rs/issues/165
        if syscall!(client.has_pin(Password::Pw1)).has_pin
            || syscall!(client.has_pin(Password::Pw3)).has_pin
        {
            debug!("Init pins after pins are already there");
            return Err(Error::Loading);
        }

        syscall!(client.set_pin(
            Password::Pw1,
            default_user_pin.clone(),
            Some(Self::MAX_RETRIES),
            true,
        ));
        syscall!(client.set_pin(
            Password::Pw3,
            default_admin_pin.clone(),
            Some(Self::MAX_RETRIES),
            true,
        ));
        #[allow(clippy::expect_used)]
        let user_key = syscall!(client.get_pin_key(Password::Pw1, default_user_pin))
            .result
            .expect("Default pin should work after initialization");
        #[allow(clippy::expect_used)]
        let admin_key = syscall!(client.get_pin_key(Password::Pw3, default_admin_pin))
            .result
            .expect("Default pin should work after initialization");

        let backup = syscall!(client.wrap_key(
            Mechanism::Chacha8Poly1305,
            admin_key,
            user_key,
            ADMIN_USER_KEY_BACKUP.as_str().as_bytes(),
            None,
        ))
        .wrapped_key;
        syscall!(client.write_file(location, PathBuf::from(ADMIN_USER_KEY_BACKUP), backup, None));

        // Clean up memory
        syscall!(client.delete(user_key));
        syscall!(client.delete(admin_key));
        Ok(())
    }
    /// US-912: probe whether `password` still holds the factory default PIN.
    /// `get_pin_key` is an AEAD unwrap against the stored PIN — a mismatch
    /// yields `Ok(None)` and burns one retry counter step — so the derivation
    /// is deferred (fail closed) while fewer than two retries remain, and a
    /// derived handle is deleted immediately. The result is persisted by the
    /// caller, so the burn happens at most once per PIN; on a failed probe
    /// the flag stays `None` and derivation is retried on the next load.
    fn probe_default_pin<T: crate::card::Client>(
        client: &mut T,
        password: Password,
        default_pin: &[u8],
    ) -> Option<bool> {
        // Fail closed: do not risk blocking the card for the sake of a probe.
        let retries = try_syscall!(client.pin_retries(password))
            .map(|r| r.retries.unwrap_or_default())
            .unwrap_or(0);
        if retries < 2 {
            return None;
        }
        let default_pin = Bytes::try_from(default_pin).ok()?;
        match try_syscall!(client.get_pin_key(password, default_pin)) {
            Ok(reply) => {
                if let Some(key) = reply.result {
                    syscall!(client.delete(key));
                    Some(false)
                } else {
                    Some(true)
                }
            }
            Err(_err) => None,
        }
    }

    pub fn load<T: crate::card::Client>(client: &mut T, storage: Location) -> Result<Self, Error> {
        if let Some(data) = load_if_exists(client, storage, &Self::path())? {
            let mut state: Self = cbor_smol::cbor_deserialize(&data).map_err(|_err| {
                error!("failed to deserialize persistent state: {_err}");
                Error::Loading
            })?;
            // US-912: pre-gate snapshots carry no changed flags; derive them
            // from the PINs actually stored so a personalized legacy card is
            // never gated and a factory card is never freed.
            if state.pw1_changed.is_none() || state.pw3_changed.is_none() {
                state.pw1_changed = state.pw1_changed
                    .or_else(|| Self::probe_default_pin(client, Password::Pw1, DEFAULT_USER_PIN));
                state.pw3_changed = state.pw3_changed
                    .or_else(|| Self::probe_default_pin(client, Password::Pw3, DEFAULT_ADMIN_PIN));
                state.save(client, storage)?;
            }
            // US-962 (I1): restore the S-723 "legacy RSA defaults" scrub that
            // S-724 deleted. The comment S-724 left behind asserted that
            // "GENERATE on it works" — it does not. Measured on the RP2350,
            // on-card RSA-2048 GENERATE runs into a PC/SC transaction timeout
            // (`0x80100016`) after ~1750 s, while X25519 returns `9000` in
            // 0.09 s (docs/tasks/known-gate-divergences.md).
            //
            // That makes this state a *trap*, not a customization: a card
            // holding `C1/C2/C3 = RSA-2048` with no keys — the C firmware
            // leaves exactly this, and so does any S-724-era flash — still
            // passes the fail-closed allow-list (`ensure_alg_allowed`,
            // data.rs: `RSA_2048` is in `allowed_generation`), so the host
            // reads the capability as available, `gpg --card-edit generate`
            // blocks for about half an hour, and the only escape is a flash
            // erase that destroys card state. The card advertises something
            // it cannot deliver.
            //
            // The scrub removes the wedge *without* withdrawing RSA from the
            // allow-list: an operator can still select RSA at run time, and a
            // card that has a key is never touched (the guard below requires
            // all three key slots empty), so no working key is ever
            // reinterpreted.
            //
            // US-964: the guard also required a zero signature counter, and
            // that clause left a reachable wedge. `set_sign_alg` calls
            // `delete_key(KeyType::Sign, …)` *before* storing the new
            // attribute, and `delete_key` does not touch `sign_count` — the
            // only `sign_count = 0` write is in `set_key`, which runs on
            // GENERATE/PUT KEY, not on the attribute PUT. So the ordinary
            // `gpg --card-edit` sequence — generate an Ed25519 key, sign once
            // (`sign_count = 1`), then `key-attr` to set C1/C2/C3 to RSA-2048
            // — deletes all three keys, leaves the counter at 1, and
            // power-cycles straight back into the state this scrub exists to
            // remove. The three-empty-slots condition is both necessary and
            // sufficient: with no key in any slot there is nothing to
            // reinterpret, and a card that holds a key is still left alone.
            // `apps/openpgp/tests/rsa_attr_scrub.rs` pins both halves
            // (`signed_card_..._is_scrubbed_on_reflash` and
            // `rsa_attributes_with_a_key_survive_a_reflash`).
            //
            // The revert is written back to flash, unlike S-723's version:
            // without the save, the state on the device would still say
            // RSA-2048 and every subsequent reflash would re-wedge the card.
            // The save only happens when the scrub actually changed
            // something, so no unrelated card pays an extra flash write per
            // boot.
            if state.signing_key.is_none()
                && state.confidentiality_key.is_none()
                && state.aut_key.is_none()
                && state.sign_alg == SignatureAlgorithm::Rsa2048
                && state.dec_alg == DecryptionAlgorithm::Rsa2048
                && state.aut_alg == AuthenticationAlgorithm::Rsa2048
            {
                state.sign_alg = SignatureAlgorithm::default();
                state.dec_alg = DecryptionAlgorithm::default();
                state.aut_alg = AuthenticationAlgorithm::default();
                state.save(client, storage)?;
            }
            Ok(state)
        } else {
            Self::init_pins(client, storage)?;
            let this = Self::default();
            this.save(client, storage)?;
            Ok(this)
        }
    }

    pub fn save<T: crate::card::Client>(
        &self,
        client: &mut T,
        storage: Location,
    ) -> Result<(), Error> {
        let mut msg = Message::new();
        cbor_smol::cbor_serialize_to(&self, &mut msg).map_err(|_err| {
            error!("Failed to serialize: {_err}");
            Error::Saving
        })?;
        try_syscall!(client.write_file(storage, Self::path(), msg, None)).map_err(|_err| {
            error!("Failed to store data: {_err:?}");
            Error::Saving
        })?;
        Ok(())
    }

    /// Report migration authentication state without treating missing or unreadable
    /// credentials as an exhausted retry counter. Keep native-card behavior intact.
    pub(crate) fn verification_status<T: crate::card::Client>(
        &self,
        client: &mut T,
        password: Password,
    ) -> Status {
        if self.migration_source.is_none() {
            return Status::RemainingRetries(self.remaining_tries(client, password));
        }
        match try_syscall!(client.pin_retries(password)) {
            Ok(reply) => match reply.retries {
                Some(0) => Status::OperationBlocked,
                Some(remaining) => Status::RemainingRetries(remaining),
                None => Status::ConditionsOfUseNotSatisfied,
            },
            Err(trussed_core::Error::NoSuchKey) => Status::ConditionsOfUseNotSatisfied,
            Err(_) => Status::UnspecifiedPersistentExecutionError,
        }
    }

    pub fn remaining_tries<T: crate::card::Client>(
        &self,
        client: &mut T,
        password: Password,
    ) -> u8 {
        try_syscall!(client.pin_retries(password))
            .map(|r| r.retries.unwrap_or_default())
            .unwrap_or(0)
    }

    pub fn is_locked<T: crate::card::Client>(&self, client: &mut T, password: Password) -> bool {
        self.remaining_tries(client, password) == 0
    }

    /// US-912: the factory-default PINs are still in force until BOTH PW1
    /// and PW3 have been changed away from the shipped defaults. While this
    /// is true, key operations (PSO:SIGN, PSO:DECIPHER, GENERATE) and
    /// TERMINATE DF are refused with `ConditionsOfUseNotSatisfied`. A `None`
    /// flag (pre-gate snapshot pending derivation) fails closed.
    pub fn factory_defaults_in_force(&self) -> bool {
        self.pw1_changed != Some(true) || self.pw3_changed != Some(true)
    }

    /// Panics if password is ResetCode, use [reset_code_len](Self::reset_code_len) instead
    pub fn pin_len(&self, password: Password) -> usize {
        match password {
            Password::Pw1 => self.user_pin_len as usize,
            Password::Pw3 => self.admin_pin_len as usize,
            Password::ResetCode => unreachable!(),
        }
    }

    /// Returns None if no code has been set
    pub fn reset_code_len(&self) -> Option<usize> {
        self.reset_code_pin_len.map(Into::into)
    }

    pub fn change_pin<T: crate::card::Client>(
        &mut self,
        client: &mut T,
        storage: Location,
        old_value: &[u8],
        new_value: &[u8],
        password: Password,
    ) -> Result<(), Error> {
        let new_pin = Bytes::try_from(new_value).map_err(|_| Error::InvalidPin)?;
        let old_pin = Bytes::try_from(old_value).map_err(|_| Error::InvalidPin)?;
        try_syscall!(client.change_pin(password, old_pin, new_pin.clone()))
            .map_err(|_| Error::InvalidPin)?;
        // US-912: record whether this PIN matches the shipped default. The
        // assignment (not an accumulate) re-arms the gate when a PIN is
        // changed back to its factory value.
        match password {
            Password::Pw1 => {
                self.pw1_changed = Some(&new_pin[..] != DEFAULT_USER_PIN);
            }
            Password::Pw3 => {
                self.pw3_changed = Some(&new_pin[..] != DEFAULT_ADMIN_PIN);
            }
            Password::ResetCode => {}
        }
        self.set_pin_len(client, storage, new_pin.len(), password)
    }

    fn set_pin_len<T: crate::card::Client>(
        &mut self,
        client: &mut T,
        storage: Location,
        new_len: usize,
        password: Password,
    ) -> Result<(), Error> {
        match password {
            Password::Pw1 => self.user_pin_len = new_len as u8,
            Password::Pw3 => self.admin_pin_len = new_len as u8,
            Password::ResetCode => self.reset_code_pin_len = Some(new_len as u8),
        }
        self.save(client, storage)
    }

    /// US-936: change a reference data value WITHOUT the old PIN, when the
    /// session already verified it (CHANGE REFERENCE DATA with the old value
    /// omitted, spec §7.2.3). `wrapped` is the session-held key wrapped by
    /// the current PIN (`Volatile::user_kek` / `Volatile::admin_kek`); it is
    /// re-wrapped under the new PIN with `set_pin_with_key` — the same
    /// re-key shape `reset_user_code_with_pw3` uses for PW1. The US-912
    /// factory-default gate is tracked exactly as in `change_pin` (setting
    /// the factory value back re-arms the gate), and the stored PIN length
    /// is updated so later length gates split correctly.
    pub fn change_pin_without_old<T: crate::card::Client>(
        &mut self,
        client: &mut T,
        storage: Location,
        new_value: &[u8],
        wrapped: KeyId,
        password: Password,
    ) -> Result<(), Error> {
        let new_pin = Bytes::try_from(new_value).map_err(|_| Error::InvalidPin)?;
        syscall!(client.set_pin_with_key(password, new_pin.clone(), Some(3), wrapped));
        match password {
            Password::Pw1 => {
                self.pw1_changed = Some(&new_pin[..] != DEFAULT_USER_PIN);
            }
            Password::Pw3 => {
                self.pw3_changed = Some(&new_pin[..] != DEFAULT_ADMIN_PIN);
            }
            Password::ResetCode => {}
        }
        self.set_pin_len(client, storage, new_pin.len(), password)
    }

    pub fn remove_reset_code<T: crate::card::Client>(
        &mut self,
        client: &mut T,
        storage: Location,
    ) -> Result<(), Error> {
        if self.reset_code_pin_len.is_some() {
            // Possible race condition so we ignore the error
            try_syscall!(client.delete_pin(Password::ResetCode)).ok();
        }
        self.reset_code_pin_len = None;
        self.save(client, storage)
    }

    pub fn sign_alg(&self) -> SignatureAlgorithm {
        self.sign_alg
    }

    pub fn set_sign_alg(
        &mut self,
        client: &mut impl crate::card::Client,
        storage: Location,
        alg: SignatureAlgorithm,
    ) -> Result<(), Error> {
        if self.sign_alg == alg {
            return Ok(());
        }
        self.delete_key(KeyType::Sign, client, storage)?;
        self.sign_alg = alg;
        self.save(client, storage)
    }

    pub fn dec_alg(&self) -> DecryptionAlgorithm {
        self.dec_alg
    }

    pub fn set_dec_alg(
        &mut self,
        client: &mut impl crate::card::Client,
        storage: Location,
        alg: DecryptionAlgorithm,
    ) -> Result<(), Error> {
        if self.dec_alg == alg {
            return Ok(());
        }
        self.delete_key(KeyType::Dec, client, storage)?;
        self.dec_alg = alg;
        self.save(client, storage)
    }

    pub fn aut_alg(&self) -> AuthenticationAlgorithm {
        self.aut_alg
    }

    pub fn set_aut_alg(
        &mut self,
        client: &mut impl crate::card::Client,
        storage: Location,
        alg: AuthenticationAlgorithm,
    ) -> Result<(), Error> {
        if self.aut_alg == alg {
            return Ok(());
        }
        self.delete_key(KeyType::Aut, client, storage)?;
        self.aut_alg = alg;
        self.save(client, storage)
    }

    pub fn fingerprints(&self) -> Fingerprints {
        self.fingerprints
    }

    pub fn set_fingerprints(
        &mut self,
        client: &mut impl crate::card::Client,
        storage: Location,
        data: Fingerprints,
    ) -> Result<(), Error> {
        self.fingerprints = data;
        self.save(client, storage)
    }

    pub fn ca_fingerprints(&self) -> CaFingerprints {
        self.ca_fingerprints
    }

    pub fn set_ca_fingerprints(
        &mut self,
        client: &mut impl crate::card::Client,
        storage: Location,
        data: CaFingerprints,
    ) -> Result<(), Error> {
        self.ca_fingerprints = data;
        self.save(client, storage)
    }

    pub fn keygen_dates(&self) -> KeyGenDates {
        self.keygen_dates
    }

    pub fn set_keygen_dates(
        &mut self,
        client: &mut impl crate::card::Client,
        storage: Location,
        data: KeyGenDates,
    ) -> Result<(), Error> {
        self.keygen_dates = data;
        self.save(client, storage)
    }

    /// fapico2 (US-972): store one key's creation date, then recompute that
    /// key's fingerprint.
    ///
    /// The date is the last input a v4 fingerprint needs, and it is the *host*
    /// that supplies it: the card does not set it during GENERATE (measured on
    /// hardware, US-972), so this is the first point at which the card can
    /// compute a fingerprint that a GnuPG client would agree with. Doing it
    /// here also means the card's answer and the host's `PUT DATA C7/C8/C9`
    /// are the same value, whichever arrives first.
    ///
    /// If the fingerprint cannot be computed — an algorithm this build does
    /// not reproduce exactly, or a key the card cannot serialize — the slot is
    /// left as it is. Writing a plausible-but-wrong fingerprint would be worse
    /// than leaving the host's, so this fails closed.
    pub fn set_keygen_date<T: crate::card::Client>(
        &mut self,
        key: KeyType,
        date: [u8; 4],
        client: &mut T,
        storage: Location,
    ) -> Result<(), Error> {
        self.keygen_dates.key_part_mut(key).copy_from_slice(&date);
        if let Some(fingerprint) = self.compute_fingerprint(client, key) {
            self.fingerprints
                .key_part_mut(key)
                .copy_from_slice(&fingerprint);
        }
        self.save(client, storage)
    }

    /// The v4 fingerprint of the public key currently in `key`'s slot, or
    /// `None` if it cannot be reproduced exactly (see [`Self::set_keygen_date`]).
    fn compute_fingerprint<T: crate::card::Client>(
        &self,
        client: &mut T,
        key: KeyType,
    ) -> Option<[u8; 20]> {
        let params = crate::fingerprint::params(key, self.sign_alg, self.dec_alg, self.aut_alg)?;
        let public = self.public_key_id(key)?;
        let offset = self.keygen_dates.key_offset(key);
        let created = u32::from_be_bytes(self.keygen_dates.0[offset..][..4].try_into().ok()?);
        let serialized = try_syscall!(client.serialize_key(
            params.mechanism,
            public,
            KeySerialization::Raw
        ))
        .ok()?
        .serialized_key;
        crate::fingerprint::fingerprint(&params, created, &serialized)
    }

    pub fn uif(&self, key: KeyType) -> Uif {
        match key {
            KeyType::Sign => self.uif_sign,
            KeyType::Dec => self.uif_dec,
            KeyType::Aut => self.uif_aut,
        }
    }

    pub fn set_uif(
        &mut self,
        client: &mut impl crate::card::Client,
        storage: Location,
        uif: Uif,
        key: KeyType,
    ) -> Result<(), Error> {
        match key {
            KeyType::Sign => self.uif_sign = uif,
            KeyType::Dec => self.uif_dec = uif,
            KeyType::Aut => self.uif_aut = uif,
        }
        self.save(client, storage)
    }

    pub fn pw1_valid_multiple(&self) -> bool {
        self.pw1_valid_multiple
    }

    pub fn set_pw1_valid_multiple(
        &mut self,
        value: bool,
        client: &mut impl crate::card::Client,
        storage: Location,
    ) -> Result<(), Error> {
        self.pw1_valid_multiple = value;
        self.save(client, storage)
    }

    pub fn cardholder_name(&self) -> &[u8] {
        &self.cardholder_name
    }

    pub fn set_cardholder_name(
        &mut self,
        value: Bytes<39>,
        client: &mut impl crate::card::Client,
        storage: Location,
    ) -> Result<(), Error> {
        self.cardholder_name = value;
        self.save(client, storage)
    }

    pub fn cardholder_sex(&self) -> Sex {
        self.cardholder_sex
    }

    pub fn set_cardholder_sex(
        &mut self,
        value: Sex,
        client: &mut impl crate::card::Client,
        storage: Location,
    ) -> Result<(), Error> {
        self.cardholder_sex = value;
        self.save(client, storage)
    }

    pub fn language_preferences(&self) -> &[u8] {
        &self.language_preferences
    }

    pub fn set_language_preferences(
        &mut self,
        value: Bytes<8>,
        client: &mut impl crate::card::Client,
        storage: Location,
    ) -> Result<(), Error> {
        self.language_preferences = value;
        self.save(client, storage)
    }

    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }

    pub fn increment_sign_count(
        &mut self,
        client: &mut impl crate::card::Client,
        storage: Location,
    ) -> Result<(), Error> {
        self.sign_count += 1;
        // Sign count is returned on 3 bytes
        if self.sign_count & 0xffffff == 0 {
            self.sign_count = 0xffffff;
        }
        self.save(client, storage)
    }

    pub fn key_origin(&self, ty: KeyType) -> Option<KeyOrigin> {
        match ty {
            KeyType::Sign => self.signing_key.map(|(_pubkey, origin)| origin),
            KeyType::Dec => self.confidentiality_key.map(|(_pubkey, origin)| origin),
            KeyType::Aut => self.aut_key.map(|(_pubkey, origin)| origin),
        }
    }

    pub fn delete_key(
        &mut self,
        ty: KeyType,
        client: &mut impl crate::card::Client,
        storage: Location,
    ) -> Result<(), Error> {
        let (key, priv_to_delete, path) = match ty {
            KeyType::Sign => (
                self.signing_key.take(),
                self.signing_private_to_delete.take(),
                SIGNING_KEY_PATH,
            ),
            KeyType::Dec => (
                self.confidentiality_key.take(),
                self.confidentiality_private_to_delete.take(),
                DEC_KEY_PATH,
            ),
            KeyType::Aut => (
                self.aut_key.take(),
                self.aut_private_to_delete.take(),
                AUTH_KEY_PATH,
            ),
        };

        if let Some((pubkey, _)) = key {
            self.fingerprints.key_part_mut(ty).copy_from_slice(&[0; 20]);
            self.keygen_dates.key_part_mut(ty).copy_from_slice(&[0; 4]);
            self.save(client, storage)?;
            try_syscall!(client.remove_file(storage, PathBuf::from(path))).map_err(|_err| {
                error!("Failed to delete key {_err:?}");
                Error::Saving
            })?;
            try_syscall!(client.delete(pubkey))
                .map_err(|_err| {
                    error!("Failed to delete public key: {:?} (ignored)", _err);
                })
                .ok();
        }
        if let Some(id) = priv_to_delete {
            syscall!(client.delete(id));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRef {
    Dec,
    Aut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRefs {
    // We can't use `KeyType` because the Signing key cannot be reassigned
    pub pso_decipher: KeyRef,
    pub internal_aut: KeyRef,
}

impl Default for KeyRefs {
    fn default() -> KeyRefs {
        KeyRefs {
            pso_decipher: KeyRef::Dec,
            internal_aut: KeyRef::Aut,
        }
    }
}

/// Since keys are stored encrypted, cache them to not have to decrypt them again
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct UserKeys {
    sign: Option<KeyId>,
    dec: Option<KeyId>,
    aut: Option<KeyId>,
    aes: Option<KeyId>,
}

impl UserKeys {
    // Replace self with an empty cache to avoid the drop check
    fn take(&mut self) -> Self {
        take(self)
    }

    fn clear(&mut self, client: &mut impl crate::card::Client) {
        for k in [&mut self.sign, &mut self.dec, &mut self.aut, &mut self.aes]
            .into_iter()
            .flat_map(Option::take)
        {
            syscall!(client.clear(k));
        }
    }
}

/// Check for memory leaks
impl Drop for UserKeys {
    fn drop(&mut self) {
        if matches!((self.sign, self.dec, self.aut), (None, None, None)) {
            return;
        }

        #[cfg(all(debug_assertions, feature = "std"))]
        if !std::thread::panicking() {
            panic!("User dropped with keys still in volatile storage {self:?}");
        }

        error!(
            "Error: User dropped with keys still in volatile storage: {:?}",
            self
        );
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
enum UserVerifiedInner {
    #[default]
    None,
    Other(KeyId, UserKeys),
    Sign(KeyId, UserKeys),
    #[allow(unused)]
    OtherAndSign(KeyId, UserKeys),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct UserVerified(UserVerifiedInner);

/// Check for memory leaks
impl Drop for UserVerified {
    fn drop(&mut self) {
        if self.0.user_kek().is_none() {
            return;
        }

        #[cfg(all(debug_assertions, feature = "std"))]
        if !std::thread::panicking() {
            panic!("User dropped with kek still available");
        }

        error!("Error: User dropped with kek still available");
    }
}

impl UserVerified {
    fn verify_sign(&mut self, k: KeyId) {
        self.0.verify_sign(k)
    }

    fn verify_other(&mut self, k: KeyId) {
        self.0.verify_other(k)
    }
}

impl UserVerifiedInner {
    fn verify_sign(&mut self, k: KeyId) {
        match self {
            Self::None => *self = Self::Sign(k, UserKeys::default()),
            Self::Other(old_k, cache) => {
                debug_assert_eq!(*old_k, k);
                *self = Self::OtherAndSign(k, cache.take())
            }
            _ => {}
        }
    }

    fn verify_other(&mut self, k: KeyId) {
        match self {
            Self::None => *self = Self::Other(k, UserKeys::default()),
            Self::Sign(old_k, cache) => {
                debug_assert_eq!(*old_k, k);
                *self = Self::OtherAndSign(k, cache.take())
            }
            _ => {}
        }
    }

    fn sign_verified(&self) -> bool {
        matches!(self, Self::Sign(_, _) | Self::OtherAndSign(_, _))
    }
    fn other_verified(&self) -> bool {
        matches!(self, Self::Other(_, _) | Self::OtherAndSign(_, _))
    }
    fn other_verified_kek(&self) -> Option<KeyId> {
        match self {
            Self::Other(k, _) | Self::OtherAndSign(k, _) => Some(*k),
            _ => None,
        }
    }
    fn user_kek(&self) -> Option<KeyId> {
        match self {
            Self::Other(k, _) | Self::Sign(k, _) | Self::OtherAndSign(k, _) => Some(*k),
            _ => None,
        }
    }
    fn clear(&mut self, client: &mut impl crate::card::Client) {
        match self.take() {
            Self::Other(k, mut cache)
            | Self::Sign(k, mut cache)
            | Self::OtherAndSign(k, mut cache) => {
                syscall!(client.delete(k));
                cache.clear(client);
            }
            _ => (),
        }
    }

    // Replace self with an empty cache to avoid the drop check
    fn take(&mut self) -> Self {
        take(self)
    }

    fn cache_mut(&mut self) -> Option<&mut UserKeys> {
        match self {
            Self::None => None,
            Self::Other(_, cache) => Some(cache),
            Self::Sign(_, cache) => Some(cache),
            Self::OtherAndSign(_, cache) => Some(cache),
        }
    }

    fn clear_cached(&mut self, client: &mut impl crate::card::Client, ty: KeyType) {
        let Some(cache) = self.cache_mut() else {
            return;
        };

        let key = match ty {
            KeyType::Sign => cache.sign.take(),
            KeyType::Dec => cache.dec.take(),
            KeyType::Aut => cache.aut.take(),
        };

        if let Some(k) = key {
            syscall!(client.clear(k));
        }
    }

    fn clear_aes_cached(&mut self, client: &mut impl crate::card::Client) {
        let Some(cache) = self.cache_mut() else {
            return;
        };

        if let Some(k) = cache.aes {
            syscall!(client.delete(k));
        }
    }

    fn clear_sign(&mut self, client: &mut impl crate::card::Client) {
        match self {
            Self::Sign(_k, _cache) => self.clear(client),
            Self::OtherAndSign(k, cache) => *self = Self::Other(*k, cache.take()),
            _ => {}
        };
    }
    fn clear_other(&mut self, client: &mut impl crate::card::Client) {
        match self {
            Self::Other(_k, _cache) => self.clear(client),
            Self::OtherAndSign(k, cache) => *self = Self::Sign(*k, cache.take()),
            _ => {}
        };
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct AdminVerified(Option<KeyId>);

impl AdminVerified {
    fn verify(&mut self, k: KeyId) {
        if let Some(old_k) = self.0 {
            debug_assert_eq!(old_k, k);
        }
        self.0 = Some(k);
    }
}

impl Drop for AdminVerified {
    fn drop(&mut self) {
        if self.0.is_none() {
            return;
        }

        #[cfg(all(debug_assertions, feature = "std"))]
        if !std::thread::panicking() {
            panic!("Admin dropped with kek still available");
        }

        error!("Error: Admin dropped with kek still available");
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Volatile {
    user: UserVerified,
    admin: AdminVerified,
    pub cur_do: Option<(Tag, Occurrence)>,
    pub keyrefs: KeyRefs,
}

impl Volatile {
    pub fn admin_verified(&self) -> bool {
        self.admin.0.is_some()
    }
    pub fn admin_kek(&self) -> Option<KeyId> {
        self.admin.0
    }

    pub fn clear_admin(&mut self, client: &mut impl crate::card::Client) {
        if let Some(k) = self.admin.0.take() {
            syscall!(client.delete(k));
        }
    }

    fn load_or_get_key(
        client: &mut impl crate::card::Client,
        user_kek: KeyId,
        opt_key: &mut Option<KeyId>,
        path: &'static Path,
        storage: Location,
    ) -> Result<KeyId, Status> {
        if let Some(k) = opt_key {
            return Ok(*k);
        }

        // Public-only migrated identities deliberately have no wrapped private
        // file yet. Distinguish absence from a corrupt or unreadable key file.
        let metadata = try_syscall!(client.entry_metadata(storage, PathBuf::from(path)))
            .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
        if metadata.metadata.is_none() {
            return Err(Status::KeyReferenceNotFound);
        }

        let unwrapped_key = try_syscall!(client.unwrap_key_from_file(
            Mechanism::Chacha8Poly1305,
            user_kek,
            PathBuf::from(path),
            storage,
            Location::Volatile,
            path.as_str().as_bytes()
        ))
        .map_err(|_err| {
            error!("Failed to load key: {:?}", _err);
            Status::UnspecifiedPersistentExecutionError
        })?
        .key
        .ok_or_else(|| {
            error!("Failed to decrypt key");
            Status::UnspecifiedPersistentExecutionError
        })?;
        *opt_key = Some(unwrapped_key);

        Ok(unwrapped_key)
    }

    pub fn aes_key_id(
        &mut self,
        client: &mut impl crate::card::Client,
        storage: Location,
    ) -> Result<KeyId, Status> {
        match &mut self.user.0 {
            UserVerifiedInner::None | UserVerifiedInner::Sign(_, _) => {
                Err(Status::ConditionsOfUseNotSatisfied)
            }
            UserVerifiedInner::Other(user_kek, cache)
            | UserVerifiedInner::OtherAndSign(user_kek, cache) => {
                Self::load_or_get_key(client, *user_kek, &mut cache.aes, AES_KEY_PATH, storage)
            }
        }
    }

    pub fn sign_verified(&self) -> bool {
        self.user.0.sign_verified()
    }
    pub fn other_verified(&self) -> bool {
        self.user.0.other_verified()
    }
    pub fn other_verified_kek(&self) -> Option<KeyId> {
        self.user.0.other_verified_kek()
    }
    pub fn user_kek(&self) -> Option<KeyId> {
        self.user.0.user_kek()
    }

    pub fn clear(&mut self, client: &mut impl crate::card::Client) {
        self.user.0.clear(client);
        self.clear_admin(client)
    }

    pub fn clear_sign(&mut self, client: &mut impl crate::card::Client) {
        self.user.0.clear_sign(client)
    }
    pub fn clear_other(&mut self, client: &mut impl crate::card::Client) {
        self.user.0.clear_other(client)
    }
}

/// DOs that can store arbitrary data from the user
///
/// They are stored each in their own files and are loaded only
/// when necessary to prevent the state from getting too big.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum ArbitraryDO {
    Url,
    KdfDo,
    PrivateUse1,
    PrivateUse2,
    PrivateUse3,
    PrivateUse4,
    LoginData,
    CardHolderCertAut,
    CardHolderCertDec,
    CardHolderCertSig,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum PermissionRequirement {
    None,
    User,
    Admin,
}

impl ArbitraryDO {
    fn path(self) -> PathBuf {
        PathBuf::from(match self {
            Self::Url => path!("url"),
            Self::KdfDo => path!("kdf_do"),
            Self::PrivateUse1 => path!("private_use_1"),
            Self::PrivateUse2 => path!("private_use_2"),
            Self::PrivateUse3 => path!("private_use_3"),
            Self::PrivateUse4 => path!("private_use_4"),
            Self::LoginData => path!("login_data"),
            Self::CardHolderCertAut => path!("cardholder_cert_aut"),
            Self::CardHolderCertDec => path!("cardholder_cert_dec"),
            Self::CardHolderCertSig => path!("cardholder_cert_sig"),
        })
    }

    fn default(self) -> Bytes<MAX_GENERIC_LENGTH> {
        #[allow(clippy::unwrap_used)]
        match self {
            // KDF-DO initialized to NONE
            Self::KdfDo => Bytes::from(&hex!("F9 03 81 01 00")),
            _ => Bytes::new(),
        }
    }

    pub fn read_permission(self) -> PermissionRequirement {
        match self {
            Self::PrivateUse3 => PermissionRequirement::User,
            Self::PrivateUse4 => PermissionRequirement::Admin,
            _ => PermissionRequirement::None,
        }
    }

    pub fn load(
        self,
        client: &mut impl crate::card::Client,
        storage: Location,
        mut reply: Reply<'_>,
        encryption_key: Option<KeyId>,
    ) -> Result<(), Status> {
        match try_syscall!(client.entry_metadata(storage, self.path())) {
            Ok(Metadata { metadata: None }) => {
                reply.expand(&self.default())?;
                return Ok(());
            }
            Err(_err) => {
                error!("File {:?} couldn't be read: {:?}", self, _err);
                return Err(Status::UnspecifiedNonpersistentExecutionError);
            }
            Ok(Metadata { metadata: Some(_) }) => {}
        }

        let mut read;
        let expected_len;
        let stop_at_first;

        if let Some(key) = encryption_key {
            try_syscall!(client.start_encrypted_chunked_read(storage, self.path(), key)).map_err(
                |_err| {
                    error!("Failed to start reading data {:?}, err: {:?}", self, _err);
                    Status::UnspecifiedNonpersistentExecutionError
                },
            )?;
            let first_data = try_syscall!(client.read_file_chunk()).map_err(|_err| {
                error!(
                    "Failed to read first encrypted data {:?}, err: {:?}",
                    self, _err
                );
                Status::UnspecifiedNonpersistentExecutionError
            })?;
            stop_at_first = !first_data.data.is_full();
            read = first_data.data.len();
            expected_len = first_data.data.len();
            reply.expand(&first_data.data)?;
        } else {
            let first_data = try_syscall!(client.start_chunked_read(storage, self.path(),))
                .map_err(|_err| {
                    error!("Failed to read first data {:?}, err: {:?}", self, _err);
                    Status::UnspecifiedNonpersistentExecutionError
                })?;
            stop_at_first = !first_data.data.is_full();
            read = first_data.data.len();
            expected_len = first_data.len;
            reply.expand(&first_data.data)?;
        }

        if !stop_at_first {
            loop {
                let res = try_syscall!(client.read_file_chunk()).map_err(|_err| {
                    error!("Failed to read data {:?}, err: {:?}", self, _err);
                    Status::UnspecifiedNonpersistentExecutionError
                })?;
                debug_assert_eq!(expected_len, res.len);
                reply.expand(&res.data)?;
                read += res.data.len();
                if !res.data.is_full() {
                    debug_assert_eq!(expected_len, read);
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    pub fn save(
        self,
        client: &mut impl crate::card::Client,
        storage: Location,
        bytes: &[u8],
        encryption_key: Option<KeyId>,
    ) -> Result<(), Error> {
        write_all(
            client,
            storage,
            self.path(),
            bytes,
            None,
            encryption_key.map(|key| EncryptionData { key, nonce: None }),
        )
        .map_err(|_err| {
            error!("Failed to store data: {_err:?}");
            Error::Saving
        })?;
        Ok(())
    }
}

fn load_if_exists(
    client: &mut impl crate::card::Client,
    location: Location,
    path: &PathBuf,
) -> Result<Option<Bytes<MAX_MESSAGE_LENGTH>>, Error> {
    match try_syscall!(client.read_file(location, path.clone())) {
        Ok(r) => Ok(Some(r.data)),
        Err(_) => match try_syscall!(client.entry_metadata(location, path.clone())) {
            Ok(Metadata { metadata: None }) => Ok(None),
            Ok(Metadata {
                metadata: Some(_metadata),
            }) => {
                error!("File {path} exists but couldn't be read: {_metadata:?}");
                Err(Error::Loading)
            }
            Err(_err) => {
                error!("File {path} couldn't be read: {_err:?}");
                Err(Error::Loading)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf};

    use super::*;

    const VERSIONS: &[&str] = &[
        "1.0.0", "1.1.0", "1.1.1", "1.2.0", "1.3.0", "1.4.0", "1.4.1", "1.5.0", "1.5.1", "1.6.0",
        "1.6.1", "1.7.0", "1.8.0",
    ];

    #[test]
    fn versions_include_current() {
        assert!(VERSIONS.contains(&env!("CARGO_PKG_VERSION")));
    }

    #[allow(clippy::unwrap_used)]
    fn test_one_state(name: &str, state: &Persistent) {
        let prefix = "tests/state_test_data/";
        for v in VERSIONS {
            let path = PathBuf::from(prefix).join(v).join(format!("{name}.cbor"));
            println!("Checking {} for version {v}", path.display());
            if *v == env!("CARGO_PKG_VERSION") {
                let mut buf = Message::new();
                cbor_smol::cbor_serialize_to(state, &mut buf).unwrap();
                // If test reference does not exist, create it
                if path.exists() {
                    let file = fs::read(&path).unwrap();
                    assert_eq!(buf, file);
                } else if env::var("TEST_STATE_CAN_CREATE").is_ok() {
                    fs::create_dir_all(PathBuf::from(prefix).join(v)).unwrap();
                    fs::write(&path, buf).unwrap();
                } else {
                    panic!("Missing test file");
                }
            }

            // If file does not exists, the old state does not exist
            if path.exists() {
                let file = fs::read(&path).unwrap();
                assert_eq!(
                    &cbor_smol::cbor_deserialize::<Persistent>(&file).unwrap(),
                    state,
                );
            }
        }
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_deserialization() {
        test_one_state("default", &Persistent::default());
        test_one_state(
            "all_non_default",
            &Persistent {
                reset_code_pin_len: Some(10),
                pw1_valid_multiple: true,
                user_pin_len: 127,
                admin_pin_len: 127,
                cardholder_name: Bytes::from(b"some name"),
                cardholder_sex: Sex::NotApplicable,
                language_preferences: Bytes::from(b"so"),
                signing_key: Some((KeyId::from_special(30), KeyOrigin::Imported)),
                confidentiality_key: Some((KeyId::from_special(30), KeyOrigin::Imported)),
                aut_key: Some((KeyId::from_special(30), KeyOrigin::Imported)),
                sign_alg: SignatureAlgorithm::Ed255,
                aut_alg: AuthenticationAlgorithm::Ed255,
                dec_alg: DecryptionAlgorithm::X255,
                ca_fingerprints: CaFingerprints([10; 60]),
                fingerprints: Fingerprints([10; 60]),
                keygen_dates: KeyGenDates([3; 12]),
                sign_count: 3,
                uif_sign: Uif::Enabled,
                uif_dec: Uif::PermanentlyEnabled,
                uif_aut: Uif::Enabled,
                aut_private_to_delete: None,
                confidentiality_private_to_delete: None,
                signing_private_to_delete: None,
            },
        );

        // Private keys to delete were added in 1.3.0
        // So tests prior to that must check equality with the default values
        test_one_state(
            "all_non_default_with_private",
            &Persistent {
                reset_code_pin_len: Some(10),
                pw1_valid_multiple: true,
                user_pin_len: 127,
                admin_pin_len: 127,
                cardholder_name: Bytes::from(b"some name"),
                cardholder_sex: Sex::NotApplicable,
                language_preferences: Bytes::from(b"so"),
                signing_key: Some((KeyId::from_special(30), KeyOrigin::Imported)),
                confidentiality_key: Some((KeyId::from_special(30), KeyOrigin::Imported)),
                aut_key: Some((KeyId::from_special(30), KeyOrigin::Imported)),
                sign_alg: SignatureAlgorithm::Ed255,
                aut_alg: AuthenticationAlgorithm::Ed255,
                dec_alg: DecryptionAlgorithm::X255,
                ca_fingerprints: CaFingerprints([10; 60]),
                fingerprints: Fingerprints([10; 60]),
                keygen_dates: KeyGenDates([3; 12]),
                sign_count: 3,
                uif_sign: Uif::Enabled,
                uif_dec: Uif::PermanentlyEnabled,
                uif_aut: Uif::Enabled,
                aut_private_to_delete: Some(KeyId::from_special(20)),
                confidentiality_private_to_delete: Some(KeyId::from_special(20)),
                signing_private_to_delete: Some(KeyId::from_special(20)),
            },
        );

        for ((sign_alg, dec_alg), aut_alg) in SignatureAlgorithm::iter_all()
            .zip(DecryptionAlgorithm::iter_all())
            .zip(AuthenticationAlgorithm::iter_all())
        {
            let name = format!("ALGOS-{sign_alg:?}-{dec_alg:?}-{aut_alg:?}");
            test_one_state(
                &name,
                &Persistent {
                    sign_alg,
                    dec_alg,
                    aut_alg,
                    ..Persistent::default()
                },
            );
        }
    }
}
