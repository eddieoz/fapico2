// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(feature = "admin-app")]
use admin_app::{ResetSignal, ResetSignalAllocation};
use bitflags::bitflags;
use hex_literal::hex;
use iso7816::Status;
use trussed_auth::AuthClient;
use trussed_chunked::ChunkedClient;
use trussed_core::{types::Location, CryptoClient, FilesystemClient, UiClient};

pub(crate) mod reply;

use crate::state::{LoadedState, State};
use crate::utils::InspectErr;
use crate::{backend::Backend, command::Command};
use reply::Reply;

// § 4.2.1
pub const RID: [u8; 5] = [0xD2, 0x76, 0x00, 0x01, 0x24];
pub const PIX_APPLICATION: [u8; 1] = [0x01];
pub const PIX_RFU: [u8; 2] = [0x00, 0x00];
/// Version of the spec implemented by opcard-rs
pub const PGP_SMARTCARD_VERSION: [u8; 2] = [3, 4];

/// OpenPGP card implementation.
///
/// This is the main entry point for this crate.  It takes care of the command handling and state
/// management.
#[derive(Clone, Debug)]
pub struct Card<T: Client> {
    backend: Backend<T>,
    options: Options,
    state: State,
}

impl<T: Client> Card<T> {
    /// Creates a new OpenPGP card with the given backend and options.
    pub fn new(client: T, options: Options) -> Self {
        let state = State::default();
        Self {
            backend: Backend::new(client),
            options,
            state,
        }
    }

    /// US-914: attach the touch-to-sign presence source. When `Some`, the
    /// card consumes a presence grant bound to the operation tag at the
    /// post-authorization seam (`command::pso::confirm_user_presence`) —
    /// immediately before key material is used. The callback is
    /// fail-closed by construction (the device runtime grants only on a
    /// touch edge while the request is pending). `None` (default) keeps
    /// the upstream UIF-prompt semantics (host/emulation auto-ack).
    pub fn set_presence_grant(&mut self, grant: Option<fn(u32) -> bool>) {
        self.options.presence_grant = grant;
    }

    /// Seed migration-owned public metadata without creating default PINs.
    /// The caller must authenticate the source before invoking this seam.
    /// Repeated calls with the same source leave durable state unchanged;
    /// native or different-source state is refused.
    pub fn restore_public_metadata(
        &mut self,
        source: [u8; 32],
        name: &[u8],
        user_pin_len: u8,
        admin_pin_len: u8,
        reset_code_pin_len: Option<u8>,
        signing: Option<crate::MigrationSigningIdentity<'_>>,
    ) -> Result<(), Status> {
        self.restore_public_metadata_with_decryption(
            source, name, user_pin_len, admin_pin_len, reset_code_pin_len, signing, None,
        )
    }

    /// Seed authenticated signing and X25519 public identities together.
    /// Like `restore_public_metadata`, never rewrites same-source state.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_public_metadata_with_decryption(
        &mut self,
        source: [u8; 32],
        name: &[u8],
        user_pin_len: u8,
        admin_pin_len: u8,
        reset_code_pin_len: Option<u8>,
        signing: Option<crate::MigrationSigningIdentity<'_>>,
        decryption: Option<crate::MigrationDecryptionIdentity<'_>>,
    ) -> Result<(), Status> {
        self.restore_public_metadata_with_keys(
            source, name, user_pin_len, admin_pin_len, reset_code_pin_len,
            signing, decryption, None,
        )
    }

    /// Seed authenticated migration public identities, including P-256 authentication.
    /// Same-source state is never rewritten; native or different-source state is refused.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_public_metadata_with_keys(
        &mut self,
        source: [u8; 32],
        name: &[u8],
        user_pin_len: u8,
        admin_pin_len: u8,
        reset_code_pin_len: Option<u8>,
        signing: Option<crate::MigrationSigningIdentity<'_>>,
        decryption: Option<crate::MigrationDecryptionIdentity<'_>>,
        authentication: Option<crate::MigrationAuthenticationIdentity<'_>>,
    ) -> Result<(), Status> {
        self.restore_public_metadata_with_profile(source, name, user_pin_len, admin_pin_len,
            reset_code_pin_len, signing, decryption, authentication, crate::MigrationProfile::default())
    }

    /// Restore authenticated native cardholder and unencrypted private DOs with the keys.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_public_metadata_with_profile(
        &mut self,
        source: [u8; 32], name: &[u8], user_pin_len: u8, admin_pin_len: u8,
        reset_code_pin_len: Option<u8>,
        signing: Option<crate::MigrationSigningIdentity<'_>>,
        decryption: Option<crate::MigrationDecryptionIdentity<'_>>,
        authentication: Option<crate::MigrationAuthenticationIdentity<'_>>,
        profile: crate::MigrationProfile<'_>,
    ) -> Result<(), Status> {
        crate::state::Persistent::restore_metadata(
            self.backend.client_mut(), self.options.storage, source, name,
            user_pin_len, admin_pin_len, reset_code_pin_len, signing, decryption, authentication, profile,
        ).map_err(|_| Status::ConditionsOfUseNotSatisfied)?;
        self.reset();
        Ok(())
    }

    fn migration_restore_status(error: crate::error::Error) -> Status {
        match error {
            crate::error::Error::Saving => Status::UnspecifiedPersistentExecutionError,
            _ => Status::ConditionsOfUseNotSatisfied,
        }
    }

    /// Preflight a captured P-256 scalar against its raw 64-byte public point.
    /// Uses the restore path's native derive/compare seam, with volatile handles
    /// only; it does not install key files, metadata, or completion markers.
    pub fn validate_migration_p256_key(
        &mut self, scalar: &[u8; 32], point: &[u8; 64],
    ) -> Result<(), Status> {
        crate::state::Persistent::validate_migration_key(
            self.backend.client_mut(), trussed_core::types::Mechanism::P256, scalar, point,
        ).map_err(Self::migration_restore_status)
    }

    /// Preflight a captured little-endian X25519 scalar against its public key.
    /// Like the P-256 preflight, uses no persistent writes.
    pub fn validate_migration_x25519_key(
        &mut self, scalar: &[u8; 32], public: &[u8; 32],
    ) -> Result<(), Status> {
        crate::state::Persistent::validate_migration_key(
            self.backend.client_mut(), trussed_core::types::Mechanism::X255, scalar, public,
        ).map_err(Self::migration_restore_status)
    }

    /// Restore the authenticated migration signing key under the stable PW1 KEK.
    /// No PIN check is bypassed for subsequent signing operations.
    pub fn restore_migration_signing_key(
        &mut self,
        source: [u8; 32],
        scalar: &[u8; 32],
        wrapping_key: &[u8; 32],
    ) -> Result<(), Status> {
        crate::state::Persistent::restore_migration_key(
            self.backend.client_mut(), self.options.storage, source, scalar, wrapping_key,
            crate::types::KeyType::Sign,
        ).map_err(Self::migration_restore_status)?;
        self.reset();
        Ok(())
    }

    /// Restore the authenticated migration P-256 authentication key under the
    /// stable PW1 KEK. Subsequent INTERNAL AUTHENTICATE still requires PW1 (82).
    pub fn restore_migration_authentication_key(
        &mut self,
        source: [u8; 32],
        scalar: &[u8; 32],
        wrapping_key: &[u8; 32],
    ) -> Result<(), Status> {
        crate::state::Persistent::restore_migration_key(
            self.backend.client_mut(), self.options.storage, source, scalar, wrapping_key,
            crate::types::KeyType::Aut,
        ).map_err(Self::migration_restore_status)?;
        self.reset();
        Ok(())
    }

    /// Restore an authenticated X25519 scalar, already in little-endian form.
    /// Subsequent decipher operations still require PW1 (82) verification.
    pub fn restore_migration_decryption_key(
        &mut self,
        source: [u8; 32],
        scalar: &[u8; 32],
        wrapping_key: &[u8; 32],
    ) -> Result<(), Status> {
        crate::state::Persistent::restore_migration_key(
            self.backend.client_mut(), self.options.storage, source, scalar, wrapping_key,
            crate::types::KeyType::Dec,
        ).map_err(Self::migration_restore_status)?;
        self.reset();
        Ok(())
    }

    /// Whether this source has durably completed native PW1 conversion.
    pub fn migration_pin_ready(&mut self, source: [u8; 32]) -> Result<bool, Status> {
        crate::state::Persistent::migration_pin_ready(
            self.backend.client_mut(), self.options.storage, source,
        ).map_err(|_| Status::ConditionsOfUseNotSatisfied)
    }

    /// Install an authenticated migration PW1 once, without changing its KEK.
    pub fn restore_migration_pin(
        &mut self, source: [u8; 32], pin: &[u8], maximum: u8, wrapping_key: &[u8; 32],
    ) -> Result<(), Status> {
        crate::state::Persistent::restore_migration_pin(
            self.backend.client_mut(), self.options.storage, source, pin, maximum, wrapping_key,
        ).map_err(|_| Status::ConditionsOfUseNotSatisfied)?;
        self.reset();
        Ok(())
    }

    #[cfg(feature = "admin-app")]
    fn ack_factory_reset(&mut self, reset_signal: &ResetSignalAllocation) -> bool {
        self.state = State::default();
        reset_signal.ack_factory_reset()
    }

    /// Handles an APDU command and writes the response to the given buffer.
    ///
    /// The APDU command must be complete, i. e. chained commands must be resolved by the caller.
    pub fn handle(
        &mut self,
        command: iso7816::command::CommandView<'_>,
        reply: &mut heapless::VecView<u8>,
    ) -> Result<(), Status> {
        #[cfg(feature = "admin-app")]
        if let Some(reset_signal) = self.options.reset_signal {
            match reset_signal.load() {
                ResetSignal::None => {}
                ResetSignal::ConfigChanged => {
                    return Err(Status::SelectedFileInTerminationState);
                }
                ResetSignal::FactoryReset => {
                    if !self.ack_factory_reset(reset_signal) {
                        return Err(Status::SelectedFileInTerminationState);
                    }
                }
            }
        }

        trace!("Received APDU {:?}", command);
        let card_command = Command::try_from(command).inspect_err_stable(|_err| {
            warn!("Failed to parse command: {command:x?} {_err:?}");
        })?;
        info!("Executing command {:x?}", card_command);
        let context = Context {
            backend: &mut self.backend,
            state: &mut self.state,
            options: &self.options,
            data: command.data(),
            reply: Reply(reply),
        };
        card_command.exec(context)
    }

    /// Resets the state of the card.
    pub fn reset(&mut self) {
        #[cfg(feature = "admin-app")]
        if let Some(reset_signal) = self.options.reset_signal {
            match reset_signal.load() {
                ResetSignal::None => {}
                ResetSignal::ConfigChanged => {
                    debug!("Attempt to reset opcard with reset signal active");
                    return;
                }
                ResetSignal::FactoryReset => {
                    self.ack_factory_reset(reset_signal);
                    return;
                }
            }
        }

        self.state.volatile.clear(self.backend.client_mut());
        let state = State::default();
        self.state = state;
    }
}

impl<T: Client> Drop for Card<T> {
    fn drop(&mut self) {
        self.reset()
    }
}

impl<T: Client> iso7816::App for Card<T> {
    fn aid(&self) -> iso7816::Aid {
        // TODO: check truncation length
        iso7816::Aid::new_truncatable(&self.options.aid(), RID.len())
    }
}

#[cfg(feature = "apdu-dispatch")]
impl<T: Client> apdu_app::App for Card<T> {
    fn select(
        &mut self,
        interface: apdu_app::Interface,
        command: iso7816::command::CommandView<'_>,
        reply: &mut heapless::VecView<u8>,
    ) -> Result<(), Status> {
        if interface != apdu_app::Interface::Contact {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        self.handle(command, reply)
    }

    fn call(
        &mut self,
        interface: apdu_app::Interface,
        command: iso7816::command::CommandView<'_>,
        reply: &mut heapless::VecView<u8>,
    ) -> Result<(), Status> {
        if interface != apdu_app::Interface::Contact {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        self.handle(command, reply)
    }

    fn deselect(&mut self) {
        self.reset()
    }
}

bitflags! {
    /// The algorithms that are allowed to be generated or imported.
    ///
    /// Used in [`Options`](allowed_generation) and [`Options`](allowed_imports)
    #[derive(Clone, Copy, Debug)]
    pub struct AllowedAlgorithms: u32 {
        /// P256 NIST curve
        const P_256 = 1;
        /// P384 NIST curve
        const P_384 = 1 << 1;
        /// P521 NIST curve
        const P_521 = 1 << 2;
        /// RSA 2048
        const RSA_2048 = 1 << 3;
        /// RSA 3072
        const RSA_3072 = 1 << 4;
        /// RSA 4096
        const RSA_4096 = 1 << 5;
        /// X25519
        const X_25519 = 1 << 6;
        /// EdDsa25519
        const ED_25519 = 1 << 7;
        /// BRAINPOOL_P256R1 Brainpool curve
        const BRAINPOOL_P256R1 = 1 << 8;
        /// BRAINPOOL_P384R1 Brainpool curve
        const BRAINPOOL_P384R1 = 1 << 9;
        /// BRAINPOOL_P521R1 Brainpool curve
        const BRAINPOOL_P512R1 = 1 << 10;
        /// SECP256k1 (bitcoin curve)
        const SECP256K1 = 1 << 11;
    }
}

impl AllowedAlgorithms {
    /// US-962 (I2): the list a factory card accepts, and therefore the list
    /// GET DATA FA advertises.
    ///
    /// Every group that is *not* served by trussed Core carries a `cfg` on
    /// the feature that builds its backend, so a group can only be advertised
    /// in a build whose dispatch can actually serve it. SECP256K1 used to be
    /// listed unconditionally while its backend sat behind an independent
    /// platform feature: a build with `secp256k1-backend` off dropped
    /// `Backend::Secp256k1` from `BACKENDS` yet still advertised the
    /// algorithm *and* accepted the attribute with `9000`, so every
    /// secp256k1 request fell through to Core and failed. The host that
    /// trusted FA had no way to see that.
    ///
    /// The features named here are the *advertisement* half; the serving
    /// half lives in `platform/Cargo.toml` and the two are turned on together
    /// by the consuming crate's single switch (`fapico2-openpgp`'s
    /// `secp256k1-backend` and friends), because this crate cannot read
    /// another crate's features. `apps/openpgp/tests/advertise_serve.rs`
    /// cross-checks the two lists against each other in whichever
    /// configuration it is built.
    ///
    /// P-256/P-384/P-521, X25519 and Ed25519 stay unconditional on purpose:
    /// they are served by trussed Core, which both this crate's
    /// `trussed-core` and the platform's `trussed` enable with
    /// p256/p384/p521/ed255/x255 unconditionally. There is no configuration
    /// of this workspace in which they could be advertised unserved, so there
    /// is nothing to couple them to.
    ///
    /// **US-966 (2026-09-27): BRAINPOOL_P384R1 is gone from both lists**, in
    /// every configuration, and *not* behind a feature. P-384r1 is deferred
    /// to a follow-up release for want of deployment pull — the OpenPGP card
    /// spec v3.4 §4.4.3.10 only asks that "at least one of this curves shall
    /// be supported" (NIST P-256/384/521 already satisfies that), RFC 8734
    /// deprecated Brainpool for TLS 1.3 "because they had little usage … not
    /// endorsed by the IETF", and no OpenPGP-card user of P-384r1 was found.
    /// P-256r1 stays: it is the one demonstrably working on hardware.
    ///
    /// The bitflag `BRAINPOOL_P384R1` itself is kept, exactly as
    /// `BRAINPOOL_P512R1` is: it is part of the card's data model, and the
    /// `trussed-core` `brainpoolp384r1` feature stays on here so the
    /// fail-closed `Algorithm` gate can *name* a P-384r1 attribute and refuse
    /// it with `6A80` instead of failing to parse it. Removing the curve from
    /// `default_gen`/`default_import` is what makes it unadvertised; nothing
    /// else needed to move, and nothing needed a switch — a switch would have
    /// been a fourth thing for `tests/scripts/check_advertise_serve_coupling.py`
    /// to reason about, guarding a curve with no user.
    fn default_gen() -> Self {
        [
            Self::P_256,
            Self::P_384,
            Self::P_521,
            #[cfg(feature = "rsa2048-gen")]
            Self::RSA_2048,
            #[cfg(feature = "rsa3072-gen")]
            Self::RSA_3072,
            #[cfg(feature = "rsa4096-gen")]
            Self::RSA_4096,
            Self::X_25519,
            Self::ED_25519,
            // US-962: gated on the software secp256k1 backend (S-724), for
            // the same reason the Brainpool bits below are.
            #[cfg(feature = "secp256k1-backend")]
            Self::SECP256K1,
            // US-945: Brainpool joins the defaults only when a backend can
            // serve it (US-944 software backend, P-256r1). P-512r1 is
            // deliberately absent — no bp512 crate exists in the ecosystem,
            // so it is never advertised (PUT DATA of a P-512r1 attribute
            // fails closed with 6A80; see
            // docs/tasks/known-gate-divergences.md US-944). P-384r1 joined
            // this list under US-945 and left it under US-966; see the
            // `default_gen` doc comment.
            #[cfg(feature = "brainpool-backend")]
            Self::BRAINPOOL_P256R1,
        ]
        .into_iter()
        .fold(Self::empty(), |acc, value| acc | value)
    }
    fn default_import() -> Self {
        [
            Self::P_256,
            Self::P_384,
            Self::P_521,
            #[cfg(feature = "rsa2048")]
            Self::RSA_2048,
            #[cfg(feature = "rsa3072")]
            Self::RSA_3072,
            #[cfg(feature = "rsa4096")]
            Self::RSA_4096,
            Self::X_25519,
            Self::ED_25519,
            // US-962: same gating as `default_gen` — see above. An import of
            // an unserved algorithm is the same lie as advertising it.
            #[cfg(feature = "secp256k1-backend")]
            Self::SECP256K1,
            // US-945: same gating as `default_gen` — see above.
            // US-966: BRAINPOOL_P384R1 removed, same as in `default_gen`.
            #[cfg(feature = "brainpool-backend")]
            Self::BRAINPOOL_P256R1,
        ]
        .into_iter()
        .fold(Self::empty(), |acc, value| acc | value)
    }
}

/// Options for the OpenPGP card.
#[derive(Clone)]
#[non_exhaustive]
pub struct Options {
    /// The manufacturer ID returned in the AID, see § 4.2.1 of the spec.
    pub manufacturer: [u8; 2],
    /// The serial number returned in the AID, see § 4.2.1 of the spec.
    pub serial: [u8; 4],

    // FIXME: Make historical bytes configurable
    /// Historical bytes, see  § 6
    pub(crate) historical_bytes: heapless::Vec<u8, 15>,

    /// Does the card have a button for user input?
    pub button_available: bool,
    /// Which trussed storage to use
    pub storage: Location,

    /// Bitflags of algorithms allowed to be imported
    pub allowed_imports: AllowedAlgorithms,

    /// Bitflags of algorithms allowed to be generated
    pub allowed_generation: AllowedAlgorithms,

    /// US-914: touch-to-sign presence source. When set, the card consumes
    /// a presence grant bound to the operation tag (see
    /// `command::pso::confirm_user_presence`) at the post-authorization
    /// seam, immediately before key material is used; it replaces the
    /// upstream UIF prompt. `None` (default) keeps the upstream
    /// semantics — the `uif`-gated UI prompt, which host and emulation
    /// UIs auto-ack.
    pub presence_grant: Option<fn(u32) -> bool>,

    /// Flag to signal that the application has had its configuration changed or was factory-resetted by the admin application
    ///
    /// Requires the feature-flag admin-app
    #[cfg(feature = "admin-app")]
    pub reset_signal: Option<&'static ResetSignalAllocation>,
}

// Manual `Debug`: `presence_grant` is a callback (not `Debug`) — report
// it as set/unset.
impl core::fmt::Debug for Options {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Options")
            .field("manufacturer", &self.manufacturer)
            .field("serial", &self.serial)
            .field("historical_bytes", &self.historical_bytes)
            .field("button_available", &self.button_available)
            .field("storage", &self.storage)
            .field("allowed_imports", &self.allowed_imports)
            .field("allowed_generation", &self.allowed_generation)
            .field("presence_grant", &self.presence_grant.is_some())
            .finish()
    }
}

impl Options {
    /// Returns the AID based on these options, see § 4.2.1 of the spec.
    pub fn aid(&self) -> [u8; 16] {
        [
            RID[0],
            RID[1],
            RID[2],
            RID[3],
            RID[4],
            PIX_APPLICATION[0],
            PGP_SMARTCARD_VERSION[0],
            PGP_SMARTCARD_VERSION[1],
            self.manufacturer[0],
            self.manufacturer[1],
            self.serial[0],
            self.serial[1],
            self.serial[2],
            self.serial[3],
            PIX_RFU[0],
            PIX_RFU[1],
        ]
    }
}

/// Returns an instance with the version number derived from the crate version
impl Default for Options {
    fn default() -> Self {
        // TODO: consider setting a default manufacturer
        #[allow(clippy::unwrap_used)]
        Self {
            manufacturer: Default::default(),
            serial: Default::default(),
            // TODO: Copied from Nitrokey Pro
            historical_bytes: heapless::Vec::from_slice(&hex!("0031F573C00160009000")).unwrap(),
            button_available: true,
            storage: Location::External,
            allowed_imports: AllowedAlgorithms::default_import(),
            allowed_generation: AllowedAlgorithms::default_gen(),
            presence_grant: None,
            #[cfg(feature = "admin-app")]
            reset_signal: None,
        }
    }
}

#[derive(Debug)]
pub struct Context<'a, T: Client> {
    pub backend: &'a mut Backend<T>,
    pub options: &'a Options,
    pub state: &'a mut State,
    pub data: &'a [u8],
    pub reply: Reply<'a>,
}

impl<T: Client> Context<'_, T> {
    pub fn load_state(&mut self) -> Result<LoadedContext<'_, T>, Status> {
        Ok(LoadedContext {
            state: self
                .state
                .load(self.backend.client_mut(), self.options.storage)
                .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?,
            options: self.options,
            backend: self.backend,
            data: self.data,
            reply: self.reply.lend(),
        })
    }

    /// Lend the context
    ///
    /// The resulting `Context` has a shorter lifetime than the original one, meaning that it
    /// can be passed by value to other functions and the original context can then be used again
    pub fn lend(&mut self) -> Context<'_, T> {
        Context {
            reply: Reply(self.reply.0),
            backend: self.backend,
            options: self.options,
            state: self.state,
            data: self.data,
        }
    }
}

#[derive(Debug)]
/// Context with the persistent state loaded from flash
pub struct LoadedContext<'a, T: Client> {
    pub backend: &'a mut Backend<T>,
    pub options: &'a Options,
    pub state: LoadedState<'a>,
    pub data: &'a [u8],
    pub reply: Reply<'a>,
}

impl<T: Client> LoadedContext<'_, T> {
    /// Lend the context
    ///
    /// The resulting `LoadedContext` has a shorter lifetime than the original one, meaning that it
    /// can be passed by value to other functions and the original context can then be used again
    pub fn lend(&mut self) -> LoadedContext<'_, T> {
        LoadedContext {
            reply: Reply(self.reply.0),
            backend: self.backend,
            options: self.options,
            state: self.state.lend(),
            data: self.data,
        }
    }
}

use trussed_wrap_key_to_file::WrapKeyToFileClient;

/// Super trait with all trussed extensions required by opcard
pub trait Client:
    CryptoClient + FilesystemClient + UiClient + AuthClient + WrapKeyToFileClient + ChunkedClient
{
}
impl<
        C: CryptoClient
            + FilesystemClient
            + UiClient
            + WrapKeyToFileClient
            + AuthClient
            + ChunkedClient,
    > Client for C
{
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Testing the concatenation of arrays used in aid
    #[test]
    fn aid() {
        assert_eq!(
            Options::default().aid(),
            hex!("D2 76 00 01 24 01 03 04 00 00 00 00 00 00 00 00"),
        )
    }
}
