// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only
//
// Adapted from Nitrokey opcard-rs (`vendor/opcard/src/virt.rs`, `pub mod
// dispatch`) for fapico2 (S-721-1, US-331): renamed to [`OpcardDispatch`].
// S-724 restores the software-RSA backend the upstream template carries and
// adds the software-secp256k1 backend (supersedes the S-723-C1 /
// controller-decision D4 ECC-only scope): gpg and Kleopatra must be able to
// select RSA-2048/3072/4096 and secp256k1 through the OpenPGP key-attribute
// interface, matching the C reference firmware (`algorithm_attr_p256k1`,
// `MBEDTLS_ECP_DP_SECP256K1`). The one-way
// LGPLv3→GPLv3 conversion of the opcard sources is recorded in `NOTICE`.

//! The trussed dispatch opcard's card logic requires: the trussed-auth
//! backend (PIN/secret management over the internal filesystem), the
//! trussed-staging backend (chunked storage + wrap-key-to-file), the
//! software-RSA backend (S-724), the software-secp256k1 backend (S-724), and
//! the three opcard extensions wired.

use trussed::{
    backend::{Backend as _, BackendId},
    platform::Platform,
    serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl},
    service::ServiceResources,
    types::Context,
};
use core::cell::RefCell;

use heapless::Vec;
use zeroize::Zeroizing;

use trussed_auth::AuthExtension;
use trussed_auth_backend::{AuthBackend, AuthContext, FilesystemLayout, MAX_HW_KEY_LEN};
use trussed_chunked::ChunkedExtension;
use trussed_core::{
    api::{reply, request, Reply, Request},
    types::{Bytes, Location},
    Error,
};
use trussed_staging::{StagingBackend, StagingContext};
use trussed_wrap_key_to_file::WrapKeyToFileExtension;

use crate::{
    migration::{self, CapturedPinResult, MigrationBuffers, MigrationError},
    secure_store::{SecureStore, SecureStoreError},
};

/// Backends used by opcard (S-724: software-RSA and software-secp256k1
/// restored; US-944: software Brainpool, P-256r1 only since US-966 deferred
/// P-384r1; all served before the trussed core backend, which has no
/// RSA/secp256k1/Brainpool mechanism implementation).
pub const BACKENDS: &[BackendId<Backend>] = &[
    BackendId::Custom(Backend::Staging),
    BackendId::Custom(Backend::Auth),
    #[cfg(feature = "rsa-backend")]
    BackendId::Custom(Backend::Rsa),
    #[cfg(feature = "secp256k1-backend")]
    BackendId::Custom(Backend::Secp256k1),
    #[cfg(feature = "brainpool-backend")]
    BackendId::Custom(Backend::Brainpool),
    BackendId::Core,
];

/// Id for the [`ExtensionDispatch`] implementation
#[derive(Debug, Clone, Copy)]
pub enum Backend {
    /// trussed-auth
    Auth,
    /// trussed-staging
    Staging,
    /// software RSA (S-724, `trussed_rsa_alloc::SoftwareRsa`)
    #[cfg(feature = "rsa-backend")]
    Rsa,
    /// software secp256k1 (S-724, `trussed_secp256k1::SoftwareSecp256k1`)
    #[cfg(feature = "secp256k1-backend")]
    Secp256k1,
    /// software Brainpool P-256r1 (US-944,
    /// `trussed_brainpool::SoftwareBrainpool`; P-384r1 was deferred by US-966
    /// and P-512r1 is not served)
    #[cfg(feature = "brainpool-backend")]
    Brainpool,
}

/// Extensions used by opcard.
/// Used for the ExtensionDispatch implementation
#[derive(Debug, Clone, Copy)]
pub enum Extension {
    /// trussed-auth
    Auth,
    /// wrap_key_to_file
    WrapKeyToFile,
    /// chunked
    Chunked,
}

impl From<Extension> for u8 {
    fn from(extension: Extension) -> Self {
        match extension {
            Extension::Auth => 0,
            Extension::WrapKeyToFile => 1,
            Extension::Chunked => 2,
        }
    }
}

impl TryFrom<u8> for Extension {
    type Error = Error;

    fn try_from(id: u8) -> Result<Self, Self::Error> {
        match id {
            0 => Ok(Extension::Auth),
            1 => Ok(Extension::WrapKeyToFile),
            2 => Ok(Extension::Chunked),
            _ => Err(Error::InternalError),
        }
    }
}

/// Dispatch implementation with the backends required by opcard
#[derive(Debug)]
pub struct OpcardDispatch<'a> {
    auth: AuthBackend,
    staging: StagingBackend,
    migration: Option<&'a dyn MigrationPinAuthority>,
}

/// Synchronous, source-bound migration authentication. Implementations must
/// persist attempts before returning and never release a key on persistence failure.
/// The same authority must serve management completion and compatibility VERIFY.
pub trait MigrationPinAuthority: core::fmt::Debug {
    /// None until migration-owned opcard state has been initialized.
    fn retries(&self) -> Result<Option<u8>, Error>;
    /// PW3 remains migration-owned independently of PW1 conversion.
    fn pw3_retries(&self) -> Result<Option<u8>, Error>;
    /// Authenticate the captured administrator credential.
    fn verify_pw3(&self, pin: &[u8]) -> Result<Option<Zeroizing<[u8; 32]>>, Error>;
    /// Captured RC budget, available only after the completed PW1 handoff.
    fn rc_retries(&self) -> Result<Option<u8>, Error>;
    /// Authenticate the captured reset code and release its stable wrapping key.
    fn verify_rc(&self, pin: &[u8]) -> Result<Option<Zeroizing<[u8; 32]>>, Error>;
    /// The source maximum, preserved through the native handoff.
    fn maximum(&self) -> Result<Option<u8>, Error>;
    /// Verify PW1 and return its stable wrapping key only on durable success.
    fn verify(&self, pin: &[u8]) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, Error>;
    /// Durably mark the native credential as authoritative; the authority
    /// stands down afterwards and the native retry counter takes over.
    fn commit_native_handoff(&self) -> Result<(), Error>;
}

#[allow(missing_debug_implementations)]
pub struct MigrationAuthority<'a, K: SecureStore> {
    store: RefCell<&'a mut K>,
    otp: [u8; 32],
    uid: Vec<u8, 32>,
    bufs: RefCell<MigrationBuffers>,
}

impl<K: SecureStore> core::fmt::Debug for MigrationAuthority<'_, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MigrationAuthority")
            .field("otp", &"[redacted]")
            .field("uid", &self.uid)
            .finish_non_exhaustive()
    }
}

impl<'a, K: SecureStore> MigrationAuthority<'a, K> {
    /// Bind one persistent SecureStore, OTP, and UID. The same identity as
    /// migration capture/completion, so budgets cannot diverge.
    pub fn new(store: &'a mut K, otp: &[u8; 32], uid: &[u8]) -> Result<Self, MigrationError> {
        let mut id = Vec::new();
        id.extend_from_slice(uid).map_err(|_| MigrationError::SlotOverflow)?;
        Ok(Self {
            store: RefCell::new(store),
            otp: *otp,
            uid: id,
            bufs: RefCell::new(MigrationBuffers::new()),
        })
    }

    /// US-939: construct the authority **directly into a `MaybeUninit`
    /// static slot** (the device's `PIN_AUTHORITY`). The authority is
    /// ~98 KiB — it owns [`MigrationBuffers`] — and the device constructs
    /// it on the boot path inside the Embassy async-main task: letting the
    /// value transit the caller's stack frame is what grew the async-main
    /// frame to 95,232 B against the main stack (the dark-boot overflow).
    /// Field-by-field in-place construction keeps the scratch off the stack;
    /// the `RefCell<MigrationBuffers>` field is zeroed in place, which is
    /// exactly the [`MigrationBuffers::new()`] state (zeroed scratch, empty
    /// `heapless` vectors).
    ///
    /// # Safety
    ///
    /// `slot` must be valid for writes of `size_of::<Self>()` bytes,
    /// well-aligned, and written exactly once (the write-once `static mut`
    /// slot discipline). The returned reference is the sole handle.
    pub unsafe fn new_in_place(
        slot: *mut core::mem::MaybeUninit<Self>,
        store: &'a mut K,
        otp: &[u8; 32],
        uid: &[u8],
    ) -> Result<&'static mut Self, MigrationError> {
        let mut id = Vec::new();
        id.extend_from_slice(uid).map_err(|_| MigrationError::SlotOverflow)?;
        let p = slot.cast::<Self>();
        core::ptr::addr_of_mut!((*p).store).write(RefCell::new(store));
        core::ptr::addr_of_mut!((*p).otp).write(*otp);
        core::ptr::addr_of_mut!((*p).uid).write(id);
        let bufs: *mut RefCell<MigrationBuffers> = core::ptr::addr_of_mut!((*p).bufs);
        core::ptr::write_bytes(bufs.cast::<u8>(), 0, core::mem::size_of::<RefCell<MigrationBuffers>>());
        Ok(&mut *p)
    }
}

impl<K: SecureStore> MigrationPinAuthority for MigrationAuthority<'_, K> {
    fn pw3_retries(&self) -> Result<Option<u8>, Error> {
        if !migration::has_openpgp_capture(*self.store.borrow()) {
            return Ok(None);
        }
        migration::captured_openpgp_pw3_retries(
            *self.store.borrow_mut(), &self.otp, &self.uid, &mut self.bufs.borrow_mut(),
        ).map(Some).map_err(|_| Error::InternalError)
    }

    fn verify_pw3(&self, pin: &[u8]) -> Result<Option<Zeroizing<[u8; 32]>>, Error> {
        let verdict = migration::verify_captured_openpgp_pw3(
            *self.store.borrow_mut(), &self.otp, &self.uid,
            &mut self.bufs.borrow_mut(), pin,
        ).map_err(|_| Error::InternalError)?;
        match verdict {
            CapturedPinResult::Verified => self.wrapping_key().map(Some),
            _ => Ok(None),
        }
    }

    fn rc_retries(&self) -> Result<Option<u8>, Error> {
        if !migration::has_openpgp_capture(*self.store.borrow()) {
            return Ok(None);
        }
        // A pending handoff retires compatibility PW1 but has not installed
        // native PW1 yet. RC must not bypass that recovery boundary.
        let mut store = self.store.borrow_mut();
        if !migration::captured_openpgp_pw1_handed_off(*store)
            .map_err(|_| Error::InternalError)?
            || migration::captured_openpgp_pw1_handoff_pending(*store)
                .map_err(|_| Error::InternalError)?
        {
            return Ok(None);
        }
        migration::captured_openpgp_rc_retries(
            *store, &self.otp, &self.uid, &mut self.bufs.borrow_mut(),
        ).map_err(|_| Error::InternalError)
    }

    fn verify_rc(&self, pin: &[u8]) -> Result<Option<Zeroizing<[u8; 32]>>, Error> {
        if self.rc_retries()?.is_none() {
            return Ok(None);
        }
        let verdict = migration::verify_captured_openpgp_rc(
            *self.store.borrow_mut(), &self.otp, &self.uid,
            &mut self.bufs.borrow_mut(), pin,
        ).map_err(|_| Error::InternalError)?;
        match verdict {
            CapturedPinResult::Verified => self.wrapping_key().map(Some),
            _ => Ok(None),
        }
    }

    fn retries(&self) -> Result<Option<u8>, Error> {
        // After the one-time handoff the native credential is authoritative;
        // this seam stands down so exactly one retry route remains.
        match migration::captured_openpgp_pw1_handed_off(*self.store.borrow_mut()) {
            Ok(true) => return Ok(None),
            Ok(false) => {}
            Err(_) => return Err(Error::InternalError),
        }
        migration::captured_openpgp_pw1_retries(
            *self.store.borrow_mut(), &self.otp, &self.uid, &mut self.bufs.borrow_mut(),
        ).map(Some).or_else(|e| match e {
            MigrationError::Store(SecureStoreError::NotFound) => Ok(None),
            _ => Err(Error::InternalError),
        })
    }

    fn maximum(&self) -> Result<Option<u8>, Error> {
        self.retries()
    }

    fn verify(&self, pin: &[u8]) -> Result<Option<Zeroizing<[u8; 32]>>, Error> {
        let verdict = migration::verify_captured_openpgp_pw1(
            *self.store.borrow_mut(), &self.otp, &self.uid,
            &mut self.bufs.borrow_mut(), pin,
        );
        match verdict {
            Ok(CapturedPinResult::Verified) => {
                self.wrapping_key().map(Some)
            }
            Ok(_) => Ok(None),
            Err(e) => match e {
                MigrationError::Store(SecureStoreError::NotFound) => Ok(None),
                _ => Err(Error::InternalError),
            },
        }
    }

    fn commit_native_handoff(&self) -> Result<(), Error> {
        migration::commit_captured_openpgp_pw1_handoff(*self.store.borrow_mut())
            .map_err(|_| Error::InternalError)
    }
}

impl<K: SecureStore> MigrationAuthority<'_, K> {
    /// Stable native wrapping key, independent of PIN and DEK completion.
    /// Only returned after compatibility authentication succeeds. Domain and
    /// authenticated source binding prevent reuse as any C cryptographic key.
    fn wrapping_key(&self) -> Result<Zeroizing<[u8; 32]>, Error> {
        let mut buffers = self.bufs.borrow_mut();
        let capture = migration::read_openpgp_capture(
            *self.store.borrow_mut(), &self.otp, &self.uid, &mut buffers.scratch,
        ).map_err(|_| Error::InternalError)?;
        migration::native_openpgp_wrapping_key(
            *self.store.borrow_mut(),
            &self.otp,
            &self.uid,
            &capture.source(),
        )
            .map_err(|_| Error::InternalError)
    }
}
#[derive(Default)]
pub struct OpcardDispatchContext {
    auth: AuthContext,
    staging: StagingContext,
    /// Stateless context slot for the software-RSA backend
    /// ([`trussed_rsa_alloc::SoftwareRsa`] carries `Context = ()`).
    #[cfg(feature = "rsa-backend")]
    rsa: (),
    /// Stateless context slot for the software-secp256k1 backend
    /// ([`trussed_secp256k1::SoftwareSecp256k1`] carries `Context = ()`).
    #[cfg(feature = "secp256k1-backend")]
    secp256k1: (),
    /// Stateless context slot for the software-Brainpool backend
    /// ([`trussed_brainpool::SoftwareBrainpool`] carries `Context = ()`).
    #[cfg(feature = "brainpool-backend")]
    brainpool: (),
}

impl<'a> OpcardDispatch<'a> {
    /// Create a new dispatch using the internal filesystem
    pub fn new() -> Self {
        Self {
            auth: AuthBackend::new(Location::Internal, FilesystemLayout::V0),
            staging: StagingBackend::new(),
            migration: None,
        }
    }

    /// Attach a shared migration authority; native behavior is unchanged while
    /// it reports no active migration credentials.
    pub fn with_migration(mut self, migration: &'a dyn MigrationPinAuthority) -> Self {
        self.migration = Some(migration);
        self
    }

    /// Create a new dispatch using the internal filesystem and a key derived
    /// from hardware parameters
    pub fn with_hw_key(hw_key: Bytes<MAX_HW_KEY_LEN>) -> Self {
        Self {
            auth: AuthBackend::with_hw_key(Location::Internal, hw_key, FilesystemLayout::V0),
            staging: StagingBackend::new(),
            migration: None,
        }
    }
}

impl Default for OpcardDispatch<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtensionDispatch for OpcardDispatch<'_> {
    type BackendId = Backend;
    type Context = OpcardDispatchContext;
    type ExtensionId = Extension;

    fn core_request<P: Platform>(
        &mut self,
        backend: &Self::BackendId,
        ctx: &mut Context<Self::Context>,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        match backend {
            Backend::Auth => {
                self.auth
                    .request(&mut ctx.core, &mut ctx.backends.auth, request, resources)
            }
            Backend::Staging => self.staging.request(
                &mut ctx.core,
                &mut ctx.backends.staging,
                request,
                resources,
            ),
            #[cfg(feature = "rsa-backend")]
            Backend::Rsa => {
                use trussed::backend::Backend as _;
                trussed_rsa_alloc::SoftwareRsa.request(
                    &mut ctx.core,
                    &mut ctx.backends.rsa,
                    request,
                    resources,
                )
            }
            #[cfg(feature = "secp256k1-backend")]
            Backend::Secp256k1 => {
                use trussed::backend::Backend as _;
                trussed_secp256k1::SoftwareSecp256k1.request(
                    &mut ctx.core,
                    &mut ctx.backends.secp256k1,
                    request,
                    resources,
                )
            }
            #[cfg(feature = "brainpool-backend")]
            Backend::Brainpool => {
                use trussed::backend::Backend as _;
                trussed_brainpool::SoftwareBrainpool.request(
                    &mut ctx.core,
                    &mut ctx.backends.brainpool,
                    request,
                    resources,
                )
            }
        }
    }

    fn extension_request<P: Platform>(
        &mut self,
        backend: &Self::BackendId,
        extension: &Self::ExtensionId,
        ctx: &mut Context<Self::Context>,
        request: &request::SerdeExtension,
        resources: &mut ServiceResources<P>,
    ) -> Result<reply::SerdeExtension, Error> {
        match backend {
            Backend::Auth => match extension {
                Extension::Auth => {
                    use trussed_core::serde_extensions::Extension as _;
                    use trussed_auth::{AuthReply, AuthRequest};
                    let decoded = AuthExtension::deserialize_request(request)?;
                    // Occupancy checks must see native PIN records, not synthetic
                    // compatibility credentials. This query never checks a PIN or
                    // creates credentials; authentication stays migration-owned.
                    if matches!(decoded, AuthRequest::HasPin(_)) {
                        return self.auth.extension_request_serialized(
                            &mut ctx.core, &mut ctx.backends.auth, request, resources,
                        );
                    }
                    if let Some(authority) = self.migration {
                        let changes_compatibility_credentials = match &decoded {
                            AuthRequest::SetPin(r) => u8::from(r.id) != 0,
                            AuthRequest::SetPinWithKey(r) => u8::from(r.id) != 0,
                            AuthRequest::ChangePin(r) => u8::from(r.id) != 0,
                            AuthRequest::DeletePin(r) => u8::from(r.id) != 0,
                            AuthRequest::DeleteAllPins(_) | AuthRequest::ResetAuthData(_) => true,
                            _ => false,
                        };
                        if changes_compatibility_credentials && authority.pw3_retries()?.is_some() {
                            return Err(Error::NoSuchKey);
                        }
                        let rc = match &decoded {
                            AuthRequest::PinRetries(r) => u8::from(r.id) == 2,
                            AuthRequest::CheckPin(r) => u8::from(r.id) == 2,
                            AuthRequest::GetPinKey(r) => u8::from(r.id) == 2,
                            _ => false,
                        };
                        // PW3 ownership identifies a captured card even when RC
                        // is absent or gated. Never fall through to native RC.
                        if rc && authority.pw3_retries()?.is_some() {
                            let remaining = authority.rc_retries()?;
                            let response: AuthReply = match &decoded {
                                AuthRequest::PinRetries(_) =>
                                    trussed_auth::reply::PinRetries { retries: remaining }.into(),
                                AuthRequest::CheckPin(r) =>
                                    trussed_auth::reply::CheckPin {
                                        success: authority.verify_rc(&r.pin)?.is_some(),
                                    }.into(),
                                AuthRequest::GetPinKey(r) => {
                                    use trussed::{key::{Kind, Secrecy}, store::Keystore as _};
                                    let result = if let Some(key) = authority.verify_rc(&r.pin)? {
                                        Some(resources.keystore(ctx.core.path.clone())?.store_key(
                                            Location::Volatile, Secrecy::Secret,
                                            Kind::Symmetric(32), &key[..],
                                        )?)
                                    } else { None };
                                    trussed_auth::reply::GetPinKey { result }.into()
                                }
                                _ => return Err(Error::NoSuchKey),
                            };
                            return AuthExtension::serialize_reply(&response);
                        }
                        let pw3 = match &decoded {
                            AuthRequest::PinRetries(r) => u8::from(r.id) == 1,
                            AuthRequest::CheckPin(r) => u8::from(r.id) == 1,
                            AuthRequest::GetPinKey(r) => u8::from(r.id) == 1,
                            _ => false,
                        };
                        if pw3 {
                            if let Some(remaining) = authority.pw3_retries()? {
                                let response: AuthReply = match &decoded {
                                    AuthRequest::PinRetries(_) =>
                                        trussed_auth::reply::PinRetries { retries: Some(remaining) }.into(),
                                    AuthRequest::CheckPin(r) =>
                                        trussed_auth::reply::CheckPin {
                                            success: authority.verify_pw3(&r.pin)?.is_some(),
                                        }.into(),
                                    AuthRequest::GetPinKey(r) => {
                                        use trussed::{key::{Kind, Secrecy}, store::Keystore as _};
                                        let result = if let Some(key) = authority.verify_pw3(&r.pin)? {
                                            Some(resources.keystore(ctx.core.path.clone())?.store_key(
                                                Location::Volatile, Secrecy::Secret,
                                                Kind::Symmetric(32), &key[..],
                                            )?)
                                        } else { None };
                                        trussed_auth::reply::GetPinKey { result }.into()
                                    }
                                    _ => return Err(Error::NoSuchKey),
                                };
                                return AuthExtension::serialize_reply(&response);
                            }
                        }
                        if let Some(remaining) = authority.retries()? {
                            let response: AuthReply = match &decoded {
                                AuthRequest::PinRetries(r) if u8::from(r.id) == 0 =>
                                    trussed_auth::reply::PinRetries { retries: Some(remaining) }.into(),
                                AuthRequest::HasPin(r) if u8::from(r.id) == 0 =>
                                    trussed_auth::reply::HasPin { has_pin: true }.into(),
                                AuthRequest::CheckPin(r) if u8::from(r.id) == 0 => {
                                    let success = authority.verify(&r.pin)?.is_some();
                                    trussed_auth::reply::CheckPin { success }.into()
                                }
                                AuthRequest::GetPinKey(r) if u8::from(r.id) == 0 => {
                                    use trussed::{key::{Kind, Secrecy}, store::Keystore as _};
                                    let result = if let Some(key) = authority.verify(&r.pin)? {
                                        Some(resources.keystore(ctx.core.path.clone())?.store_key(
                                            Location::Volatile, Secrecy::Secret,
                                            Kind::Symmetric(32), &key[..],
                                        )?)
                                    } else { None };
                                    trussed_auth::reply::GetPinKey { result }.into()
                                }
                                // No fallback to native/default credentials, and no native
                                // mutation until the source-bound conversion is committed.
                                _ => return Err(Error::NoSuchKey),
                            };
                            return AuthExtension::serialize_reply(&response);
                        }
                    }
                    self.auth.extension_request_serialized(
                        &mut ctx.core, &mut ctx.backends.auth, request, resources,
                    )
                },
                Extension::WrapKeyToFile | Extension::Chunked => {
                    Err(Error::RequestNotAvailable)
                }
            },
            Backend::Staging => match extension {
                Extension::WrapKeyToFile => <StagingBackend as ExtensionImpl<
                    WrapKeyToFileExtension,
                >>::extension_request_serialized(
                    &mut self.staging,
                    &mut ctx.core,
                    &mut ctx.backends.staging,
                    request,
                    resources,
                ),
                Extension::Chunked => <StagingBackend as ExtensionImpl<
                    ChunkedExtension,
                >>::extension_request_serialized(
                    &mut self.staging,
                    &mut ctx.core,
                    &mut ctx.backends.staging,
                    request,
                    resources,
                ),
                Extension::Auth => Err(Error::RequestNotAvailable),
            },
            #[cfg(feature = "rsa-backend")]
            Backend::Rsa => match extension {
                Extension::Auth | Extension::WrapKeyToFile | Extension::Chunked => {
                    Err(Error::RequestNotAvailable)
                }
            },
            #[cfg(feature = "secp256k1-backend")]
            Backend::Secp256k1 => match extension {
                Extension::Auth | Extension::WrapKeyToFile | Extension::Chunked => {
                    Err(Error::RequestNotAvailable)
                }
            },
            #[cfg(feature = "brainpool-backend")]
            Backend::Brainpool => match extension {
                Extension::Auth | Extension::WrapKeyToFile | Extension::Chunked => {
                    Err(Error::RequestNotAvailable)
                }
            },
        }
    }
}

impl ExtensionId<AuthExtension> for OpcardDispatch<'_> {
    type Id = Extension;

    const ID: Self::Id = Self::Id::Auth;
}
impl ExtensionId<WrapKeyToFileExtension> for OpcardDispatch<'_> {
    type Id = Extension;

    const ID: Self::Id = Self::Id::WrapKeyToFile;
}
impl ExtensionId<ChunkedExtension> for OpcardDispatch<'_> {
    type Id = Extension;

    const ID: Self::Id = Self::Id::Chunked;
}
