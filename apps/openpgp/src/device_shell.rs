//! OpenPGP app over a trussed client (S-721-2, US-331).
//!
//! One generic app for both builds: `OpenPgpApp<T: opcard::Client>` runs the
//! vendored `opcard` implementation (OpenPGP card spec v3.4) — unmodified —
//! over any trussed client:
//!
//! * **Device** (RP2350, `no_std`): the S-721-1 no_std platform client
//!   (`fapico2_platform::trusted_backend::device` — TRNG entropy, QSPI-flash
//!   littlefs2, LED UI; the client is moved out of its static with
//!   `device::take_client()` and owned here, by value, in the app);
//! * **Host** (emulation + tests): the same `SyscallRunner` client on the
//!   host backend (`trusted_backend::host::with_host_backend`).
//!
//! The file name is historical (the US-386 wiring shell lived here); the
//! shell is gone — this is the real command set.
//!
//! Card state persistence: opcard persists its own state through its trussed
//! files (keys, PINs, card data) in the trussed internal filesystem — on
//! device the 1 MiB QSPI-flash window (`Options::storage = Location::Internal`,
//! load-bearing for S-721-4 persistence), on the host a RAM littlefs2. The
//! migration authority also updates the shared secure store. Migration-owned
//! cards request a transport snapshot after commands; failed persistence keeps
//! the app dirty and clears volatile authentication before an error reply.

use fapico2_platform::apdu_chain::{ChainAssembler, Step};
use fapico2_platform::dispatch::{App, MAX_RESPONSE, Sw, SW_INS_NOT_SUPPORTED, SW_OK};

/// OpenPGP card AID (§4.2.1 of the OpenPGP card 3.4 spec): RID D2 76,
/// 00 01 24 01.
pub const OPENPGP_AID: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// FCI returned on SELECT (OpenPGP card §7.2.1). opcard's SELECT writes no
/// FCI (upstream the APDU layer adds it; we drive `Card::handle` directly),
/// so the app synthesizes one: the US-386 template (proprietary block with
/// the AID + "OPENPGP" label) plus the `5F 52` historical bytes, which
/// `opcard::Options` keeps `pub(crate)` — the bytes pinned here are
/// `Options::default().historical_bytes`
/// (`00 31 F5 73 C0 01 60 00 90 00`, 10 bytes; see
/// `vendor/opcard/src/card.rs`). Well-formed: `62 20` = 32 content bytes
/// (the `82 11` block, 19 bytes, + the `5F 52 0A` block, 13 bytes).
///
/// Hosts need not parse the SELECT FCI (spec §7.2.1: "don't need to be
/// evaluated"; gpg reads the AID and the historical bytes via direct
/// `GET DATA` 004F / 5F52 from the `6E` object) — this template exists so
/// the SELECT response is a well-formed ISO 7816-4 FCI, not empty.
const SELECT_FCI: &[u8] = &[
    0x62, 0x20, // FCI template (32 bytes)
    0x82, 0x11, //   FCI proprietary template (17 bytes)
    0xA5, 0x06, //     application identifier (6-byte AID)
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
    0x50, 0x07, //     application label (7 bytes)
    b'O', b'P', b'E', b'N', b'P', b'G', b'P',
    0x5F, 0x52, 0x0A, //   historical bytes (10 bytes, `Options::default()`)
    0x00, 0x31, 0xF5, 0x73, 0xC0, 0x01, 0x60, 0x00, 0x90, 0x00,
];

/// US-914: operation tags for the touch-to-sign presence grant — the
/// INS/P1/P2 triple of the gated key operation packed big-endian into the
/// 32-bit grant tag, so a grant is bound to the *pending operation*.
/// Defined at the opcard seam (`command::pso`), where the grant is
/// actually consumed, and re-exported here for the app contract.
pub use opcard::{PRESENCE_TAG_INT_AUTH, PRESENCE_TAG_PSO_DECIPHER, PRESENCE_TAG_PSO_SIGN};

/// OpenPGP 3.4 app backed by opcard over a trussed client `T`.
///
/// `T` is the client's lifetime (the client is owned by value; the app is
/// built inside the client's owning scope — `with_host_backend` on the
/// host, the app static on device).
pub struct OpenPgpApp<T: opcard::Client> {
    card: opcard::Card<T>,
    // opcard speaks heapless 0.9 `VecView`; the platform uses heapless 0.8
    // `Vec`. A scratch buffer bridges the two, bounded by MAX_RESPONSE. It
    // also stages the current reply across `61XX`/GET RESPONSE exchanges
    // (`scratch_offset` — S-723-A2).
    scratch: heapless09::Vec<u8, MAX_RESPONSE>,
    scratch_offset: usize,
    /// US-181 (PICOForge-COMPAT): receive-side ISO 7816-4 command chaining.
    ///
    /// opcard is explicit that this is the caller's job
    /// (`vendor/opcard/src/card.rs:236` — "The APDU command must be complete,
    /// i. e. chained commands must be resolved by the caller"), and the
    /// OpenPGP applet is the applet that pays for it: a `PUT DATA` of a
    /// large cardholder certificate is fragmented by PicoForge's
    /// `send_chained` (`picoforge/src/hal/transport/ccid.rs:115-144`) and
    /// opcard's `Command::try_from` has no CLA gate at all
    /// (`vendor/opcard/src/command.rs:118` is literally `// TODO: check CLA`),
    /// so without this the fragment is accepted and then fails on the
    /// truncated TLV.
    ///
    /// The buffer is a static cost — this struct is built straight into
    /// `boot::OPENPGP_APP` (`firmware/src/main.rs:546`), so the
    /// `MAX_CHAINED_APDU` bytes land in `.bss`. That is deliberate: the
    /// alternative is a per-fragment copy into a second buffer, which is the
    /// same memory plus a memcpy per fragment.
    chain: ChainAssembler,
    migration_active: bool,
    migration_dirty: bool,
    // US-914: the touch-to-sign presence source lives in the opcard card
    // itself (`Options::presence_grant` — see [`Self::with_presence_grant`]).
}

impl<T: opcard::Client> OpenPgpApp<T> {
    /// Build the app over a trussed client (taken by value — the client is
    /// owned by the card from here on).
    ///
    /// `Options::storage = Location::Internal`: the card state lives in the
    /// trussed internal filesystem — the 1 MiB QSPI-flash window on device
    /// (load-bearing for S-721-4 persistence) — not the RAM volatile store.
    /// US-934: the AID serial is provisioned here (see
    /// [`Self::provision_serial`]); the manufacturer stays the reserved
    /// test value `00 00` (OQ-1 — gpg's "test card" display stays truthful
    /// until the FSFE registration lands). Everything else stays
    /// `Options::default()` (the AID, historical bytes, and button
    /// availability match the PIV/OpenPGP identity this token advertises;
    /// opcard is run unmodified apart from the US-912 / US-914 review
    /// patches) — the serial flows only through `Options`.
    // US-939: `#[inline(never)]` -- `State::default()` materializes a ~6 KiB
    // temporary; keep it in this function's own frame, out of the Embassy
    // async-main frame.
    #[inline(never)]
    pub fn new(mut client: T) -> Self {
        let mut options = opcard::Options::default();
        options.storage = trussed_core::types::Location::Internal;
        options.serial = Self::provision_serial(&mut client);
        Self {
            card: opcard::Card::new(client, options),
            scratch: heapless09::Vec::new(),
            scratch_offset: 0,
            chain: ChainAssembler::new(),
            migration_active: false,
            migration_dirty: false,
        }
    }

    /// US-934: load the per-device serial from the trussed internal
    /// filesystem (file `us934-serial`, next to the opcard state — the
    /// OQ-2 durability discipline of the US-912 gate flag: `Location::Internal`
    /// littlefs2, a plain reboot never changes it, a factory wipe that
    /// regenerates it is acceptable).
    ///
    /// First boot (or an unreadable/oversized file): draw a random 4-byte
    /// serial (OQ-5 — a TRNG draw on device, OS entropy on host) and
    /// persist it. The draw retries while it lands on all-zeros (a
    /// meaningless all-zero serial is what this story removes). A failed
    /// persistence write is not fatal — the draw is used for this session
    /// and the next boot redraws — since a filesystem that cannot write
    /// cannot keep opcard's state either.
    ///
    /// The already-persisted branch above is deliberately NOT re-derived:
    /// a fielded card's serial is the identity the host has already seen
    /// and written down, so US-150 fixes the draw forward only. A card
    /// provisioned before this change keeps presenting its stored bytes —
    /// possibly not canonical packed BCD — until a factory wipe draws a
    /// new one.
    fn provision_serial(client: &mut T) -> [u8; 4] {
        use trussed_core::{
            try_syscall,
            types::{Location, Message, PathBuf},
        };
        let path: PathBuf = PathBuf::from(
            littlefs2_core::Path::from_str_with_nul("us934-serial\0")
                .expect("the serial file name is a valid littlefs2 path"),
        );
        if let Ok(reply) = try_syscall!(client.read_file(Location::Internal, path.clone())) {
            if let Ok(serial) = <[u8; 4]>::try_from(reply.data.as_slice()) {
                return serial;
            }
        }
        // Fresh card or unreadable file: draw, then persist. OQ-2 permits
        // regeneration on factory wipe; a corrupt file is treated the same
        // as absent (regenerate) rather than failing the boot.
        let serial: [u8; 4] = draw_bcd_serial(|| {
            let reply = try_syscall!(client.random_bytes(4)).ok()?;
            let mut drawn = [0u8; 4];
            drawn.copy_from_slice(&reply.bytes[..4]);
            Some(drawn)
        });
        if let Ok(data) = Message::try_from(serial.as_slice()) {
            try_syscall!(client.write_file(Location::Internal, path, data, None,)).ok();
        }
        serial
    }

    /// US-914: attach the touch-to-sign presence source (device wiring).
    /// The callback receives the operation's presence tag
    /// ([`PRESENCE_TAG_PSO_SIGN`] &c.) and must consume a presence grant
    /// bound to it — the firmware injects the shared presence runtime's
    /// blocking BOOTSEL wait. The grant is consumed at the opcard seam
    /// (`command::pso::confirm_user_presence`), after authorization and
    /// immediately before key use — consent still precedes the side
    /// effect, but the touch prompt is never offered for commands that
    /// cannot succeed. Without a source the app auto-acks
    /// (host/emulation default).
    pub fn with_presence_grant(mut self, grant: fn(u32) -> bool) -> Self {
        self.card.set_presence_grant(Some(grant));
        self
    }

    /// US-939: post-construction variant of [`Self::with_presence_grant`].
    /// The firmware builds the app straight into its static slot
    /// (`boot::init_static_slot_with`) so the 6.6 KiB app never transits
    /// the caller's stack frame by value.
    pub fn set_presence_grant(&mut self, grant: fn(u32) -> bool) {
        self.card.set_presence_grant(Some(grant));
    }

    /// Firmware boot entry, after backend mount and before registration.
    /// Restores public state and resumes an already-completed DEK import.
    // US-939: `#[inline(never)]` -- async-main frame discipline.
    #[inline(never)]
    pub fn restore_at_boot<K: fapico2_platform::secure_store::SecureStore>(
        &mut self,
        store: &mut K,
        otp: &[u8; 32],
        uid: &[u8],
        bufs: &mut fapico2_platform::migration::MigrationBuffers,
    ) -> Result<(), fapico2_platform::migration::MigrationError> {
        use fapico2_platform::{migration, secure_store::SecureStoreError};
        let capture = match migration::read_openpgp_capture(store, otp, uid, &mut bufs.scratch) {
            Ok(capture) => capture,
            Err(migration::MigrationError::Store(SecureStoreError::NotFound))
                if !migration::has_openpgp_capture(store)
                    && !fapico2_platform::secure_store::chunked::contains_chunked(store, migration::SLOT_OPENPGP)
                    && !store.contains(migration::SLOT_OPENPGP_DEK)
                    && !store.contains(migration::SLOT_OPENPGP_HANDOFF) => return Ok(()),
            Err(error) => return Err(error),
        };
        self.restore_captured_public_metadata(&capture, otp, uid)?;
        let mut dek = zeroize::Zeroizing::new([0; 48]);
        // US-917: accepts the AEAD record (current) and the pre-US-917
        // plaintext DEK (open-only compat) — see `migration::read_openpgp_dek`.
        match migration::read_openpgp_dek(store, otp, uid, &mut dek) {
            Ok(()) => {
                // US-918: bound device root (boot-entropy slot; fail-closed).
                let kek = migration::native_openpgp_wrapping_key(store, otp, uid, &capture.source())?;
                self.restore_captured_private_key(&kek, &capture, otp, uid, &dek)
            }
            Err(migration::MigrationError::Store(SecureStoreError::NotFound)) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Complete the authenticated OpenPGP capture and flush runtime state before
    /// importing the signing key or acknowledging completion. Retains the source.
    /// `nonce` is the fresh per-record US-917 draw for the AEAD DEK rewrap
    /// (platform TRNG at the call sites; US-380).
    #[allow(clippy::too_many_arguments)]
    pub fn complete_migration<S: fapico2_platform::cfs::CFlashSource + ?Sized,
        K: fapico2_platform::secure_store::SecureStore>(
        &mut self, flash: &S, part: fapico2_platform::cflash::DataPartition,
        store: &mut K, otp: &[u8; 32], uid: &[u8],
        bufs: &mut fapico2_platform::migration::MigrationBuffers, pin: &[u8],
        nonce: &[u8; 12],
        sink: &mut dyn fapico2_platform::persist::ImageSink,
    ) -> Result<fapico2_platform::migration::ClassStatus, fapico2_platform::migration::MigrationError> {
        use fapico2_platform::{ckey::CKeyError, migration, persist, secure_store::SecureStoreError};
        let capture = migration::read_openpgp_capture(store, otp, uid, &mut bufs.scratch)?;
        let source = capture.source();
        // Validate destination ownership before spending attempts or changing state.
        self.restore_captured_public_metadata(&capture, otp, uid)?;
        if self.card.migration_pin_ready(source).map_err(|_| CKeyError::BadFormat)? {
            migration::commit_captured_openpgp_pw1_handoff(store)?;
            if !persist::snapshot_and_program(store, sink) { return Err(SecureStoreError::Corrupt.into()); }
            return Ok(migration::ClassStatus::Migrated);
        }
        let status = if migration::captured_openpgp_pw1_handoff_pending(store)? {
            migration::verify_pending_openpgp_pw1(store, otp, uid, bufs, pin).map(|result| {
                match result {
                    migration::CapturedPinResult::Verified => migration::ClassStatus::Migrated,
                    migration::CapturedPinResult::Unsupported => migration::ClassStatus::NotMigratable,
                    _ => migration::ClassStatus::NeedsPassphrase,
                }
            })
        } else {
            if migration::captured_openpgp_pw1_handed_off(store)? {
                return Err(SecureStoreError::Corrupt.into());
            }
            migration::complete_passphrase_class(flash, part, store, otp, uid, bufs, 1, nonce, pin)
        };
        // Flush even rejected attempts and unwrap errors; never release a key if
        // the durable budget update cannot be written.
        if !persist::snapshot_and_program(store, sink) { return Err(SecureStoreError::Corrupt.into()); }
        let status = status?;
        if status != migration::ClassStatus::Migrated { return Ok(status); }
        let capture = migration::read_openpgp_capture(store, otp, uid, &mut bufs.scratch)?;
        let maximum = *capture.record(0x10c5)?.ok_or(CKeyError::BadFormat)?
            .get(1).ok_or(CKeyError::BadLength)?;
        let mut dek = zeroize::Zeroizing::new([0; 48]);
        // US-917: the completion just (re-)wrote the AEAD record.
        migration::read_openpgp_dek(store, otp, uid, &mut dek)?;
        // US-918: bound device root (boot-entropy slot; fail-closed) — derived
        // before the private-key install so a missing slot refuses first.
        let kek = migration::native_openpgp_wrapping_key(store, otp, uid, &source)?;
        self.restore_captured_private_key(&kek, &capture, otp, uid, &dek)?;
        // Retire the C retry route durably BEFORE installing a native PIN.
        // A power loss here leaves a pending, fail-closed credential rather
        // than two independently usable counters. Never retry conversion over
        // an occupied native credential without its source completion record.
        migration::begin_captured_openpgp_pw1_handoff(store)?;
        if !persist::snapshot_and_program(store, sink) { return Err(SecureStoreError::Corrupt.into()); }
        self.card.restore_migration_pin(source, pin, maximum, &kek)
            .map_err(|_| CKeyError::BadFormat)?;
        migration::commit_captured_openpgp_pw1_handoff(store)?;
        if !persist::snapshot_and_program(store, sink) { return Err(SecureStoreError::Corrupt.into()); }
        Ok(status)
    }

    /// Initialize migration-owned public metadata from the authenticated
    /// capture in the device secure store. Does not install credentials or
    /// private keys. Idempotent for the same source; refuses occupied state.
    pub fn restore_public_metadata<K: fapico2_platform::secure_store::SecureStore>(
        &mut self,
        store: &mut K,
        otp: &[u8; 32],
        uid: &[u8],
        bufs: &mut fapico2_platform::migration::MigrationBuffers,
    ) -> Result<(), fapico2_platform::migration::MigrationError> {
        let capture = fapico2_platform::migration::read_openpgp_capture(
            store, otp, uid, &mut bufs.scratch,
        )?;
        self.restore_captured_public_metadata(&capture, otp, uid)
    }

    // Validate every advertised algorithm, including slots without a key and
    // both aliases. An unsupported alias must never hide behind a supported one.
    fn preflight_profile(
        capture: &fapico2_platform::migration::OpenPgpCapture<'_>,
    ) -> Result<(), fapico2_platform::migration::MigrationError> {
        use fapico2_platform::ckey::CKeyError;
        for (fid, expected) in [
            (0x10c1, &[0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7][..]),
            (0x10c2, &[0x12, 0x2b, 6, 1, 4, 1, 0x97, 0x55, 1, 5, 1][..]),
            (0x10c3, &[0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7][..]),
        ] {
            for alias in [fid, fid & 0xff] {
                if let Some(attribute) = capture.record(alias)? {
                    if attribute != expected { return Err(CKeyError::BadFormat.into()); }
                }
            }
        }
        for (tag, maximum) in [(0x005b, 39usize), (0x5f2d, 8), (0x5f35, 1),
            (0x0101, 4096), (0x0102, 4096)] {
            if let Some(value) = capture.record(tag)? {
                if value.len() > maximum || (tag == 0x5f2d && value.len() % 2 != 0)
                    || (tag == 0x5f35 && !matches!(value.first(), Some(0x30..=0x32) | Some(0x39))) {
                    return Err(CKeyError::BadLength.into());
                }
            }
        }
        // Encrypted private DOs need user/admin KEKs the capture cannot supply.
        for tag in [0x0103, 0x0104, 0x1099] {
            if capture.record(tag)?.is_some() { return Err(CKeyError::BadFormat.into()); }
        }
        Ok(())
    }

    /// Initialize from an already authenticated capture. Keeping capture loading
    /// separate lets the authentication backend exclusively own the secure store.
    pub fn restore_captured_public_metadata(
        &mut self,
        capture: &fapico2_platform::migration::OpenPgpCapture<'_>,
        otp: &[u8; 32],
        uid: &[u8],
    ) -> Result<(), fapico2_platform::migration::MigrationError> {
        Self::preflight_profile(capture)?;
        let name = capture
            .record(0x005B)?
            .ok_or(fapico2_platform::ckey::CKeyError::BadFormat)?;
        // PIN length is stored in each C verifier record, not in retry DOs.
        let user = capture.record(0x1081)?.ok_or(fapico2_platform::ckey::CKeyError::BadFormat)?;
        let admin = capture.record(0x1083)?.ok_or(fapico2_platform::ckey::CKeyError::BadFormat)?;
        if !matches!(user.len(), 33 | 34) || !matches!(admin.len(), 33 | 34) {
            return Err(fapico2_platform::ckey::CKeyError::BadLength.into());
        }
        let user_pin_len = user[0];
        let admin_pin_len = admin[0];
        let reset_code_pin_len = match capture.record(0x1082)? {
            Some(record) => Some(*record.first().ok_or(fapico2_platform::ckey::CKeyError::BadLength)?),
            None => None,
        };
        let mut public = [0; 128];
        let signing = match capture.read_public_key(0x10d1, otp, uid, &mut public)? {
            None => None,
            Some(n) => {
                use fapico2_platform::ckey::CKeyError;
                if n != 70 || public[..6] != [0x7f, 0x49, 0x43, 0x86, 0x41, 0x04]
                    || capture.record(0x10c1)?.or(capture.record(0x00c1)?)
                        != Some(&[0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7][..])
                {
                    return Err(CKeyError::BadFormat.into());
                }
                let count = capture.record(0x0093)?.ok_or(CKeyError::BadFormat)?;
                if count.len() != 3 { return Err(CKeyError::BadLength.into()); }
                Some(opcard::MigrationSigningIdentity {
                    point: public[6..70].try_into().map_err(|_| CKeyError::BadLength)?,
                    fingerprint: capture.record(0x00c7)?.ok_or(CKeyError::BadFormat)?
                        .try_into().map_err(|_| CKeyError::BadLength)?,
                    date: capture.record(0x00ce)?.ok_or(CKeyError::BadFormat)?
                        .try_into().map_err(|_| CKeyError::BadLength)?,
                    count: u32::from_be_bytes([0, count[0], count[1], count[2]]),
                })
            }
        };
        let mut decryption_public = [0; 128];
        let decryption = match capture.read_public_key(0x10d2, otp, uid, &mut decryption_public)? {
            None => None,
            Some(n) => {
                use fapico2_platform::ckey::CKeyError;
                if n != 37 || decryption_public[..5] != [0x7f, 0x49, 0x22, 0x86, 0x20]
                    || capture.record(0x10c2)?.or(capture.record(0x00c2)?)
                        != Some(&[0x12, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01][..])
                {
                    return Err(CKeyError::BadFormat.into());
                }
                Some(opcard::MigrationDecryptionIdentity {
                    public: decryption_public[5..37].try_into().map_err(|_| CKeyError::BadLength)?,
                    fingerprint: capture.record(0x00c8)?.ok_or(CKeyError::BadFormat)?
                        .try_into().map_err(|_| CKeyError::BadLength)?,
                    date: capture.record(0x00cf)?.ok_or(CKeyError::BadFormat)?
                        .try_into().map_err(|_| CKeyError::BadLength)?,
                })
            }
        };
        let mut authentication_public = [0; 128];
        let authentication = match capture.read_public_key(0x10d3, otp, uid, &mut authentication_public)? {
            None => None,
            Some(n) => {
                use fapico2_platform::ckey::CKeyError;
                if n != 70 || authentication_public[..6] != [0x7f, 0x49, 0x43, 0x86, 0x41, 0x04]
                    || capture.record(0x10c3)?.or(capture.record(0x00c3)?)
                        != Some(&[0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7][..])
                {
                    return Err(CKeyError::BadFormat.into());
                }
                Some(opcard::MigrationAuthenticationIdentity {
                    point: authentication_public[6..70].try_into().map_err(|_| CKeyError::BadLength)?,
                    fingerprint: capture.record(0x00c9)?.ok_or(CKeyError::BadFormat)?
                        .try_into().map_err(|_| CKeyError::BadLength)?,
                    date: capture.record(0x00d0)?.ok_or(CKeyError::BadFormat)?
                        .try_into().map_err(|_| CKeyError::BadLength)?,
                })
            }
        };
        self.card.restore_public_metadata_with_profile(
            capture.source(), name, user_pin_len, admin_pin_len, reset_code_pin_len,
            signing, decryption, authentication,
            opcard::MigrationProfile {
                language: capture.record(0x5f2d)?.unwrap_or(&[]),
                sex: capture.record(0x5f35)?.and_then(|v| v.first().copied()),
                private_use_1: capture.record(0x0101)?,
                private_use_2: capture.record(0x0102)?,
            },
        ).map_err(|_| fapico2_platform::ckey::CKeyError::BadFormat)?;
        self.migration_active = true;
        Ok(())
    }

    /// Resume private restore only after the migration completion handler has
    /// durably unwrapped the 48-byte C DEK. The source remains retained.
    /// US-918: the native wrapping key (`kek`) is the bound device root —
    /// the caller derives it through
    /// [`migration::native_openpgp_wrapping_key`], which reads the store's
    /// boot-entropy slot and fails closed (no legacy fallback) when absent.
    pub fn restore_captured_private_key(
        &mut self,
        kek: &[u8; 32],
        capture: &fapico2_platform::migration::OpenPgpCapture<'_>,
        otp: &[u8; 32],
        uid: &[u8],
        dek: &[u8; 48],
    ) -> Result<(), fapico2_platform::migration::MigrationError> {
        use fapico2_platform::{ckey::CKeyError, migration};
        Self::preflight_profile(capture)?;
        // Decode and validate ALL present keys before calling any installer.
        // Fixed-size, no-heap secrets are wiped on every exit, including refusal.
        let mut scalars = zeroize::Zeroizing::new([[0u8; 32]; 3]);
        let mut present = [false; 3];
        let keys = [(0x10d1, 3), (0x10d2, 9), (0x10d3, 3)];
        for (index, (fid, tag)) in keys.into_iter().enumerate() {
            let mut private = zeroize::Zeroizing::new([0; 64]);
            let Some(n) = capture.read_private_key(fid, otp, uid, dek, &mut private[..])? else {
                continue;
            };
            if n != 33 || private[0] != tag {
                return Err(CKeyError::BadFormat.into());
            }
            scalars[index].copy_from_slice(&private[1..33]);
            let mut public = [0; 70];
            let n = capture.read_public_key(fid, otp, uid, &mut public)?
                .ok_or(CKeyError::BadFormat)?;
            if tag == 3 {
                if n != 70 || public[..6] != [0x7f, 0x49, 0x43, 0x86, 0x41, 0x04] {
                    return Err(CKeyError::BadFormat.into());
                }
                self.card.validate_migration_p256_key(&scalars[index],
                    public[6..70].try_into().map_err(|_| CKeyError::BadLength)?)
                    .map_err(|status| match status {
                        iso7816::Status::UnspecifiedPersistentExecutionError =>
                            migration::MigrationError::Store(fapico2_platform::secure_store::SecureStoreError::Corrupt),
                        _ => CKeyError::BadFormat.into(),
                    })?;
            } else {
                if n != 37 || public[..5] != [0x7f, 0x49, 0x22, 0x86, 0x20] {
                    return Err(CKeyError::BadFormat.into());
                }
                self.card.validate_migration_x25519_key(&scalars[index],
                    public[5..37].try_into().map_err(|_| CKeyError::BadLength)?)
                    .map_err(|status| match status {
                        iso7816::Status::UnspecifiedPersistentExecutionError =>
                            migration::MigrationError::Store(fapico2_platform::secure_store::SecureStoreError::Corrupt),
                        _ => CKeyError::BadFormat.into(),
                    })?;
            }
            present[index] = true;
        }
        // Installation retains existing per-key resume semantics. Storage
        // failures here are not input-preflight refusals or a transaction rollback.
        for (index, (fid, _)) in keys.into_iter().enumerate() {
            if !present[index] { continue; }
            let scalar = &scalars[index];
            let restore = match fid {
                0x10d1 => self.card.restore_migration_signing_key(capture.source(), scalar, kek),
                // C's Montgomery scalar is already little-endian, unlike GnuPG's import template.
                0x10d2 => self.card.restore_migration_decryption_key(capture.source(), scalar, kek),
                _ => self.card.restore_migration_authentication_key(capture.source(), scalar, kek),
            };
            restore.map_err(|status| match status {
                iso7816::Status::UnspecifiedPersistentExecutionError =>
                    migration::MigrationError::Store(fapico2_platform::secure_store::SecureStoreError::Corrupt),
                _ => CKeyError::BadFormat.into(),
            })?;
        }
        Ok(())
    }

    /// Run one APDU through opcard. Returns the status word; on success the
    /// opcard reply (if any) is staged in the scratch buffer, sized to the
    /// request Le, for the caller to append to `resp` (SELECT appends the
    /// FCI instead — opcard's SELECT writes no reply data).
    ///
    /// Reply sizing (S-723-A2): upstream opcard splits oversized replies at
    /// the apdu-dispatch seam — `vendor/opcard/src/vpicc.rs`
    /// `ResponseBuffer` serves at most the request's Le bytes and answers
    /// `61XX` (remaining count) until GET RESPONSE (INS C0) drains the
    /// rest. That seam is exactly what this app replaces, so the same
    /// semantics live here: the scratch buffer stages the full composed
    /// reply and `serve` honors Le across exchanges. Without it, gpg's
    /// short-Le `00 CA 00 6E 00` (Le = 256) met the full 272-byte wire
    /// reply and scd's `le + 2` buffer truncated it (EPIC S723-REPAIR C1).
    fn run(&mut self, apdu: &[u8], resp: &mut heapless::Vec<u8, MAX_RESPONSE>) -> Sw {
        // Bare SELECT MF is a compatibility no-op only in the selected app;
        // it must neither reselect opcard nor change authentication state.
        if apdu == [0x00, 0xA4, 0x00, 0x00, 0x00] {
            return SW_OK;
        }
        // US-181 (PICOForge-COMPAT): resolve the receive-side chain **before**
        // anything parses the command. opcard cannot do this for us — its
        // `Command::try_from` has no CLA gate (`vendor/opcard/src/command.rs:118`)
        // and `Card::handle` requires a complete command
        // (`vendor/opcard/src/card.rs:236`) — so a `cla|0x10` fragment reaches
        // `parse_lengths` as an ordinary case-3S body with `lc = 255` and is
        // then refused on the truncated TLV (`vendor/opcard/src/tlv.rs:32-34`).
        //
        // Four outcomes, and the second one is the one a reader will forget:
        //
        // * `Pass` — no chain in progress. `apdu` is the caller's own slice
        //   and the code below is byte-for-byte what it always was.
        // * `Buffered` — a non-final fragment. Dispatch **nothing** and answer
        //   `9000`, because PicoForge hard-fails on any other status
        //   (`picoforge/src/hal/transport/ccid.rs:129-131`). Note that this is
        //   also why `6Cxx` is never the answer to a broken chain: it would
        //   make `transceive_paged` re-send the fragment and the bytes would
        //   land in the accumulator twice. See `ChainError::status`.
        // * `Complete` — `self.chain.apdu()` is the whole command.
        // * `Broken` — the accumulated bytes are gone; answer the error.
        let apdu = match self.chain.push(apdu) {
            Step::Pass => apdu,
            Step::Buffered => return SW_OK,
            Step::Complete => self.chain.apdu(),
            Step::Broken(err) => return Sw::from(err.status()),
        };
        let command = match iso7816::command::CommandView::try_from(apdu) {
            Ok(cmd) => cmd,
            Err(_) => return SW_INS_NOT_SUPPORTED,
        };
        if command.instruction() != iso7816::Instruction::GetResponse {
            self.scratch.clear();
            self.scratch_offset = 0;
            let scratch_view: &mut heapless09::VecView<u8> = &mut self.scratch;
            if let Err(status) = self.card.handle(command, scratch_view) {
                // A failed command must not leave reply data staged: the
                // touch-to-sign refusal (US-914) fires inside opcard now,
                // so a refusal must not serve stale data through GET
                // RESPONSE either.
                self.scratch.clear();
                self.scratch_offset = 0;
                return Sw::from(status);
            }
        }
        self.serve(command.expected(), resp)
    }

    /// Serve the staged reply honoring the request Le: at most `le` bytes
    /// per exchange, `61XX` with the remaining count while more is pending
    /// (the vpicc `ResponseBuffer::response` semantics). A GET RESPONSE
    /// with nothing staged answers an empty 9000, like upstream.
    fn serve(&mut self, le: usize, resp: &mut heapless::Vec<u8, MAX_RESPONSE>) -> Sw {
        // ISO 7816 parses a short Le of 0x00 and an absent Le field alike
        // as 0; hosts mean "up to 256" in both cases — gpg's GENERATE is a
        // case-3 APDU (CRT `B6 00` is Lc data, no Le) whose 37-byte reply
        // is expected in full, and scd reads `6100` as Le = 256.
        let le = if le == 0 { 256 } else { le };
        let available = self.scratch.len() - self.scratch_offset;
        let n = le.min(available);
        resp.extend_from_slice(&self.scratch[self.scratch_offset..][..n]).ok();
        self.scratch_offset += n;
        match self.scratch.len() - self.scratch_offset {
            0 => SW_OK,
            rest => Sw::from(iso7816::Status::MoreAvailable(
                u8::try_from(rest).unwrap_or(u8::MAX),
            )),
        }
    }
}

impl<T: opcard::Client> App for OpenPgpApp<T> {
    fn aid(&self) -> &[u8] {
        OPENPGP_AID
    }

    fn select(&mut self, _internal: bool) -> Sw {
        // The SELECT APDU itself is routed through `select_apdu` so the FCI
        // is returned; a bare re-select without payload just answers OK.
        //
        // US-181: a SELECT must also drop a half-accumulated command chain.
        // The chain belongs to the *previous* selection, and a client that
        // abandoned it mid-stream must not have its bytes prepended to the
        // next command after the re-select.
        self.chain.reset();
        SW_OK
    }

    fn select_apdu(
        &mut self,
        _internal: bool,
        apdu: &[u8],
        resp: &mut heapless::Vec<u8, MAX_RESPONSE>,
    ) -> Sw {
        self.scratch.clear();
        self.chain.reset();
        let scratch_view: &mut heapless09::VecView<u8> = &mut self.scratch;
        let command = match iso7816::command::CommandView::try_from(apdu) {
            Ok(cmd) => cmd,
            Err(_) => return SW_INS_NOT_SUPPORTED,
        };
        match self.card.handle(command, scratch_view) {
            // opcard's SELECT writes no FCI — append the synthesized one
            // (the dispatcher appends the SW after `select_apdu`).
            Ok(()) => {
                resp.extend_from_slice(SELECT_FCI).ok();
                SW_OK
            }
            // Error: return the opcard status with no data.
            Err(status) => Sw::from(status),
        }
    }

    fn deselect(&mut self) {
        self.card.reset();
        // Drop any staged reply chunk with the session (S-723-A2).
        self.scratch.clear();
        self.scratch_offset = 0;
        // US-181: and any half-received command chain, for the same reason
        // `select` does — a chain is per-selection state, and this is where
        // the OpenPGP applet already drops the rest of it.
        self.chain.reset();
    }

    fn process(&mut self, apdu: &[u8], resp: &mut heapless::Vec<u8, MAX_RESPONSE>) {
        // The dispatcher appends nothing after `process` — the app writes
        // both the data and the status word itself.
        // Compatibility authentication mutates the shared secure store, not
        // Trussed files. The transport must persist even rejected commands.
        self.migration_dirty |= self.migration_active;
        let sw = self.run(apdu, resp);
        let sw_bytes = sw.to_be_bytes();
        // Unreachable in practice (opcard errors on oversized output before
        // the scratch fills), but a drop here would corrupt the APDU
        // dialogue — panic in debug, keep the old `.ok()` tolerance in
        // release.
        debug_assert!(
            resp.len() + sw_bytes.len() <= MAX_RESPONSE,
            "process: response scratch full — SW dropped"
        );
        resp.extend_from_slice(&sw_bytes).ok();
    }

    fn persist_state(&mut self, _store: &mut dyn fapico2_platform::secure_store::SecureStore) -> bool {
        // The authority already wrote RAM state; request its durable snapshot.
        core::mem::take(&mut self.migration_dirty)
    }

    fn mark_dirty(&mut self) {
        self.migration_dirty = true;
        self.card.reset();
        // Drop any staged reply chunk with the session (S-723-A2).
        self.scratch.clear();
        self.scratch_offset = 0;
        // US-181: a factory reset that re-arms the card must not leave a
        // partial `PUT DATA` queued to be appended to the first command after
        // it. Same rule, same reason as `select`.
        self.chain.reset();
    }

    fn is_dirty(&self) -> bool {
        self.migration_dirty
    }

    /// US-711: the management RESET hook — re-initialize the card in RAM so
    /// a later command can never re-persist the pre-reset state
    /// ([`opcard::Card::reset`]: volatile authentication cleared, card state
    /// back to factory default, so the next durable save writes
    /// factory-fresh opcard state). The durable OpenPGP slots
    /// (`openpgp.keystore.v1`, `openpgp.dek.v1`) are deleted device-wide by
    /// the management RESET hook (`DeviceFactoryResetHandler`); this hook
    /// must not touch the shared store (the sole `&mut` belongs to the
    /// owning transport) — it only clears the in-RAM state the persist gate
    /// would otherwise flush (the migration dirtiness that asks the gate
    /// for a snapshot-and-program of the pre-reset card).
    fn factory_wipe(&mut self) {
        self.card.reset();
        self.migration_active = false;
        self.migration_dirty = false;
        // Drop any staged reply chunk with the session (S-723-A2).
        self.scratch.clear();
        self.scratch_offset = 0;
    }
}

/// US-150: fold a raw entropy draw into packed BCD — every nibble becomes a
/// decimal digit 0-9, so the four serial bytes always read back as an
/// eight-digit decimal.
///
/// The OpenPGP AID serial (spec §4.2.1, `AID[10..14]`) is consumed as packed
/// BCD: hosts render it digit-per-nibble with no validity check of their own,
/// so a draw that happens to carry a nibble above 9 prints as a garbage
/// serial on the host while the card considers it perfectly valid. Folding at
/// the draw makes the property structural instead of lucky.
///
/// Forward-only by design (see [`OpenPgpApp::provision_serial`]): a serial
/// already persisted on a fielded card is that card's host-visible identity
/// and is never rewritten.
fn to_bcd(drawn: [u8; 4]) -> [u8; 4] {
    let mut serial = [0u8; 4];
    for (byte, raw) in serial.iter_mut().zip(drawn.iter()) {
        *byte = (((raw >> 4) % 10) << 4) | ((raw & 0x0F) % 10);
    }
    serial
}

/// Draw a packed-BCD serial, redrawing while the fold lands on all zeros.
///
/// `draw` returns the next raw entropy draw, or `None` when the entropy
/// source is unavailable — then the spec's §4.2.1 increment-counter start is
/// the serial (already valid BCD, and non-zero, so no redraw applies). The
/// all-zero test is on the *folded* value, not the raw draw: modulo ten maps
/// `0x0A`, `0xA0` and `0xAA` onto `0x00`, so a non-zero draw can still
/// collapse onto the meaningless all-zero serial.
fn draw_bcd_serial(mut draw: impl FnMut() -> Option<[u8; 4]>) -> [u8; 4] {
    loop {
        match draw() {
            None => return [0x00, 0x00, 0x00, 0x01],
            Some(drawn) => {
                let serial = to_bcd(drawn);
                if serial != [0; 4] {
                    return serial;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{draw_bcd_serial, to_bcd};

    /// Every value a single serial byte can take must fold to two decimal
    /// digits — checked over the full 0x00..=0xFF range rather than a
    /// sample, because a single unchecked input byte is a serial that
    /// prints wrong on the host.
    #[test]
    fn to_bcd_folds_every_byte_to_decimal_nibbles() {
        for raw in 0u16..=0xFF {
            let folded = to_bcd([raw as u8, 0, 0, 0])[0];
            assert!(
                folded >> 4 <= 9 && folded & 0x0F <= 9,
                "0x{raw:02X} folded to 0x{folded:02X}, which is not packed BCD"
            );
        }
    }

    /// The fold is a decimal rendering, not a bit splice: each nibble is
    /// taken modulo ten, so a raw nibble of 0x0A renders as the digit 0 and
    /// 0x0F as 5.
    #[test]
    fn to_bcd_renders_each_nibble_as_its_decimal_digit() {
        assert_eq!(to_bcd([0x12, 0x34, 0x56, 0x78]), [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(to_bcd([0x0A, 0xA0, 0xAA, 0xFF]), [0x00, 0x00, 0x00, 0x55]);
    }

    /// A redraw must be asked for while the fold is meaningless: the raw
    /// draws here are all non-zero, but each folds onto all zeros, and the
    /// serial actually returned must come from the draw after them.
    #[test]
    fn all_zero_fold_is_redrawn_not_returned() {
        let mut draws = vec![
            [0x00, 0x00, 0x00, 0x00],
            [0x0A, 0xA0, 0xAA, 0x00], // every nibble is 10 -> folds to zero
            [0xAB, 0xCD, 0xEF, 0x12],
        ]
        .into_iter();
        let mut calls = 0;
        let serial = draw_bcd_serial(|| {
            calls += 1;
            draws.next()
        });
        assert_eq!(calls, 3, "the two all-zero folds must each be redrawn");
        assert_ne!(serial, [0; 4], "an all-zero serial is meaningless");
        assert_eq!(serial, to_bcd([0xAB, 0xCD, 0xEF, 0x12]));
    }

    /// No entropy source: the §4.2.1 increment-counter start is returned
    /// without redrawing, and it is already valid packed BCD.
    #[test]
    fn no_entropy_falls_back_to_the_increment_counter_start() {
        let mut calls = 0;
        let serial = draw_bcd_serial(|| {
            calls += 1;
            None
        });
        assert_eq!(calls, 1, "a failed draw must not spin");
        assert_eq!(serial, [0x00, 0x00, 0x00, 0x01]);
    }
}
