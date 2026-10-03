//! Device-side FIDO shell (US-386, no_std).
//!
//! The host `app.rs` stack (3200+ lines of CTAP2.1 crypto, U2F, attestation,
//! PIN, keystore) is std-only. This module is the no_std stand-in the RP2350
//! serve loop wires behind the HID transport:
//!
//! * derives the persistent P-256 key-agreement key (`hkey`) from the
//!   platform TRNG (the sole randomness source, US-380) — the same derivation
//!   the host `with_keystore` performs;
//! * answers CTAP2 `getInfo` (0x04) with a real, hand-written CBOR info map;
//! * answers everything else with the matching CTAP/U2F error so a CTAP client
//!   sees a well-formed (if feature-poor) authenticator.
//!
//! Full CTAP2 crypto, U2F, attestation and PIN on device land with the
//! SecureStore keystore (US-387) and reboot persistence (US-388); live-USB
//! `lsusb`/SELECT acceptance is Phase 6.

use fapico2_platform::secure_store::{SecureStore, SecureStoreError};
use crate::crypto::TrngAdapter;
use crate::device_keystore::DeviceKeystore;
use fapico2_platform::trng::Trng;

/// SecureStore key under which the persistent `hkey` is stored (US-387). The
/// RP2350 secure partition backs the store on device — the secret never
/// touches plain flash. `pub` so the firmware's US-711 factory-reset handler
/// can wipe it by the same name it boots from.
pub const HKEY_KEY: &[u8] = b"fido.hkey";

/// CTAP2_ERR_INVALID_COMMAND — the shell's answer to every command it does
/// not (yet) implement. Matches the host `Ctap2Response::InvalidCommand`.
const CTAP2_ERR_INVALID_COMMAND: u8 = 0x01;


/// Minimal no_std FIDO authenticator: TRNG-derived P-256 `hkey` + a real
/// `getInfo`. All command handlers return the matching error byte until the
/// US-387/US-388 keystore lands.
/// Pending getAssertion enumeration state (S-701-4): remaining credential
/// IDs served one-per-getNextAssertion on the same channel.
pub struct DeviceGaState {
    pub(crate) remaining: heapless::Vec<heapless::Vec<u8, 64>, { crate::device_keystore::DEVICE_MAX_CREDS }>,
    pub(crate) client_data_hash: [u8; 32],
    pub(crate) uv: bool,
    pub(crate) do_up: bool,
    pub(crate) total: usize,
    pub(crate) channel: [u8; 4],
}

pub struct FidoApp {
    /// Persistent P-256 key agreement key (ECDH `hkey`).
    pub(crate) hkey: p256::SecretKey,
    /// US-916: the per-device attestation identity (TRNG-minted key +
    /// on-device self-signed cert), provisioned through the secure store at
    /// boot — no repo-committed attestation material exists any more.
    pub(crate) attestation: crate::attestation::AttestationIdentity,
    /// S-701-3: the persisted credential/PIN state (chunked
    /// `fido.keystore.v1` snapshot).
    pub(crate) keystore: DeviceKeystore,
    // ---- S-701-4 session state (volatile; never persisted) ----
    /// US-176: the RS-Key `0x41` **volatile** state — the "unlocked this
    /// power cycle" flag and the current MSE channel.
    ///
    /// On the app and not in the keystore, and that is the whole point: the
    /// durable half is `keystore.vendor` (snapshot auth keys 7 and 8), and
    /// putting these two beside it would make "this power cycle" survive the
    /// power cycle it is named after. `~76` bytes of `.bss` for that class of
    /// mistake is the cheapest fix available.
    pub(crate) vendor_session: crate::vendor_state::VendorSession,
    /// Raw 32-byte PIN token minted by getPinToken / 0x09.
    pub(crate) pin_token: Option<[u8; 32]>,
    /// Permissions bound to the current token (0 = legacy getPinToken: MC+GA).
    pub(crate) token_permissions: u8,
    /// rpId binding of the current token (empty = unbound).
    pub(crate) token_rp_id: heapless::Vec<u8, 64>,
    /// Pending getAssertion enumeration.
    pub(crate) ga_pending: Option<DeviceGaState>,
    /// Volatile per-session pinUvAuth-failure streak (US-909: the PIN
    /// mismatch counter and 3-strike latch live durably in
    /// `keystore.pin_state`; only this streak stays session-scoped).
    pub(crate) auth_failures: u8,
    /// Channel of the CTAP-HID transaction currently being served.
    pub(crate) current_channel: [u8; 4],
    /// US-380: boot-time TRNG pool (the serve loop has no TRNG handle; the
    /// pool is filled from the platform TRNG at boot and stretched with a
    /// keyed hash when exhausted — every random byte is TRNG-derived).
    pub(crate) rng_pool: heapless::Vec<u8, 512>,
    pub(crate) rng_cursor: usize,
    // ---- S-701-5 command-set state (volatile) ----
    /// Pending credMgmt RP enumeration (RP id + hash pairs, cursor, channel).
    pub(crate) cm_rp_state: Option<CmRpState>,
    /// Pending credMgmt credential enumeration.
    pub(crate) cm_cred_state: Option<CmCredState>,
    /// Which CBOR dialect the credMgmt command being served arrived in. The
    /// response encoders read this: the PicoForge and CTAP2 key sets collide
    /// (see `device_core::CmDialect`), so a request has to be answered in the
    /// shape its sender asked in.
    pub(crate) cm_dialect: crate::device_core::CmDialect,
    /// Pending largeBlobs write (fragment assembly).
    pub(crate) lb_pending: Option<LbPending>,
    /// Pending vault enrollment (vendor 0x41 0x05 ENROLL_BEGIN state).
    pub(crate) vault_pending: Option<VaultPending>,
    /// US-907: user-presence source (board button poll on device). `None`
    /// uses the build default: fail-closed on the device build, auto-ack on
    /// host/emulation (`device_core::default_user_present`).
    pub(crate) presence: Option<fn() -> bool>,
    /// US-921: the whole grant path (pending request + latch binding) when
    /// the runtime owns the shared presence service (device wiring). Takes
    /// precedence over `presence` — the shared runtime IS the grant path.
    pub(crate) presence_grant: Option<fn(u32) -> bool>,
}

/// US-426: the canonical FIDO2 AID the shell answers to as a dispatcher
/// `App` — matches the `AID_FIDO2` constant in the platform dispatcher
/// tests (`platform/src/dispatch.rs`).
pub const FIDO_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

/// The fixed CTAP channel the APDU bridge (`App::process`) binds the shell's
/// per-channel session state to: the dispatcher transport is not CTAP-HID,
/// so there is no per-connection channel to bind to — every bridged command
/// routes through this one.
const BRIDGE_CHANNEL: [u8; 4] = [0, 0, 0, 1];

/// US-921 review (P0-1): domain-separate the presence tag space. The HID
/// transport derives its consent tag from the CTAP-HID channel; without the
/// high bit, an allocated CID eventually equals a CCID presence tag (mgmt
/// WRITE_CONFIG=0x1C, RESET=0x1E, OATH RESET=0x04/0x03) and
/// `PresenceRuntime::window_grant`'s same-tag join would let a CCID
/// destructive command consume a press that consented to a FIDO touch (and
/// vice versa). Setting bit 31 carves the HID domain out of the
/// small-integer CCID tag space; `CidAllocator` (firmware/src/ctap_hid.rs)
/// never issues channels with the bit set, so the two spaces stay disjoint.
/// The raw CID itself (GA/credMgmt channel-equality checks) is NOT
/// domain-separated — only the presence tag.
pub fn presence_tag_from_channel(channel: [u8; 4]) -> u32 {
    0x8000_0000 | u32::from_be_bytes(channel)
}

/// US-426: FIDO satisfies the same `App::persist_state` contract as
/// OATH/OTP/mgmt/OpenPGP, so registering it into any dispatcher persists it
/// through the platform persist gate automatically — zero per-transport
/// code. The keystore's dirty flag is authoritative
/// (`persist_state` → `persist_if_dirty`); the platform blanket
/// `impl<T: App> Persist for T` now serves the `persist_one` call sites the
/// HID transports keep (identical behavior to the deleted direct `Persist`
/// impl of US-421).
impl fapico2_platform::dispatch::App for FidoApp {
    fn aid(&self) -> &[u8] {
        &FIDO_AID
    }

    fn select(&mut self, _internal: bool) -> fapico2_platform::dispatch::Sw {
        // No side effects: the CTAP session state is per-CTAP-channel, not
        // per-SELECT (a SELECT here never means a new CTAP-HID connection).
        fapico2_platform::dispatch::SW_OK
    }

    fn deselect(&mut self) {
        // Connection tear-down / foreign-transport switch: drop the volatile
        // session state (token, mismatch counters, enumeration cursors).
        self.clear_session_state()
    }

    fn process(
        &mut self,
        apdu: &[u8],
        resp: &mut heapless::Vec<u8, { fapico2_platform::dispatch::MAX_RESPONSE }>,
    ) {
        // Minimal APDU→CTAP2 bridge: the INS byte is the CTAP2 command, the
        // short-form Lc at [4] bounds the CBOR payload at [5..]. (The
        // dispatcher is not a CTAP transport; this shape exists so any
        // dispatcher can drive the shell's command path.)
        let Some(ins) = apdu.get(1).copied() else {
            let _ = resp.extend_from_slice(
                &fapico2_platform::dispatch::SW_INS_NOT_SUPPORTED.to_be_bytes(),
            );
            return;
        };
        let lc = apdu.get(4).copied().unwrap_or(0) as usize;
        let data = apdu.get(5..5 + lc).unwrap_or(&[]);
        let mut local = heapless::Vec::<u8, { crate::CTAP2_MAX_MSG }>::new();
        let n = self
            .process_ctap2(ins, data, BRIDGE_CHANNEL, &mut local)
            .min(fapico2_platform::dispatch::MAX_RESPONSE - 2);
        // A CTAP response longer than `MAX_RESPONSE - 2` is truncated here
        // (the 2 bytes are reserved for the appended status word); the
        // dispatcher PDU bound is smaller than `CTAP2_MAX_MSG`.
        let _ = resp.extend_from_slice(&local.as_slice()[..n]);
        let _ = resp.extend_from_slice(&fapico2_platform::dispatch::SW_OK.to_be_bytes());
    }

    fn persist_state(&mut self, store: &mut dyn SecureStore) -> bool {
        self.persist_if_dirty(store)
    }

    fn mark_dirty(&mut self) {
        self.keystore.dirty = true;
    }

    fn is_dirty(&self) -> bool {
        self.keystore.dirty
    }
}

/// credMgmt RP enumeration state.
pub struct CmRpState {
    pub(crate) rps: heapless::Vec<([u8; 32], heapless::Vec<u8, 64>), { crate::device_keystore::DEVICE_MAX_CREDS }>,
    pub(crate) cursor: usize,
    pub(crate) channel: [u8; 4],
    /// The dialect of the `enumerateRpsBegin` that armed this enumeration.
    ///
    /// A Next request cannot be classified from its own bytes: PicoForge and
    /// CTAP2 both send exactly `{1: 0x03}` for `enumerateRpsNext`, because
    /// the Next sub-commands carry no `pinUvAuthParam` in either dialect —
    /// the layouts are indistinguishable here. The enumeration is a
    /// continuation, so it is answered in the dialect that started it.
    pub(crate) dialect: crate::device_core::CmDialect,
}

/// credMgmt credential enumeration state.
pub struct CmCredState {
    pub(crate) creds: heapless::Vec<heapless::Vec<u8, 64>, { crate::device_keystore::DEVICE_MAX_CREDS }>,
    pub(crate) total: usize,
    pub(crate) channel: [u8; 4],
    /// See [`CmRpState::dialect`] — `enumerateCredentialsGetNextCredential`
    /// is likewise `{1: 0x05}` and nothing else in both dialects.
    pub(crate) dialect: crate::device_core::CmDialect,
}

/// largeBlobs fragment assembly state.
pub struct LbPending {
    pub(crate) total: usize,
    pub(crate) buf: heapless::Vec<u8, { crate::device_keystore::LARGE_BLOB_MAX }>,
}

/// Pending vault enrollment: device X448 secret/public and the challenge.
pub struct VaultPending {
    pub(crate) secret: [u8; 56],
    pub(crate) public: [u8; 56],
    pub(crate) challenge: [u8; 32],
}

impl FidoApp {
    /// Derive the persistent `hkey` from the platform TRNG (the sole
    /// randomness source on device, US-380). Mirrors the host
    /// `FidoApp::with_keystore` derivation (`SecretKey::random` over a
    /// TRNG-backed RNG).
    ///
    /// # Why this is `Result` (US-1005 fix)
    ///
    /// It is `Result` because of the **keystore**, not the `hkey`. The
    /// keystore's `device_random` is a plain draw into a zero-initialised
    /// buffer, so a refused infallible draw installs 32 zero bytes as the
    /// seed of the device's stateless U2F master — a value anyone can
    /// derive. `DeviceKeystore::fresh` now refuses rather than do that, and
    /// this constructor has to carry the refusal out to its own caller
    /// rather than swallow it.
    pub fn new<R: Trng>(
        trng: &mut R,
    ) -> Result<Self, fapico2_platform::trng::TrngError> {
        let mut adapter = TrngAdapter(trng);
        let hkey = p256::SecretKey::random(&mut adapter);
        let keystore = DeviceKeystore::fresh(trng)?;
        // US-916: ephemeral identity (no store to persist through — the
        // persisted identity is the `boot` contract).
        let attestation = crate::attestation::AttestationIdentity::generate_from(trng);
        let mut app = Self {
            hkey,
            attestation,
            keystore,
            vendor_session: crate::vendor_state::VendorSession::default(),
            pin_token: None,
            token_permissions: 0,
            token_rp_id: heapless::Vec::new(),
            ga_pending: None,
            auth_failures: 0,
            current_channel: [0; 4],
            rng_pool: heapless::Vec::new(),
            rng_cursor: 0,
            cm_rp_state: None,
            cm_cred_state: None,
            cm_dialect: crate::device_core::CmDialect::default(),
            lb_pending: None,
            vault_pending: None,
            presence: None,
            presence_grant: None,
        };
        app.fill_rng_pool(trng);
        Ok(app)
    }

    /// Fill the TRNG pool (boot path; US-380 sole randomness source).
    fn fill_rng_pool<R: Trng>(&mut self, trng: &mut R) {
        self.rng_pool.clear();
        self.rng_cursor = 0;
        let mut chunk = [0u8; 64];
        for _ in 0..8 {
            trng.random_bytes(&mut chunk);
            if self.rng_pool.extend_from_slice(&chunk).is_err() {
                break;
            }
        }
    }

    /// Boot the authenticator (US-387): load the persistent `hkey` from the
    /// platform [`SecureStore`] — the RP2350 secure partition on device, the
    /// in-memory store + partition image on host. On a fresh partition the
    /// key is derived from the TRNG and persisted through the store. All app
    /// secret persistence routes through the store; plain flash is never
    /// touched.
    ///
    /// The firmware treats an `Err` return as a fatal boot condition: a
    /// corrupt/absent keystore would silently orphan every enrolled
    /// credential on the next reboot.
    // US-939: `#[inline(never)]` — the keystore decode internals (~10 KiB
    // scratch) must stay in this function's own frame, never merge into the
    // Embassy async-main frame (the dark-boot stack overflow).
    //
    // US-956: this is now a thin by-value wrapper over [`Self::boot_in_place`]
    // so the two can never diverge — the host/emulation suites and the device
    // boot path run the *same* construction; they differ only in where the
    // value lands.
    pub fn boot<R: Trng>(
        trng: &mut R,
        store: &mut dyn SecureStore,
    ) -> Result<Self, SecureStoreError> {
        let mut slot = core::mem::MaybeUninit::<Self>::uninit();
        // SAFETY: `slot` is a fresh local, valid for exactly one write of
        // `size_of::<Self>()` bytes, properly aligned, and aliased by nothing.
        // `boot_in_place` initializes every field before handing back the
        // sole reference; the read below moves the value out and ends it.
        let app = unsafe { Self::boot_in_place(&raw mut slot, trng, store)? };
        Ok(unsafe { core::ptr::read(app) })
    }

    /// US-956: the real boot, constructing **directly into a caller-provided
    /// `MaybeUninit` slot** and returning that slot's sole `&'static mut`.
    ///
    /// US-939 moved the app into `boot::FIDO_APP` but kept the value flowing
    /// *through* the stack: `boot_fido` reserved 15,744 B for the
    /// `Result<FidoApp, _>` sret destination and memcpy'd it into the slot,
    /// and this function reserved a second 15,724 B `Self` for the
    /// fresh-partition arm. Together with the inlined `DeviceKeystore` decode
    /// scratch that put the measured boot-path call chain at 117,828 B
    /// against a 5,056 B linker-leftover stack zone — the device could not
    /// boot. Writing the fields in place removes both copies: the app is
    /// materialized once, in the static that owns it.
    ///
    /// Every field is written explicitly, never by a blanket zero-fill: the
    /// fresh-app state is the literal `None` / `0` / empty-vector set below
    /// (what the by-value form produced), and a blanket memset would be wrong
    /// for any `Option` whose niche encoding does not read as `None` at zero.
    ///
    /// # Safety
    ///
    /// `slot` must be valid for writes of `size_of::<Self>()` bytes, properly
    /// aligned, and written exactly once — the write-once `static mut` slot
    /// discipline `boot::init_static_slot` establishes for every sibling
    /// slot. The returned reference is the sole handle to the value.
    #[inline(never)]
    pub unsafe fn boot_in_place<R: Trng>(
        slot: *mut core::mem::MaybeUninit<Self>,
        trng: &mut R,
        store: &mut dyn SecureStore,
    ) -> Result<&'static mut Self, SecureStoreError> {
        let app: *mut Self = slot.cast::<Self>();
        let mut buf = [0u8; 32];
        // S-701-3: keystore restore rides the same boot — a corrupt snapshot
        // is fatal (FX-440 parity with FX-409: never silently overwrite).
        let keystore = match DeviceKeystore::load(store)? {
            Some(ks) => ks,
            // US-1005 fix: a fresh partition's `device_random` is a plain
            // draw, so it is the D-9 item-(1) shape — all zeros on a
            // starved generator, and this one persists. Refuse, and refuse
            // as `Entropy` rather than as `Corrupt`, because nothing is
            // corrupt: the store is empty and the generator is silent.
            None => DeviceKeystore::fresh(trng).map_err(|_| SecureStoreError::Entropy)?,
        };
        // US-916: provision the per-device attestation identity (fresh
        // TRNG key + on-device self-signed cert on a fresh store; loaded
        // from the store afterwards). An Err here — including a corrupt
        // stored identity — is fatal by policy (fail-closed).
        let attestation = crate::attestation::provision(trng, store)?;
        // `fresh_partition` records which arm we took, because the fresh arm
        // is the only one that seeds the TRNG pool and persists the keystore.
        let (hkey, fresh_partition) = match store.read(HKEY_KEY, &mut buf) {
            Ok(32) => {
                // A stored scalar must be a valid P-256 key (0 < k < n).
                let hkey = p256::SecretKey::from_slice(&buf)
                    .map_err(|_| SecureStoreError::Corrupt)?;
                (hkey, false)
            }
            Ok(_) => return Err(SecureStoreError::Corrupt),
            Err(SecureStoreError::NotFound) => {
                // Fresh partition: derive + persist.
                let mut adapter = TrngAdapter(trng);
                let hkey = p256::SecretKey::random(&mut adapter);
                store.write(HKEY_KEY, hkey.to_bytes().as_slice())?;
                (hkey, true)
            }
            Err(e) => return Err(e),
        };
        // The three owned fields, then the volatile session state — the same
        // struct literal the by-value form used, field for field.
        core::ptr::addr_of_mut!((*app).hkey).write(hkey);
        core::ptr::addr_of_mut!((*app).attestation).write(attestation);
        core::ptr::addr_of_mut!((*app).keystore).write(keystore);
        // US-176: the volatile `0x41` half. Written here rather than left to
        // `Default` because this function writes every other field explicitly
        // into a `MaybeUninit` slot, and a field it forgets is uninitialised
        // memory — which for a "is the device unlocked" flag is not a benign
        // default.
        core::ptr::addr_of_mut!((*app).vendor_session)
            .write(crate::vendor_state::VendorSession::default());
        core::ptr::addr_of_mut!((*app).pin_token).write(None);
        core::ptr::addr_of_mut!((*app).token_permissions).write(0);
        core::ptr::addr_of_mut!((*app).token_rp_id).write(heapless::Vec::new());
        core::ptr::addr_of_mut!((*app).ga_pending).write(None);
        core::ptr::addr_of_mut!((*app).auth_failures).write(0);
        core::ptr::addr_of_mut!((*app).current_channel).write([0; 4]);
        core::ptr::addr_of_mut!((*app).rng_pool).write(heapless::Vec::new());
        core::ptr::addr_of_mut!((*app).rng_cursor).write(0);
        core::ptr::addr_of_mut!((*app).cm_rp_state).write(None);
        core::ptr::addr_of_mut!((*app).cm_cred_state).write(None);
        core::ptr::addr_of_mut!((*app).cm_dialect)
            .write(crate::device_core::CmDialect::default());
        core::ptr::addr_of_mut!((*app).lb_pending).write(None);
        core::ptr::addr_of_mut!((*app).vault_pending).write(None);
        core::ptr::addr_of_mut!((*app).presence).write(None);
        core::ptr::addr_of_mut!((*app).presence_grant).write(None);
        let app = &mut *app;
        if fresh_partition {
            app.fill_rng_pool(trng);
            app.keystore.persist(store).ok();
        }
        Ok(app)
    }

    /// The device keystore (S-701-3) — credential/PIN model access for the
    /// command path (S-701-4+).
    pub fn keystore(&mut self) -> &mut DeviceKeystore {
        &mut self.keystore
    }

    /// The stored physical configuration (`PhyConfig`, keystore auth-map key
    /// 6) — read-only, for the boot path that resolves the USB identity.
    ///
    /// The descriptors consume VID/PID and the identity names; LED fields stay
    /// with the LED task. Immutable on purpose: `&mut keystore()` would force
    /// the boot to take a mutable borrow of the whole app just to read four
    /// fields.
    pub fn phy(&self) -> &crate::vendorff::PhyConfig {
        &self.keystore.phy
    }

    /// US-907: attach the user-presence source (the board button poll on
    /// device). `None` uses the build default: fail-closed on the device
    /// build (no press → no grant → CTAP2 UpRequired), auto-ack on
    /// host/emulation — the existing host suites stay green.
    pub fn with_user_presence(mut self, f: fn() -> bool) -> Self {
        self.presence = Some(f);
        self
    }

    /// US-921: attach the shared presence runtime's grant path (device
    /// wiring) — the runtime owns the pending-request slot and the button
    /// latch binding, so presence is granted only by a press that lands
    /// while *this* command's request is pending.
    pub fn with_presence_grant(mut self, g: fn(u32) -> bool) -> Self {
        self.presence_grant = Some(g);
        self
    }

    /// US-939: post-construction variant of [`Self::with_presence_grant`].
    /// The firmware builds the app straight into its static slot
    /// (`boot::init_static_slot_with`) — the by-value builder forced a
    /// 15.7 KiB `FidoApp` temporary through the caller's stack frame, which
    /// was part of the async-main frame overflow.
    pub fn set_presence_grant(&mut self, g: fn(u32) -> bool) {
        self.presence_grant = Some(g);
    }

    /// Dirty-gated persistence hook: `true` = the keystore changed and the
    /// snapshot was re-persisted to `store`; the caller must then program the
    /// secure-partition flash image.
    pub fn persist_if_dirty(&mut self, store: &mut dyn SecureStore) -> bool {
        self.keystore.persist_if_dirty(store)
    }

    /// US-711 (review fix): re-initialize the app in RAM to factory-fresh
    /// state — the same CTAP2 Reset primitive (`handle_reset`) the spec's
    /// own reset serves. The HID task drives this when it observes a
    /// management factory reset (the `boot::RESET_GENERATION` counter), so
    /// a later mutating command persists the FRESH snapshot and can never
    /// re-persist the pre-reset one the durable wipe deleted (C
    /// `cbor_reset` → `init_fido()` parity).
    pub fn factory_reset(&mut self) {
        let mut out = heapless::Vec::<u8, { crate::CTAP2_MAX_MSG }>::new();
        self.process_ctap2(0x07, &[], BRIDGE_CHANNEL, &mut out);
    }

    /// The persistent P-256 key-agreement key. Exposed for the SecureStore
    /// persistence seam (US-387/US-388), which stores/loads it across reboots.
    pub fn hkey(&self) -> &p256::SecretKey {
        &self.hkey
    }

    /// US-161/162 (PICOForge-COMPAT Phase H): adopt the durable `phy` record
    /// this app's in-RAM keystore copy has fallen behind on.
    ///
    /// The Rescue applet lives behind the **CCID** dispatcher and this app
    /// behind the **HID** task, so a `RESCUE WRITE` committed durably on the
    /// CCID side is not visible in this app's RAM until it is told. The owner
    /// signals with `boot::RESCUE_PHY_GENERATION` and the HID task calls this
    /// at the top of its command loop — the same
    /// generation-then-act discipline `factory_reset` uses for the management
    /// wipe, and for the same reason: a later mutating command must not
    /// re-persist a stale snapshot over the record that was just written.
    ///
    /// **Only `phy` is copied.** The credentials, PIN state, device random,
    /// large-blob array and vault state are left exactly as they are: this is
    /// a targeted catch-up, not a reload, and a Rescue WRITE — which is
    /// unauthenticated by design (threat model §1) — must not be a
    /// path that re-derives or rewrites anything but one config record.
    ///
    /// Returns `true` when a durable snapshot was found and its `phy` adopted,
    /// `false` when there was nothing to adopt (a missing or unreadable
    /// snapshot leaves the in-RAM record untouched rather than clearing it —
    /// a failed read is not evidence of an absent record).
    pub fn sync_phy(&mut self, store: &mut dyn SecureStore) -> bool {
        match DeviceKeystore::load(store) {
            Ok(Some(ks)) => {
                self.keystore.phy = ks.phy;
                true
            }
            _ => false,
        }
    }

    /// US-916: the per-device attestation identity (key + self-signed cert)
    /// provisioned at boot — the device U2F register path signs with it.
    pub fn attestation(&self) -> &crate::attestation::AttestationIdentity {
        &self.attestation
    }

    /// Clear volatile session state (new HID client connection / power
    /// cycle): token, assertion cursor and the per-session pinUvAuth
    /// streak. US-909: the PIN-mismatch counters and 3-strike latch are
    /// durable in `keystore.pin_state` and intentionally NOT cleared.
    pub fn clear_session_state(&mut self) {
        // Zeroize the raw PIN token bytes before dropping the session
        // (US-704) — `None` alone leaves the 32 bytes resident in RAM.
        if let Some(mut token) = self.pin_token.take() {
            token.fill(0);
        }
        self.pin_token = None;
        self.token_permissions = 0;
        self.token_rp_id.clear();
        self.ga_pending = None;
        self.auth_failures = 0;
        self.cm_rp_state = None;
        self.cm_cred_state = None;
        self.lb_pending = None;
        self.vault_pending = None;
        // US-176: the `0x41` volatile half. This is where the firmware
        // simulates a power cycle for a new HID client, and the unlocked flag
        // and the MSE channel are both defined against that boundary — the
        // durable halves live in `keystore.vendor` and are deliberately not
        // touched here.
        self.vendor_session.clear();
    }

    /// Process a CTAP2 command. `out` is cleared; returns the response length.
    ///
    /// * `0x04` getInfo → real CBOR info map (versions, AAGUID, capabilities,
    ///   maxMsgSize).
    /// * everything else → `CTAP2_ERR_INVALID_COMMAND` (the shell does not
    ///   (yet) implement the crypto commands).
    pub fn process_ctap2(
        &mut self,
        command: u8,
        data: &[u8],
        channel: [u8; 4],
        out: &mut heapless::Vec<u8, { crate::CTAP2_MAX_MSG }>,
    ) -> usize {
        self.process_ctap2_with_store(command, data, channel, out, None)
    }

    /// [`FidoApp::process_ctap2`] with the app's `SecureStore` bound for the
    /// duration of the command (SOAK-FINDING-1): growth mutations
    /// (makeCredential, largeBlobs commit, config RP-id lists, vault enroll)
    /// verify the resulting snapshot still persists — serialize-ahead against
    /// the actual store — before committing, so an overflow is a clean
    /// rejection and never an un-persistable dirty state. `None` keeps the
    /// legacy mutate-and-mark-dirty behavior (the dispatcher bridge path,
    /// whose persist gate runs after `App::process`).
    pub fn process_ctap2_with_store(
        &mut self,
        command: u8,
        data: &[u8],
        channel: [u8; 4],
        out: &mut heapless::Vec<u8, { crate::CTAP2_MAX_MSG }>,
        mut store: Option<&mut dyn SecureStore>,
    ) -> usize {
        self.current_channel = channel;
        match command {
            0x04 => self.handle_get_info(out),
            0x01 => self.handle_make_credential(data, out, store),
            0x02 => self.handle_get_assertion(data, out, store),
            0x06 => self.handle_client_pin(data, out),
            0x07 => self.handle_reset(out),
            0x08 => self.handle_get_next_assertion(out, store),
            0x0A => self.handle_cred_mgmt(data, out),
            // US-1514: authenticatorSelection. This arm is what made the
            // emulator able to do something the board could not — the host
            // twin had `0x0B` since FX-415 and this dispatch fell through to
            // `_ =>` with INVALID_COMMAND, so a platform enumerating
            // authenticators (Chrome on Windows calls this) got `OK` from
            // the emulator and an error from the board.
            //
            // It answers `CTAP2_OK` without a touch, which is the point of
            // story US-1514 rather than an oversight: `handle_authenticator_
            // selection` in `device_core.rs` states the full argument. In
            // short, a gated answer is unreachable from here (the
            // `UpRequired` → keepalive → retry loop that makes a gate into a
            // prompt is `serve_once` + `dispatch` in `firmware/src/hid_serve.rs`,
            // and its `presence_windowed` predicate does not name `0x0B`),
            // `fido2`'s `Ctap2.selection()` raises a
            // `CtapError` on *any* non-zero status so no gated status reads
            // as a selection, and the reference C firmware's gate is
            // disarmed in its default build. Answering here is what makes
            // the twins agree; the gate is a separate story that would have
            // to change both twins *and* the transport.
            0x0B => self.handle_authenticator_selection(out),
            0x0C => self.handle_large_blobs(data, out, store),
            0x0D => self.handle_authenticator_config(data, out, store),
            // US-106: the RS-Key vendor channel (PicoForge framing C) — the
            // first payload byte of a standard 0x90 CBOR frame. NOT the vendor
            // vault: that one dispatches on the CTAPHID frame CMD byte (its
            // arm in `firmware/src/hid_serve.rs`'s `dispatch`), so the two
            // read disjoint fields of disjoint frames and cannot alias.
            // `vendor41` owns the sub-command set and the shrink-to-empty
            // discipline; the store is threaded so an arm need not re-open
            // this dispatch.
            //
            // US-112: the caller's pinUvAuth token is handed down as
            // `TokenAuth`, and the outcome can ask this app to charge a
            // rejected MAC against its three-strike counter.
            //
            // US-1516 replaces two sentences this comment used to carry. It
            // said "every sub-command is a NOT_ALLOWED stub until Phase I
            // implements it", and that the token "is not consulted by the
            // twelve arms still in `vendor41::PENDING` — those still answer
            // `0x30`". Both were true when written and outlived the stubs:
            // `PENDING` drained across US-170 … US-175 and **all fourteen
            // sub-commands now have real arms**. A comment claiming a
            // capability this path does not have is the failure the decision
            // table exists to prevent, one layer up — and it is worse here
            // than in `vendor41`, because this is the arm the RP2350 runs.
            // What replaced it: every arm is listed, with the gate it declares
            // and what authorises a tokenless request, in `vendor41::decision`.
            //
            // The gate is therefore **per arm**, not per dispatch. `CONFIG_READ`
            // is ungated *by protocol* — the client sends it as its probe for
            // whether this firmware speaks `0x41` at all — so consulting a
            // token for it would be wrong rather than early. `CONFIG_WRITE`
            // consults it for the identity tier only. The twelve
            // token-optional rows call `authorize` from inside their own gate
            // helpers, so a bare request reaches them and is answered with a
            // touch instead of refused for want of a token.
            //
            // US-115: `CONFIG_WRITE`'s record is committed here — `vendor41`
            // has the store but not the snapshot, and only this arm can make
            // the write durable (see `vendor41::handle`).
            //
            // `tests/vendor41.rs::every_subcommand_is_dispatched_on_the_device_path`
            // is what keeps this arm honest: it drives every sub-command over
            // *this* path and requires a dispatched answer, so the module's
            // claim cannot be true for the host twin and false here.
            crate::vendor41::CMD => {
                let auth = self.pin_token.as_ref().map(|token| crate::vendor41::TokenAuth {
                    token,
                    permissions: self.token_permissions,
                    // The same latch `verify_token` gates on. Handed across
                    // because the `0x41` seam bypasses `verify_token`; see
                    // `TokenAuth`.
                    blocked: self.keystore.pin_state.needs_power_cycle,
                });
                // The same two probes `user_present` resolves, handed across as
                // a `Copy` value because `vendor41` has no `&mut self`. The
                // precedence and the build default are `PresenceGate`'s
                // problem and are `user_present`'s answer, not a second one.
                let presence = crate::vendor41::PresenceGate {
                    window_grant: self.presence_grant,
                    poll: self.presence,
                    tag: presence_tag_from_channel(self.current_channel),
                };
                // US-114: the `0x41` response is `status || CBOR`, so the
                // sub-command arm has somewhere to put a body. It is written
                // into `out` rather than into a scratch buffer, so a PHY
                // record costs no separate stack.
                //
                // `out` is **not** cleared here, and that is deliberate.
                //
                // On this path it is `HID_RESP` — a `&'static mut` the
                // firmware reuses for every CTAPHID command and never clears
                // (`firmware/src/tasks.rs`) — so it still holds the previous
                // command's reply at this point.
                // `vendor41::handle` empties it as its buffer contract, and it
                // is the only writer of it on this channel, so that is the one
                // place the rule can live. Clearing here as well would look
                // more defensive and be strictly worse: with the clear in two
                // layers, removing either changes nothing observable and
                // neither layer can be tested.
                // `tests/vendor41.rs::vendor41_reused_output_buffer_carries_no_stale_bytes`
                // drives a stale buffer through this arm and pins the result.
                let status_byte = {
                    let phy = self.keystore.phy;
                    // US-176: `ops` is the Phase I state seam. The keystore is
                    // copied out of (`phy`) first because the ops borrow below
                    // takes it mutably, and the three borrows are three
                    // *different* fields of this app — the snapshot, the
                    // volatile session and the RNG pool — which is why they can
                    // coexist at all. The durable commit inside a `0x41` arm
                    // therefore runs through `grow_checked` (persist, or undo
                    // and refuse), exactly like the `Outcome::phy` commit just
                    // below, and the ack still goes out after the write landed.
                    // Scoped so the ops — and the `store` reborrow inside it —
                    // are dropped before the `grow_checked` below needs
                    // `store` again.
                    //
                    // Four **disjoint field** borrows, not a `&mut self`: `auth`
                    // above borrows `self.pin_token` immutably, and a whole-app
                    // mutable borrow would collide with it. Edition-2021 closure
                    // capture is what lets the entropy closure take only
                    // `rng_pool` and `rng_cursor` (`device_core`'s
                    // `take_random`) while `keystore` and `vendor_session` are
                    // borrowed mutably beside it. That split is the device's
                    // whole difference from the host twin, which has OS entropy
                    // and so needs no closure at all.
                    let outcome = {
                        let mut random = |buf: &mut [u8]| {
                            crate::device_core::take_random(
                                &mut self.rng_pool,
                                &mut self.rng_cursor,
                                buf,
                            )
                        };
                        crate::vendor_state::with_keystore_ops(
                            &mut self.keystore,
                            &mut self.vendor_session,
                            &mut store,
                            &mut random,
                            |ops| {
                                crate::vendor41::handle(data, auth, &phy, presence, out, ops)
                            },
                        )
                    };
                    let status = if outcome.pin_auth_failure {
                        // Reuse the existing private latch, so the third strike still
                        // answers `0x34` and still sets `blocked` + `needs_power_cycle`
                        // + `dirty` exactly the way the rest of this path sets them.
                        self.note_pin_auth_failure()
                    } else {
                        outcome.status.code()
                    };
                    // Durable-before-ack, at the only layer that can do it.
                    //
                    // `config_write` *proposes* a record; `grow_checked` makes it
                    // durable or puts the old one back, which is SOAK-FINDING-1
                    // parity with the `0xFF` legacy framing's arm in
                    // `device_core.rs`. A snapshot that cannot be programmed is
                    // a clean rejection here rather than a `0x00` that is true
                    // only in RAM — and the HID task's persist gate
                    // (`firmware/src/tasks.rs`'s `persist_hid`) runs after this
                    // and finds the app already clean, which is why the ack is
                    // safe to send.
                    // `KeyStoreFull` (0x28) is the closest existing byte for
                    // "the write did not land", the same choice the host twin's
                    // `cfg_physical_config` makes.
                    match outcome.phy {
                        Some(next) => {
                            let old = self.keystore.phy;
                            let committed = self.keystore.grow_checked(
                                store,
                                |ks| {
                                    ks.phy = next;
                                    ks.dirty = true;
                                },
                                |ks| ks.phy = old,
                            );
                            if committed {
                                status
                            } else {
                                crate::ctap2::Ctap2Response::KeyStoreFull.code()
                            }
                        }
                        None => status,
                    }
                };
                // `config_read` wrote the body at index 0, so the status byte
                // goes in front of it — over a PHY record, at most 16 bytes
                // today and bounded by `phy_record_len` in any case. The
                // full-buffer case is handled inside, not with a discarded
                // `.ok()`; see `vendor41::finish_reply`.
                crate::vendor41::finish_reply(out, status_byte);
                out.len()
            }
            _ => {
                out.clear();
                out.push(CTAP2_ERR_INVALID_COMMAND).ok();
                out.len()
            }
        }
    }

    /// Process a U2F APDU (CTAP1) — S-701-5 device path.
    pub fn process_u2f(&mut self, apdu: &[u8], out: &mut heapless::Vec<u8, { crate::CTAP2_MAX_MSG }>) -> usize {
        self.process_u2f_with_store(apdu, out, None)
    }

    /// [`FidoApp::process_u2f`] with the store bound (SOAK-FINDING-1): a
    /// register whose resulting snapshot cannot be made durable is rejected
    /// with `WrongData` (6A80) instead of being accepted into an
    /// un-persistable dirty state.
    pub fn process_u2f_with_store(
        &mut self,
        apdu: &[u8],
        out: &mut heapless::Vec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> usize {
        self.handle_u2f(apdu, out, store)
    }

    /// US-921: set the transaction channel the U2F (CTAP1) presence tag
    /// derives from. `process_ctap2` re-derives it per call; the U2F
    /// entry predates the channel plumbing, so the HID task sets it
    /// explicitly — without this the app would consult a stale tag and
    /// the cross-call window's grant could never match.
    pub fn set_channel(&mut self, channel: [u8; 4]) {
        self.current_channel = channel;
    }

    /// Handle the vendor vault function (CTAPHID vendor 0x41) — S-701-5.
    pub fn process_vendor_vault(
        &mut self,
        data: &[u8],
        out: &mut heapless::Vec<u8, { crate::CTAP2_MAX_MSG }>,
    ) -> usize {
        self.process_vendor_vault_with_store(data, out, None)
    }

    /// [`FidoApp::process_vendor_vault`] with the store bound
    /// (SOAK-FINDING-1): the enroll commit is transactional like the other
    /// growth mutations.
    pub fn process_vendor_vault_with_store(
        &mut self,
        data: &[u8],
        out: &mut heapless::Vec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> usize {
        self.handle_vendor_vault(data, out, store)
    }
}

#[cfg(test)]
mod tests {
    // The shell is device/arm-gated; host tests exercise the host stack.
    use super::*;




    #[test]
    fn unimplemented_commands_answer_ctap_error() {
        let mut trng = fapico2_platform::trng::HostTrng::new();
        let mut app = FidoApp::new(&mut trng).expect("host TRNG is /dev/urandom-backed");
        let mut out = heapless::Vec::<u8, { crate::CTAP2_MAX_MSG }>::new();
        // US-113 removed `0xFF` from this list. It was here as evidence that
        // the opcode was *unimplemented*; the story made it implemented, and
        // leaving the assertion would have been a test contradicting the code
        // it is supposed to describe. The coverage it used to give is now
        // `tests/vendor41.rs::vendor_prototype_set_led_gpio_persists`, which
        // drives the real `0xFF` path rather than asserting its absence.
        // US-1514 removed the `0x0B` leg that used to sit here. It was asserted
        // as INVALID_COMMAND purely because the device dispatch had no arm
        // for it — the assertion pinned the exact parity hole the story is
        // about. `0x09` (bio enrollment in this dialect) replaces it: still
        // genuinely unimplemented, and it keeps this test's coverage honest
        // rather than merely present. `tests/selection.rs` now asserts the
        // twins agree on `0x0B`, which is the claim that has to survive a
        // future refactor.
        let n = app.process_ctap2(0x09u8, b"anything", [0; 4], &mut out);
        assert_eq!(
            out.as_slice()[..n],
            [CTAP2_ERR_INVALID_COMMAND],
            "0x09 (bio enrollment) is unimplemented and answers INVALID_COMMAND"
        );
        // S-701-5: the vault is implemented; malformed CBOR → INVALID_CBOR.
        let n = app.process_vendor_vault(b"{}", &mut out);
        assert_eq!(out.as_slice()[..n], [0x12]);
    }

    // US-387 TDD: the device keystore path — `boot` loads/persists the hkey
    // through the platform `SecureStore` (the RP2350 secure partition on
    // device, the in-memory store + partition image on host).
    #[cfg(not(target_arch = "arm"))]
    mod boot {
        use super::*;
        use fapico2_platform::secure_store::{HostSecureStore, SecureStore};

        /// Boot on an empty partition: hkey is derived from the TRNG and
        /// persisted under `HKEY_KEY`; the secret never appears in plain
        /// flash.
        #[test]
        fn boot_on_empty_partition_derives_and_persists_hkey() {
            let mut trng = fapico2_platform::trng::HostTrng::new();
            let mut store = HostSecureStore::new();
            store.set_plain_flash(b"plain application data".to_vec());

            let app = FidoApp::boot(&mut trng, &mut store).unwrap();

            let mut buf = [0u8; 32];
            let n = store.read(HKEY_KEY, &mut buf).unwrap();
            assert_eq!(n, 32, "the persisted hkey is a 32-byte P-256 scalar");
            assert_eq!(
                buf.as_slice(),
                app.hkey().to_bytes().as_slice(),
                "the persisted hkey must match the app's key"
            );
            assert!(
                !store
                    .plain_flash_dump()
                    .windows(32)
                    .any(|w| w == buf.as_slice()),
                "the hkey must never appear in plain flash"
            );
        }

        /// Reboot (partition image snapshot + restore): the same hkey is
        /// reloaded — no re-derivation, credentials are not orphaned.
        #[test]
        fn boot_after_reboot_reloads_persisted_hkey() {
            let mut trng = fapico2_platform::trng::HostTrng::new();
            let mut store = HostSecureStore::new();
            let app1 = FidoApp::boot(&mut trng, &mut store).unwrap();
            let hkey1 = app1.hkey().to_bytes();

            // Power-down: snapshot the secure partition, drop everything.
            let image = store.partition_image();
            drop(app1);
            drop(store);

            let mut trng = fapico2_platform::trng::HostTrng::new();
            let mut restored = HostSecureStore::new();
            restored.from_partition_image(&image);
            let app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();
            assert_eq!(
                app2.hkey().to_bytes(),
                hkey1,
                "the hkey must survive a reboot (loaded, not re-derived)"
            );
        }

        /// US-711 review fix: after the management reset handler's durable
        /// wipe (the keystore + hkey slots deleted), the app re-initialized
        /// via `factory_reset()` (what the HID task does when it observes
        /// the reset generation) persists only FRESH state — a mutating
        /// command after the reset can never re-persist the pre-reset
        /// snapshot. Without the re-init, the dirty-gated persist would
        /// write the FULL old snapshot back (the resurrection hazard).
        #[test]
        fn factory_reset_reinit_prevents_snapshot_resurrection() {
            use crate::device_keystore::KEYSTORE_SLOT;
            use fapico2_platform::secure_store::chunked;

            let mut trng = fapico2_platform::trng::HostTrng::new();
            let mut store = HostSecureStore::new();
            let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();

            // Enroll one credential + persist — the pre-reset snapshot.
            let mut cred = crate::device_keystore::DeviceCredential::new_template();
            cred.rp_id.extend_from_slice(b"pre-reset.example").ok();
            app.keystore().store_credential(cred).unwrap();
            assert!(app.persist_if_dirty(&mut store), "pre-reset snapshot persisted");
            assert_eq!(
                DeviceKeystore::load(&mut store).unwrap().unwrap().credentials.len(),
                1
            );

            // The management reset handler's durable wipe (boot.rs).
            assert!(chunked::delete_chunked(&mut store, KEYSTORE_SLOT).is_ok());
            assert!(store.delete(HKEY_KEY).is_ok());

            // Without the re-init, ANY later mutating command (e.g.
            // getAssertion bumping the credential counter, or another
            // makeCredential) re-persists the FULL in-RAM snapshot — the
            // pre-reset credential comes back. Demonstrate the hazard first.
            let mut late = crate::device_keystore::DeviceCredential::new_template();
            late.credential_id.extend_from_slice(b"late-id").ok();
            late.rp_id.extend_from_slice(b"late.example").ok();
            app.keystore().store_credential(late).unwrap();
            assert!(app.persist_if_dirty(&mut store));
            assert_eq!(
                DeviceKeystore::load(&mut store).unwrap().unwrap().credentials.len(),
                2,
                "hazard check: a mutation after the bare durable wipe resurrects the pre-reset snapshot"
            );

            // Now the fix path: wipe again and let the HID task observe the
            // reset generation, re-initializing the app in RAM first.
            // (the hkey slot is only written at boot, so it is already gone
            // here — the hazard-phase persist only rewrites the keystore.)
            let _ = store.delete(HKEY_KEY);
            assert!(chunked::delete_chunked(&mut store, KEYSTORE_SLOT).is_ok());
            let _ = store.delete(HKEY_KEY);
            app.factory_reset();

            // A subsequent mutation + persist now writes only fresh state.
            assert!(app.persist_if_dirty(&mut store), "fresh snapshot persisted");
            let ks = DeviceKeystore::load(&mut store).unwrap().unwrap();
            assert!(
                ks.credentials.is_empty(),
                "no pre-reset credential may be re-persisted after the wipe"
            );
            // US-1012: `load` is the restore path, and a restore starts a
            // whole counter window above the durable image so a batched
            // counter can never repeat a value after a power cut. A freshly
            // reset device's durable counter is 0, so the restored one is
            // exactly the window — never anything that could have come from
            // the pre-reset snapshot.
            assert_eq!(
                ks.cred_counter,
                crate::device_keystore::COUNTER_PERSIST_INTERVAL as u32,
                "the fresh snapshot has a zero counter, and a restore adds one \
                 window of slack to it (US-1012)"
            );
        }

        /// A corrupt persisted hkey (invalid P-256 scalar) is a clean error,
        /// never a panic.
        #[test]
        fn boot_rejects_corrupt_persisted_hkey() {
            let mut trng = fapico2_platform::trng::HostTrng::new();
            let mut store = HostSecureStore::new();
            // All-zero is not a valid P-256 scalar.
            store.write(HKEY_KEY, &[0u8; 32]).unwrap();
            assert!(FidoApp::boot(&mut trng, &mut store).is_err());
        }
    }

    // US-426 TDD: the `App::persist_state` contract. FIDO is registered in a
    // platform `Dispatcher`, dirties its keystore through the APDU→CTAP2
    // bridge, and the platform persist gate (`persist_apps` — the gate the
    // transports call after every dispatched command) programs exactly one
    // image that round-trips the credential into a fresh store (reboot).
    #[cfg(not(target_arch = "arm"))]
    mod app_contract {
        use super::*;
        use crate::cbor::no_heap::{self, Item, Parser};
        use fapico2_platform::dispatch::{Dispatcher, MAX_RESPONSE, SW_OK};
        use fapico2_platform::persist::{persist_apps, pull_image, ImageSink, WindowedImageSource};
        use fapico2_platform::secure_store::HostSecureStore;
        use fapico2_platform::trng::HostTrng;
        use heapless::Vec as HV;

        /// Records every program call and the last image (the
        /// `persist_gate.rs` sink idiom, counting `program` calls).
        #[derive(Default)]
        struct RecordingSink {
            programs: usize,
            last: Vec<u8>,
        }

        impl ImageSink for RecordingSink {
            fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
                self.programs += 1;
                self.last = pull_image(src);
                true
            }
        }

        /// makeCredential request CBOR — the same shape the S-701-4 device
        /// harness builds (clientDataHash, rp {id}, user {id},
        /// pubkeyCredParams [{type: "public-key", alg: -7}]), which
        /// `parse_mc` accepts on a fresh PIN-less keystore.
        fn build_mc_req(challenge: &[u8; 32]) -> Vec<u8> {
            let mut r: HV<u8, 512> = HV::new();
            no_heap::push_map_header(&mut r, 4).unwrap();
            no_heap::push_uint(&mut r, 1).unwrap();
            no_heap::push_bstr(&mut r, challenge).unwrap();
            no_heap::push_uint(&mut r, 2).unwrap();
            no_heap::push_map_header(&mut r, 1).unwrap();
            no_heap::push_tstr(&mut r, "id").unwrap();
            no_heap::push_tstr(&mut r, "example.com").unwrap();
            no_heap::push_uint(&mut r, 3).unwrap();
            no_heap::push_map_header(&mut r, 1).unwrap();
            no_heap::push_tstr(&mut r, "id").unwrap();
            no_heap::push_bstr(&mut r, b"user_id").unwrap();
            no_heap::push_uint(&mut r, 4).unwrap();
            no_heap::push_array_header(&mut r, 1).unwrap();
            no_heap::push_map_header(&mut r, 2).unwrap();
            no_heap::push_tstr(&mut r, "type").unwrap();
            no_heap::push_tstr(&mut r, "public-key").unwrap();
            no_heap::push_tstr(&mut r, "alg").unwrap();
            no_heap::push_neg(&mut r, -7).unwrap();
            r.as_slice().to_vec()
        }

        /// The credential id inside a makeCredential authData
        /// (rpIdHash(32) flags(1) count(4) aaguid(16) credIdLen(2) credId …).
        fn cred_id_from_auth_data(ad: &[u8]) -> Vec<u8> {
            let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
            ad[55..55 + id_len].to_vec()
        }

        #[test]
        fn app_persist_state_round_trips_credential_through_gate() {
            let mut trng = HostTrng::new();
            let mut store = HostSecureStore::new();
            let mut fido = FidoApp::boot(&mut trng, &mut store).unwrap();

            // Register in the dispatcher; SELECT FIDO_AID → SW_OK.
            let mut d: Dispatcher<2> = Dispatcher::new();
            assert!(d.register(&mut fido), "FIDO_AID must register cleanly");
            let select = [
                0x00u8, 0xA4, 0x04, 0x00, 0x08,
                0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
            ];
            let mut resp: HV<u8, MAX_RESPONSE> = HV::new();
            d.dispatch(&select, &mut resp);
            assert_eq!(resp.as_slice(), &SW_OK.to_be_bytes(), "SELECT FIDO_AID");

            // One state-mutating CTAP2 command through the dispatcher:
            // bridge APDU [00, INS=0x01 (makeCredential), 00, 00, lc, cbor…].
            let challenge = [0xC1u8; 32];
            let cbor = build_mc_req(&challenge);
            let mut apdu: HV<u8, 512> = HV::new();
            apdu.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]).unwrap();
            apdu.push(cbor.len() as u8).unwrap();
            apdu.extend_from_slice(&cbor).unwrap();
            d.dispatch(apdu.as_slice(), &mut resp);
            assert!(resp.len() >= 3, "bridge response: CTAP byte + SW at least");
            assert_eq!(resp.as_slice()[0], 0x00, "CTAP2 success byte 0x00");
            assert_eq!(
                &resp.as_slice()[resp.len() - 2..],
                &SW_OK.to_be_bytes(),
                "the bridge appends SW_OK"
            );

            // The credential id out of the makeCredential response
            // (map key 2: authData).
            let cbor_resp = &resp.as_slice()[1..resp.len() - 2];
            let mut p = Parser::new(cbor_resp);
            assert!(matches!(p.next(), Ok(Item::Map(3))));
            let mut auth_data = None;
            while p.remaining() > 0 {
                let Item::U(k) = p.next().unwrap() else { panic!("map key") };
                match k {
                    2 => auth_data = Some(p.next().unwrap()),
                    _ => p.skip().unwrap(),
                }
            }
            let Item::B(ad) = auth_data.unwrap() else { panic!("no authData") };
            let cred_id = cred_id_from_auth_data(ad);
            assert!(!cred_id.is_empty(), "a credential id must be attested");

            // The platform persist gate — the App::persist_state contract:
            // the dirty keystore is written to the store and exactly one
            // partition image is programmed.
            let mut sink = RecordingSink::default();
            assert!(
                persist_apps(d.apps_mut(), &mut store, &mut sink),
                "the gate must report a persist for the dirty FIDO keystore"
            );
            assert_eq!(sink.programs, 1, "exactly one image programmed");

            // Round trip: the store image restores the credential into a
            // fresh store + app (the reboot half).
            let img = store.partition_image();
            assert_eq!(
                sink.last, img.as_slice(),
                "the gate programmed the store's partition image"
            );
            let mut restored = HostSecureStore::new();
            restored.from_partition_image(&img);
            let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();
            assert!(
                app2.keystore().get_credential(&cred_id).is_some(),
                "the credential must survive the partition-image round trip"
            );
            assert!(app2.keystore().cred_count() >= 1);
        }
    }
}
