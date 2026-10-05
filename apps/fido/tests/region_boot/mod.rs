//! Shared fixtures for the two region-boot stories: **US-1558** (migrate an
//! existing snapshot into records) and **US-1560** (a key-region failure
//! degrades rather than halting).
//!
//! # Why these live in a module and not in one of the two test files
//!
//! Both stories need the *same* three things, and duplicating them would put
//! two copies of the applet's boot + PIN-client sequence in the tree — which is
//! the defect class `AGENTS.md` §5 names twice over ("one record format, one
//! region, one key hierarchy": two files describing one layout is the same
//! defect as two AAD builders). `tests/common/mod.rs` is the host twin's
//! harness and could not be extended for this without putting device-path
//! fixtures behind a feature gate the host suites do not have.
//!
//! # The provider is a process-global, so the tests are serialised
//!
//! [`fapico2_fido::device_app::install_region_provider`] writes one
//! `AtomicPtr`, so it is process-wide state and `cargo test` runs the tests in
//! one process with threads. Every test therefore takes [`lock`] for its whole
//! body, and [`install`] publishes the region under the same discipline. That
//! is also what makes the raw-pointer hand-out in [`provider`] sound: while the
//! lock is held, exactly one test is touching the region.
//!
//! # Why the region is a file, not a `Vec<u8>`
//!
//! [`FileKeyRegion`] models NOR honestly — `program` ANDs into what is there and
//! **refuses** a 0 → 1 transition, `erase_sector` clears a whole 4 KiB sector
//! (`platform/src/keyregion/host.rs`, "Why a stand-in that lies is worse than
//! no stand-in"). A migration that would be impossible on the part fails here.

#![allow(dead_code)] // each of the two test files uses a subset of this

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use fapico2_fido::cbor::no_heap as nh;
use fapico2_fido::cbor::no_heap::{Item, Parser};
use fapico2_fido::crypto;
use fapico2_fido::device_app;
use fapico2_fido::FidoApp;
use fapico2_platform::fused_key::FusedKey;
use fapico2_platform::keyregion::host::{Faults, FileKeyRegion};
use fapico2_platform::keyregion::record;
use fapico2_platform::keyregion::slotmap::SlotImage;
use fapico2_platform::keyregion::{KeyRegion, Slot, SlotRead, SLOTS_PER_SECTOR, TOTAL_SLOTS};
use fapico2_platform::secure_store::rp2350::Rp2350SecureStore;
use fapico2_platform::secure_store::SecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;

pub use fapico2_fido::device_keystore::{
    DeviceCoseKey, DeviceCredential, DeviceKeystore, PrivateScalar, RegionCredentialError,
    RegionCredentials, RegionKeys,
};

pub const MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;

/// The region's whole geometry.
///
/// The **full** region, not a short stand-in, because several assertions here
/// are about what the index reservation and the allocator's bound do — a short
/// file would move `region.slots()` and hide exactly those.
pub const REGION_SLOTS: u32 = TOTAL_SLOTS;

// ---------------------------------------------------------------------------
// Process-global region installation
// ---------------------------------------------------------------------------

static TEST_LOCK: Mutex<()> = Mutex::new(());
static REGION: Mutex<Option<Box<FileKeyRegion>>> = Mutex::new(None);
/// The counting install's region, kept apart from [`REGION`] because the two
/// providers are different *types* and [`InstalledRegion::with`] hands out a
/// concrete `&mut FileKeyRegion` for the fault injectors to work through.
///
/// **One provider is installed at a time**, whichever [`install`] or
/// [`install_counting`] ran last, and both `Drop` arms clear both slots — so a
/// test can never find a live region behind a provider that answers `None`.
static COUNTING: Mutex<Option<Box<CountingRegion>>> = Mutex::new(None);

/// Serialise the tests in this file against the process-global provider.
///
/// Every test in both files takes this **before** it touches a region, and
/// holds it until the end. `unwrap_or_else(|e| e.into_inner())` rather than
/// `unwrap()`: a test that panicked while holding the lock poisons it, and
/// every later test would then fail on the *poison*, hiding the real failure.
pub fn lock() -> MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The provider [`install`] publishes.
///
/// A `fn` pointer cannot capture, so the region is reached through a
/// `static`. The guard is dropped before the reference is returned — holding it
/// would deadlock the very applet code being driven — which is sound only
/// because of the [`lock`] discipline stated above: the `Box` is stable in
/// address for as long as it is installed, and no other test can be inside a
/// region call while this one holds the lock.
fn provider() -> Option<&'static mut dyn KeyRegion> {
    let mut guard = REGION.lock().unwrap_or_else(|e| e.into_inner());
    // `&mut **boxed`, not a `&T` cast: producing a `&mut` from a shared
    // reference is `invalid_reference_casting`, which is undefined behaviour
    // even when the reference is never read — and the lint is `deny` by
    // default, which is the right default for it.
    let boxed = guard.as_mut()?;
    let ptr: *mut FileKeyRegion = &mut **boxed;
    drop(guard);
    // SAFETY: `boxed` is the `Box`'s own heap allocation, which does not move
    // while installed; the `Drop` impl below only removes it, and only after
    // the `TEST_LOCK` guard the caller holds has been released. Exactly one
    // `&mut` to it is ever live, because every caller is inside the lock.
    Some(unsafe { &mut *ptr })
}

/// The provider [`install_counting`] publishes — the same
/// [`provider`], over [`COUNTING`].
fn counting_provider() -> Option<&'static mut dyn KeyRegion> {
    let mut guard = COUNTING.lock().unwrap_or_else(|e| e.into_inner());
    let boxed = guard.as_mut()?;
    let ptr: *mut CountingRegion = &mut **boxed;
    drop(guard);
    // SAFETY: identical to [`provider`]'s — the `Box` allocation is stable for
    // as long as it is installed, and every caller holds [`lock`].
    Some(unsafe { &mut *ptr })
}

/// The provider that answers "no region".
///
/// What a host build has, and what a device has before
/// `boot::release_key_region()`. Installed on drop so one test cannot leak an
/// installed region into the next.
fn provider_none() -> Option<&'static mut dyn KeyRegion> {
    None
}

/// A published region file, removed on drop.
pub struct InstalledRegion {
    path: PathBuf,
}

/// Create a fresh region file and publish it as the applet's provider.
///
/// The file is **erased** (`0xFF`) on creation, not zero-filled, because a
/// region whose virgin state is `0x00` would accept records a real part cannot
/// hold.
pub fn install(tag: &str) -> InstalledRegion {
    let region = InstalledRegion::new_file(tag);
    FileKeyRegion::create(region.path(), REGION_SLOTS).expect("a fresh key region file");
    *REGION.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(Box::new(FileKeyRegion::open(region.path()).expect("reopen the region")));
    device_app::install_region_provider(provider);
    region
}

/// [`install`], with a region that records what the applet's own writes cost.
///
/// **The only way to measure the erase profile of a command path**, because the
/// applet reaches the region exclusively through the provider — a test cannot
/// wrap the region the applet is holding. The wrapper is transparent apart from
/// the two logs, so a command that behaves here behaves on the board.
pub fn install_counting(tag: &str) -> InstalledRegion {
    let region = InstalledRegion::new_file(tag);
    FileKeyRegion::create(region.path(), REGION_SLOTS).expect("a fresh key region file");
    *COUNTING.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(Box::new(CountingRegion::open(region.path())));
    device_app::install_region_provider(counting_provider);
    region
}

impl InstalledRegion {
    fn new_file(tag: &str) -> InstalledRegion {
        let path = std::env::temp_dir()
            .join(format!("fapico2-region-boot-{}-{tag}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        InstalledRegion { path }
    }
}

impl InstalledRegion {
    /// The region file, so a test can reopen it or read its raw bytes.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Borrow the live region, to inject faults or read statistics.
    ///
    /// Only valid while the caller holds [`lock`] — which every caller does.
    pub fn with<R>(&self, f: impl FnOnce(&mut FileKeyRegion) -> R) -> R {
        let mut guard = REGION.lock().unwrap_or_else(|e| e.into_inner());
        let boxed = guard.as_mut().expect("the region is installed");
        f(boxed)
    }

    /// Run `f` over the live counting region.
    ///
    /// `None` when the plain [`install`] ran instead — a distinct answer rather
    /// than a panic, because a caller asking for erase counts and handed zeroes
    /// would write a test that passes against nothing.
    pub fn with_counting<R>(&self, f: impl FnOnce(&mut CountingRegion) -> R) -> Option<R> {
        let mut guard = COUNTING.lock().unwrap_or_else(|e| e.into_inner());
        let boxed = guard.as_mut()?;
        Some(f(boxed))
    }
}

impl Drop for InstalledRegion {
    fn drop(&mut self) {
        device_app::install_region_provider(provider_none);
        *REGION.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *COUNTING.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// The region that counts what a write cost
// ---------------------------------------------------------------------------

/// A [`KeyRegion`] that logs every erase and program **by sector**.
///
/// Per-sector because the whole lifetime argument is a per-sector argument
/// (`docs/erase-budget.md` §4c.3), and because "one erase and one program" has
/// to be answered as "one erase of *this* sector" — a counter of calls cannot
/// say which sector paid.
///
/// Logged whether or not the call succeeded: the wear question is what the
/// protocol **attempted**, and no interface says whether a refused erase
/// consumed a cycle.
pub struct CountingRegion {
    inner: FileKeyRegion,
    erase_log: Vec<u32>,
    program_log: Vec<u32>,
}

impl CountingRegion {
    /// A counting region over a **new** file at `path`.
    pub fn create(path: &Path) -> Self {
        CountingRegion::wrap(FileKeyRegion::create(path, REGION_SLOTS).expect("a fresh region file"))
    }

    /// A counting region over the existing file at `path`.
    pub fn open(path: &Path) -> Self {
        CountingRegion::wrap(FileKeyRegion::open(path).expect("the region file is reopenable"))
    }

    fn wrap(inner: FileKeyRegion) -> Self {
        CountingRegion { inner, erase_log: Vec::new(), program_log: Vec::new() }
    }

    /// Forget everything logged so far, so a test can measure one command.
    pub fn reset_log(&mut self) {
        self.erase_log.clear();
        self.program_log.clear();
    }

    /// Every sector erase since the last [`Self::reset_log`].
    pub fn erases(&self) -> u32 {
        self.erase_log.iter().sum()
    }

    /// Slot programs issued against `slot`'s sector since the last
    /// [`Self::reset_log`].
    pub fn programs_on(&self, slot: Slot) -> u32 {
        Self::on(&self.program_log, slot)
    }

    /// Sector erases of `slot`'s sector since the last [`Self::reset_log`].
    pub fn erases_on(&self, slot: Slot) -> u32 {
        Self::on(&self.erase_log, slot)
    }

    /// Inject faults into the wrapped region, for the "the flash says no" cases.
    pub fn inject_faults(&mut self, faults: Faults) {
        self.inner.inject_faults(faults);
    }

    fn on(log: &[u32], slot: Slot) -> u32 {
        log.get(slot.index() as usize / SLOTS_PER_SECTOR as usize).copied().unwrap_or(0)
    }

    fn bump(log: &mut Vec<u32>, slot: Slot) {
        let at = slot.index() as usize / SLOTS_PER_SECTOR as usize;
        if at >= log.len() {
            log.resize(at + 1, 0);
        }
        log[at] += 1;
    }
}

impl KeyRegion for CountingRegion {
    fn read_slot(&mut self, slot: Slot) -> Result<SlotImage, &'static str> {
        self.inner.read_slot(slot)
    }

    fn erase_sector(&mut self, slot: Slot) -> Result<(), &'static str> {
        let out = self.inner.erase_sector(slot);
        Self::bump(&mut self.erase_log, slot);
        out
    }

    fn program(&mut self, slot: Slot, offset: u32, data: &[u8]) -> Result<(), &'static str> {
        Self::bump(&mut self.program_log, slot);
        self.inner.program(slot, offset, data)
    }

    fn slots(&self) -> u32 {
        self.inner.slots()
    }
}

// ---------------------------------------------------------------------------
// A region that refuses writes part-way through
// ---------------------------------------------------------------------------

/// A region whose `program` calls stop succeeding after a fixed budget.
///
/// # Why the budget is in **programs** and not in erases
///
/// A `put` is a `commit::commit` — one erase, up to `SLOTS_PER_SECTOR` programs
/// — followed by `write_index_entry`, which is a sector rewrite of its own. So
/// "fail after N programs" cuts at a *precise* point in the middle of a
/// credential's write rather than at a credential boundary, which is the harder
/// case the gherkin asks for: "an interrupted migration" is not obliged to have
/// stopped between two credentials.
pub struct CappedRegion {
    inner: FileKeyRegion,
    budget: u32,
    served: u32,
}

/// The refusal string [`CappedRegion`] returns. Its own constant so a test can
/// match on it rather than on any failure being equally acceptable.
pub const E_CAPPED: &str = "capped region: the write budget is exhausted";

impl CappedRegion {
    /// Wrap `inner`, allowing `budget` further `program` calls.
    pub fn new(inner: FileKeyRegion, budget: u32) -> Self {
        CappedRegion { inner, budget, served: 0 }
    }

    /// How many programs this region has **served** — refused ones excluded.
    ///
    /// The distinction is the point of the wrapper: `FileKeyRegion`'s own
    /// `Stats` counts a refused call as well as a served one, so a test asking
    /// "did anything reach the medium?" would read a clean refusal as a write.
    pub fn programs(&self) -> u32 {
        self.served
    }

    /// How many programs this region has **refused**.
    pub fn refusals(&self) -> u32 {
        self.inner.stats().programs - self.served
    }

    /// How many live sectors this region has erased.
    pub fn erases(&self) -> u32 {
        self.inner.stats().sector_erases
    }
}

impl KeyRegion for CappedRegion {
    fn read_slot(
        &mut self,
        slot: Slot,
    ) -> Result<[u8; fapico2_platform::keyregion::FIDO_SLOT_BYTES as usize], &'static str> {
        self.inner.read_slot(slot)
    }

    fn erase_sector(&mut self, slot: Slot) -> Result<(), &'static str> {
        self.inner.erase_sector(slot)
    }

    fn program(&mut self, slot: Slot, offset: u32, data: &[u8]) -> Result<(), &'static str> {
        if self.budget == 0 {
            // Routed through the inner region's own fault injector rather than a
            // bare `Err`, so the refusal is produced by the same code a real I/O
            // failure would come from — a stand-in that invents its own error is
            // a stand-in the codec could accidentally pass (`host.rs`, "Why a
            // stand-in that lies is worse than no stand-in").
            self.inner.inject_faults(Faults { programs: true, ..Faults::default() });
            return self.inner.program(slot, offset, data);
        }
        self.budget -= 1;
        let out = self.inner.program(slot, offset, data);
        if out.is_ok() {
            self.served += 1;
        }
        out
    }

    fn slots(&self) -> u32 {
        self.inner.slots()
    }
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// The credential ID fixture `n` enrols under.
pub fn credential_id(n: u32) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(b"us58");
    id[4..8].copy_from_slice(&n.to_le_bytes());
    id[8..].copy_from_slice(&[(n >> 8) as u8; 24]);
    id
}

/// The RP hash fixture `n` belongs to.
pub fn rp_hash(n: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = (n as u8).wrapping_mul(47).wrapping_add(i as u8).wrapping_add(0x3b);
    }
    h
}

/// A resident credential, encoded by the applet's own codec.
///
/// Real `DeviceCredential`s, never synthetic blobs, so a record built from one
/// is indistinguishable from one the device would write — the same discipline
/// `region_delete_compaction.rs` states for its tombstones.
pub fn credential(n: u32, resident: bool) -> DeviceCredential {
    let mut cred = DeviceCredential {
        credential_id: HV::new(),
        public_key: DeviceCoseKey::es256([n as u8; 32], [0x22; 32]),
        private_key: PrivateScalar::from_bytes([0x66; 32]),
        rp_id_hash: rp_hash(n),
        rp_id: HV::new(),
        user_handle: HV::new(),
        user_name: HV::new(),
        user_display_name: HV::new(),
        cred_protect: 0,
        large_blob_key: None,
        hmac_secret: HV::new(),
        cred_blob: HV::new(),
        third_party_payment: false,
        pin_complexity_policy: false,
        resident,
        algorithm: -7,
        counter: n,
        revoked: false,
        expires_at: None,
    };
    cred.credential_id.extend_from_slice(&credential_id(n)).unwrap();
    cred.rp_id.extend_from_slice(b"example.test").unwrap();
    cred.user_handle.extend_from_slice(&[n as u8; 8]).unwrap();
    cred.user_name.extend_from_slice(b"user").unwrap();
    cred
}

/// A keystore holding `count` resident credentials, from a **fixed**
/// `device_random`.
///
/// The `device_random` is fixed so the payload key derived from it is the same
/// in the migration and in every later lookup — `region_pin_secret` mixes it in,
/// and a test that re-derived a different key per call would see every record
/// fail to open and could read that as a migration bug.
pub fn populated_keystore(count: u32) -> DeviceKeystore {
    let mut trng = HostTrng::new();
    let mut ks = DeviceKeystore::fresh(&mut trng).expect("host TRNG");
    ks.device_random = [0x3c; 32];
    for n in 0..count {
        ks.store_credential(credential(n, true)).expect("well under the resident bound");
    }
    ks
}

/// The region keys the applet derives from `store` and `ks`.
///
/// Through [`device_app::region_keys`] rather than a second derivation here:
/// the applet's own accessor is the thing under test, and a copy of it in the
/// test file would be free to drift from the one the command path uses.
pub fn region_keys(store: &dyn SecureStore, ks: &DeviceKeystore) -> RegionKeys {
    device_app::region_keys(store, ks).expect("a store that seals")
}

/// A deterministic nonce for fixture write `n`.
pub fn nonce(n: u32) -> [u8; record::NONCE_LEN] {
    let mut out = [0u8; record::NONCE_LEN];
    out[..4].copy_from_slice(&n.to_le_bytes());
    out[4..].copy_from_slice(&b"us1558nonce!!"[..record::NONCE_LEN - 4]);
    out
}

/// Unwrap a [`SlotRead`] that must be `Present`.
///
/// `SlotRead` has no `expect` on purpose — its whole point is that `Fault` and
/// `Absent` are *different* answers — so the assertion is written down rather
/// than defaulted. A helper that turned both into a panic would let a test read
/// a degraded region as a healthy one.
pub fn expect_present<T>(outcome: SlotRead<T>, what: &str) -> T {
    match outcome {
        SlotRead::Present(v) => v,
        SlotRead::Absent => panic!("{what}: absent"),
        SlotRead::Fault(why) => panic!("{what}: the region must be readable, got a fault: {why}"),
    }
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// A store shaped like the board's: the RP2350 secure partition, keyed.
///
/// `Rp2350SecureStore` rather than `HostSecureStore` because it is *the store
/// the board has* (`secure_store.rs:809`, and
/// `tests/key_store_ceiling.rs` says so explicitly), and because it is the only
/// one of the two whose key source can be made to read cold — which is how the
/// "OTP row unavailable" case is injected at the right layer.
pub fn keyed_store() -> Rp2350SecureStore {
    let mut store = Rp2350SecureStore::new();
    store.set_store_key([0x5au8; 32]);
    store
}

/// The same store with its OTP row reading cold.
///
/// **Injected at the key source, not at the region's medium.** The EPIC records
/// this correction: a cold OTP array halts the board today for four
/// pre-existing reasons (`derive_boot_store_key`, `init_drbg`, `derive_oath_seal`,
/// the migration authority), all before `RUNG_USB`, and none of them is US-1558
/// or US-1560's to relax. A reader that answers `None` is exactly the shape a
/// `fatal_boot` would otherwise be, and it lets this story's obligation be
/// tested: the applet layer degrades when it cannot derive its keys.
pub fn cold_otp_store() -> Rp2350SecureStore {
    let mut store = Rp2350SecureStore::new();
    store.set_fused_store_key(FusedKey::new("test/cold-otp", || None));
    store
}

// ---------------------------------------------------------------------------
// The device twin, driven through the real command entry points
// ---------------------------------------------------------------------------

/// The device `FidoApp` plus the store it reads and writes, and a PIN-protocol-v1
/// client beside them.
///
/// **A CTAP2 client, not the host twin.** `app.rs`'s `FidoApp` is the *other*
/// `FidoApp` (`AGENTS.md` §1): the migration, the region provider and the
/// degradation all live on the path `device_core.rs` runs, and a test against
/// the host twin would prove nothing about them.
pub struct Device {
    app: FidoApp,
    store: Rp2350SecureStore,
    hmac_key: [u8; 32],
    enc_key: [u8; 32],
    pin_token: Option<[u8; 32]>,
}

impl Device {
    /// Boot the authenticator over `store`.
    ///
    /// `FidoApp::boot` restores the snapshot — which is where a pre-migration
    /// device's credentials come from — and runs long before any region is
    /// reachable, exactly as on the board.
    pub fn boot(mut store: Rp2350SecureStore) -> Self {
        let mut trng = HostTrng::new();
        let app = FidoApp::boot(&mut trng, &mut store).expect("boot the device twin");
        Device { app, store, hmac_key: [0; 32], enc_key: [0; 32], pin_token: None }
    }

    /// The store, for reading what a command persisted.
    pub fn store(&self) -> &Rp2350SecureStore {
        &self.store
    }

    /// Borrow the store mutably, for reading back what a command persisted.
    ///
    /// Needed because `Rp2350SecureStore` is pure static memory and has no
    /// `Clone` — which is correct: a test that could copy it would be able to
    /// read a store state the device cannot see. The closure gets exactly the
    /// store the applet wrote to.
    pub fn with_store<R>(&mut self, f: impl FnOnce(&mut Rp2350SecureStore) -> R) -> R {
        f(&mut self.store)
    }

    /// Run the transport's persist gate — what `firmware/src/tasks.rs::persist_hid`
    /// runs after every HID transaction, and what the dispatcher's
    /// `persist_state` runs after every APDU.
    ///
    /// **A region-backed device needs this and it is easy to forget.** The
    /// snapshot is still the home of `device_random`, and `region_pin_secret`
    /// mixes it into the region's payload key, so a test that never persists
    /// has a device whose payload key is redrawn at every boot — every record
    /// unreadable, and a failure that would be read as a region bug. Every test
    /// here that reboots the app goes through this first, which is what makes the
    /// reboot a power cut rather than a factory reset.
    pub fn persist(&mut self) -> bool {
        self.app.persist_if_dirty(&mut self.store)
    }

    /// The store, so a test can boot a **second** device over it.
    ///
    /// Consuming rather than cloning, for the reason [`Self::with_store`] gives
    /// about `Rp2350SecureStore` — and it also drops the applet, which is the
    /// half a power-cut test wants: nothing about the medium survives in the
    /// old app, because `FidoRecordStore` holds no cache
    /// (`fido_store.rs`'s module docs).
    pub fn into_store(mut self) -> Rp2350SecureStore {
        core::mem::replace(&mut self.store, Rp2350SecureStore::new())
    }

    /// Grant user presence unconditionally.
    ///
    /// The board polls a button (`device_app.rs`'s `presence_grant`), and every
    /// makeCredential/getAssertion/U2F-enforce needs one, so a test that wants
    /// to reach those paths has to answer it. A `fn` pointer cannot capture,
    /// hence the inner `fn` — the same constraint `install`'s `provider` states.
    pub fn grant_presence_always(&mut self) {
        fn grant(_tag: u32) -> bool {
            true
        }
        self.app.set_presence_grant(grant);
    }

    /// Install an **arbitrary** presence source, replacing whatever
    /// [`Self::grant_presence_always`] installed.
    ///
    /// Needed by the stories whose subject is what happens when a human has
    /// *not* consented — an unauthorised `authenticatorReset` being the one
    /// that ships. `grant_presence_always` cannot express "denied", and a test
    /// that never denies a press would be asserting about a command nobody is
    /// trying to change.
    ///
    /// The grant is called once per presence request and the grant is consumed
    /// by that request (`device_core::FidoApp::user_present`), so a `fn` that
    /// records into a global is how a caller counts the calls — the tripwire
    /// `reset_presence_gate.rs` needs for the "exactly one grant, not two"
    /// property.
    pub fn with_presence_grant(&mut self, g: fn(u32) -> bool) {
        self.app.set_presence_grant(g);
    }

    /// The live `pinUvAuthToken`, once [`Self::set_pin`] has minted one.
    pub fn pin_token(&self) -> Option<[u8; 32]> {
        self.pin_token
    }

    /// Which store this device's credentials are in (US-1557).
    ///
    /// Delegates to the applet's own accessor rather than re-deriving the
    /// answer from `key_region().is_some()` here: the test's subject is what
    /// the applet *says*, and a second copy of the predicate in a test file is
    /// free to drift from the one the command path uses.
    pub fn backend(&self) -> fapico2_fido::device_keystore::CredentialBackend {
        self.app.credential_backend()
    }

    /// Fill the key region to [`FIDO_CAPACITY`] credentials, through the
    /// applet's own codec and its own key derivation.
    ///
    /// **The cost is `tests/capacity_boundary.rs`'s, not this file's to pay
    /// inside a parity script**: the allocator is a linear scan by design
    /// (`slotmap.rs`, "Lowest free slot is a linear scan"), so enrolling *n*
    /// credentials costs ~n²/2 header reads and 856 is ~366,000 1 KiB reads.
    /// What a caller wants from this is a region that is *full*, so that the
    /// next command-path enrolment is refused — and that single call is the part
    /// worth driving through `process_ctap2_with_store`.
    ///
    /// Panics rather than returning a result: a fill that did not reach
    /// capacity would make the caller's boundary assertion vacuous, and a
    /// `Result` here would only invite it to be ignored.
    pub fn fill_region_to_capacity(&mut self, region_file: &InstalledRegion) {
        for n in 0..fapico2_platform::keyregion::FIDO_CAPACITY {
            if let Err(e) = self.enroll_directly(region_file, n) {
                panic!("credential {n} of FIDO_CAPACITY must enrol, got {e:?}");
            }
        }
    }

    /// Register one resident credential directly into the region: no clientPIN
    /// leg, no presence window, no makeCredential handshake.
    ///
    /// `make_cred` is the real path and is what most tests want. This exists for
    /// the tests whose subject is what happens *after* an enrolment — US-1550's
    /// zeroization and US-1557's capacity boundary — where paying the
    /// makeCredential handshake on every fixture would make the test about the
    /// handshake instead of about the region.
    ///
    /// It writes through the applet's own codec
    /// ([`credential_record_body`](fapico2_fido::device_keystore::credential_record_body)),
    /// so the record is byte-for-byte one the device would write, and it derives
    /// its keys through [`region_keys`] — the applet's own accessor — so a test
    /// cannot accidentally seal under a different key hierarchy than the one
    /// shipped.
    pub fn enroll_directly(
        &mut self,
        region_file: &InstalledRegion,
        n: u32,
    ) -> Result<(), RegionCredentialError> {
        let keys = self.with_store(|store| {
            let ks = DeviceKeystore::load(store).expect("readable").expect("snapshot present");
            region_keys(store, &ks)
        });
        let cred = credential(n, true);
        region_file.with(|region| {
            let mut creds = RegionCredentials::new(region, &keys);
            creds.put(&nonce(n), &cred).map(|_| ())
        })
    }

    /// One U2F (CTAP1) APDU, through the **store-bearing** entry point, and the
    /// raw response APDU.
    ///
    /// `process_u2f_with_store` rather than `process_u2f` for the reason
    /// [`Self::call`] gives: the migration reads and writes the snapshot through
    /// the store it is handed, so a test using the store-less form would be
    /// driving a device that cannot retire anything.
    ///
    /// The response is a raw APDU — a trailing status byte, not the CTAP2
    /// status-then-CBOR shape — so this returns it whole rather than splitting
    /// it.
    pub fn u2f(&mut self, apdu: &[u8]) -> Vec<u8> {
        let mut out: HV<u8, MAX_MSG> = HV::new();
        let n = self
            .app
            .process_u2f_with_store(apdu, &mut out, Some(&mut self.store));
        out.as_slice()[..n].to_vec()
    }

    /// One CTAP2 command, through the **store-bearing** entry point.
    ///
    /// `process_ctap2_with_store` rather than `process_ctap2`: the migration
    /// reads and writes the snapshot through the store it is handed, so a test
    /// that used the store-less form would be testing a device that cannot
    /// retire anything.
    pub fn call(&mut self, cmd: u8, payload: &[u8]) -> (u8, Vec<u8>) {
        let mut out: HV<u8, MAX_MSG> = HV::new();
        let n = self
            .app
            .process_ctap2_with_store(cmd, payload, [1, 2, 3, 4], &mut out, Some(&mut self.store));
        let resp = out.as_slice()[..n].to_vec();
        (resp[0], resp[1..].to_vec())
    }

    // ---- PIN protocol v1 ------------------------------------------------

    fn push_ka(&self, out: &mut HV<u8, 256>) {
        let client_sk = p256::SecretKey::from_slice(&[0x99u8; 32]).unwrap();
        let bytes = crypto::public_key_bytes(&client_sk.public_key());
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        nh::push_map_header(out, 5).unwrap();
        nh::push_uint(out, 1).unwrap();
        nh::push_uint(out, 2).unwrap();
        nh::push_uint(out, 3).unwrap();
        nh::push_neg(out, -25).unwrap();
        nh::push_neg(out, -1).unwrap();
        nh::push_uint(out, 1).unwrap();
        nh::push_neg(out, -2).unwrap();
        nh::push_bstr(out, &x).unwrap();
        nh::push_neg(out, -3).unwrap();
        nh::push_bstr(out, &y).unwrap();
    }

    fn v1_encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut padded = plaintext.to_vec();
        while !padded.len().is_multiple_of(16) {
            padded.push(0);
        }
        let zero_iv = [0u8; 16];
        let mut buf = [0u8; 96];
        buf[..padded.len()].copy_from_slice(&padded);
        crypto::aes256_cbc_encrypt_into(&self.enc_key, &zero_iv, &mut buf[..padded.len()]).unwrap();
        buf[..padded.len()].to_vec()
    }

    fn v1_decrypt(&self, ct: &[u8]) -> Vec<u8> {
        let zero_iv = [0u8; 16];
        let mut buf = [0u8; 96];
        buf[..ct.len()].copy_from_slice(ct);
        crypto::aes256_cbc_decrypt_into(&self.enc_key, &zero_iv, &mut buf[..ct.len()]).unwrap();
        buf[..ct.len()].to_vec()
    }

    fn pin_auth_shared(&self, msg: &[u8]) -> Vec<u8> {
        crypto::hmac_sha256(&self.hmac_key, msg)[..16].to_vec()
    }

    /// HMAC-SHA-256 over `msg` under the live pinUvAuthToken, truncated to 16.
    pub fn pin_auth(&self, msg: &[u8]) -> Vec<u8> {
        let token = self.pin_token.expect("a minted pinUvAuthToken");
        crypto::hmac_sha256(&token, msg)[..16].to_vec()
    }

    fn derive_keys(&mut self) {
        let mut req: HV<u8, 64> = HV::new();
        nh::push_map_header(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        let (status, cbor) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00, "getPinUvAuthToken: ECDH");
        let mut p = Parser::new(&cbor);
        let _ = p.next().unwrap();
        let _ = p.next().unwrap();
        let Item::Map(n) = p.next().unwrap() else { panic!("getKeyAgreement") };
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        for _ in 0..n {
            let key = match p.next().unwrap() {
                Item::U(u) => u as i64,
                Item::N(n) => n,
                _ => panic!(),
            };
            match key {
                -2 => match p.next().unwrap() {
                    Item::B(b) => x.copy_from_slice(b),
                    _ => panic!(),
                },
                -3 => match p.next().unwrap() {
                    Item::B(b) => y.copy_from_slice(b),
                    _ => panic!(),
                },
                _ => p.skip().unwrap(),
            }
        }
        let client_sk = p256::SecretKey::from_slice(&[0x99u8; 32]).unwrap();
        let device_pub = crypto::parse_cose_ec2_p256_bytes(&x, &y).unwrap();
        let raw = crypto::ecdh_shared_secret(&client_sk, &device_pub);
        let k = crypto::derive_shared_secret_v1(&raw);
        self.hmac_key = k;
        self.enc_key = k;
    }

    /// Set `pin` and mint a pinUvAuthToken carrying every permission the tests
    /// need (`mc|ga|cm|lbf|acfg`).
    ///
    /// credMgmt is PIN-gated on this device — `cred_mgmt_inner` answers
    /// `PinNotSet` without a live token — so any test that reads a credential
    /// count over the wire has to pay this.
    pub fn set_pin(&mut self, pin: &[u8]) {
        self.derive_keys();
        let pin_enc = self.v1_encrypt(pin);
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        nh::push_uint(&mut req, 3).unwrap(); // keyAgreement
        self.push_ka(&mut req);
        nh::push_uint(&mut req, 5).unwrap();
        nh::push_bstr(&mut req, &pin_enc).unwrap();
        nh::push_uint(&mut req, 4).unwrap();
        nh::push_bstr(&mut req, &self.pin_auth_shared(&pin_enc)).unwrap();
        assert_eq!(self.call(0x06, req.as_slice()).0, 0x00, "setPIN");

        self.mint_token_with_pin(pin);
    }

    /// Mint a pinUvAuthToken from an **already-set** PIN, with the same
    /// permissions [`Self::set_pin`] asks for.
    ///
    /// **A separate entry point because `setPIN` is refused once a PIN exists**
    /// (`CTAP2_ERR_PIN_INVALID`), so a test that reboots the device — the whole
    /// shape of a power-cut story — cannot re-run [`Self::set_pin`] and is left
    /// with no token, which every `pinUvAuthParam` on the wire then fails
    /// against. Only the setPIN half is missing; the leg below is the same one
    /// `set_pin` finishes with.
    pub fn unlock_with_pin(&mut self, pin: &[u8]) {
        self.derive_keys();
        self.mint_token_with_pin(pin);
    }

    /// `getPinUvAuthTokenUsingPinWithPermissions` with `mc|ga|cm|lbf|acfg`.
    fn mint_token_with_pin(&mut self, pin: &[u8]) {
        let pin_hash = crypto::pin_hash(pin);
        let pin_hash_enc = self.v1_encrypt(&pin_hash);
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 9).unwrap(); // getPinUvAuthTokenUsingPinWithPermissions
        nh::push_uint(&mut req, 3).unwrap();
        self.push_ka(&mut req);
        nh::push_uint(&mut req, 6).unwrap();
        nh::push_bstr(&mut req, &pin_hash_enc).unwrap();
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, 0x37).unwrap();
        let (status, cbor) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00, "getPinUvAuthTokenUsingPinWithPermissions");
        let mut p = Parser::new(&cbor);
        let _ = p.next().unwrap();
        let _ = p.next().unwrap();
        let Item::B(ct) = p.next().unwrap() else { panic!() };
        let pt = self.v1_decrypt(ct);
        let mut token = [0u8; 32];
        token.copy_from_slice(&pt[..32]);
        self.pin_token = Some(token);
    }

    // ---- commands -------------------------------------------------------

    /// `authenticatorGetInfo` (0x04).
    pub fn get_info(&mut self) -> (u8, Vec<u8>) {
        self.call(0x04, &[])
    }

    /// `authenticatorMakeCredential` (0x01), resident, signed with the token.
    pub fn make_cred(&mut self, rp: &str, user: &[u8]) -> (u8, Vec<u8>) {
        let challenge = [0xCCu8; 32];
        let mut r: HV<u8, 512> = HV::new();
        // Seven pairs: clientDataHash(1), rp(2), user(3), pubKeyCredParams(4),
        // options(7), pinUvAuthParam(8), pinUvAuthProtocol(9). The header and
        // the pairs are counted separately on purpose — `device_full_set.rs`
        // says the same thing, and a mismatch here is an `InvalidCbor` (0x12)
        // from the applet with an empty body, which is a confusing way to learn
        // about a test's own typo.
        nh::push_map_header(&mut r, 7).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_bstr(&mut r, &challenge).unwrap();
        nh::push_uint(&mut r, 2).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_tstr(&mut r, rp).unwrap();
        nh::push_uint(&mut r, 3).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_bstr(&mut r, user).unwrap();
        nh::push_uint(&mut r, 4).unwrap();
        nh::push_array_header(&mut r, 1).unwrap();
        nh::push_map_header(&mut r, 2).unwrap();
        nh::push_tstr(&mut r, "type").unwrap();
        nh::push_tstr(&mut r, "public-key").unwrap();
        nh::push_tstr(&mut r, "alg").unwrap();
        nh::push_neg(&mut r, -7).unwrap();
        nh::push_uint(&mut r, 7).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "rk").unwrap();
        nh::push_bool(&mut r, true).unwrap();
        nh::push_uint(&mut r, 8).unwrap();
        nh::push_bstr(&mut r, &self.pin_auth(&challenge)).unwrap();
        nh::push_uint(&mut r, 9).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        self.call(0x01, r.as_slice())
    }

    /// `authenticatorGetAssertion` (0x02) for `rp`, with an optional allowList.
    ///
    /// **CTAP 2.1 §6.2.1's key numbering, which is the reverse of
    /// makeCredential's** — `rpId` is key 1 here and key 2 in a
    /// makeCredential, and `clientDataHash` is the other way round. Writing this
    /// from the makeCredential builder's memory produces `InvalidCbor` (0x12)
    /// with an empty body, which is exactly the shape of an applet bug and is
    /// why the numbers are spelled out here rather than factored out.
    ///
    /// allowList entries are **`{type, id}` maps**, not bare byte strings —
    /// `device_core.rs::parse_ga` reads an array of maps and discards any entry
    /// whose `type` is not `"public-key"`, so a bare `bstr` would be an empty
    /// allowList and the assertion would fall through to the resident walk.
    ///
    /// The pinUvAuth message is the clientDataHash (`device_core.rs:1481`,
    /// `verify_token(..., &req.client_data_hash)`), and the challenge here is a
    /// constant so the signature is reproducible.
    pub fn get_assertion(&mut self, rp: &str, allow: Option<&[u8]>) -> (u8, Vec<u8>) {
        let challenge = [0xCCu8; 32];
        let mut r: HV<u8, 512> = HV::new();
        // Four pairs without an allowList (rpId 1, clientDataHash 2,
        // pinUvAuthParam 6, pinUvAuthProtocol 7), five with it.
        nh::push_map_header(&mut r, if allow.is_some() { 5 } else { 4 }).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, rp).unwrap();
        nh::push_uint(&mut r, 2).unwrap();
        nh::push_bstr(&mut r, &challenge).unwrap();
        if let Some(id) = allow {
            nh::push_uint(&mut r, 3).unwrap();
            nh::push_array_header(&mut r, 1).unwrap();
            nh::push_map_header(&mut r, 2).unwrap();
            nh::push_tstr(&mut r, "type").unwrap();
            nh::push_tstr(&mut r, "public-key").unwrap();
            nh::push_tstr(&mut r, "id").unwrap();
            nh::push_bstr(&mut r, id).unwrap();
        }
        nh::push_uint(&mut r, 6).unwrap();
        nh::push_bstr(&mut r, &self.pin_auth(&challenge)).unwrap();
        nh::push_uint(&mut r, 7).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        self.call(0x02, r.as_slice())
    }

    /// `authenticatorCredentialManagement` (0x0A), **PicoForge dialect**.
    ///
    /// The dialect is binding (`AGENTS.md` §2): the applet does not speak CTAP
    /// 2.1 numbering, and `python-fido2`/`ykman` do not either. Sub-commands are
    /// PicoForge's — `getCredsMetadata = 0x01`, `enumerateRpsBegin = 0x02` —
    /// and the pinUvAuth message for those two is the **bare sub-command byte**,
    /// because PicoForge excludes their (empty) parameters from it
    /// (`tests/device_full_set.rs::picoforge_cred_mgmt` is the reference).
    pub fn cred_mgmt(&mut self, sub: u8) -> (u8, Vec<u8>) {
        let mut r: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut r, 3).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_uint(&mut r, sub as u64).unwrap();
        nh::push_uint(&mut r, 3).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_uint(&mut r, 4).unwrap();
        let auth_msg: Vec<u8> = vec![sub];
        nh::push_bstr(&mut r, &self.pin_auth(&auth_msg)).unwrap();
        self.call(0x0A, r.as_slice())
    }

    /// credMgmt `getCredsMetadata` — where this firmware reports the resident
    /// credential counts.
    pub fn cm_get_metadata(&mut self) -> (u8, Vec<u8>) {
        self.cred_mgmt(0x01)
    }

    /// credMgmt `enumerateRpsBegin` — the enumeration a user sees.
    pub fn cm_enumerate_rps(&mut self) -> (u8, Vec<u8>) {
        self.cred_mgmt(0x02)
    }

    /// credMgmt `enumerateCredsBegin` (PicoForge sub-command `0x04`) for one
    /// RP, in the request layout PicoForge sends.
    ///
    /// Not `cred_mgmt(0x04)`, because that helper signs the **bare** sub-command
    /// byte — which is right for `getCredsMetadata` and `enumerateRpsBegin`
    /// (PicoForge omits their empty parameters from the signed message) and
    /// wrong for this one.
    pub fn cm_enumerate_creds(&mut self, rp_id: &str) -> (u8, Vec<u8>) {
        let hash = crypto::sha256(rp_id.as_bytes());
        // PicoForge's `subCommandParams` is a **bare map** under the request's
        // key `0x02`, not a byte string wrapping one — `device_core.rs`'s
        // `cm_dialect` decides "PicoForge" precisely because key 2 decodes as
        // `Item::Map`, and a bstr there reads as neither dialect and is answered
        // `0x12`. Inside it, `rpIdHash` is key **1**, not the CTAP2 key 4.
        let mut r: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut r, 4).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_uint(&mut r, 4).unwrap();
        nh::push_uint(&mut r, 2).unwrap();
        let params_at = r.len();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_bstr(&mut r, &hash).unwrap();
        let params_end = r.len();
        // And the signed message is `subCommand ‖ CBOR(subCommandParams)` — the
        // params map byte-exact, as it appears on the wire, key order included
        // (`device_core.rs` captures the raw bytes for exactly this reason).
        let mut auth_msg: Vec<u8> = vec![0x04];
        auth_msg.extend_from_slice(&r[params_at..params_end]);
        nh::push_uint(&mut r, 3).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_uint(&mut r, 4).unwrap();
        nh::push_bstr(&mut r, &self.pin_auth(&auth_msg)).unwrap();
        self.call(0x0A, r.as_slice())
    }
}

/// Read an unsigned integer at `key` out of a CTAP2 response map.
///
/// **On the hand-rolled reader below, not on `cbor::no_heap::Parser`.** That
/// parser has a single linear cursor with no way to look at a value after
/// `next()` has stepped over it, so walking a map whose values include a
/// *nested* map — which every credMgmt reply does, `{"id": …}` being one — means
/// re-deriving where each value ended. That is a second definition of the CBOR
/// grammar inside a test file, and it is the wrong place for one: an assertion
/// built on a re-implemented parser fails in ways that look like applet bugs.
/// Reading the wire format directly keeps these tests pinned to the bytes the
/// client sees.
pub fn uint_at(cbor: &[u8], key: u64) -> Option<u64> {
    let mut i = 0;
    let (major, pairs) = cbor_head(cbor, &mut i)?;
    if major != 5 {
        return None;
    }
    for _ in 0..pairs {
        let (km, k) = cbor_head(cbor, &mut i)?;
        if km != 0 {
            return None;
        }
        let value_at = i;
        cbor_skip(cbor, &mut i)?;
        if k != key {
            continue;
        }
        let mut j = value_at;
        let (vm, v) = cbor_head(cbor, &mut j)?;
        return match vm {
            0 => Some(v),
            1 => None,
            _ => None,
        };
    }
    None
}

/// The byte string at `key` out of a CTAP2 response map, or `None`.
///
/// The counterpart of [`uint_at`], and it exists for the same reason: a
/// getAssertion reply carries its `authData` — and therefore its `signCount` —
/// as a **byte string**, and reading that off the wire needs the same
/// walk-the-bytes discipline rather than a second parser written for one test.
pub fn bstr_at(cbor: &[u8], key: u64) -> Option<Vec<u8>> {
    let mut i = 0;
    let (major, pairs) = cbor_head(cbor, &mut i)?;
    if major != 5 {
        return None;
    }
    for _ in 0..pairs {
        let (km, k) = cbor_head(cbor, &mut i)?;
        if km != 0 {
            return None;
        }
        let value_at = i;
        cbor_skip(cbor, &mut i)?;
        if k != key {
            continue;
        }
        let mut j = value_at;
        let (vm, len) = cbor_head(cbor, &mut j)?;
        if vm != 2 {
            return None;
        }
        let end = j.checked_add(len as usize)?;
        return cbor.get(j..end).map(|b| b.to_vec());
    }
    None
}

/// The integer keys of a CBOR map, in wire order, with their values skipped.
///
/// **The key *set*, not the decoded map.** US-1557's claim is that the two
/// twins answer the same command with the same CBOR shape — the same key
/// numbering, which is the thing `AGENTS.md` §2 calls binding — and a decoded
/// `BTreeMap`/`Vec` would have thrown that order away, and would have made an
/// assertion built on the *implementation's* parser able to mistake an
/// implementation bug for its own. Reading the head of each item and skipping
/// its value keeps the assertion on the bytes.
///
/// Values are skipped through [`cbor_skip`], so a nested map (`{"id": …}`,
/// which every credMgmt reply carries) does not confuse the walk.
pub fn top_level_keys(cbor: &[u8]) -> Vec<u64> {
    let mut i = 0;
    let mut keys = Vec::new();
    let (major, pairs) = match cbor_head(cbor, &mut i) {
        Some(head) => head,
        None => return keys,
    };
    if major != 5 {
        return keys;
    }
    for _ in 0..pairs {
        let key_at = i;
        if cbor_skip(cbor, &mut i).is_none() {
            break;
        }
        if cbor_skip(cbor, &mut i).is_none() {
            break;
        }
        let mut j = key_at;
        match cbor_head(cbor, &mut j) {
            Some((0, k)) => keys.push(k),
            _ => break,
        }
    }
    keys
}

/// The CBOR major type and argument of the item starting at `i`.
///
/// A hand-rolled four-line CBOR head reader, and the reason is that the two
/// helper parsers in the tree cannot both do what these tests need:
/// `cbor::no_heap::Parser` exposes one linear cursor with no way to look at a
/// value's bytes after `next` has stepped over it, and it is the parser the
/// **implementation** uses — so a test that shared it could not tell an
/// implementation bug from its own. This one reads the wire format directly,
/// which is the point of a wire-format assertion.
fn cbor_head(b: &[u8], i: &mut usize) -> Option<(u8, u64)> {
    let b0 = *b.get(*i)?;
    *i += 1;
    let major = b0 >> 5;
    let arg = match b0 & 0x1F {
        0..=23 => u64::from(b0 & 0x1F),
        24 => {
            let v = u64::from(*b.get(*i)?);
            *i += 1;
            v
        }
        25 => {
            let v = u16::from_be_bytes([*b.get(*i)?, *b.get(*i + 1)?]);
            *i += 2;
            u64::from(v)
        }
        26 => {
            let v = u32::from_be_bytes([
                *b.get(*i)?, *b.get(*i + 1)?, *b.get(*i + 2)?, *b.get(*i + 3)?,
            ]);
            *i += 4;
            u64::from(v)
        }
        27 => {
            let tail: [u8; 8] = b.get(*i..*i + 8)?.try_into().ok()?;
            *i += 8;
            u64::from_be_bytes(tail)
        }
        // 28..=30 are reserved and 31 is indefinite-length. Neither encoder in
        // this applet emits either, so refusing them is honest rather than
        // permissive: a value this cannot read is a value it will not guess at.
        _ => return None,
    };
    Some((major, arg))
}

/// Step `i` past exactly one CBOR item.
fn cbor_skip(b: &[u8], i: &mut usize) -> Option<()> {
    let (major, arg) = cbor_head(b, i)?;
    match major {
        0 | 1 => {}
        2 | 3 => {
            *i = i.checked_add(arg as usize)?;
            if *i > b.len() {
                return None;
            }
        }
        4 => {
            for _ in 0..arg {
                cbor_skip(b, i)?;
            }
        }
        5 => {
            for _ in 0..arg {
                cbor_skip(b, i)?;
                cbor_skip(b, i)?;
            }
        }
        6 => {
            cbor_skip(b, i)?;
            cbor_skip(b, i)?;
        }
        7 => match arg {
            20..=23 => {}
            25 => *i = i.checked_add(2)?,
            26 => *i = i.checked_add(4)?,
            27 => *i = i.checked_add(8)?,
            _ => {}
        },
        _ => return None,
    }
    Some(())
}

/// The RP id string in a credMgmt `enumerateRpsBegin` reply.
///
/// **Both dialects, deliberately.** PicoForge puts the `{1: "id"}` map under
/// key **3** with the RP's hash under key **4** (`device_core.rs`'s encoder —
/// note AGENTS.md §2's shorthand "rp=3, rpID=4" names key 4 `rpID` where the
/// encoder calls it `rpIdHash`, so the *map* is the thing to look at either
/// way); CTAP 2.1 §12.1.6 puts the same map under key **1**. Accepting both
/// keeps the assertion about the content — that the RP the snapshot holds
/// actually came back — and leaves the dialect itself to
/// `credmgmt_ctap2_spec.rs`, which is where it is pinned against the spec.
pub fn enumerate_rps_id(cbor: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    let (major, pairs) = cbor_head(cbor, &mut i)?;
    if major != 5 {
        return None;
    }
    for _ in 0..pairs {
        let (km, k) = cbor_head(cbor, &mut i)?;
        if km != 0 {
            return None;
        }
        let value_at = i;
        cbor_skip(cbor, &mut i)?;
        if k != 1 && k != 3 {
            continue;
        }
        // The value is a one-pair map in both dialects. **Its key is the text
        // `"id"`, not the integer 1** — CTAP 2.1 §12.1.6 spells the PublicKey
        // Credential Descriptor that way and the encoder writes what the encoder
        // writes (`device_core.rs`: `push_tstr("id")` then the RP id). Reading it
        // as an integer is the mistake this comment exists to stop a future
        // reader repeating.
        let mut j = value_at;
        let (vm, inner_pairs) = cbor_head(cbor, &mut j)?;
        if vm != 5 || inner_pairs != 1 {
            continue;
        }
        let (ikm, inner_len) = cbor_head(cbor, &mut j)?;
        if ikm != 3 {
            continue;
        }
        let key_end = j.checked_add(inner_len as usize)?;
        if cbor.get(j..key_end) != Some(&b"id"[..]) {
            continue;
        }
        j = key_end;
        let (tm, len) = cbor_head(cbor, &mut j)?;
        if tm != 3 {
            continue;
        }
        let end = j.checked_add(len as usize)?;
        return Some(cbor.get(j..end)?.to_vec());
    }
    None
}
