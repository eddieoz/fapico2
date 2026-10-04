//! Host (non-arm) trussed platform (S-721-2, D-D).
//!
//! The host analog of [`super::device::DevicePlatform`]: OS entropy (the
//! [`crate::trng`] host source — the host side of the device's "no
//! software PRNG" rule), littlefs2 stores over heap-backed buffers, and a
//! no-op UI. It runs the real `opcard` card logic over exactly the same
//! "call thyself" [`super::runner::SyscallRunner`] client as the device —
//! the emulation binary (`fapico2-firmware` `emulation` feature) and the
//! `apps/openpgp` device-path tests drive one `OpenPgpApp` over this
//! platform instead of a second, virt-only one.
//!
//! `alloc` is used for the backing buffers — host-only by construction
//! (this module is gated `feature = "host-backend"` AND
//! `not(target_arch = "arm")`, so it never compiles into the device
//! binary; the CI no-heap grep gates the device sources). Every consumer
//! of this module (host tests, the emulation binary) links `std`, so the
//! allocations resolve against the process global allocator.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;

use littlefs2::consts::{U256, U8};
use littlefs2::driver::Storage;
use littlefs2::fs::{Allocation, Filesystem};
use littlefs2_core::DynFilesystem;
use rand_core::{CryptoRng, RngCore};
use trussed::platform::{Platform, UserInterface};
use trussed::store::Store;

use crate::trng;

use super::dispatch::{MigrationAuthority, OpcardDispatch};
use super::runner::{with_backend, Client};
use crate::{migration::MigrationError, secure_store::SecureStore};

/// Internal-FS size, in 4 KiB blocks.
///
/// **This no longer mirrors the device.** US-1538 split the device's 1 MiB
/// trussed window into `ifs` 192 blocks (768 KiB) and `efs` 64 blocks (256 KiB),
/// so the device's `ifs` is 192, not 256. The host twin still allocates 256 for
/// `ifs` and 8 for `efs`/`vfs`, which is a deliberate divergence rather than an
/// oversight: the twin exists to exercise card logic, and its sizes are chosen
/// to be obviously large enough rather than to match. Anything that depends on
/// the device geometry must read `device::TRUSSED_IFS_BLOCKS` /
/// `device::TRUSSED_EFS_BLOCKS`, never these.
const INTERNAL_BLOCKS: usize = 256;
/// efs/vfs size: the host's RAM stores (8 × 4 KiB). On device `efs` is flash
/// (US-1538) and only `vfs` is RAM.
const RAM_BLOCKS: usize = 8;

/// littlefs2 `Storage` over a (leaked, host-only) heap buffer.
///
/// The buffer is held as a raw pointer rather than `&'static mut [u8]` so
/// that a "power cycle" test can mount the *same* backing buffer twice in
/// sequence without the borrow checker treating the first (leaked) mount's
/// borrow as live during the second. Buffers are leaked for the process
/// lifetime and the host builds here are single-threaded, so the mounts
/// never actually overlap in time.
pub struct BufStorage<const BLOCKS: usize> {
    buf: *mut [u8],
}

impl<const BLOCKS: usize> BufStorage<BLOCKS> {
    /// SAFETY: the buffer was leaked for the process lifetime; `&mut self`
    /// guarantees at most one in-flight driver call at a time.
    fn with_buf(&mut self) -> &mut [u8] {
        unsafe { &mut *self.buf }
    }
}

impl<const BLOCKS: usize> Storage for BufStorage<BLOCKS> {
    const READ_SIZE: usize = 256;
    const WRITE_SIZE: usize = 256;
    const BLOCK_SIZE: usize = 4096;
    const BLOCK_COUNT: usize = BLOCKS;
    const BLOCK_CYCLES: isize = -1;

    type CACHE_SIZE = U256;
    type LOOKAHEAD_SIZE = U8;

    fn read(&mut self, off: usize, buf: &mut [u8]) -> littlefs2::io::Result<usize> {
        let s = self.with_buf();
        buf.copy_from_slice(&s[off..off + buf.len()]);
        Ok(buf.len())
    }

    fn write(&mut self, off: usize, data: &[u8]) -> littlefs2::io::Result<usize> {
        let s = self.with_buf();
        s[off..off + data.len()].copy_from_slice(data);
        Ok(data.len())
    }

    fn erase(&mut self, off: usize, len: usize) -> littlefs2::io::Result<usize> {
        let s = self.with_buf();
        s[off..off + len].fill(0xFF);
        Ok(len)
    }
}

/// A 0xFF-filled buffer leaked for the process lifetime, as a raw pointer
/// (see the [`BufStorage`] docs for why the raw pointer matters).
pub fn leak_buf(n: usize) -> *mut [u8] {
    let b = Box::leak(Box::new(vec![0xFFu8; n].into_boxed_slice()));
    core::ptr::addr_of_mut!(**b)
}

/// Mount (formatting on first boot) a littlefs2 filesystem over a leaked
/// buffer and return a `&'static dyn DynFilesystem` to it. The storage,
/// allocation, and filesystem are all leaked so the reference is valid for
/// the whole process (single-threaded host build; `alloc` is fine here).
pub fn mount_fs<const BLOCKS: usize>(buf: *mut [u8]) -> &'static dyn DynFilesystem {
    let storage: &'static mut BufStorage<BLOCKS> =
        Box::leak(Box::new(BufStorage { buf }));
    let alloc: &'static mut Allocation<BufStorage<BLOCKS>> = Box::leak(Box::new(Allocation::new()));
    if !Filesystem::is_mountable(storage) {
        Filesystem::format(storage).expect("host backend: format littlefs2 storage");
    }
    let fs = Filesystem::mount(alloc, storage).expect("host backend: mount littlefs2 storage");
    Box::leak(Box::new(fs))
}

/// trussed `Store` over three mounted littlefs2 filesystems (the same
/// shape as the device's `DeviceFsStore`). `Copy` of `'static`
/// references — the mounted filesystems (and their storage/allocation
/// state) live in the leaked host buffers.
#[derive(Clone, Copy)]
pub struct HostStore {
    pub ifs: &'static dyn DynFilesystem,
    pub efs: &'static dyn DynFilesystem,
    pub vfs: &'static dyn DynFilesystem,
}

impl HostStore {
    /// Assemble a store from three already-mounted filesystems.
    pub fn new(
        ifs: &'static dyn DynFilesystem,
        efs: &'static dyn DynFilesystem,
        vfs: &'static dyn DynFilesystem,
    ) -> Self {
        Self { ifs, efs, vfs }
    }

    /// A fresh RAM store at the device's store sizes: internal =
    /// [`INTERNAL_BLOCKS`] 4 KiB blocks, efs/vfs = [`RAM_BLOCKS`]. The
    /// backing buffers are leaked (process lifetime; ~1.1 MiB per call —
    /// fine on the host, where this replaces the device's flash + RAM).
    pub fn fresh() -> Self {
        Self {
            ifs: mount_fs::<INTERNAL_BLOCKS>(leak_buf(INTERNAL_BLOCKS * 4096)),
            efs: mount_fs::<RAM_BLOCKS>(leak_buf(RAM_BLOCKS * 4096)),
            vfs: mount_fs::<RAM_BLOCKS>(leak_buf(RAM_BLOCKS * 4096)),
        }
    }
}

impl Store for HostStore {
    fn ifs(&self) -> &dyn DynFilesystem {
        self.ifs
    }

    fn efs(&self) -> &dyn DynFilesystem {
        self.efs
    }

    fn vfs(&self) -> &dyn DynFilesystem {
        self.vfs
    }
}

/// No-op UI (the service already brackets every request with
/// Processing→Idle; nothing to observe on the host).
#[derive(Debug, Default)]
pub struct NoopUi;

impl UserInterface for NoopUi {}

/// Host fake platform: OS entropy + RAM littlefs2 stores + no-op UI —
/// the host twin of `device::DevicePlatform` (same `Platform` impl shape).
pub struct HostPlatform {
    rng: HostRng,
    store: HostStore,
    ui: NoopUi,
}

impl HostPlatform {
    /// A fresh platform with a fresh RAM store (one leaked ~1.1 MiB per
    /// call — process lifetime, host-only).
    pub fn new() -> Self {
        Self::with_store(HostStore::fresh())
    }

    /// A platform over a caller-assembled store (the "power cycle" tests
    /// remount one backing buffer across calls).
    pub fn with_store(store: HostStore) -> Self {
        Self {
            rng: HostRng::Os,
            store,
            ui: NoopUi,
        }
    }

    /// A platform whose entropy source refuses (US-1006).
    ///
    /// This is the host twin of a wedged RP2350 TRNG, and it exists because
    /// the behaviour under test is a *refusal*: that a request needing
    /// randomness answers a card error and leaves the executor alive. On the
    /// device that refusal comes from `Rp2350Rng::try_fill_bytes` once the
    /// generator cannot re-seed; here `StallingRng` reproduces the same
    /// observable — `try_fill_bytes` returns `Err` — through the same
    /// `RngCore` surface trussed calls, so the test exercises trussed's
    /// real error path rather than a mock of it.
    pub fn with_stalled_rng(store: HostStore) -> Self {
        Self {
            rng: HostRng::Stalled,
            store,
            ui: NoopUi,
        }
    }
}

/// [`HostRng`] with two behaviours, selected at platform construction.
///
/// The indirection is one enum because `HostPlatform` names its `R` in the
/// `Platform` impl, and the two behaviours have to share that type. Splitting
/// it into two structs would mean making `HostPlatform` generic, which would
/// thread a type parameter through every host test for no benefit.
#[derive(Debug, Clone, Copy, Default)]
pub enum HostRng {
    /// OS entropy — the healthy path.
    #[default]
    Os,
    /// `try_fill_bytes` always fails; `fill_bytes` leaves the buffer
    /// untouched. The host twin of a wedged peripheral.
    Stalled,
}

impl HostRng {
    fn ok(&self) -> bool {
        matches!(self, HostRng::Os)
    }
}

/// The one `rand_core` error every refused draw reports, whatever refused it.
///
/// The `expect` cannot fire: `RNG_ERR_RESEED_REFUSED` is a non-zero
/// compile-time constant, so `NonZeroU32::new` returns `Some`. The device's
/// `Rp2350Rng::try_fill_bytes` maps the same condition onto the same code
/// (`device.rs`), so a host refusal and a device refusal are indistinguishable
/// to trussed — which is the point: the twin must be exercising the real
/// error path, not a distinguishable host-only one.
fn starve_error() -> rand_core::Error {
    rand_core::Error::from(
        core::num::NonZeroU32::new(crate::trng::RNG_ERR_RESEED_REFUSED)
            .expect("constant is non-zero"),
    )
}

/// Whether the US-1007 live starvation seam is currently refusing draws.
///
/// `cfg`-gated behind exactly the pair the seam's `mod` declaration carries
/// (`emulation` feature AND non-`arm` target), so a device build resolves
/// this to a constant `false` and the name does not exist there at all.
/// `tests/scripts/check_rng_path.py` fails if the `cfg` is dropped or if this
/// name is reached from outside the declared allowlist.
#[inline]
fn starvation_active() -> bool {
    #[cfg(all(feature = "emulation", not(target_arch = "arm")))]
    {
        crate::entropy_starve::starved()
    }
    #[cfg(not(all(feature = "emulation", not(target_arch = "arm"))))]
    {
        false
    }
}

impl RngCore for HostRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    /// Leaves `buf` untouched when stalled — the same choice the device
    /// `Rp2350Rng` makes, and for the same reason: filling with a constant
    /// would hand a caller predictable bytes and no signal.
    ///
    /// Under the US-1007 seam it leaves the buffer untouched too, because
    /// `trng::random_bytes_into` reaches `HostTrng`, which returns without
    /// writing when the seam is active. This method is `RngCore`'s
    /// *infallible* half, so that is all it can do (D-9); a caller that can
    /// act on a refusal must use `try_fill_bytes`.
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        if self.ok() {
            trng::random_bytes_into(buf);
        }
    }

    /// The honest half, and the one trussed actually calls
    /// (`trussed-0.2.0/src/service.rs:744`). A stall is a real `Err` here,
    /// which is what makes the OpenPGP starvation test possible at all.
    ///
    /// # US-1007: the live seam
    ///
    /// [`HostRng::Stalled`] is a *construction-time* choice — a platform
    /// built stalled stays stalled for its whole life. US-1007 needs the
    /// other thing: a healthy platform that becomes starved and then
    /// recovers, inside one process, with no restart. So the refusal here is
    /// also taken while the emulation's control file exists.
    ///
    /// This is the method the twin's "clean error" assertion lands on,
    /// because it is the only place a request can be *told* entropy is gone
    /// rather than silently handed an untouched buffer.
    fn try_fill_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> core::result::Result<(), rand_core::Error> {
        if !self.ok() || starvation_active() {
            return Err(starve_error());
        }
        trng::random_bytes_into(buf);
        Ok(())
    }
}

impl CryptoRng for HostRng {}

impl Default for HostPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform for HostPlatform {
    type R = HostRng;
    type S = HostStore;
    type UI = NoopUi;

    fn rng(&mut self) -> &mut Self::R {
        &mut self.rng
    }

    fn store(&self) -> Self::S {
        self.store
    }

    fn user_interface(&mut self) -> &mut Self::UI {
        &mut self.ui
    }
}

/// Run `f` with a client over a fresh [`HostPlatform`] (the S-721-1
/// `with_backend` seam, host-flavored): the same "call thyself"
/// `SyscallRunner` client type the device builds. The client (and any
/// `opcard::Card` built from it) must not escape the closure.
pub fn with_host_backend<R>(
    client_id: &str,
    f: impl FnOnce(Client<'_, HostPlatform, OpcardDispatch>) -> R,
) -> R {
    with_backend(HostPlatform::new(), OpcardDispatch::new(), client_id, f)
}

/// Same as [`with_host_backend`], with a shared migration PIN authority
/// attached to the dispatch (S-721-4).
pub fn with_host_backend_and_migration<K: SecureStore, R>(
    client_id: &str,
    store: &mut K,
    otp: &[u8; 32],
    uid: &[u8],
    f: impl FnOnce(Client<'_, HostPlatform, OpcardDispatch<'_>>) -> R,
) -> Result<R, MigrationError> {
    with_host_store_and_migration(HostStore::fresh(), client_id, store, otp, uid, f)
}

/// Reuse a caller-owned filesystem across migration sessions, including reboot
/// tests. Volatile files should be replaced by the caller on a power cycle.
pub fn with_host_store_and_migration<K: SecureStore, R>(
    filesystem: HostStore,
    client_id: &str,
    store: &mut K,
    otp: &[u8; 32],
    uid: &[u8],
    f: impl FnOnce(Client<'_, HostPlatform, OpcardDispatch<'_>>) -> R,
) -> Result<R, MigrationError> {
    let authority = MigrationAuthority::new(store, otp, uid)?;
    Ok(with_backend(
        HostPlatform::with_store(filesystem),
        OpcardDispatch::new().with_migration(&authority),
        client_id,
        f,
    ))
}
