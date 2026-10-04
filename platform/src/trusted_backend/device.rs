//! Device (RP2350) trussed platform (S-721-1, US-331).
//!
//! Entropy from the RP2350 TRNG (the sole source — no software PRNG), the
//! trussed internal filesystem on QSPI flash (the `DevFlash` region,
//! controller decision D2), volatile/external littlefs2 stores on static RAM
//! buffers, and the activity LED as the trussed UI.
//!
//! The client, its interchange channel, the platform, and the mounted
//! filesystems all live in `static` memory (init-once at boot, the same
//! write-once discipline as `firmware/src/boot.rs` `STORE` / `FLASH_DEV`),
//! because the client's `TrussedRequester<'static>` borrows the channel and
//! opcard's `Card` must outlive any stack frame (decision D1: the runner is
//! called inline from the executor's task context, so nothing needs a
//! competing task or a heap).
//!
//! **No LTO volatile-read shenanigans are needed here** (unlike the
//! `.secure_partition` read in `firmware/src/boot.rs`): the flash content is
//! read through the embassy-rp driver (ROM flash functions), not through a
//! const-initialized memory-mapped static, so there is no const-foldable
//! initializer to defeat.

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::gpio::Output;
use embassy_rp::peripherals::FLASH;
use embassy_time::Instant;
use littlefs2::consts::{U256, U8};
use littlefs2::driver::Storage;
use littlefs2::fs::{Allocation, FileType, Filesystem};
use littlefs2_core::{DynFilesystem, OpenSeekFrom, Path, PathBuf};
use rand_core::{CryptoRng, RngCore};
use trussed::platform::{Platform, UserInterface};
use trussed::pipe::{ServiceEndpoint, TrussedChannel};
use trussed::store::Store;
use trussed::types::CoreContext;
use trussed::{ClientImplementation, Service};
use trussed_core::types::reboot;

use crate::trng::DrbgTrng;

use super::dispatch::OpcardDispatch;
use super::runner::{Backends, Client, SyscallRunner};

// ---------------------------------------------------------------------------
// Flash region (controller decision D3)
// ---------------------------------------------------------------------------

// US-1536: the window's offset, length and the budget it must stay clear of
// are owned by [`crate::flashmap`] now. They used to be literals here, which is
// how the CI flash budget came to sit 504 KiB *above* this window's start with
// nothing relating the two — a firmware image the ratchet accepted could link
// over the front of this filesystem. Re-exported here because `device` is where
// the window is actually used and `platform/src/trusted_backend/host.rs`
// documents itself against `device::TRUSSED_FS_BLOCKS`.
//
// US-1538 adds the split of that window into the two filesystems this module
// mounts: `ifs` at the front ([`TRUSSED_IFS_BLOCKS`]) and `efs` at the tail
// ([`TRUSSED_EFS_BLOCKS`] at [`TRUSSED_EFS_OFFSET`]). `TRUSSED_FS_OFFSET` /
// `TRUSSED_FS_BLOCKS` still name the *window*, because that is what the linker
// reserves and what `board::KEY_REGION_BYTES` is derived from.
pub use crate::flashmap::{
    BLOCK_SIZE, TRUSSED_EFS_BLOCKS, TRUSSED_EFS_OFFSET, TRUSSED_FS_BLOCKS, TRUSSED_FS_END,
    TRUSSED_FS_OFFSET, TRUSSED_IFS_BLOCKS,
};

/// littlefs2 read quantum.
pub const READ_SIZE: usize = 256;
/// littlefs2 write quantum: a multiple of the flash program (page) size
/// (embassy-rp `PAGE_SIZE = 256`), so the driver never receives a smaller
/// write than the flash accepts.
pub const WRITE_SIZE: usize = 256;

/// QSPI flash size, from the selected board file's `flash_size_kb` (4 MiB on
/// the `pico2` board) — the same `Flash` instance the firmware boot path wraps
/// as `boot::DevFlash`.
///
/// US-1080: this was a fourth hardcoded `4 * 1024 * 1024`, and it was the one
/// that made a second board *fail to compile* rather than misbehave: the type
/// is a const generic, so the firmware's `Flash<_, _, _, FLASH_SIZE>` and this
/// alias have to agree. Board parameterisation is what found it — building the
/// 8 MiB board produced `expected 4194304, found 8388608` at the `boot()` call
/// site, which is the good outcome. Silently keeping 4 MiB here would have let
/// a larger board believe it had a smaller part than it does, and every
/// address past 4 MiB would have been an unchecked read.
const FLASH_SIZE: usize = crate::board::FLASH_SIZE_BYTES;

/// Blocking QSPI flash handle (the type S-721-2 hands to [`DeviceBackend::boot`]).
pub type DevFlash = Flash<'static, FLASH, Blocking, FLASH_SIZE>;

// ---------------------------------------------------------------------------
// Entropy
// ---------------------------------------------------------------------------

/// [`RngCore`] + [`CryptoRng`] adapter over the device's **DRBG** (US-1006).
///
/// # What changed, and why it mattered
///
/// This used to hold an [`Rp2350Trng`] and answer every request from the
/// peripheral, with `try_fill_bytes` written as `self.fill_bytes(buf);
/// Ok(())` — an unconditional success. That signature is the defect US-1006
/// names: it told every caller, including trussed's own
/// `Service::rng()`, that entropy was available, and could not be wrong
/// about that, because the only way it could return an error was never
/// written. A caller that checks the result — and trussed does, mapping it to
/// `Error::EntropyMalfunction` — was being handed a permanent "yes".
///
/// It now serves from the [`DrbgTrng`] built at boot, and the error is real:
/// a generator whose re-seed budget is spent, and whose re-seed the source
/// refuses, reports it.
///
/// # The two methods differ, and the difference is the point
///
/// `rand_core` splits them deliberately:
///
/// * [`try_fill_bytes`](RngCore::try_fill_bytes) is the **honest** one. It
///   propagates [`DrbgTrngError`], and it is what the card's request path
///   must reach — trussed calls it when seeding its own ChaCha8 layer
///   (`trussed-0.2.0/src/service.rs:744`), so a starved generator becomes
///   `Error::EntropyMalfunction` and a card error rather than a panic.
/// * `fill_bytes` is the **infallible** one, because `RngCore` requires it.
///   It cannot report the same failure, so on one it leaves the buffer
///   untouched — see [`DrbgTrng`]'s `Trng` impl for why zeroing was rejected.
///   This is a genuine residual: a caller reaching for `fill_bytes` under
///   starvation gets stale bytes and no signal, and the only mitigation is
///   that no request-path caller in this tree does so.
///
/// The concrete seed source the device builds its one generator from.
///
/// Named rather than generic so `DevicePlatform` — and the `static mut
/// CLIENT` that holds it, and the `take_client()` return type that hands it
/// to the app — can stay non-generic. Making them generic over `S` would
/// thread a type parameter through three write-once statics for no property
/// the device needs; the *host* twin is where a stalling source is useful,
/// and that lives in `host.rs`.
pub type DeviceSeedSource = crate::drbg_seed::FuseSeedSource<
    'static,
    crate::secure_store::SharedStore<'static, crate::secure_store::rp2350::Rp2350SecureStore>,
    crate::trng::Rp2350Probe<'static>,
>;

/// The one generator the device serves nonces from.
pub type DeviceDrbg = DrbgTrng<DeviceSeedSource>;

/// C-1, enforced on the **real** device type at compile time.
///
/// The seed source must stay four borrowed inputs: the OTP row, the flash
/// UID, the secure store and the peripheral probe. There must be no room in it
/// for a cached seed or a cached draw, so a RAM-disclosure bug finds nothing
/// to take — and the fresh draw per call (drbg_seed's C-1) is the property
/// that disappears the moment a cache appears.
///
/// This lives here, next to the alias, because it **cannot** live in a host
/// test: `DeviceSeedSource` and the `Rp2350Probe` inside it are arm-only, so
/// they do not exist in an x86_64 test build. The host suite
/// (`platform/tests/drbg_trng.rs`) measures the generic shape over its own
/// mocks; this is the half that counts, and it is checked by
/// `cargo build -p fapico2-firmware --target thumbv8m.main-none-eabi --release`.
///
/// Five words on a 32-bit target: three thin pointers plus `uid`, a `&[u8]`
/// fat pointer. Written as a sum of the parts so a future field says what
/// grew.
const _: () = assert!(
    core::mem::size_of::<DeviceSeedSource>()
        == core::mem::size_of::<&[u8; 32]>()  // otp_key_1
            + core::mem::size_of::<&[u8]>()   // uid (fat: ptr + len)
            + core::mem::size_of::<&mut crate::secure_store::SharedStore<
                'static,
                crate::secure_store::rp2350::Rp2350SecureStore,
            >>()
            + core::mem::size_of::<&mut crate::trng::Rp2350Probe<'static>>(),
    "the DEVICE's FuseSeedSource has acquired state; it must stay four \
     borrowed inputs (no cached seed, no cached draw)"
);

pub struct Rp2350Rng(DeviceDrbg);

impl Rp2350Rng {
    /// Wrap an already-seeded generator.
    ///
    /// Construction of the generator is the caller's, not this type's: a
    /// refusal to seed is a boot-time decision with its own diagnostics (see
    /// `firmware::boot::init_drbg`), and a constructor here that could fail
    /// would push that decision somewhere it cannot be reported from.
    pub fn new(drbg: DeviceDrbg) -> Self {
        Self(drbg)
    }
}

impl RngCore for Rp2350Rng {
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

    /// The infallible half. On a starved generator this leaves `buf`
    /// untouched rather than fabricating bytes; callers that need the failure
    /// must use [`try_fill_bytes`](RngCore::try_fill_bytes).
    ///
    /// The `debug_assert` is the tripwire for that hole. `RngCore` makes this
    /// method infallible by contract, so "leaves the buffer untouched" is only
    /// safe while nothing can mistake the result for a draw — and there is one
    /// device caller that would: `apps/fido/src/device_app.rs` generates the
    /// persistent FIDO `hkey` through `p256::SecretKey::random`, whose
    /// `RngCore` path lands here, and a starved generator would leave it with
    /// an all-zero key. The release profile has `debug-assertions = false`
    /// (root `Cargo.toml`), so this changes no shipped behaviour; it is the
    /// development-time signal that the infallible seam was reached under
    /// starvation. `tests/scripts/check_rng_path.py` separately forbids
    /// `.random_bytes(` outside a commented allowlist, so a new caller has to
    /// be declared with a reason. Making the seam genuinely fallible is a
    /// follow-up, not this commit — see
    /// `docs/known-gate-divergences.md` (D-9).
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let outcome = self.0.try_random_bytes(buf);
        debug_assert!(
            outcome.is_ok(),
            "Rp2350Rng::fill_bytes is infallible by rand_core contract and left the \
             caller's buffer untouched. Use try_fill_bytes at any site that can act \
             on a starved generator."
        );
        let _ = outcome;
    }

    /// The fallible half — genuinely fallible, which is what the old
    /// `Ok(())` was not.
    ///
    /// The two [`DrbgTrngError`] variants get **distinct** `rand_core` error
    /// codes rather than being collapsed into one. In `no_std` that type is
    /// an opaque `NonZeroU32`, so the code is the only channel a caller has
    /// to tell "budget spent" from "the peripheral stopped answering" — and
    /// those call for different operator responses (retry later vs. reset the
    /// device). Both sit at or above `rand_core::Error::CUSTOM_START`, the
    /// documented range for user-defined codes, so they cannot collide with
    /// `rand` / `getrandom`'s.
    fn try_fill_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> core::result::Result<(), rand_core::Error> {
        self.0.try_random_bytes(buf).map_err(|e| {
            #[cfg(all(feature = "device", target_arch = "arm"))]
            match e {
                crate::trng::DrbgTrngError::ReseedRequired => {
                    defmt::error!("Rp2350Rng: DRBG re-seed required, budget spent");
                }
                crate::trng::DrbgTrngError::Reseed(_) => {
                    defmt::error!("Rp2350Rng: DRBG re-seed refused (peripheral)");
                }
            }
            #[cfg(not(all(feature = "device", target_arch = "arm")))]
            let _ = e;
            // `rand_core::Error` has no public `from_code`; the documented
            // constructor in the 0.6 line is the `From<NonZeroU32>` impl.
            // SAFETY of the unwrap: both constants are non-zero (they are
            // `CUSTOM_START` and `CUSTOM_START + 1`, and `CUSTOM_START` is a
            // compile-time non-zero constant), so `new` cannot return `None`.
            rand_core::Error::from(core::num::NonZeroU32::new(match e {
                crate::trng::DrbgTrngError::ReseedRequired => crate::trng::RNG_ERR_RESEED_REQUIRED,
                crate::trng::DrbgTrngError::Reseed(_) => crate::trng::RNG_ERR_RESEED_REFUSED,
            })
            .expect("CUSTOM_START is non-zero by construction"))
        })
    }
}


impl CryptoRng for Rp2350Rng {}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// [`littlefs2::driver::Storage`] over the embassy-rp blocking QSPI `Flash`
/// driver, confined to the **front** of the trussed window — the `ifs`
/// filesystem, at [`TRUSSED_FS_OFFSET`] for [`TRUSSED_IFS_BLOCKS`] blocks.
///
/// The driver is held by value (constructed at boot from `p.FLASH`; S-721-2
/// passes it in) and is **the one owner of the QSPI handle**: every other
/// filesystem in this module reaches the flash through
/// [`DevFlashStorage::alias`], never by owning a second handle.
pub struct DevFlashStorage {
    flash: DevFlash,
}

impl DevFlashStorage {
    /// The live `ifs` window, at [`TRUSSED_FS_OFFSET`].
    pub fn new(flash: DevFlash) -> Self {
        Self { flash }
    }

    /// A second view of the **same** QSPI handle, for a filesystem that must
    /// address a different part of flash.
    ///
    /// # Why a raw pointer, and why it is sound here
    ///
    /// A QSPI flash part has one controller. Two `DevFlash` values would be two
    /// drivers for one peripheral, which is the thing this module has always
    /// refused to do; a raw pointer to the one owner says the same thing more
    /// honestly, and lets the safety argument be stated once, here.
    ///
    /// It is sound because every alias this returns is used **strictly
    /// sequentially and never re-entrantly**:
    ///
    /// * `ifs` and `efs` are separate flash windows. A trussed syscall resolves
    ///   exactly one `Location` (`trussed-0.2.0/src/store.rs:136-141`), so a
    ///   request touches one of them and not the other, and each
    ///   `blocking_read`/`blocking_write`/`blocking_erase` is a complete
    ///   transaction that returns before the next one begins. The same argument
    ///   as [`LedUi`]'s shared board LED: the device is single-core and the
    ///   executor is cooperative, so there is no point at which two handles are
    ///   inside a flash transaction at once.
    /// * The migration ([`migrate_legacy_window`]) does hold two mounted
    ///   filesystems at once, but it too alternates — read a chunk from the
    ///   legacy volume, write it to the new one — and runs on the boot path
    ///   before any task, client or service exists.
    ///
    /// What this buys back: `ifs` and `efs` both being flash-backed costs zero
    /// permanent `.bss` and zero extra `.bss` growth over the single-owner
    /// design, on a board where `.bss` growth moves `MSPLIM` and shrinks the
    /// main stack (DARK-BOOT-1, documented on the statics below).
    fn alias(&mut self) -> *mut DevFlash {
        core::ptr::addr_of_mut!(self.flash)
    }
}

impl Storage for DevFlashStorage {
    const READ_SIZE: usize = READ_SIZE;
    const WRITE_SIZE: usize = WRITE_SIZE;
    const BLOCK_SIZE: usize = BLOCK_SIZE;
    const BLOCK_COUNT: usize = TRUSSED_IFS_BLOCKS;
    const BLOCK_CYCLES: isize = -1;

    type CACHE_SIZE = U256;
    type LOOKAHEAD_SIZE = U8;

    fn read(&mut self, off: usize, buf: &mut [u8]) -> littlefs2::io::Result<usize> {
        // SAFETY: `&mut self` is an exclusive borrow of the owner, so no other
        // handle is in a flash transaction (see `Self::alias`).
        unsafe { &mut *self.alias() }
            .blocking_read(TRUSSED_FS_OFFSET + off as u32, buf)
            .map_err(|_| littlefs2::io::Error::IO)?;
        Ok(buf.len())
    }

    fn write(&mut self, off: usize, data: &[u8]) -> littlefs2::io::Result<usize> {
        // SAFETY: as `read`.
        unsafe { &mut *self.alias() }
            .blocking_write(TRUSSED_FS_OFFSET + off as u32, data)
            .map_err(|_| littlefs2::io::Error::IO)?;
        Ok(data.len())
    }

    fn erase(&mut self, off: usize, len: usize) -> littlefs2::io::Result<usize> {
        // SAFETY: as `read`.
        unsafe { &mut *self.alias() }
            .blocking_erase(
                TRUSSED_FS_OFFSET + off as u32,
                TRUSSED_FS_OFFSET + (off + len) as u32,
            )
            .map_err(|_| littlefs2::io::Error::IO)?;
        Ok(len)
    }
}

/// [`littlefs2::driver::Storage`] over the **tail** of the trussed window — the
/// `efs` filesystem, at [`TRUSSED_EFS_OFFSET`] for [`TRUSSED_EFS_BLOCKS`]
/// blocks (US-1538).
///
/// # What this type is for
///
/// `Location::External` is opcard's default storage
/// (`vendor/opcard/src/card.rs:569`), and until US-1538 `efs` was a 32 KiB RAM
/// buffer that `mount_ram_fs` **formatted on every boot**. A key written at the
/// default location therefore survived exactly until the next power cycle, and
/// nothing reported an error at any point in between: the write succeeded, into
/// something that was about to be erased. That is the defect. This type is the
/// fix — a second littlefs2 filesystem in flash, mounted like `ifs` and
/// formatted only when it does not already carry a volume.
///
/// `efs` is a tail window because `ifs` must stay at the front: littlefs2 pins
/// `block_count` in the volume superblock and refuses a geometry mismatch
/// (`lfs.c:4523-4531`), so the relocated legacy volume's blocks 0 and 1 — its
/// superblock pair — must stay inside `ifs`.
///
/// # Safety of the aliased handle
///
/// The pointer comes from [`DevFlashStorage::alias`], whose serialization
/// argument is the contract this type depends on. `efs` and `ifs` are distinct
/// flash windows and a trussed request resolves exactly one `Location`, so the
/// two are never inside a flash transaction together.
pub struct DevEfsStorage {
    flash: *mut DevFlash,
}

impl DevEfsStorage {
    /// The `efs` tail window, borrowing the one QSPI handle.
    ///
    /// # Safety
    ///
    /// `flash` must point at the live `DevFlash` owned by the boot-path
    /// `IFS_STORAGE` static, and every access through it must be serialized
    /// against every access through that owner — see [`DevFlashStorage::alias`].
    unsafe fn new(flash: *mut DevFlash) -> Self {
        Self { flash }
    }
}

impl Storage for DevEfsStorage {
    const READ_SIZE: usize = READ_SIZE;
    const WRITE_SIZE: usize = WRITE_SIZE;
    const BLOCK_SIZE: usize = BLOCK_SIZE;
    const BLOCK_COUNT: usize = TRUSSED_EFS_BLOCKS;
    const BLOCK_CYCLES: isize = -1;

    type CACHE_SIZE = U256;
    type LOOKAHEAD_SIZE = U8;

    fn read(&mut self, off: usize, buf: &mut [u8]) -> littlefs2::io::Result<usize> {
        // SAFETY: `Self::new`'s contract — the pointer is the live boot-path
        // handle and accesses are serialized against the `ifs` owner.
        unsafe { &mut *self.flash }
            .blocking_read(TRUSSED_EFS_OFFSET + off as u32, buf)
            .map_err(|_| littlefs2::io::Error::IO)?;
        Ok(buf.len())
    }

    fn write(&mut self, off: usize, data: &[u8]) -> littlefs2::io::Result<usize> {
        // SAFETY: as `read`.
        unsafe { &mut *self.flash }
            .blocking_write(TRUSSED_EFS_OFFSET + off as u32, data)
            .map_err(|_| littlefs2::io::Error::IO)?;
        Ok(data.len())
    }

    fn erase(&mut self, off: usize, len: usize) -> littlefs2::io::Result<usize> {
        // SAFETY: as `read`.
        unsafe { &mut *self.flash }
            .blocking_erase(
                TRUSSED_EFS_OFFSET + off as u32,
                TRUSSED_EFS_OFFSET + (off + len) as u32,
            )
            .map_err(|_| littlefs2::io::Error::IO)?;
        Ok(len)
    }
}

/// littlefs2 `Storage` over the **legacy** trussed window, at
/// [`crate::flashmap::LEGACY_TRUSSED_FS_OFFSET`], read-only.
///
/// Stack-only and never installed in a static: the migration asks "is there a
/// filesystem at the old offset, and if so what is in it?" without giving the
/// module a second owner of the QSPI handle.
///
/// `BLOCK_COUNT` is the **legacy** [`TRUSSED_FS_BLOCKS`] — the whole 1 MiB — and
/// has to be. littlefs2 compares the driver's block count against the volume's
/// superblock and fails the mount on a mismatch (`lfs.c:4523-4531`), so this is
/// the only geometry at which a pre-US-1536 volume can be read at all.
struct LegacyWindow {
    flash: *mut DevFlash,
}

impl LegacyWindow {
    /// A read-only view of the legacy window over the one QSPI handle.
    ///
    /// # Safety
    ///
    /// As [`DevFlashStorage::alias`]: the pointer must be the live boot-path
    /// handle, and accesses serialized against every other use of it.
    unsafe fn new(flash: *mut DevFlash) -> Self {
        Self { flash }
    }
}

impl Storage for LegacyWindow {
    const READ_SIZE: usize = READ_SIZE;
    const WRITE_SIZE: usize = WRITE_SIZE;
    const BLOCK_SIZE: usize = BLOCK_SIZE;
    const BLOCK_COUNT: usize = TRUSSED_FS_BLOCKS;
    const BLOCK_CYCLES: isize = -1;

    type CACHE_SIZE = U256;
    type LOOKAHEAD_SIZE = U8;

    fn read(&mut self, off: usize, buf: &mut [u8]) -> littlefs2::io::Result<usize> {
        // SAFETY: `Self::new`'s contract. `write` and `erase` below refuse, so
        // nothing this handle does can move a byte in the source window.
        unsafe { &mut *self.flash }
            .blocking_read(crate::flashmap::LEGACY_TRUSSED_FS_OFFSET + off as u32, buf)
            .map_err(|_| littlefs2::io::Error::IO)?;
        Ok(buf.len())
    }

    fn write(&mut self, _off: usize, _data: &[u8]) -> littlefs2::io::Result<usize> {
        // The legacy window is never written: that is what makes the migration
        // idempotent and retryable — a power cut leaves the source intact and
        // the next boot tries again from the source, not from a half-written
        // destination.
        Err(littlefs2::io::Error::IO)
    }

    fn erase(&mut self, _off: usize, _len: usize) -> littlefs2::io::Result<usize> {
        Err(littlefs2::io::Error::IO)
    }
}

// RAM littlefs2 storage (32 KiB = 8 × 4 KiB blocks) for the **volatile** store
// only (US-1538). `const_ram_storage!` from littlefs2; the buffer is a
// const-initialized static (the erase value 0xFF), so the "storage" is a
// zero-copy slice of a fixed RAM region. The macro emits a `pub struct`,
// so the invocation is confined to a private submodule — `RamFsStorage`
// is nameable inside this module only, never from the crate root.
//
// It used to back the external store too, which is the defect US-1538 fixes:
// `Location::External` resolved to RAM and `mount_ram_fs` reformatted it on
// every boot. `Location::Volatile` is what RAM is *for* — software key
// generation asks for it deliberately (`vendor/opcard/src/command/gen.rs:171`,
// `:217`), because the private key must not outlive the operation that made
// it.
mod ram_fs {
    use littlefs2::const_ram_storage;
    use littlefs2::consts::{U256, U4};

    const_ram_storage!(
        name = RamFsStorage,
        erase_value = 0xFF,
        read_size = 256,
        write_size = 256,
        cache_size_ty = U256,
        block_size = 4096,
        block_count = 8,
        lookahead_size_ty = U4,
    );
}

// Private import: keeps the type name usable inside this module without
// re-exporting it (the macro emits a `pub struct`, so the path must not
// escape `device`).
use self::ram_fs::RamFsStorage;

/// The trussed [`Store`]: three mounted littlefs2 filesystems — `ifs` and
/// `efs` on the QSPI window, `vfs` on RAM (US-1538). `Copy` of `'static`
/// references — the mounted filesystems and their storage/allocation state live
/// in the statics below (init-once at boot).
#[derive(Clone, Copy)]
pub struct DeviceFsStore {
    ifs: &'static dyn DynFilesystem,
    efs: &'static dyn DynFilesystem,
    vfs: &'static dyn DynFilesystem,
}

impl Store for DeviceFsStore {
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

// The three (storage, allocation, filesystem) static triples. `Filesystem`
// borrows its storage + `Allocation` with one lifetime, so each triple must
// live in distinct `static`s (each is `'static`); `Allocation` is not
// const-initializable, hence `MaybeUninit` + write-once at boot — the
// `firmware/src/boot.rs` `FLASH_DEV` discipline.
//
// US-951: **every** member of all three triples is `MaybeUninit`, the two RAM
// stores included. They used to be `static mut … : RamFsStorage =
// RamFsStorage::new()`, which is a const-initialization to the erase value
// 0xFF, not to zero — so rustc emitted them into **`.data`**, not `.bss`:
// 2 × 32,768 B of real RAM that `size`'s `bss` column omits, which is how a
// 5,056 B main stack zone went unreported for an epic. The write-once-at-boot
// move is byte-identical in effect: the value written is still
// `RamFsStorage::new()`, it is written before any task exists, and
// `mount_ram_fs` unconditionally formats the volume immediately afterwards
// (lfs_format erases the whole device), so neither the initial bytes nor any
// later read can tell the difference. It also takes 64 KiB of flash→RAM
// memcpy out of every boot.
//
// **It does not give any of it back to the stack.** `.data` and `.bss` are
// both RAM inside `0x20000000…0x20082000`; relocating a static between them
// leaves `_stack_end` — and therefore the 5,056 B main stack zone — exactly
// where it was (measured: before 5,056 B, after 5,056 B). The stack deficit
// is real and larger than it looks: the async-main boot path needs a
// ~117,828 B call chain. See `docs/size-report.md` ("Main-stack demand").
static mut IFS_STORAGE: core::mem::MaybeUninit<DevFlashStorage> = core::mem::MaybeUninit::uninit();
static mut IFS_ALLOC: core::mem::MaybeUninit<Allocation<DevFlashStorage>> =
    core::mem::MaybeUninit::uninit();
static mut IFS: core::mem::MaybeUninit<Filesystem<'static, DevFlashStorage>> =
    core::mem::MaybeUninit::uninit();

static mut EFS_STORAGE: core::mem::MaybeUninit<DevEfsStorage> = core::mem::MaybeUninit::uninit();
static mut EFS_ALLOC: core::mem::MaybeUninit<Allocation<DevEfsStorage>> =
    core::mem::MaybeUninit::uninit();
static mut EFS: core::mem::MaybeUninit<Filesystem<'static, DevEfsStorage>> =
    core::mem::MaybeUninit::uninit();

static mut VFS_STORAGE: core::mem::MaybeUninit<RamFsStorage> = core::mem::MaybeUninit::uninit();
static mut VFS_ALLOC: core::mem::MaybeUninit<Allocation<RamFsStorage>> =
    core::mem::MaybeUninit::uninit();
static mut VFS: core::mem::MaybeUninit<Filesystem<'static, RamFsStorage>> =
    core::mem::MaybeUninit::uninit();

impl DeviceFsStore {
    /// Mount (or format, on first boot) the three filesystems. Boot-path
    /// only, before any task exists (single-core; see the static docs).
    ///
    /// The order is load-bearing: `IFS_STORAGE` is written first because it
    /// **owns the QSPI handle**, and both the external storage and the
    /// migration's legacy window are aliases of it
    /// ([`DevFlashStorage::alias`]). Nothing may reach flash before that write.
    fn boot(flash: DevFlash) -> Self {
        // SAFETY: single-core pre-task boot path — each static is written
        // exactly once here, before any executor task exists, and the only
        // live handles afterwards are the `&'static` references stored in
        // this struct (and the channel/client statics, which reach them only
        // through this struct).
        unsafe {
            (*core::ptr::addr_of_mut!(IFS_STORAGE)).write(DevFlashStorage::new(flash));
            (*core::ptr::addr_of_mut!(IFS_ALLOC)).write(Allocation::new());
            let storage = (*core::ptr::addr_of_mut!(IFS_STORAGE)).as_mut_ptr();
            let alloc = (*core::ptr::addr_of_mut!(IFS_ALLOC)).as_mut_ptr();
            migrate_legacy_window(&mut *storage, &mut *alloc);
            if !Filesystem::is_mountable(&mut *storage) {
                defmt::info!("trussed: formatting internal FS (first boot)");
                Filesystem::format(&mut *storage).expect("trussed: format internal FS");
            }
            let ifs = Filesystem::mount(&mut *alloc, &mut *storage)
                .expect("trussed: mount internal FS");
            (*core::ptr::addr_of_mut!(IFS)).write(ifs);

            // The external store is a second window of the same flash part,
            // addressed through an alias of the handle `IFS_STORAGE` owns.
            // SAFETY: `storage` is the live boot-path owner written above; the
            // alias's serialization contract is `DevFlashStorage::alias`.
            (*core::ptr::addr_of_mut!(EFS_STORAGE)).write(DevEfsStorage::new((*storage).alias()));
            let efs = mount_flash_fs(
                &mut *core::ptr::addr_of_mut!(EFS_STORAGE),
                &mut *core::ptr::addr_of_mut!(EFS_ALLOC),
                &mut *core::ptr::addr_of_mut!(EFS),
                "external",
            );
            let vfs = mount_ram_fs(
                &mut *core::ptr::addr_of_mut!(VFS_STORAGE),
                &mut *core::ptr::addr_of_mut!(VFS_ALLOC),
                &mut *core::ptr::addr_of_mut!(VFS),
            );

            Self {
                ifs: &*(*core::ptr::addr_of!(IFS)).as_ptr(),
                efs,
                vfs,
            }
        }
    }
}

/// Format-on-first-boot + mount for a **flash-backed** store.
///
/// # Why this is not `mount_ram_fs`
///
/// `mount_ram_fs` formats unconditionally, because a RAM volume has nothing
/// worth preserving. A flash volume has something worth preserving, and
/// formatting one on every boot is the exact defect US-1538 exists to remove —
/// so the format here is guarded by `is_mountable`, and a store that already
/// carries a volume comes up with its contents intact.
///
/// # Safety
///
/// The caller passes the dedicated single-core boot-path statics (see the
/// statics docs) — each is written exactly once here, before any executor task
/// exists. `label` is a `&'static str` used only in log messages.
unsafe fn mount_flash_fs<S: Storage>(
    storage: &'static mut core::mem::MaybeUninit<S>,
    alloc: &'static mut core::mem::MaybeUninit<Allocation<S>>,
    fs_slot: &'static mut core::mem::MaybeUninit<Filesystem<'static, S>>,
    label: &'static str,
) -> &'static dyn DynFilesystem {
    unsafe {
        let storage = storage.as_mut_ptr();
        if !Filesystem::is_mountable(&mut *storage) {
            defmt::info!("trussed: formatting the {} FS (first boot)", label);
            // `.expect()`, not the fail-closed `return false` that
            // `wipe_internal_fs` uses. The two are different situations: a wipe
            // runs on a device that is already working and can report a
            // failure to a caller, while this runs on a volume that has *no*
            // content to fall back to — if the first-boot format does not
            // succeed there is nothing to mount and nothing to serve, so the
            // only outcomes are a device that comes up or one that does not.
            // That is the boot path's existing discipline (see the format in
            // `DeviceFsStore::boot`), not a new rule introduced here.
            Filesystem::format(&mut *storage).expect("trussed: format flash FS");
        }
        alloc.write(Allocation::new());
        let fs = Filesystem::mount(&mut *alloc.as_mut_ptr(), &mut *storage)
            .expect("trussed: mount flash FS");
        fs_slot.write(fs);
        &*fs_slot.as_ptr()
    }
}

/// One-shot migration of a populated pre-US-1536 window into the split
/// geometry (US-1538).
///
/// # What this carries, and why it is no longer a byte copy
///
/// The window moved from `0x102_000` to `0x200_000` (US-1536) and was then
/// split into `ifs` + `efs` (US-1538). A unit provisioned before either has a
/// populated littlefs2 volume at `0x102_000` that is **256 blocks** wide, and
/// this is what carries it across — otherwise the split is a silent wipe of
/// every OpenPGP and PIV key on the unit.
///
/// Until US-1538 this function erased the new window and streamed the old
/// bytes into it, which was exactly right while both windows had the same
/// geometry. **littlefs2 stores `block_count` in the volume superblock and
/// refuses to mount a volume whose geometry does not match the driver's**
/// (`lfs.c:4523-4531`, `Invalid block count` → `LFS_ERR_INVAL`). A 256-block
/// volume dropped into a [`TRUSSED_IFS_BLOCKS`]-block `ifs` is therefore not a
/// volume with a truncated tail; it is an *unmountable* one, and the caller's
/// `is_mountable` → `format` fall-through would erase it. That failure mode is
/// executable and is pinned by
/// `platform/tests/fs_store_backing.rs::a_legacy_volume_will_not_mount_in_the_split_window`,
/// which runs the same refusal against the real C library.
///
/// So the contents cross as **files**: the destination is formatted at the new
/// geometry, then every directory is recreated and every file's bytes are
/// streamed across. littlefs2 offers no shrink — `lfs_fs_grow` only grows
/// (`lfs.c:5180-5185`) — so re-creating the volume at the new size is the only
/// way to keep the keys.
///
/// # Why it is safe to run on every boot
///
/// The legacy window is **read-only** here and never written, so the decision
/// tree is naturally idempotent with no marker record to keep in sync:
///
/// 1. the current `ifs` mounts → nothing to do (the normal case, including
///    every boot after a successful migration);
/// 2. the current `ifs` is empty **and** the legacy window mounts → migrate,
///    then let the caller's `is_mountable` check confirm the result;
/// 3. neither mounts → the caller's first-boot format, i.e. an unprovisioned
///    unit starting empty at the new geometry.
///
/// A power cut mid-migration leaves the source intact and the destination
/// un-mountable, which lands on arm 2 again next boot. There is no state in
/// which the migration has to be "told" to run.
///
/// A migration that *reports* failure erases its own partial destination for the
/// same reason — a half-written volume is mountable, and a mountable volume is
/// one the boot path would accept forever, so without the erase the unit would
/// come up permanently missing whichever files did not make it across.
///
/// # The one way this fails for good
///
/// [`LegacyWindow`] refuses writes, so a legacy volume whose mount itself
/// needs a `gstate` commit (`lfs_dir_fetchmatch` → `lfs_dir_commit`, taken when
/// the volume's gstate is non-zero) cannot be mounted at all. That fails the
/// migration on every boot and leaves the device empty with the source intact
/// and reported — recoverable, not silent. It is not a state this firmware
/// writes: the legacy window was written by this same littlefs2 (0.8, on-disk
/// v2.0), whose mounts do not write. It is recorded rather than worked around,
/// because the workaround — a writable legacy handle — would be the one change
/// that could destroy the only copy of a user's keys.
///
/// # Why failure falls through to a format rather than halting
///
/// A migration that fails still leaves the caller's `is_mountable` false, which
/// is the first-boot path: the unit comes up empty and reachable rather than
/// parked. The legacy window is left intact for recovery. Halting here would
/// trade a recoverable, loudly-logged empty device for an unreachable one, and
/// the boot path's whole discipline is that the board always reaches USB.
///
/// # The cost, stated rather than hidden
///
/// This holds two mounted volumes at once, which is the one place in the module
/// where two handles alias the QSPI part ([`DevFlashStorage::alias`]), and it
/// puts an [`Allocation`] (856 B, measured on x86_64) on the boot-path stack.
///
/// Both are bounded and both were taken knowingly:
///
/// * the stack cost is *transient* — the frame is gone before `Service` is
///   constructed — and permanent `.bss` is the worse trade here, because on
///   this board `.bss` growth moves `MSPLIM` and shrinks the main stack
///   (DARK-BOOT-1, on the statics above). The measured margin is in
///   `docs/size-report.md` ("Main-stack demand") and is enforced by
///   `tests/scripts/check_boot_chain.py`.
/// * the tree walk is depth-capped at [`MIGRATE_MAX_DEPTH`] so a pathological
///   tree cannot become an unbounded boot-path loop (S8). Nothing trussed or
///   opcard writes nests that deep; a tree that does is reported and the
///   migration fails closed, which is the same outcome as any other failure
///   here.
fn migrate_legacy_window(storage: &mut DevFlashStorage, alloc: &mut Allocation<DevFlashStorage>) {
    if Filesystem::is_mountable(&mut *storage) {
        return;
    }
    // Probe the legacy window through a short-lived, stack-only handle.
    //
    // It aliases the flash rather than owning it, which is what keeps
    // `DevFlashStorage` down to a single field: an `offset` field would have
    // cost 8 B of `.bss` on `IFS_STORAGE` (2 -> 8), and this board has 4 B of
    // unallocated SRAM in total — DARK-BOOT-1 territory, where RAM growth is a
    // hardware risk and not merely a gate failure.
    let legacy_mounts = {
        // SAFETY: `storage` is the live boot-path owner of the QSPI handle; the
        // probe exists for the length of this call, writes nothing (both
        // `write` and `erase` on `LegacyWindow` refuse), and no other handle is
        // inside a flash transaction while it runs.
        let mut probe = unsafe { LegacyWindow::new(storage.alias()) };
        Filesystem::is_mountable(&mut probe)
    };
    if !legacy_mounts {
        defmt::info!("trussed: no legacy window; starting empty at the new offset");
        return;
    }

    defmt::info!("trussed: migrating the legacy internal FS into the split window");
    if Filesystem::format(&mut *storage).is_err() {
        defmt::error!("trussed: migration failed (1); the legacy window is intact");
        return;
    }

    let mut legacy_alloc = Allocation::new();
    let migrated = {
        // SAFETY: as the probe above. Two mounts are now alive — the legacy
        // volume (read-only, `write`/`erase` refuse) and the freshly formatted
        // destination — and both address the one QSPI handle. They alternate:
        // each littlefs2 call completes before the next begins, no call
        // re-enters flash, and this runs on the boot path before any task,
        // client or service exists. That is the serialization
        // `DevFlashStorage::alias` requires, and the only reason it is stated
        // here and nowhere else.
        let mut legacy_storage = unsafe { LegacyWindow::new(storage.alias()) };
        let Ok(legacy) = Filesystem::mount(&mut legacy_alloc, &mut legacy_storage) else {
            defmt::error!("trussed: migration failed (2); the legacy window is intact");
            return;
        };
        let Ok(dst) = Filesystem::mount(&mut *alloc, &mut *storage) else {
            defmt::error!("trussed: migration failed (3); the legacy window is intact");
            return;
        };
        // No explicit sync, and none is needed: littlefs2 commits a file's
        // metadata when the file handle closes (`lfs_file_close_` ends in
        // `lfs_dir_commit` on the containing directory) and a directory's when
        // it is created. The 0.8 Rust `Filesystem` exposes no `sync` because
        // there is nothing left to flush by the time a call has returned, so a
        // copy that returns `Ok` is already in flash.
        let outcome = copy_tree(&legacy, &dst);
        if outcome.is_err() {
            defmt::error!("trussed: migration failed (4); the legacy window is intact");
        }
        outcome.is_ok()
    };
    // `dst` is gone; its borrow of `storage` and of the caller's `Allocation`
    // ended with the block. The caller's mount gets a fresh allocation for the
    // same reason `wipe_internal_fs` rewrites its own — the one in `alloc`
    // belongs to the mount that has just been dropped.
    *alloc = Allocation::new();
    if !migrated {
        // **Erase the partial destination.** This is the difference between a
        // retryable migration and a silent key loss: a failed copy still leaves
        // a *mountable* volume, because the format succeeded and some files
        // made it across. If boot mounted that, the unit would come up with
        // most of its OpenPGP keys missing and the legacy window would never be
        // looked at again — a permanently half-provisioned device with no
        // indication of why. Formatting the destination back leaves it
        // un-mountable, which is exactly the state that sends the next boot to
        // arm 2 and re-runs the whole copy from the intact source.
        defmt::error!("trussed: migration incomplete; erasing the partial window to retry");
        let _ = Filesystem::format(&mut *storage);
        return;
    }
    if Filesystem::is_mountable(&mut *storage) {
        defmt::info!("trussed: migration complete");
    } else {
        defmt::error!("trussed: migrated window does not mount; starting empty");
    }
}

/// Copy every directory and file of one littlefs2 volume into another.
///
/// # Why the file level and not the block level
///
/// littlefs2 addresses a file's data by CTZ skip-list over *block indices in
/// `[0, block_count)`*, and the block count is part of the volume's identity
/// (`lfs.c:4523-4531`). Shrinking a volume from 256 blocks to
/// [`TRUSSED_IFS_BLOCKS`] therefore cannot be done by moving blocks around:
/// there is nowhere for the live blocks above the new bound to go, and
/// littlefs2 has no shrink. Re-creating the volume at the new geometry and
/// replaying its contents is the whole of the fix.
///
/// The destination is the *front* of the window, which is why the paths here are
/// the same on both sides — the migration moves content, not geometry.
///
/// `Result<(), u8>` rather than `littlefs2::io::Result` because the code is only
/// logged: the caller decides what an unmountable window means, and that is the
/// first-boot path.
fn copy_tree(src: &dyn DynFilesystem, dst: &dyn DynFilesystem) -> Result<(), u8> {
    let root = PathBuf::try_from("/").map_err(|_| MIGRATE_ERR_PATH)?;
    copy_dir(src, dst, root.as_path(), 0)
}

/// Recursive half of [`copy_tree`].
///
/// Depth is capped at [`MIGRATE_MAX_DEPTH`] (S8: no unbounded loop on the boot
/// path), and a failure at any entry stops the walk rather than continuing — a
/// half-migrated key set is worse than a loudly-reported empty one, because the
/// destination still has whatever did make it across, and the source is intact.
fn copy_dir(
    src: &dyn DynFilesystem,
    dst: &dyn DynFilesystem,
    path: &Path,
    depth: usize,
) -> Result<(), u8> {
    if depth > MIGRATE_MAX_DEPTH {
        defmt::error!("trussed: migration tree deeper than {=usize} levels", MIGRATE_MAX_DEPTH);
        return Err(MIGRATE_ERR_DEPTH);
    }
    let mut failure: Option<u8> = None;
    let listed = src.read_dir_and_then(path, &mut |entries| {
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    failure = Some(MIGRATE_ERR_LIST);
                    break;
                }
            };
            // `.` and `..` are real directory entries in littlefs2, and
            // `DirEntry::path()` builds `parent + "/" + name`
            // (`littlefs2-0.8.1/src/fs.rs:1020`), so recursing into `.` asks
            // the filesystem to list itself and hands back another `.` — an
            // unbounded walk that the depth cap below would eventually turn
            // into a failed migration rather than a completed one. Skip them.
            let name = entry.file_name().as_ref();
            if name == "." || name == ".." {
                continue;
            }
            let outcome = match entry.file_type() {
                FileType::Dir => {
                    if dst.create_dir_all(entry.path()).is_err() {
                        Err(MIGRATE_ERR_MKDIR)
                    } else {
                        copy_dir(src, dst, entry.path(), depth + 1)
                    }
                }
                FileType::File => copy_file(src, dst, entry.path(), entry.metadata().len()),
            };
            if let Err(code) = outcome {
                failure = Some(code);
                break;
            }
        }
        Ok(())
    });
    // The callback cannot return the walk's own error code (the closure is
    // `FnMut` over an iterator the library owns), so the code is carried out by
    // `failure` and the `Ok(())` above keeps the directory iteration itself
    // going long enough to record it.
    failure.map_or_else(
        || if listed.is_err() { Err(MIGRATE_ERR_LIST) } else { Ok(()) },
        Err,
    )
}

/// Copy one file's bytes across in [`MIGRATE_CHUNK`]-sized pieces.
///
/// `size` comes from the source's own metadata and is treated as a bound, not
/// as a promise: a file that ends early is a copy failure, not a short file.
/// Silently truncating a private key would leave a credential that reads back
/// as corrupt much later, on the first signature, with nothing to connect it
/// back to this boot.
fn copy_file(
    src: &dyn DynFilesystem,
    dst: &dyn DynFilesystem,
    path: &Path,
    size: usize,
) -> Result<(), u8> {
    // Create the destination first, so a zero-length file still exists on the
    // far side and a later chunked write has something to open.
    if dst.write(path, &[]).is_err() {
        return Err(MIGRATE_ERR_CREATE);
    }
    let mut buf = [0u8; MIGRATE_CHUNK];
    let mut pos = 0usize;
    let copied = src.open_file_and_then(path, &mut |file| {
        while pos < size {
            let read = match file.read(&mut buf) {
                Ok(0) | Err(_) => return Err(littlefs2_core::Error::IO),
                Ok(n) => n,
            };
            if dst
                .write_chunk(path, &buf[..read], OpenSeekFrom::Start(pos as u32))
                .is_err()
            {
                return Err(littlefs2_core::Error::IO);
            }
            pos += read;
        }
        Ok(())
    });
    if copied.is_err() {
        return Err(MIGRATE_ERR_COPY);
    }
    Ok(())
}

/// Chunk size for the migration copy: one flash page (`embassy-rp`
/// `PAGE_SIZE = 256`, which is also this driver's [`WRITE_SIZE`]).
///
/// Deliberately a small **stack** buffer. The migration runs on the boot path
/// before any task exists, and a buffer sized to a whole block would be 16×
/// this for no benefit — the destination is flash, so there is nothing to
/// gain by holding more of it in RAM at once.
const MIGRATE_CHUNK: usize = WRITE_SIZE;

/// How deep [`copy_dir`] will descend.
///
/// Four levels (root + three) is far beyond anything trussed or opcard writes:
/// a key file sits at `/<client>/<hash>` and the trussed-auth PIN credentials at
/// `/auth/<hash>`. The cap exists so that a corrupted or hostile directory
/// cannot turn the boot-path migration into an unbounded walk (S8), and it is
/// reported rather than silently truncating the copy.
const MIGRATE_MAX_DEPTH: usize = 3;

/// Migration failure codes. Distinct so a device log says which step failed —
/// they are the only trace a user with a dead key set will ever see.
const MIGRATE_ERR_PATH: u8 = 1;
const MIGRATE_ERR_LIST: u8 = 2;
const MIGRATE_ERR_MKDIR: u8 = 3;
const MIGRATE_ERR_CREATE: u8 = 4;
const MIGRATE_ERR_COPY: u8 = 5;
const MIGRATE_ERR_DEPTH: u8 = 6;

/// Format + mount one RAM-backed filesystem into its static triple.
///
/// **The volatile store only** (US-1538). It used to build the external store
/// too, and that is the difference the story exists to remove: a RAM volume
/// that is reformatted on every boot is the right thing for
/// `Location::Volatile` and the wrong thing for every other location. It is
/// **always formatted** here (fresh on every power-up — there is nothing to
/// preserve), which is exactly why it must not serve `Location::External`.
///
/// The storage is a `MaybeUninit` slot (US-951) rather than a const-initialized
/// `static`, so the `[0xFF; 32 KiB]` erase fill happens *here* instead of at
/// compile time; that keeps the 32 KiB out of `.data` (so it no longer
/// counts as flash) and out of every boot's `.data`-copy loop. It is a
/// `MaybeUninit::write` at the slot's own address, so no 32 KiB stack
/// temporary is materialized on the boot path — which matters, because the
/// stack this runs on is 5,056 B. Note this frees *no* stack: see the statics
/// comment above.
///
/// SAFETY: the caller passes the dedicated single-core boot-path statics
/// (see the statics docs) — each is written exactly once here, before any
/// executor task exists.
fn mount_ram_fs(
    storage: &'static mut core::mem::MaybeUninit<RamFsStorage>,
    alloc: &'static mut core::mem::MaybeUninit<Allocation<RamFsStorage>>,
    fs_slot: &'static mut core::mem::MaybeUninit<Filesystem<'static, RamFsStorage>>,
) -> &'static dyn DynFilesystem {
    unsafe {
        storage.write(RamFsStorage::new());
        let storage = storage.as_mut_ptr();
        alloc.write(Allocation::new());
        Filesystem::format(&mut *storage).expect("trussed: format RAM FS");
        let fs = Filesystem::mount(&mut *alloc.as_mut_ptr(), &mut *storage)
            .expect("trussed: mount RAM FS");
        fs_slot.write(fs);
        &*fs_slot.as_ptr()
    }
}

// ---------------------------------------------------------------------------
// UI (activity LED)
// ---------------------------------------------------------------------------

/// Trussed UI on the activity LED (GPIO25 = [`crate::LED_PIN`], active-low
/// on the Pico 2).
///
/// The trussed service already brackets every request with
/// `Processing`→`Idle` (see `process` in `trussed-0.2.0/src/service.rs`), so
/// `set_status` alone *is* the activity behavior. [`Self::refresh`] is a
/// no-op.
///
/// **Shared pin (S-721-2, D-E.3):** the board LED is also driven by the
/// firmware's 1 Hz heartbeat task (`firmware/src/main.rs`
/// `led_heartbeat_task`, reborrows the same `LED_OUT` slot). `Output` is
/// not shareable by value (`set_low`/`set_high` take `&mut self`), so the
/// UI holds a raw pointer to the one boot-constructed `Output<'static>`
/// and drives it through the pointer. The two drivers never interleave:
/// the device is single-core and the executor is cooperative — the UI runs
/// only inside a synchronous trussed request section (the "call thyself"
/// runner, no yield point), where it *temporarily overrides* the heartbeat
/// (LED on while processing, restored when the request finishes); the
/// heartbeat resumes between requests. That override is the intended
/// activity indication (see the contract on [`DeviceBackend::boot`]).
pub struct LedUi {
    /// The one boot-constructed board LED (the `firmware` `LED_OUT` slot),
    /// shared with the 1 Hz heartbeat task under single-core serialization
    /// (see the struct docs + [`DeviceBackend::boot`]).
    led: *mut Output<'static>,
    /// Boot instant (the time driver is up by the time `DeviceBackend::boot`
    /// runs — `embassy_rp::init` precedes it in `main`).
    boot: Instant,
}

impl LedUi {
    /// Construct the UI over the shared board LED.
    ///
    /// # Safety
    ///
    /// `led` must point to a valid `Output<'static>` constructed exactly
    /// once on the boot path (the `firmware` `LED_OUT` slot), and every
    /// access (this UI's `set_status`/`wink` and the heartbeat task) must
    /// be serialized single-core — the contract [`DeviceBackend::boot`]
    /// documents; the sole caller is `DevicePlatform::new`, called only
    /// from there.
    pub unsafe fn new(led: *mut Output<'static>) -> Self {
        Self {
            led,
            boot: Instant::now(),
        }
    }
}

impl UserInterface for LedUi {
    fn set_status(&mut self, status: trussed::types::ui::Status) {
        // SAFETY: the pointer is valid for the whole run (boot-constructed
        // `LED_OUT` slot) and single-core serialization keeps this access
        // disjoint from the heartbeat task's (see the struct docs).
        let led = unsafe { &mut *self.led };
        match status {
            // Active-low board LED: set_low = on.
            trussed::types::ui::Status::Processing => led.set_low(),
            _ => led.set_high(),
        }
    }

    fn refresh(&mut self) {
        // No-op: idle-blink cadence is the S-721-2 serve loop's concern.
    }

    fn uptime(&mut self) -> Duration {
        // `embassy_time::Instant::elapsed` returns an `embassy_time::Duration`;
        // the trussed trait wants `core::time::Duration`.
        Duration::from_nanos(self.boot.elapsed().as_nanos())
    }

    fn reboot(&mut self, _to: reboot::To) -> ! {
        // cortex-m 0.7.9's own system-reset helper (safe, `-> !`): DSB,
        // then an AIRCR write of VECTKEY | SYSRESETREQ with the
        // priority-group bits preserved, then a spin — the core never
        // returns here.
        cortex_m::peripheral::SCB::sys_reset()
    }

    fn wink(&mut self, duration: Duration) {
        // Bounded, non-deadlocking blink: at most `duration` of busy-wait,
        // two on/off cycles. (A state consumed by `refresh()` would also be
        // fine; this keeps the UI stateless.) `embassy_time::Duration::as_nanos`
        // is u64, so keep the half-period there too (u64 ns ≈ 584 years — no
        // truncation for any real wink duration).
        // SAFETY: as `set_status` — the pointer is valid for the whole run
        // and single-core serialization keeps this disjoint from the
        // heartbeat task.
        let led = unsafe { &mut *self.led };
        let half_ns = (duration.as_nanos() / 2) as u64;
        for _ in 0..2 {
            led.set_low(); // on (active-low)
            let start = Instant::now();
            while start.elapsed().as_nanos() < half_ns {}
            led.set_high();
            let start = Instant::now();
            while start.elapsed().as_nanos() < half_ns {}
        }
    }
}

// ---------------------------------------------------------------------------
// Platform + client
// ---------------------------------------------------------------------------

/// The device trussed platform (decision D1/D2): TRNG entropy, flash + RAM
/// littlefs2 stores, LED UI.
pub struct DevicePlatform {
    rng: Rp2350Rng,
    store: DeviceFsStore,
    ui: LedUi,
}

impl DevicePlatform {
    /// `led` is the shared board-LED pointer (the `firmware` `LED_OUT`
    /// slot) — the shared-pin contract is documented on
    /// [`DeviceBackend::boot`], the sole caller of this constructor.
    ///
    /// # Safety
    ///
    /// `led` must be a valid, live `Output<'static>` for the whole run
    /// (the boot-constructed `LED_OUT` slot), with single-core-serialized
    /// access per the shared-pin contract on [`DeviceBackend::boot`].
    pub unsafe fn new(
        flash: DevFlash,
        drbg: DeviceDrbg,
        led: *mut Output<'static>,
    ) -> Self {
        // SAFETY: upheld by the caller (`DeviceBackend::boot`) per the
        // `# Safety` contract above.
        Self {
            rng: Rp2350Rng::new(drbg),
            store: DeviceFsStore::boot(flash),
            ui: LedUi::new(led),
        }
    }
}

impl Platform for DevicePlatform {
    type R = Rp2350Rng;
    type S = DeviceFsStore;
    type UI = LedUi;

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

/// The interchange channel. Const-initializable (both ends unclaimed), so a
/// plain `static` — `split(&self)` hands out the `'static` requester and
/// responder by shared borrow.
static CHANNEL: TrussedChannel = TrussedChannel::new();

/// The one device client (init-once; see [`DeviceBackend::boot`]).
///
/// S-721-2: the client is *taken by value* out of this slot exactly once
/// ([`take_client`]) — opcard's `Card` owns its client, so the app (the
/// `OpenPgpApp` static in `firmware`) is the client's sole owner from then
/// on. The slot is left `MaybeUninit::uninit()` and [`client`] panics.
static mut CLIENT: core::mem::MaybeUninit<Client<'static, DevicePlatform, OpcardDispatch<'static>>> =
    core::mem::MaybeUninit::uninit();
static CLIENT_READY: AtomicBool = AtomicBool::new(false);
/// S-721-2: `true` once [`take_client`] has moved the client out of
/// [`CLIENT`] (the app is the sole owner; [`client`] must then panic).
static CLIENT_TAKEN: AtomicBool = AtomicBool::new(false);

/// The device backend namespace: one-shot boot + the client accessors.
pub struct DeviceBackend;

impl DeviceBackend {
    /// The trussed client ID this backend serves — the path namespace under
    /// which the card's keys and files are stored.
    pub const CLIENT_ID: &str = "opcard";

    /// One-shot device boot (decisions D1/D6): builds the platform, mounts
    /// (or formats) the stores, and creates the channel + client in the
    /// statics. The second call panics — the single-core boot path inits
    /// exactly once. S-721-2 calls this from `main` after
    /// `embassy_rp::init` (the time driver must be up for the UI's
    /// `Instant`) and passes the handles out of the `boot::FLASH_DEV` slot.
    ///
    /// # Safety
    ///
    /// `led` must point to the board LED constructed exactly once on the
    /// boot path (the `firmware` `LED_OUT` slot), shared with the 1 Hz
    /// heartbeat task: the two drivers never interleave because the device
    /// is single-core and the executor is cooperative — the trussed UI
    /// runs only inside a synchronous request section (the "call thyself"
    /// runner has no yield point), where it temporarily overrides the
    /// heartbeat, and the heartbeat resumes between requests. See
    /// [`LedUi`].
    // US-939: `#[inline(never)]` — the client/service construction must keep
    // its own frame instead of merging into the Embassy async-main frame
    // (the dark-boot stack overflow).
    #[inline(never)]
    pub unsafe fn boot(
        flash: DevFlash,
        drbg: DeviceDrbg,
        led: *mut Output<'static>,
        migration: Option<&'static dyn super::dispatch::MigrationPinAuthority>,
    ) -> &'static mut Client<'static, DevicePlatform, OpcardDispatch<'static>> {
        assert!(
            !CLIENT_READY.load(Ordering::Relaxed),
            "trusted backend: DeviceBackend::boot() may be called exactly once, at boot"
        );

        // S-724: the software-RSA backend allocates; its static heap must be
        // live before any OpenPGP request runs (keygen/import). Arm binaries
        // that bypass this boot keep an empty allocator — RSA requests fail
        // cleanly instead of wedging.
        #[cfg(feature = "rsa-backend")]
        crate::rsa_heap::init();

        let platform = DevicePlatform::new(flash, drbg, led);
        let (requester, responder) =
            CHANNEL.split().expect("trusted backend: channel must split at boot");
        let ep = ServiceEndpoint::new(
            responder,
            CoreContext::new(
                PathBuf::try_from(Self::CLIENT_ID)
                    .expect("trusted backend: client id must be a valid path"),
            ),
            <OpcardDispatch as Backends>::BACKENDS,
        );
        let dispatch = match migration {
            Some(authority) => OpcardDispatch::new().with_migration(authority),
            None => OpcardDispatch::new(),
        };
        let runner = SyscallRunner::new(Service::with_dispatch(platform, dispatch), ep);
        let client = ClientImplementation::new(requester, runner, None);

        // SAFETY: single-core, pre-task boot path — CLIENT is written exactly
        // once here and never read before CLIENT_READY is set; the returned
        // reference is the sole handle for the rest of the run.
        unsafe {
            (*core::ptr::addr_of_mut!(CLIENT)).write(client);
            CLIENT_READY.store(true, Ordering::Relaxed);
            (*core::ptr::addr_of_mut!(CLIENT)).assume_init_mut()
        }
    }
}

/// Move the one device client out of its static, by value (S-721-2, D-B).
///
/// opcard's `Card` takes its client by value and owns it, so the app
/// (`OpenPgpApp::new(take_client())`) is the client's sole owner from this
/// call on — this is the ownership seam between the boot path (which
/// builds the client) and the app static (which holds it for the rest of
/// the run). May be called exactly once, after
/// [`DeviceBackend::boot`]; afterwards [`client`] panics, and a second
/// `take_client` panics too.
pub fn take_client() -> Client<'static, DevicePlatform, OpcardDispatch<'static>> {
    assert!(
        CLIENT_READY.load(Ordering::Relaxed),
        "trusted backend: DeviceBackend::boot() has not run yet"
    );
    assert!(
        !CLIENT_TAKEN.swap(true, Ordering::Relaxed),
        "trusted backend: the client was already taken (the app owns it)"
    );
    // SAFETY: single-core — `take_client` runs on the boot path, after
    // `DeviceBackend::boot` wrote CLIENT exactly once and before any
    // executor task exists, so nothing else aliases the slot. The
    // `assume_init_read` move + immediate re-write of `uninit` leaves the
    // slot well-defined (`MaybeUninit`) with the client now owned by the
    // caller; `CLIENT_TAKEN` keeps every later `client()` from reading
    // the uninitialized slot.
    unsafe {
        let slot = core::ptr::addr_of_mut!(CLIENT);
        // Move the client out of the slot (by value), then leave the slot
        // well-defined as `uninit` (a moved-out `MaybeUninit` union is
        // re-established explicitly — nothing may assume its bytes).
        let client = (*slot).assume_init_read();
        core::ptr::write(slot, core::mem::MaybeUninit::uninit());
        client
    }
}

/// A `&'static mut` to the one device client.
///
/// S-721-2: the client is taken by value by the app
/// ([`take_client`]), so this accessor exists only for pre-take use and
/// panics once the app owns the client. Also panics (clearly) if called
/// before [`DeviceBackend::boot`] — the boot path inits exactly once, so
/// a legitimate call always succeeds.
pub fn client() -> &'static mut Client<'static, DevicePlatform, OpcardDispatch<'static>> {
    assert!(
        CLIENT_READY.load(Ordering::Relaxed),
        "trusted backend: DeviceBackend::boot() has not run yet"
    );
    assert!(
        !CLIENT_TAKEN.load(Ordering::Relaxed),
        "trusted backend: the client has been taken (the app owns it)"
    );
    // SAFETY: boot initialized CLIENT exactly once before CLIENT_READY was
    // set and take_client has not run (single-core); every call in between
    // sees the initialized value.
    unsafe { (*core::ptr::addr_of_mut!(CLIENT)).assume_init_mut() }
}

// ---------------------------------------------------------------------------
// C string stubs — the littlefs2 C backend's free-function dependencies
// ---------------------------------------------------------------------------
//
// S-721-2: once the firmware actually *calls* the trussed backend, the
// littlefs2 C backend (`lfs.c`) enters the device link for the first time
// (at S-721-1 the module compiled but was LTO-elided — nothing referenced
// it). `lfs.c` calls four C string functions that a no_std device has no
// libc to provide: `strcpy`, `strchr`, `strspn`, `strcspn`. These are the
// sole provider — platform enables littlefs2 with
// `default-features = false`, so littlefs2's own `c-stubs` feature is not
// in the build. On the host these resolve from libc — this module is
// arm/device-gated, so the stubs never collide with it.

/// Set membership for the C string stubs below.
///
/// SAFETY: C ABI contract — `set` is a valid NUL-terminated string.
fn c_str_in_set(c: i8, set: *const i8) -> bool {
    unsafe {
        let mut p = set;
        while *p != 0 {
            if *p == c {
                return true;
            }
            p = p.add(1);
        }
        false
    }
}

/// C ABI stub: first occurrence of `c` in the NUL-terminated string at
/// `s` (or the terminating NUL if `c == 0`), or `NULL` if not present.
///
/// # Safety
///
/// C ABI contract — `s` is a valid NUL-terminated string. (The C caller
/// in `lfs.c` is unaffected by the Rust safety marker.)
#[no_mangle]
pub unsafe extern "C" fn strchr(s: *const i8, c: i8) -> *const i8 {
    // SAFETY: C ABI contract — `s` is a valid NUL-terminated string.
    unsafe {
        let mut p = s;
        loop {
            if *p == c {
                return p;
            }
            if *p == 0 {
                return core::ptr::null();
            }
            p = p.add(1);
        }
    }
}

/// C ABI stub: length of the initial segment of the NUL-terminated string
/// at `s` consisting only of bytes from the NUL-terminated set `set`.
///
/// # Safety
///
/// C ABI contract — both pointers are valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn strspn(mut s: *const i8, set: *const i8) -> usize {
    // SAFETY: C ABI contract — both pointers are valid NUL-terminated
    // strings.
    let mut n = 0;
    unsafe {
        while *s != 0 && c_str_in_set(*s, set) {
            s = s.add(1);
            n += 1;
        }
    }
    n
}

/// C ABI stub: length of the initial segment of the NUL-terminated string
/// at `s` containing no byte from the NUL-terminated set `set`.
///
/// # Safety
///
/// C ABI contract — both pointers are valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn strcspn(mut s: *const i8, set: *const i8) -> usize {
    // SAFETY: C ABI contract — both pointers are valid NUL-terminated
    // strings.
    let mut n = 0;
    unsafe {
        while *s != 0 && !c_str_in_set(*s, set) {
            s = s.add(1);
            n += 1;
        }
    }
    n
}

/// C ABI stub: copy the NUL-terminated string at `src` to `dst`
/// (non-overlapping), return `dst`.
///
/// # Safety
///
/// C ABI contract — `src` is a valid NUL-terminated string and `dst`
/// holds at least `strlen(src) + 1` bytes, non-overlapping.
#[no_mangle]
pub unsafe extern "C" fn strcpy(dst: *mut i8, src: *const i8) -> *mut i8 {
    // SAFETY: C ABI contract — `src` is a valid NUL-terminated string and
    // `dst` holds at least `strlen(src) + 1` bytes, non-overlapping.
    unsafe {
        let mut d = dst;
        let mut s = src;
        loop {
            *d = *s;
            if *s == 0 {
                break;
            }
            d = d.add(1);
            s = s.add(1);
        }
        dst
    }
}

// ---------------------------------------------------------------------------
// US-711 review finding 2: the factory wipe of the internal FS
// ---------------------------------------------------------------------------

/// US-711 review finding 2: factory-wipe the trussed filesystems — the
/// OpenPGP PW1 flag + retry counter (opcard state files, trussed-auth
/// PIN credentials) live in `ifs`, outside the secure-store slots the
/// RESET hook deletes. Formats both flash windows and remounts them
/// factory-fresh, overwriting the boot-path statics in place (littlefs2
/// 0.8 has no unmount; the stale mount's RAM bookkeeping is discarded —
/// the same statics the boot path wrote).
///
/// # Why `efs` is wiped too (US-1538)
///
/// Before this story `efs` was a RAM buffer that a power cycle erased on
/// its own, so leaving it alone was leaving nothing behind. It is now a
/// 256 KiB QSPI window, and anything written to `Location::External` — which
/// is opcard's *default* storage (`vendor/opcard/src/card.rs:569`) — survives
/// a reset unless this function says otherwise. A factory reset that wiped
/// `ifs` and left `efs` would hand the next owner the previous owner's keys,
/// which is the exact failure the RESET hook exists to prevent.
///
/// The volatile store is deliberately **not** touched: it is RAM, it is
/// reformatted on the next boot regardless, and nothing durable lives there.
///
/// # Safety
/// Device builds only. Single-core serialized (the cooperative
/// executor): the caller runs on a transport task between commands — no
/// trussed syscall is in flight (opcard syscalls run synchronously
/// inside app command processing and hold no open files across
/// commands), so no other code can touch the IFS/EFS statics during the
/// format. The next opcard command lazily re-creates its state in the
/// fresh filesystem.
pub fn wipe_internal_fs() -> bool {
    // SAFETY: the write-once boot statics, mutated here on the
    // serialized between-commands discipline documented above; the
    // format/mount pair follows `DeviceFsStore::boot` exactly.
    unsafe {
        let storage = (*core::ptr::addr_of_mut!(IFS_STORAGE)).as_mut_ptr();
        if Filesystem::format(&mut *storage).is_err() {
            defmt::error!("trussed: internal FS wipe format failed");
            return false;
        }
        (*core::ptr::addr_of_mut!(IFS_ALLOC)).write(Allocation::new());
        let alloc = (*core::ptr::addr_of_mut!(IFS_ALLOC)).as_mut_ptr();
        // Same fail-closed shape as the `format` above rather than
        // `.expect()`: this profile is `panic = "abort"`, so a panic here
        // bricks the token with no unwinding, no rollback and no USB
        // enumeration. A mount that fails after a successful format is the
        // corrupted-storage case, and the caller already handles `false`.
        let ifs = match Filesystem::mount(&mut *alloc, &mut *storage) {
            Ok(ifs) => ifs,
            Err(_) => {
                defmt::error!("trussed: internal FS wipe remount failed");
                return false;
            }
        };
        (*core::ptr::addr_of_mut!(IFS)).write(ifs);

        // `efs`: same shape, same discipline, same fail-closed contract. It
        // is a distinct window of the same part, addressed through the alias
        // `DeviceFsStore::boot` installed, and it is not in flight either —
        // a trussed request resolves exactly one `Location` at a time and no
        // syscall is running here.
        let efs_storage = (*core::ptr::addr_of_mut!(EFS_STORAGE)).as_mut_ptr();
        if Filesystem::format(&mut *efs_storage).is_err() {
            defmt::error!("trussed: external FS wipe format failed");
            return false;
        }
        (*core::ptr::addr_of_mut!(EFS_ALLOC)).write(Allocation::new());
        let efs_alloc = (*core::ptr::addr_of_mut!(EFS_ALLOC)).as_mut_ptr();
        let efs = match Filesystem::mount(&mut *efs_alloc, &mut *efs_storage) {
            Ok(efs) => efs,
            Err(_) => {
                defmt::error!("trussed: external FS wipe remount failed");
                return false;
            }
        };
        (*core::ptr::addr_of_mut!(EFS)).write(efs);
    }
    defmt::info!("trussed: internal and external FS wiped (factory reset)");
    true
}
