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
use littlefs2::fs::{Allocation, Filesystem};
use littlefs2_core::{DynFilesystem, PathBuf};
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
pub use crate::flashmap::{BLOCK_SIZE, TRUSSED_FS_BLOCKS, TRUSSED_FS_END, TRUSSED_FS_OFFSET};

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
/// driver, confined to the [`TRUSSED_FS_OFFSET`] window. The driver is held
/// by value (constructed at boot from `p.FLASH`; S-721-2 passes it in).
pub struct DevFlashStorage {
    flash: DevFlash,
    /// Flash-relative base this storage window covers. US-1536: this became a
    /// field because the relocation reads the legacy window at one offset while
    /// programming the current one at another, through the same flash handle.
    offset: u32,
}

impl DevFlashStorage {
    /// The live trussed window, at [`TRUSSED_FS_OFFSET`].
    pub fn new(flash: DevFlash) -> Self {
        Self {
            flash,
            offset: TRUSSED_FS_OFFSET,
        }
    }
}

impl Storage for DevFlashStorage {
    const READ_SIZE: usize = READ_SIZE;
    const WRITE_SIZE: usize = WRITE_SIZE;
    const BLOCK_SIZE: usize = BLOCK_SIZE;
    const BLOCK_COUNT: usize = TRUSSED_FS_BLOCKS;
    const BLOCK_CYCLES: isize = -1;

    type CACHE_SIZE = U256;
    type LOOKAHEAD_SIZE = U8;

    fn read(&mut self, off: usize, buf: &mut [u8]) -> littlefs2::io::Result<usize> {
        self.flash
            .blocking_read(self.offset + off as u32, buf)
            .map_err(|_| littlefs2::io::Error::IO)?;
        Ok(buf.len())
    }

    fn write(&mut self, off: usize, data: &[u8]) -> littlefs2::io::Result<usize> {
        self.flash
            .blocking_write(self.offset + off as u32, data)
            .map_err(|_| littlefs2::io::Error::IO)?;
        Ok(data.len())
    }

    fn erase(&mut self, off: usize, len: usize) -> littlefs2::io::Result<usize> {
        self.flash
            .blocking_erase(
                self.offset + off as u32,
                self.offset + (off + len) as u32,
            )
            .map_err(|_| littlefs2::io::Error::IO)?;
        Ok(len)
    }
}

// RAM littlefs2 storage (32 KiB = 8 × 4 KiB blocks) for the external and
// volatile stores. `const_ram_storage!` from littlefs2; the buffer is a
// const-initialized static (the erase value 0xFF), so the "storage" is a
// zero-copy slice of a fixed RAM region. The macro emits a `pub struct`,
// so the invocation is confined to a private submodule — `RamFsStorage`
// is nameable inside this module only, never from the crate root.
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

/// The trussed [`Store`]: three mounted littlefs2 filesystems (internal on
/// flash, external + volatile on RAM). `Copy` of `'static` references — the
/// mounted filesystems and their storage/allocation state live in the statics
/// below (init-once at boot).
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

static mut EFS_STORAGE: core::mem::MaybeUninit<RamFsStorage> = core::mem::MaybeUninit::uninit();
static mut EFS_ALLOC: core::mem::MaybeUninit<Allocation<RamFsStorage>> =
    core::mem::MaybeUninit::uninit();
static mut EFS: core::mem::MaybeUninit<Filesystem<'static, RamFsStorage>> =
    core::mem::MaybeUninit::uninit();

static mut VFS_STORAGE: core::mem::MaybeUninit<RamFsStorage> = core::mem::MaybeUninit::uninit();
static mut VFS_ALLOC: core::mem::MaybeUninit<Allocation<RamFsStorage>> =
    core::mem::MaybeUninit::uninit();
static mut VFS: core::mem::MaybeUninit<Filesystem<'static, RamFsStorage>> =
    core::mem::MaybeUninit::uninit();

impl DeviceFsStore {
    /// Mount (or format, on first boot) the three filesystems. Boot-path
    /// only, before any task exists (single-core; see the static docs).
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
            relocate_legacy_window(&mut *storage);
            if !Filesystem::is_mountable(&mut *storage) {
                defmt::info!("trussed: formatting internal FS (first boot)");
                Filesystem::format(&mut *storage).expect("trussed: format internal FS");
            }
            let ifs = Filesystem::mount(&mut *alloc, &mut *storage)
                .expect("trussed: mount internal FS");
            (*core::ptr::addr_of_mut!(IFS)).write(ifs);

            let efs = mount_ram_fs(
                &mut *core::ptr::addr_of_mut!(EFS_STORAGE),
                &mut *core::ptr::addr_of_mut!(EFS_ALLOC),
                &mut *core::ptr::addr_of_mut!(EFS),
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

/// One-shot relocation of the trussed window from its pre-US-1536 offset.
///
/// The window moved from `0x102_000` to `0x200_000` so the CI flash-budget
/// ratchet can no longer reach it. A unit provisioned before that move has a
/// populated littlefs2 volume at the old offset, and this is what carries it
/// across — otherwise the move is a silent wipe of every OpenPGP and PIV key.
///
/// # Why it is safe to run on every boot
///
/// The legacy window is **read-only** here and never written. So the decision
/// tree is naturally idempotent, with no marker record to keep in sync:
///
/// 1. the current window mounts → nothing to do (the normal case, including
///    every boot after a successful relocation);
/// 2. the current window is empty **and** the legacy window mounts → copy,
///    then let the caller's `is_mountable` check confirm the result;
/// 3. neither mounts → the caller's first-boot format, i.e. an unprovisioned
///    unit starting empty at the new offset.
///
/// A power cut mid-copy therefore leaves the source intact and the destination
/// un-mountable, which lands on arm 2 again next boot. There is no state in
/// which the relocation has to be "told" to run.
///
/// # Why failure falls through to a format rather than halting
///
/// A copy that fails still leaves the caller's `is_mountable` false, which is
/// the first-boot path: the unit comes up empty and reachable rather than
/// parked. The legacy window is left intact for recovery. Halting here would
/// trade a recoverable, loudly-logged empty device for an unreachable one, and
/// the boot path's whole discipline is that the board always reaches USB.
fn relocate_legacy_window(storage: &mut DevFlashStorage) {
    if Filesystem::is_mountable(&mut *storage) {
        return;
    }
    // Probe the legacy window by pointing this storage at it for the duration
    // of the check and restoring the live offset immediately after. A second
    // `DevFlashStorage` would need a second `Flash` handle, and `Flash` is not
    // `Copy` — so this is the one arrangement that needs no aliasing.
    let legacy_offset = crate::flashmap::LEGACY_TRUSSED_FS_OFFSET;
    let live_offset = storage.offset;
    storage.offset = legacy_offset;
    let legacy_mounts = Filesystem::is_mountable(&mut *storage);
    storage.offset = live_offset;
    if !legacy_mounts {
        defmt::info!("trussed: no legacy window; starting empty at the new offset");
        return;
    }

    defmt::info!("trussed: relocating the internal FS to the new offset");
    let window = (TRUSSED_FS_BLOCKS * BLOCK_SIZE) as u32;
    if let Err(e) = relocate_copy(storage, legacy_offset, window) {
        defmt::error!("trussed: relocation failed ({=u8}); the legacy window is intact", e);
        return;
    }
    if Filesystem::is_mountable(&mut *storage) {
        defmt::info!("trussed: relocation complete");
    } else {
        defmt::error!("trussed: relocated window does not mount; starting empty");
    }
}

/// Stream the legacy window into the current one.
///
/// Erase-then-program in [`WRITE_SIZE`]-aligned chunks — NOR flash cannot
/// rewrite programmed bytes, and `WRITE_SIZE` is the flash page size, so a
/// chunk is the largest unit that is always program-safe.
///
/// `Result<(), u8>` rather than `littlefs2::io::Result` because the error is
/// only logged: the caller decides what an unmountable window means, and it is
/// the first-boot path.
fn relocate_copy(
    storage: &mut DevFlashStorage,
    legacy_offset: u32,
    window: u32,
) -> Result<(), u8> {
    let mut buf = [0u8; RELOCATE_CHUNK];
    for off in (0..window as usize).step_by(BLOCK_SIZE) {
        storage
            .flash
            .blocking_erase(
                TRUSSED_FS_OFFSET + off as u32,
                TRUSSED_FS_OFFSET + (off + BLOCK_SIZE) as u32,
            )
            .map_err(|_| 1u8)?;
    }
    let mut copied = 0usize;
    while copied < window as usize {
        let flash = &mut storage.flash;
        flash
            .blocking_read(legacy_offset + copied as u32, &mut buf)
            .map_err(|_| 2u8)?;
        flash
            .blocking_write(TRUSSED_FS_OFFSET + copied as u32, &buf)
            .map_err(|_| 3u8)?;
        copied += RELOCATE_CHUNK;
    }
    Ok(())
}

/// Chunk size for the relocation copy: one flash page (`embassy-rp`
/// `PAGE_SIZE = 256`, which is also this driver's [`WRITE_SIZE`]).
///
/// Deliberately a small **stack** buffer. The relocation runs on the boot path
/// before any task exists, where the main stack zone is 5,056 B — a large
/// buffer here would be a stack overflow found only on hardware.
const RELOCATE_CHUNK: usize = WRITE_SIZE;

/// Format + mount one RAM-backed filesystem into its static triple.
///
/// The RAM stores are volatile, so they are **always formatted** at boot
/// (fresh on every power-up — there is nothing to preserve).
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

/// US-711 review finding 2: factory-wipe the trussed internal filesystem —
/// the OpenPGP PW1 flag + retry counter (opcard state files, trussed-auth
/// PIN credentials) live here, outside the secure-store slots the RESET
/// hook deletes. Formats the QSPI window and remounts it factory-fresh,
/// overwriting the boot-path statics in place (littlefs2 0.8 has no
/// unmount; the stale mount's RAM bookkeeping is discarded — the same
/// statics the boot path wrote).
///
/// # Safety
/// Device builds only. Single-core serialized (the cooperative
/// executor): the caller runs on a transport task between commands — no
/// trussed syscall is in flight (opcard syscalls run synchronously
/// inside app command processing and hold no open files across
/// commands), so no other code can touch the IFS statics during the
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
    }
    defmt::info!("trussed: internal FS wiped (factory reset)");
    true
}
