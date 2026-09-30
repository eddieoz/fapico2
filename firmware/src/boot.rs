//! Device boot path (PB-M6, US-427): the secure-partition slot selection,
//! the store / flash / migration statics, first-boot C→Rust migration, and
//! the write-once app-static slots.
//!
//! Extracted from `main.rs` as a pure move: `main()` (in `main.rs`) still
//! orchestrates the boot sequence and spawns the serve-loop tasks
//! (`tasks.rs`); this module owns the static memory the boot sequence runs
//! on. The single-core write-once-`static mut` discipline is unchanged
//! (US-391 E6 / S-701-3).

use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::gpio::{Output};
use embassy_rp::peripherals::FLASH;
use fapico2_fido::FidoApp;
use fapico2_mgmt::ManagementApp;
use fapico2_oath::{OathApp, OathSeal, OtpApp};
use fapico2_openpgp::OpenPgpApp;
use fapico2_vendor_led::VendorLedApp;
// US-161/162/163 (PICOForge-COMPAT Phase H): the unauthenticated Rescue
// applet. It is a `no_std` applet like the other four, so the device build
// carries it — and it *is* carried on the device, not only in the
// emulator: the client reaches it over CCID, which is a device transport.
use fapico2_rescue::{
    PhySnapshot, PhyUpdate, RebootMode, RescueApp, RescueConfigHandler, RescueDeviceHandler,
};
// S-721-2: the OpenPGP app owns the trussed platform client by value
// (taken out of the backend static with `trusted_backend::take_client`).
use fapico2_platform::trusted_backend::{Client, DevicePlatform, OpcardDispatch};
use fapico2_platform::cflash;
use fapico2_platform::cfs::{Cfs, PoolBounds, XipFlash};
use fapico2_platform::dispatch::{Dispatcher, MAX_RESPONSE};
use fapico2_platform::fw_manifest;
use fapico2_platform::migration::{self, MigrationBuffers, MigrationOutcome};
use fapico2_platform::persist_sink::SlotFlash;
use fapico2_platform::secure_store::{
    ImageReader, Rp2350SecureStore, SecureStore, SecureStoreError,
};
use fapico2_platform::store_v3::{boot_decision_sealed_reader, SealedBootDecision};
use heapless::Vec as HeaplessVec;

/// Worst-case size of the serialized secure-partition image — US-915: the
/// SEALED (format-v3) bound (see
/// [`Rp2350SecureStore::SEALED_PARTITION_IMAGE_MAX`]); the on-flash slots
/// hold sealed images once the store key is set at boot.
pub const SECURE_PARTITION_SIZE: usize = Rp2350SecureStore::SEALED_PARTITION_IMAGE_MAX;
/// One image slot's on-flash size, rounded up to the NOR erase granularity
/// (each slot occupies this many consecutive 4 KiB sectors).
pub const SECURE_SLOT_BYTES: usize =
    SECURE_PARTITION_SIZE.div_ceil(FLASH_ERASE_SIZE as usize) * (FLASH_ERASE_SIZE as usize);

/// On-flash layout of the reserved 64 KiB secure-partition region (the
/// `SECURE` region of the generated `memory.x`; `0x103F0000` on the 4 MiB
/// `pico2` board): **two** image slots. US-391 durability, per the C
/// secure-store review's publish-after-durable discipline: persist programs
/// the primary slot, then the shadow slot; a power loss mid-program can
/// destroy at most the slot being written, and boot falls back to the other
/// slot. Worst case an in-flight persist is rolled back — never a total loss
/// of every app secret (the old single-slot layout made one torn write wipe
/// the whole store, and `FidoApp::boot` would then silently re-derive the
/// hkey, orphaning every enrolled credential).
///
/// US-1080: derived from `flash_size_kb` in the selected board file rather
/// than written down. `0x3F_0000` is what the arithmetic produces for 4 MiB, so
/// the value is unchanged for the board that exists — what changed is that it
/// can no longer be wrong. The reservation is subtracted from the **top**, so a
/// larger part moves the region rather than leaving it stranded in the middle
/// of app flash, and the same number feeds both this constant and the
/// `SECURE` `ORIGIN` in the linker script `firmware/build.rs` generates from
/// the same file. A mismatch between the two would place a provisioned unit's
/// keystore outside the region the linker reserved for it, which is a corrupt
/// store rather than a link error — hence one source.
pub const SECURE_PRIMARY_OFFSET: u32 = fapico2_platform::board::SECURE_PARTITION_OFFSET;
pub const SECURE_SHADOW_OFFSET: u32 = SECURE_PRIMARY_OFFSET + SECURE_SLOT_BYTES as u32;

/// The two on-flash image slots (primary + shadow), linked into the reserved
/// `.secure_partition` flash region (memory.x), distinct from the app text.
/// Boot reads the keystore from the first valid slot — erased flash is 0xFF
/// (an invalid magic, hence an empty store), and app secrets never touch the
/// plain app-flash region. The persist gate (US-422,
/// `fapico2_platform::persist`) snapshots the store and programs the image
/// back into both slots (`FlashSlotSink`, compare-then-write).
///
/// `#[used]` + the linker script's `KEEP` hold the section through LTO/gc;
/// the volatile boot read (see `read_partition_slot`) keeps the flash content
/// authoritative — without it, LTO const-folds the 0xFF initializer and a
/// later re-flash of the region would be ignored.
#[used]
#[link_section = ".secure_partition"]
static SECURE_PARTITION: [u8; 2 * SECURE_SLOT_BYTES] = [0xFF; 2 * SECURE_SLOT_BYTES];

/// US-715 (POLISH-PUB): windowed volatile reader over one on-flash image
/// slot — the [`ImageReader`] the boot-time slot decision, the store restore,
/// and the boot-persist compare all walk through. The two whole-slot static
/// buffers this replaces (`BOOT_PARTITION_BUF` + `BOOT_SHADOW_BUF`, 2 × 9,100
/// B of bss) are gone: every consumer pulls bounded windows straight from the
/// `.secure_partition` XIP region with volatile reads — which also keeps LTO
/// from const-folding the driver-programmed flash content (the same reason
/// the deleted whole-slot copies were volatile). Reads at/after the slot's
/// end short-fill (return 0 there), so a walk that runs off the slot fails
/// validation — the streaming analog of the old fixed-buffer bounds.
pub struct SecureSlotReader {
    /// Slot base inside `.secure_partition` (0 or [`SECURE_SLOT_BYTES`]).
    base: usize,
}

impl SecureSlotReader {
    /// Reader over the primary slot (offset 0 in `.secure_partition`).
    pub fn primary() -> Self {
        Self { base: 0 }
    }

    /// Reader over the shadow slot (offset [`SECURE_SLOT_BYTES`]).
    pub fn shadow() -> Self {
        Self {
            base: SECURE_SLOT_BYTES,
        }
    }
}

impl ImageReader for SecureSlotReader {
    fn read_window(&mut self, off: usize, buf: &mut [u8]) -> usize {
        let n = buf.len().min(SECURE_SLOT_BYTES.saturating_sub(off));
        // SAFETY: `SECURE_PARTITION` is the `'static` flash-resident
        // primary+shadow region (`2 * SECURE_SLOT_BYTES` bytes at 0x103F0000);
        // `base` is 0 or `SECURE_SLOT_BYTES` and `off + n` stays within the
        // slot (clamped above), so the volatile reads stay in bounds. This
        // runs on the pre-task boot path or inside a synchronous command
        // section — it races with nothing (single core).
        unsafe {
            let src = (core::ptr::addr_of!(SECURE_PARTITION) as *const u8).add(self.base + off);
            for (i, b) in buf[..n].iter_mut().enumerate() {
                *b = core::ptr::read_volatile(src.add(i));
            }
        }
        n
    }
}

/// US-715: which on-flash image slot boot loads (the windowed form of the
/// old `boot_partition_image()` slot selection). US-915: the decision is
/// the sealed boot policy — a slot loads only as a **tag-verified v3**
/// image; both slots holding CRC-valid format-v2 (the pre-update device
/// signature) is the one-time `MigratePrimary` trigger, reported as
/// [`BootSlot::Primary`] (the restore is the primary's legacy image; the
/// boot persist gate then re-seals it into v3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSlot {
    /// The primary slot holds a valid image (v3 sealed, or the v2
    /// migration load).
    Primary,
    /// The primary is invalid, the shadow is valid (a torn program destroyed
    /// at most the slot that was being written).
    Shadow,
    /// Both slots erased: fresh first boot, empty store.
    Fresh,
}

/// Boot-time slot selection (US-391 durability, US-427 torn-write
/// semantics, US-915 sealed boot policy), windowed (US-715): a slot loads
/// only as a tag-verified v3 image under the boot store key; both slots
/// erased is the fresh first boot; both slots CRC-valid format-v2 is the
/// genuine pre-update signature and migrates (restore the primary, re-seal
/// through the boot persist gate); everything else **refuses** — content
/// present that validates nowhere (a forged lone-v2 slot, a bad-tag v3, a
/// torn write) parks the device in [`fatal_boot`] instead. A silent re-seed
/// would orphan every enrolled credential (Token2 dark-data-loss) and, in
/// the sealed format, would launder a forged slot into the store.
///
/// The erased check covers the first [`SECURE_PARTITION_SIZE`] bytes of
/// each slot — the whole of any possible (sealed) image.
// US-939: `#[inline(never)]` -- async-main frame discipline.
#[inline(never)]
pub fn boot_slot_decision(key: &[u8; 32]) -> BootSlot {
    let mut primary = SecureSlotReader::primary();
    let mut shadow = SecureSlotReader::shadow();
    match boot_decision_sealed_reader(
        &mut primary,
        &mut shadow,
        key,
        SECURE_PARTITION_SIZE,
    ) {
        SealedBootDecision::LoadPrimary => BootSlot::Primary,
        SealedBootDecision::LoadShadow => {
            defmt::info!("secure partition: primary slot invalid; booting from shadow");
            BootSlot::Shadow
        }
        SealedBootDecision::MigratePrimary => {
            defmt::info!("secure partition: legacy v2 slots; migrating to sealed v3");
            BootSlot::Primary
        }
        SealedBootDecision::Fresh => {
            defmt::info!("secure partition: no valid image slot; starting with an empty store");
            BootSlot::Fresh
        }
        SealedBootDecision::Refuse => {
            fatal_boot("secure partition: untrusted image content; refusing to boot (US-915)")
        }
    }
}

/// QSPI flash size, from the selected board file's `flash_size_kb` (4 MiB on
/// the `pico2` board, the same value as before US-1080) and the RP2350
/// NOR-erase granularity.
/// (embassy-rp flash offsets are relative to 0x10000000; the `.secure_partition`
/// region lives at the top of flash — 0x103F0000 on `pico2` = offset
/// [`SECURE_PRIMARY_OFFSET`].)
const FLASH_SIZE: usize = fapico2_platform::board::FLASH_SIZE_BYTES;
const FLASH_ERASE_SIZE: u32 = 4096;

/// Blocking QSPI flash handle (embassy-rp: ROM flash functions + the boot2
/// copy in BOOTRAM — the standard RP2350 self-programming path).
pub type DevFlash = Flash<'static, FLASH, Blocking, FLASH_SIZE>;

/// `SlotFlash` adapter over the embassy-rp blocking QSPI flash driver
/// (US-422). The orphan rule keeps the adapter here (local struct, foreign
/// trait); the compare-then-write slot logic lives in
/// `fapico2_platform::persist_sink::FlashSlotSink` (the behavior-identical
/// port of the deleted `persist_secure_partition`/`secure_slot_matches`).
/// Driver errors map to [`SecureStoreError::Flash`].
///
/// Decision (US-391): direct QSPI programming. The CryptoCell secure-partition
/// gating is a post-cutover hardening step; this board runs non-secure boot
/// (BOOTSEL-flashable), so the pragmatic path is the same flash access the
/// self-programming ROM uses.
///
/// US-918: the boot-entropy slot ([`migration::SLOT_BOOT_ENTROPY`]) rides
/// this same persist path — admitted by the same compare-then-program
/// discipline as every other slot — so the entropy record is part of the
/// sealed v3-AEAD store image (authenticated, not attacker-writable on a
/// re-flash) rather than a separate unsealed artifact.
/// The field is public: `tasks.rs` wraps this adapter in the
/// `FlashSlotSink` at the persist call sites (`secure_slot_sink`).
pub struct DevSlotFlash<'a>(pub &'a mut DevFlash);

impl SlotFlash for DevSlotFlash<'_> {
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), SecureStoreError> {
        self.0.blocking_read(addr, buf).map_err(|_| SecureStoreError::Flash)
    }
    fn erase(&mut self, from: u32, to: u32) -> Result<(), SecureStoreError> {
        self.0.blocking_erase(from, to).map_err(|_| SecureStoreError::Flash)
    }
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), SecureStoreError> {
        self.0.blocking_write(addr, data).map_err(|_| SecureStoreError::Flash)
    }
}

/// Park the boot sequence: a fatal condition the device must not continue
/// past (the serve loops never start, so nothing is served).
#[allow(clippy::empty_loop)]
pub fn fatal_boot(msg: &str) -> ! {
    defmt::error!("{}", msg);
    loop {}
}

// The secure store lives outside the async main() future (in static memory,
// not the generator state). At ~9 KB (`[Slot; 16]` × 512 B values) it is too
// large to hold in the async frame — the task-frame overflow chain was the
// E3–E7 boot wedge (store by-value in the spawn param, then the app objects
// and `Dispatcher` riding the task frame; see the ladder doc's root-cause
// reconciliation). `static mut` is safe here: the device is single-core,
// single-thread, and each static is touched once on the boot path.
pub type DeviceStore = fapico2_platform::secure_store::SharedStore<'static, Rp2350SecureStore>;
pub static mut STORE: core::cell::RefCell<Rp2350SecureStore> =
    core::cell::RefCell::new(Rp2350SecureStore::new());

/// Distinct handles borrow the backing store only for an individual operation.
/// The static cell is never replaced after boot; the executor is single-core.
pub fn store_handle() -> DeviceStore {
    DeviceStore::new(unsafe { &*core::ptr::addr_of!(STORE) })
}

static mut AUTH_STORE: core::mem::MaybeUninit<DeviceStore> = core::mem::MaybeUninit::uninit();
static mut PIN_AUTHORITY: core::mem::MaybeUninit<
    fapico2_platform::trusted_backend::dispatch::MigrationAuthority<'static, DeviceStore>,
> = core::mem::MaybeUninit::uninit();

/// Construct once before backend boot. The authority and management path use
/// the same store but never retain a borrow of its contents across a syscall.
// US-939: `#[inline(never)]` -- async-main frame discipline.
#[inline(never)]
pub fn migration_authority() -> Option<&'static dyn fapico2_platform::trusted_backend::dispatch::MigrationPinAuthority> {
    let store = init_static_slot(core::ptr::addr_of_mut!(AUTH_STORE), store_handle());
    if !migration::has_openpgp_capture(store) { return None; }
    let otp = read_otp_key_1()
        .unwrap_or_else(|| fatal_boot("migration: captured identity OTP unavailable"));
    let uid = embassy_rp::otp::get_chipid()
        .unwrap_or_else(|_| fatal_boot("migration: captured identity chipid unavailable"));
    // US-939: the authority (~98 KiB, it owns the migration scratch) is
    // constructed field-by-field directly into its `PIN_AUTHORITY` static
    // slot — letting the value transit this function's stack frame (then
    // `init_static_slot`'s by-value move) is what drove the Embassy
    // async-main frame to 95,232 B (the dark-boot stack overflow).
    // SAFETY: the PIN_AUTHORITY slot is the write-once `static mut` discipline
    // (see `init_static_slot`) — valid, aligned, written exactly once here.
    Some(unsafe {
        fapico2_platform::trusted_backend::dispatch::MigrationAuthority::new_in_place(
            core::ptr::addr_of_mut!(PIN_AUTHORITY),
            store,
            &otp,
            &uid.to_be_bytes(),
        )
    }.unwrap_or_else(|_| fatal_boot("migration: authority initialization failed")))
}

/// US-413 S-413-5: migration working buffers (~96 KiB, bss — never on the
/// boot-path stack).
static mut MIG_BUFS: MigrationBuffers = MigrationBuffers::new();

/// S-701-3: the blocking flash handle lives in its own write-once static so
/// both serve loops (CCID persist + FIDO HID keystore persist) can program
/// the secure partition. SAFETY: single-core cooperative scheduling — each
/// user touches the statics only inside its synchronous handler section,
/// never across an await point.
pub static mut FLASH_DEV: core::mem::MaybeUninit<DevFlash> = core::mem::MaybeUninit::uninit();

/// US-413 S-413-6: management-APDU migration completion hook state. The
/// store/buffers are reached through `static mut` at call time (same
/// single-threaded boot/CCID-task ownership as [`STORE`]).
pub struct DeviceMigrationHandler;

/// US-1005 (closing D-10): the migration-completion nonce source — a second
/// [`Rp2350Probe`](fapico2_platform::trng::Rp2350Probe) over the same
/// peripheral, serving `DeviceMigrationHandler`. The passphrase-completion
/// hook draws a fresh 12-byte per-record nonce for the AEAD DEK rewrap
/// through the **bounded** seam, so a wedged peripheral is a card error rather
/// than the unbounded busy-wait this handle used to be.
///
/// # Why a second probe and not the existing one
///
/// `DRBG_SEED_PROBE` below is the obvious thing to reuse, and reusing it would
/// have been a two-line change. It cannot be: `FuseSeedSource` holds a
/// `&'static mut` to that very probe for as long as the generator lives, and
/// `boot.rs` would have to mint a **second** `&mut` to the same object from a
/// raw pointer. Nothing ever calls them at the same time — single core,
/// cooperative executor, and the draw here completes before
/// `complete_migration` runs — but "not concurrent" is an argument, whereas
/// two `&mut` to one object is UB whether or not the argument holds. A
/// separate handle costs two bytes of bss and one more `Peri` duplication
/// (the same documented, serialized duplication the boot-path handles already
/// use) and has no alias at all.
///
/// # What the handle count is now
///
/// Three, as before: the boot-path `Rp2350Trng` driver, the DRBG seed probe,
/// and this one. The composition changed, not the total: the unbounded
/// `Rp2350Trng` that used to sit in this slot is gone, so the two handles a
/// *request* can reach are now the same implementation. That narrows D-11's
/// interleaving question rather than settling it: the boot-path driver still
/// alternates with both probes during boot, and that pair's symmetry remains
/// an argument (see D-11) rather than a type identity.
pub static mut MIG_PROBE: core::mem::MaybeUninit<
    fapico2_platform::trng::Rp2350Probe<'static>,
> = core::mem::MaybeUninit::uninit();

/// US-917, bounded by US-1005: a fresh per-record nonce for the AEAD DEK
/// rewrap, or [`Err`].
///
/// # What a caller must do with the error
///
/// Return a card error and **use nothing**. The draw happens before any
/// migration state is touched — see the two call sites, which take this after
/// the OTP/chipid reads and before `complete_migration` /
/// `complete_passphrase_class` are entered, so a refusal here cannot leave a
/// migration half-applied: there is no store write, no scratch-buffer use and
/// no flash program to roll back, because none of them has run.
///
/// # Why the DRBG is not the source, restated at the call site
///
/// The device generator is moved by value into the trussed platform
/// ([`take_drbg`]) and from there into the client the OpenPGP app owns, so
/// there is no handle left to draw from inside a CCID request. See
/// `platform::trng::try_migration_nonce` for why that is acceptable here and
/// what it gives up.
fn migration_nonce() -> Result<[u8; fapico2_platform::trng::MIGRATION_NONCE_LEN], fapico2_platform::trng::TrngError> {
    let mut nonce = [0u8; fapico2_platform::trng::MIGRATION_NONCE_LEN];
    // SAFETY: the slot was written on the boot path (`init_static_slot`
    // in `main.rs`) before any task spawned; this is the only runtime
    // accessor and it runs inside the CCID task's synchronous section, so
    // the generator's own use of `DRBG_SEED_PROBE` is not in flight.
    let probe = unsafe { (&mut *core::ptr::addr_of_mut!(MIG_PROBE)).assume_init_mut() };
    fapico2_platform::trng::try_migration_nonce(probe, &mut nonce)?;
    Ok(nonce)
}

/// The second bounded probe on the boot path, for pre-task boot callers.
///
/// [`MIG_PROBE`] is not only the migration nonce's probe. It is the boot
/// path's *spare* bounded probe, and the US-919 wipe arm needs one: it
/// redraws the boot-entropy slot after wiping the store, and that draw has
/// the same requirement the nonce's did — a wait with a deadline instead of
/// a retry loop that never ends. The first probe is not an alternative,
/// because [`init_drbg`] takes it **by value** a few lines earlier in
/// `main` (the DRBG owns it for the life of the process), which is the whole
/// reason a second handle exists.
///
/// Same single-core cooperative discipline as [`migration_nonce`]: this is
/// reached only before any task is spawned, so it cannot race the CCID
/// task's use of the same probe.
// Gated with the wipe that is its only caller. A default device build
// compiles the wipe out, and an accessor nothing calls is dead code — which
// `clippy -D warnings` says out loud rather than leaving for someone else to
// find. The `MIG_PROBE` SLOT is unconditional (the migration nonce needs it
// at runtime); only this door onto it goes away.
#[cfg(FAPICO2_FOREIGN_IMAGE_WIPE)]
//
// SAFETY: the slot is written by `init_static_slot` in `main.rs` before the
// tasks spawn and before `ensure_fw_manifest` runs.
pub fn spare_probe() -> &'static mut fapico2_platform::trng::Rp2350Probe<'static> {
    unsafe { (&mut *core::ptr::addr_of_mut!(MIG_PROBE)).assume_init_mut() }
}

/// Log which of the bounded wait's refusals fired, as the `ClassStatus::Error`
/// the caller is about to return.
///
/// Three static strings rather than a `defmt::Format` derive on the error: the
/// three are different facts and the difference is what an operator needs. The
/// first is "the peripheral missed the deadline"; the second is "the wall
/// clock never moved, so the deadline was never measured" (D-12) — a fact
/// about the *instrument*, which is a different bug with a different fix; the
/// third is "a block arrived carrying nothing". Collapsing them into one line
/// would put back precisely the indistinguishability D-12 exists to remove,
/// and this is a device property nobody can reproduce from a host.
fn log_migration_nonce_refusal(e: fapico2_platform::trng::TrngError) {
    use fapico2_platform::trng::TrngError;
    match e {
        TrngError::Stalled => defmt::error!(
            "migration: nonce refused — no validated TRNG block within the entropy \
             budget; the migration was NOT started"
        ),
        TrngError::ClockStalled => defmt::error!(
            "migration: nonce refused — the entropy wait's wall clock did not move, \
             so the budget was never in play; the migration was NOT started"
        ),
        TrngError::Entropy => defmt::error!(
            "migration: nonce refused — the TRNG reported a block carrying no \
             entropy; the migration was NOT started"
        ),
    }
}

// ---------------------------------------------------------------------------
// US-1005: the DRBG's seed source, and the generator built from it.
// ---------------------------------------------------------------------------

/// The OTP key row the DRBG seed is derived from. A `static` rather than a
/// local because [`FuseSeedSource`] *borrows* it: RS-Key's `FusedKey` closure
/// shape exists precisely so a fuse window is never copied into RAM, and a
/// `[u8; 32]` local on the boot stack would be exactly that copy. `Zeroize`d
/// on drop is not applicable to a `static` — which is the point: this is a
/// fuse window read through the HAL, not a secret this firmware stores.
pub static mut DRBG_OTP_KEY: core::mem::MaybeUninit<[u8; 32]> = core::mem::MaybeUninit::uninit();

/// The flash UID (`chipid.to_be_bytes()`), the second device-binding input.
/// Same reasoning as [`DRBG_OTP_KEY`]: borrowed, never copied.
pub static mut DRBG_UID: core::mem::MaybeUninit<[u8; 8]> = core::mem::MaybeUninit::uninit();

/// The store handle the seed source reads `boot.entropy.v1` through, and the
/// bounded probe it takes the fresh draw from. Both live in write-once slots
/// so the [`fapico2_platform::drbg_seed::FuseSeedSource`] built from them can
/// carry the `'static` borrows the trussed client needs.
pub static mut DRBG_SEED_STORE: core::mem::MaybeUninit<DeviceStore> =
    core::mem::MaybeUninit::uninit();
pub static mut DRBG_SEED_PROBE: core::mem::MaybeUninit<
    fapico2_platform::trng::Rp2350Probe<'static>,
> = core::mem::MaybeUninit::uninit();

/// The one DRBG the trussed backend serves nonces from (US-1005/US-1006).
///
/// A `static mut` for the same reason as every other large boot-path object
/// here: it must not transit the async-main frame. `Drbg` is 80 bytes and the
/// source is four pointers, so the frame cost would be tolerable — but
/// keeping it out of the frame is the established discipline for anything
/// living past boot, and a reseed must be callable from a CCID task later.
pub static mut DRBG: core::mem::MaybeUninit<
    fapico2_platform::trng::DrbgTrng<
        fapico2_platform::drbg_seed::FuseSeedSource<
            'static,
            DeviceStore,
            fapico2_platform::trng::Rp2350Probe<'static>,
        >,
    >,
> = core::mem::MaybeUninit::uninit();

/// Build the device DRBG and install it in [`DRBG`] (US-1005).
///
/// Call **after** `ensure_boot_entropy`: the seed source reads the very record
/// that function writes, and a missing record is
/// `CKeyError::MissingBootEntropy` — the fail-closed refusal US-1003 defines.
/// Ordering it before would make every device look unprovisioned.
///
/// A refusal here is **fatal**, and deliberately so. The alternatives were
/// considered:
///
/// * *Continue with a peripheral-only source* — reinstates exactly the
///   arrangement US-1003 exists to end, and puts an unbounded wait back on
///   the request path.
/// * *Continue with the fuse seed alone* — the cross-boot nonce-reuse defect,
///   and a private-key-recovery bug for any ECDSA signature made across two
///   boots.
///
/// A card that cannot reach a validated entropy block is a card that cannot
/// sign, and saying so at boot with one line of defmt is better than
/// discovering it on a customer's first signature.
///
/// # The consequence, stated as US-1008 requires
///
/// **A TRNG wedge at boot bricks the device until a hardware reset.** That is
/// the cost of this policy, stated in the form the story asks for rather than
/// in the euphemism "fails closed": the device does not enumerate over CCID
/// or CTAP-HID, `fatal_boot` is a `loop {}` after one `defmt::error!`, and a
/// power cycle re-runs the same failing check, so **no software action
/// recovers it**. The only recoveries are a hardware reset or a reflash, and
/// a reflash does not help because the failure is in the peripheral, not the
/// image.
///
/// It is paid deliberately, and the currency is availability rather than
/// security, because every alternative trades the other way — see the two
/// bullets above. A degraded mode would be worse than an outage: it would
/// look like a working token.
///
/// # This is the *only* entropy fatal site, and that is US-1008's other half
///
/// The branch has several unconditional pre-USB `fatal_boot` calls, and the
/// review's finding was that one of them — `main.rs`'s boot sanity draw — was
/// a **diagnostic** that could end the boot. It is now a `defmt::warn!`. The
/// rule this function's presence establishes:
///
/// > A refusal is fatal here because requiring a seeded generator **is** this
/// > function's job. Everywhere else on the boot path, a refusal is
/// > something to report, and the *next* site decides whether it is also
/// > something to refuse on.
///
/// The pre-USB fatal sites and why each is entitled to be one:
///
/// | site | condition | entitled because |
/// |---|---|---|
/// | `init_drbg` (this) | seed refused | requiring a generator is the function's whole job |
/// | `main.rs` `boot_fido` / `boot_oath` | keystore boot failed | a device that cannot read its own keystore cannot serve a correct one; serving anyway is silently wrong |
/// | `main.rs` `device chipid` | chipid unavailable | the boot store key is `fuse ⊕ chipid`; without it every stored secret is unopenable |
/// | `boot.rs` `boot_slot_decision` | untrusted image content | signed-boot enforcement (US-915); an unverified image is exactly what the fuse exists to prevent |
/// | `boot.rs` migration paths | migration failed | the module's own documented rule: a migration that cannot complete must not leave a *partially* destructively-bootable backend |
/// | `main.rs` secure-partition persist | boot persist failed | same as the keystore row, one layer down |
/// | `main.rs` OATH seal (via `boot.rs`) | OTP key row / chipid unavailable | same inputs as the store key; the OATH seal is unopenable without them |
///
/// The site that is **not** on that list is the entropy *diagnostic*, and
/// keeping it off the list is what this commit changed. Two of the rows are
/// seed-adjacent and worth naming: `init_drbg`'s own `read_otp_key_1` /
/// `chipid` reads and `Rp2350Timer::require_advancing` in `main.rs` are
/// fatal, and both should be — they are not "the entropy source is
/// unhealthy", they are "a required input is absent", which is a different
/// condition with a different fix.
///
/// The two properties that make the policy real rather than aspirational are
/// pinned by `platform/tests/drbg_seed_stall.rs`: a refused seed yields **no
/// generator** (there is no infallible constructor to reach for instead), and
/// the refusal is **prompt** — bounded by the same wall-clock budget the
/// device applies, so "fatal" is a decision the firmware made and can report
/// rather than a hang. That second one is the property the 2026-09-29 dark
/// boot turned on: a wait whose clock was not running made the budget
/// unreachable, and a healthy part reported a stall.
///
/// # What this policy does not settle
///
/// The branch is parked dark on hardware and the cause is not established.
/// Nothing here claims to have found it. What US-1008 changes is that one of
/// the two entropy sites that could have been the cause can no longer be
/// one, and the remaining one is observable in the order it happens.
///
/// # Safety
/// Single-core, boot path only; each slot is written exactly once here, before
/// any task exists (the [`init_static_slot`] contract).
#[inline(never)]
pub unsafe fn init_drbg(
    probe: fapico2_platform::trng::Rp2350Probe<'static>,
) -> &'static mut fapico2_platform::trng::DrbgTrng<
    fapico2_platform::drbg_seed::FuseSeedSource<
        'static,
        DeviceStore,
        fapico2_platform::trng::Rp2350Probe<'static>,
    >,
> {
    let otp = read_otp_key_1()
        .unwrap_or_else(|| fatal_boot("drbg: OTP key row unavailable (cannot seed)"));
    let chipid = embassy_rp::otp::get_chipid()
        .unwrap_or_else(|_| fatal_boot("drbg: chipid unavailable (cannot seed)"));

    let otp: &'static mut [u8; 32] = init_static_slot(core::ptr::addr_of_mut!(DRBG_OTP_KEY), otp);
    let uid: &'static mut [u8; 8] =
        init_static_slot(core::ptr::addr_of_mut!(DRBG_UID), chipid.to_be_bytes());
    let store: &'static mut DeviceStore =
        init_static_slot(core::ptr::addr_of_mut!(DRBG_SEED_STORE), store_handle());
    let probe: &'static mut fapico2_platform::trng::Rp2350Probe<'static> =
        init_static_slot(core::ptr::addr_of_mut!(DRBG_SEED_PROBE), probe);

    let source = fapico2_platform::drbg_seed::FuseSeedSource::new(otp, uid, store, probe);
    // Fail-closed: no constructor hands back an unseeded generator, and a
    // refusal is fatal at boot (see the doc comment above).
    let drbg = fapico2_platform::trng::DrbgTrng::try_new(source)
        .unwrap_or_else(|_| fatal_boot("drbg: seed refused (see SeedError) — no generator"));
    init_static_slot(core::ptr::addr_of_mut!(DRBG), drbg)
}

/// Move the device DRBG out of [`DRBG`] by value, exactly once (US-1006).
///
/// The trussed platform takes its `Rng` **by value** — `Rp2350Rng` owns the
/// generator, and its `try_fill_bytes` re-seeds through the source it holds —
/// so the generator has to be handed over rather than shared. This is the same
/// "take by value exactly once" shape as
/// [`take_client`](fapico2_platform::trusted_backend::take_client): the slot
/// is left `MaybeUninit::uninit()` and a second call panics.
///
/// # Safety
///
/// Call at most once, on the boot path, before any task exists. A second call
/// reads an uninitialized slot, hence the assert. Between `init_drbg` and
/// this call there are exactly **two** borrowers, and both are named here
/// because a SAFETY justification is only as good as its enumeration of
/// aliases — a list one entry out of date gets trusted past the point where
/// it stopped being true, which is how the second one was added without this
/// paragraph being reopened.
///
/// * `boot_fido` (`main.rs`), which takes `&mut` and releases it at the end
///   of the call;
/// * `boot_oath` (`main.rs`), added by the whole-branch review's I-1 fix,
///   which takes `&mut *drbg` to serve the OATH boot pool.
///
/// Both release before returning, so the by-value move is not overlapping any
/// live borrow. A **third** borrower must be added to this list in the same
/// change that introduces it.
pub fn take_drbg() -> fapico2_platform::trusted_backend::device::DeviceDrbg {
    static TAKEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    assert!(
        !TAKEN.swap(true, core::sync::atomic::Ordering::Relaxed),
        "trusted backend: the DRBG was already taken (the platform owns it)"
    );
    // SAFETY: single-core boot path. `init_drbg` wrote the slot exactly once,
    // before any task existed; `boot_fido`'s `&mut` borrow ended before this
    // call; the slot is reset to `uninit` immediately, and `TAKEN` keeps a
    // second call from reading it.
    //
    // The reset is a raw `ptr::write` rather than `MaybeUninit::write`
    // because `(*slot).write(..)` resolves to `DrbgTrng::write`-style
    // inherent-method lookup on the *pointee* rather than to
    // `MaybeUninit::write` on the slot.
    unsafe {
        let slot = core::ptr::addr_of_mut!(DRBG);
        let value = core::ptr::read((*slot).as_mut_ptr());
        core::ptr::write(slot, core::mem::MaybeUninit::uninit());
        value
    }
}


impl fapico2_mgmt::MigrationHandler for DeviceMigrationHandler {
    /// Complete the passphrase-gated OpenPGP class. Class 1 routes through the
    /// production app wrapper — the same `complete_migration` path the tests
    /// prove — so the DEK import, native PW1 conversion, and durable flush
    /// share one retry authority. Other classes keep the platform completion.
    fn complete(
        &mut self,
        class: u8,
        passphrase: &[u8],
        out: &mut HeaplessVec::<u8, MAX_RESPONSE>,
    ) -> fapico2_platform::dispatch::Sw {
        use fapico2_platform::migration::ClassStatus;
        if class != 1 {
            return self.complete_other_class(class, passphrase, out);
        }
        let Some(otp_key_1) = read_otp_key_1() else {
            out.push(ClassStatus::Error.to_byte()).ok();
            return fapico2_platform::dispatch::SW_OK;
        };
        let Ok(chipid) = embassy_rp::otp::get_chipid() else {
            out.push(ClassStatus::Error.to_byte()).ok();
            return fapico2_platform::dispatch::SW_OK;
        };
        let part = cflash::data_partition();
        // SAFETY: single-threaded CCID task; the store, app, and buffer statics
        // are not otherwise mutably borrowed while an APDU is processed (the
        // persist gate runs after the response is framed). The OpenPGP app
        // does not read these statics itself — its trussed state lives in the
        // backend client.
        let mut handle = store_handle();
        let store = &mut handle;
        let bufs = unsafe { &mut *core::ptr::addr_of_mut!(MIG_BUFS) };
        let app = unsafe { &mut *core::ptr::addr_of_mut!(OPENPGP_APP) };
        // SAFETY: the slot was initialized on the boot path (`init_static_slot`)
        // before any task spawned; this is the only runtime accessor.
        let app = unsafe { app.assume_init_mut() };
        // SAFETY: FLASH_DEV was initialized on the boot path before any task
        // spawned (see main.rs); only this synchronous section touches it now.
        let flash = unsafe { (&mut *core::ptr::addr_of_mut!(FLASH_DEV)).as_mut_ptr() };
        // The runtime flush uses the same secure-slot sink as the persist
        // gate; a failed program fails the completion closed (no DEK, no
        // native PIN, source retained).
        let mut sink = crate::tasks::secure_slot_sink(unsafe { &mut *flash });
        // US-917, bounded by US-1005 (D-10): a fresh per-record nonce for the
        // AEAD DEK rewrap, through the bounded probe. Taken here, after the
        // OTP/chipid reads and before `complete_migration` is entered, so a
        // refusal returns a card error with no migration state touched — there
        // is no store write, no scratch-buffer use and no flash program that
        // could need rolling back. Same shape as the two refusals above it:
        // report `ClassStatus::Error`, answer `SW_OK`, and let the operator
        // read a status byte instead of a timeout.
        let nonce = match migration_nonce() {
            Ok(nonce) => nonce,
            Err(e) => {
                log_migration_nonce_refusal(e);
                out.push(ClassStatus::Error.to_byte()).ok();
                return fapico2_platform::dispatch::SW_OK;
            }
        };
        match app.complete_migration(
            &XipFlash, part, store, &otp_key_1, &chipid.to_be_bytes(), bufs,
            passphrase, &nonce, &mut sink,
        ) {
            Ok(status) => {
                out.push(status.to_byte()).ok();
                fapico2_platform::dispatch::SW_OK
            }
            Err(_) => {
                out.push(ClassStatus::Error.to_byte()).ok();
                fapico2_platform::dispatch::SW_OK
            }
        }
    }
}

impl DeviceMigrationHandler {
    fn complete_other_class(
        &mut self,
        class: u8,
        passphrase: &[u8],
        out: &mut HeaplessVec::<u8, MAX_RESPONSE>,
    ) -> fapico2_platform::dispatch::Sw {
        use fapico2_platform::migration::ClassStatus;
        let Some(otp_key_1) = read_otp_key_1() else {
            out.push(ClassStatus::Error.to_byte()).ok();
            return fapico2_platform::dispatch::SW_OK;
        };
        let Ok(chipid) = embassy_rp::otp::get_chipid() else {
            out.push(ClassStatus::Error.to_byte()).ok();
            return fapico2_platform::dispatch::SW_OK;
        };
        let part = cflash::data_partition();
        // SAFETY: single-threaded CCID task; the store and buffers statics
        // are not otherwise mutably borrowed while an APDU is processed
        // (the US-422 persist gate runs after the response is framed).
        let mut handle = store_handle();
        let store = &mut handle;
        let bufs = unsafe { &mut *core::ptr::addr_of_mut!(MIG_BUFS) };
        // US-917, bounded by US-1005 (D-10): only the class-1 DEK rewrap
        // consumes the nonce (class 0 persists the raw keydev value); one
        // fresh draw serves either class. Taken before
        // `complete_passphrase_class` is entered, so a refusal leaves the
        // store, the scratch buffers and the flash untouched — see
        // `migration_nonce`.
        let nonce = match migration_nonce() {
            Ok(nonce) => nonce,
            Err(e) => {
                log_migration_nonce_refusal(e);
                out.push(ClassStatus::Error.to_byte()).ok();
                return fapico2_platform::dispatch::SW_OK;
            }
        };
        match migration::complete_passphrase_class(
            &XipFlash,
            part,
            store,
            &otp_key_1,
            &chipid.to_be_bytes(),
            bufs,
            class,
            &nonce,
            passphrase,
        ) {
            Ok(status) => {
                out.push(status.to_byte()).ok();
                fapico2_platform::dispatch::SW_OK
            }
            Err(_) => {
                out.push(ClassStatus::Error.to_byte()).ok();
                fapico2_platform::dispatch::SW_OK
            }
        }
    }
}

pub static mut MIGRATION_HANDLER: DeviceMigrationHandler = DeviceMigrationHandler;

/// US-711: management-APDU factory-reset hook state (INS 0x1E). Same
/// injection model and task discipline as [`DeviceMigrationHandler`].
pub struct DeviceFactoryResetHandler;

/// US-711 review fix: bumped by the management factory reset once its
/// durable wipe is done. Each transport task observes the counter at the
/// top of its command handling (the check → process → persist window is
/// synchronous, no `.await` inside) and re-initializes the apps it owns:
/// re-initializes the apps it owns: the CCID task wipes OATH/OTP/OpenPGP
/// through the dispatcher ([`Dispatcher::factory_wipe_apps`]), the HID task
/// re-initializes the FIDO app in RAM
/// ([`fapico2_fido::device_app::FidoApp::factory_reset`],
/// C `cbor_reset` → `init_fido()` parity) so a later mutating command can
/// never re-persist the pre-reset snapshot the wipe deleted. The durable
/// wipe itself covers the FIDO/OpenPGP secure-store slots **and** the
/// trussed internal FS (US-711 review finding 2 — the OpenPGP PW1 state
/// lives in trussed files/credentials, not the secure store).
pub static RESET_GENERATION: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// A missing entry is the benign outcome of a wipe — there was nothing
/// there to destroy. Every other variant means the delete did not land and
/// must not be acknowledged as success.
fn ignore_absent(
    r: Result<(), fapico2_platform::secure_store::SecureStoreError>,
) -> Result<(), fapico2_platform::secure_store::SecureStoreError> {
    match r {
        Err(fapico2_platform::secure_store::SecureStoreError::NotFound) | Ok(()) => Ok(()),
        Err(e) => Err(e),
    }
}

impl fapico2_mgmt::FactoryResetHandler for DeviceFactoryResetHandler {
    /// Wipe device-wide durable state (C `cmd_factory_reset` →
    /// `cbor_reset()` parity): the FIDO keystore + hkey slots, the OpenPGP
    /// keystore + DEK slots, the trussed internal filesystem (US-711
    /// review finding 2 — the OpenPGP PW1 flag + retry counter live in
    /// opcard state files / trussed-auth PIN credentials there, outside
    /// the secure-store slots), then signal [`RESET_GENERATION`] for the
    /// task-owned app state.
    //
    // Task split: the OATH/OTP/OpenPGP apps live behind the CCID dispatcher
    // (sole `&mut` per app) and the FIDO app on the HID task — none of them
    // is reachable from here without aliasing `&mut`, which this handler
    // must not do. Instead it deletes the FIDO and OpenPGP durable slots
    // (the store boots factory-fresh even if the power is cut before a task
    // observes the generation) and bumps the generation; each owning task
    // wipes / re-initializes its apps before the next command and the
    // persist gate flushes the emptied state durable-before-ack.
    fn factory_reset(&mut self) -> fapico2_platform::dispatch::Sw {
        // US-711 review finding 2: the trussed internal FS holds the
        // OpenPGP PW1 flag + retry counter (opcard state files,
        // trussed-auth PIN credentials) — the secure-store slots below
        // don't cover it, and the hardware probe left the app PW1-blocked
        // after a wipe (counter burned to 0). Format it factory-fresh; a
        // failure aborts the reset closed (fail-closed hook contract;
        // 0x6F00 is the codebase's fail-closed SW — tasks.rs `6F 00`).
        if !fapico2_platform::trusted_backend::wipe_internal_fs() {
            return 0x6F00;
        }
        let mut handle = store_handle();
        let store = &mut handle;
        // FIDO: the durable keystore + hkey slots (the app re-derives
        // factory-fresh state from the emptied store). OpenPGP: the migrated
        // keystore (DO records, PIN hashes) and the wrapped private-key DEK —
        // a prior owner's keys must not survive a handover
        // ([`migration::SLOT_OPENPGP`], [`migration::SLOT_OPENPGP_DEK`]).
        //
        // All four run, then all four are checked. Collecting into an array
        // rather than chaining combinators is deliberate: `and`/`and_then`
        // make "did every delete actually execute" depend on which
        // combinator is used, and this path must not short-circuit past a
        // key that is still present. `NotFound` is the benign case — an
        // unprovisioned or pre-migration device has nothing to wipe — but any
        // other error means a delete did NOT land, and this path must not
        // ack `90 00` over surviving key material: the operator's handover
        // contract is "I reset it, it is clean". Bumping the generation
        // before this check would be worse than useless — the tasks would
        // re-persist, and re-seal, the keys the reset was meant to destroy.
        let wiped = [
            ignore_absent(fapico2_platform::secure_store::chunked::delete_chunked(
                store,
                fapico2_fido::device_keystore::KEYSTORE_SLOT,
            )),
            ignore_absent(store.delete(fapico2_fido::device_app::HKEY_KEY)),
            ignore_absent(fapico2_platform::secure_store::chunked::delete_chunked(
                store,
                migration::SLOT_OPENPGP,
            )),
            ignore_absent(store.delete(migration::SLOT_OPENPGP_DEK)),
        ];
        if wiped.iter().any(|r| r.is_err()) {
            return 0x6F00;
        }
        // Signal both transport tasks to re-initialize the apps they own.
        RESET_GENERATION.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        fapico2_platform::dispatch::SW_OK
    }
}

pub static mut FACTORY_RESET_HANDLER: DeviceFactoryResetHandler = DeviceFactoryResetHandler;

// ── US-161/162/163 (PICOForge-COMPAT Phase H): the Rescue applet's owners ──

/// Bumped by a successful `RESCUE WRITE` once the merged `phy` record is
/// **durable**, so the HID task adopts it into the FIDO app's in-RAM keystore
/// copy before it can re-persist a stale snapshot over it.
///
/// The same generation-then-act shape as [`RESET_GENERATION`], for the same
/// structural reason: the Rescue applet is behind the **CCID** dispatcher and
/// the FIDO app is behind the **HID** task, so they are two owners of one
/// record and only one of them can be told synchronously. What crosses the
/// boundary is a counter — never a `&mut` to either app, which is what keeps
/// the aliasing argument the factory-reset handler documents intact on an
/// *unauthenticated* path.
pub static RESCUE_PHY_GENERATION: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// The mode a `REBOOT` asked for, `0xFF` = none pending.
///
/// A `REBOOT` cannot reset the core from inside the handler: the `9000` has to
/// reach the host first, and the client treats anything other than a `9000` as
/// a failed reboot (`ops.rs:653-656`). So the handler records the mode and
/// `ccid_task` performs the reset **after** the reply is written.
pub static RESCUE_REBOOT_PENDING: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(NO_REBOOT_PENDING);

/// `RESCUE_REBOOT_PENDING` sentinel meaning "nothing was asked for". Distinct
/// from both protocol modes, which are `0x00` (normal) and `0x01` (BOOTSEL).
pub const NO_REBOOT_PENDING: u8 = 0xFF;

/// The device-side owner of the PHY record: `fapico2_fido::vendorff::PhyConfig`
/// in the FIDO keystore's auth-map key 6.
///
/// **The applet does not own this record and never holds a handle to it**
/// (`docs/tasks/rescue-threat-model.md` §0.4). What crosses the boundary is a
/// [`PhySnapshot`] out and a [`PhyUpdate`] in — two `Copy` structs of small
/// integers — so an unauthenticated applet cannot reach a key, a keystore or a
/// store through this seam.
///
/// The read-modify-write is done against the **durable snapshot**, not against
/// the FIDO app's RAM: [`RESCUE_PHY_GENERATION`] then tells the HID task to
/// catch up. Doing it the other way round would need a `&mut` into an app this
/// task does not own.
pub struct DeviceRescueConfigHandler;

impl RescueConfigHandler for DeviceRescueConfigHandler {
    fn snapshot(&self) -> PhySnapshot {
        let mut handle = store_handle();
        match fapico2_fido::device_keystore::DeviceKeystore::load(&mut handle) {
            Ok(Some(ks)) => PhySnapshot {
                vid_pid: ks.phy.vid_pid,
                led_gpio: ks.phy.led_gpio,
                led_brightness: ks.phy.led_brightness,
                options: ks.phy.options,
                enabled_usb_itf: ks.phy.enabled_usb_itf,
                // The two identity names cross as fixed buffers because
                // `PhySnapshot` is a `Copy` struct of plain data by design —
                // the threat model (§2) leans on that boundary being
                // incapable of reaching anything. `None` is a real answer
                // here, not a default to fill in: an unconfigured name is what
                // "nobody set this" looks like.
                product: ks.phy.product.map(|n| {
                    let mut buf = [0u8; fapico2_platform::phy_tlv::MAX_NUL_STRING_LEN];
                    let bytes = n.as_bytes();
                    buf[..bytes.len()].copy_from_slice(bytes);
                    buf
                }),
                manufacturer: ks.phy.manufacturer.map(|n| {
                    let mut buf = [0u8; fapico2_platform::phy_tlv::MAX_NUL_STRING_LEN];
                    let bytes = n.as_bytes();
                    buf[..bytes.len()].copy_from_slice(bytes);
                    buf
                }),
            },
            // No durable snapshot yet. The applet's own default answer for this
            // is an empty blob, and an absent record *is* the empty record, so
            // this is the same answer rather than a second convention.
            _ => PhySnapshot::default(),
        }
    }

    /// Merge `update` over the stored record and persist it, durable-before-ack.
    ///
    /// `Ok(None)` \u2014 no keystore snapshot on the device \u2014 is refused
    /// `0x6F00` rather than "creating" one: a fresh keystore needs a TRNG draw
    /// for its device random, and silently substituting a default for that
    /// would be a persistence path with a hole in it. In practice the slot
    /// always exists, because `main.rs` runs a boot persist before serving.
    fn commit(&mut self, update: &PhyUpdate) -> fapico2_platform::dispatch::Sw {
        let mut handle = store_handle();
        let store = &mut handle;
        let Ok(Some(mut ks)) = fapico2_fido::device_keystore::DeviceKeystore::load(store) else {
            return 0x6F00;
        };
        // An absent field is a *preserve*: this is the merge the Rescue WRITE
        // is defined to be (`ops.rs:584-585`), and doing it here rather than in
        // the applet is what keeps the applet from needing a store handle.
        if update.vid_pid.is_some() {
            ks.phy.vid_pid = update.vid_pid;
        }
        if update.led_gpio.is_some() {
            ks.phy.led_gpio = update.led_gpio;
        }
        if update.led_brightness.is_some() {
            ks.phy.led_brightness = update.led_brightness;
        }
        if update.options.is_some() {
            ks.phy.options = update.options;
        }
        if update.enabled_usb_itf.is_some() {
            ks.phy.enabled_usb_itf = update.enabled_usb_itf;
        }
        // The two identity names. Same present-means-write, absent-means-preserve
        // merge as every field above, and the NUL the applet strips on the way
        // in is the reason this goes back through `IdentityName::new` rather
        // than being copied byte-for-byte: a name that cannot be stored is
        // refused at the boundary rather than persisted as something the
        // encoder will later decline to frame.
        for (field, name) in [
            (0, update.product),
            (1, update.manufacturer),
        ] {
            let Some(raw) = name else { continue };
            let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let Ok(text) = core::str::from_utf8(&raw[..len]) else {
                return 0x6A80;
            };
            let Some(built) = fapico2_fido::vendorff::IdentityName::new(text) else {
                return 0x6A80;
            };
            if field == 0 {
                ks.phy.product = Some(built);
            } else {
                ks.phy.manufacturer = Some(built);
            }
        }
        // The CCID-mask guard was already applied by the applet before it got
        // here \u2014 this side does not re-check it, and a future reader should
        // not add a second copy: the guard belongs to the surface, because the
        // surface is the only thing an unauthenticated APDU can reach.
        if ks.persist(store).is_err() {
            // Failure contract: nothing is acknowledged. A `9000` here would
            // tell the operator a configuration change is durable when it is
            // not, and the Rescue applet exists for recovery.
            return 0x6F00;
        }
        RESCUE_PHY_GENERATION.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        fapico2_platform::dispatch::SW_OK
    }
}

pub static mut RESCUE_CONFIG_HANDLER: DeviceRescueConfigHandler = DeviceRescueConfigHandler;

/// The device-side `REBOOT` / `SECURE` actions.
///
/// `SECURE` is implemented per US-163 and **refuses every request** on this
/// firmware. The reason is the threat model's \u00a76.1 objection 1, which is
/// the strongest argument in the document: an unauthenticated `80 1D 00 01 00`
/// that only refuses future PHY writes, on a tree where **nothing implements
/// secure boot** (§0.3 \u2014 no secure-boot state, no bootrom key, no
/// verification step anywhere), would cost the owner a permanent
/// reconfiguration lockout and prevent no reflash at all. R9 in the residual
/// register. A lock that only locks a config blob is a lock that costs the
/// owner everything and buys nothing, so the honest answer is `0x6A86` \u2014
/// "this firmware does not support that" \u2014 and the command is left
/// dispatchable for the day a real mechanism lands.
pub struct DeviceRescueDeviceHandler;

impl RescueDeviceHandler for DeviceRescueDeviceHandler {
    fn reboot(&mut self, mode: RebootMode) -> fapico2_platform::dispatch::Sw {
        // Record the mode and answer. The reset itself happens in `ccid_task`
        // after the reply is written, because a reset that outruns the reply
        // surfaces to the operator as a transport error on a command that in
        // fact succeeded.
        RESCUE_REBOOT_PENDING.store(mode.p1(), core::sync::atomic::Ordering::Release);
        fapico2_platform::dispatch::SW_OK
    }

    fn set_secure_boot(&mut self, _key_index: u8, _lock: bool) -> fapico2_platform::dispatch::Sw {
        // 0x6A86, the same status the applet uses for "this build has no
        // destination for this". See the type's docs.
        0x6A86
    }
}

pub static mut RESCUE_DEVICE_HANDLER: DeviceRescueDeviceHandler = DeviceRescueDeviceHandler;

/// Perform a Rescue `REBOOT` that has been acknowledged to the host.
///
/// Called by `ccid_task` after the reply is on the wire, and `-> !` because
/// neither path returns:
///
/// * **Normal** \u2014 `SCB::sys_reset()`, the same helper
///   `platform/src/trusted_backend/device.rs:447` uses for its `reboot`.
/// * **BOOTSEL** \u2014 the RP2350 bootrom's own `reboot2` path via
///   `embassy_rp::rom_data::rp235x::reset_to_usb_boot`, which arms the
///   watchdog and re-enters as the USB mass-storage bootloader.
///
/// BOOTSEL is destructive from the client's point of view and the threat
/// model \u00a75 / R5 is the abuse case: the device leaves the bus and, on a
/// reflash on top of a stale secure partition, is a brick needing
/// `nuke_universal.uf2`. It ships anyway \u2014 it is the recovery path \u00a76
/// depends on being able to rely on.
pub fn perform_rescue_reboot(mode: u8) -> ! {
    match mode {
        // `rom_data` re-exports the chip-specific module flat, so the path is
        // `rom_data::reset_to_usb_boot` and not `rom_data::rp235x::…`.
        0x01 => embassy_rp::rom_data::reset_to_usb_boot(0, 0),
        _ => cortex_m::peripheral::SCB::sys_reset(),
    }
    // `reset_to_usb_boot` is documented as not returning on success; the
    // `sys_reset` arm above does not return either. Looping here rather than
    // lying with `unreachable!()`: if a future bootrom call *did* return, a
    // spin is still a better failure than a panic inside a USB task.
    loop {
        cortex_m::asm::wfi();
    }
}

/// S-701-1: the CTAP-HID response buffer is a static sized to
/// CTAPHID_MAX_MSG (7609 B) — the previous 1024-byte task-local buffer could
/// not carry largeBlobs / credential-enumeration replies despite the
/// assembler framing up to CTAPHID_MAX_MSG and getInfo advertising 7609.
pub static mut HID_RESP: HeaplessVec<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HeaplessVec::new();

/// US-413 S-413-4: the C key row (`OTP_MKEK_ROW 0xE90`, 32 bytes = 16 ECC
/// words, `otp_rp2350.c:33,69-72`), read memory-mapped exactly like the C
/// firmware does (readable from any code — no read-protect; the boot-path
/// software lock in [`otp_hw_write_lock_key_row`] is RUNTIME-ONLY and does
/// not survive reset, so this row carries no durable write-lock until an OTP
/// lock page is burned — US-918/D-14; read-protection is a CryptoCell
/// cutover item, US-924).
fn read_otp_key_1() -> Option<[u8; 32]> {
    let mut key = [0u8; 32];
    for i in 0..16u8 {
        match embassy_rp::otp::read_ecc_word(0xE90 + i as usize) {
            Ok(w) => key[(i as usize) * 2..(i as usize) * 2 + 2].copy_from_slice(&w.to_le_bytes()),
            Err(_) => return None,
        }
    }
    Some(key)
}

/// US-915: the boot store key — [`fapico2_platform::store_v3::derive_store_key`]
/// over the C key row (OTP 0xE90) + the chipid. The key never lives in the
/// image or the store; a leaked flash image does not decrypt on another
/// board and a leaked OTP row alone does not open this device's store.
/// Hardware-identity failure is fatal: without the key, neither the sealed
/// slots nor the restore validate.
///
/// US-918 residual risk until the CryptoCell cutover (US-924): the OTP row
/// is still **readable from any code** (no read-protect), so a physical
/// attacker who reads the row and the flash can reconstruct the C-compat
/// root by construction and unlock the store key against the chipid. On the
/// write side there is likewise **no durable lock**: the boot-path software
/// lock is runtime-only (D-14). Full mitigation (CryptoCell
/// secure-arena key) is story US-924; see the ckey module docs.
// US-939: `#[inline(never)]` -- async-main frame discipline.
#[inline(never)]
pub fn derive_boot_store_key() -> [u8; 32] {
    let otp_key_1 = read_otp_key_1()
        .unwrap_or_else(|| fatal_boot("secure partition: OTP key row unavailable"));
    let chipid = embassy_rp::otp::get_chipid()
        .unwrap_or_else(|_| fatal_boot("secure partition: chipid unavailable"));
    fapico2_platform::store_v3::derive_store_key(&otp_key_1, &chipid.to_be_bytes())
}

/// US-1030: the OATH credential-key seal context — the C `"OATH"`-magic GCM
/// key, derived from the **flash UID + the OTP key row**. This is the key
/// material the OATH boot path could not reach before this story, and it is
/// what the migration's plaintext OATH keys are re-sealed under.
///
/// Fatal on a hardware-identity failure, exactly like
/// [`derive_boot_store_key`] and for the same reason: an OATH app booted
/// without its seal context would load a migrated credential it can never
/// re-seal, so there is nothing to fall back to. US-130's reasoning applies
/// unchanged — this is a required value, and the failure mode is a refusal,
/// not an unencrypted boot.
#[inline(never)]
pub fn derive_oath_seal() -> OathSeal {
    let otp_key_1 = read_otp_key_1()
        .unwrap_or_else(|| fatal_boot("oath seal: OTP key row unavailable"));
    let chipid = embassy_rp::otp::get_chipid()
        .unwrap_or_else(|_| fatal_boot("oath seal: chipid unavailable"));
    OathSeal::derive(&otp_key_1, &chipid.to_be_bytes())
}

/// US-918: guarantee the boot-entropy slot
/// ([`migration::SLOT_BOOT_ENTROPY`]) exists before anything derives the
/// bound device root ([`fapico2_platform::ckey::derive_kbase`]). Absence →
/// draw [`fapico2_platform::ckey::BOOT_ENTROPY_LEN`] bytes from the TRNG and
/// write; the write rides the boot persist gate, so once the store is
/// persisted the record is authenticated by the sealed v3 image and stable
/// across boots. A present record is left untouched (determinism —
/// re-drawing would change the bound root and orphan everything derived
/// under it); a wrong-length record is treated as corrupt and redrawn
/// (a wrong-length slot never produced a successful derivation). A failed
/// write is logged and NOT fatal here: fail-closed happens at the
/// derivation site, which refuses without the slot (no legacy fallback).
///
/// # Why the draw is BOUNDED, and when that mattered
///
/// The draw used to take `&mut impl Trng` — the unbounded `Rp2350Trng`,
/// whose `embassy-rp` driver (`trng.rs:220-243`) contains two loops with no
/// exit: `while trng_busy { }`, and `while !success`, which on an
/// autocorrelation error soft-resets the peripheral and retries **forever**.
/// The datasheet, quoted in that same file, names the condition a soft reset
/// does not clear: *"When set, RNG ceases functioning until next reset"* —
/// meaning until a power-on reset. A peripheral that lands there wedges the
/// boot from inside a driver call, forever, and no difference in the flash
/// content between a reflash and a power cycle explains it.
///
/// This was the last unbounded spin left on the release boot path, and it is
/// reached on exactly the boot this investigation is about: the slot is
/// absent only after US-919 has wiped the store — the first boot after a
/// reflash of a different image. Every other draw was rerouted to
/// `Rp2350Probe` by US-1005 (the boot sanity draw, the DRBG seed) and the
/// D-10 fix (the migration nonce). This one was missed because the diff that
/// found the second occurrence saw two identical call sites and rerouted one.
///
/// The draw is now a [`fapico2_platform::trng::TrngProbe`], whose wait
/// carries the named budget, and a refusal is fatal with a message naming
/// this site. The trade is the one US-1008 made for the sanity draw, and the
/// reasoning is different in the one way that matters: that site was a
/// *diagnostic*, and a diagnostic that can kill the boot belongs somewhere
/// else. This site is not a diagnostic — without the slot every bound
/// derivation refuses anyway, so halting here changes no outcome. It only
/// turns "dark board, spinning peripheral, no explanation" into "dark board
/// with a message that says which entropy site refused", which is the
/// difference between a bug that can be argued about and one that can be
/// reproduced.
// US-939: `#[inline(never)]` -- async-main frame discipline.
#[inline(never)]
pub fn ensure_boot_entropy(
    probe: &mut impl fapico2_platform::trng::TrngProbe,
    store: &mut DeviceStore,
) {
    use fapico2_platform::ckey;
    let mut buf = [0u8; ckey::BOOT_ENTROPY_LEN];
    match store.read(migration::SLOT_BOOT_ENTROPY, &mut buf) {
        Ok(n) if n == ckey::BOOT_ENTROPY_LEN => return,
        Ok(_) | Err(SecureStoreError::NotFound) => {} // draw below
        Err(_) => {
            defmt::error!("boot entropy: slot unreadable; refusing to redraw (US-918)");
            return;
        }
    }
    if fapico2_platform::trng::try_fresh_bytes(probe, &mut buf).is_err() {
        fatal_boot("boot entropy: TRNG refused inside the budget; nothing to guarantee the slot with");
    }
    if store.write(migration::SLOT_BOOT_ENTROPY, &buf).is_err() {
        defmt::error!("boot entropy: could not persist the drawn entropy (US-918)");
    }
}

// ---------------------------------------------------------------------------
// US-919: foreign-image boot admission (EPIC `security-hardening`, R9/R6).
// BOOTSEL accepts an unsigned reflash; boot computes the running image's
// manifest hash and compares it against the last-known-good hash in the
// dedicated secure-store slot ([`fw_manifest::SLOT_FW_MANIFEST`], the
// US-918 `boot.entropy.v1` pattern). On a mismatch the secure-partition
// slots are wiped BEFORE any app loads — the deliberate
// data-loss-over-implant policy — so an implanted firmware starts with a
// fresh store instead of inheriting every secret. The pure decision +
// streaming hash live in [`fapico2_platform::fw_manifest`]; this block owns
// the device-side region bounds and the wipe execution.
// ---------------------------------------------------------------------------

// cortex-m-rt 0.7.6 `link.x` layout symbols (all unconditionally defined):
// `.data`'s RAM bounds and its load address in flash. The running image's
// manifest region ends at the END OF THE `.data` INIT IMAGE in flash —
// `__sidata + (__edata - __sdata)` — which covers the vector table, the
// PICOBIN IMAGE_DEF (`.start_block`, anchored right after the vector
// table by `memory.x`), `.text`, `.rodata`, and the `.data` init bytes:
// a stable, injective-enough description of the CURRENT image (verified
// at US-924). The `_etext`-only alternative (story-mentioned fallback)
// would exclude the `.data` init region from the coverage.
extern "C" {
    static __sdata: u8;
    static __edata: u8;
    static __sidata: u8;
}

/// QSPI flash XIP base (`memory.x` `FLASH` ORIGIN) and the reserved
/// secure-partition origin (`memory.x` `SECURE`). The manifest
/// hash must NEVER read the secure-partition region: its content is
/// boot-mutable store data (the persist gate programs it), so hashing it
/// would make the manifest depend on the data it is supposed to protect —
/// the region bound stops the hash at the boundary.
///
/// US-1010: both were literals — `0x1000_0000` and `0x103F_0000` — sitting
/// beside a *board-derived* [`SECURE_PRIMARY_OFFSET`] with nothing linking
/// them. The two agreed only because the board happens to be 4 MiB: a 2 MiB
/// board (which `platform/board_def.rs::MIN_FLASH_SIZE_KB` still accepts) puts
/// its partition at `0x101F0000`, and the manifest cap would have sat 1 MiB
/// past the end of the region, hashing the keystore it exists to protect. Now
/// both are arithmetic on the same board value that renders `memory.x`, and
/// the assertion below is what makes the two *and* the linker script one fact.
const FLASH_ORIGIN: usize = fapico2_platform::board::FLASH_ORIGIN as usize;
const SECURE_ORIGIN: usize = FLASH_ORIGIN + SECURE_PRIMARY_OFFSET as usize;

/// The manifest-hash cap, the store's keystore offset, and the top of flash
/// have to describe one region. Kept as a `_` item, so it costs nothing in the
/// image.
///
/// The first clause is what makes the derivation above worth anything beyond
/// tidiness: it is the check a hand-written literal could not survive, because
/// a literal is compared against nothing. The second is the top-anchoring
/// property `platform::board` already asserts for the *offset*; it is restated
/// here because this is the consumer that would read past the region if the
/// region moved.
const _: () = assert!(
    SECURE_ORIGIN + fapico2_platform::board::SECURE_RESERVE_KB as usize * 1024
        == FLASH_ORIGIN + fapico2_platform::board::FLASH_SIZE_KB as usize * 1024,
    "the secure partition must be top-anchored: it ends at the top of flash. A manifest cap \
     derived from a different region would read the keystore it exists to protect."
);

/// US-919: the manifest region length — from the flash XIP base to the end
/// of the `.data` init image, capped at [`SECURE_ORIGIN`] (belt-and-suspenders:
/// the init image ends inside the 4032 KiB `FLASH` region well before the
/// secure partition, but the cap makes the exclusion structural).
fn manifest_region_len() -> usize {
    let sdata = core::ptr::addr_of!(__sdata) as usize;
    let edata = core::ptr::addr_of!(__edata) as usize;
    let sidata = core::ptr::addr_of!(__sidata) as usize;
    let end = sidata + (edata - sdata);
    // Clippy 1.94 (manual_clamp): the floor-then-ceiling form below is the
    // equivalent of the old `end.max(..).min(..)` — the floor first keeps
    // the clamp's `max < min` panic unreachable (end >= FLASH_ORIGIN
    // whenever the linker script places .data in flash, as it must).
    (end.max(FLASH_ORIGIN).clamp(FLASH_ORIGIN, SECURE_ORIGIN)).saturating_sub(FLASH_ORIGIN)
}

/// US-919: volatile-window reader over the running image's XIP-mapped
/// flash region (the same discipline as [`SecureSlotReader`] — volatile
/// reads keep LTO from const-folding the driver-programmed flash content,
/// and the bounded windows keep no whole-image buffer on the boot path).
struct XipManifestReader {
    len: usize,
}

impl ImageReader for XipManifestReader {
    fn read_window(&mut self, off: usize, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.len.saturating_sub(off));
        // SAFETY: the reads walk `[FLASH_ORIGIN + off, FLASH_ORIGIN + off + n)`
        // — `off + n` is clamped to the manifest region bound above, which
        // never reaches the secure-partition region ([`SECURE_ORIGIN`]) and
        // stays inside the XIP-mapped QSPI flash the CPU itself executes
        // from. Pre-task boot path, single core: it races with nothing.
        unsafe {
            for (i, b) in buf[..n].iter_mut().enumerate() {
                *b = core::ptr::read_volatile((FLASH_ORIGIN + off + i) as *const u8);
            }
        }
        n
    }
}

/// US-919 boot admission, device wiring. Computes the running image's
/// manifest hash ([`fw_manifest::hash_region`] over
/// [`manifest_region_len`]), reads the last-known-good slot and applies
/// [`fw_manifest::foreign_image_decision`]:
///
/// * `Load` (absent slot or equal hash): the slot is stamped with the
///   current hash when it differs — the write rides the boot persist gate,
///   so the record is sealed into the v3 store image at the successful
///   boot it records.
/// * `WipeAndFresh`: **every** secure-partition slot is wiped
///   ([`SecureStore::wipe_all`] — data-loss-over-implant, deliberate), the
///   event is logged, the US-918 boot-entropy slot is redrawn (the wipe
///   took it with everything else, and the bound derivations refuse
///   without it), and the caller starts from a fresh store — the boot
///   never re-compares this boot. The wipe is compiled in only for
///   builds that selected it (`FAPICO2_FOREIGN_IMAGE_WIPE=1`); without it
///   the mismatch is still computed and logged, but boot continues
///   log-only (dev/emulation knob).
// US-939: `#[inline(never)]` -- async-main frame discipline.
#[inline(never)]
pub fn ensure_fw_manifest(store: &mut DeviceStore) -> fw_manifest::ForeignImageDecision {
    let region_len = manifest_region_len();
    // US-930: decision-point trace, debug profile only (`dlog!` compiles to
    // nothing without the `dbg-log` feature — the release-forbidden gate in
    // `tests/scripts/check_dbg_release_gate.py` must stay green). Event
    // semantics are unchanged; every point below is one `(a, b)` record in
    // the RAM ring, drained via the CTAP-HID vendor command (US-922).
    dlog!(
        crate::dbg::T_MAIN,
        crate::dbg::E_FWLEN,
        region_len as u32,
        0
    );
    let mut reader = XipManifestReader { len: region_len };
    let current = fw_manifest::hash_region(&mut reader, region_len);
    dlog!(
        crate::dbg::T_MAIN,
        crate::dbg::E_FWHASH,
        u32::from_be_bytes(current[..4].try_into().expect("4-byte hash prefix")),
        0
    );
    let mut buf = [0u8; 32];
    let stored = match store.read(fw_manifest::SLOT_FW_MANIFEST, &mut buf) {
        Ok(32) => {
            dlog!(
                crate::dbg::T_MAIN,
                crate::dbg::E_FWSTORED,
                32,
                u32::from_be_bytes(buf[..4].try_into().expect("4-byte hash prefix"))
            );
            Some(buf)
        }
        // Absent (first boot / pre-policy) or wrong-length (corrupt —
        // treated as absent, restamped below).
        _ => {
            dlog!(crate::dbg::T_MAIN, crate::dbg::E_FWSTORED, 0, 0);
            None
        }
    };
    match fw_manifest::foreign_image_decision(stored, current) {
        fw_manifest::ForeignImageDecision::Load => {
            dlog!(
                crate::dbg::T_MAIN,
                crate::dbg::E_FWDECIDE,
                0,
                u32::from_be_bytes(current[..4].try_into().expect("4-byte hash prefix"))
            );
            if stored != Some(current) {
                // Stamp (first boot / pre-policy): rides the boot persist gate.
                let stamped = store.write(fw_manifest::SLOT_FW_MANIFEST, &current);
                dlog!(
                    crate::dbg::T_MAIN,
                    crate::dbg::E_FWSTAMP,
                    u32::from(stamped.is_ok()),
                    0
                );
                if stamped.is_err() {
                    defmt::error!("fw manifest: could not stamp the last-known-good hash (US-919)");
                }
            }
            fw_manifest::ForeignImageDecision::Load
        }
        fw_manifest::ForeignImageDecision::WipeAndFresh => {
            dlog!(
                crate::dbg::T_MAIN,
                crate::dbg::E_FWDECIDE,
                1,
                u32::from_be_bytes(current[..4].try_into().expect("4-byte hash prefix"))
            );
            #[cfg(FAPICO2_FOREIGN_IMAGE_WIPE)]
            {
                let wiped = store.wipe_all();
                dlog!(
                    crate::dbg::T_MAIN,
                    crate::dbg::E_FWWIPE,
                    u32::from(wiped.is_ok()),
                    1
                );
                if wiped.is_err() {
                    defmt::error!("fw manifest: secure-slot wipe failed (US-919)");
                }
                defmt::error!("foreign firmware image detected; secure slots wiped (US-919)");
                // The wipe took the boot-entropy slot too; the bound
                // derivations (US-918) refuse without it — redraw so the
                // fresh store boots apps (a fresh root is the point).
                ensure_boot_entropy(spare_probe(), store);
            }
            #[cfg(not(FAPICO2_FOREIGN_IMAGE_WIPE))]
            {
                // The wipe — and with it the entropy redraw below — is
                // compiled out. The mismatch is still computed and still
                // logged, one branch above; nothing is destroyed.
                //
                // The wording matters and used to be a lie: this arm said
                // "wipe disabled (dev build)", which was true when the only
                // way to reach it was an emulation build. It is now the
                // SHIPPING path for device images, and "dev build" would tell
                // an operator reading the log that they had put a
                // development image on a token, when what actually happened
                // is that they installed an update and — correctly — still
                // have their passkeys. The line names what happened to the
                // store, not the build profile, because the store is the
                // thing the operator cares about.
                dlog!(crate::dbg::T_MAIN, crate::dbg::E_FWWIPE, 0, 0);
                defmt::error!(
                    "foreign firmware image detected AND ADMITTED: this build has the \
                     wipe compiled out, so the previous image's keystore was kept \
                     (FAPICO2_FOREIGN_IMAGE_WIPE=0 at build time)"
                );
            }
            // Never stamp on the mismatch arm: the fresh store (or the
            // dev log-only store) re-decides on the next boot.
            fw_manifest::ForeignImageDecision::WipeAndFresh
        }
    }
}

/// US-918: best-effort software lock of the C key row's page (OTP 0xE90) for
/// the remainder of THIS BOOT. It is **not** a durable write-lock — see
/// "runtime-only" below.
///
/// OTP page 233 (`0xE90 / 16`) covers exactly rows 0xE90..=0xE9F, so the
/// lock on this page covers the key row and its page-neighbors without
/// touching anything else. From non-secure boot only the NSEC field is
/// writable (`SEC` is read-only to NS code), and `READ_ONLY` (write-lock) is
/// chosen over `INACCESSIBLE` because the firmware reads the row every boot
/// (store key + bound root) — an inaccessible row would brick the device.
/// Writes are OR'd, so the lock is monotonic/idempotent; a page group
/// already locked earlier in this boot is skipped.
///
/// # This lock is RUNTIME-ONLY (US-918, corrected 2026-09-29)
///
/// `SW_LOCK` is initialised from the **OTP lock pages at reset**; the
/// register "can be written to further advance the lock state of each page
/// (*until next reset*)" — rp-pac 7.0.0, `src/rp235x/otp.rs:17`. A power
/// cycle therefore presents whatever the lock PAGES hold, and the write
/// below is forgotten. It does not stop later software on a rebooted unit.
///
/// A real lock is an irreversible OTP lock-page burn via SBPI — the other
/// half of the C reference's `otp_lock_page()`
/// (`pico-keys-sdk/src/otp/otp_rp2350.c:88-95`), which burns the lock row
/// through `rom_func_otp_access` and *then* does this same register write.
/// Only the runtime half is implemented here. A permanently write-locked key
/// row additionally needs a provisioning decision about who may burn a unit
/// and when. Recorded as D-14 in `docs/known-gate-divergences.md`.
///
/// The call is KEPT on purpose: it is harmless, non-fatal, and it makes a
/// unit whose lock pages are already burnt behave correctly at runtime.
/// Whether to keep it is a separate decision; what was wrong was the
/// claim, and that is what this comment corrects.
///
/// NEVER fatal: a failed lock only restores the pre-US-918 exposure (the
/// row stays software-unlocked), while wedging boot over a lock register
/// would cost more than the residual risk itself. Read-protection (the
/// stronger half) is the CryptoCell cutover, story US-924.
// US-939: `#[inline(never)]` -- async-main frame discipline.
#[inline(never)]
pub fn otp_hw_write_lock_key_row() {
    use rp_pac::otp::vals::SwLockNsec;
    // The RP2350 OTP spans 256 pages of 16 ECC rows (row 0xE90 = page
    // 233) and the 64 SWLOCK registers each cover a group of 4 pages, so
    // the key row's lock register is 233 / 4 = 58 (`sw_lock` asserts
    // n < 64 — the per-page form would panic at boot). The lock also
    // covers the row's 3 page-neighbors, which this firmware never
    // writes — write-locking them is harmless. RUNTIME-ONLY: reset reloads
    // the lock state from the OTP lock pages, not from this register.
    const KEY_ROW_PAGE: usize = 0xE90 / 16; // 233
    const OTP_PAGES: usize = 256;
    const SWLOCK_REGS: usize = 64;
    const SWLOCK_REG: usize = KEY_ROW_PAGE / (OTP_PAGES / SWLOCK_REGS); // 58
    let swlock = rp_pac::OTP.sw_lock(SWLOCK_REG);
    if swlock.read().nsec() == SwLockNsec::READ_ONLY {
        return; // already write-locked (boot is idempotent)
    }
    swlock.modify(|v| v.set_nsec(SwLockNsec::READ_ONLY));
    if swlock.read().nsec() != SwLockNsec::READ_ONLY {
        defmt::warn!(
            "otp: SWLOCK reg {} write-lock did not take; key row remains writable (residual risk, US-924)",
            SWLOCK_REG
        );
    }
}

/// Restore captured OpenPGP state after backend mount and before registration.
/// Missing hardware identity is acceptable only when there is no capture.
// US-939: `#[inline(never)]` -- async-main frame discipline.
#[inline(never)]
pub fn restore_openpgp_at_boot(
    app: &mut OpenPgpApp<Client<'static, DevicePlatform, OpcardDispatch>>,
    store: &mut DeviceStore,
) {
    if !migration::has_openpgp_capture(store) {
        return;
    }
    let otp = read_otp_key_1()
        .unwrap_or_else(|| fatal_boot("migration: captured identity OTP unavailable"));
    let uid = embassy_rp::otp::get_chipid()
        .unwrap_or_else(|_| fatal_boot("migration: captured identity chipid unavailable"));
    // Boot-only exclusive access; runtime has not started.
    let bufs = unsafe { &mut *core::ptr::addr_of_mut!(MIG_BUFS) };
    if app.restore_at_boot(store, &otp, &uid.to_be_bytes(), bufs).is_err() {
        fatal_boot("migration: OpenPGP restore failed");
    }
}

/// US-413 S-413-5: first-boot C→Rust data migration. Detects a used C data
/// partition on an empty Rust store and re-seeds the keystore slots
/// (strictly read-only on the C region). Silent skip when there is nothing
/// to migrate or the marker is already set; `NeverBootC` (all-zero OTP row)
/// means the C firmware never initialized the device.
// US-939: `#[inline(never)]` -- keep the migration walk's buffers in this
// function's own frame, out of the Embassy async-main frame.
#[inline(never)]
pub fn run_first_boot_migration(store: &mut DeviceStore) {
    let Some(otp_key_1) = read_otp_key_1() else {
        defmt::info!("migration: OTP key row unreadable; skipping");
        return;
    };
    let chipid = match embassy_rp::otp::get_chipid() {
        Ok(id) => id,
        Err(_) => {
            defmt::info!("migration: chipid unreadable; skipping");
            return;
        }
    };
    let part = cflash::data_partition();
    let bounds = PoolBounds::from_partition(part);
    let cfs = Cfs::new(&XipFlash, bounds);
    use fapico2_platform::cfs::CState;
    if cfs.state() == CState::FactoryFresh || cfs.state() == CState::Empty {
        defmt::info!("migration: C partition not used; skipping");
        return;
    }
    // SAFETY: MIG_BUFS is a `static mut` touched only here on the boot path
    // (single-threaded, before the executor starts).
    let bufs = unsafe { &mut *core::ptr::addr_of_mut!(MIG_BUFS) };
    match migration::run(&XipFlash, part, store, &otp_key_1, &chipid.to_be_bytes(), bufs) {
        Ok(MigrationOutcome::Done(report)) => defmt::info!(
            "migration done: hkey {} devconf {} passphrase {} (pgp {} oath {} otp {} piv {} fido {})",
            report.hkey_migrated,
            report.dev_conf_migrated,
            report.needs_passphrase,
            report.openpgp_records,
            report.oath_records,
            report.otp_records,
            report.piv_records,
            report.fido_container_records
        ),
        Ok(MigrationOutcome::Skipped(reason)) => {
            use fapico2_platform::migration::SkipReason as MigrationOutcomeSkipReason;
            let what = match reason {
                MigrationOutcomeSkipReason::AlreadyMigrated => "already migrated",
                MigrationOutcomeSkipReason::StoreNotEmpty => "store not empty",
                MigrationOutcomeSkipReason::CStateFactoryFresh => "C factory-fresh",
                MigrationOutcomeSkipReason::CStateEmpty => "C empty",
            };
            defmt::info!("migration skipped: {}", what)
        }
        Err(_) => fatal_boot("migration failed; refusing destructive backend boot"),
    }
}

// US-391 E6 (S-391-10): the CCID applets live in static memory, not the
// `ccid_task` spawn frame. In E5 they were moved *into* the task by value and,
// together with the `Dispatcher<4>`, still left the task future too large to
// spawn (E3/E4/E5 wedged before stage C — see the ladder doc). Each is
// constructed exactly once on the boot path (single-core, no task exists yet)
// and handed `ccid_task` as a `&'static mut` — the same write-once discipline
// as [`STORE`]. `MaybeUninit` keeps the `static mut` const-initializable
// without const constructors; the `init_static_slot` write is the one and
// only init.
pub static mut MANAGEMENT_APP: core::mem::MaybeUninit<ManagementApp> =
    core::mem::MaybeUninit::uninit();
// US-939: the FIDO app joins the other applets in static memory — the async
// `hid_task` spawn frame held it by value and the Embassy async-main frame
// reserved 95,232 B against the ~20.8 KiB main stack (the dark-boot stack
// overflow US-952 confirms on hardware). Same write-once discipline as
// [`MANAGEMENT_APP`]: constructed exactly once on the boot path (single-core,
// no task exists yet) and handed `hid_task` as the sole `&'static mut`.
pub static mut FIDO_APP: core::mem::MaybeUninit<FidoApp> = core::mem::MaybeUninit::uninit();

pub static mut OATH_APP: core::mem::MaybeUninit<OathApp> = core::mem::MaybeUninit::uninit();
pub static mut OTP_APP: core::mem::MaybeUninit<OtpApp> = core::mem::MaybeUninit::uninit();
// S-721-2: the OpenPGP app carries the trussed client by value (opcard
// owns its client) — the client is taken out of the backend static on the
// boot path (`trusted_backend::take_client`) and constructed into this
// slot, the same write-once discipline as the other apps.
pub static mut OPENPGP_APP: core::mem::MaybeUninit<
    OpenPgpApp<Client<'static, DevicePlatform, OpcardDispatch>>,
> = core::mem::MaybeUninit::uninit();
// US-160 (PICOForge-COMPAT): the RS-Key vendor LED applet. Static memory for
// the same reason as the four above — `CCID_DISPATCHER` lives in static memory
// and borrows every app for `'static`, so an app on the stack would not
// outlive it. The applet itself is tiny (a 17-byte block plus a dirty flag),
// so the slot costs nothing measurable against the boot path's RAM budget.
pub static mut VENDOR_LED_APP: core::mem::MaybeUninit<VendorLedApp> =
    core::mem::MaybeUninit::uninit();
// US-161/162/163 (PICOForge-COMPAT Phase H): the Rescue applet, static memory
// for the same reason as the five above — `CCID_DISPATCHER` lives in static
// memory and borrows every app for `'static`. This one is the smallest of the
// six (a `u64` chip id, a 20-byte flash word, two status bytes and two
// `Option<&'static mut dyn>` handles), so the slot costs nothing measurable.
pub static mut RESCUE_APP: core::mem::MaybeUninit<RescueApp> =
    core::mem::MaybeUninit::uninit();

// The CCID dispatcher holds the five apps by reference. Built + registered on
// the boot path and stored in its own write-once static slot so it never
// lives on the task frame either; `ccid_task` only borrows a `&'static mut`
// to it.
//
// US-160: `4 → 5`; US-161/162/163: `5 → 6`. This const generic,
// `register_ccid_apps`' `Dispatcher<'a, 6>` parameter and the six `register`
// calls move together — the dispatcher's registration capacity *is* this
// number, so a stale `5` would make the sixth `register` fail on a full `Vec`
// and the device would refuse to boot rather than half-wire.
pub static mut CCID_DISPATCHER: core::mem::MaybeUninit<Dispatcher<'static, 6>> =
    core::mem::MaybeUninit::uninit();

/// Construct `value` into a write-once `static mut` slot and hand back the
/// sole `&'static mut` to it (US-391 E6; the [`STORE`] pattern generalized to
/// non-const-initializable types).
///
/// SAFETY: single-core, boot path only — each slot is written exactly once
/// here, before any task exists, and the returned reference is the only
/// handle to the value for the rest of the boot (`ccid_task` owns it).
pub fn init_static_slot<T>(slot: *mut core::mem::MaybeUninit<T>, value: T) -> &'static mut T {
    unsafe {
        slot.write(core::mem::MaybeUninit::new(value));
        let initialized: &mut core::mem::MaybeUninit<T> = &mut *slot;
        initialized.assume_init_mut()
    }
}

/// US-939: [`init_static_slot`] with a constructor closure. The closure's
/// return value is written **straight into the slot** (its sret destination
/// IS the slot storage), so `T` never transits the caller's stack frame by
/// value — the plain `init_static_slot(slot, f())` form forces the whole
/// value to materialize in the caller's frame first (15.7 KiB for `FidoApp`,
/// 11.3 KiB for `OathApp`), which is how the Embassy async-main frame grew
/// to 95,232 B against a ~20.8 KiB main stack. Same SAFETY contract: the
/// slot is written exactly once, on the boot path, before any task exists.
pub fn init_static_slot_with<T>(
    slot: *mut core::mem::MaybeUninit<T>,
    value: impl FnOnce() -> T,
) -> &'static mut T {
    unsafe {
        core::ptr::write((*slot).as_mut_ptr(), value());
        let initialized: &mut core::mem::MaybeUninit<T> = &mut *slot;
        initialized.assume_init_mut()
    }
}

// Board LED (GPIO25, active-low on the Pico 2), owned by the 1 Hz heartbeat
// task once it spawns. Initialized on the boot path via the write-once slot
// discipline shared with the app statics.
pub static mut LED_OUT: core::mem::MaybeUninit<Output<'static>> =
    core::mem::MaybeUninit::uninit();
