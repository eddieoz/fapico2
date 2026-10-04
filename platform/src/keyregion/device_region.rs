//! The device key region (US-1541): a [`KeyRegion`](super::KeyRegion) over the
//! RP2350 QSPI window that [`flashmap::KEY_REGION_OFFSET`] names.
//!
//! # Why this file exists at all, given `host.rs`
//!
//! [`FileKeyRegion`](crate::keyregion::host::FileKeyRegion) is the only other
//! implementation, and it is gated
//! `all(feature = "host-backend", not(target_arch = "arm"))`. So on hardware
//! there was **none**: `fido_store.rs` and `oath_store.rs` are written,
//! `FIDO_CAPACITY` is 856, and the fifth passkey is still refused with
//! `KeyStoreFull` because nothing can reach the region those adapters address.
//! This is the device half.
//!
//! # Why the NOR rules are a separate, host-buildable core
//!
//! The load-bearing property of this medium is that **a program only clears
//! bits**; `program` cannot set a bit back from 0 to 1, and the only way to
//! restore erased state is a sector erase. Every ordering discipline in
//! `commit.rs` exists because of it, and the QSPI driver enforces **none** of
//! it: `embassy-rp`'s `Flash::blocking_write`
//! (`embassy-rp-0.10.0/src/flash.rs:169`) bounds-checks the window and then
//! programs it. A byte that needs a 0 → 1 transition is either silently
//! dropped by the part or corrupts a neighbour, and neither is an `Err` a store
//! could report.
//!
//! So the check has to be here, in the region, where it can become one. The
//! rules themselves — page alignment, the slot bound, the sector span, the bit
//! test — are **pure functions over byte images** with no flash in them, so they
//! live in [`nor`] and compile on the host. `platform/tests/
//! key_region_device_nor.rs` then drives [`nor`] against [`FileKeyRegion`]
//! (`keyregion/host.rs:373-379`) and requires the two to accept and refuse
//! **the same** windows. The host model is what the whole codec test suite is
//! calibrated against, so if this device's copy of the rules drifted, every host
//! test would stay green while the part refused the write.
//!
//! # Why a third `Flash` handle rather than a shared one
//!
//! The QSPI peripheral is already spoken for twice: `boot::FLASH_DEV` (the
//! secure-partition image) and the trussed backend's handle
//! (`firmware/src/main.rs:793-804`). `Flash` is neither `Copy` nor `Clone`, and
//! the trussed backend takes its handle **by value** into `IFS_STORAGE`, so
//! there is no borrow to share.
//!
//! A third handle is nevertheless the answer, and it is the one this tree
//! already uses: `Flash::new_blocking` stores `Option<Channel> = None` plus a
//! `PhantomData` and **touches no QSPI register**
//! (`embassy-rp-0.10.0/src/flash.rs:255-260`), so a second and third
//! construction over a `Peri` duplicated with `clone_unchecked` are independent
//! values addressing disjoint windows. The alternative — minting a second
//! `&mut` to the *same* `Flash` object — is what US-1005 rejects in terms
//! (`firmware/src/boot.rs`, the `DRBG_SEED_PROBE` doc): "two `&mut` to one
//! object is UB whether or not the argument holds". Distinct objects, disjoint
//! regions.
//!
//! `KEY_REGION_OFFSET .. KEY_REGION_OFFSET + KEY_REGION_BYTES` is disjoint from
//! both other windows by construction, not by comment: `flashmap.rs:145-160`
//! asserts the trussed window ends where this one begins and this one ends
//! where the secure partition begins.
//!
//! # Nothing here reads the region
//!
//! Constructing a [`DeviceKeyRegion`] is `Self { flash }`. There is no scan, no
//! discovery pass and no mount, at construction or anywhere else in this file —
//! the first flash access is inside `KeyRegion::read_slot`, and the boot path
//! makes no call at all (S8/S9). `firmware/src/boot.rs` additionally gates the
//! handle behind an explicit release **after** `RUNG_USB`, so a pre-USB caller
//! gets `None` rather than a handle it should not have. That gate is runtime,
//! not merely a source-order convention, which is why
//! `platform/tests/key_region_boot_gate.rs` can still be green if somebody moves
//! a call site.
//!
//! # Degrade, never halt (S10)
//!
//! Every method returns `Result`; there is no `unwrap`, no `expect` and no
//! panic in this file. An unreachable flash address, a misaligned window and a
//! refused program are all `Err` values the caller turns into an empty key set
//! and a clean CTAP error — never a `fatal_boot` and never a brick.
//!
//! # Gate
//!
//! [`nor`] is ungated: it is pure, and the host differential test needs it.
//! [`DeviceKeyRegion`] is `all(feature = "device", target_arch = "arm")`, the
//! same pair `trusted_backend/mod.rs:95` uses for its device platform, because
//! `embassy-rp` is an arm-only dependency of this crate (`platform/Cargo.toml`,
//! the `[target.'cfg(target_arch = "arm")']` scope). An empty module on the host
//! costs nothing and cannot be linked by accident, where a QSPI driver reachable
//! from a host test could.

/// The NOR rules, as pure functions over byte images.
///
/// Nothing in here touches flash, so it is host-testable, and it is the copy
/// the differential test pins against [`FileKeyRegion`](crate::keyregion::host::FileKeyRegion).
///
/// # The check order is load-bearing, and it mirrors `FileKeyRegion`
///
/// [`check_program_geometry`] then [`check_bits`], in that order, and the
/// geometry check's own order is **in-region, then page-aligned, then
/// past-slot** — exactly `keyregion/host.rs:342-356`. The reason is that the
/// geometry check also answers *how many bytes the caller must read back*:
/// only once the window is known to be whole pages inside the slot can
/// `data.len()` be used as a read length. Reordering these would not be a
/// refactor; it would make the device refuse (or accept) windows the host model
/// treats differently, which is the entire thing [`nor`] exists to prevent.
pub mod nor {
    use super::super::{Slot, FIDO_SLOT_BYTES, SLOTS_PER_SECTOR, TOTAL_SLOTS};
    use crate::flashmap::BLOCK_SIZE;

    /// The byte a NOR cell holds when erased.
    ///
    /// The same figure [`FileKeyRegion`](crate::keyregion::host::FileKeyRegion) uses
    /// (`keyregion/host.rs:73`) — stated here rather than imported because
    /// `host.rs` is gated off the device, so the device cannot borrow it.
    pub const ERASED_BYTE: u8 = 0xFF;

    /// The NOR program granularity: a program takes whole pages of this size.
    ///
    /// `embassy-rp`'s own `PAGE_SIZE` (`embassy-rp-0.10.0/src/flash.rs:33`) and
    /// `keyregion/host.rs:81`'s `PAGE_BYTES` are the same 256 B. The two
    /// host/device flash models agreeing on the figure is what lets the
    /// differential test compare them at all.
    pub const PAGE_BYTES: usize = 256;

    /// How many slots a device region holds — always the whole window.
    ///
    /// The device region is the whole `[KEY_REGION_OFFSET, …+KEY_REGION_BYTES)`
    /// or nothing: `flashmap.rs:152-160` already asserts that window's exact
    /// extent, and a region shorter than the one the flash map describes would
    /// be a second, disagreeing description of the same storage.
    pub const REGION_SLOTS: u32 = TOTAL_SLOTS;

    /// Why a program window was refused.
    ///
    /// A type rather than a bare `&'static str` so the differential test can
    /// compare *which* rule fired instead of string-matching two messages
    /// written for two different transports.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum ProgramRefusal {
        /// The slot is not inside this region. A `Slot` can be valid for the
        /// device's geometry and still be past the end of a short region.
        SlotOutOfRegion,
        /// The window is not a whole number of page-aligned 256-byte pages.
        ///
        /// Both halves matter: a QSPI page program addresses a page boundary, so
        /// a caller that checked only the length could ask for a window that
        /// cannot exist on the part.
        PageAlign,
        /// The window would run past the end of the slot.
        PastSlot,
        /// **The load-bearing one.** At least one byte needed a 0 → 1
        /// transition, which NOR cannot do.
        SetBit,
    }

    impl ProgramRefusal {
        /// The `&'static str` `KeyRegion::program` reports.
        ///
        /// Distinct per variant on purpose. The caller turns this into a CTAP
        /// error and a `defmt` line, and "the window needed a 0 → 1 bit" is an
        /// actionable codec bug while "the window was misaligned" is not the
        /// same bug at all.
        pub const fn reason(self) -> &'static str {
            match self {
                ProgramRefusal::SlotOutOfRegion => {
                    "device key region: slot is outside this region"
                }
                ProgramRefusal::PageAlign => {
                    "device key region: program must be a whole number of 256-byte pages, \
                     page-aligned"
                }
                ProgramRefusal::PastSlot => {
                    "device key region: program would run past the end of the slot"
                }
                ProgramRefusal::SetBit => {
                    "device key region: NOR program refused — would set a bit from 0 to 1"
                }
            }
        }
    }

    /// Why a sector erase was refused.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum EraseRefusal {
        /// The slot's sector does not start inside this region.
        SlotOutOfRegion,
        /// The region ends inside the sector, so erasing it would destroy a
        /// record that has no slot of its own to be restored into.
        SectorTruncated,
    }

    impl EraseRefusal {
        /// The `&'static str` `KeyRegion::erase_sector` reports.
        pub const fn reason(self) -> &'static str {
            match self {
                EraseRefusal::SlotOutOfRegion => "device key region: slot is outside this region",
                EraseRefusal::SectorTruncated => {
                    "device key region: sector is not wholly inside the region"
                }
            }
        }
    }

    /// The index of the first slot in `slot`'s sector.
    ///
    /// Alignment is arithmetic, not an assertion: `mod.rs:303-307` already
    /// asserts at compile time that `BLOCK_SIZE == SLOTS_PER_SECTOR *
    /// FIDO_SLOT_BYTES`, so every slot lies wholly inside one sector and this
    /// division is exact. `keyregion/host.rs:269-271` is the same function.
    pub const fn sector_first_slot(slot: Slot) -> u32 {
        (slot.index() as u32 / SLOTS_PER_SECTOR) * SLOTS_PER_SECTOR
    }

    /// The flash-relative byte range `[from, to)` a sector erase covers.
    ///
    /// A **range**, not a slot: RP2350 QSPI erases whole 4 KiB sectors
    /// (`flashmap.rs:65`, and `embassy-rp`'s `ERASE_SIZE = 4096`), and
    /// [`SLOTS_PER_SECTOR`] slots share one (`mod.rs:132`). That is why the
    /// commit unit is a sector and not a slot, and why the addresses are given
    /// in flash space — `Slot::offset()` (`mod.rs:419-421`) adds
    /// `KEY_REGION_OFFSET`, and the erase has to land there.
    pub const fn erase_span(slot: Slot, slots: u32) -> Result<(u32, u32), EraseRefusal> {
        let first = sector_first_slot(slot);
        if first >= slots {
            return Err(EraseRefusal::SlotOutOfRegion);
        }
        if first + SLOTS_PER_SECTOR > slots {
            return Err(EraseRefusal::SectorTruncated);
        }
        // `first < slots <= TOTAL_SLOTS`, so the conversion cannot fail; the
        // `match` rather than `unwrap` keeps this a `const fn`.
        let base = match Slot::new(first as u16) {
            Some(s) => s,
            None => return Err(EraseRefusal::SlotOutOfRegion),
        };
        Ok((base.offset(), base.offset() + BLOCK_SIZE as u32))
    }

    /// Everything about a program window that can be decided without reading the
    /// flash: is it in this region, is it whole aligned pages, does it fit in
    /// the slot.
    ///
    /// Check order is [`FileKeyRegion`](crate::keyregion::host::FileKeyRegion)'s, and the
    /// module docs explain why that is not free.
    pub fn check_program_geometry(
        slot: Slot,
        slots: u32,
        offset: u32,
        data: &[u8],
    ) -> Result<(), ProgramRefusal> {
        if slot.index() as u32 >= slots {
            return Err(ProgramRefusal::SlotOutOfRegion);
        }
        if data.is_empty()
            || !data.len().is_multiple_of(PAGE_BYTES)
            || !(offset as usize).is_multiple_of(PAGE_BYTES)
        {
            return Err(ProgramRefusal::PageAlign);
        }
        let end = offset as usize + data.len();
        if end > FIDO_SLOT_BYTES as usize {
            return Err(ProgramRefusal::PastSlot);
        }
        Ok(())
    }

    /// The NOR rule itself, over the window that is already there.
    ///
    /// Checked over the **whole** window before a single byte is applied: a real
    /// part programs a page atomically and refuses the operation, so a partial
    /// application would leave the device holding bytes the part could never
    /// hold — the state `keyregion/host.rs:369-379` refuses to let its stand-in
    /// reach too.
    ///
    /// `existing` may be longer than `data`; only `data.len()` bytes are
    /// examined, which is the read-back the geometry check sized.
    pub fn check_bits(existing: &[u8], data: &[u8]) -> Result<(), ProgramRefusal> {
        if data.len() > existing.len() {
            return Err(ProgramRefusal::PastSlot);
        }
        if data
            .iter()
            .zip(existing.iter())
            .any(|(d, cur)| d & !cur != 0)
        {
            return Err(ProgramRefusal::SetBit);
        }
        Ok(())
    }

    /// The apply step: `dst[i] &= data[i]`, after the rule has said yes.
    ///
    /// The AND *is* the physics. `*d &= *s` with erased `0xFF` is the same
    /// expression `tests/persist_sink.rs:100` models for the persist gate, so
    /// all three flash models in this crate describe one medium.
    pub fn apply_program(dst: &mut [u8], data: &[u8]) -> Result<(), ProgramRefusal> {
        check_bits(dst, data)?;
        for (d, s) in dst.iter_mut().zip(data.iter()) {
            *d &= *s;
        }
        Ok(())
    }
}

/// The QSPI-backed region (arm only).
///
/// See the module docs for why it is a third handle, why the NOR rules live in
/// [`nor`], and why nothing here runs before `RUNG_USB`.
#[cfg(all(feature = "device", target_arch = "arm"))]
mod qspi {
    use crate::flashmap::{BLOCK_SIZE, KEY_REGION_BYTES, KEY_REGION_OFFSET};
    use crate::trusted_backend::device::DevFlash;

    use super::nor::{self, ERASED_BYTE, PAGE_BYTES};
    use super::super::slotmap::SlotImage;
    use super::super::{FIDO_SLOT_BYTES, KeyRegion, Slot};

    /// The QSPI operation itself failed.
    ///
    /// Deliberately **not** collapsed into the NOR refusals: a bus error is a
    /// fact about the transport, not about the data, and US-1573's whole point
    /// is that the two must not be memoized as the same thing.
    pub const E_IO: &str = "device key region: QSPI flash operation failed";

    /// Geometry facts about this board's key window that the driver relies on.
    ///
    /// `blocking_erase` funnels into `embedded_storage`'s `check_erase`, which
    /// refuses a range that is not aligned to `ERASE_SIZE` (4096) — so a region
    /// starting off a 4 KiB boundary would make **every** erase in it fail.
    ///
    /// And `blocking_write` pads its window to `PAGE_SIZE`, but
    /// `ram_helpers::flash_range_write` underneath it wants a page-aligned
    /// start; the FIDO stride is a power of two at or above one page
    /// (`mod.rs:284-288`), so a `PAGE_BYTES`-aligned region base aligns every
    /// slot and every program window in it.
    ///
    /// Stated as a bitmask rather than `% BLOCK_SIZE == 0` for the reason
    /// `mod.rs:280-288` gives: CI runs clippy with `-D warnings` and
    /// `manual_is_multiple_of` rejects the `%` form.
    const _: () = {
        assert!(
            KEY_REGION_OFFSET & (BLOCK_SIZE as u32 - 1) == 0,
            "the key region must start on a 4 KiB NOR sector boundary: `blocking_erase` refuses \
             a misaligned range, so every sector erase in the region would fail"
        );
        assert!(
            KEY_REGION_OFFSET & (PAGE_BYTES as u32 - 1) == 0,
            "the key region must start on a flash page boundary: every slot address is the \
             region base plus a multiple of the stride, and a misaligned base makes every \
             program window misaligned"
        );
        assert!(
            KEY_REGION_OFFSET + KEY_REGION_BYTES <= crate::board::FLASH_SIZE_BYTES as u32,
            "the key region must lie inside the part: `blocking_read`/`blocking_write` bounds-check \
             against FLASH_SIZE, so a window past the end is OutOfBounds rather than a record"
        );
    };

    /// A [`KeyRegion`] over the RP2350 QSPI flash window the key store lives in.
    ///
    /// # What it is *not*
    ///
    /// Not a filesystem, not a mount, and not a discovery pass. It is a flat
    /// grid of fixed-size slots over `[KEY_REGION_OFFSET, KEY_REGION_OFFSET +
    /// KEY_REGION_BYTES)`, and construction ([`Self::new`]) touches no QSPI
    /// register — see the module docs. The first read is whichever applet
    /// operation runs first, after `RUNG_USB`.
    ///
    /// # The two halves of `program`
    ///
    /// Read-back, then check, then write. The read-back costs one window of QSPI
    /// traffic per program and buys the only thing that makes this medium safe
    /// to hand to a codec: a program that cannot be performed is an `Err`
    /// **before** the write, so `commit.rs` can roll back instead of discovering
    /// afterwards that a record is half-written.
    pub struct DeviceKeyRegion {
        /// The third QSPI handle. Never aliased with `FLASH_DEV` or the trussed
        /// backend's — see the module docs and `firmware/src/main.rs`, where it
        /// is constructed with `Peri::clone_unchecked`.
        flash: DevFlash,
    }

    impl DeviceKeyRegion {
        /// Wrap a flash handle.
        ///
        /// **Nothing is read here.** No discovery scan, no sector probe, no
        /// index read: S8/S9 forbid the boot path from touching the key region,
        /// and a constructor is exactly the sort of thing a boot path calls. The
        /// field assignment below is the whole body, which is the property the
        /// construction site is allowed to rely on.
        pub fn new(flash: DevFlash) -> Self {
            Self { flash }
        }
    }

    impl KeyRegion for DeviceKeyRegion {
        /// Read one slot's raw bytes.
        ///
        /// **Every** byte failure is `E_IO`, never a partially-filled buffer:
        /// handing back the `0xFF` the buffer was initialised with would report
        /// a bus error as an erased slot, which is the exact memoization
        /// US-1573 exists to prevent (`keyregion/host.rs:309-313` makes the
        /// same refusal for the same reason).
        fn read_slot(&mut self, slot: Slot) -> Result<SlotImage, &'static str> {
            let mut buf = [ERASED_BYTE; FIDO_SLOT_BYTES as usize];
            self.flash
                .blocking_read(slot.offset(), &mut buf)
                .map_err(|_| E_IO)?;
            Ok(buf)
        }

        /// Erase the whole 4 KiB sector holding `slot`.
        ///
        /// [`SLOTS_PER_SECTOR`](super::super::SLOTS_PER_SECTOR) slots go with it. That
        /// is not a defect of this implementation — it is what NOR does — and it
        /// is why `commit.rs` re-programs the sector-mates.
        fn erase_sector(&mut self, slot: Slot) -> Result<(), &'static str> {
            let (from, to) = nor::erase_span(slot, self.slots()).map_err(|e| e.reason())?;
            self.flash.blocking_erase(from, to).map_err(|_| E_IO)
        }

        /// Program a page-aligned window at `offset` within `slot`.
        ///
        /// Geometry, then the NOR rule over what is actually there, then the
        /// write. A refusal leaves the medium untouched.
        fn program(&mut self, slot: Slot, offset: u32, data: &[u8]) -> Result<(), &'static str> {
            nor::check_program_geometry(slot, self.slots(), offset, data)
                .map_err(|e| e.reason())?;

            let at = slot.offset() + offset;
            // Sized to a whole slot, not a page: the trait accepts any whole-page
            // window inside the slot, so "what is there now" has to hold the
            // largest window the trait permits. `check_program_geometry` has
            // already proved `data.len() <= FIDO_SLOT_BYTES`, so this slice
            // cannot panic.
            let mut existing = [ERASED_BYTE; FIDO_SLOT_BYTES as usize];
            self.flash
                .blocking_read(at, &mut existing[..data.len()])
                .map_err(|_| E_IO)?;

            // The refusal that makes this medium safe to hand to a codec. The
            // part would not report it; `nor` does.
            nor::check_bits(&existing[..data.len()], data).map_err(|e| e.reason())?;

            self.flash.blocking_write(at, data).map_err(|_| E_IO)
        }

        fn slots(&self) -> u32 {
            nor::REGION_SLOTS
        }
    }
}

#[cfg(all(feature = "device", target_arch = "arm"))]
pub use qspi::{DeviceKeyRegion, E_IO};

/// A geometry fact that holds on the host too, so a board change that breaks
/// the device region's arithmetic fails `cargo test -p fapico2-platform` rather
/// than only the arm build.
const _: () = {
    use super::FIDO_SLOT_BYTES as SLOT_BYTES;
    assert!(
        crate::flashmap::KEY_REGION_BYTES == nor::REGION_SLOTS * SLOT_BYTES,
        "the device region addresses exactly whole slots; a partial last slot would be a record \
         that cannot be erased without touching its neighbour"
    );
};