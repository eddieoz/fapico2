//! The host key region (US-1541): a [`KeyRegion`] over a host file that
//! behaves like NOR.
//!
//! # Why a stand-in that lies is worse than no stand-in
//!
//! Everything the key store does on hardware rests on one physical property:
//! **a NOR program only clears bits.** Programming cannot set a bit back from
//! 0 to 1; the only way to restore erased state is a sector erase. That single
//! fact is what forces the commit discipline US-1544/1545 have to write — erase
//! the sector, then program the commit marker last.
//!
//! A host region implemented over a `Vec<u8>` with `copy_from_slice` would let
//! a record codec write bytes that could never be written on the part, and
//! every one of those tests would pass. So the model here is not "a file": it
//! is `0xFF` everywhere at open, `program` ANDs into what is already there and
//! **refuses** any byte that would need a 0 → 1 transition, and
//! `erase_sector` restores `0xFF` over a whole 4 KiB sector. The refusal is the
//! test: a stand-in that lets you set a bit back is a stand-in that will let
//! the record codec pass on a device where the write is impossible.
//!
//! `tests/persist_sink.rs` already models this the same way for the persist
//! gate — `*d &= b` with erased `0xFF` (`tests/persist_sink.rs:100`) — so the
//! two host flash models in this crate agree on the physics.
//!
//! # What the file is
//!
//! The file **is the region**: byte 0 is slot 0, and `KEY_REGION_OFFSET`
//! (`keyregion/mod.rs:291-292`, flashmap's `0x30_0000`) is deliberately absent.
//! A host region that carried the flash base would make every host test depend
//! on where the region sits on the part, so a board change would move a
//! constant that has nothing to do with the codec under test.
//!
//! # Capacity: a short file is a smaller region, and that is the point
//!
//! [`KeyRegion::slots`] is a method and not [`TOTAL_SLOTS`] precisely so that a
//! short file reports its own capacity (`keyregion/mod.rs:437-441`). The rule:
//!
//! * **shorter than the full region** → the region is that many slots. A test
//!   wants 8 slots and 8 KiB on disk, not 960 KiB, and a capacity that only ever
//!   equals the constant could not tell "the allocator used every slot" from
//!   "the allocator never looked".
//! * **longer than the region** → **refused**. A file with bytes past
//!   `KEY_REGION_BYTES` describes storage the firmware never addresses;
//!   silently ignoring the tail would let a region-overlap bug pass, which is
//!   precisely the class of bug `flashmap.rs`'s compile-time boundary asserts
//!   exist to catch.
//! * **not a whole number of slots, or of sectors** → **refused**. A partial
//!   slot is a record that cannot be erased without touching its neighbour, and
//!   the sector — not the slot — is the erase and commit unit
//!   (`keyregion/mod.rs:118-132`), so a region that does not tile whole
//!   sectors has no valid commit unit at all.
//!
//! # Host only
//!
//! Gated `all(feature = "host-backend", not(target_arch = "arm"))` — the exact
//! pair `trusted_backend/mod.rs` uses for its host platform. The gate is an
//! inner attribute because `keyregion/mod.rs` declares this module
//! unconditionally and that file is not this story's to change; an empty
//! module on arm costs nothing and cannot be linked by accident, where a
//! `std::fs::File` reachable from the device image could.

#![cfg(all(feature = "host-backend", not(target_arch = "arm")))]

use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::slotmap::SlotImage;
use super::{FIDO_SLOT_BYTES, KeyRegion, Slot, SLOTS_PER_SECTOR, TOTAL_SLOTS};
use crate::flashmap::{BLOCK_SIZE, KEY_REGION_BYTES};

/// The byte a NOR cell holds when erased.
pub const ERASED_BYTE: u8 = 0xFF;

/// The NOR program granularity: `program` takes whole pages of this size.
///
/// The same figure the rest of the tree programs in — `persist_sink.rs:41`
/// (`WINDOW = 256`) and the littlefs2 `WRITE_SIZE` at
/// `trusted_backend/host.rs:66` — and the figure
/// [`KeyRegion::program`]'s own contract states (`keyregion/mod.rs:436`).
pub const PAGE_BYTES: usize = 256;

/// `read_slot` failed at the transport. Indistinguishable, on purpose, from a
/// device bus error: the point of the three-state [`super::SlotRead`] is that a
/// caller cannot tell "empty" from "unreadable" by accident.
pub const E_IO: &str = "file key region: read/write failed at the transport";

/// The file ended before a whole slot could be read — the region was resized
/// under an open region, or the file was truncated.
pub const E_SHORT_READ: &str = "file key region: file ended inside the slot";

/// NOR refused a program: at least one byte needed a 0 → 1 transition.
///
/// This is the load-bearing refusal. A region that silently ignored it would
/// let a codec that rewrites bytes in place pass here and fail on the part.
pub const E_NOR_SET_BIT: &str =
    "file key region: NOR program refused — would set a bit from 0 to 1";

/// `program` was not given whole flash pages.
pub const E_PAGE_ALIGN: &str =
    "file key region: program must be a whole number of 256-byte pages, page-aligned";

/// `program` would run past the end of the slot.
pub const E_PAST_SLOT: &str = "file key region: program would run past the end of the slot";

/// The slot is not inside **this** region. A `Slot` can be valid for the
/// device's geometry and still be past the end of a short host file.
pub const E_SLOT_OUT_OF_REGION: &str = "file key region: slot is outside this region";

/// The sector holding the slot is not wholly inside the file.
pub const E_SECTOR_TRUNCATED: &str = "file key region: sector is not wholly inside the file";

/// How many flash operations the region has served — the instrument the erase
/// accounting in `tests/persist_sink.rs` models (`erase_count` /
/// `write_count` there), so the two host flash models report the same facts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// `read_slot` calls served.
    pub slot_reads: u32,
    /// `erase_sector` calls served — the wear figure, since NOR endurance is
    /// specified **per sector** and this counts sectors, not slots.
    pub sector_erases: u32,
    /// `program` calls served (pages within a call are not counted separately).
    pub programs: u32,
}

/// Forced transport failures, so `KeyRegion`'s error channel can be exercised
/// without corrupting a file on disk.
///
/// Same shape and the same justification as `FakeFlash::fail_reads` /
/// `fail_writes` (`tests/persist_sink.rs`): the behaviour under test is a
/// **refusal**, and a refusal you can only provoke by damaging the file cannot
/// be provoked at all in the one test that must not damage it (US-1573).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Faults {
    /// Every `read_slot` fails with [`E_IO`].
    pub reads: bool,
    /// Every `erase_sector` fails with [`E_IO`].
    pub erases: bool,
    /// Every `program` fails with [`E_IO`].
    pub programs: bool,
}

/// A [`KeyRegion`] over a host file, with NOR semantics.
///
/// See the module docs for the capacity rule and for why the file is
/// region-relative rather than flash-relative.
pub struct FileKeyRegion {
    file: std::fs::File,
    path: PathBuf,
    slots: u32,
    stats: Stats,
    faults: Faults,
}

impl FileKeyRegion {
    /// Create (truncating any existing file) a region of `slots` slots,
    /// pre-erased to `0xFF`.
    ///
    /// `slots` must be a non-zero multiple of [`SLOTS_PER_SECTOR`] and at most
    /// [`TOTAL_SLOTS`]. Pre-erasing is explicit rather than left to
    /// `set_len`, which zero-fills on Linux: a region whose virgin state is
    /// `0x00` would accept records a real part cannot hold.
    pub fn create(path: impl AsRef<Path>, slots: u32) -> Result<Self, Error> {
        if slots == 0 {
            return Err(invalid("a key region must hold at least one slot"));
        }
        if !slots.is_multiple_of(SLOTS_PER_SECTOR) {
            return Err(invalid(
                "a key region must hold whole NOR sectors — the sector is the erase and commit \
                 unit (keyregion/mod.rs:118-132), so a partial sector has no commit unit",
            ));
        }
        if slots > TOTAL_SLOTS {
            return Err(invalid(
                "a key region cannot hold more than TOTAL_SLOTS slots",
            ));
        }
        let bytes = slots as usize * FIDO_SLOT_BYTES as usize;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path.as_ref())?;
        file.set_len(0)?;
        erase_range(&mut file, 0, bytes)?;
        Ok(Self {
            file,
            path: path.as_ref().to_path_buf(),
            slots,
            stats: Stats::default(),
            faults: Faults::default(),
        })
    }

    /// Open an existing region file, deriving its capacity from its length.
    ///
    /// See the module docs for the rule; every rejection is
    /// [`ErrorKind::InvalidInput`] so a caller can tell a bad file from an I/O
    /// error without string matching.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let bytes = file.metadata()?.len();
        if bytes == 0 {
            return Err(invalid("the key region file is empty"));
        }
        if bytes > KEY_REGION_BYTES as u64 {
            return Err(invalid(
                "the key region file is larger than KEY_REGION_BYTES — it describes storage the \
                 firmware never addresses, and ignoring the tail would hide a region overlap",
            ));
        }
        if !bytes.is_multiple_of(FIDO_SLOT_BYTES as u64) {
            return Err(invalid(
                "the key region file is not a whole number of slots",
            ));
        }
        if !bytes.is_multiple_of(BLOCK_SIZE as u64) {
            return Err(invalid(
                "the key region file is not a whole number of NOR sectors",
            ));
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            slots: (bytes / FIDO_SLOT_BYTES as u64) as u32,
            stats: Stats::default(),
            faults: Faults::default(),
        })
    }

    /// The file this region is backed by.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Operation counts, for the wear and I/O assertions.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Force subsequent operations to fail at the transport.
    pub fn inject_faults(&mut self, faults: Faults) {
        self.faults = faults;
    }

    /// Forget the operation counters — so a test can measure one phase.
    pub fn reset_stats(&mut self) {
        self.stats = Stats::default();
    }
}

/// The byte offset of `slot` **within the region**, i.e. within this file.
///
/// [`Slot::offset`] (`keyregion/mod.rs:291-292`) is the flash-relative address
/// and adds `KEY_REGION_OFFSET`; the file is the region, so it never carries
/// that base.
const fn region_offset(slot: Slot) -> u64 {
    slot.index() as u64 * FIDO_SLOT_BYTES as u64
}

/// The index of the first slot in `slot`'s sector.
///
/// Alignment is arithmetic, not an assertion: `mod.rs:158-162` already asserts
/// at compile time that `BLOCK_SIZE % FIDO_SLOT_BYTES == 0`, so every slot lies
/// wholly inside one sector and this division is exact.
const fn sector_first_slot(slot: Slot) -> u32 {
    (slot.index() as u32 / SLOTS_PER_SECTOR) * SLOTS_PER_SECTOR
}

/// An `InvalidInput` error carrying a message, so `open`/`create` report a
/// layout violation as itself rather than as a generic I/O failure.
fn invalid(msg: &'static str) -> Error {
    Error::new(ErrorKind::InvalidInput, msg)
}

/// Fill `len` bytes at `at` with `0xFF` — the erase primitive.
fn erase_range(file: &mut std::fs::File, at: u64, len: usize) -> Result<(), Error> {
    file.seek(SeekFrom::Start(at))?;
    // A fixed buffer rather than `len` bytes of stack, so an erase costs the
    // same stack whatever the caller's region size is.
    let buf = [ERASED_BYTE; 512];
    let mut left = len;
    while left > 0 {
        let n = core::cmp::min(left, buf.len());
        file.write_all(&buf[..n])?;
        left -= n;
    }
    file.flush()
}

impl KeyRegion for FileKeyRegion {
    fn read_slot(&mut self, slot: Slot) -> Result<SlotImage, &'static str> {
        self.stats.slot_reads += 1;
        if self.faults.reads {
            return Err(E_IO);
        }
        if slot.index() as u32 >= self.slots {
            return Err(E_SLOT_OUT_OF_REGION);
        }
        self.file
            .seek(SeekFrom::Start(region_offset(slot)))
            .map_err(|_| E_IO)?;
        let mut buf = [ERASED_BYTE; FIDO_SLOT_BYTES as usize];
        // `read_exact`, not `read`: a short read is a truncated region, and
        // handing back the `0xFF` the buffer was initialised with would report
        // a fault as an erased slot — the exact memoization US-1573 exists to
        // prevent.
        self.file
            .read_exact(&mut buf)
            .map_err(|_| E_SHORT_READ)?;
        Ok(buf)
    }

    fn erase_sector(&mut self, slot: Slot) -> Result<(), &'static str> {
        self.stats.sector_erases += 1;
        if self.faults.erases {
            return Err(E_IO);
        }
        let first = sector_first_slot(slot);
        if first >= self.slots {
            return Err(E_SLOT_OUT_OF_REGION);
        }
        // Whole sectors only. `open`/`create` refuse a region that is not a
        // whole number of sectors, so a file-backed region never truncates one;
        // the check is kept because the trait accepts any `Slot` the *device*
        // geometry allows and this region may be shorter than that.
        if first + SLOTS_PER_SECTOR > self.slots {
            return Err(E_SECTOR_TRUNCATED);
        }
        let base = Slot::new(first as u16).expect("first < slots <= TOTAL_SLOTS");
        erase_range(&mut self.file, region_offset(base), BLOCK_SIZE).map_err(|_| E_IO)
    }

    fn program(&mut self, slot: Slot, offset: u32, data: &[u8]) -> Result<(), &'static str> {
        self.stats.programs += 1;
        if self.faults.programs {
            return Err(E_IO);
        }
        if slot.index() as u32 >= self.slots {
            return Err(E_SLOT_OUT_OF_REGION);
        }
        // Whole pages, page-aligned. Both halves matter: a QSPI page program
        // addresses a page boundary, so a caller that checked only `len` could
        // ask for a window that cannot exist on the part.
        if data.is_empty()
            || !data.len().is_multiple_of(PAGE_BYTES)
            || !(offset as usize).is_multiple_of(PAGE_BYTES)
        {
            return Err(E_PAGE_ALIGN);
        }
        let end = offset as usize + data.len();
        if end > FIDO_SLOT_BYTES as usize {
            return Err(E_PAST_SLOT);
        }

        let at = region_offset(slot) + offset as u64;
        self.file.seek(SeekFrom::Start(at)).map_err(|_| E_IO)?;
        // Sized to a whole slot, not a page: `program` accepts any whole-page
        // window within the slot, so reading "what is there now" has to be able
        // to hold the largest window the trait permits.
        let mut existing = [ERASED_BYTE; FIDO_SLOT_BYTES as usize];
        self.file
            .read_exact(&mut existing[..data.len()])
            .map_err(|_| E_SHORT_READ)?;

        // The NOR rule, checked over the **whole** window before a single byte
        // is applied: a real part programs a page atomically and refuses the
        // operation, so a partial application here would leave this stand-in
        // holding bytes the part could never hold.
        if data
            .iter()
            .zip(existing.iter())
            .any(|(d, cur)| d & !cur != 0)
        {
            return Err(E_NOR_SET_BIT);
        }

        self.file.seek(SeekFrom::Start(at)).map_err(|_| E_IO)?;
        self.file.write_all(data).map_err(|_| E_IO)?;
        self.file.flush().map_err(|_| E_IO)
    }

    fn slots(&self) -> u32 {
        self.slots
    }
}