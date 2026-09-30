//! Read-only walker of the C firmware flash file system (US-413 S-413-3).
//!
//! The C firmware stores files as a **backward linked list of records**
//! growing downward from a head pointer at `end_data_pool`
//! (`pico-keys-sdk/src/fs/flash.c:42-49,60-68`, `file.c:327-364`):
//!
//! ```text
//! | next_addr | prev_addr | fid u16 LE | len16 u16 LE | payload        | legacy
//! | next_addr | prev_addr | fid u16 LE | FFFF | len32 u32 LE | payload | extended
//! ```
//!
//! `next` points at the older record (0 terminates); all fields are native
//! little-endian (`low_flash.c:433-441`, superseding the epic's BE claim —
//! see `us413-migration-feasibility.md` correction 3). The head pointer
//! (`uintptr_t`, LE) lives at `end_data_pool`; the factory-fresh sentinels
//! (`0xFFFFFFFF`/`0xEFEFEFEF`, two words) live at `end_rom_pool`
//! (`file.c:365-380`). Pool geometry mirrors `flash_set_bounds`
//! (`flash.c:60-68`).
//!
//! The walker is strictly **read-only** and **streaming**: payloads are
//! copied through bounded caller buffers for whitelisted FIDs only; the
//! C partition is never written.

use heapless::Vec as HVec;

/// Maximum records collected by one scan (heapless, no heap).
pub const MAX_RECORDS: usize = 256;
/// Cap for the single-shot whitelisted payload reader. Larger records must
/// be streamed via [`Cfs::read_at`] chunks.
pub const MAX_WHOLE_PAYLOAD: usize = 16 * 1024;

/// C file-state classification (see module docs; `file.c:365-380`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CState {
    /// Rom-pool head words still carry the factory sentinels
    /// (`0xFFFFFFFF`/`0xEFEFEFEF`): the C firmware never initialized its
    /// persistent region. Functionally "nothing to migrate".
    FactoryFresh,
    /// Initialized but zero records (hard-init head = 0, `file.c:310-315`).
    Empty,
    /// Records present.
    Used,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfsError {
    /// Chain pointers leave the data pool or loop past [`MAX_RECORDS`].
    Corrupt,
    /// More than [`MAX_RECORDS`] records in the chain.
    TooManyRecords,
    /// Record extends beyond the data pool.
    RecordOverflow,
    /// FID not on the migration whitelist.
    NotWhitelisted,
    /// Payload too large for a single-buffer read (stream it instead).
    PayloadTooLarge,
    /// Offset/bounds problem on a streaming read.
    BadRange,
}

/// One C file record: FID, payload length, and the absolute XIP address of
/// the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordDesc {
    pub fid: u16,
    pub len: u32,
    pub payload_addr: u32,
}

/// Abstraction over the flash backing store so the walker is host-testable:
/// read `buf.len()` bytes at absolute XIP `addr`.
pub trait CFlashSource {
    fn read(&self, addr: u32, buf: &mut [u8]);
}

/// Data-pool geometry derived from the resolved partition
/// (`flash.c:60-68`): the partition `end` already excludes the 8 KB tail
/// reservation; below it sit the 12-byte rom-pool header, the 16 KiB
/// persistent region, and an 8-byte hard-init header above the data pool.
#[derive(Debug, Clone, Copy)]
pub struct PoolBounds {
    pub data_start: u32,
    /// One past the last byte the head-pointer chain may occupy.
    pub data_end: u32,
    /// Rom-pool head words live here and at `+4` (sentinel check).
    pub end_rom_pool: u32,
}

impl PoolBounds {
    pub fn from_partition(part: crate::cflash::DataPartition) -> Self {
        let end_flash = part.end; // C `end_flash` (8 KB already reserved)
        let end_rom_pool = end_flash - 12;
        let start_rom_pool = end_rom_pool - 16 * 1024;
        let end_data_pool = start_rom_pool - 8;
        PoolBounds {
            data_start: part.start,
            data_end: end_data_pool,
            end_rom_pool,
        }
    }
}

/// Walker over one C data partition. Read-only; `S` abstracts the flash
/// backing store (host test fixture or device XIP deref).
pub struct Cfs<'a, S: CFlashSource + ?Sized> {
    src: &'a S,
    bounds: PoolBounds,
}

impl<'a, S: CFlashSource + ?Sized> Cfs<'a, S> {
    pub fn new(src: &'a S, bounds: PoolBounds) -> Self {
        Cfs { src, bounds }
    }

    fn read_u16_le(&self, addr: u32) -> u32 {
        let mut b = [0u8; 2];
        self.src.read(addr, &mut b);
        u16::from_le_bytes(b) as u32
    }

    fn read_u32_le(&self, addr: u32) -> u32 {
        let mut b = [0u8; 4];
        self.src.read(addr, &mut b);
        u32::from_le_bytes(b)
    }

    /// Classify the partition state without walking records.
    pub fn state(&self) -> CState {
        let r1 = self.read_u32_le(self.bounds.end_rom_pool);
        let r2 = self.read_u32_le(self.bounds.end_rom_pool + 4);
        // C `file.c:365-380`: either word still erased/sentinel-valued means
        // the persistent region was never initialized (or is corrupted) —
        // the "first initialization" case.
        if (r1 == 0xFFFF_FFFF || r1 == 0xEFEF_EFEF) && (r2 == 0xFFFF_FFFF || r2 == 0xEFEF_EFEF) {
            return CState::FactoryFresh;
        }
        let head = self.read_u32_le(self.bounds.data_end);
        // Hard-init zeroes the head (`file.c:310-315`); an erased head with
        // initialized sentinels is also file-less.
        if head == 0 || head == 0xFFFF_FFFF {
            return CState::Empty;
        }
        CState::Used
    }

    /// Walk the record chain (newest first) into `out`, validating that
    /// every record stays inside the data pool.
    pub fn scan(
        &self,
        out: &mut HVec<RecordDesc, MAX_RECORDS>,
    ) -> Result<CState, CfsError> {
        match self.state() {
            CState::FactoryFresh => return Ok(CState::FactoryFresh),
            CState::Empty => return Ok(CState::Empty),
            CState::Used => {}
        }
        let mut base = self.read_u32_le(self.bounds.data_end);
        loop {
            // Chain guards: 0 terminates; anything outside the pool or the
            // record-count cap is corruption (the C loop trusts flash).
            if base == 0 {
                break;
            }
            if base < self.bounds.data_start || base + 12 > self.bounds.data_end {
                return Err(CfsError::Corrupt);
            }
            if out.len() >= MAX_RECORDS {
                return Err(CfsError::TooManyRecords);
            }
            let fid = self.read_u16_le(base + 8) as u16;
            let stored = self.read_u16_le(base + 10) as u16;
            let (len, payload_addr) = if stored == 0xFFFF {
                let len = self.read_u32_le(base + 12);
                (len, base + 16)
            } else {
                (stored as u32, base + 12)
            };
            // Record must fit inside the data pool.
            if payload_addr.checked_add(len).is_none_or(|end| end > self.bounds.data_end) {
                return Err(CfsError::RecordOverflow);
            }
            out.push(RecordDesc {
                fid,
                len,
                payload_addr,
            })
            .map_err(|_| CfsError::TooManyRecords)?;
            base = self.read_u32_le(base);
        }
        Ok(CState::Used)
    }

    /// Stream `buf.len()` payload bytes of `rec` starting at payload
    /// `offset`; returns the number of bytes actually read (clamped to the
    /// record length). Read-only: bytes flow from flash into `buf` only.
    pub fn read_at(&self, rec: &RecordDesc, offset: u32, buf: &mut [u8]) -> u32 {
        if offset >= rec.len {
            return 0;
        }
        let n = buf.len().min((rec.len - offset) as usize);
        self.src
            .read(rec.payload_addr + offset, &mut buf[..n]);
        n as u32
    }

    /// Single-buffer read of a **whitelisted** record payload; rejects
    /// payloads above [`MAX_WHOLE_PAYLOAD`] (stream via [`Cfs::read_at`]).
    pub fn read_whitelisted(
        &self,
        rec: &RecordDesc,
        buf: &mut [u8],
    ) -> Result<u32, CfsError> {
        if !is_migratable_fid(rec.fid) {
            return Err(CfsError::NotWhitelisted);
        }
        if rec.len as usize > MAX_WHOLE_PAYLOAD {
            return Err(CfsError::PayloadTooLarge);
        }
        if (buf.len() as u32) < rec.len {
            return Err(CfsError::BadRange);
        }
        Ok(self.read_at(rec, 0, &mut buf[..rec.len as usize]))
    }
}

/// Device flash source: the C data partition is memory-mapped through XIP,
/// so a plain pointer dereference reads it (no driver init needed, exactly
/// like the C firmware's `flash_read`).
#[cfg(all(feature = "device", target_arch = "arm"))]
pub struct XipFlash;

#[cfg(all(feature = "device", target_arch = "arm"))]
impl CFlashSource for XipFlash {
    fn read(&self, addr: u32, buf: &mut [u8]) {
        // SAFETY: `addr` is validated against the resolved data partition
        // by the walker before any read is issued; XIP maps the whole 4 MiB
        // window at 0x10000000.
        unsafe {
            core::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), buf.len());
        }
    }
}

/// Stored OpenPGP identity records from the local merged C producer.
///
/// Physical roles come from authenticated PKOC descriptors, not prefixes:
/// EB is both the slot-0 public and slot-1 private prefix. Preserve both
/// generations, restricting physical containers to OpenPGP key IDs D1..D3.
pub fn is_openpgp_migration_fid(fid: u16) -> bool {
    matches!(fid,
        0x1081..=0x1083 | 0x1099..=0x109c |
        0x10c1..=0x10c5 | 0x10d1..=0x10d6 |
        0x004f | 0x005b | 0x005e | 0x0093 | 0x0101..=0x0104 |
        0x00c1..=0x00c3 |
        0x00c7..=0x00cc | 0x00ce..=0x00d0 | 0x00d6..=0x00d8 |
        0x5f2d | 0x5f35 | 0x5f50
    ) || ((0xe8..=0xed).contains(&(fid >> 8)) && (0xd1..=0xd3).contains(&(fid & 0xff)))
}

/// Migration whitelist (`us413-migration-feasibility.md` section 5):
/// per-class C file IDs eligible for re-seed. Payload access outside this
/// set is refused.
pub fn is_migratable_fid(fid: u16) -> bool {
    if is_openpgp_migration_fid(fid) {
        return true;
    }
    match fid {
        // FIDO: keydev (+ vendor-wrapped), vault, counter/opts, creds, RPs,
        // large blob.
        0xCC00 | 0xCC01 | 0xCE00 | 0xCE01 | 0xCE03 | 0xCE04 | 0xC000 | 0xC001 | 0x1101 => true,
        0xCF00..=0xD0FF => true, // creds + RPs (contiguous)
        // OATH creds + code.
        0xBA00..=0xBAFF => true,
        // OTP slots + OTP PIN.
        0xBB00..=0xBB03 | 0x10A0 => true,
        // Management EF_DEV_CONF.
        0x1122 => true,
        // OpenPGP PIN hashes (PW1/RC/PW3 + PIV PIN/PUK), admin data.
        0x1080 | 0x1081 | 0x1082 | 0x1083 | 0x1184 | 0x1185 | 0xFF00 => true,
        // OpenPGP public keys, binding signatures, DEK wrappers (legacy +
        // per-PW), DO blobs.
        0x10D1..=0x10D6 | 0x1099 | 0x109A..=0x109D => true,
        0x00E8..=0x00ED => true,
        // PIV certificates / retired key material (re-seed only; serving is
        // post-cutover).
        0xC101..=0xC1FF | 0x0082..=0x0087 => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const FLASH_XIP_BASE: u32 = crate::cflash::FLASH_XIP_BASE;
    const PART_START: u32 = FLASH_XIP_BASE + 0x102_000;
    const PART_END: u32 = FLASH_XIP_BASE + 0x102_000 + 3064 * 1024;

    struct MemFlash {
        img: Vec<u8>,
        base: u32,
    }

    impl MemFlash {
        /// One image spanning the whole synthetic partition (factory-erased).
        fn new() -> Self {
            MemFlash {
                img: vec![0xFFu8; (PART_END - PART_START) as usize],
                base: PART_START,
            }
        }

        fn bounds(&self) -> PoolBounds {
            PoolBounds::from_partition(crate::cflash::DataPartition {
                start: PART_START,
                end: PART_END,
            })
        }

        fn off(&self, addr: u32) -> usize {
            (addr - self.base) as usize
        }

        fn write(&mut self, addr: u32, bytes: &[u8]) {
            let o = self.off(addr);
            self.img[o..o + bytes.len()].copy_from_slice(bytes);
        }

        /// Append a record at the current downward cursor; returns its
        /// address. Payload = `data` repeated.
        fn push_record(&mut self, cursor: &mut u32, fid: u16, data: &[u8]) -> u32 {
            let ext = data.len() >= 0xFFFF;
            let hdr = 12 + if ext { 6 } else { 2 };
            *cursor -= hdr + data.len() as u32;
            let base = *cursor;
            self.write(base, &0u32.to_le_bytes()); // next, patched later
            self.write(base + 4, &0u32.to_le_bytes()); // prev
            self.write(base + 8, &fid.to_le_bytes());
            if ext {
                self.write(base + 10, &0xFFFFu16.to_le_bytes());
                self.write(base + 12, &(data.len() as u32).to_le_bytes());
            } else {
                self.write(base + 10, &(data.len() as u16).to_le_bytes());
            }
            self.write(base + 12 + if ext { 4 } else { 0 }, data);
            base
        }

        fn link(&mut self, new_base: u32, older: u32) {
            self.write(new_base, &older.to_le_bytes());
        }

        fn publish_head(&mut self, addr: u32) {
            let b = self.bounds();
            self.write(b.data_end, &addr.to_le_bytes());
        }

        fn set_sentinels(&mut self, v: u32) {
            let b = self.bounds();
            self.write(b.end_rom_pool, &v.to_le_bytes());
            self.write(b.end_rom_pool + 4, &v.to_le_bytes());
        }

        fn hard_init(&mut self) {
            self.set_sentinels(0x0000_0000);
            self.publish_head(0);
        }
    }

    impl CFlashSource for MemFlash {
        fn read(&self, addr: u32, buf: &mut [u8]) {
            let o = self.off(addr);
            buf.copy_from_slice(&self.img[o..o + buf.len()]);
        }
    }

    #[test]
    fn erased_partition_is_factory_fresh() {
        // All-0xFF (never touched) partition: the C boot path classifies it
        // as "first initialization" (file.c:365-380) — FactoryFresh.
        let f = MemFlash::new();
        let cfs = Cfs::new(&f, f.bounds());
        assert_eq!(cfs.state(), CState::FactoryFresh);
    }

    #[test]
    fn initialized_empty_partition_is_empty() {
        // Hard init (head = 0, sentinels zeroed) but no files written.
        let mut f = MemFlash::new();
        f.hard_init();
        let cfs = Cfs::new(&f, f.bounds());
        let mut recs = HVec::new();
        assert_eq!(cfs.scan(&mut recs), Ok(CState::Empty));
        assert!(recs.is_empty());
    }

    #[test]
    fn efefefef_sentinel_is_factory_fresh() {
        // Partially-erased persistent region (C's "or corrupted!" branch).
        let mut f = MemFlash::new();
        f.set_sentinels(0xEFEF_EFEF);
        let cfs = Cfs::new(&f, f.bounds());
        assert_eq!(cfs.state(), CState::FactoryFresh);
    }

    #[test]
    fn scan_returns_records_newest_first_with_exact_payloads() {
        let mut f = MemFlash::new();
        let mut cursor = f.bounds().data_end;

        // Oldest record first (C allocates downward, head = newest).
        let r1 = f.push_record(&mut cursor, 0xCC00, &[0xAA; 32]);
        let r2 = f.push_record(&mut cursor, 0x1122, &[0xBB; 300]);
        let r3 = f.push_record(&mut cursor, 0xBA01, &[0xCC; 7]);
        f.link(r3, r2);
        f.link(r2, r1);
        f.link(r1, 0);
        f.hard_init();
        f.publish_head(r3);

        let cfs = Cfs::new(&f, f.bounds());
        let mut recs = HVec::new();
        assert_eq!(cfs.scan(&mut recs), Ok(CState::Used));
        assert_eq!(recs.len(), 3);
        // Newest first (head chain order).
        assert_eq!(recs[0].fid, 0xBA01);
        assert_eq!(recs[0].len, 7);
        assert_eq!(recs[1].fid, 0x1122);
        assert_eq!(recs[1].len, 300);
        assert_eq!(recs[2].fid, 0xCC00);
        assert_eq!(recs[2].len, 32);

        // Payload contents readable at the reported addresses.
        let mut buf = [0u8; 7];
        assert_eq!(cfs.read_at(&recs[0], 0, &mut buf), 7);
        assert_eq!(&buf, &[0xCC; 7]);
        let mut buf = [0u8; 32];
        assert_eq!(cfs.read_at(&recs[2], 0, &mut buf), 32);
        assert_eq!(&buf, &[0xAA; 32]);
    }

    #[test]
    fn scan_walks_reversed_chain_by_pointers_not_address_order() {
        // Newest record at the LOWEST address, chain ascending — the reader
        // must follow `next` pointers, never assume address order.
        let mut f = MemFlash::new();
        let mut cursor = f.bounds().data_end;
        let r_old = f.push_record(&mut cursor, 0xBB02, &[0x11; 4]);
        let r_new = f.push_record(&mut cursor, 0xBB01, &[0x22; 4]);
        // Head = newest (lowest address), next -> older (higher address).
        f.link(r_new, r_old);
        f.link(r_old, 0);
        f.hard_init();
        f.publish_head(r_new);

        let cfs = Cfs::new(&f, f.bounds());
        let mut recs = HVec::new();
        assert_eq!(cfs.scan(&mut recs), Ok(CState::Used));
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].fid, 0xBB01);
        assert_eq!(recs[1].fid, 0xBB02);
    }

    #[test]
    fn extended_length_record_decodes_u32_size_and_streams() {
        // Length 70_000 >= 0xFFFF forces the extended [FFFF | len32] form.
        let big = vec![0x5Au8; 70_000];
        let mut f = MemFlash::new();
        let mut cursor = f.bounds().data_end;
        let r = f.push_record(&mut cursor, 0x10D1, &big);
        f.link(r, 0);
        f.hard_init();
        f.publish_head(r);

        let cfs = Cfs::new(&f, f.bounds());
        let mut recs = HVec::new();
        cfs.scan(&mut recs).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].len, 70_000);
        assert_eq!(recs[0].fid, 0x10D1);

        // Stream the big payload in two bounded chunks + tail.
        let mut out = vec![0u8; 70_000];
        let mut off = 0u32;
        while (off as usize) < out.len() {
            let end = ((off as usize) + 32 * 1024).min(out.len());
            let n = cfs.read_at(&recs[0], off, &mut out[off as usize..end]);
            assert!(n > 0);
            off += n;
        }
        assert_eq!(out, big);
    }

    #[test]
    fn whitelisted_payload_read_enforces_fid_and_cap() {
        let mut f = MemFlash::new();
        let mut cursor = f.bounds().data_end;
        let keydev = f.push_record(&mut cursor, 0xCC00, &[0x42; 33]);
        let foreign = f.push_record(&mut cursor, 0x1234, &[0x00; 8]);
        f.link(keydev, foreign);
        f.link(foreign, 0);
        f.hard_init();
        f.publish_head(keydev);

        let cfs = Cfs::new(&f, f.bounds());
        let mut recs = HVec::new();
        cfs.scan(&mut recs).unwrap();

        // 0xCC00 (EF_KEY_DEV) is whitelisted, payload fits one buffer.
        let mut buf = [0u8; 64];
        let n = cfs.read_whitelisted(&recs[0], &mut buf).unwrap();
        assert_eq!(n, 33);
        assert_eq!(&buf[..33], &[0x42; 33]);

        // Non-whitelisted FID rejected.
        assert_eq!(
            cfs.read_whitelisted(&recs[1], &mut buf),
            Err(CfsError::NotWhitelisted)
        );

        // Payload larger than the cap rejected for single-buffer read
        // (streaming via read_at is the path for big records).
        let big = vec![0u8; MAX_WHOLE_PAYLOAD + 1];
        let mut f2 = MemFlash::new();
        let mut cursor2 = f2.bounds().data_end;
        let r = f2.push_record(&mut cursor2, 0xCC00, &big);
        f2.link(r, 0);
        f2.hard_init();
        f2.publish_head(r);
        let cfs2 = Cfs::new(&f2, f2.bounds());
        let mut recs2 = HVec::new();
        cfs2.scan(&mut recs2).unwrap();
        let mut buf = vec![0u8; MAX_WHOLE_PAYLOAD];
        assert_eq!(
            cfs2.read_whitelisted(&recs2[0], &mut buf),
            Err(CfsError::PayloadTooLarge)
        );
    }

    #[test]
    fn corrupt_chain_is_reported() {
        let mut f = MemFlash::new();
        let mut cursor = f.bounds().data_end;
        let r = f.push_record(&mut cursor, 0xCC00, &[1u8; 8]);
        // next pointing outside the data pool.
        f.link(r, f.bounds().data_start - 0x100);
        f.hard_init();
        f.publish_head(r);

        let cfs = Cfs::new(&f, f.bounds());
        let mut recs = HVec::new();
        assert_eq!(cfs.scan(&mut recs), Err(CfsError::Corrupt));
    }

    #[test]
    fn pool_geometry_matches_flash_set_bounds() {
        let b = PoolBounds::from_partition(crate::cflash::DataPartition {
            start: PART_START,
            end: PART_END,
        });
        // flash.c:60-68 arithmetic, absolute XIP:
        assert_eq!(b.end_rom_pool, PART_END - 12);
        let start_rom_pool = b.end_rom_pool - 16 * 1024;
        assert_eq!(b.data_end, start_rom_pool - 8);
        assert_eq!(b.data_start, PART_START);
        // Head pointer word sits at data_end (inside the partition, below
        // the reserved tail).
        assert!(b.data_end > b.data_start);
    }
}
