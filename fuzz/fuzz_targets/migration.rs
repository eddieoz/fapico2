#![no_main]
//! US-1052 — `fapico2_platform::migration::run`, the first-boot C→Rust data
//! migration over the legacy C flash partition.
//!
//! 1 733 lines parsing attacker-adjacent legacy records, entirely unfuzzed
//! before this target. Absence of panic is the *weakest* thing it can assert:
//! the interesting failures here are quiet ones —
//!
//! * a walker bounds check that stops bounding, so a record whose payload
//!   runs off the end of the data pool is read from outside the partition;
//! * a per-class record framed with a length field that does not match its
//!   payload, so the migrated stream is structurally corrupt and the *next*
//!   boot's restore (OATH `load_stream`, OpenPGP capture) mis-parses it;
//! * a value written into the store that the store cannot serialize back, so
//!   the destination is no longer loadable.
//!
//! So the fuzzer supplies the **record chain** (the C partition's linked
//! list of `[fid u16][len u32][payload]` records, laid out exactly as the
//! production C firmware lays it out), and the target asserts:
//!
//! 1. **the walker never reads outside the data partition** — every address
//!    the `Cfs` issues stays within `[data_start, data_end]`; recorded by
//!    the flash model, not inferred from the return value;
//! 2. **no unbounded length** — after the run, every key and every value in
//!    the destination store is within the store's own bounds;
//! 3. **the store is left loadable** — seal → unseal → re-seal is a fixed
//!    point, and every migrated per-class record stream re-parses *exactly*
//!    (each `[fid][len][payload]`'s length field matches its payload and the
//!    records consume the value with nothing left over). A record the
//!    migration could not make sense of must be absent, never half-written.
//!
//! # Red-under-mutation (the evidence that these assertions bite)
//!
//! An off-by-one in `push_tlv`'s length field turns assertion 3 red; dropping
//! `Cfs::scan`'s `RecordOverflow` bound turns assertion 1 red. See
//! `.superpowers/sdd/report-P6.md`.

use std::vec::Vec;

use fapico2_platform::cflash::{fallback_partition_reserved, DataPartition};
use fapico2_platform::cfs::{CFlashSource, PoolBounds};
use fapico2_platform::migration::{self, MigrationBuffers, SLOT_BOOT_ENTROPY};
use fapico2_platform::secure_store::{
    HostSecureStore, SecureStore, MAX_KEY_LEN, MAX_VALUE_LEN, PARTITION_IMAGE_MAGIC,
};
use fapico2_platform::store_v3::{emulation_store_key, seal_image, unseal_image};

/// The C firmware's OTP key row and flash UID. Fixed test vectors, as in
/// `apps/openpgp/tests/migration_restore.rs` — the migration's crypto is not
/// what this target probes.
const OTP: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];
const UID: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];

/// Bound on the record count one input lays out. `Cfs::scan` caps at 256 and
/// `migration::run` reserves slots against that cap; the harness bounds it
/// lower only to keep the run inside the CI smoke's time budget.
const MAX_RECORDS: usize = 24;
/// Bound on one record's payload length.
const MAX_PAYLOAD: usize = 512;

/// The C data partition as a flash model that **records every read address**,
/// so the walker's own bounds discipline is observable.
///
/// Reads outside the partition return erased flash rather than panicking: a
/// read past a NOR device is not a fault, and modelling it as one would
/// report the model's limits as the walker's bug. The recording is what
/// turns an out-of-pool read into an assertion failure instead of silence.
struct CPartition {
    bytes: Vec<u8>,
    part: DataPartition,
    /// `(first_addr, last_addr_exclusive)` of every read outside
    /// `[data_start, data_end]`. `RefCell` because `CFlashSource::read` takes
    /// `&self` — the trait's contract is that it never writes the medium,
    /// and this is the harness's own bookkeeping, not a medium write.
    out_of_pool: core::cell::RefCell<Vec<(u32, u32)>>,
}

impl CPartition {
    /// Lay the fuzzer's record stream out the way the C firmware's linked
    /// list is laid out: each record is `[prev u32][pad u32][fid u16]
    /// [len u16][payload]`, chained newest-first from `data_end`, with the
    /// 16-byte extended header (`len == 0xFFFF`) also reachable.
    ///
    /// The record's **declared length is the fuzzer's**, and is deliberately
    /// independent of how many payload bytes are actually laid down. That
    /// separation is the attack this target needs to express: a record that
    /// *claims* more bytes than the pool can hold is only reachable if the
    /// harness can write a short record with a long declared length, which is
    /// exactly what a stale/torn C record looks like to the walker.
    fn from_record_stream(part: DataPartition, mut stream: &[u8]) -> Self {
        let bounds = PoolBounds::from_partition(part);
        let mut f = Self {
            bytes: vec![0xFF; part.size_bytes() as usize],
            part,
            out_of_pool: core::cell::RefCell::new(Vec::new()),
        };
        let mut put = |addr: u32, data: &[u8]| {
            let o = (addr - part.start) as usize;
            f.bytes[o..o + data.len()].copy_from_slice(data);
        };
        // Initialised-but-empty rom-pool sentinel: the "C partition exists"
        // shape, so the walker does not take the factory-fresh shortcut.
        put(bounds.end_rom_pool, &[0, 0, 0, 0, 0, 0, 0, 0]);
        let mut cursor = bounds.data_end;
        let mut previous = 0u32;
        let mut placed = 0usize;
        while stream.len() >= 6 && placed < MAX_RECORDS {
            let fid = u16::from_le_bytes([stream[0], stream[1]]);
            let declared = u32::from_le_bytes([stream[2], stream[3], stream[4], stream[5]]);
            let body = &stream[6..];
            // Physical footprint: the bytes actually laid down. A record
            // never claims more space than the pool has left.
            let written = body.len().min(MAX_PAYLOAD);
            let extended = declared >= 0xFFFF;
            let header = if extended { 16 } else { 12 };
            let Some(next) = cursor.checked_sub((header + written) as u32) else {
                break; // harness framing exhausted the pool; stop laying out
            };
            if next < bounds.data_start + 4 {
                break;
            }
            cursor = next;
            put(cursor, &previous.to_le_bytes());
            put(cursor + 4, &[0, 0, 0, 0]);
            put(cursor + 8, &fid.to_le_bytes());
            if extended {
                // The walker's extended form reads the real length from
                // base+12 and the payload from base+16. `declared` is
                // re-used as the extended length so one fuzz word drives
                // both the dialect and the overrun.
                put(cursor + 10, &[0xFF, 0xFF]);
                put(cursor + 12, &declared.to_le_bytes());
                put(cursor + 16, &body[..written]);
            } else {
                put(cursor + 10, &(declared as u16).to_le_bytes());
                put(cursor + 12, &body[..written]);
            }
            previous = cursor;
            stream = &stream[6 + written..];
            placed += 1;
        }
        put(bounds.data_end, &previous.to_le_bytes());
        f
    }

    /// One whole-partition erase with no records at all — the "C partition
    /// never initialised" shape, which the walker must take as a skip, not
    /// as a parse.
    fn factory_fresh(part: DataPartition) -> Self {
        Self {
            bytes: vec![0xFF; part.size_bytes() as usize],
            part,
            out_of_pool: core::cell::RefCell::new(Vec::new()),
        }
    }

    /// The windows the migration may **legally** read, from `PoolBounds`:
    ///
    /// * `[data_start, data_end + 4)` — the record pool, plus the head word
    ///   `Cfs::state` reads at `data_end` itself; and
    /// * `[end_rom_pool, end_rom_pool + 8)` — the rom-pool head words, which
    ///   `Cfs::state` reads as the "was this region ever initialised"
    ///   sentinel. Those sit above `data_end` by construction, so excluding
    ///   them would flag the walker's own, correct, first two reads.
    ///
    /// Both of the walker's *own* bootstrap reads are inside this set. Every
    /// other read a record payload issues is the walker's business, and a
    /// payload that reaches outside these windows is a record whose length
    /// was not validated against the remaining pool.
    ///
    /// Nothing else is in bounds. In particular a record payload that runs
    /// off the end of the pool into the persistent region above it — the
    /// shape a dropped `RecordOverflow` bound produces — is caught here.
    fn allowed(&self) -> [(u32, u32); 2] {
        let b = PoolBounds::from_partition(self.part);
        [
            (b.data_start, b.data_end + 4),
            (b.end_rom_pool, b.end_rom_pool + 8),
        ]
    }
}

impl CFlashSource for CPartition {
    fn read(&self, addr: u32, buf: &mut [u8]) {
        let end = addr.wrapping_add(buf.len() as u32);
        if !self.allowed().iter().any(|(s, e)| addr >= *s && end <= *e) {
            self.out_of_pool.borrow_mut().push((addr, end));
        }
        for (i, out) in buf.iter_mut().enumerate() {
            let a = (addr - self.part.start) as usize + i;
            // Erased flash past the modelled array, not a fault.
            *out = self.bytes.get(a).copied().unwrap_or(0xFF);
        }
    }
}

/// US-918: seed the boot-entropy record so the bound device root is
/// derivable. `migration::run` is fail-closed without it.
fn seed_entropy(store: &mut HostSecureStore) {
    let entropy = [0xA5u8; fapico2_platform::ckey::BOOT_ENTROPY_LEN];
    store.write(SLOT_BOOT_ENTROPY, &entropy).expect("the store accepts the entropy record");
}

/// Every `(key, value)` in the store, recovered by unsealing its own
/// serialization — the only public way to enumerate what a migration wrote.
fn store_entries(store: &HostSecureStore) -> Vec<(Vec<u8>, Vec<u8>)> {
    let sealed = store.partition_image();
    let logical = unseal_image(&sealed, &emulation_store_key())
        .expect("the store's own serialization always unseals");
    assert!(
        logical.len() >= 8,
        "the logical image is too short to hold a header",
    );
    assert_eq!(
        u32::from_le_bytes([logical[0], logical[1], logical[2], logical[3]]),
        PARTITION_IMAGE_MAGIC,
    );
    let mut out = Vec::new();
    let mut i = 8usize;
    while i + 4 <= logical.len() - 4 {
        let kl =
            u32::from_le_bytes([logical[i], logical[i + 1], logical[i + 2], logical[i + 3]]) as usize;
        i += 4;
        let k = logical[i..i + kl].to_vec();
        i += kl;
        let vl =
            u32::from_le_bytes([logical[i], logical[i + 1], logical[i + 2], logical[i + 3]]) as usize;
        i += 4;
        let v = logical[i..i + vl].to_vec();
        i += vl;
        out.push((k, v));
    }
    out
}

/// The migration's own record framing: `[fid u16 LE][len u32 LE][payload]`.
/// Re-walk a per-class stream the way every consumer of it does
/// (`OathApp::load_stream`, `captured_record`, …) and assert it consumes
/// **exactly**, with every length field matching its payload. A stream that
/// does not is the half-written-record failure this target exists for.
fn assert_stream_is_framed(where_: &str, stream: &[u8]) {
    let mut i = 0usize;
    while i < stream.len() {
        assert!(
            i + 6 <= stream.len(),
            "{where_}: a record header runs past the end of the stream at offset {i} of {}",
            stream.len(),
        );
        let len = u32::from_le_bytes([
            stream[i + 2],
            stream[i + 3],
            stream[i + 4],
            stream[i + 5],
        ]) as usize;
        i += 6;
        assert!(
            i + len <= stream.len(),
            "{where_}: a record at offset {} declares {len} bytes with only {} remaining",
            i - 6,
            stream.len() - i,
        );
        i += len;
    }
    assert_eq!(i, stream.len(), "{where_}: the records do not consume the stream exactly");
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let part = fallback_partition_reserved();

    // Two shapes per input: the fuzzer's record stream laid out as a live C
    // chain, and (when the fuzzer's low byte says so) the uninitialised
    // partition. Both must be skipped or refused, never half-applied.
    for variant in 0..2u8 {
        let flash = if variant == 0 && data.first() == Some(&0x00) {
            CPartition::factory_fresh(part)
        } else {
            CPartition::from_record_stream(part, data)
        };

        let mut store = HostSecureStore::new();
        seed_entropy(&mut store);
        let mut bufs = MigrationBuffers::new();
        let _ = migration::run(&flash, part, &mut store, &OTP, UID, &mut bufs);

        // -- 1. the walker stayed inside the data pool ---------------------
        let out_of_pool = flash.out_of_pool.borrow().clone();
        for (first, last) in &out_of_pool {
            let inside = flash
                .allowed()
                .iter()
                .any(|(s, e)| *first >= *s && *last <= *e);
            assert!(
                inside,
                "the C walker read {first:#x}..{last:#x}, outside every legal window {:?}",
                flash.allowed(),
            );
        }

        // -- 2. no unbounded length reached the store ----------------------
        for (k, v) in store_entries(&store) {
            assert!(
                k.len() <= MAX_KEY_LEN,
                "a {}-byte key was written to the store (bound {MAX_KEY_LEN})",
                k.len(),
            );
            assert!(
                v.len() <= MAX_VALUE_LEN,
                "a {}-byte value was written to the store (bound {MAX_VALUE_LEN})",
                v.len(),
            );
        }

        // -- 3. the destination store is still loadable --------------------
        // (a) seal -> unseal -> seal is a fixed point: nothing was written
        //     that the store cannot serialize back out.
        let sealed = store.partition_image();
        let logical = unseal_image(&sealed, &emulation_store_key())
            .expect("the destination store no longer unseals after the migration");
        let resealed = seal_image(&logical, &emulation_store_key())
            .expect("the recovered logical image re-seals");
        assert_eq!(
            resealed, sealed,
            "the destination store is not a fixed point of seal/unseal",
        );

        // (b) every migrated per-class record stream is framed exactly, so
        //     the next boot's restore parses it without a partial record.
        for (k, v) in store_entries(&store) {
            if matches!(
                k.as_slice(),
                b"oath.keystore.v1"
                    | b"otp.keystore.v1"
                    | b"piv.keystore.v1"
                    | b"fido.ccontainer.v1"
            ) {
                assert_stream_is_framed(
                    &format!("migration slot {:?}", String::from_utf8_lossy(&k)),
                    &v,
                );
            }
        }
    }
});
