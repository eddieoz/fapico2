//! S-701-2 TDD: chunked logical slots over the secure store.

use fapico2_platform::secure_store::{
    chunked, rp2350, HostSecureStore, Rp2350SecureStore, SecureStore, SecureStoreError,
    MAX_KEY_LEN, MAX_VALUE_LEN,
};

/// A bounded store mirroring the RP2350 device contract (16 entries × 512 B)
/// without needing the arm-only `Rp2350SecureStore` — the bound enforcement
/// (`Full`) is what the exhaustion test observes.
struct Bounded16 {
    slots: heapless::Vec<([u8; MAX_KEY_LEN], usize, heapless::Vec<u8, 512>), 16>,
}

impl Bounded16 {
    fn new() -> Self {
        Self { slots: heapless::Vec::new() }
    }
}

impl SecureStore for Bounded16 {
    fn write(&mut self, key: &[u8], value: &[u8]) -> Result<(), SecureStoreError> {
        if value.len() > 512 {
            return Err(SecureStoreError::ValueTooLong);
        }
        if let Some(slot) = self.slots.iter_mut().find(|(k, kl, _)| kl == &key.len() && &k[..*kl] == key) {
            slot.2.clear();
            slot.2.extend_from_slice(value).map_err(|_| SecureStoreError::ValueTooLong)?;
            return Ok(());
        }
        let mut k = [0u8; MAX_KEY_LEN];
        k[..key.len()].copy_from_slice(key);
        let mut v = heapless::Vec::<u8, 512>::new();
        v.extend_from_slice(value).map_err(|_| SecureStoreError::ValueTooLong)?;
        self.slots
            .push((k, key.len(), v))
            .map_err(|_| SecureStoreError::Full)
    }
    fn read(&mut self, key: &[u8], out: &mut [u8]) -> Result<usize, SecureStoreError> {
        let slot = self
            .slots
            .iter()
            .find(|(k, kl, _)| kl == &key.len() && &k[..*kl] == key)
            .ok_or(SecureStoreError::NotFound)?;
        if slot.2.len() > out.len() {
            return Err(SecureStoreError::Full);
        }
        out[..slot.2.len()].copy_from_slice(&slot.2);
        Ok(slot.2.len())
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), SecureStoreError> {
        let before = self.slots.len();
        self.slots.retain(|(k, kl, _)| !(kl == &key.len() && &k[..*kl] == key));
        if self.slots.len() < before {
            Ok(())
        } else {
            Err(SecureStoreError::NotFound)
        }
    }
    fn contains(&self, key: &[u8]) -> bool {
        self.slots
            .iter()
            .any(|(k, kl, _)| kl == &key.len() && &k[..*kl] == key)
    }
    fn snapshot_partition(&self, buf: &mut [u8]) -> Result<usize, SecureStoreError> {
        // Test double: dump every slot as [key_len u32][key][val_len u32][value]
        // (no v2 framing — nothing in this test loads the image back).
        let mut i = 0usize;
        for slot in self.slots.iter() {
            let (k, kl, v) = slot;
            let kl = *kl;
            if i + 4 + kl + 4 + v.len() > buf.len() {
                return Err(SecureStoreError::Full);
            }
            buf[i..i + 4].copy_from_slice(&(kl as u32).to_le_bytes());
            i += 4;
            buf[i..i + kl].copy_from_slice(&k[..kl]);
            i += kl;
            buf[i..i + 4].copy_from_slice(&(v.len() as u32).to_le_bytes());
            i += 4;
            buf[i..i + v.len()].copy_from_slice(v);
            i += v.len();
        }
        Ok(i)
    }
    fn snapshot_len(&self) -> usize {
        self.slots.iter().map(|(_, kl, v)| 4 + kl + 4 + v.len()).sum()
    }
    fn snapshot_window(&self, off: usize, buf: &mut [u8]) -> usize {
        // Windowed twin of snapshot_partition: emit the window's
        // intersection with each slot segment contiguously.
        let mut pos = 0usize; // image offset
        let mut filled = 0usize;
        let end = off.saturating_add(buf.len());
        for slot in self.slots.iter() {
            let (k, kl, v) = slot;
            let kl = *kl;
            for seg in [
                &(kl as u32).to_le_bytes()[..],
                &k[..kl],
                &(v.len() as u32).to_le_bytes()[..],
                &v[..],
            ] {
                let seg_end = pos + seg.len();
                let lo = off.max(pos);
                let hi = end.min(seg_end);
                if lo < hi {
                    buf[filled..filled + (hi - lo)].copy_from_slice(&seg[lo - pos..hi - pos]);
                    filled += hi - lo;
                }
                pos = seg_end;
            }
        }
        filled
    }
    fn is_empty(&self) -> Result<bool, SecureStoreError> {
        Ok(self.slots.is_empty())
    }
    fn is_empty_except(&self, slot: &[u8]) -> Result<bool, SecureStoreError> {
        Ok(self.slots.iter().all(|(k, kl, _)| &k[..*kl] == slot))
    }
    // US-919: the trait's foreign-image wipe primitive — the test double
    // mirrors the real stores' clear-everything semantics.
    fn wipe_all(&mut self) -> Result<(), SecureStoreError> {
        self.slots.clear();
        Ok(())
    }
}

#[allow(unused_imports)]
use MAX_VALUE_LEN as _MAX_VALUE_LEN_USED;

/// Deterministic pseudo-content: byte i = (i * 31 + 7) & 0xFF.
fn fill(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((i * 31 + 7) & 0xFF) as u8;
    }
}

#[test]
fn logical_slot_larger_than_physical_cap_roundtrips() {
    let mut store = HostSecureStore::new();
    // `MAX_LOGICAL_LEN` — the widest value the device store can ever accept.
    // The point of the test is the *span* (a logical slot far larger than
    // any single 512-B physical slot), not a particular byte count, so it is
    // written against the constant rather than a literal that silently rots
    // when the constant moves.
    let mut value = vec![0u8; chunked::MAX_LOGICAL_LEN];
    fill(&mut value);

    chunked::write_chunked(&mut store, b"fido.keystore.v1", &value).unwrap();

    let mut out = vec![0xFFu8; chunked::MAX_LOGICAL_LEN];
    let n = chunked::read_chunked(&mut store, b"fido.keystore.v1", &mut out).unwrap();
    assert_eq!(n, value.len());
    assert_eq!(out, value);

    // Every physical part record stays within the device 512-B value cap.
    for buf in 0..2u8 {
        for index in 0..chunked::MAX_PARTS {
            if let Some((pk, pklen)) = chunked::physical_part_key(b"fido.keystore.v1", buf, index) {
                if store.contains(&pk[..pklen]) {
                    let mut rec = [0u8; 1024];
                    let n = store.read(&pk[..pklen], &mut rec).unwrap();
                    assert!(
                        n <= 512,
                        "part record {n} B exceeds the 512-B physical cap"
                    );
                }
            }
        }
    }

    // A value beyond the logical bound is rejected cleanly.
    let big = vec![0u8; chunked::MAX_LOGICAL_LEN + 1];
    assert_eq!(
        chunked::write_chunked(&mut store, b"fido.keystore.v1", &big),
        Err(SecureStoreError::ValueTooLong)
    );
}

/// US-1010 — **the capacity invariant, as arithmetic.** A chunked rewrite
/// writes the new generation into the buffer *not* holding the current set and
/// retires the old buffer's parts only afterwards, so a full-width value
/// transiently needs `2 × MAX_PARTS` physical entries. There are only
/// `DEV_MAX_ENTRIES`. This fails whenever the two constants contradict
/// each other, and it fails *loudly at the source of the claim* rather than
/// leaving the contradiction to be discovered in the field as a
/// `KeyStoreFull` on a rewrite.
///
/// The invariant is a `const` assert rather than a runtime one: both operands
/// are constants, so a runtime `assert!` here is a constant expression, which
/// newer clippy flags (`clippy::assertions_on_constants`) and which runs on
/// every test invocation to learn nothing. Failing to compile is also the
/// stronger outcome — the contradiction can never reach a build at all.
const _: () = assert!(
    2 * chunked::MAX_PARTS <= rp2350::DEV_MAX_ENTRIES,
    "a full-width chunked rewrite transiently holds 2 x MAX_PARTS physical \
     entries, but the device store has fewer DEV_MAX_ENTRIES — \
     MAX_LOGICAL_LEN is therefore a documented number, not a reachable one. \
     Lower MAX_PARTS (free) or raise DEV_MAX_ENTRIES (568 B of partition \
     image AND ~580 B of bss per entry, on a build with no spare RAM)."
);

#[test]
fn chunked_rewrite_peak_occupancy_fits_the_device_store() {
    // The invariant is enforced at compile time by the `const assert` above.
    // This test records the measured numbers, so tightening either constant
    // shows up in the log as a diff rather than only as a build failure.
    println!(
        "chunked rewrite peak: 2 x MAX_PARTS = {} entries, DEV_MAX_ENTRIES = {}, \
         slack = {}",
        2 * chunked::MAX_PARTS,
        rp2350::DEV_MAX_ENTRIES,
        rp2350::DEV_MAX_ENTRIES as isize - 2 * chunked::MAX_PARTS as isize,
    );
}

/// US-1010 — the same invariant, observed rather than asserted: the real
/// `Rp2350SecureStore` must be able to rewrite a maximum-width logical slot
/// over its own previous maximum-width generation. This is the behaviour the
/// arithmetic above predicts, on the store that enforces it, with the
/// `SecureStoreError::Full` the device would return.
#[test]
fn max_width_chunked_rewrite_succeeds_on_the_device_store() {
    let mut store = Rp2350SecureStore::new();
    let mut v1 = vec![0u8; chunked::MAX_LOGICAL_LEN];
    fill(&mut v1);
    chunked::write_chunked(&mut store, b"oath.keystore.v1", &v1).unwrap();

    // The rewrite: a second full-width generation, written into the other
    // buffer while the first still occupies its parts.
    let mut v2 = vec![0u8; chunked::MAX_LOGICAL_LEN];
    for (i, b) in v2.iter_mut().enumerate() {
        *b = ((i * 17 + 3) & 0xFF) as u8;
    }
    chunked::write_chunked(
        &mut store,
        b"oath.keystore.v1",
        &v2,
    )
    .expect("a max-width chunked rewrite must fit the device store (US-1010)");

    let mut out = vec![0u8; chunked::MAX_LOGICAL_LEN];
    let n =
        chunked::read_chunked(&mut store, b"oath.keystore.v1", &mut out).expect("readable");
    assert_eq!(n, v2.len());
    assert_eq!(out, v2, "the retired generation's bytes must not win");
}

#[test]
fn torn_write_recovers_last_valid_parts() {
    let mut store = HostSecureStore::new();
    let mut v1 = [0u8; 1200]; // 3 parts
    fill(&mut v1);
    chunked::write_chunked(&mut store, b"oath.keystore.v1", &v1).unwrap();

    // Simulate a torn v2 write: gen 2 records land in buffer 1 for parts
    // 1..4 but the part-0 commit marker never makes it to flash.
    let mut v2 = [0u8; 1900]; // would be 4 parts
    fill(&mut v2);
    let mut rec = [0u8; chunked::PART_HEADER_LEN + chunked::PART_PAYLOAD_MAX];
    for index in 1..4 {
        let start = index * chunked::PART_PAYLOAD_MAX;
        let end = ((index + 1) * chunked::PART_PAYLOAD_MAX).min(v2.len());
        let n = chunked::encode_part_record(2, index, 4, v2.len(), &v2[start..end], &mut rec)
            .unwrap();
        let (pk, pklen) =
            chunked::physical_part_key(b"oath.keystore.v1", 1, index).unwrap();
        store.write(&pk[..pklen], &rec[..n]).unwrap();
    }

    // The last VALID part set (gen 1) wins — the torn gen-2 set is ignored.
    let mut out = [0u8; 2048];
    let n = chunked::read_chunked(&mut store, b"oath.keystore.v1", &mut out).unwrap();
    assert_eq!(n, v1.len());
    assert_eq!(&out[..n], &v1);

    // Completing the gen-2 write (commit marker lands) flips the reader to
    // the new set.
    let n = chunked::encode_part_record(2, 0, 4, v2.len(), &v2[..chunked::PART_PAYLOAD_MAX], &mut rec)
        .unwrap();
    let (pk, pklen) = chunked::physical_part_key(b"oath.keystore.v1", 1, 0).unwrap();
    store.write(&pk[..pklen], &rec[..n]).unwrap();
    let n = chunked::read_chunked(&mut store, b"oath.keystore.v1", &mut out).unwrap();
    assert_eq!(n, v2.len());
    assert_eq!(&out[..n], &v2);
}

#[test]
fn chunked_delete_frees_all_parts() {
    let mut store = HostSecureStore::new();
    let mut value = [0u8; 2000]; // 5 parts
    fill(&mut value);
    chunked::write_chunked(&mut store, b"openpgp.keystore.v1", &value).unwrap();
    assert!(chunked::contains_chunked(&mut store, b"openpgp.keystore.v1"));

    chunked::delete_chunked(&mut store, b"openpgp.keystore.v1").unwrap();

    assert!(!chunked::contains_chunked(&mut store, b"openpgp.keystore.v1"));
    // No physical part of either buffer survives.
    for buf in 0..2u8 {
        for index in 0..chunked::MAX_PARTS {
            if let Some((pk, pklen)) = chunked::physical_part_key(b"openpgp.keystore.v1", buf, index)
            {
                assert!(!store.contains(&pk[..pklen]), "part {buf}/{index} leaked");
            }
        }
    }
    assert_eq!(
        chunked::read_chunked(&mut store, b"openpgp.keystore.v1", &mut [0u8; 8]),
        Err(SecureStoreError::NotFound)
    );
}

#[test]
fn exhausted_entries_reports_full() {
    // The device store contract (16 entries × 512 B): one-part chunked
    // slots consume one physical entry each; the 17th logical slot must
    // report Full.
    let mut store = Bounded16::new();
    let small = [0xABu8; 100];
    for i in 0..16u8 {
        let key = [b'k', b'0' + i / 10, b'0' + i % 10];
        chunked::write_chunked(&mut store, &key, &small).unwrap();
    }
    assert_eq!(
        chunked::write_chunked(&mut store, b"overflow", &small),
        Err(SecureStoreError::Full)
    );
}

/// BDD (host): Given a simulated reboot **when** a chunked slot is re-opened
/// from the partition image **then** its bytes are identical.
#[test]
fn chunked_slot_survives_partition_image_reboot() {
    let mut store = HostSecureStore::new();
    let mut value = [0u8; 4096];
    fill(&mut value);
    chunked::write_chunked(&mut store, b"fido.keystore.v1", &value).unwrap();

    // Power down: snapshot the partition image; restore on "boot".
    let image = store.partition_image();
    drop(store);
    let mut restored = HostSecureStore::new();
    restored.from_partition_image(&image);

    let mut out = [0u8; 4096];
    let n = chunked::read_chunked(&mut restored, b"fido.keystore.v1", &mut out).unwrap();
    assert_eq!(n, value.len());
    assert_eq!(out, value);
}
