//! US-1030 — the OATH credential keys in the C migration stream move from
//! plaintext to C's sealed `"OATH"`-magic GCM form.
//!
//! # Why these tests are here and not in `apps/openpgp/tests/migration_restore.rs`
//!
//! The story names `migration_restore.rs`, and the first cut put them there.
//! That is the file that already knows how to build a **C-format stream**
//! from a fixture and drive it through `migration::run` — but reaching it
//! from `fapico2-openpgp` needs a dev-dependency on `fapico2-oath`, and
//! `fapico2-oath` depends on `fapico2-platform` **with default features**.
//! Cargo unifies features across the whole graph, so that one dev-edge
//! silently turns the `secp256k1` / `brainpool` / `rsa` backends back on in
//! the *reduced* build, and `check_advertise_serve_coupling.py` goes red —
//! which is the gate existing precisely to catch that (its own header records
//! the same trap arriving by a different route). The evidence is in the
//! report; the fix is to live in a crate whose graph is not under that
//! gate's microscope, and to say so here rather than quietly.
//!
//! So: the C-stream fixture machinery is rebuilt below (it is ~40 lines)
//! rather than shared across a crate boundary, and the property under test
//! is unchanged — `migration::run` over a C partition carrying a plaintext
//! OATH credential, then the OATH applet's boot.

use fapico2_oath::oath_core::{device_id_from_chipid, OathApp, EMULATION_CHIPID};
use fapico2_oath::oath_core::SLOT_OATH_SEAL_GENERATION;
use fapico2_oath::OathSeal;
use fapico2_platform::cflash::{fallback_partition_reserved, DataPartition};
use fapico2_platform::cfs::{CFlashSource, PoolBounds};
use fapico2_platform::migration::{self, MigrationBuffers};
use fapico2_platform::secure_store::{chunked, HostSecureStore, SecureStore, SecureStoreError};
use fapico2_platform::trng::HostTrng;

const UID: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
const OTP: [u8; 32] =
    hex_literal::hex!("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
// ===========================================================================
//
// These three are the reds the story names, one per property:
//
//   1. a C-format stream carrying **plaintext** OATH keys migrates to sealed;
//   2. a mid-read fault leaves the device **refusing**, not serving the
//      plaintext it just read, and the next boot re-seals *higher* rather
//      than skipping;
//   3. re-sealing the **same** key twice never reuses a nonce.
//
// They live here rather than in `apps/oath/tests/` because this file is the
// only place that already builds a **C-format stream** from a fixture and
// drives it through `migration::run`. The seal is a property of exactly
// that path.


/// A C data partition holding `stream`, laid out the way the C firmware
/// lays one out (a backward-linked free list from `data_end` down). This is
/// `migration_restore.rs`'s builder, reproduced rather than imported: the
/// two crates' test targets cannot share code without a lib, and the ~35
/// lines are the price of not putting these tests in the crate whose
/// feature graph `check_advertise_serve_coupling.py` guards.
struct CFlash {
    bytes: Vec<u8>,
    part: DataPartition,
}

impl CFlashSource for CFlash {
    fn read(&self, addr: u32, out: &mut [u8]) {
        let o = (addr - self.part.start) as usize;
        out.copy_from_slice(&self.bytes[o..o + out.len()]);
    }
}

fn fixture_from_stream(mut stream: &[u8]) -> CFlash {
    let part = fallback_partition_reserved();
    let bounds = PoolBounds::from_partition(part);
    let mut flash = CFlash {
        bytes: vec![0xff; part.size_bytes() as usize],
        part,
    };
    let mut put = |addr: u32, data: &[u8]| {
        let o = (addr - part.start) as usize;
        flash.bytes[o..o + data.len()].copy_from_slice(data);
    };
    put(bounds.end_rom_pool, &[0; 8]);
    let mut cursor = bounds.data_end;
    let mut previous = 0u32;
    while !stream.is_empty() {
        let fid = &stream[..2];
        let n = u32::from_le_bytes(stream[2..6].try_into().unwrap()) as usize;
        cursor -= (12 + n) as u32;
        put(cursor, &previous.to_le_bytes());
        put(cursor + 4, &[0; 4]);
        put(cursor + 8, fid);
        put(cursor + 10, &(n as u16).to_le_bytes());
        put(cursor + 12, &stream[6..6 + n]);
        previous = cursor;
        stream = &stream[6 + n..];
    }
    put(bounds.data_end, &previous.to_le_bytes());
    flash
}

/// The boot-entropy record, so the bound device root the migration derives
/// is available. Harmless where no derivation happens.
fn seed_entropy(store: &mut dyn SecureStore) {
    const ENTROPY: [u8; 32] = [0xA5u8; 32];
    store.write(migration::SLOT_BOOT_ENTROPY, &ENTROPY).unwrap();
}

/// A C-partition OATH record stream: `[fid u16 LE][len u32 LE][payload]`,
/// exactly what `migration::run` walks. One credential (fid `0xBA00`) with
/// a **plaintext** TOTP-SHA1/6 key, the shape the C firmware writes for a
/// credential it chose not to seal.
fn c_oath_plaintext_stream(secret: &[u8]) -> Vec<u8> {
    let mut key = vec![0x21u8, 6]; // ALG_SHA1 | TOTP, 6 digits
    key.extend_from_slice(secret);
    let mut payload = vec![0x71, 4]; // TAG_NAME, len 4
    payload.extend_from_slice(b"acct");
    payload.push(0x73); // TAG_KEY
    payload.push(key.len() as u8);
    payload.extend_from_slice(&key);
    let mut out = Vec::new();
    out.extend_from_slice(&0xBA00u16.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    out
}

/// The 20-byte TOTP secret the fixture credential carries. Distinctive on
/// purpose: the "no plaintext on the medium" assertions search for exactly
/// these bytes.
const OATH_SECRET: [u8; 20] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xFF, 0xEE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
    0x23, 0x45, 0x67, 0x89,
];

/// The device-wide seal high-water mark, as the store holds it.
fn seal_generation(store: &mut dyn SecureStore) -> Option<u64> {
    let mut raw = [0u8; 8];
    match store.read(SLOT_OATH_SEAL_GENERATION, &mut raw) {
        Ok(8) => Some(u64::from_be_bytes(raw)),
        _ => None,
    }
}

/// The plaintext `TAG_KEY` value the C record carries.
fn plaintext_key() -> Vec<u8> {
    let mut k = vec![0x21u8, 6];
    k.extend_from_slice(&OATH_SECRET);
    k
}

/// The current `oath.keystore.v1` value: the chunked form if there is one
/// (which is what every write produces), else the plain migration entry.
fn oath_stream(store: &mut dyn SecureStore) -> Vec<u8> {
    let mut buf = vec![0u8; chunked::MAX_LOGICAL_LEN];
    match chunked::read_chunked(store, migration::SLOT_OATH, &mut buf) {
        Ok(n) => buf.truncate(n),
        Err(_) => {
            let n = store
                .read(migration::SLOT_OATH, &mut buf)
                .expect("an OATH stream");
            buf.truncate(n);
        }
    }
    buf
}

/// The credential records' `TAG_KEY` values, in slot order. Deliberately a
/// second, independent walk of the stream: a helper that shared
/// `oath_core`'s parser could not catch a bug in that parser.
fn stream_key_values(stream: &[u8]) -> Vec<Vec<u8>> {
    fn tlv(data: &[u8], want: u8) -> Option<Vec<u8>> {
        let mut i = 0;
        while i + 1 < data.len() {
            let tag = data[i];
            let len = data[i + 1] as usize;
            if i + 2 + len > data.len() {
                return None;
            }
            if tag == want {
                return Some(data[i + 2..i + 2 + len].to_vec());
            }
            i += 2 + len;
        }
        None
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + 6 <= stream.len() {
        let fid = u16::from_le_bytes([stream[i], stream[i + 1]]);
        let len = u32::from_le_bytes(stream[i + 2..i + 6].try_into().unwrap()) as usize;
        i += 6;
        if i + len > stream.len() {
            break;
        }
        if (0xBA00..=0xBA43).contains(&fid) {
            if let Some(k) = tlv(&stream[i..i + len], 0x73) {
                out.push(k);
            }
        }
        i += len;
    }
    out
}

fn migrated_oath_store() -> fapico2_platform::secure_store::HostSecureStore {
    let _ = HostTrng::new();
    let flash = fixture_from_stream(&c_oath_plaintext_stream(&OATH_SECRET));
    let mut store = HostSecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    store
}

/// RED 1 — a C-format stream with plaintext OATH keys migrates to sealed.
#[test]
fn c_plaintext_oath_keys_migrate_to_sealed() {
    let mut store = migrated_oath_store();

    // The migration itself is byte-preserving: the C plaintext stream lands
    // on the medium as it was written, which is the defect this story is
    // about. Asserted, so the rest of the test is about the boot re-seal and
    // not about a migration that changed shape.
    let before = oath_stream(&mut store);
    assert!(
        before.windows(OATH_SECRET.len()).any(|w| w == OATH_SECRET),
        "precondition: the migrated stream really is plaintext on the medium"
    );
    assert!(
        !stream_key_values(&before)
            .iter()
            .any(|k| OathSeal::is_sealed(k)),
        "precondition: no key is sealed yet"
    );

    // Boot. The re-seal happens here, inside `boot_in_place`.
    OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        device_id_from_chipid(EMULATION_CHIPID),
        OathSeal::derive(&OTP, UID),
    )
    .expect("a C plaintext credential must still boot");

    let after = oath_stream(&mut store);
    let keys = stream_key_values(&after);
    assert_eq!(keys.len(), 1, "the credential survived the re-seal");
    let seal = OathSeal::derive(&OTP, UID);
    assert!(
        OathSeal::is_sealed(&keys[0]),
        "the migrated credential is not in the sealed form"
    );
    // ... and it is C's form: the magic, the version byte, the nonce and
    // the GCM tag, at C's offsets. A private format would satisfy nothing
    // here and would make a rollback to the C firmware a data-loss event.
    assert_eq!(&keys[0][..4], b"OATH");
    assert_eq!(keys[0][4], 1);
    assert!(OathSeal::nonce_of(&keys[0]).is_some());

    // The plaintext is gone from the medium — not just from the live record.
    let mut image = vec![0u8; 64 * 1024];
    let n = store.snapshot_partition(&mut image).unwrap();
    assert!(
        !image[..n]
            .windows(OATH_SECRET.len())
            .any(|w| w == OATH_SECRET),
        "the plaintext credential key is still in the store image"
    );
    // ... including the plain entry the migration wrote, which the chunked
    // write shadows but does not remove.
    assert!(
        store.read(migration::SLOT_OATH, &mut [0u8; 64]).is_err(),
        "the plaintext migration entry survived the re-seal"
    );

    // And the credential is still the same credential: the sealed blob
    // opens back to exactly the C plaintext key.
    let mut plain = [0u8; 66];
    let n = seal
        .open(&keys[0], &mut plain)
        .expect("the sealed key must open");
    assert_eq!(&plain[..n], &plaintext_key()[..]);

    // And the applet that loaded it boots again off the sealed form — which
    // is the load-bearing half, because `load_stream` **refuses** a sealed
    // record that does not open. A silent success here is not available.
    //
    // The second boot must also be a **fixed point**: an already-sealed
    // store sets no re-seal flag, so nothing is rewritten. That is what
    // keeps this story off the flash-wear budget — a re-seal on every boot
    // would mean a partition program on every boot, and a device that never
    // touches its credentials would pay for it forever.
    let sealed_stream = oath_stream(&mut store);
    let sealed_gen = seal_generation(&mut store);
    OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        device_id_from_chipid(EMULATION_CHIPID),
        OathSeal::derive(&OTP, UID),
    )
    .expect("a sealed credential must boot again");
    assert_eq!(
        oath_stream(&mut store),
        sealed_stream,
        "a boot over an already-sealed store must not rewrite it"
    );
    assert_eq!(seal_generation(&mut store), sealed_gen);
}

/// RED 2 — a mid-read fault refuses rather than serving the plaintext it
/// just read, and the next boot re-seals at a strictly higher generation
/// instead of skipping.
#[test]
fn faulted_read_refuses_and_next_boot_reseals_higher() {    use fapico2_oath::{OathSeal, SLOT_OATH_SEAL_GENERATION};

    /// A store that forwards everything except reads of one named key, which
    /// it answers with a medium fault. This is the shape of the M-1
    /// collapsing read, expressed as the injection seam: a collapsing
    /// implementation would turn this `Flash` into "absent".
    struct Faulty<'a> {
        inner: &'a mut fapico2_platform::secure_store::HostSecureStore,
        fault_on: Vec<u8>,
    }
    impl SecureStore for Faulty<'_> {
        fn write(&mut self, k: &[u8], v: &[u8]) -> Result<(), SecureStoreError> {
            self.inner.write(k, v)
        }
        fn read(&mut self, k: &[u8], out: &mut [u8]) -> Result<usize, SecureStoreError> {
            if k == self.fault_on.as_slice() {
                return Err(SecureStoreError::Flash);
            }
            self.inner.read(k, out)
        }
        fn delete(&mut self, k: &[u8]) -> Result<(), SecureStoreError> {
            self.inner.delete(k)
        }
        fn contains(&self, k: &[u8]) -> bool {
            self.inner.contains(k)
        }
        fn snapshot_partition(&self, b: &mut [u8]) -> Result<usize, SecureStoreError> {
            self.inner.snapshot_partition(b)
        }
        fn snapshot_len(&self) -> usize {
            self.inner.snapshot_len()
        }
        fn snapshot_window(&self, off: usize, b: &mut [u8]) -> usize {
            self.inner.snapshot_window(off, b)
        }
        fn is_empty(&self) -> Result<bool, SecureStoreError> {
            self.inner.is_empty()
        }
        fn is_empty_except(&self, s: &[u8]) -> Result<bool, SecureStoreError> {
            self.inner.is_empty_except(s)
        }
        fn wipe_all(&mut self) -> Result<(), SecureStoreError> {
            self.inner.wipe_all()
        }
        fn store_key(&self) -> Option<[u8; 32]> {
            self.inner.store_key()
        }
    }
    fn generation(store: &mut dyn SecureStore) -> Option<u64> {
        let mut raw = [0u8; 8];
        match store.read(SLOT_OATH_SEAL_GENERATION, &mut raw) {
            Ok(8) => Some(u64::from_be_bytes(raw)),
            _ => None,
        }
    }

    let mut store = migrated_oath_store();
    let before = oath_stream(&mut store);
    let seal = OathSeal::derive(&OTP, UID);
    let dev = device_id_from_chipid(EMULATION_CHIPID);

    // (a) A fault reading the credential stream. A collapsing read would
    // report "no credentials", the applet would boot, and the plaintext
    // would sit on the medium with nothing to re-seal it.
    {
        let mut faulty = Faulty {
            inner: &mut store,
            fault_on: migration::SLOT_OATH.to_vec(),
        };
        let err = OathApp::boot(&mut HostTrng::new(), &mut faulty, dev, seal.clone())
            .err()
            .expect("a faulted stream read must refuse the boot");
        assert!(
            matches!(
                err,
                SecureStoreError::Flash | SecureStoreError::Io | SecureStoreError::Corrupt
            ),
            "the fault was not propagated as a fault: {err:?}"
        );
    }
    assert_eq!(
        oath_stream(&mut store),
        before,
        "a refused boot must leave the store exactly as it found it"
    );
    assert_eq!(generation(&mut store), None, "no counter was written");

    // (b) A fault reading the counter, *after* a successful seal. This is
    // the sharp one: `0` is a generation this device has already spent, so
    // a collapsing read here would re-derive a nonce that was already used
    // on a different plaintext.
    {
        let app = OathApp::boot(&mut HostTrng::new(), &mut store, dev, seal.clone()).unwrap();
        drop(app);
    }
    let after_first = generation(&mut store).expect("the first boot reserved a generation");
    let first_nonce = {
        let k = stream_key_values(&oath_stream(&mut store));
        OathSeal::nonce_of(&k[0]).unwrap()
    };
    {
        let mut faulty = Faulty {
            inner: &mut store,
            fault_on: SLOT_OATH_SEAL_GENERATION.to_vec(),
        };
        // Force a re-seal attempt with the counter unreadable. On the device
        // this is `boot_in_place` on a store whose counter read faults; the
        // path under test is the same one.
        let mut app = OathApp::boot(&mut HostTrng::new(), &mut faulty, dev, seal.clone()).unwrap();
        let err = app
            .reseal(&mut faulty)
            .expect_err("a faulted counter read must refuse");
        assert!(
            matches!(
                err,
                SecureStoreError::Flash | SecureStoreError::Io | SecureStoreError::Corrupt
            ),
            "the counter fault was not propagated: {err:?}"
        );
    }
    assert_eq!(
        generation(&mut store),
        Some(after_first),
        "a refused re-seal must not have moved the counter"
    );

    // (c) The next healthy boot re-seals — it does not skip — and it
    // re-seals *higher*, because the counter it reads is already past the
    // generation whose nonce is in the store.
    {
        let mut app = OathApp::boot(&mut HostTrng::new(), &mut store, dev, seal.clone()).unwrap();
        app.reseal(&mut store).unwrap();
    }
    let after_second = generation(&mut store).expect("the second seal reserved a generation");
    assert!(
        after_second > after_first,
        "the re-seal re-used generations {after_first}..{after_first}"
    );
    let second_nonce = {
        let k = stream_key_values(&oath_stream(&mut store));
        OathSeal::nonce_of(&k[0]).unwrap()
    };
    assert_ne!(
        first_nonce, second_nonce,
        "a re-seal after a faulted read reused the nonce"
    );
}

/// RED 3 — re-sealing the same key twice never reuses a nonce.
#[test]
fn resealing_the_same_key_never_reuses_a_nonce() {    use fapico2_oath::{OathSeal, SLOT_OATH_SEAL_GENERATION};

    let mut store = migrated_oath_store();
    let seal = OathSeal::derive(&OTP, UID);
    let dev = device_id_from_chipid(EMULATION_CHIPID);

    // Boot 1: the migration's plaintext is sealed at generation 1.
    let mut app = OathApp::boot(&mut HostTrng::new(), &mut store, dev, seal.clone()).unwrap();
    let n1 = OathSeal::nonce_of(&stream_key_values(&oath_stream(&mut store))[0]).unwrap();
    let g1 = {
        let mut raw = [0u8; 8];
        store.read(SLOT_OATH_SEAL_GENERATION, &mut raw).unwrap();
        u64::from_be_bytes(raw)
    };

    // Re-seal the *unchanged* key. This is the case `store_v3`'s
    // content-hash nonce cannot survive: the content is identical, so a
    // content-derived nonce would be identical too.
    app.reseal(&mut store).unwrap();
    let n2 = OathSeal::nonce_of(&stream_key_values(&oath_stream(&mut store))[0]).unwrap();
    let g2 = {
        let mut raw = [0u8; 8];
        store.read(SLOT_OATH_SEAL_GENERATION, &mut raw).unwrap();
        u64::from_be_bytes(raw)
    };

    assert_ne!(n1, n2, "re-sealing the same key reused its nonce");
    assert_eq!(g2, g1 + 1, "the generation did not advance by exactly one");
    // The record still opens to the C plaintext — this is a re-seal, not a
    // re-key. That equality is exactly why a *repeated* nonce here would
    // be survivable in GCM terms, and it is why the assertion above has to
    // be about the nonce: the plaintext cannot tell the two cases apart.
    let mut plain = [0u8; 66];
    let n = seal
        .open(&stream_key_values(&oath_stream(&mut store))[0], &mut plain)
        .unwrap();
    assert_eq!(&plain[..n], &plaintext_key()[..]);

    // A different credential at the same generation index must not collide
    // with the first one's nonce either — the nonce binds the fid as well
    // as the generation, so the two-slot REUSE story cannot reappear through
    // a delete/put cycle.
    let other = seal.nonce_for(0xBA01, 1);
    assert_ne!(other, seal.nonce_for(0xBA00, 1));
}
