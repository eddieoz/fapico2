//! US-1003 — the DRBG is seeded **from the fuses, on demand**, and it fails
//! closed when the seed cannot be produced.
//!
//! The contract this file pins, and the reason each pin exists:
//!
//! * **Fail-closed, no legacy fallback.** A store whose `boot.entropy.v1`
//!   record has been deleted produces *no* DRBG. The OTP key row alone is
//!   not a seed — the OTP row is readable from any code on the board
//!   (`ckey`'s US-918 rationale), so a seed built from it alone would be a
//!   seed an attacker holding the OTP row already knows. The refusal is
//!   [`CKeyError::MissingBootEntropy`], the same refusal the bound device
//!   root uses, and there is no path in this file that produces bytes
//!   without the record.
//! * **The seed is re-read, never cached.** Two seeds from one store are
//!   two store reads: the test asserts the read *count*, not just that two
//!   seeds happen to differ, because a cached seed would also "happen to
//!   differ" from a differently-configured expectation.
//! * **The seed is never a struct field.** The whole point of the
//!   `FusedKey`-closure shape RS-Key uses is that a memory-disclosure bug
//!   finds nothing, because the OTP window is not RAM. A `Drbg` that held
//!   its seed would hand the whole key hierarchy to whoever dumped the
//!   stack. [`size_of::<Drbg>`] is asserted unchanged for that reason.
//! * **A failed re-seed is atomic.** A source that refuses leaves the
//!   generator exactly as it was — and, at exhaustion, still refusing.

use core::mem::size_of;

use fapico2_platform::ckey::{
    self, derive_kbase, CKeyError, BOOT_ENTROPY_LEN, KEY_LEN, SERIAL_HASH_LEN,
};
use fapico2_platform::drbg::{
    Drbg, DrbgError, SeedError, SeedMaterial, SeedSource, NONCE_LEN, OUTLEN,
};
use fapico2_platform::drbg_seed::FuseSeedSource;
use fapico2_platform::migration::SLOT_BOOT_ENTROPY;
use fapico2_platform::secure_store::{SecureStore, SecureStoreError};
use fapico2_platform::trng::{
    EntropyClock, ProbeStatus, TrngError, TrngProbe, MAX_ENTROPY_WAIT,
};

/// A wall clock that **counts**, one tick per status read.
///
/// # Why it is live rather than frozen
///
/// It used to be frozen, on the reasoning that a frozen clock is "the
/// strictest way to ask" whether a wedged peripheral refuses. That stopped
/// being true once `await_ready` learned to check its own clock
/// (`CLOCK_LIVENESS_SPINS`): a frozen clock now ends the wait at the
/// liveness bound *before the peripheral has been meaningfully polled*, so a
/// frozen clock in this file would quietly have turned every one of these
/// tests into a test of the clock instead of a test of the seed path.
///
/// These tests are about the seed path: a wedged peripheral must produce
/// `Err`, atomically, and never a generator. That refusal has to be reached
/// by a wait that really did poll the peripheral, which needs a clock that is
/// counting — which is also the realistic device shape. The clock's own
/// failure is covered where it belongs, in `trng_clock_precondition.rs`.
struct TickingClock {
    now: u64,
}

impl TickingClock {
    const fn new() -> Self {
        Self { now: 0 }
    }
}

impl EntropyClock for TickingClock {
    fn ticks(&self) -> u64 {
        self.now
    }
}


const OTP_KEY_1_HEX: &str =
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
const UID_HEX: &str = "0102030405060708";
const CHIPID: u64 = 0x0102_0304_0506_0708;

/// An interval long enough that no test in this file exhausts it by
/// accident; the boundary itself is US-1004's file.
const NEVER: u64 = 1 << 20;

/// The record a healthy device carries, written by
/// `firmware::boot::ensure_boot_entropy` on first boot.
const ENTROPY: [u8; BOOT_ENTROPY_LEN] = [0xA5u8; BOOT_ENTROPY_LEN];

fn h(s: &str) -> std::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// Test double: the entropy peripheral
// ---------------------------------------------------------------------------

/// Host stand-in for the RP2350 TRNG, in the `trng_wedge.rs` house style: a
/// scripted status plus a poll count, so a test can assert that a wait was
/// *bounded* rather than merely that it ended.
///
/// Three knobs, because the three things a seed path must be shown to do are
/// different: a peripheral that works (so the happy path is reachable), one
/// that has wedged (so the refusal is reachable), and one that hands back a
/// *chosen* block (so a test can show the draw is actually mixed into the
/// generator rather than merely carried alongside it).
struct ScriptedProbe {
    status: ProbeStatus,
    /// The block `read_into` stamps. A counter makes two draws on the same
    /// probe differ, which is the honest stand-in for a real peripheral: two
    /// blocks from the ring oscillators are not equal.
    counter: u8,
    /// Set to stamp a constant instead, and to zero, to stand in for a
    /// peripheral that reports success and delivers nothing.
    fixed: Option<u8>,
    polls: u32,
    draws: u32,
    /// Live: see [`TickingClock`].
    clock: TickingClock,
}

impl ScriptedProbe {
    /// A peripheral that reports `status` on every poll and never becomes
    /// ready — the wedged case.
    fn wedged(status: ProbeStatus) -> Self {
        Self {
            status,
            counter: 0,
            fixed: None,
            polls: 0,
            draws: 0,
            clock: TickingClock::new(),
        }
    }

    /// A healthy peripheral: `Ready` on the first poll, a fresh block every
    /// draw.
    fn healthy() -> Self {
        Self {
            status: ProbeStatus::Ready,
            counter: 0,
            fixed: None,
            polls: 0,
            draws: 0,
            clock: TickingClock::new(),
        }
    }

    /// A healthy peripheral that always delivers the *same* block. Used to
    /// show the draw is load-bearing: same draw ⇒ same generator, different
    /// draw ⇒ different generator. That pair is what distinguishes "mixed
    /// in" from "stored and ignored".
    fn fixed(byte: u8) -> Self {
        Self {
            status: ProbeStatus::Ready,
            counter: 0,
            fixed: Some(byte),
            polls: 0,
            draws: 0,
            clock: TickingClock::new(),
        }
    }
}

impl TrngProbe for ScriptedProbe {
    fn status(&mut self) -> ProbeStatus {
        self.polls += 1;
        self.clock.now += 1;
        self.status
    }

    fn read_block(&mut self, block: &mut [u8]) {
        self.draws += 1;
        match self.fixed {
            Some(b) => block.fill(b),
            None => {
                for (i, slot) in block.iter_mut().enumerate() {
                    *slot = self.counter.wrapping_add(i as u8);
                }
                self.counter = self.counter.wrapping_add(1);
            }
        }
    }

    fn read_into(&mut self, buf: &mut [u8]) -> Result<(), TrngError> {
        if buf.is_empty() {
            return Ok(());
        }
        self.await_ready()?;
        self.read_block(buf);
        Ok(())
    }

    fn source_enable(&mut self) {}

    fn source_disable(&mut self) {}

    fn clock(&mut self) -> &mut dyn EntropyClock {
        &mut self.clock
    }
}

/// Owns the two non-store inputs a `FuseSeedSource` borrows, so a test can
/// hold the source across several statements. The source holds
/// *references*: a fuse row is not RAM, and copying it into a struct would
/// be the thing this file exists to prevent.
struct Device {
    otp: [u8; KEY_LEN],
    uid: [u8; 8],
}

impl Device {
    fn provisioned() -> Self {
        Self {
            otp: h(OTP_KEY_1_HEX).try_into().unwrap(),
            uid: h(UID_HEX).try_into().unwrap(),
        }
    }

    /// A device the C firmware never initialized: an all-zero OTP row.
    fn never_booted() -> Self {
        Self {
            otp: [0u8; KEY_LEN],
            uid: h(UID_HEX).try_into().unwrap(),
        }
    }

    fn source<'a>(
        &'a self,
        store: &'a mut MemStore,
        probe: &'a mut ScriptedProbe,
    ) -> FuseSeedSource<'a, MemStore, ScriptedProbe> {
        FuseSeedSource::new(&self.otp, &self.uid, store, probe)
    }

    fn seed(
        &self,
        store: &mut MemStore,
        probe: &mut ScriptedProbe,
    ) -> Result<SeedMaterial, SeedError> {
        let mut src = self.source(store, probe);
        src.seed()
    }

    fn drbg(
        &self,
        store: &mut MemStore,
        probe: &mut ScriptedProbe,
        interval: u64,
    ) -> Result<Drbg, SeedError> {
        let mut src = self.source(store, probe);
        Drbg::seed_from(&mut src, interval)
    }
}

// ---------------------------------------------------------------------------
// Test double
// ---------------------------------------------------------------------------

/// In-memory `SecureStore` with the two things the seed path needs: a
/// readable/deletable slot, and a count of how many times it was read.
///
/// `read_fails` injects a medium-level failure, which is a *different*
/// refusal from an absent record and must stay distinguishable — an absent
/// record says "this store was never provisioned", an I/O error says "this
/// store cannot be trusted right now", and a caller that conflates them
/// cannot tell a fresh device from a failing one.
struct MemStore {
    slots: heapless::Vec<(heapless::Vec<u8, 48>, heapless::Vec<u8, 64>), 8>,
    reads: usize,
    read_fails: bool,
}

impl MemStore {
    fn new() -> Self {
        Self {
            slots: heapless::Vec::new(),
            reads: 0,
            read_fails: false,
        }
    }

    /// A store already carrying a valid record, with the provisioning write
    /// excluded from the read count.
    fn provisioned() -> Self {
        let mut s = Self::new();
        s.write(SLOT_BOOT_ENTROPY, &ENTROPY).unwrap();
        s.reads = 0;
        s
    }

    fn find(&self, key: &[u8]) -> Option<usize> {
        self.slots.iter().position(|(k, _)| k.as_slice() == key)
    }
}

impl SecureStore for MemStore {
    fn write(&mut self, key: &[u8], value: &[u8]) -> Result<(), SecureStoreError> {
        let mut v = heapless::Vec::new();
        v.extend_from_slice(value)
            .map_err(|_| SecureStoreError::ValueTooLong)?;
        match self.find(key) {
            Some(i) => self.slots[i].1 = v,
            None => self
                .slots
                .push((key.try_into().map_err(|_| SecureStoreError::KeyTooLong)?, v))
                .map_err(|_| SecureStoreError::Full)?,
        }
        Ok(())
    }

    fn read(&mut self, key: &[u8], out: &mut [u8]) -> Result<usize, SecureStoreError> {
        self.reads += 1;
        if self.read_fails {
            return Err(SecureStoreError::Io);
        }
        let i = self.find(key).ok_or(SecureStoreError::NotFound)?;
        let v = &self.slots[i].1;
        if v.len() > out.len() {
            return Err(SecureStoreError::Full);
        }
        out[..v.len()].copy_from_slice(v);
        Ok(v.len())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), SecureStoreError> {
        let i = self.find(key).ok_or(SecureStoreError::NotFound)?;
        self.slots.remove(i);
        Ok(())
    }

    fn contains(&self, key: &[u8]) -> bool {
        self.find(key).is_some()
    }

    // The seed path only reads. Snapshotting is the persist gate's business;
    // an unimplemented body says so rather than inventing a fake image.
    fn snapshot_partition(&self, _buf: &mut [u8]) -> Result<usize, SecureStoreError> {
        unimplemented!("the DRBG seed path never snapshots the store")
    }
    fn snapshot_len(&self) -> usize {
        unimplemented!("the DRBG seed path never snapshots the store")
    }
    fn snapshot_window(&self, _off: usize, _buf: &mut [u8]) -> usize {
        unimplemented!("the DRBG seed path never snapshots the store")
    }
    fn is_empty(&self) -> Result<bool, SecureStoreError> {
        Ok(self.slots.is_empty())
    }
    fn is_empty_except(&self, slot: &[u8]) -> Result<bool, SecureStoreError> {
        Ok(self.slots.iter().all(|(k, _)| k.as_slice() == slot))
    }
    fn wipe_all(&mut self) -> Result<(), SecureStoreError> {
        self.slots.clear();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// (1) The happy path: a provisioned device produces a working generator.
// ---------------------------------------------------------------------------

/// The seed derivation is pinned against an independent HKDF-SHA256
/// (Python `hmac`, RFC 5869 — the same implementation that produced
/// `ckey`'s `DEVICE/ROOT` vector, so the two agree on the KDF and differ
/// only in the `info` label):
///
///   ikm  = otp_key_1,  salt = serial_hash(32) ‖ chipid BE(8) ‖ 32 × 0xA5,
///   info = "DRBG/SEED"
const SEED_VECTOR: &str = "8f13fa3a2788ed98c2e4ab87cb9d4c88232f4a82bddd3eb1c39e00850776fb4b";

#[test]
fn a_device_with_a_valid_record_produces_a_working_drbg() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::healthy();

    // The derivation itself, pinned. Note the probe: the *fuse half* of the
    // seed is still a deterministic function of its four inputs — it is a
    // key, and a key is supposed to be reproducible. What the probe adds is
    // the second half, which is not this vector.
    assert_eq!(
        device.seed(&mut store, &mut probe).unwrap().seed.as_slice(),
        h(SEED_VECTOR).as_slice(),
        "the fused key half must match the independent HKDF vector"
    );

    // And end to end: a generator built from that source serves bytes.
    let mut drbg = device.drbg(&mut store, &mut probe, NEVER).unwrap();
    let mut out = [0u8; OUTLEN];
    drbg.generate(&mut out).unwrap();
    assert_ne!(out, [0u8; OUTLEN], "a seeded DRBG must produce non-zero output");
}

/// RED (C-1). The seed must **not** be reproducible across two draws. The
/// three fuse-side inputs are constant for the life of the device, so a seed
/// made only from them is a *key*, not entropy: every warm boot would derive
/// the same generator state and the first nonce of a session would repeat the
/// first nonce of the previous boot. S-4 forbids repeating nonces; two
/// signatures sharing an ECDSA *k* is private-key recovery.
#[test]
fn the_seed_is_not_reproducible_across_draws() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::healthy();
    let a = device.seed(&mut store, &mut probe).unwrap();
    let b = device.seed(&mut store, &mut probe).unwrap();
    assert_ne!(
        a.halves(),
        b.halves(),
        "two seeds from one store must differ: a seed that repeats across \
         sessions repeats the nonce, and a repeated ECDSA nonce recovers the \
         private key"
    );
    assert_eq!(a.seed.len(), OUTLEN);
    assert_eq!(a.nonce.len(), NONCE_LEN);
}

/// The precise statement of what varies and what does not. The **fuse half**
/// stays byte-identical — it is a key, bound to this board, and reproducibility
/// is its job. The **draw** is what changes, every call. Without this split a
/// future edit that "optimised" the derivation into a cache would still pass
/// the non-reproducibility test above, because the probe would paper over it.
#[test]
fn only_the_draw_varies_the_fuse_half_stays_pinned_to_the_board() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::healthy();

    let a = device.seed(&mut store, &mut probe).unwrap();
    let b = device.seed(&mut store, &mut probe).unwrap();

    assert_eq!(
        a.seed.as_slice(),
        b.seed.as_slice(),
        "the fuse-derived key is a key: it must stay bound to this board and \
         must not drift with the draw"
    );
    assert_ne!(
        a.nonce.as_slice(),
        b.nonce.as_slice(),
        "the draw is the entropy: it must be fresh on every seed"
    );
}

// ---------------------------------------------------------------------------
// (2) The fail-closed contract.
// ---------------------------------------------------------------------------

/// **The story in one test.** Delete the record and the device produces
/// *nothing* — not a DRBG seeded from the OTP row alone, which is the
/// fallback the EPIC forbids and the one that would hand out a keystream
/// anyone holding a leaked OTP row could already compute.
#[test]
fn a_store_with_the_record_deleted_refuses() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::healthy();
    store.delete(SLOT_BOOT_ENTROPY).unwrap();
    assert!(!store.contains(SLOT_BOOT_ENTROPY));

    assert_eq!(
        device.seed(&mut store, &mut probe).err(),
        Some(SeedError::CKey(CKeyError::MissingBootEntropy)),
        "a store with no boot-entropy record must refuse, not fall back to \
         the OTP row alone"
    );

    // And the same refusal one level up: no `Drbg` is constructed.
    assert!(device.drbg(&mut store, &mut probe, NEVER).is_err());
}

/// A record of the wrong length is corrupt media, not an absent record, and
/// the two refusals must not be conflated: the first says "provision me",
/// the second says "this store cannot be trusted".
#[test]
fn a_corrupt_record_refuses_without_guessing() {
    let device = Device::provisioned();
    let mut store = MemStore::new();
    let mut probe = ScriptedProbe::healthy();
    store.write(SLOT_BOOT_ENTROPY, &[0xA5u8; 16]).unwrap();
    assert_eq!(
        device.seed(&mut store, &mut probe).err(),
        Some(SeedError::CKey(CKeyError::BadLength)),
        "a short record is corrupt, never padded up to BOOT_ENTROPY_LEN"
    );
}

/// A store that cannot be read right now refuses; it does not degrade into
/// "as if the record were absent" (which would read as a fresh device) and
/// it does not serve from a cached seed.
#[test]
fn an_unreadable_store_refuses() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::healthy();
    store.read_fails = true;
    assert_eq!(
        device.seed(&mut store, &mut probe).err(),
        Some(SeedError::Store(SecureStoreError::Io))
    );
}

/// An all-zero OTP row is a device the C firmware never initialized
/// (`NeverBootC`, US-918). The seed refuses it with **its own** error even
/// when the record is present, so the error names the real fault rather than
/// a downstream symptom of a missing one — and with both faults present the
/// OTP row is still the one reported, because `derive_drbg_seed` checks it
/// first (the same ordering `ckey` pins for `derive_kbase`).
#[test]
fn an_uninitialized_device_refuses_with_its_own_error() {
    let device = Device::never_booted();
    let mut provisioned = MemStore::provisioned();
    let mut probe = ScriptedProbe::healthy();
    assert_eq!(
        device.seed(&mut provisioned, &mut probe).err(),
        Some(SeedError::CKey(CKeyError::NeverBootC)),
        "a valid record must not paper over an uninitialized OTP row"
    );

    let mut bare = MemStore::new();
    assert_eq!(
        device.seed(&mut bare, &mut probe).err(),
        Some(SeedError::CKey(CKeyError::NeverBootC)),
        "the OTP row is checked before the absent record is reported"
    );
}

/// A record that is present, correctly sized, and carries **no entropy** —
/// an erased or zeroized slot. Every US-918 length rule waves this through,
/// and it is the worst case of the three: a constant seed, so a keystream
/// an attacker computes offline without ever touching the device. Seeding
/// from it is strictly worse than having no record at all, which at least
/// refuses.
#[test]
fn a_zeroed_record_refuses_rather_than_seeding_from_a_constant() {
    let device = Device::provisioned();
    let mut store = MemStore::new();
    let mut probe = ScriptedProbe::healthy();
    store.write(SLOT_BOOT_ENTROPY, &[0u8; BOOT_ENTROPY_LEN]).unwrap();

    assert_eq!(
        device.seed(&mut store, &mut probe).err(),
        Some(SeedError::DepletedBootEntropy),
        "an all-zero record must not produce a seed"
    );
    assert!(
        device.drbg(&mut store, &mut probe, NEVER).is_err(),
        "and it must not produce a generator either"
    );

    // One non-zero byte is enough: the refusal is about a *constant* seed,
    // not about a quality threshold this crate cannot measure.
    let mut nearly_empty = [0u8; BOOT_ENTROPY_LEN];
    nearly_empty[BOOT_ENTROPY_LEN - 1] = 0x01;
    store.write(SLOT_BOOT_ENTROPY, &nearly_empty).unwrap();
    assert!(device.seed(&mut store, &mut probe).is_ok());
}

/// A flash UID too short to carry the chipid refuses rather than
/// zero-padding it into some other device's identity.
#[test]
fn a_short_uid_refuses() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let short: [u8; 4] = [0u8; 4];
    let mut probe = ScriptedProbe::healthy();
    let mut src = FuseSeedSource::new(&device.otp, &short, &mut store, &mut probe);
    assert_eq!(src.seed().err(), Some(SeedError::CKey(CKeyError::BadLength)));
}

// ---------------------------------------------------------------------------
// (3) On demand, not cached.
// ---------------------------------------------------------------------------

/// The record is read **once per seed**, never held. The count is the
/// assertion: a cached seed would produce identical outputs while reading
/// once, and only the read count distinguishes the two.
#[test]
fn the_record_is_re_read_on_every_seed_not_cached() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::healthy();

    let first = device.seed(&mut store, &mut probe).unwrap();
    assert_eq!(store.reads, 1, "one seed is one store read");

    let second = device.seed(&mut store, &mut probe).unwrap();
    assert_eq!(store.reads, 2, "a second seed must be a second store read");
    assert_ne!(
        first.halves(),
        second.halves(),
        "the record is a fixed persisted value, so it alone cannot make the \
         seed differ: the fresh draw mixed in on top is what makes it differ"
    );

    // Change the record, seed again: the seed must follow it. A cached seed
    // would be blind to the change. Compared against `first`'s *key* half,
    // because the draw differs on every seed and would mask the result.
    store
        .write(SLOT_BOOT_ENTROPY, &[0x5Au8; BOOT_ENTROPY_LEN])
        .unwrap();
    let third = device.seed(&mut store, &mut probe).unwrap();
    assert_eq!(store.reads, 3);
    assert_ne!(
        first.seed.as_slice(),
        third.seed.as_slice(),
        "a re-read must observe the record, so a changed record changes the seed"
    );
}

/// The mirror of the read count, on the peripheral: **one probe per seed**,
/// not one at instantiate and never again. A re-seed that reused a cached
/// draw would be entropy-neutral — the exact defect the draw was added to
/// close, reappearing one layer up.
#[test]
fn a_fresh_draw_is_taken_on_every_seed_not_cached() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::healthy();

    assert_eq!(
        device.seed(&mut store, &mut probe).unwrap().nonce.len(),
        NONCE_LEN
    );
    assert_eq!(probe.draws, 1, "one seed is one peripheral draw");

    let mut drbg = device.drbg(&mut store, &mut probe, NEVER).unwrap();
    assert_eq!(probe.draws, 2, "instantiating again must draw again");

    drbg.reseed_from(&mut device.source(&mut store, &mut probe))
        .unwrap();
    assert_eq!(
        probe.draws, 3,
        "a re-seed must draw again, not reuse the previous block"
    );

    // A re-seed refused for an *in-process* reason must not reach the
    // peripheral at all: the fault was already knowable, and a stalled draw
    // on top of it would report the wrong thing to the operator.
    store.delete(SLOT_BOOT_ENTROPY).unwrap();
    let counter_before = drbg.reseed_counter();
    assert!(drbg
        .reseed_from(&mut device.source(&mut store, &mut probe))
        .is_err());
    assert_eq!(
        probe.draws, 3,
        "a refusal that needed no hardware must spend no draw"
    );
    assert_eq!(drbg.reseed_counter(), counter_before);

    // And one refused *by* the peripheral consults it, and is still atomic:
    // the poll count proves the peripheral was reached, the counter proves
    // nothing was applied.
    store.write(SLOT_BOOT_ENTROPY, &ENTROPY).unwrap();
    let mut dead = ScriptedProbe::wedged(ProbeStatus::AutocorrErr);
    let counter_before = drbg.reseed_counter();
    assert_eq!(
        drbg.reseed_from(&mut device.source(&mut store, &mut dead))
            .err(),
        Some(SeedError::Trng(TrngError::Stalled))
    );
    assert_eq!(
        dead.polls as u64, MAX_ENTROPY_WAIT,
        "the wait is still bounded — it spent the whole budget and stopped"
    );
    assert_eq!(dead.draws, 0, "a stalled peripheral delivers no block");
    assert_eq!(
        drbg.reseed_counter(),
        counter_before,
        "a refused re-seed must apply nothing, whatever refused it"
    );
}

// ---------------------------------------------------------------------------
// (4) Binding and domain separation.
// ---------------------------------------------------------------------------

/// The seed is bound to the board and to the fuse row, exactly like the
/// device root. Two devices with the same leaked OTP row must not derive
/// the same generator.
#[test]
fn the_seed_is_bound_to_the_chipid_and_the_fuse_row() {
    let otp: [u8; KEY_LEN] = h(OTP_KEY_1_HEX).try_into().unwrap();
    let serial: [u8; SERIAL_HASH_LEN] = ckey::serial_hash(&h(UID_HEX));

    let seed = ckey::derive_drbg_seed(&otp, &serial, CHIPID, Some(&ENTROPY)).unwrap();
    let other_chip =
        ckey::derive_drbg_seed(&otp, &serial, 0x090a_0b0c_0d0e_0f10, Some(&ENTROPY)).unwrap();
    let mut other_row = otp;
    other_row[0] ^= 0x01;
    let other_row = ckey::derive_drbg_seed(&other_row, &serial, CHIPID, Some(&ENTROPY)).unwrap();
    assert_ne!(seed, other_chip, "the chipid must be load-bearing");
    assert_ne!(seed, other_row, "the OTP key row must be load-bearing");
}

/// The DRBG seed is **not** the device root. They share their input
/// material, so only the `info` label separates them; without the label a
/// compromise of one would be a compromise of the other, and every key
/// this device ever derives would be one HKDF away from the keystream.
#[test]
fn the_seed_is_domain_separated_from_the_device_root() {
    let otp: [u8; KEY_LEN] = h(OTP_KEY_1_HEX).try_into().unwrap();
    let serial: [u8; SERIAL_HASH_LEN] = ckey::serial_hash(&h(UID_HEX));

    let seed = ckey::derive_drbg_seed(&otp, &serial, CHIPID, Some(&ENTROPY)).unwrap();
    let root = derive_kbase(&otp, &serial, CHIPID, Some(&ENTROPY)).unwrap();
    assert_ne!(
        seed, root,
        "identical input material must still derive two unrelated values"
    );
    // The seed inherits the device root's fail-closed rule verbatim.
    assert_eq!(
        ckey::derive_drbg_seed(&otp, &serial, CHIPID, None),
        Err(CKeyError::MissingBootEntropy)
    );
    // ...and adds the one rule the device root does not need: a record that
    // is *present but all zero* is a constant key, and a constant key is
    // fatal for a generator. M-2: the check is inside the derivation, so a
    // direct caller of `derive_drbg_seed` cannot bypass it the way a direct
    // caller bypassed it before.
    assert_eq!(
        ckey::derive_drbg_seed(&otp, &serial, CHIPID, Some(&[0u8; BOOT_ENTROPY_LEN])),
        Err(CKeyError::DepletedBootEntropy),
        "a direct caller of the derivation must not be able to skip the \
         all-zero refusal that the prose above it claims"
    );
    // The bound root deliberately does NOT take that check — a constant key
    // is merely degenerate for a root, and the two derivations have
    // different security properties. Pinned so the difference is a decision
    // rather than an accident.
    assert!(derive_kbase(&otp, &serial, CHIPID, Some(&[0u8; BOOT_ENTROPY_LEN])).is_ok());
}

// ---------------------------------------------------------------------------
// (5) The seed is transient.
// ---------------------------------------------------------------------------

/// The structural invariant, asserted on the type: US-1003 added **no
/// field** to `Drbg`. 80 bytes is two 32-byte state words plus the two
/// `u64` counters, and it is what it was before the seeding story landed.
/// A field here would be seed material sitting in RAM for the life of the
/// generator, which is the outcome RS-Key's `FusedKey` closure exists to
/// make impossible.
#[test]
fn the_drbg_struct_gained_no_seed_field() {
    assert_eq!(
        size_of::<Drbg>(),
        2 * OUTLEN + 2 * size_of::<u64>(),
        "Drbg must stay k ‖ v ‖ reseed_counter ‖ reseed_interval — no seed field"
    );
}

/// The same invariant on the other half, stated in the type's own terms so
/// the expected size follows from the fields rather than from a number
/// somebody measured: a thin `&[u8; 32]` to the OTP row, a fat `&[u8]` to
/// the flash UID, a thin `&mut K` to the store, and a thin `&mut P` to the
/// peripheral. All four borrowed.
///
/// A fifth field holding the OTP row **by value** would look harmless — it
/// is a fuse window, not RAM — right up until the moment it is copied into a
/// struct that does live in RAM. That 32 bytes is exactly the gap between
/// this size and `this size + 32`, and it is the difference the EPIC's "the
/// OTP window is not RAM" line is actually about. Pinned here rather than
/// left to the type signature to imply.
///
/// The fourth borrow is C-1 made structural. Before it, a `FuseSeedSource`
/// could be built with no reference to hardware entropy at all, which is
/// precisely the shape that made the generator identical across boots. The
/// size assertion is the cheap half of that: the type parameter is the half
/// that cannot be written out of by accident.
#[test]
fn the_seed_source_holds_references_and_nothing_else() {
    assert_eq!(
        size_of::<FuseSeedSource<MemStore, ScriptedProbe>>(),
        size_of::<&[u8; KEY_LEN]>()
            + size_of::<&[u8]>()
            + size_of::<&MemStore>()
            + size_of::<&ScriptedProbe>(),
        "FuseSeedSource must stay &otp_key_1 ‖ &uid ‖ &mut store ‖ &mut probe \
         — no owned key material, no cached seed, and no reachable \
         constructor that omits the peripheral"
    );
}

/// `Debug` is the other way a secret escapes a struct field, so the
/// generator's own formatting is pinned to the exact opaque shape it is
/// supposed to have.
///
/// **This can actually fail**, which the previous version of it could not:
/// it asserted only that the rendering did not contain the seed's hex, and
/// since `Debug` prints neither `Key` nor `V` that held by construction and
/// would still have held after someone added a field carrying a secret. The
/// exact-shape assertion fails on an added field, on a field rename, and on
/// a switch away from `finish_non_exhaustive`.
///
/// The seed-substring check is **retained as a regression pin**, and is
/// labelled as such: it is a cheap backstop, not the evidence.
#[test]
fn the_drbg_debug_rendering_is_exactly_the_opaque_shape() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::healthy();
    let drbg = device.drbg(&mut store, &mut probe, NEVER).unwrap();
    let rendered = std::format!("{drbg:?}");

    assert_eq!(
        rendered,
        std::format!("Drbg {{ reseed_counter: 1, reseed_interval: {NEVER}, .. }}"),
        "the Debug rendering must stay exactly the two non-secret counters, \
         with everything else elided"
    );

    // Regression pin, not evidence: `Debug` prints no key material today, so
    // this cannot fail. It is here so that a future `Debug` that starts
    // printing `k` or `v` in hex fails here first and with a better message
    // than the shape assertion above.
    let material = device.seed(&mut store, &mut probe).unwrap();
    for (label, bytes) in [("seed", &material.seed[..]), ("draw", &material.nonce[..])] {
        let hex: std::string::String =
            bytes.iter().map(|b| std::format!("{b:02X}")).collect();
        assert!(
            !rendered.to_uppercase().contains(&hex),
            "the Debug rendering must not contain the {label}: {rendered}"
        );
    }
}

// ---------------------------------------------------------------------------
// (5b) The draw is load-bearing (C-1).
// ---------------------------------------------------------------------------

/// The test that distinguishes "the draw is mixed in" from "the draw is
/// carried alongside and ignored". Both halves are asserted, and neither
/// alone would be evidence:
///
/// * **same draw ⇒ same generator.** If this failed, something *other* than
///   the draw were varying — an uncounted clock, an address, a cached seed —
///   and the determinism the DRBG is *supposed* to have given it would be
///   gone as well.
/// * **different draw ⇒ different generator.** If this failed, the draw is
///   being read, checked for non-zero, and then discarded — which is what
///   "not merely stored" means.
///
/// The second is the security property. The first is what makes it evidence.
#[test]
fn the_draw_is_mixed_into_the_generator_not_merely_carried() {
    let device = Device::provisioned();

    let mut first = {
        let mut store = MemStore::provisioned();
        let mut probe = ScriptedProbe::fixed(0x11);
        device.drbg(&mut store, &mut probe, NEVER).unwrap()
    };
    let mut same_draw = {
        let mut store = MemStore::provisioned();
        let mut probe = ScriptedProbe::fixed(0x11);
        device.drbg(&mut store, &mut probe, NEVER).unwrap()
    };
    let mut other_draw = {
        let mut store = MemStore::provisioned();
        let mut probe = ScriptedProbe::fixed(0x22);
        device.drbg(&mut store, &mut probe, NEVER).unwrap()
    };

    let block = |d: &mut Drbg| {
        let mut out = [0u8; OUTLEN];
        d.generate(&mut out).unwrap();
        out
    };

    assert_eq!(
        block(&mut first),
        block(&mut same_draw),
        "identical draws over identical material must give an identical \
         generator: if they did not, the draw would not be the only thing \
         varying"
    );
    assert_ne!(
        block(&mut first),
        block(&mut other_draw),
        "a one-byte change in the draw must change the generator's output — \
         otherwise the draw is read and thrown away, and every warm boot \
         replays the same first block"
    );
}

/// **The defect, stated as a test.** Two "boots" of the same provisioned
/// device — same OTP row, same chipid, same (never-refreshed) entropy record
/// — must not produce the same first block. This is the assertion the
/// pre-review code inverted: it asserted the two were *equal*, which is
/// exactly the ECDSA nonce reuse that recovers the private key.
#[test]
fn two_warm_boots_do_not_replay_the_same_first_block() {
    let device = Device::provisioned();
    // One store and one peripheral, as a real device has: the same sealed
    // NOR image, the same fuse window, the same chip — booted twice. The
    // peripheral is the only thing that moves between the two, which is
    // exactly the point.
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::healthy();

    let mut boot_one = device.drbg(&mut store, &mut probe, NEVER).unwrap();
    let mut boot_two = device.drbg(&mut store, &mut probe, NEVER).unwrap();

    let mut first = [0u8; OUTLEN];
    let mut second = [0u8; OUTLEN];
    boot_one.generate(&mut first).unwrap();
    boot_two.generate(&mut second).unwrap();

    assert_ne!(
        first, second,
        "every input the fuse seed depends on is constant for the life of the \
         device, so a boot that replays the previous boot's first block is \
         reusing an ECDSA nonce — which is private-key recovery (S-4)"
    );
}

// ---------------------------------------------------------------------------
// (5c) A wedged peripheral refuses (C-1, the no-fallback half).
// ---------------------------------------------------------------------------

/// A peripheral reporting `AUTOCORR_ERR` forever: the RP2350's own
/// documentation says the RNG "ceases functioning until next reset", so
/// there is no convergence to wait for. Seeding must **refuse**.
///
/// The direct analogue of `trng_wedge.rs`, applied one layer up. The
/// `trng_wedge` tests show the *wait* is bounded; this shows the *seed path*
/// treats a bounded stall as fatal rather than as something to route around.
#[test]
fn a_wedged_peripheral_refuses_to_seed_rather_than_falling_back_to_the_fuses() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::wedged(ProbeStatus::AutocorrErr);

    assert_eq!(
        device.seed(&mut store, &mut probe).err(),
        Some(SeedError::Trng(TrngError::Stalled)),
        "a peripheral that will not produce a block must refuse to seed"
    );
    assert_eq!(
        probe.polls as u64, MAX_ENTROPY_WAIT,
        "the refusal must arrive when the bounded wait expires, not hang"
    );
    assert_eq!(probe.draws, 0, "a stalled peripheral delivers no block");

    // Same device, same dead peripheral: no generator either. The fuse seed
    // is not a fallback — it is the defect.
    assert!(
        device.drbg(&mut store, &mut probe, NEVER).is_err(),
        "a wedged peripheral must produce NO generator"
    );
}

/// The other wedge branch, for the same reason `trng_wedge.rs` tests both: a
/// loop that special-cased `AutocorrErr` and gave up early on
/// `InvalidEhr` would pass the test above and be wrong.
#[test]
fn the_other_invalid_ehr_branch_also_refuses_to_seed() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::wedged(ProbeStatus::InvalidEhr);

    assert_eq!(
        device.seed(&mut store, &mut probe).err(),
        Some(SeedError::Trng(TrngError::Stalled))
    );
    assert!(probe.polls as u64 <= MAX_ENTROPY_WAIT);
}

/// A peripheral that reports success and delivers an all-zero block is
/// either broken or being emulated badly, and both are worse than a
/// refusal: an all-zero draw is a constant, and a constant in the nonce slot
/// is the same cross-boot repetition the draw was added to prevent, one
/// layer further up.
#[test]
fn an_all_zero_draw_is_refused_rather_than_mixed_in() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::fixed(0x00);

    assert_eq!(
        device.seed(&mut store, &mut probe).err(),
        Some(SeedError::Trng(TrngError::Entropy)),
        "a block of zeros is not entropy; refusing is the only safe reading"
    );
    assert!(device.drbg(&mut store, &mut probe, NEVER).is_err());
}

/// The refusals must be **ordered**: a device that is misprovisioned *or*
/// has a dead peripheral should name the fault that needs no hardware, and
/// must not spend a poll budget discovering a problem it can already report.
/// This is what keeps a broken device from looking like a wedged one.
#[test]
fn a_misprovisioned_device_refuses_without_touching_the_peripheral() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::wedged(ProbeStatus::AutocorrErr);
    store.delete(SLOT_BOOT_ENTROPY).unwrap();

    assert_eq!(
        device.seed(&mut store, &mut probe).err(),
        Some(SeedError::CKey(CKeyError::MissingBootEntropy)),
        "the missing record is the real fault and must be reported first"
    );
    assert_eq!(
        probe.polls, 0,
        "an in-process refusal must not spend a probe budget on the way out"
    );
}

// ---------------------------------------------------------------------------
// (6) A refused re-seed is atomic.
// ---------------------------------------------------------------------------

/// A source that refuses. Standing in for a store whose record vanished,
/// which is the realistic way a re-seed fails in the field.
struct Refusing;
impl SeedSource for Refusing {
    fn seed(&mut self) -> Result<SeedMaterial, SeedError> {
        Err(SeedError::CKey(CKeyError::MissingBootEntropy))
    }
}

/// A refused re-seed must leave the generator byte-for-byte as it was.
/// Getting this wrong is the quiet way to lose state: a re-seed that
/// half-applies would produce a generator that is neither the old one nor a
/// correctly seeded one.
#[test]
fn a_refused_reseed_leaves_the_generator_untouched() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    // A peripheral that always delivers the *same* block, so both
    // instantiations are bit-identical. The point of the test is the
    // refused re-seed, and a control that is not reproducible could not
    // show "untouched" — it would only show "different".
    let mut probe = ScriptedProbe::fixed(0x3C);

    let mut trial = device.drbg(&mut store, &mut probe, NEVER).unwrap();
    let mut control = device.drbg(&mut store, &mut probe, NEVER).unwrap();
    let mut warmup = [0u8; OUTLEN];
    trial.generate(&mut warmup).unwrap();
    control.generate(&mut warmup).unwrap();

    let counter_before = trial.reseed_counter();
    let mut refuse = Refusing;
    assert!(trial.reseed_from(&mut refuse).is_err());
    assert_eq!(
        trial.reseed_counter(),
        counter_before,
        "a refused re-seed must not move the counter"
    );

    // The next block is byte-for-byte what the untouched control produces.
    let mut after = [0u8; OUTLEN];
    trial.generate(&mut after).unwrap();
    let mut expected = [0u8; OUTLEN];
    control.generate(&mut expected).unwrap();
    assert_eq!(
        after, expected,
        "a refused re-seed must leave the state bit-for-bit intact"
    );
}

/// At exhaustion, a failed re-seed leaves the generator **refusing**. This
/// is the security-relevant ordering: if a caller retries the seed and it
/// fails, the device must not quietly resume serving from a stretched
/// state whose budget is already spent.
#[test]
fn a_failed_reseed_at_exhaustion_still_refuses() {
    let device = Device::provisioned();
    let mut store = MemStore::provisioned();
    let mut probe = ScriptedProbe::healthy();
    // interval 1: the counter is 1 after instantiate, so the first generate
    // is served and the second is refused.
    let mut drbg = device.drbg(&mut store, &mut probe, 1).unwrap();
    let mut out = [0u8; OUTLEN];
    assert_eq!(drbg.generate(&mut out), Ok(()));
    assert_eq!(drbg.generate(&mut out), Err(DrbgError::ReseedRequired));

    // The record disappears between the exhaustion and the re-seed.
    store.delete(SLOT_BOOT_ENTROPY).unwrap();
    assert!({
        let mut src = device.source(&mut store, &mut probe);
        drbg.reseed_from(&mut src).is_err()
    });
    assert_eq!(
        drbg.generate(&mut out),
        Err(DrbgError::ReseedRequired),
        "a failed re-seed must not reopen a spent generator"
    );

    // Restoring the record reopens it — the only way out is a real seed.
    store.write(SLOT_BOOT_ENTROPY, &ENTROPY).unwrap();
    let mut src = device.source(&mut store, &mut probe);
    drbg.reseed_from(&mut src).unwrap();
    assert_eq!(drbg.generate(&mut out), Ok(()));
}
