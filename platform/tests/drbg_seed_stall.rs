//! US-1008 — the boot-brick policy, stated as behaviour rather than prose.
//!
//! # The decision this file records
//!
//! RS-Key's US-1008 asks a question the code was already answering by
//! accident: **on the boot path, what is the right response to a TRNG that
//! cannot produce a validated block?** The branch answers *fatal* at six
//! unconditional pre-USB sites, and until this story it answered it
//! inconsistently — a *diagnostic* (`main.rs`'s boot sanity draw) could kill
//! the boot, which is a diagnostic in the wrong place.
//!
//! The policy the branch now holds, in one sentence:
//!
//! > **A TRNG wedge at boot bricks the device until a hardware reset.** That
//! > is the accepted consequence of refusing, and it is accepted at exactly
//! > one site — `boot::init_drbg` — which is the only site whose whole job is
//! > to require a seeded generator. Every other pre-USB site either has a
//! > different, non-entropy justification, or is a diagnostic and must
//! > report rather than halt.
//!
//! # Why "fatal" is the right answer, and what it costs
//!
//! The two alternatives were both considered at `init_drbg` and are recorded
//! on [`FuseSeedSource`] and on `init_drbg` itself:
//!
//! * *Continue with a peripheral-only source* — reinstates the arrangement
//!   US-1003 exists to end, and puts an unbounded wait back on the request
//!   path, where a wedge is a hang in a CCID request rather than a clean
//!   refusal at boot.
//! * *Continue with the fuse seed alone* — the cross-boot nonce-reuse defect
//!   (US-1003), i.e. a private-key-recovery bug for any ECDSA signature made
//!   across two boots.
//!
//! So a device that cannot reach a validated block is a device that cannot
//! sign, and the honest failure is to say so once, at boot, with one line of
//! defmt. What "once, at boot" means in the field is the sentence at the top:
//! **the device does not enumerate, and no software action recovers it — a
//! power cycle re-runs the same failing check.** There is no degraded mode
//! and none is proposed; the cost of the policy is deliberately paid in
//! availability rather than in security, because every alternative trades
//! the other way.
//!
//! # What this file can and cannot prove
//!
//! It cannot prove the device halts — `fatal_boot` is a `loop {}` behind a
//! `defmt::error!` on a path no host build compiles, and the RP2350's
//! peripheral cannot be stalled from here. What it pins is the **half of the
//! policy that is logic rather than hardware**, and that half is where the
//! failure modes live:
//!
//! 1. the refusal is a *value*, and it reaches the caller (`SeedError::Trng`);
//! 2. **no generator exists after a refusal** — there is no API that yields
//!    one, so "continue with a degraded source" is not reachable even by
//!    accident;
//! 3. a peripheral that reports success while handing back a **constant** is
//!    refused, so a wedged part that lies is caught as well as one that
//!    refuses;
//! 4. the refusal is **prompt** — bounded by the same wall-clock budget the
//!    device uses — so "fatal" is a decision rather than a hang, and the
//!    difference between the two is the difference between a device that is
//!    off and a device that is broken.
//!
//! Point 4 is the one the dark boot of 2026-09-29 turned on: a wait whose
//! clock was not running made the budget unreachable, the probe degenerated
//! to a poll cap, and a healthy part reported a stall. The clock is now
//! checked at the point of use (D-12), and `PlatformSeedProbe` below models a
//! *counting* clock so the budget is exercised as a budget.

use std::cell::Cell;
use std::rc::Rc;

use fapico2_platform::ckey::{self, BOOT_ENTROPY_LEN, KEY_LEN};
use fapico2_platform::drbg::{SeedError, SeedSource, NONCE_LEN};
use fapico2_platform::drbg_seed::FuseSeedSource;
use fapico2_platform::migration::SLOT_BOOT_ENTROPY;
use fapico2_platform::secure_store::{SecureStore, SecureStoreError};
use fapico2_platform::trng::{
    DrbgTrng, EntropyClock, ProbeStatus, TrngError, TrngProbe, ENTROPY_CLOCK_TICKS_PER_MS,
    MAX_ENTROPY_WAIT,
};

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// A wall clock that **counts**, one tick per status read.
///
/// This is the load-bearing detail of this file. The 2026-09-29 dark boot
/// was a wait whose budget was unreachable because the clock behind it was
/// stopped, so the "bounded" wait was not bounded at all and a healthy part
/// reported a stall. A frozen clock in a test would reproduce that failure
/// mode and call it correct; a counting one exercises the budget the device
/// actually applies.
///
/// The read counter is a `static` rather than a field because the clock and
/// the probe are separate objects the driver holds at the same time; a
/// shared counter is the honest model of a single peripheral being polled.
/// The tests that read it reset it first, and the file's tests are
/// single-threaded by construction (no shared mutable state beyond this
/// counter, and the driver under test never yields).
/// A clock that advances **one millisecond per read**, so
/// `await_ready`'s arithmetic against `ENTROPY_CLOCK_TICKS_PER_MS` is
/// exercised as written rather than approximated.
///
/// The counter is owned by the probe and shared with the test through an
/// `Rc<Cell<_>>`, not a `static`. A static would be a cross-test race — the
/// suite runs tests in parallel threads, and every other probe in this file
/// reads the clock too, so the budget assertion would be measuring whatever
/// the other five tests happened to be doing. Per-probe ownership makes the
/// measurement mean what it says.
#[derive(Clone)]
struct CountingClock(Rc<Cell<u64>>);

impl CountingClock {
    fn new() -> Self {
        Self(Rc::new(Cell::new(0)))
    }

    fn elapsed_ticks(&self) -> u64 {
        self.0.get()
    }
}

impl EntropyClock for CountingClock {
    fn ticks(&self) -> u64 {
        let now = self.0.get();
        self.0.set(now + ENTROPY_CLOCK_TICKS_PER_MS);
        now
    }
}

/// The device's seed probe, with the peripheral's behaviour as the only
/// variable: it is otherwise shaped like the real one (status polls, a
/// clock, a bounded `await_ready`).
struct WedgedProbe {
    /// How the peripheral answers. `Stalled` is the realistic case — the
    /// health test never passes. `Lying` is the adversarial one: it claims a
    /// valid block and hands back a constant.
    mode: Mode,
    /// The clock the driver mutably borrows for the duration of a wait. A
    /// field rather than a temporary so the borrow outlives the call.
    clock: CountingClock,
}

enum Mode {
    /// Never valid. The device's actual dark-boot symptom.
    Stalled,
    /// Reports `Ready` and returns all zeros. The "peripheral that lies"
    /// case, and the one D-9 item (1) is about one layer up.
    Lying,
}

impl WedgedProbe {
    fn stalled() -> Self {
        Self { mode: Mode::Stalled, clock: CountingClock::new() }
    }

    fn lying() -> Self {
        Self { mode: Mode::Lying, clock: CountingClock::new() }
    }

    /// The clock reading, after any `&mut dyn EntropyClock` borrow is gone.
    fn elapsed_ticks(&self) -> u64 {
        self.clock.elapsed_ticks()
    }
}

impl TrngProbe for WedgedProbe {
    fn status(&mut self) -> ProbeStatus {
        match self.mode {
            Mode::Stalled => ProbeStatus::Busy,
            Mode::Lying => ProbeStatus::Ready,
        }
    }

    fn clock(&mut self) -> &mut dyn EntropyClock {
        &mut self.clock
    }

    fn read_block(&mut self, block: &mut [u8]) {
        block.fill(0);
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
}

/// An in-memory `SecureStore` carrying one good boot-entropy record.
///
/// The record has to be **good**, not merely present: the seed path refuses
/// an all-zero record specifically, so a zeroed fixture would test that
/// refusal instead of the peripheral one. With a real record in place, the
/// only remaining reason a seed can fail is the peripheral — which is the
/// variable each test below names.
#[derive(Default)]
struct MemStore {
    slots: heapless::Vec<(heapless::Vec<u8, 48>, heapless::Vec<u8, 64>), 8>,
}

impl MemStore {
    /// A store already carrying a valid, non-constant record.
    fn provisioned() -> Self {
        let mut s = Self::default();
        let mut record = [0u8; BOOT_ENTROPY_LEN];
        // Recognisably non-zero and non-constant: `i*7 + 1` over 32 bytes
        // never repeats and never zeroes, so the "present but carries
        // nothing" refusal cannot fire.
        for (i, b) in record.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        s.write(SLOT_BOOT_ENTROPY, &record).expect("fixture record persists");
        s
    }
}

impl SecureStore for MemStore {
    fn write(&mut self, key: &[u8], value: &[u8]) -> Result<(), SecureStoreError> {
        let mut v = heapless::Vec::new();
        v.extend_from_slice(value)
            .map_err(|_| SecureStoreError::ValueTooLong)?;
        let idx = self
            .slots
            .iter()
            .position(|(k, _)| k.as_slice() == key);
        match idx {
            Some(i) => self.slots[i].1 = v,
            None => self
                .slots
                .push((
                    key.try_into().map_err(|_| SecureStoreError::KeyTooLong)?,
                    v,
                ))
                .map_err(|_| SecureStoreError::Full)?,
        }
        Ok(())
    }

    fn read(&mut self, key: &[u8], out: &mut [u8]) -> Result<usize, SecureStoreError> {
        let found = self
            .slots
            .iter()
            .find(|(k, _)| k.as_slice() == key)
            .map(|(_, v)| v.as_slice())
            .ok_or(SecureStoreError::NotFound)?;
        if found.len() != out.len() {
            return Err(SecureStoreError::Corrupt);
        }
        out.copy_from_slice(found);
        Ok(out.len())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), SecureStoreError> {
        match self.slots.iter().position(|(k, _)| k.as_slice() == key) {
            Some(i) => {
                self.slots.remove(i);
                Ok(())
            }
            None => Err(SecureStoreError::NotFound),
        }
    }

    fn contains(&self, key: &[u8]) -> bool {
        self.slots.iter().any(|(k, _)| k.as_slice() == key)
    }

    // The seed path only reads. Snapshotting is the persist gate's business,
    // so these say so rather than inventing a fake image the tests would
    // then be silently not exercising.
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

const OTP_KEY: [u8; KEY_LEN] = [0xA1; KEY_LEN];

/// 8 bytes of chipid, big-endian, as `migration::chipid_from_uid` expects.
const UID: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

// ---------------------------------------------------------------------------
// 1. The refusal is a value, and it names the peripheral
// ---------------------------------------------------------------------------

/// **The core of US-1008, as an assertion.** With the peripheral wedged, the
/// seed source answers `SeedError::Trng` — it does not hang, does not return
/// a partial seed, and does not substitute anything.
///
/// A hang is what makes "fatal" a euphemism; a silent partial seed is what
/// makes it a security defect instead. Both are excluded here.
#[test]
fn a_wedged_peripheral_makes_the_seed_refuse_with_a_named_error() {
    let mut store = MemStore::provisioned();
    let mut probe = WedgedProbe::stalled();
    let mut src = FuseSeedSource::new(&OTP_KEY, &UID, &mut store, &mut probe);

    match src.seed() {
        Err(SeedError::Trng(TrngError::Stalled)) => {}
        Err(other) => panic!("expected the refusal to name the peripheral, got {other:?}"),
        Ok(_) => panic!(
            "a wedged peripheral produced a seed. This is the degraded-source \
             failure US-1008 exists to rule out — refusing is the whole \
             policy, and this assertion is what it rests on."
        ),
    }
}

// ---------------------------------------------------------------------------
// 2. No generator exists after a refusal
// ---------------------------------------------------------------------------

/// The second half of the policy, and the part that makes the first half
/// real: there is **no constructor** that yields a `DrbgTrng` from a source
/// that refuses. `try_new` returns `Err` and there is no `new`.
///
/// If a future change adds an infallible constructor "for the boot path",
/// the fail-closed property is gone and this test stops compiling — which is
/// the intended kind of failure.
#[test]
fn a_refused_source_yields_no_generator() {
    let mut store = MemStore::provisioned();
    let mut probe = WedgedProbe::stalled();
    let mut src = FuseSeedSource::new(&OTP_KEY, &UID, &mut store, &mut probe);

    let Err(err) = DrbgTrng::try_new(&mut src) else {
        panic!("a refused source must not produce a generator")
    };
    // The specific error is the peripheral's, not a generic one: the
    // operator reading the boot log needs to know whether the device is
    // unprovisioned or wedged, and those two have different fixes.
    assert!(
        matches!(err, SeedError::Trng(_)),
        "the refusal must survive the DRBG constructor intact, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. A peripheral that lies is caught as well as one that refuses
// ---------------------------------------------------------------------------

/// The adversarial half. A part that reports `Ready` and hands back a
/// constant is *worse* than one that refuses, because it takes the all-zero
/// check in [`FuseSeedSource`] out of the picture by making the draw look
/// successful — and the symptom then reappears one layer up as D-9 item (1),
/// the all-zero device secret.
///
/// This is the test that makes the two halves of US-1008 and D-9 one
/// argument: the seed path refuses a constant, and the keystore path (D-9,
/// fixed separately) refuses the draw that would have produced one.
#[test]
fn a_peripheral_that_reports_success_with_a_constant_is_refused() {
    let mut store = MemStore::provisioned();
    let mut probe = WedgedProbe::lying();
    let mut src = FuseSeedSource::new(&OTP_KEY, &UID, &mut store, &mut probe);

    let Err(err) = src.seed() else {
        panic!("a draw of all zeros is not entropy and must be refused")
    };
    assert!(
        matches!(err, SeedError::Trng(TrngError::Entropy)),
        "a constant draw must be refused as `Entropy` (the peripheral claimed \
         success and carried nothing), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. The refusal is prompt, so "fatal" is a decision and not a hang
// ---------------------------------------------------------------------------

/// The property the 2026-09-29 dark boot turned on.
///
/// `fatal_boot` is a `loop {}`. The difference between "the device refused to
/// boot" and "the device hung" is entirely this: a refusal that arrives
/// within the budget is a **decision the firmware made and can report**, and
/// one that arrives after an unbounded spin is indistinguishable, from the
/// outside, from a device that never started. The outside is the only place
/// that difference exists — LED solid, absent from `lsusb`, no reader in
/// `pcscd` — and it is exactly the observation that could not be attributed.
///
/// The budget is asserted against the library's own constants rather than
/// literals, so a change to `MAX_ENTROPY_WAIT_MS` cannot make this test
/// quietly vacuous.
#[test]
fn a_wedged_peripheral_is_refused_within_the_entropy_budget() {
    let mut store = MemStore::provisioned();
    let mut probe = WedgedProbe::stalled();
    // Scoped, so the source's `&mut probe` borrow ends before the clock is
    // read — the measurement is taken outside the driver's own lifetime.
    // A `drop(src)` would say the same thing without the clippy complaint
    // about dropping a type with no destructor, but a scope is the clearer
    // statement of the intent.
    {
        let mut src = FuseSeedSource::new(&OTP_KEY, &UID, &mut store, &mut probe);
        assert!(src.seed().is_err(), "a wedged peripheral must refuse");
    }

    // The bound is stated in the clock's own units, not in polls. A poll
    // count would be a statement about this loop's shape; elapsed clock is
    // a statement about the property — and the property is what the dark
    // boot violated. The one extra tick quantum is the granularity at which
    // the loop can notice it has run out: it can only check the budget after
    // reading the clock, so a wait that overruns by less than one read is
    // on-budget by construction.
    let elapsed_ticks = probe.elapsed_ticks();
    let quantum = ENTROPY_CLOCK_TICKS_PER_MS;
    let one_quantum_past_budget = MAX_ENTROPY_WAIT + quantum;
    assert!(
        elapsed_ticks <= one_quantum_past_budget,
        "the refusal took {elapsed_ticks} clock ticks, past the \
         {MAX_ENTROPY_WAIT}-tick wall-clock budget by more than one read \
         ({quantum} ticks). A wait that overruns its budget is not a bounded \
         wait, and a bounded wait that overruns is the 2026-09-29 dark boot: \
         the device looks identical from outside whether it refused or hung."
    );

    // And the same fact in the unit an operator would use: a clock that
    // advances one millisecond per read must exhaust a 20 ms budget in 20
    // reads of the peripheral, plus the one read `await_ready` takes to
    // establish its own `start`. A different number means the loop and the
    // budget have drifted apart, which is the arithmetic D-8 rests on.
    let reads = elapsed_ticks / quantum;
    let budget_reads = MAX_ENTROPY_WAIT / ENTROPY_CLOCK_TICKS_PER_MS;
    assert_eq!(
        reads,
        budget_reads + 1,
        "a clock that advances one millisecond per read must exhaust the \
         budget in the budget's milliseconds of peripheral reads, plus the \
         one establishing read. A different number means the wait loop and \
         the budget have drifted apart."
    );
}

// ---------------------------------------------------------------------------
// 5. The boot sanity draw is a diagnostic, not a second authority
// ---------------------------------------------------------------------------

/// US-1008's other half, and the finding the review named: `main.rs` had a
/// **diagnostic** that could kill the boot. A diagnostic that can end the
/// boot is a diagnostic in the wrong place — it converts a question into a
/// verdict, at the site whose purpose is to ask.
///
/// The property is structural (it is about a call site in a `no_std`,
/// device-only file no host build compiles), so it is pinned the only way it
/// can be: by reading the source. The check is narrow on purpose — it looks
/// for the specific anti-pattern, not for a general absence of
/// `fatal_boot`, because `init_drbg`'s fatal arm is the *policy* and must
/// stay.
#[test]
fn the_boot_sanity_draw_is_not_a_fatal_boot_site() {
    let src = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../firmware/src/main.rs"),
    )
    .expect("firmware/src/main.rs must be readable from the platform suite");

    // The sanity draw's own anchor. If this stops naming, the test is
    // stale rather than green, and the failure says so.
    assert!(
        src.contains("trng: boot sanity draw refused"),
        "the boot sanity draw is no longer where US-1008's fix put it; this \
         test's anchor is stale and must be re-derived"
    );

    // The refusal must be a `warn!`, not a halt. A `fatal_boot` naming the
    // sanity draw is the defect this test exists to prevent, and it is
    // matched on the message rather than on the call so that moving the
    // call around does not hide it.
    let halts_on_sanity: Vec<&str> = src
        .lines()
        .filter(|l| l.contains("fatal_boot") && l.contains("sanity"))
        .collect();
    assert!(
        halts_on_sanity.is_empty(),
        "the boot sanity draw is fatal again (US-1008). A diagnostic must \
         report; the authority on a TRNG wedge at boot is `init_drbg`, which \
         is fatal for a stated reason. Found: {halts_on_sanity:?}"
    );
}

/// The flip side, and the reason the previous test is not a gate weakening:
/// the authority itself must still be fatal. If someone "fixed" the dark
/// boot by making `init_drbg` return a default generator, the fail-closed
/// property would be gone and *this* is the test that says so.
#[test]
fn init_drbg_is_still_the_fatal_authority_on_a_wedged_peripheral() {
    let src = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../firmware/src/boot.rs"),
    )
    .expect("firmware/src/boot.rs must be readable from the platform suite");

    assert!(
        src.contains("drbg: seed refused"),
        "US-1008: the fatal authority on a TRNG wedge at boot is `init_drbg`, \
         and this test asserts the refusal is still reported there. If the \
         message has moved, re-derive the anchor before accepting that the \
         policy is unchanged."
    );
    // And the property that makes it fatal: a DRBG is only ever built
    // through `try_new`, never through an infallible constructor.
    assert!(
        !src.contains("DrbgTrng::new("),
        "`DrbgTrng::new` does not exist and must not be introduced: the \
         fail-closed property US-1008 rests on is that a refused seed yields \
         no generator, and an infallible constructor would be a way to get \
         one anyway."
    );
}

/// The width the whole policy is about. `NONCE_LEN` bytes of fresh
/// peripheral material is the *only* input that distinguishes one boot from
/// the next; a draw that silently came back short or constant is the
/// cross-boot nonce-reuse defect US-1003 was written to end. Asserted
/// against the library's own constant so the arithmetic below cannot drift
/// from the one the seed path uses.
#[test]
fn the_peripheral_contribution_is_the_whole_nonce_slot() {
    assert_eq!(
        NONCE_LEN, ckey::BOOT_ENTROPY_LEN,
        "US-1008: the fresh peripheral draw must fill the nonce slot in full. \
         A short draw would be indistinguishable from a long one at the type \
         level, and the difference is one boot's ECDSA nonce."
    );
}

