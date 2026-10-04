//! US-1561 — "a signature counter does not erase on every assertion", against
//! the per-record key region.
//!
//! ```gherkin
//! Scenario: a signature counter does not erase on every assertion
//!   Given a credential at counter C
//!   When 31 assertions are signed
//!   Then no erase occurs
//!   And the 32nd performs one erase and one program
//!   And the counter is monotonic across the batch and across a power cut
//! ```
//!
//! # Why this file exists when `tests/counter_batching.rs` and
//! `tests/counter_monotonic.rs` already do this for the snapshot path
//!
//! Because the store underneath changed shape, and both of those files drive
//! [`DeviceKeystore`]'s whole-image rewrite through the chunked
//! `fido.keystore.v1` slot. The cost of a counter bump is now a **record
//! commit plus an index rewrite** ([`fido_store::SECTOR_ERASES_PER_COUNTER_WRITE`]),
//! which is a different number, a different medium and a different batching
//! mechanism: [`CounterWindow`] holds `(slot, counter)` pairs, not a dirty
//! snapshot, and nothing about it is resident per credential.
//!
//! Keeping the old tests green while this behaviour did not exist is exactly
//! the failure AGENTS.md §1 warns about — a guarantee that is measured on the
//! path the device no longer takes.
//!
//! # What "one erase and one program" means here, stated plainly
//!
//! **There is no slot erase on this part.** `SLOTS_PER_SECTOR` slots share one
//! 4 KiB NOR sector and NOR cannot rewrite programmed bytes, which is the whole
//! reason `keyregion/commit.rs` exists. So the criterion is read at sector
//! granularity and this file asserts both halves of that reading:
//!
//! * `the_32nd_assertion_erases_exactly_one_live_record_sector` — one erase of
//!   the sector holding the record, and the other five land on the index and the
//!   commit scratchpad, which [`the_32nd_assertion_costs_the_whole_counter_write`]
//!   accounts for;
//! * `the_32nd_assertion_reprograms_the_whole_live_sector` — one *sector*
//!   program, which is [`SLOTS_PER_SECTOR`] slot programs because the erase left
//!   nothing to keep.
//!
//! Asserting "one erase" over the whole write would be false, and a test that
//! asserted it would have to be lying to pass.
//!
//! # Why the counters go through a power cut
//!
//! US-1012's guarantee is that a cut inside a batch window can only **skip
//! forward**. The mechanism is two halves — a restore *grants* one window of
//! slack and *spends* it, so the first assertion after the power-on writes down
//! — and they are only safe together. [`the_counter_is_monotonic_across_a_power_cut_at_every_point_of_the_window`]
//! takes the cut at **every** point of the window rather than at one, because
//! the dangerous cut is the one where the in-RAM counter is furthest ahead of
//! the durable one, and "one cut at one point" is a measurement of the
//! arithmetic rather than of the property.
//!
//! A cut is simulated by dropping the region without flushing anything and
//! reopening the file — the store holds nothing resident, so dropping it *is* a
//! power cut as far as the medium is concerned. There is no in-RAM cache to
//! lose, which is `fido_store.rs`'s whole design and is why the simulation is
//! honest rather than approximate.

use std::path::{Path, PathBuf};

mod region_boot;

use fapico2_fido::device_keystore::{
    region_pin_secret, CounterWindow, DeviceCredential, DevicePinState, PrivateScalar,
    RegionCredentials, RegionKeys, COUNTER_PERSIST_INTERVAL,
};
use fapico2_platform::keyregion::crypto;
use fapico2_platform::keyregion::fido_store;
use fapico2_platform::keyregion::record;
use fapico2_platform::keyregion::{Slot, SLOTS_PER_SECTOR};
use region_boot::CountingRegion;

use heapless::Vec as HeaplessVec;

/// The window's size, taken from the code rather than repeated. If the constant
/// moves, this file follows it and the arithmetic in the test names stays true;
/// a literal `31` here would silently become a lie.
const W: u16 = COUNTER_PERSIST_INTERVAL;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A region file in the host temp directory, removed on drop.
struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir()
            .join(format!("fapico2-us1561-{}-{tag}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRegion {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The device-rooted OTP row. Non-zero because `crypto::derive_otp_root`
/// refuses an all-zero row rather than return a constant root.
fn otp_row() -> [u8; 32] {
    let mut row = [0u8; 32];
    for (i, b) in row.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(29).wrapping_add(0x0b);
    }
    row
}

fn chip_id() -> [u8; 8] {
    [0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]
}

/// The two region keys, from the OTP row and the applet's PIN secret.
///
/// `region_pin_secret` is the applet's own derivation, so this fixture is the
/// same key hierarchy the device would use.
fn keys() -> RegionKeys {
    let row = otp_row();
    let root = crypto::derive_otp_root(&row, &chip_id()).expect("a non-zero OTP row");
    let secret = region_pin_secret(&DevicePinState::default(), &[0x5a; 32]);
    RegionKeys {
        index: crypto::derive_index_key_from_root(&root),
        payload: crypto::derive_payload_key_from_root(&root, &secret),
    }
}

/// A fresh GCM nonce for the `n`-th durable write.
///
/// Unique per write, which `record::seal` requires. The device draws from its
/// TRNG pool; this is the host's equivalent, and a counter fixture would
/// otherwise reuse a nonce under one key.
fn nonce(n: u32) -> [u8; record::NONCE_LEN] {
    let mut out = [0u8; record::NONCE_LEN];
    out[..4].copy_from_slice(&n.to_le_bytes());
    out[4..].copy_from_slice(&b"us1561 nonce!"[..record::NONCE_LEN - 4]);
    out
}

/// One credential, minimal but real: every field is one the applet's codec
/// writes, so the record that lands in the region is a credential and not a
/// blob that happens to fit.
fn credential(n: u32) -> DeviceCredential {
    let mut cred = DeviceCredential {
        credential_id: HeaplessVec::new(),
        public_key: fapico2_fido::device_keystore::DeviceCoseKey::es256([n as u8; 32], [0x77; 32]),
        private_key: PrivateScalar::from_bytes([0x33; 32]),
        rp_id_hash: rp_hash(n),
        rp_id: HeaplessVec::new(),
        user_handle: HeaplessVec::new(),
        user_name: HeaplessVec::new(),
        user_display_name: HeaplessVec::new(),
        cred_protect: 2,
        large_blob_key: None,
        hmac_secret: HeaplessVec::new(),
        cred_blob: HeaplessVec::new(),
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: true,
        algorithm: -7,
        counter: 0,
        revoked: false,
        expires_at: None,
    };
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(b"u156");
    id[4..8].copy_from_slice(&n.to_le_bytes());
    id[8..].copy_from_slice(&[(n >> 8) as u8; 24]);
    cred.credential_id.extend_from_slice(&id).unwrap();
    cred.rp_id.extend_from_slice(b"example.test").unwrap();
    cred.user_handle.extend_from_slice(&[0x11; 64]).unwrap();
    cred.user_name.extend_from_slice(b"alice@example.test").unwrap();
    cred
}

fn rp_hash(n: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = (n as u8).wrapping_mul(17).wrapping_add(i as u8).wrapping_add(0x3d);
    }
    h
}

// ---------------------------------------------------------------------------
// The counting region
// ---------------------------------------------------------------------------

// `CountingRegion` itself is shared: `region_boot/mod.rs` owns it, because the
// **same** sector-granular erase log has to be readable from two places — this
// file, which drives the applet's store API directly, and
// `region_assertion_counter.rs`, which needs it behind the applet's *provider*
// because that is the only handle a command-path write goes through. Two
// copies of "log erases by sector" in a tree that keeps finding the same
// mechanism written twice is `AGENTS.md` §5's defect class, and the two would
// agree only until one of them was edited.

// ---------------------------------------------------------------------------
// Helpers over the applet API
// ---------------------------------------------------------------------------

/// Run `f` with a [`RegionCredentials`] over `region`.
///
/// The borrow has to end for a test to look at the medium, and re-creating the
/// store is free: `RegionCredentials::new` reads nothing (S8/S9 forbid the boot
/// path from touching the region, and a constructor is what a boot path calls).
fn with_store<R>(region: &mut CountingRegion, f: impl FnOnce(&mut RegionCredentials<'_, '_>) -> R) -> R {
    let k = keys();
    let mut creds = RegionCredentials::new(region, &k);
    f(&mut creds)
}

/// Sign one assertion against `slot`, batching through `window`, and return the
/// counter the reply would sign.
///
/// This is the whole applet-side loop in one place, so every test drives the
/// same code and a change to the batching lands in all of them. `held` is the
/// counter the applet is holding in RAM — which is the *window's* value when
/// there is one, and the durable value otherwise; a caller that got this wrong
/// would be handing the store a counter it has already signed past, so it is
/// read through [`RegionCredentials::counter_value`] rather than tracked here.
fn assert_once(
    region: &mut CountingRegion,
    window: &mut CounterWindow,
    slot: Slot,
    draws: &mut u32,
) -> u32 {
    with_store(region, |creds| {
        let held = creds.counter_value(window, slot).expect("the credential is in the region");
        let mut next_nonce = || {
            *draws += 1;
            nonce(*draws)
        };
        creds.bump_counter(window, slot, held, &mut next_nonce).expect("a batched bump succeeds")
    })
}

/// Enrol `count` credentials and return the slots, in enrolment order.
fn enrol(region: &mut CountingRegion, count: u32) -> Vec<Slot> {
    with_store(region, |creds| {
        let mut out = Vec::new();
        for n in 0..count {
            let next_nonce = || nonce(n);
            let report = creds
                .put(&next_nonce(), &credential(n))
                .expect("a fresh credential enrols");
            out.push(report.slot);
        }
        out
    })
}

// ---------------------------------------------------------------------------
// The gherkin
// ---------------------------------------------------------------------------

/// **"When 31 assertions are signed, then no erase occurs."**
///
/// The load-bearing test of the story: without it the rest would pass against a
/// store that simply never wrote a counter, and the durability of the 32nd
/// assertion would be untested.
#[test]
fn thirty_one_assertions_erase_nothing() {
    let tmp = TempRegion::new("31");
    let mut region = CountingRegion::create(tmp.path());
    let slots = enrol(&mut region, 1);
    let target = slots[0];

    let mut window = CounterWindow::fresh();
    let mut draws = 0u32;
    region.reset_log();
    let mut signed = Vec::new();
    for _ in 0..(W - 1) {
        signed.push(assert_once(&mut region, &mut window, target, &mut draws));
    }

    assert_eq!(
        region.erases(),
        0,
        "{} assertions inside an open batch window must not erase a single sector — the window \
         is the whole of US-1561 and this is the assertion that would have failed without it",
        W - 1
    );
    assert_eq!(region.programs_on(target), 0, "and must not program the record sector either");
    assert_eq!(
        window.unpersisted(),
        W - 1,
        "every bump must be counted, or the window would close early and this test would be \
         measuring a batch of the wrong length"
    );
    assert_eq!(window.pending_len(), 1, "one credential is in flight");
    assert!(
        signed.windows(2).all(|w| w[1] > w[0]),
        "the counters signed inside the window must be strictly increasing: {signed:?}"
    );

    // And the durable record still holds the *old* counter — that is the
    // weakening, asserted rather than assumed.
    let durable = with_store(&mut region, |creds| creds.durable_counter(target).unwrap());
    assert_eq!(
        durable, 0,
        "nothing has been written, so the durable counter must still be the value the credential \
         was enrolled with"
    );
}

/// **"The 32nd performs one erase and one program."**
///
/// Read at sector granularity, and stated here rather than assumed: the write
/// erases **one** sector holding the record and reprograms **one** sector —
/// four slot programs, because the erase left nothing to keep. The other two
/// sectors the write touches are the index's and the commit scratchpad's, and
/// [`the_32nd_assertion_costs_the_whole_counter_write`] accounts for them.
#[test]
fn the_32nd_assertion_erases_one_live_sector_and_reprograms_it() {
    let tmp = TempRegion::new("32");
    let mut region = CountingRegion::create(tmp.path());
    // A **full** sector: SLOTS_PER_SECTOR credentials, so the sector really is
    // reprogrammed in full. A sector with one record in it would program one
    // slot and the test would be measuring the wrong geometry.
    let slots = enrol(&mut region, SLOTS_PER_SECTOR);
    let target = slots[0];

    let mut window = CounterWindow::fresh();
    let mut draws = 0u32;
    for _ in 0..(W - 1) {
        assert_once(&mut region, &mut window, target, &mut draws);
    }

    region.reset_log();
    let last = assert_once(&mut region, &mut window, target, &mut draws);

    assert_eq!(
        region.erases_on(target),
        1,
        "the criterion's 'one erase': exactly one erase of the sector holding the record"
    );
    assert_eq!(
        region.programs_on(target),
        SLOTS_PER_SECTOR,
        "the criterion's 'one program', at sector granularity: one reprogram of the live sector, \
         which is {SLOTS_PER_SECTOR} slot programs"
    );
    assert_eq!(
        with_store(&mut region, |c| c.durable_counter(target).unwrap()),
        last,
        "the 32nd assertion is the one that writes, so its counter must be the durable one"
    );
    assert_eq!(window.unpersisted(), 0, "the window closed on the write");
    assert_eq!(window.pending_len(), 0, "and emptied");

    // Monotonic across the batch, in one place rather than scattered: the whole
    // window's signed values are strictly increasing, and the last one is what
    // landed.
    let mut seen = Vec::new();
    let mut window = CounterWindow::fresh();
    let mut draws = 100;
    for _ in 0..W {
        seen.push(assert_once(&mut region, &mut window, target, &mut draws));
    }
    assert!(
        seen.windows(2).all(|w| w[1] > w[0]),
        "the batch must be monotonic: {seen:?}"
    );
}

/// The whole durable write, accounted for: six sector erases over three sectors,
/// four of them on the commit scratchpad.
///
/// The companion to the test above, and it is what makes "one erase" honest
/// rather than convenient. Without it a reader of the first test could not tell
/// whether the other five erases did not happen or simply went somewhere the
/// test did not look.
#[test]
fn the_32nd_assertion_costs_the_whole_counter_write() {
    let tmp = TempRegion::new("cost");
    let mut region = CountingRegion::create(tmp.path());
    let slots = enrol(&mut region, SLOTS_PER_SECTOR);
    let target = slots[0];

    let mut window = CounterWindow::fresh();
    let mut draws = 0u32;
    for _ in 0..(W - 1) {
        assert_once(&mut region, &mut window, target, &mut draws);
    }

    region.reset_log();
    assert_once(&mut region, &mut window, target, &mut draws);
    let total = region.erases();
    assert_eq!(
        total,
        fido_store::SECTOR_ERASES_PER_COUNTER_WRITE,
        "a durable counter write is a record commit plus an index rewrite, and \
         docs/erase-budget.md §4c divides the lifetime by the busiest of them"
    );
    let record_sector = region.erases_on(target);
    let scratchpad_sector = region.erases_on(fido_store::scratchpad_slot());
    assert_eq!(
        scratchpad_sector,
        fido_store::MAX_ERASES_PER_SECTOR_PER_COUNTER_WRITE,
        "both writes stage through the same scratchpad, and it is the wear bottleneck"
    );
    assert!(
        scratchpad_sector > record_sector,
        "the scratchpad is where the durable counter write's wear concentrates ({scratchpad_sector} \
         erases against {record_sector} on the record's own sector)"
    );
}

/// **"The counter is monotonic across the batch and across a power cut."**
///
/// The cut is taken at **every** point of the window, not one, because the
/// dangerous cut is the one where the in-RAM counter is furthest ahead of the
/// durable one and "one cut at one point" would be a measurement of the
/// arithmetic rather than of the property.
///
/// Each round: enrol, bump `k` times, **drop the region without flushing**
/// (the store is stateless, so that is a power cut as far as the medium is
/// concerned), reopen, and check that the first counter the restored device
/// will sign is strictly greater than every value the cut-away session signed.
#[test]
fn the_counter_is_monotonic_across_a_power_cut_at_every_point_of_the_window() {
    for cut_after in 1..W {
        let tmp = TempRegion::new(&format!("cut{cut_after}"));
        let mut region = CountingRegion::create(tmp.path());
        let slots = enrol(&mut region, 1);
        let target = slots[0];

        let mut window = CounterWindow::fresh();
        let mut draws = 0u32;
        let mut signed = Vec::new();
        for _ in 0..cut_after {
            signed.push(assert_once(&mut region, &mut window, target, &mut draws));
        }

        // **The cut.** Nothing is flushed and the region is dropped. Every
        // counter above is in RAM only, and the region holds whichever of them
        // last closed a window (none, if `cut_after < W`).
        drop(region);

        let mut region = CountingRegion::open(tmp.path());
        let durable = with_store(&mut region, |c| c.durable_counter(target).unwrap());
        let highest_seen = *signed.iter().max().expect("at least one assertion was signed");

        // US-1012, "spend": a restored window arrives with its whole budget
        // already spent, so the first assertion after the cut writes down
        // instead of riding in RAM for another whole window.
        let mut window = CounterWindow::restored();
        assert!(
            window.should_flush(),
            "a restored window arrives already spent — that is the half of US-1012 that makes the \
             first assertion after the cut write down instead of riding in RAM"
        );
        assert!(
            CounterWindow::resume_from(durable) > highest_seen,
            "cut after {cut_after}: one window of slack above the durable image ({durable}) must \
             exceed every value the cut-away session signed ({highest_seen}) — equal would \
             already be a clone-detection failure"
        );

        // US-1012, "grant": applied **inside** `bump_counter`, from the window
        // rather than by the caller. The test does not pass a slacked counter —
        // that is the point, and passing one is the mistake the window exists to
        // make impossible.
        let next = assert_once(&mut region, &mut window, target, &mut draws);
        assert!(
            next > highest_seen,
            "cut after {cut_after}: the first assertion after the power-on signed {next}, which \
             does not exceed {highest_seen}"
        );
        assert_eq!(
            window.unpersisted(),
            0,
            "cut after {cut_after}: the restore's spent window must close on the very first \
             assertion, or the device signs a second un-durable value inside the same slack"
        );
        let durable_after = with_store(&mut region, |c| c.durable_counter(target).unwrap());
        assert_eq!(
            durable_after, next,
            "cut after {cut_after}: that first value is written down, so it is the durable one"
        );
        drop(region);
    }
}

/// Two cuts in a row: the second restore must clear the first one's value, not
/// merely sit above it.
///
/// This is the only state in which the **spend** half of US-1012 is observable
/// from the outside — a single cut could be satisfied by a slack that is
/// applied once at boot, whereas a device that is cut twice has already spent a
/// window and a slack that were re-applied rather than granted-and-spent would
/// hand the second session a value inside the first one's.
#[test]
fn a_device_restored_from_a_restore_still_never_repeats() {
    let tmp = TempRegion::new("double");
    let mut region = CountingRegion::create(tmp.path());
    let slots = enrol(&mut region, 1);
    let target = slots[0];

    let mut draws = 0u32;

    // First session: one window's worth, so the last assertion is durable.
    let mut signed = Vec::new();
    {
        let mut window = CounterWindow::fresh();
        for _ in 0..W {
            signed.push(assert_once(&mut region, &mut window, target, &mut draws));
        }
    }
    drop(region);

    // Second session: cut again after `W - 1` assertions, then restore.
    let mut region = CountingRegion::open(tmp.path());
    {
        let mut window = CounterWindow::fresh();
        for _ in 0..(W - 1) {
            signed.push(assert_once(&mut region, &mut window, target, &mut draws));
        }
    }
    let highest_seen = *signed.iter().max().unwrap();
    drop(region);

    let mut region = CountingRegion::open(tmp.path());
    let durable = with_store(&mut region, |c| c.durable_counter(target).unwrap());
    let mut window = CounterWindow::restored();
    let next = assert_once(&mut region, &mut window, target, &mut draws);
    assert!(
        next > highest_seen,
        "a twice-restored device signed {next} after having already signed {highest_seen} — the \
         restore slack was re-applied instead of granted-and-spent"
    );
    assert!(
        next >= CounterWindow::resume_from(durable),
        "the restored value must be at least one window above the durable image ({durable})"
    );
}

/// A mixed workload — many credentials, one store-wide window — costs one flush
/// per `COUNTER_PERSIST_INTERVAL` bumps **in total**, not one per counter.
///
/// The reason the window is store-wide, stated as a test: a per-credential
/// budget would make a deployment with thirty active passkeys wear 30× faster
/// than one with a single, which is precisely the shape of bug US-1011's sibling
/// already fixes on the snapshot path.
#[test]
fn a_mixed_workload_costs_one_flush_per_window_not_one_per_credential() {
    let tmp = TempRegion::new("mixed");
    let mut region = CountingRegion::create(tmp.path());
    let slots = enrol(&mut region, 4);
    let target = slots[0];
    let others: Vec<Slot> = slots[1..].to_vec();

    let mut window = CounterWindow::fresh();
    let mut draws = 0u32;
    region.reset_log();

    // Interleave the four credentials across one full window of bumps, so the
    // window closes **with all four still pending** — which is the case that
    // distinguishes a store-wide budget from a per-credential one.
    let mut flushes = 0u32;
    let mut before = region.erases();
    for i in 0..W {
        let slot = std::iter::once(&target).chain(others.iter()).nth(i as usize % 4).copied().unwrap();
        assert_once(&mut region, &mut window, slot, &mut draws);
        let now = region.erases();
        if now > before {
            flushes += 1;
            before = now;
        }
    }

    assert_eq!(
        flushes, 1,
        "one window of bumps across four credentials must close the window exactly once"
    );
    assert!(
        window.pending_len() <= 4,
        "at most four credentials can be in flight in one window, got {}",
        window.pending_len()
    );
    // And every pending counter reached the medium.
    for slot in std::iter::once(&target).chain(others.iter()) {
        let durable = with_store(&mut region, |c| c.durable_counter(*slot).unwrap());
        assert!(durable > 0, "every flushed credential must carry its batched counter");
    }
}