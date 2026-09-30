//! US-1010: the OATH table's **measured** durable capacity.
//!
//! # Why this file exists
//!
//! Two numbers in this tree disagreed for as long as both existed, and neither
//! could fail:
//!
//! * `chunked::MAX_PARTS` (17) and `rp2350::DEV_MAX_ENTRIES` (24). A chunked
//!   rewrite writes the new generation into the buffer *not* holding the
//!   current set and retires the old buffer's parts only afterwards, so a
//!   full-width value transiently needs `2 × MAX_PARTS` physical entries.
//!   `2 × 17 = 34 > 24`, so the `MAX_LOGICAL_LEN` of 8,432 B that the docs,
//!   this app's module header and the round-trip test all described was never
//!   reachable: the first full-width rewrite returned `SecureStoreError::Full`.
//! * `MAX_CREDS` (68) in `oath_core.rs`, a `heapless` table bound. 68 maximal
//!   credentials is ~13.3 KB, which no store of this size has ever held, in
//!   either world. It is a RAM/compile bound, not a capacity claim, and
//!   nothing said so.
//!
//! # What this measures
//!
//! The real ceiling, from the real encoder, on the real store: put maximal
//! credentials in one at a time and persist after each, counting how many the
//! device can actually make durable. This is the number the documentation
//! should carry, and it is *measured* here rather than derived from a
//! hand-copied per-credential byte count, which is how `8,432 B` and `~42
//! credentials` both came to be wrong.
//!
//! The capacity is a property of the **record encoding** (name + algorithm +
//! digits + sealed secret + property byte), not of the name lengths a caller
//! happens to use, so the fixture below uses the *maximal* record
//! (`MAX_NAME` name, `MAX_KEY` secret) and reports the worst case. A real
//! deployment with 8-character names fits more.

use fapico2_oath::oath_core::{device_id_from_chipid, OathApp, DEVICE_ID_LEN, EMULATION_CHIPID};
use fapico2_oath::OathSeal;
use fapico2_platform::dispatch::{App, MAX_RESPONSE};
use fapico2_platform::secure_store::{
    chunked, rp2350, rp2350::Rp2350SecureStore, HostSecureStore, SecureStoreError,
};
use fapico2_platform::trng::HostTrng;

fn emul_device_id() -> [u8; DEVICE_ID_LEN] {
    device_id_from_chipid(EMULATION_CHIPID)
}

/// Maximal records: the worst case is the honest ceiling. `MAX_NAME` is 64 and
/// `MAX_KEY` is 66, so the secret is 63 bytes after the 1-byte algorithm tag,
/// 1-byte digit count and 1-byte key id are subtracted (`oath_core`'s decoder
/// left-pads the algorithm/digit/key triple to 8 bytes).
const MAXIMAL_NAME: usize = 64;
const MAXIMAL_SECRET: usize = 63;

fn apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8, ins, p1, p2, 0];
    if data.is_empty() {
        out.push(0);
    } else {
        let lc = data.len() as u16;
        out.extend_from_slice(&lc.to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

fn drive(app: &mut OathApp, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = heapless::Vec::<u8, MAX_RESPONSE>::new();
    app.process(apdu, &mut resp);
    let bytes: Vec<u8> = resp.as_slice().to_vec();
    let sw = u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
    (bytes[..bytes.len() - 2].to_vec(), sw)
}

fn put_cred(app: &mut OathApp, name: &[u8], secret: &[u8]) -> u16 {
    let mut data = vec![0x71, name.len() as u8];
    data.extend_from_slice(name);
    data.extend_from_slice(&[0x73, 2 + secret.len() as u8, 0x21, 6]);
    data.extend_from_slice(secret);
    let (_, sw) = drive(app, &apdu(0x01, 0, 0, &data));
    sw
}

/// How many maximal credentials this device store can make **durable**.
///
/// Persisting after every PUT is the shape a real session has (each mutation
/// dirties the state, the persist gate runs), and it is the shape that
/// exercises the transient `2 × parts` peak — which is where the store runs
/// out. A `Full` here is the clean, retryable capacity failure, not a latch.
fn durable_maximal_creds() -> usize {
    let mut store = Rp2350SecureStore::new();
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    let secret = [0x5Au8; MAXIMAL_SECRET];
    let mut n = 0usize;
    for i in 0..200u16 {
        // A unique 64-byte name per credential: names must be distinct, and
        // the length is the maximal one.
        let mut name = [b'c'; MAXIMAL_NAME];
        name[MAXIMAL_NAME - 2..].copy_from_slice(&i.to_le_bytes());
        assert_eq!(
            put_cred(&mut app, &name, &secret),
            0x9000,
            "PUT {i} must be accepted"
        );
        if !app.persist_state(&mut store) {
            return n;
        }
        n += 1;
    }
    n
}

/// The headline capacity number, **measured**, and the arithmetic it rests on.
///
/// Measured on this build: **30 maximal credentials**, 5,460 B of stream at
/// 182 B each. That is 12 chunked parts (11 × 496 = 5,456 is 4 B short, so the
/// 30th spills into a 12th). The OATH app also holds one resident entry
/// outside the chunked table: the US-1030 seal high-water mark
/// (`oath.seal.gen.v1`).
///
/// # Why 31 does not fit — and it is *not* because of a 13th part
///
/// US-1010 first wrote this as "the 31st credential needs a 13th part, so the
/// rewrite peaks at 12 + 13 + 1 = 25 > 24". That is wrong twice: 31
/// credentials is 5,642 B, which is still **12** parts (12 × 496 = 5,952), and
/// `12 + 13 + 1` is 26, not 25. The conclusion survived; the derivation did
/// not, and the derivation is the part a support answer has to be able to
/// stand behind.
///
/// The correct statement is that the binding constraint is the **rewrite
/// peak**, `parts_live + parts_being_written + resident`, and the peak depends
/// on how many parts the *previous* generation had:
///
/// * reaching 12 parts for the first time rewrites **from 11**:
///   `11 + 12 + 1 = 24 ≤ 24` — fits, so the 30th credential is durable;
/// * the 31st is still a 12-part value, so its rewrite is **12 → 12**:
///   `12 + 12 + 1 = 25 > 24` — the clean, retryable `SecureStoreError::Full`,
///   not corruption.
///
/// The number the tree used to carry was **~42**, derived by dividing a
/// hand-copied 195 B/credential into the *undeliverable* 8,432 B. Both halves
/// were wrong. The byte bound is 5,952 B and the per-credential cost is 182 B,
/// and — this is the part the arithmetic gets wrong twice if you do it from
/// the byte count alone — the binding constraint is the **part count under the
/// double-buffered rewrite**, not the byte count. 31 credentials is 5,642 B,
/// which fits *both* 5,952 B and 12 parts; it still cannot be made durable.
///
/// If this test starts failing because a change made the table cheaper or
/// dearer, the honest response is to update the number in `oath_core.rs`'s
/// module docs and `docs/size-report.md` to the new measurement — not to
/// widen the constant here, and never to raise `DEV_MAX_ENTRIES` to make it go
/// away: that costs 568 B of partition image **and** ~580 B of bss per entry on
/// a build with zero unallocated RAM.
#[test]
fn the_documented_credential_ceiling_is_the_measured_one() {
    const DOCUMENTED: usize = 30;
    /// Resident entries the OATH app itself holds, outside the chunked table:
    /// the US-1030 seal high-water mark.
    const RESIDENT_SLOTS: usize = 1;
    const MEASURED_STREAM_BYTES: usize = 5_460;
    const MEASURED_PARTS: usize = 12;

    let measured = durable_maximal_creds();
    assert_eq!(
        measured, DOCUMENTED,
        "the durable maximal-credential count moved ({measured}, was {DOCUMENTED}). Update the \
         capacity in apps/oath/src/oath_core.rs's module docs and docs/size-report.md to the \
         measured value; do not change the ceiling here."
    );

    // Restate the arithmetic so a reader can check the number rather than trust
    // it, and so a future change to either constant breaks something.
    assert_eq!(
        MEASURED_STREAM_BYTES / DOCUMENTED,
        182,
        "182 B per maximal credential"
    );
    assert_eq!(
        MEASURED_STREAM_BYTES.div_ceil(chunked::PART_PAYLOAD_MAX),
        MEASURED_PARTS,
        "the stream occupies {MEASURED_PARTS} parts, not fewer"
    );
    // The 31st credential is NOT a 13th part. This is the claim US-1010 got
    // wrong, and it is the one that makes the rest of the arithmetic checkable:
    // if a 31st ever did need a 13th part, the ceiling would be set by the
    // part count crossing 12, not by the rewrite peak, and the reasoning
    // below would be the wrong story.
    let thirty_one = MEASURED_STREAM_BYTES + 182;
    assert_eq!(
        thirty_one.div_ceil(chunked::PART_PAYLOAD_MAX),
        MEASURED_PARTS,
        "31 credentials is {thirty_one} B and is still {MEASURED_PARTS} parts — if this changes, \
         the ceiling is set by the part count and the rewrite-peak derivation is stale"
    );
    // Reaching 12 parts rewrites FROM 11, and that peak is what fits. Both
    // capacity claims below are between constants, so they are `const`
    // asserts: they hold at compile time or the build does not happen, and a
    // runtime `assert!` would only restate a constant on every test run
    // (clippy::assertions_on_constants).
    const _: () = assert!(
        (MEASURED_PARTS - 1) + MEASURED_PARTS + RESIDENT_SLOTS <= rp2350::DEV_MAX_ENTRIES,
        "the 30th credential must fit: it is the first to reach MEASURED_PARTS \
         parts, so the rewrite peaks one part below that, plus the resident slot"
    );
    // …and one more credential does not, because it is a *same-width* rewrite:
    // both generations are 12 parts, plus the resident slot.
    const _: () = assert!(
        2 * MEASURED_PARTS + RESIDENT_SLOTS > rp2350::DEV_MAX_ENTRIES,
        "the 31st credential must not fit: a same-width rewrite holds both \
         generations at once, plus the resident slot"
    );
    // And the byte bound is *not* what stops it — 31 credentials is 5,642 B
    // and would fit 5,952 B. Saying otherwise is the error this test exists
    // to prevent.
    assert!(
        thirty_one <= chunked::MAX_LOGICAL_LEN,
        "the 31st credential is {thirty_one} B and DOES fit the {} B byte bound — so the \
         ceiling is the rewrite peak, not the byte count",
        chunked::MAX_LOGICAL_LEN
    );
}

/// The store runs out of **parts**, and the peak is the double-buffered
/// rewrite's, not the steady state's.
///
/// This is the claim the capacity number depends on: if the transient peak
/// were only `parts` entries, the ceiling would be roughly twice what is
/// documented, and the constant above would be under-stating the device.
///
/// # The direct observation, and why it replaced an arithmetic restatement
///
/// US-1010 asserted `2 * parts <= DEV_MAX_ENTRIES` here. That is arithmetic on
/// a read-back, not an observation of the peak, and it is **wrong**: it counts
/// the two generations and omits the third thing that is resident during the
/// rewrite, the US-1030 seal high-water mark (`oath.seal.gen.v1`). At 12 parts
/// the true peak is `12 + 12 + 1 = 25`, one over the store's 24 — and the
/// arithmetic form asserted the opposite.
///
/// So this test now *observes* the peak instead of restating it: at the
/// measured ceiling, a PUT that does not widen the table (it replaces a
/// credential, so the stream stays 12 parts) is accepted by the protocol and
/// still cannot be persisted. That rewrite is `12 → 12`, the exact peak the
/// capacity argument turns on, and it fails for one reason only. A model that
/// cannot reproduce that observation is not the model.
#[test]
fn the_ceiling_is_the_double_buffered_rewrite_peak_not_the_steady_state() {
    // Grow to the measured ceiling, persisting after every PUT.
    let mut store = Rp2350SecureStore::new();
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    let secret = [0x5Au8; MAXIMAL_SECRET];
    let mut persisted = 0usize;
    for i in 0..200u16 {
        let mut name = [b'c'; MAXIMAL_NAME];
        name[MAXIMAL_NAME - 2..].copy_from_slice(&i.to_le_bytes());
        assert_eq!(put_cred(&mut app, &name, &secret), 0x9000);
        if !app.persist_state(&mut store) {
            break;
        }
        persisted += 1;
    }

    // Read the persisted stream back and take its part count. The steady state
    // holds one generation; the rewrite that *failed* is the one that had to
    // hold two, so this is the number the peak is derived from.
    let mut out = [0u8; chunked::MAX_LOGICAL_LEN];
    let n = chunked::read_chunked(&mut store, b"oath.keystore.v1", &mut out)
        .expect("the persisted table must be readable back");
    let parts = n.div_ceil(chunked::PART_PAYLOAD_MAX).max(1);

    assert!(
        persisted > 0,
        "the fixture must persist at least one credential or this test proves nothing"
    );
    // The steady state is NOT the peak: it holds one generation plus the
    // resident seal slot and leaves a lot of the store unused.
    const RESIDENT_SLOTS: usize = 1;
    assert!(
        parts + RESIDENT_SLOTS < rp2350::DEV_MAX_ENTRIES,
        "the steady state ({parts} + {RESIDENT_SLOTS} = {}) already fills the store's {} entries, \
         so this test is no longer distinguishing the steady state from the rewrite peak",
        parts + RESIDENT_SLOTS,
        rp2350::DEV_MAX_ENTRIES,
    );

    // The observation. Replacing a credential does not widen the stream, so the
    // next persist is a `parts -> parts` rewrite: the peak the capacity number
    // turns on, at `parts + parts + resident`.
    let mut name = [b'c'; MAXIMAL_NAME];
    name[MAXIMAL_NAME - 2..].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(
        put_cred(&mut app, &name, &secret),
        0x9000,
        "a same-width PUT at the ceiling is a well-formed request and must be accepted; \
         the failure below is capacity, not protocol"
    );
    let rewrote = app.persist_state(&mut store);
    let peak = 2 * parts + RESIDENT_SLOTS;
    assert!(
        !rewrote,
        "a same-width rewrite at {parts} parts persisted, so the rewrite peak fits {} entries \
         and the documented ceiling of {} is an UNDER-statement — the peak is {parts} + {parts} \
         + {RESIDENT_SLOTS} = {peak} against the store's {}",
        peak,
        persisted,
        rp2350::DEV_MAX_ENTRIES,
    );
    // …and the arithmetic agrees with the observation, which is what makes the
    // observation a check on the model rather than a separate anecdote.
    assert!(
        peak > rp2350::DEV_MAX_ENTRIES,
        "the observed failure says the peak ({peak}) exceeds {} entries, but the arithmetic says \
         it fits — the two must not disagree, and if they do the SEAL SLOT or the rewrite \
         accounting has moved and this test is no longer measuring what it claims",
        rp2350::DEV_MAX_ENTRIES,
    );
    // The store is left consistent: the failed persist did not corrupt the
    // stream, and the app stays dirty so the gate retries.
    let after = chunked::read_chunked(&mut store, b"oath.keystore.v1", &mut out)
        .expect("the persisted table must still be readable back after a refused rewrite");
    assert_eq!(
        after, n,
        "a refused rewrite must leave the previous generation intact, not truncate it"
    );
}

/// A fresh `HostSecureStore` is unbounded, so the ceiling above is the
/// **device** store's and not the layer's. Guard that: if a future change
/// made `Rp2350SecureStore` unbounded, the number in the docs would silently
/// become an under-statement again.
#[test]
fn the_ceiling_is_a_property_of_the_device_store() {
    let mut host = HostSecureStore::new();
    let big = [0u8; chunked::MAX_LOGICAL_LEN];
    // The host store has no entry cap, so a full-width write succeeds there.
    assert!(
        chunked::write_chunked(&mut host, b"oath.keystore.v1", &big).is_ok(),
        "HostSecureStore is unbounded; the ceiling under test is Rp2350SecureStore's"
    );

    // …and the device store refuses a value one part beyond the bound, which
    // is the clean capacity error (never a panic, never a partial write).
    let mut dev = Rp2350SecureStore::new();
    let over = vec![0u8; chunked::MAX_LOGICAL_LEN + 1];
    assert_eq!(
        chunked::write_chunked(&mut dev, b"oath.keystore.v1", &over),
        Err(SecureStoreError::ValueTooLong)
    );
}
