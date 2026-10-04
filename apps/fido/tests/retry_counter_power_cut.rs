//! US-1571 — the retry counter across a power cut, pinned as an invariant.
//!
//! The properties in this file already hold. Nothing here is a redesign: it is
//! the assertion that they keep holding, over **every torn-write point** of a
//! failed verification rather than over a sample.
//!
//! ```gherkin
//! Scenario: a failed attempt can never yield more retries than before it
//!   Given the retry counter and 3-strike latch inside the AEAD-sealed snapshot
//!   When power-cut oracles replay every torn-write point of a failed verification
//!   Then the durable retry count is never higher than the pre-attempt count
//!   And the counter is never resettable without the store key
//!   And the residual (a torn write rolling back to the prior snapshot generation)
//!     is documented as such rather than claimed away
//! ```
//!
//! # The three mechanisms this pins, and where they live
//!
//! 1. **Decrement before compare.** `device_core.rs` decrements the counter and
//!    sets `dirty` *before* it re-derives the verifier, on both the changePIN
//!    (`:2077-2078`) and getPinToken (`:2176-2177`) arms. So a wrong PIN costs
//!    a retry whether or not the comparison is reached.
//! 2. **Durable before ack.** The decrement is not written by the command; it is
//!    written by the persist gate (`DeviceKeystore::persist_if_dirty`, called
//!    from `FidoApp::persist_if_dirty`) which the transport runs before the
//!    reply leaves. `US-421`: a failed store write keeps `dirty` set rather
//!    than dropping the change.
//! 3. **The counter is authenticated.** The snapshot is an AEAD-sealed
//!    partition image (`store_v3`, encrypt-then-MAC per entry), and the store
//!    key is OTP + chipid-derived on the device. pico-openpgp re-initialises an
//!    erased counter file to `3,3,3` (`openpgp.c:448-452`) and RS-Key's lockout
//!    rides an unauthenticated scratch tag (`pin_lock.rs:36-40`); neither can
//!    say this.
//!
//! # The residual, which is the point of the third test
//!
//! The property above is **monotone non-increasing**, not "strictly
//! decreasing". A torn write that rolls back to the prior snapshot generation
//! *restores* the retry count: the decrement is lost and the failed attempt
//! becomes free. An attacker with physical access can therefore take the power
//! away between the wrong PIN and the persist, repeatedly, and the budget never
//! moves.
//!
//! This is written down rather than claimed away because it is a property of
//! the storage medium, not of the code: `chunked::write_chunked` writes a new
//! generation into the buffer *not* holding the current set and writes part 0 —
//! the commit marker — **last**, precisely so that a torn write cannot destroy
//! the last valid set. That is the right design for crash consistency and it is
//! exactly what makes a rollback possible. Closing it needs a mechanism that
//! is not a rollback-resistant counter: an append-only latch (each failure burns
//! a distinct one-time flag), or the attempt being recorded *before* it is
//! spent. Neither exists, and inventing one is out of scope for a story whose
//! requirement is to pin what is already there.
//!
//! `a_torn_write_can_roll_the_retry_count_back_to_the_prior_generation` names
//! the residual and asserts it, so a future change that closes it fails here —
//! which is the correct direction for a test to fail in.

use fapico2_fido::cbor::no_heap as nh;
use fapico2_fido::cbor::no_heap::{Item, Parser};
use fapico2_fido::crypto;
use fapico2_fido::device_app::FidoApp;
use fapico2_fido::device_keystore::DeviceKeystore;
use fapico2_platform::secure_store::rp2350::Rp2350SecureStore;
use fapico2_platform::secure_store::{SecureStore, SecureStoreError};
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;
use p256::SecretKey;

const CTAP2_MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;
/// The device's full retry budget (`device_core.rs`: `MAX_PIN_RETRIES`).
const MAX_PIN_RETRIES: u8 = 8;
/// The PIN the fixture device is set to. Never a *correct* candidate for the
/// failed verifications below — the point is the failed path.
const PIN: &[u8] = b"1234";
/// CTAP2 `PIN_INVALID` (0x31) — a wrong PIN that has not yet tripped the latch.
const PIN_INVALID: u8 = 0x31;
/// CTAP2 `PIN_AUTH_BLOCKED` (0x34) — the third consecutive mismatch. This is
/// the status the attempt under test returns, because the fixtures below prime
/// the device to exactly two strikes.
const PIN_AUTH_BLOCKED: u8 = 0x34;

// ---------------------------------------------------------------------------
// The power-cut oracle
// ---------------------------------------------------------------------------

/// A [`SecureStore`] that **fails its Nth mutating operation and every one
/// after it**, over a real [`Rp2350SecureStore`].
///
/// This is the oracle, and what makes it genuine rather than a simulation:
///
/// * The mutating operations it counts are the store's own `write` and
///   `delete` — the only two calls that change durable state. Everything the
///   keystore persists goes through `chunked::write_chunked`, which is
///   `count` writes (part `count-1` down to part `0`, the commit marker,
///   **last**) followed by up to `MAX_PARTS` deletes retiring the previous
///   generation. So "fail after k" is a torn write at a real program boundary,
///   not an injected error at an arbitrary point in the caller.
/// * The failure is `Err`, and `write_chunked`'s own self-cleaning pass then
///   deletes whatever this call had written — which is exactly what a device
///   whose flash program failed would leave behind, and it is what makes the
///   sweep cover the "orphaned part" states rather than skipping them.
/// * Everything before `arm` runs untouched, so the device is brought up, has
///   its PIN set and reaches its pre-attempt state through the ordinary path.
struct CutStore {
    inner: Rp2350SecureStore,
    /// Mutating operations still permitted. `0` means the next one fails.
    allowance: usize,
    /// Armed at all? Before `arm` the store is a pass-through, so setup
    /// (boot, setPIN, the earlier failed attempts) cannot be cut by accident.
    armed: bool,
    /// Every mutating operation attempted since `arm`, in order.
    ops: Vec<String>,
    /// The key this store seals its partition image with, if any.
    key: Option<[u8; 32]>,
}

impl CutStore {
    fn new(key: Option<[u8; 32]>) -> Self {
        let mut inner = Rp2350SecureStore::new();
        if let Some(k) = key {
            inner.set_store_key(k);
        }
        Self { inner, allowance: 0, armed: false, ops: Vec::new(), key }
    }

    /// Let `n` further mutating operations through, then fail every one after.
    fn arm(&mut self, n: usize) {
        self.allowance = n;
        self.armed = true;
        self.ops.clear();
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.allowance = usize::MAX;
    }

    /// One mutating operation: record it, then succeed or fail.
    fn step(&mut self, what: &str) -> Result<(), SecureStoreError> {
        if !self.armed {
            return Ok(());
        }
        self.ops.push(what.to_string());
        if self.allowance == 0 {
            // The flash program failed. `Flash` is the variant the secure
            // partition driver itself reports (US-422), and it is *not* one of
            // the "your bytes are not trustworthy" errors — the bytes already
            // written are fine, the next one never landed.
            return Err(SecureStoreError::Flash);
        }
        self.allowance -= 1;
        Ok(())
    }

    /// Everything a power cut leaves behind: the durable partition image.
    fn image(&self) -> Vec<u8> {
        let mut img = vec![0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
        let len = self.inner.partition_image(&mut img).expect("the image fits");
        img.truncate(len);
        img
    }
}

impl SecureStore for CutStore {
    fn write(&mut self, key: &[u8], value: &[u8]) -> Result<(), SecureStoreError> {
        self.step(&format!("write {}", String::from_utf8_lossy(key)))?;
        self.inner.write(key, value)
    }

    fn read(&mut self, key: &[u8], out: &mut [u8]) -> Result<usize, SecureStoreError> {
        self.inner.read(key, out)
    }

    /// `is_read` is deliberately *not* intercepted: a torn write does not make
    /// the store's own reads fail, it just returns the previous generation.
    /// Counting reads would shrink the sweep to the wrong points.
    fn delete(&mut self, key: &[u8]) -> Result<(), SecureStoreError> {
        self.step(&format!("delete {}", String::from_utf8_lossy(key)))?;
        self.inner.delete(key)
    }

    fn contains(&self, key: &[u8]) -> bool {
        self.inner.contains(key)
    }

    fn snapshot_partition(&self, buf: &mut [u8]) -> Result<usize, SecureStoreError> {
        self.inner.snapshot_partition(buf)
    }

    fn snapshot_len(&self) -> usize {
        self.inner.snapshot_len()
    }

    fn snapshot_window(&self, off: usize, buf: &mut [u8]) -> usize {
        self.inner.snapshot_window(off, buf)
    }

    fn is_empty(&self) -> Result<bool, SecureStoreError> {
        self.inner.is_empty()
    }

    fn is_empty_except(&self, slot: &[u8]) -> Result<bool, SecureStoreError> {
        self.inner.is_empty_except(slot)
    }

    fn wipe_all(&mut self) -> Result<(), SecureStoreError> {
        self.step("wipe_all")?;
        self.inner.wipe_all()
    }

    fn store_key(&self) -> Option<[u8; 32]> {
        self.key
    }
}

/// Boot a fresh device from a durable image and read back the retry counter.
///
/// This is what a power-on does: the in-RAM app is discarded and a new one
/// boots from the partition image that survived. The store key is *not* set —
/// the fixture stores for the cut sweep are unkeyed, so the image is the
/// legacy format-v2 serialization and the restore is the ordinary one. The
/// keyed case is `the_counter_is_not_resettable_without_the_store_key`'s job.
///
/// `Err(Corrupt)` and `Ok(None)` are both "there is no usable snapshot", and
/// both are answered `None` here: a failed verification must never leave the
/// device *unable to answer*, because a client that cannot read `getRetries`
/// cannot tell a lockout from a broken device.
fn durable_retries(img: &[u8], key: Option<[u8; 32]>) -> Option<u8> {
    let mut store = Rp2350SecureStore::new();
    if let Some(k) = key {
        store.set_store_key(k);
    }
    store.from_partition_image(img);
    let ks = DeviceKeystore::load(&mut store).ok()??;
    Some(ks.pin_state.retries)
}

/// The full durable PIN record a power-on reads back.
fn durable_pin_state(img: &[u8]) -> Option<(u8, bool, bool, u32)> {
    let mut store = Rp2350SecureStore::new();
    store.from_partition_image(img);
    let ks = DeviceKeystore::load(&mut store).ok()??;
    let s = ks.pin_state;
    Some((s.retries, s.blocked, s.needs_power_cycle, s.new_pin_mismatches as u32))
}

// ---------------------------------------------------------------------------
// The device-twin client
// ---------------------------------------------------------------------------

struct DeviceClient {
    /// PIN-protocol-v1 shared key. v1 and v2 have the same HMAC and encryption
    /// key, so one `k` serves both legs and the request stays short.
    k: [u8; 32],
    x: [u8; 32],
    y: [u8; 32],
}

impl DeviceClient {
    /// getKeyAgreement (clientPin sub-command `0x02`) then ECDH.
    fn new(app: &mut FidoApp) -> Self {
        let sk = SecretKey::from_slice(&[0x39u8; 32]).expect("a fixed client scalar");
        let mut req: HV<u8, 16> = HV::new();
        nh::push_map_header(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        let resp = call(app, 0x06, req.as_slice());
        assert_eq!(resp[0], 0x00, "getKeyAgreement must succeed");

        let mut p = Parser::new(&resp[1..]);
        let Item::Map(_) = p.next().unwrap() else {
            panic!("reply map")
        };
        let Item::U(1) = p.next().unwrap() else {
            panic!("label 1")
        };
        let Item::Map(n) = p.next().unwrap() else {
            panic!("cose map")
        };
        let mut dx = [0u8; 32];
        let mut dy = [0u8; 32];
        for _ in 0..n {
            let label = match p.next().unwrap() {
                Item::U(u) => u as i64,
                Item::N(n) => n,
                other => panic!("label {other:?}"),
            };
            match label {
                -2 => match p.next().unwrap() {
                    Item::B(b) => dx.copy_from_slice(b),
                    other => panic!("x {other:?}"),
                },
                -3 => match p.next().unwrap() {
                    Item::B(b) => dy.copy_from_slice(b),
                    other => panic!("y {other:?}"),
                },
                _ => {
                    p.skip().unwrap();
                }
            }
        }
        let device_pub = crypto::parse_cose_ec2_p256_bytes(&dx, &dy).expect("device pubkey");
        let raw = crypto::ecdh_shared_secret(&sk, &device_pub);
        // v1: hmac_key == enc_key == SHA256(raw), so one key serves both the
        // auth and the encryption leg and the requests stay inside their
        // no-heap scratch.
        let k = crypto::derive_shared_secret_v1(&raw);
        let sec1 = crypto::public_key_bytes(&sk.public_key());
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&sec1[1..33]);
        y.copy_from_slice(&sec1[33..65]);
        Self { k, x, y }
    }

    fn push_cose<const N: usize>(&self, out: &mut HV<u8, N>) {
        nh::push_map_header(out, 5).unwrap();
        nh::push_uint(out, 1).unwrap();
        nh::push_uint(out, 2).unwrap();
        nh::push_uint(out, 3).unwrap();
        nh::push_neg(out, -25).unwrap();
        nh::push_neg(out, -1).unwrap();
        nh::push_uint(out, 1).unwrap();
        nh::push_neg(out, -2).unwrap();
        nh::push_bstr(out, &self.x).unwrap();
        nh::push_neg(out, -3).unwrap();
        nh::push_bstr(out, &self.y).unwrap();
    }

    /// setPIN (`0x03`). `pin` is NUL-padded to a 64-byte block.
    fn set_pin(&self, app: &mut FidoApp, pin: &[u8]) {
        let mut plain = [0u8; 64];
        plain[..pin.len()].copy_from_slice(pin);
        let enc = crypto::aes_cbc_encrypt(&self.k, &[0u8; 16], &plain);
        let param = crypto::hmac_sha256(&self.k, &enc);
        let mut req: HV<u8, 320> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap(); // pinUvAuthProtocol v1
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 3).unwrap(); // setPIN
        nh::push_uint(&mut req, 3).unwrap();
        self.push_cose(&mut req);
        nh::push_uint(&mut req, 4).unwrap();
        nh::push_bstr(&mut req, &param[..16]).unwrap();
        nh::push_uint(&mut req, 5).unwrap();
        nh::push_bstr(&mut req, &enc).unwrap();
        let resp = call(app, 0x06, req.as_slice());
        assert_eq!(resp[0], 0x00, "setPIN must succeed, got 0x{:02x}", resp[0]);
    }

    /// getPinToken (`0x05`) with a 16-byte `SHA256(candidate)[..16]` the caller
    /// chose. Returns the CTAP2 status byte.
    fn get_token_with_candidate(&self, app: &mut FidoApp, pin_hash: [u8; 16]) -> u8 {
        let enc = crypto::aes_cbc_encrypt(&self.k, &[0u8; 16], &pin_hash);
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 4).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 5).unwrap(); // getPinToken
        nh::push_uint(&mut req, 3).unwrap();
        self.push_cose(&mut req);
        nh::push_uint(&mut req, 6).unwrap();
        nh::push_bstr(&mut req, &enc).unwrap();
        call(app, 0x06, req.as_slice())[0]
    }

    fn wrong_pin_attempt(&self, app: &mut FidoApp) -> u8 {
        self.get_token_with_candidate(app, crypto::pin_hash(b"0000-wrong"))
    }
}

fn call(app: &mut FidoApp, cmd: u8, payload: &[u8]) -> Vec<u8> {
    let mut out: HV<u8, CTAP2_MAX_MSG> = HV::new();
    let n = app.process_ctap2(cmd, payload, [1, 2, 3, 4], &mut out);
    out[..n].to_vec()
}

/// Bring a device up on `store` with `PIN` set and `failures` wrong PINs
/// already durably spent. Returns the pre-attempt durable retry count.
fn primed(store: &mut CutStore, failures: u8) -> (u8, ()) {
    let mut trng = HostTrng::new();
    let mut app = FidoApp::boot(&mut trng, store).expect("boot");
    let _ = app.persist_if_dirty(store);
    let client = DeviceClient::new(&mut app);
    client.set_pin(&mut app, PIN);

    // A large-blob array the device will never serve. It exists only to make
    // the snapshot **multi-part**: `write_chunked` writes part 0 last, so a
    // one-part snapshot has exactly one torn-write point (before it) and the
    // interesting mid-write states are unreachable. With three parts the sweep
    // covers "part 2 landed", "part 1 landed", "part 0 landed", and the
    // retirement deletes after each.
    let mut blob: heapless::Vec<u8, 1024> = heapless::Vec::new();
    blob.extend_from_slice(&[0x5Au8; 1024]).unwrap();
    app.keystore().large_blob_array = Some(blob);
    app.persist_if_dirty(store);

    for _ in 0..failures {
        assert_eq!(
            client.wrong_pin_attempt(&mut app),
            PIN_INVALID,
            "a wrong PIN must answer PIN_INVALID while the latch is unset"
        );
        assert!(app.persist_if_dirty(store), "the decrement must be durable");
    }
    store.disarm();
    let pre = MAX_PIN_RETRIES - failures;
    // The store's own key, because a keyed store seals its image: reading it
    // back without the key is the attack `the_counter_is_not_resettable_...`
    // performs, not the control this line is.
    assert_eq!(durable_retries(&store.image(), store.key), Some(pre));
    (pre, ())
}

// ---------------------------------------------------------------------------
// "the durable retry count is never higher than the pre-attempt count"
// ---------------------------------------------------------------------------

/// HEADLINE (US-1571): cut the power at **every** torn-write point of one
/// failed verification and require that the durable retry count is never
/// *higher* than it was before the attempt.
///
/// # Why the sweep is over the store's mutating operations and not over "a
/// failure"
///
/// A `SecureStore` that fails once, somewhere, is a simulation: it does not
/// say *which* bytes reached flash, and the whole question is which ones did.
/// [`CutStore`] therefore fails the k-th `write`/`delete` for every k, and the
/// store underneath is the real [`Rp2350SecureStore`] writing a real multi-part
/// chunked snapshot. Every k from 0 (nothing reached flash) to the total number
/// of mutating operations (the whole rewrite landed and only the retirement
/// pass was cut) is a distinct durable state, and each one is asserted.
///
/// The property is **non-increasing**, not decreasing. See the module docs: the
/// rolled-back states are real, and
/// `a_torn_write_can_roll_the_retry_count_back_to_the_prior_generation` is the
/// test that says so out loud.
#[test]
fn the_durable_retry_count_is_never_higher_than_the_pre_attempt_count() {
    // **Two** prior failures, not three: the third consecutive mismatch trips
    // the durable 3-strike latch (`new_pin_mismatches >= 3`,
    // `device_core.rs`), so priming to three would leave the attempt under test
    // answering `PIN_AUTH_BLOCKED` (0x34) instead of exercising the ordinary
    // refusal. Two also keeps the counter away from both ends — not at its
    // maximum, where a `saturating_sub` would be indistinguishable from a
    // working decrement, and not near zero.
    let failures: u8 = 2;
    let pre = MAX_PIN_RETRIES - failures;

    // One uncut run first, so the sweep covers every mutating operation the
    // attempt performs rather than a guessed number of them. Counting the
    // operations of the *cut* runs cannot do it: a cut at k only ever attempts
    // k+1 of them.
    let ops_in_a_failed_attempt = {
        let mut store = CutStore::new(None);
        let _ = primed(&mut store, failures);
        let mut trng = HostTrng::new();
        let mut app = FidoApp::boot(&mut trng, &mut store).expect("boot");
        let client = DeviceClient::new(&mut app);
        store.arm(usize::MAX);
        assert_eq!(client.wrong_pin_attempt(&mut app), PIN_AUTH_BLOCKED);
        let _ = app.persist_if_dirty(&mut store);
        drop(app);
        let ops = store.ops.len();
        store.disarm();
        ops
    };
    let mut distinct_durable_states = Vec::new();

    // k = 0 ..= ops, inclusive of both ends: `0` is "the first write never
    // reached flash" and `ops` is "every write landed and the cut fell inside
    // the retirement pass".
    for k in 0..=ops_in_a_failed_attempt {
        let mut store = CutStore::new(None);
        let (pre_observed, ()) = primed(&mut store, failures);
        assert_eq!(pre_observed, pre);

        let mut trng = HostTrng::new();
        let mut app = FidoApp::boot(&mut trng, &mut store).expect("boot");
        let client = DeviceClient::new(&mut app);

        store.arm(k);
        let status = client.wrong_pin_attempt(&mut app);
        assert_eq!(
            status, PIN_AUTH_BLOCKED,
            "the attempt under test is the third strike and must answer \
             PIN_AUTH_BLOCKED; a different status means the fixture no longer \
             drives the arm under test"
        );
        // Durable-before-ack: the persist gate runs whether or not the write
        // succeeded, and the in-RAM app is then thrown away. Everything that
        // survives is the partition image.
        let _ = app.persist_if_dirty(&mut store);
        drop(app);
        // The cut had an effect. It does not attempt *exactly* one more
        // operation: `write_chunked`'s own self-cleaning pass deletes whatever
        // the failed call had already written, and those deletes are mutating
        // operations too. That is deliberate (S-731-2) and it is why the
        // oracle counts operations rather than assuming a fixed count — the
        // orphan states are part of what a real power cut leaves behind.
        if k < ops_in_a_failed_attempt {
            assert!(
                store.ops.len() > k,
                "a cut after {k} of {ops_in_a_failed_attempt} operation(s) \
                 attempted nothing beyond the allowance, so the injected \
                 failure did not happen"
            );
        } else {
            // The upper endpoint: nothing was cut, so every mutating operation
            // landed. It is still a distinct point in the sweep — it is the
            // durable state the persist gate was reaching for.
            assert_eq!(
                store.ops.len(),
                ops_in_a_failed_attempt,
                "the upper endpoint of the sweep must not cut anything"
            );
        }
        store.disarm();

        let durable = durable_retries(&store.image(), store.key);
        let durable = durable.expect(
            "a failed verification must leave a loadable snapshot: a device \
             that cannot answer getRetries is worse than one with a stale count",
        );
        assert!(
            durable <= pre,
            "cut after {k} of {ops_in_a_failed_attempt} mutating store \
             operation(s): the durable retry count came back as {durable}, \
             which is HIGHER than the {pre} the device had before the attempt. \
             A cut may lose a decrement; it must never invent one."
        );

        if !distinct_durable_states.contains(&durable) {
            distinct_durable_states.push(durable);
        }
    }

    assert!(
        ops_in_a_failed_attempt > 3,
        "a failed verification performed only {ops_in_a_failed_attempt} \
         mutating store operations — too few for this sweep to be a torn-write \
         sweep rather than a single point. The fixture must produce a \
         multi-part snapshot."
    );
    // The sweep found more than one durable value, which is what makes it a
    // sweep: a run that only ever produced `pre` would have proved nothing
    // about the states in between.
    assert!(
        distinct_durable_states.len() > 1,
        "every cut produced the same durable retry count {distinct_durable_states:?} \
         — the sweep did not reach a commit-marker point, so it never observed \
         the decrement landing"
    );
}

/// The same property through `changePIN` (`0x04`), which is the other arm that
/// decrements before comparing.
///
/// Not redundant with the getPinToken sweep: the two arms are separate code
/// with separate persist behaviour (changePIN goes through the same gate, but
/// its failure path also touches the `new_pin_mismatches` latch counter), and a
/// property that holds on one arm and not the other is the interesting case.
#[test]
fn the_property_holds_on_the_changepin_arm_too() {
    let mut store = CutStore::new(None);
    let (pre, ()) = primed(&mut store, 2);
    let mut trng = HostTrng::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).expect("boot");
    let client = DeviceClient::new(&mut app);

    // changePIN with a wrong old-PIN hash and a syntactically valid new one.
    let wrong = crypto::aes_cbc_encrypt(&client.k, &[0u8; 16], &crypto::pin_hash(b"0000-wrong"));
    let mut new_pin = [0u8; 64];
    new_pin[..5].copy_from_slice(b"56789");
    let new_enc = crypto::aes_cbc_encrypt(&client.k, &[0u8; 16], &new_pin);
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&new_enc);
    auth_data.extend_from_slice(&wrong);
    let param = crypto::hmac_sha256(&client.k, &auth_data);

    let mut req: HV<u8, 320> = HV::new();
    nh::push_map_header(&mut req, 6).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_uint(&mut req, 2).unwrap();
    nh::push_uint(&mut req, 4).unwrap(); // changePIN
    nh::push_uint(&mut req, 3).unwrap();
    client.push_cose(&mut req);
    nh::push_uint(&mut req, 4).unwrap();
    nh::push_bstr(&mut req, &param[..16]).unwrap();
    nh::push_uint(&mut req, 5).unwrap();
    nh::push_bstr(&mut req, &new_enc).unwrap();
    nh::push_uint(&mut req, 6).unwrap();
    nh::push_bstr(&mut req, &wrong).unwrap();

    store.arm(0);
    let status = call(&mut app, 0x06, req.as_slice())[0];
    assert_eq!(
        status, PIN_AUTH_BLOCKED,
        "changePIN with a wrong old PIN on the third strike is PIN_AUTH_BLOCKED"
    );
    let _ = app.persist_if_dirty(&mut store);
    drop(app);
    store.disarm();

    let durable = durable_retries(&store.image(), store.key).expect("a loadable snapshot");
    assert!(
        durable <= pre,
        "changePIN's cut before anything reached flash came back at {durable}, \
         above the pre-attempt {pre}"
    );
}

// ---------------------------------------------------------------------------
// the residual
// ---------------------------------------------------------------------------

/// THE RESIDUAL, asserted rather than claimed away: a torn write that rolls
/// back to the prior snapshot generation **restores** the retry count, so the
/// failed attempt costs nothing.
///
/// This test is the reason the headline property is stated as "never higher"
/// rather than "always one lower". Read together they say exactly what is true:
///
/// * a cut can never *increase* the budget — that is the security-relevant
///   direction and it is absolute;
/// * a cut can leave the budget *unchanged* — and an attacker with physical
///   access can take that outcome as often as they like.
///
/// The second is why the CTAP2 retry counter is a speed bump against an
/// unattended device, not a bound against an attacker who controls the power.
/// The C reference has no protection here at all (pico-openpgp re-initialises an
/// erased counter file to `3,3,3`; RS-Key's lockout is an unauthenticated
/// scratch tag), so fapico2 is strictly better — and "strictly better than a
/// speed bump" is where the claim stops.
///
/// If a future change makes this test fail, that is **good news**: it means the
/// rollback is gone. The mechanism that would do it is an append-only latch or
/// a write *before* the compare; neither exists today.
#[test]
fn a_torn_write_can_roll_the_retry_count_back_to_the_prior_generation() {
    let failures: u8 = 2;
    let pre = MAX_PIN_RETRIES - failures;

    // Cut before the very first mutating operation: nothing of the new
    // generation reached flash, so the previous complete generation — with the
    // full pre-attempt count — is what a power-on reads.
    let mut store = CutStore::new(None);
    let (pre_observed, ()) = primed(&mut store, failures);
    assert_eq!(pre_observed, pre);
    let mut trng = HostTrng::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).expect("boot");
    let client = DeviceClient::new(&mut app);

    store.arm(0);
    assert_eq!(client.wrong_pin_attempt(&mut app), PIN_AUTH_BLOCKED);
    let _ = app.persist_if_dirty(&mut store);
    drop(app);
    store.disarm();

    assert_eq!(
        durable_retries(&store.image(), store.key),
        Some(pre),
        "this is the residual, stated as an assertion: a cut before the first \
         program byte restores the retry count to {pre}, so the failed attempt \
         was free. If this fails, the rollback has been closed and this test \
         should be deleted rather than weakened."
    );

    // ...and the counter *is* decremented when the write completes, so the
    // rollback is a torn-write artefact and not a missing decrement. Without
    // this half, the assertion above would also be satisfied by a device that
    // never decrements at all.
    let mut store = CutStore::new(None);
    let (pre2, ()) = primed(&mut store, failures);
    let mut trng = HostTrng::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).expect("boot");
    let client = DeviceClient::new(&mut app);
    assert_eq!(client.wrong_pin_attempt(&mut app), PIN_AUTH_BLOCKED);
    assert!(
        app.persist_if_dirty(&mut store),
        "an uninterrupted failed verification must be durable"
    );
    drop(app);
    assert_eq!(
        durable_retries(&store.image(), store.key),
        Some(pre2 - 1),
        "the decrement must land when the write completes — otherwise the \
         rolled-back state above would not be a torn write but the actual \
         behaviour"
    );
}

// ---------------------------------------------------------------------------
// "the counter is never resettable without the store key"
// ---------------------------------------------------------------------------

/// The durable retry counter cannot be raised without the store key.
///
/// Three arms, and they are three different attacks:
///
/// 1. **Read it back with no key.** The partition image is format-v3
///    encrypt-then-MAC (`store_v3::seal_image`), so a restore without the key
///    cannot open the snapshot at all — the device answers as a fresh one, not
///    as a device with eight retries.
/// 2. **Read it back with the wrong key.** Same, and the failure is silent by
///    design: a wrong key must be indistinguishable from no key, or it becomes
///    an oracle for guessing the key.
/// 3. **Forge it.** A byte-level sweep over the image: at every offset, flip one
///    bit and require that the restore still cannot produce a retry count above
///    the durable one. This is what "MACed under the store key" buys over RS-Key's
///    unauthenticated scratch tag — there, flipping the byte is the attack.
#[test]
fn the_counter_is_not_resettable_without_the_store_key() {
    const STORE_KEY: [u8; 32] = [0x6Du8; 32];
    const WRONG_KEY: [u8; 32] = [0x6Eu8; 32];

    let failures: u8 = 2;
    let durable = MAX_PIN_RETRIES - failures;

    // A keyed device: same priming, but the image is sealed.
    let mut store = CutStore::new(Some(STORE_KEY));
    let (pre, ()) = primed(&mut store, failures);
    assert_eq!(pre, durable);

    let img = store.image();
    assert!(
        !img.is_empty(),
        "the keyed device must have written a durable image"
    );
    // The image is the sealed format, not the legacy logical one: the magic is
    // the v3 value, which is what makes the two arms below meaningful rather
    // than a plaintext read.
    assert_eq!(
        u32::from_le_bytes([img[0], img[1], img[2], img[3]]),
        fapico2_platform::store_v3::PARTITION_IMAGE_MAGIC_V3,
        "a keyed store must seal its partition image (format v3)"
    );

    // (1) the legitimate reader
    assert_eq!(
        durable_retries(&img, Some(STORE_KEY)),
        Some(durable),
        "with the store key the durable count must read back exactly"
    );

    // (2) no key at all, and a wrong key: both must be indistinguishable from
    // one another, and neither may produce a count.
    assert_eq!(
        durable_retries(&img, None),
        None,
        "a sealed snapshot restored without the store key must not yield a \
         retry count — this is the attack 'replay a reset snapshot'"
    );
    assert_eq!(
        durable_retries(&img, Some(WRONG_KEY)),
        durable_retries(&img, None),
        "a wrong key must be indistinguishable from no key; if it is not, the \
         restore is an oracle for guessing the store key"
    );

    // (3) the forgery sweep. Every single-bit flip, at a stride that covers the
    // whole image — the header, the nonce, the ciphertext, every tag and the
    // trailing CRC. `getRetries` after such a restore may be any value or none;
    // what it must never be is a count *above* the durable one.
    let stride = (img.len() / 256).max(1);
    let mut probed = 0usize;
    for i in (0..img.len()).step_by(stride) {
        for bit in 0..8 {
            let mut forged = img.clone();
            forged[i] ^= 1 << bit;
            let seen = durable_retries(&forged, Some(STORE_KEY));
            if let Some(seen) = seen {
                assert!(
                    seen <= durable,
                    "flipping bit {bit} of image byte {i} produced a restore \
                     with {seen} retries, above the durable {durable}: the \
                     counter can be reset without the store key"
                );
            }
            probed += 1;
        }
    }
    assert!(
        probed >= 256,
        "the forgery sweep probed only {probed} bits — too few to call it a \
         sweep of the image"
    );
}

/// The 3-strike latch rolls back **with** the counter, or not at all.
///
/// The latch (`blocked` / `needs_power_cycle` / `new_pin_mismatches`) and the
/// retry counter are fields of the *same* snapshot record, written by the same
/// `write_chunked`. So a torn write cannot produce the state that would
/// actually be dangerous — "counter decremented, latch cleared" — because there
/// is no intermediate state in which those two disagree. It rolls the pair back
/// together, or it moves them forward together.
///
/// That is a difference in *kind* from the residual the other test names, not in
/// degree. Losing the counter decrement is a loss of progress against a
/// physical attacker; losing the latch is bounded, because the two cannot
/// diverge. Neither is a bound against someone who controls the power, and this
/// test does not claim otherwise.
#[test]
fn the_three_strike_latch_rolls_back_with_the_counter_or_not_at_all() {
    // One prior strike, so the attempt under test is the second and answers
    // PIN_INVALID rather than tripping the latch — the point here is that the
    // latch *counter* moves in lockstep, not that the latch trips.
    let (pre, ()) = primed(&mut CutStore::new(None), 1);
    assert_eq!(pre, MAX_PIN_RETRIES - 1);

    // --- cut before anything reached flash: the whole record comes back ---
    let mut store = CutStore::new(None);
    let (pre_cut, ()) = primed(&mut store, 1);
    let mut trng = HostTrng::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).expect("boot");
    let client = DeviceClient::new(&mut app);
    store.arm(0);
    assert_eq!(client.wrong_pin_attempt(&mut app), PIN_INVALID);
    let _ = app.persist_if_dirty(&mut store);
    drop(app);
    store.disarm();
    let (retries, blocked, power_cycle, mismatches) =
        durable_pin_state(&store.image()).expect("a loadable snapshot");
    assert_eq!(retries, pre_cut, "the counter rolled back");
    assert_eq!(mismatches, 1, "the strike counter rolled back with it");
    assert!(
        !blocked && !power_cycle,
        "the latch is one strike in; a cut that lost the counter must not have \
         cleared or tripped it"
    );

    // --- write intact: both move together ---
    let mut store = CutStore::new(None);
    let (pre_ok, ()) = primed(&mut store, 1);
    let mut trng = HostTrng::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).expect("boot");
    let client = DeviceClient::new(&mut app);
    assert_eq!(client.wrong_pin_attempt(&mut app), PIN_INVALID);
    assert!(app.persist_if_dirty(&mut store));
    drop(app);
    let (retries, blocked, power_cycle, mismatches) =
        durable_pin_state(&store.image()).expect("a loadable snapshot");
    assert_eq!(retries, pre_ok - 1, "the counter moved down");
    assert_eq!(
        mismatches, 2,
        "the strike counter moved with it, in the same snapshot"
    );
    assert!(
        !blocked && !power_cycle,
        "two strikes must not trip a three-strike latch"
    );
    // The control that makes the previous two lines mean something: the
    // counter did move down by exactly one while the latch counter moved up by
    // exactly one, so neither is a coincidence of the other.
    assert_eq!((pre_ok - 1, 2), (retries, mismatches));
}
