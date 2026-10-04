//! US-1011 TDD: the FIDO signature counter is persisted in BATCHES, not on
//! every assertion.
//!
//! The defect this pins: `bump_credential_counter_checked` rewrote the whole
//! keystore image (two slot erases, 8 sector erasures — `docs/erase-budget.md`)
//! on **every** `getAssertion`, so N assertions cost N full-image rewrites and
//! the measured assertion ceiling was the flash's own endurance.
//!
//! What is asserted here is the *count*, measured on the real device command
//! path (`FidoApp::process_u2f_with_store`) against the real device store, by
//! counting the keystore's durable rewrites as they happen:
//!
//! * N assertions cost `ceil(N / COUNTER_PERSIST_INTERVAL)` rewrites, for the
//!   per-credential counter AND for the keystore-wide counter that stateless
//!   U2F credentials authenticate against (US-714's `ef_counter` parity);
//! * the batch carries the **counter only** — a credential created or deleted
//!   inside a batch window is still durable the moment the persist gate runs,
//!   which is the failure that would make "delete" a lie.

use fapico2_fido::FidoApp;
use fapico2_platform::dispatch::App as _;
use fapico2_fido::device_keystore::{DeviceCoseKey, DeviceCredential, PrivateScalar, KEYSTORE_SLOT};
use fapico2_platform::secure_store::rp2350::Rp2350SecureStore;
use fapico2_platform::secure_store::{SecureStore, SecureStoreError};
use fapico2_platform::trng::HostTrng;

const CTAP2_MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;
const U2F_SW_OK: [u8; 2] = [0x90, 0x00];
/// C `KEY_HANDLE_LEN` (32-byte key path + 32-byte tag).
const KEY_HANDLE_LEN: usize = 64;
/// The chosen batching interval, **pinned here**. US-1011 chose this number by
/// reasoning (see `COUNTER_PERSIST_INTERVAL`'s own doc comment and §6 of
/// `docs/erase-budget.md`); changing it is a deliberate edit of this test, of
/// that constant's trade-off comment, and of the document's arithmetic.
const PINNED_INTERVAL: u16 = 32;
/// The app parameter a legacy stored credential is registered under.
const APP_PARAM: [u8; 32] = [0xA0; 32];

fn sw(reply: &[u8]) -> [u8; 2] {
    [reply[reply.len() - 2], reply[reply.len() - 1]]
}

/// The U2F signature counter out of an AUTHENTICATE reply
/// (`01 ‖ counter(4) ‖ sig ‖ SW(2)`).
fn reply_counter(reply: &[u8]) -> u32 {
    u32::from_be_bytes([reply[1], reply[2], reply[3], reply[4]])
}

/// U2F REGISTER APDU: `00 01 00 00 40 ‖ client(32) ‖ app(32)`.
fn register_apdu(client: u8) -> Vec<u8> {
    let mut apdu = vec![0x00, 0x01, 0x00, 0x00, 0x40];
    apdu.extend_from_slice(&[client; 32]);
    apdu.extend_from_slice(&APP_PARAM);
    apdu
}

/// U2F AUTHENTICATE APDU, enforce + user presence:
/// `00 02 03 00 Lc ‖ client(32) ‖ app(32) ‖ kh_len ‖ kh`.
fn authenticate_apdu(client: u8, kh: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0x02, 0x03, 0x00, (64 + 1 + kh.len()) as u8];
    apdu.extend_from_slice(&[client; 32]);
    apdu.extend_from_slice(&APP_PARAM);
    apdu.push(kh.len() as u8);
    apdu.extend_from_slice(kh);
    apdu
}

fn key_handle_of(reply: &[u8]) -> Vec<u8> {
    let kh_len = reply[66] as usize;
    reply[67..67 + kh_len].to_vec()
}

/// CTAP2 makeCredential (rk, no PIN) — the growth mutation. A distinct user
/// handle per call, so each call is a distinct resident credential.
fn mc_rk_req(user: u8) -> Vec<u8> {
    use fapico2_fido::cbor::no_heap as nh;

    let mut r: heapless::Vec<u8, 512> = heapless::Vec::new();
    nh::push_map_header(&mut r, 5).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_bstr(&mut r, &[user; 32]).unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_tstr(&mut r, "example.com").unwrap();
    nh::push_uint(&mut r, 3).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_bstr(&mut r, &[user; 32]).unwrap();
    nh::push_uint(&mut r, 4).unwrap();
    nh::push_array_header(&mut r, 1).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "type").unwrap();
    nh::push_tstr(&mut r, "public-key").unwrap();
    nh::push_tstr(&mut r, "alg").unwrap();
    nh::push_neg(&mut r, -7).unwrap();
    nh::push_uint(&mut r, 7).unwrap(); // options
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "rk").unwrap();
    nh::push_bool(&mut r, true).unwrap();
    r.as_slice().to_vec()
}

// ---------------------------------------------------------------------------
// The instrument
// ---------------------------------------------------------------------------

/// A [`Rp2350SecureStore`] that counts the keystore's durable rewrites.
///
/// **How a rewrite is counted.** `chunked::write_chunked` writes a logical
/// slot as N physical parts (indices `N-1 … 0`, descending) and deletes the
/// other buffer's parts afterwards. So part **0** is written exactly once per
/// rewrite and never otherwise, which makes "a write whose part index is 0"
/// an exact rewrite counter that needs no knowledge of the snapshot's part
/// count. Everything else (the boot's `fido.hkey`, the attestation slots) is
/// not part of the keystore family and is not counted.
struct CountingStore {
    inner: Rp2350SecureStore,
    /// Whole-image rewrites of `fido.keystore.v1`.
    persists: usize,
    /// Every physical write into the keystore's chunked family (parts).
    writes: usize,
}

/// The chunked part index a physical key names, or `None` if `key` is not a
/// part of the keystore family (`<KEYSTORE_SLOT>.p<buffer><index>`).
fn keystore_part_index(key: &[u8]) -> Option<usize> {
    let base = KEYSTORE_SLOT;
    if key.len() != base.len() + 5 || !key.starts_with(base) {
        return None;
    }
    let tail = &key[base.len()..];
    if tail[0] != b'.' || tail[1] != b'p' || !matches!(tail[2], b'0' | b'1') {
        return None;
    }
    let hi = (tail[3] as char).to_digit(16)? as usize;
    let lo = (tail[4] as char).to_digit(16)? as usize;
    Some(hi * 16 + lo)
}

impl CountingStore {
    fn new() -> Self {
        Self {
            inner: Rp2350SecureStore::new(),
            persists: 0,
            writes: 0,
        }
    }

    /// A store restored from a partition image, with the counters at zero —
    /// what a device sees at the moment it powers on.
    fn from_image(image: &[u8]) -> Self {
        let mut inner = Rp2350SecureStore::new();
        inner.from_partition_image(image);
        Self {
            inner,
            persists: 0,
            writes: 0,
        }
    }
}

impl SecureStore for CountingStore {
    fn write(&mut self, key: &[u8], value: &[u8]) -> Result<(), SecureStoreError> {
        if let Some(index) = keystore_part_index(key) {
            self.writes += 1;
            if index == 0 {
                self.persists += 1;
            }
        }
        self.inner.write(key, value)
    }
    fn read(&mut self, key: &[u8], out: &mut [u8]) -> Result<usize, SecureStoreError> {
        self.inner.read(key, out)
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), SecureStoreError> {
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
        self.persists = 0;
        self.writes = 0;
        self.inner.wipe_all()
    }
    fn store_key(&self) -> Option<[u8; 32]> {
        self.inner.store_key()
    }
}

// ---------------------------------------------------------------------------
// Fixtures / drivers
// ---------------------------------------------------------------------------

/// A booted app with one legacy (store-backed) U2F credential, already
/// durable. Returns the 32-byte key handle.
fn booted_with_legacy_credential(
    trng: &mut HostTrng,
    store: &mut CountingStore,
) -> (FidoApp, Vec<u8>) {
    let mut app = FidoApp::boot(trng, store).unwrap();
    let kh = vec![0x5Au8; 32];
    let mut id = heapless::Vec::<u8, 64>::new();
    id.extend_from_slice(&kh).unwrap();
    let cred = DeviceCredential {
        credential_id: id,
        public_key: DeviceCoseKey::es256([1; 32], [2; 32]),
        private_key: PrivateScalar::from_bytes([0x0B; 32]), // valid non-zero P-256 scalar
        rp_id_hash: APP_PARAM,
        rp_id: heapless::Vec::new(),
        user_handle: heapless::Vec::new(),
        user_name: heapless::Vec::new(),
        user_display_name: heapless::Vec::new(),
        cred_protect: 0,
        large_blob_key: None,
        hmac_secret: heapless::Vec::new(),
        cred_blob: heapless::Vec::new(),
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: false,
        algorithm: -7,
        counter: 0,
        revoked: false,
        expires_at: None,
    };
    app.keystore().store_credential(cred).unwrap();
    assert!(
        app.persist_if_dirty(store),
        "the fixture credential must be durable before the first assertion"
    );
    (app, kh)
}

/// Everything a power cut leaves behind: the durable partition image, booted
/// into a fresh app. This is the shape a real device spends its life in: it
/// boots from an image and then asserts, and the wear budget is about *that*
/// loop, so the counting tests measure from here rather than from a live app
/// that has just written.
fn power_on(
    trng: &mut HostTrng,
    store: &mut CountingStore,
) -> (FidoApp, CountingStore) {
    let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let len = store.inner.partition_image(&mut img).unwrap();
    let mut restored = CountingStore::from_image(&img[..len]);
    let app = FidoApp::boot(trng, &mut restored).unwrap();
    (app, restored)
}

/// One U2F command through the device path **plus** the persist gate, exactly
/// as the serve loop runs them.
fn u2f_and_persist(
    app: &mut FidoApp,
    store: &mut CountingStore,
    apdu: &[u8],
) -> Vec<u8> {
    let mut out = heapless::Vec::<u8, CTAP2_MAX_MSG>::new();
    let n = app.process_u2f_with_store(apdu, &mut out, Some(store));
    let reply = out.as_slice()[..n].to_vec();
    let _ = app.persist_if_dirty(store);
    reply
}

fn authenticate(app: &mut FidoApp, store: &mut CountingStore, kh: &[u8], client: u8) -> Vec<u8> {
    let reply = u2f_and_persist(app, store, &authenticate_apdu(client, kh));
    assert_eq!(sw(&reply), U2F_SW_OK, "U2F authenticate must succeed");
    reply
}

// ---------------------------------------------------------------------------
// The batching contract
// ---------------------------------------------------------------------------

/// HEADLINE (US-1011 + US-1012): N assertions against a stored credential
/// cost `ceil(N / COUNTER_PERSIST_INTERVAL)` whole-image rewrites — not N.
///
/// **Measured from a power-on**, because that is the loop a device actually
/// lives in and the loop the wear budget is about: boot from the durable
/// image, then assert. A restore (US-1012) opens a window that is already
/// [`COUNTER_PERSIST_INTERVAL`] wide, so the first assertion after a power-on
/// closes it and the N assertions cost `ceil(N / INTERVAL)`.
#[test]
fn n_assertions_after_a_power_on_cost_ceil_n_over_interval_rewrites() {
    let interval = PINNED_INTERVAL as usize;

    for n in [1usize, interval, 2 * interval, 3 * interval, 3 * interval + 1] {
        let mut trng = HostTrng::new();
        let mut store = CountingStore::new();
        let (_fixture, kh) = booted_with_legacy_credential(&mut trng, &mut store);
        // The fixture's own write closed a window; power on to get the
        // production shape.
        let (mut app, mut store) = power_on(&mut trng, &mut store);

        let before = store.persists;
        let before_writes = store.writes;
        let mut first = None;
        for i in 0..n {
            let reply = authenticate(&mut app, &mut store, &kh, i as u8);
            let c = reply_counter(&reply);
            if let Some(f) = first {
                assert_eq!(
                    c,
                    f + i as u32,
                    "n={n}: assertion {i} signed {c}, expected {} — the in-RAM \
                     counter must advance by exactly one per assertion",
                    f + i as u32
                );
            } else {
                first = Some(c);
            }
        }
        let rewrites = store.persists - before;
        assert_eq!(
            rewrites,
            n.div_ceil(interval),
            "n={n} assertions after a power-on must cost ceil({n}/{interval}) = \
             {} keystore rewrites, not {n} (RED: one whole-image rewrite per \
             assertion is the defect this story removes)",
            n.div_ceil(interval)
        );
        // The counting instrument's own premise, asserted rather than assumed.
        // `persists` counts part-0 writes, which is an exact rewrite counter
        // only if part 0 is written exactly once per rewrite AND every
        // rewrite writes the same number of parts. The single-credential
        // fixture snapshot fits in one chunk, so the ratio below is the part
        // count itself — but the invariant it checks (a whole, constant
        // number of parts per rewrite) is what a future change to
        // `chunked::write_chunked` would break, and every other count in this
        // file rests on it.
        let writes = store.writes - before_writes;
        assert!(
            rewrites > 0,
            "precondition: n={n} must have cost at least one rewrite, or the \
             part-count assertion below would divide by zero"
        );
        assert_eq!(
            writes % rewrites,
            0,
            "each of the {rewrites} rewrites must write the same number of \
             parts ({writes} part writes over {rewrites} rewrites is not a \
             whole number per rewrite): `persists` counts part 0 once per \
             rewrite, which is only exact if every rewrite writes the same \
             number of parts"
        );
        assert!(
            writes / rewrites >= 1,
            "a keystore rewrite must write at least one part (it wrote {writes} \
             part write(s) for {rewrites} rewrite(s))"
        );
    }
}

/// The keystore-wide counter — the one a **stateless** U2F credential
/// authenticates against, added by US-714 for C `ef_counter` parity — has the
/// same wear cost and the same clone-detection role, so it batches on the same
/// window. Pinned deliberately: leaving it out would be a wear hole that
/// looked like an oversight.
#[test]
fn the_global_stateless_counter_batches_on_the_same_window() {
    let interval = PINNED_INTERVAL as usize;
    let n = 2 * interval + 1;

    let mut trng = HostTrng::new();
    let mut store = CountingStore::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();
    let _ = app.persist_if_dirty(&mut store); // drain the boot snapshot

    let before_reg = store.persists;
    let reg = u2f_and_persist(&mut app, &mut store, &register_apdu(0x42));
    assert_eq!(reg[0], 0x05, "U2F register must succeed");
    let kh = key_handle_of(&reg);
    assert_eq!(kh.len(), KEY_HANDLE_LEN, "C-format stateless handle");
    assert_eq!(
        store.persists - before_reg,
        0,
        "a stateless U2F registration writes nothing (US-714)"
    );
    drop(app);

    // Power on: the stateless handle is re-derived from the persisted device
    // master, so it authenticates on the restored device too
    // (`stateless_keyhandle.rs::stateless_auth_survives_reboot`).
    let (mut app, mut store) = power_on(&mut trng, &mut store);

    let before = store.persists;
    let before_writes = store.writes;
    let mut first = None;
    for i in 0..n {
        let reply = authenticate(&mut app, &mut store, &kh, i as u8);
        let c = reply_counter(&reply);
        if let Some(f) = first {
            assert_eq!(c, f + i as u32, "global counter advances by one");
        } else {
            first = Some(c);
        }
    }
    let rewrites = store.persists - before;
    assert_eq!(
        rewrites,
        n.div_ceil(interval),
        "the global counter must batch on the same window: {n} stateless \
         authenticates cost {} rewrites, not {n}",
        n.div_ceil(interval)
    );
    // The same instrument premise as the per-credential test: a stateless
    // authenticate carries no credential, so the snapshot it rewrites is the
    // existing one — same size, same part count, same whole number of parts
    // per rewrite.
    assert_eq!(
        (store.writes - before_writes) % rewrites,
        0,
        "every stateless-driven rewrite must write the same number of parts, \
         or `persists` is not counting rewrites"
    );
}

// ---------------------------------------------------------------------------
// "The batch carries the counter only"
// ---------------------------------------------------------------------------

/// A credential DELETED inside a batch window must be gone from the durable
/// image the moment the persist gate runs.
///
/// This is the failure the batching introduces and the reason the deferred
/// path is written the way it is. A counter-only rewrite that left the
/// `stored` flag set would make the *next* command's growth mutation look
/// already-durable: the gate would skip its write, the delete would never
/// reach the store, and "delete" would silently be a no-op that only a reboot
/// could undo — the credential would come back.
#[test]
fn credential_deleted_inside_a_batch_window_is_durable() {
    let mut trng = HostTrng::new();
    let mut store = CountingStore::new();
    let (mut app, kh) = booted_with_legacy_credential(&mut trng, &mut store);
    // A second, disposable credential.
    let doomed = vec![0x7Bu8; 32];
    let mut id = heapless::Vec::<u8, 64>::new();
    id.extend_from_slice(&doomed).unwrap();
    let cred = DeviceCredential {
        credential_id: id,
        public_key: DeviceCoseKey::es256([3; 32], [4; 32]),
        private_key: PrivateScalar::from_bytes([0x0C; 32]),
        rp_id_hash: APP_PARAM,
        rp_id: heapless::Vec::new(),
        user_handle: heapless::Vec::new(),
        user_name: heapless::Vec::new(),
        user_display_name: heapless::Vec::new(),
        cred_protect: 0,
        large_blob_key: None,
        hmac_secret: heapless::Vec::new(),
        cred_blob: heapless::Vec::new(),
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: false,
        algorithm: -7,
        counter: 0,
        revoked: false,
        expires_at: None,
    };
    app.keystore().store_credential(cred).unwrap();
    assert!(app.persist_if_dirty(&mut store), "both credentials durable");
    assert_eq!(app.keystore().cred_count(), 2);

    // One assertion, which lands INSIDE a batch window: the fixture's persist
    // closed the last window, so this one opens a fresh 32-assertion window.
    // (Whether it really was batched is asserted last, so that a failure below
    // is about the delete and not about the precondition.)
    let before = store.persists;
    let _ = authenticate(&mut app, &mut store, &kh, 1);
    assert!(
        !app.is_dirty(),
        "a batched counter bump must not mark the snapshot dirty: that flag is \
         the persist gate's only instruction to write, and a counter that has \
         not been written must not look like one that has"
    );
    // Now delete, and run the gate. The delete is not a counter change and
    // must reach the store now.
    app.keystore().delete_credential(&doomed).unwrap();
    assert_eq!(app.keystore().cred_count(), 1, "deleted in RAM");
    assert!(
        app.persist_if_dirty(&mut store),
        "the delete must make the gate write: a batched counter must never \
         leave the snapshot looking already-durable"
    );

    // Reboot: the delete is durable, and the surviving credential is intact.
    let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let len = store.inner.partition_image(&mut img).unwrap();
    let mut restored = Rp2350SecureStore::new();
    restored.from_partition_image(&img[..len]);
    let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();
    assert_eq!(
        app2.keystore().cred_count(),
        1,
        "the deleted credential came back: a batched counter write marked the \
         snapshot durable, so the delete's own write was skipped"
    );
    assert!(app2.keystore().get_credential(&kh).is_some());
    assert_eq!(
        store.persists - before,
        1,
        "precondition, asserted last: the assertion itself must have been \
         batched (no rewrite), leaving exactly the delete's one rewrite"
    );
}

/// The mirror: a credential CREATED inside a batch window must also be
/// durable on its own terms — a makeCredential is not counter traffic and may
/// never be folded into (or deferred by) the counter's window.
#[test]
fn credential_created_inside_a_batch_window_is_durable() {
    let mut trng = HostTrng::new();
    let mut store = CountingStore::new();
    let (mut app, kh) = booted_with_legacy_credential(&mut trng, &mut store);

    let before = store.persists;
    let before_writes = store.writes;
    let _ = authenticate(&mut app, &mut store, &kh, 1);

    let mut out = heapless::Vec::<u8, CTAP2_MAX_MSG>::new();
    let n = app.process_ctap2_with_store(0x01, &mc_rk_req(7), [1, 2, 3, 4], &mut out, Some(&mut store));
    assert_eq!(out.as_slice()[0], 0x00, "makeCredential inside the window: {}", n);
    assert!(app.persist_if_dirty(&mut store), "the growth mutation persists");
    assert_eq!(app.keystore().cred_count(), 2);

    let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let len = store.inner.partition_image(&mut img).unwrap();
    let mut restored = Rp2350SecureStore::new();
    restored.from_partition_image(&img[..len]);
    let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();
    assert_eq!(
        app2.keystore().cred_count(),
        2,
        "the credential created inside a batch window did not survive: the \
         counter batch swallowed a growth mutation"
    );
    // The growth mutation writes on its own account: the assertion was
    // batched, the makeCredential was not, so the window sees one rewrite here
    // (makeCredential's own) rather than two.
    assert_eq!(
        store.persists - before,
        1,
        "a makeCredential is never counter traffic: it persists on its own \
         terms even mid-window"
    );
    // The instrument's premise, on a snapshot that genuinely spans more than
    // one chunk: the two-credential snapshot does not fit in a single part, so
    // the rewrite above wrote more than one part. This is the assertion that
    // would fail if `persists` were counting something other than rewrites —
    // the part-0 write is one inside that set, and the ratio is the part count.
    assert!(
        store.writes - before_writes >= 2,
        "a two-credential snapshot spans more than one chunk, so its rewrite \
         must have written at least 2 parts ({} part write(s) for the \
         makeCredential's one rewrite): `persists` counts the part-0 write once \
         per rewrite, and this is what makes that an exact rewrite count \
         rather than a part count",
        store.writes - before_writes
    );
}
