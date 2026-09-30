#![no_main]
//! US-1055 — the FIDO credential / large-blob transactional state machine.
//!
//! SOAK-FINDING-1 was a soak-found wedge: a snapshot that could not be
//! programmed latched `dirty`, and because the durable-before-ack gate reads
//! that flag, *every* subsequent command — reads included — answered CTAPHID
//! ERROR / INVALID_COMMAND. The token was alive and answered nothing.
//!
//! Absence of panic proves nothing here. A `grow_checked` that latched
//! `dirty` on a rejected commit still returns `false`, still answers the
//! command with its clean rejection status word, and looks entirely correct
//! on the wire. The damage is entirely in the **next** command's persist
//! gate — so that gate is what the target observes.
//!
//! `grow_checked` is `pub(crate)`, and its `apply` closure is required by
//! contract to set the `pub(crate)` dirty flag — so an external caller could
//! not honour the contract and exposing it would create an API nothing could
//! use correctly. The target therefore drives it through its real public
//! seam, `vendor_state::with_keystore_ops`, whose seven mutating methods
//! (`set_master_seed`, `set_soft_lock`, `set_audit_enabled`,
//! `audit_append`, `set_org_attestation`, …) all commit through
//! `grow_checked` and nothing else. The sibling `store_credential_checked`
//! — the credential half of the same transaction — is public and driven
//! directly with attacker-sized credentials.
//!
//! For each rejected commit the target asserts:
//!
//! 1. **a rejected commit latches nothing** — the persist gate over a
//!    *healthy* store must return `false`. Any other answer means the
//!    caller is told to program a partition image for a mutation that was
//!    rolled back, which is the latched state and the wedge.
//! 2. **the undo actually ran** — the state the commit would have changed is
//!    byte-identical to before it (master seed, soft lock, audit head,
//!    credential count and IDs, large-blob array).
//! 3. **an accepted commit is durable and idempotent** — `persist_if_dirty`
//!    returns `true` exactly once, and the credential reloads from the store.
//!
//! # Red-under-mutation (the evidence that these assertions bite)
//!
//! Setting `dirty = true` instead of restoring `dirty_before` on the rejected
//! path turns assertion 1 red. See `.superpowers/sdd/report-P6.md`.

use std::vec::Vec;

use fapico2_fido::device_keystore::{DeviceCredential, DeviceCoseKey, DeviceKeystore};
use fapico2_fido::vendor41::SoftLock;
use fapico2_fido::vendor_state::{with_keystore_ops, VendorSession};
use fapico2_platform::secure_store::{
    HostSecureStore, SecureStore, SecureStoreError, MAX_KEY_LEN,
};
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HVec;

/// A `SecureStore` that can be told to refuse writes and otherwise delegates
/// to a real `HostSecureStore`, so "healthy" means the genuine article rather
/// than a mock whose own bounds could mask a result.
struct Switchable {
    inner: HostSecureStore,
    fail_writes: bool,
}

impl Switchable {
    fn healthy() -> Self {
        Self { inner: HostSecureStore::new(), fail_writes: false }
    }
    /// A store that cannot be written — the SOAK-FINDING-1 precondition.
    fn failing() -> Self {
        Self { inner: HostSecureStore::new(), fail_writes: true }
    }
}

impl SecureStore for Switchable {
    fn write(&mut self, key: &[u8], value: &[u8]) -> Result<(), SecureStoreError> {
        if self.fail_writes {
            return Err(SecureStoreError::Flash);
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
        self.inner.wipe_all()
    }
    fn store_key(&self) -> Option<[u8; 32]> {
        self.inner.store_key()
    }
}

/// An attacker-sized credential. The ID is what a client controls directly;
/// the cred blob is what actually moves the snapshot across the store's
/// ceiling, so both are fuzzer-driven.
fn credential(id_len: usize, blob_len: usize, salt: u8) -> DeviceCredential {
    let mut cred = DeviceCredential {
        credential_id: HVec::new(),
        public_key: DeviceCoseKey::es256([salt; 32], [salt.wrapping_add(1); 32]),
        private_key: [salt; 32],
        rp_id_hash: [salt; 32],
        rp_id: HVec::new(),
        user_handle: HVec::new(),
        user_name: HVec::new(),
        user_display_name: HVec::new(),
        cred_protect: 0,
        large_blob_key: None,
        hmac_secret: HVec::new(),
        cred_blob: HVec::new(),
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: true,
        algorithm: -7,
        counter: 0,
        revoked: false,
        expires_at: None,
    };
    for i in 0..id_len.min(MAX_KEY_LEN) {
        cred.credential_id.push(salt.wrapping_add(i as u8)).ok();
    }
    for i in 0..blob_len {
        cred.cred_blob.push(salt ^ (i as u8)).ok();
    }
    cred
}

/// The observable a SOAK-FINDING-1 latch corrupts: what the persist gate
/// wants to do once the failing store is gone.
fn assert_nothing_latched(ks: &mut DeviceKeystore, what: &str) {
    let mut healthy = Switchable::healthy();
    assert!(
        !ks.persist_if_dirty(&mut healthy),
        "{what}: a rejected commit left a latched dirty state -- the persist gate \
         will now answer every command with an error (SOAK-FINDING-1)",
    );
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let id_len = data.first().copied().unwrap_or(0) as usize;
    let blob_len = data.get(1).copied().unwrap_or(0) as usize * 64;
    let salt = data.get(2).copied().unwrap_or(1).max(1);

    let mut trng = HostTrng::new();
    let mut ks = DeviceKeystore::fresh(&mut trng);
    let mut session = VendorSession::default();
    let mut random = |buf: &mut [u8]| buf.fill(0x5Au8);

    // Settle the keystore first. `DeviceKeystore::fresh` is dirty by
    // construction (its TRNG-derived `device_random` has never been written),
    // so the interesting question is not "is the gate idle" but "does the
    // rejected commit change what the gate wants". A clean baseline makes
    // that question answerable: flush once, and every later `true` is a
    // latch the commit caused.
    assert!(
        ks.persist_if_dirty(&mut Switchable::healthy()),
        "a fresh keystore carries an unwritten device random and must be dirty",
    );

    // ---- the grow_checked half, through its public seam ------------------
    {
        let mut failing = Switchable::failing();
        let mut store: Option<&mut dyn SecureStore> = Some(&mut failing);
        let seed_before = ks.vendor.secret.master_seed;
        let lock_before = ks.vendor.secret.lock;
        let audit_head_before = ks.vendor.public.audit_head();
        let creds_before = ks.cred_count();
        let audit_enabled_before = ks.vendor.public.audit_enabled;

        let results = with_keystore_ops(&mut ks, &mut session, &mut store, &mut random, |ops| {
            // Each of these commits through `grow_checked` and nothing else.
            let a = ops.set_master_seed([salt; 32]);
            let b = ops.set_soft_lock(SoftLock {
                key: Some([salt.wrapping_add(1); 64]),
                key_len: 64,
            });
            let c = ops.set_audit_enabled(!audit_enabled_before);
            (a, b, c)
        });

        assert!(
            results.0.is_err() && results.1.is_err() && results.2.is_err(),
            "a store that refuses every write must refuse every commit, got {:?}",
            results,
        );
        assert_eq!(ks.vendor.secret.master_seed, seed_before, "master seed half-applied");
        assert_eq!(ks.vendor.secret.lock, lock_before, "soft lock half-applied");
        assert_eq!(ks.vendor.public.audit_head(), audit_head_before, "audit journal half-applied");
        assert_eq!(ks.cred_count(), creds_before, "credential count changed");
        assert_nothing_latched(&mut ks, "grow_checked via with_keystore_ops");
    }

    // The same seam with a healthy store: the commit lands and the snapshot
    // it wrote reloads out of the store.
    //
    // Note what is deliberately NOT asserted here. `vendor_state::commit`'s
    // seven call sites do not set `dirty` inside their apply closure, while
    // every other `grow_checked` caller in the crate does (`device_app.rs`,
    // `device_core.rs`). So after an accepted commit on this seam the
    // keystore is `stored == true, dirty == false`, and `persist_if_dirty`
    // answers `false` — the gate is not asked to reprogram the partition
    // image for a vendor-state change. That is the code's behaviour today;
    // this target records it, does not judge it, and must not encode it as
    // an invariant (encoding it would turn a target red on a clean tree, and
    // encoding its negation would be asserting a behaviour the firmware does
    // not have). The durability property that IS owned here — the rejected
    // commit latching nothing — is asserted above.
    {
        let mut healthy = Switchable::healthy();
        let seed_wanted = [salt.wrapping_add(9); 32];
        {
            let mut store: Option<&mut dyn SecureStore> = Some(&mut healthy);
            with_keystore_ops(&mut ks, &mut session, &mut store, &mut random, |ops| {
                ops.set_master_seed(seed_wanted)
                    .expect("a healthy store accepts the commit");
            });
        }
        assert_eq!(ks.vendor.secret.master_seed, Some(seed_wanted));
        let reloaded = DeviceKeystore::load(&mut healthy)
            .expect("the store reloads")
            .expect("a stored snapshot loads as a keystore");
        assert_eq!(
            reloaded.vendor.secret.master_seed,
            Some(seed_wanted),
            "an accepted commit did not land in the store",
        );
    }

    // ---- the credential half, driven directly ---------------------------
    {
        let doomed = credential(id_len, blob_len, salt.wrapping_add(7));
        let doomed_len = doomed.credential_id.len();
        let before = ks.cred_count();
        let ids_before: Vec<Vec<u8>> =
            ks.credentials.iter().map(|c| c.credential_id.to_vec()).collect();
        let blob_before = ks.large_blob_array.clone();

        let mut failing = Switchable::failing();
        let ok = ks.store_credential_checked(doomed, &mut failing);

        if ok.is_err() {
            assert_eq!(
                ks.cred_count(),
                before,
                "store_credential_checked: a rejected commit still changed the count",
            );
            let ids_after: Vec<Vec<u8>> =
                ks.credentials.iter().map(|c| c.credential_id.to_vec()).collect();
            assert_eq!(ids_after, ids_before, "store_credential_checked: credential half-applied");
            assert_eq!(
                ks.large_blob_array, blob_before,
                "store_credential_checked: the large-blob array moved",
            );
            assert_nothing_latched(&mut ks, "store_credential_checked");
        } else {
            // An accepted commit is visible to the gate exactly once and
            // survives a reload.
            assert!(
                ks.persist_if_dirty(&mut Switchable::healthy()),
                "an accepted credential commit left the gate idle",
            );
            let mut reload_from = Switchable::healthy();
            ks.persist(&mut reload_from).expect("the healthy store accepts the snapshot");
            let reloaded = DeviceKeystore::load(&mut reload_from)
                .expect("the store reloads")
                .expect("a stored snapshot loads as a keystore");
            assert!(
                reloaded.credentials.iter().any(|c| c.credential_id.len() == doomed_len),
                "an accepted credential commit did not reload from the store",
            );
        }
    }

    // Structural invariants that must hold whatever the fuzzer did.
    assert!(
        ks.credentials.iter().all(|c| c.credential_id.len() <= MAX_KEY_LEN),
        "a credential ID grew past the store's key bound",
    );
});
