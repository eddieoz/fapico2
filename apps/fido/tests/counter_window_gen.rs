//! US-1728 — the counter window dies with slot reuse.
//!
//! ```gherkin
//! Scenario: Re-allocated slot starts its counter clean
//!   Given a pending counter entry for slot S
//!   When slot S is re-allocated for a brand-new credential
//!   Then the window holds no pending value for S
//!   And the new credential's first assertion signs from its own stored counter
//! ```
//!
//! [`CounterWindow`](fapico2_fido::device_keystore::CounterWindow) is keyed by
//! slot **alone**: `(slot, counter)` pairs with no notion of which credential
//! the value belonged to. A slot that is freed while one of its values is still
//! pending — the batched value the RP has already seen that no durable write
//! carries — can therefore be re-allocated to a brand-new credential while the
//! old tenant's entry is still in the window. From then on the new tenant's
//! assertions read [`pending_value`](fapico2_fido::device_keystore::CounterWindow::pending_value)
//! first ([`RegionCredentials::counter_value`]), so the new credential signs
//! and eventually persists a counter that was raised for a credential that no
//! longer exists — and a pending entry left pointing at a slot that becomes a
//! tombstone wedges every later flush on it
//! (`delete_all_by_id`'s counter-carry note names this shape).
//!
//! US-1722's `delete_all_by_id` flushes the window before tombstoning, which
//! retires the pending entries of the records *that delete removes*. The rule
//! here is broader and simpler (`AGENTS.md` §5 rule 3): the moment a slot is
//! handed to a new tenant, its pending entry dies — clear-on-reuse, not
//! generation-keying.
//!
//! The fixture is `region_counter_batching.rs`'s, in the minimal form this
//! story needs: the same OTP row, key derivation, nonce discipline and
//! credential shape, because a counter test against a different key hierarchy
//! would not be a measurement of the device's.

use std::path::{Path, PathBuf};

mod region_boot;

use fapico2_fido::device_keystore::{
    region_pin_secret, CounterWindow, DeviceCredential, DevicePinState, PrivateScalar,
    RegionCredentials, RegionKeys,
};
use fapico2_platform::keyregion::commit;
use fapico2_platform::keyregion::crypto;
use fapico2_platform::keyregion::record;
use fapico2_platform::keyregion::Slot;
use heapless::Vec as HeaplessVec;
use region_boot::CountingRegion;

// ---------------------------------------------------------------------------
// Fixtures — the minimal copy of region_counter_batching.rs's
// ---------------------------------------------------------------------------

/// A region file in the host temp directory, removed on drop.
struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir()
            .join(format!("fapico2-us1728-{}-{tag}.bin", std::process::id()));
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
fn keys() -> RegionKeys {
    let row = otp_row();
    let root = crypto::derive_otp_root(&row, &chip_id()).expect("a non-zero OTP row");
    let secret = region_pin_secret(&DevicePinState::default(), &[0x5a; 32]);
    RegionKeys {
        index: crypto::derive_index_key_from_root(&root),
        payload: crypto::derive_payload_key_from_root(&root, &secret),
    }
}

/// A fresh GCM nonce for the `n`-th durable write — unique per write, which
/// `record::seal` requires.
fn nonce(n: u32) -> [u8; record::NONCE_LEN] {
    let mut out = [0u8; record::NONCE_LEN];
    out[..4].copy_from_slice(&n.to_le_bytes());
    out[4..].copy_from_slice(&b"us1728 nonce!"[..record::NONCE_LEN - 4]);
    out
}

/// One credential, minimal but real — the same shape the batching fixture
/// enrols, distinct per `n` in ID and RP so tenant B is not tenant A.
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
    id[..4].copy_from_slice(b"u728");
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
// Helpers over the applet API
// ---------------------------------------------------------------------------

/// Run `f` with a [`RegionCredentials`] over `region`.
///
/// The borrow has to end for a test to look at the window, and re-creating the
/// store is free: `RegionCredentials::new` reads nothing.
fn with_store<R>(region: &mut CountingRegion, f: impl FnOnce(&mut RegionCredentials<'_, '_>) -> R) -> R {
    let k = keys();
    let mut creds = RegionCredentials::new(region, &k);
    f(&mut creds)
}

/// Sign one assertion against `slot`, batching through `window`, and return the
/// counter the reply would sign — the whole applet-side loop in one place, as
/// `region_counter_batching.rs`'s `assert_once` is.
fn bump_once(
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

/// Free `slot`'s record the way the device does: a delete by ID (tombstone
/// commit), then the sector rewrite that makes the slot reachable again.
fn free_slot(region: &mut CountingRegion, cred: &DeviceCredential, draws: &mut u32) -> Slot {
    with_store(region, |creds| {
        let report = creds
            .delete(&nonce(*draws), cred.credential_id.as_slice())
            .expect("the live credential deletes");
        *draws += 1;
        let sector = commit::sector_base(report.slot);
        creds.compact(sector).expect("the tombstone's sector compacts");
        report.slot
    })
}

// ---------------------------------------------------------------------------
// The gherkin
// ---------------------------------------------------------------------------

/// **"Re-allocated slot starts its counter clean."**
///
/// Tenant A is enrolled, signs one batched assertion — the window now holds a
/// pending `(S, 1)` no durable write carries — and is deleted; the freed slot
/// is re-allocated to tenant B, a brand-new credential. The window must hold
/// **no** pending value for the slot, and B's first assertion must sign from
/// B's own stored counter, not from the value A's last bump left behind.
#[test]
fn re_allocated_slot_starts_its_counter_clean() {
    let tmp = TempRegion::new("reuse");
    let mut region = CountingRegion::create(tmp.path());

    // Tenant A: enrol, then one batched assertion. The value it signed is in
    // the window and nowhere else — the durable image still holds 0.
    let slot_a = with_store(&mut region, |creds| {
        creds.put(&nonce(1), &credential(1)).expect("tenant A enrols").slot
    });
    let mut window = CounterWindow::fresh();
    let mut draws = 0u32;
    let a_signed = bump_once(&mut region, &mut window, slot_a, &mut draws);
    assert_eq!(a_signed, 1, "tenant A enrols at 0 and its first assertion signs 1");
    assert_eq!(
        window.pending_value(slot_a),
        Some(1),
        "the bump is batched: the window holds A's signed value, the region does not"
    );

    // A is freed the way the device frees a slot — a delete, then the sector
    // rewrite. Nothing here flushes the window: the pending entry outlives the
    // record it stood for, which is the state the story is about.
    free_slot(&mut region, &credential(1), &mut draws);

    // Tenant B: a brand-new credential. The allocator's lowest-free rule hands
    // it the slot A just vacated — this is the reuse.
    let slot_b = with_store(&mut region, |creds| {
        creds.put(&nonce(2), &credential(2)).expect("tenant B enrols").slot
    });
    assert_eq!(
        slot_b, slot_a,
        "the allocator must re-issue the freed slot for this scenario to be the reuse it claims"
    );

    // **The reuse retires the old tenant's pending entry** — the call the
    // makeCredential put site makes (US-1728). A pending counter for a freed
    // slot must not sign for the slot's next tenant.
    window.clear_slot(slot_b);

    assert_eq!(
        window.pending_value(slot_b),
        None,
        "after the re-allocation the window holds no pending value for the slot: the entry \
         belonged to a credential that no longer exists"
    );

    // B's first assertion signs from B's own stored counter — 0 + 1 — not from
    // A's leftover 1 + 1.
    let b_signed = bump_once(&mut region, &mut window, slot_b, &mut draws);
    assert_eq!(
        b_signed, 1,
        "tenant B enrolled at counter 0; its first assertion signs 1. Signing 2 would be the \
         old tenant's pending value bleeding into the new one"
    );

    // And the flush lands it: the reused slot writes cleanly, no wedge.
    with_store(&mut region, |creds| {
        let mut next_nonce = || {
            draws += 1;
            nonce(draws)
        };
        creds.flush_counters(&mut window, &mut next_nonce).expect("the flush after reuse succeeds");
    });
    let durable = with_store(&mut region, |creds| creds.durable_counter(slot_b).unwrap());
    assert_eq!(
        durable, 1,
        "the value B signed is the value the region ends up holding for it"
    );
}

/// **The clear is per-slot, and the batching contract survives it.**
///
/// Two tenants are in flight when one slot is reused: the reused slot's entry
/// dies and the other tenant's entry — and the store-wide batch budget's
/// meaning — survive untouched. A clear that wiped the whole window would
/// strand the *other* credential's signed-but-unpersisted counter (the next
/// flush could not carry it), and a clear that counted as a durable write would
/// silently close the window on values nobody wrote.
#[test]
fn clearing_one_slot_leaves_the_others_batched() {
    let tmp = TempRegion::new("perslot");
    let mut region = CountingRegion::create(tmp.path());

    let slots = with_store(&mut region, |creds| {
        [0u32, 1u32]
            .map(|n| creds.put(&nonce(n), &credential(n)).expect("enrols").slot)
    });
    let (slot_a, slot_b) = (slots[0], slots[1]);

    let mut window = CounterWindow::fresh();
    let mut draws = 0u32;
    let a_signed = bump_once(&mut region, &mut window, slot_a, &mut draws);
    let b_signed = bump_once(&mut region, &mut window, slot_b, &mut draws);
    assert_eq!(a_signed, 1, "tenant A enrols at 0 and its first assertion signs 1");
    assert_eq!(window.pending_len(), 2, "both tenants are in flight");
    let budget_before = window.unpersisted();
    assert_eq!(budget_before, 2, "two bumps, one store-wide budget");

    // Reuse slot A for a new tenant; the clear rides the reuse, as the
    // makeCredential put site makes it.
    free_slot(&mut region, &credential(0), &mut draws);
    let slot_c = with_store(&mut region, |creds| {
        creds.put(&nonce(9), &credential(9)).expect("the new tenant enrols").slot
    });
    assert_eq!(slot_c, slot_a, "the freed slot is the one re-issued");
    window.clear_slot(slot_c);

    // A's entry is gone; B's is exactly where it was.
    assert_eq!(window.pending_value(slot_c), None, "the reused slot starts clean");
    assert_eq!(
        window.pending_value(slot_b),
        Some(b_signed),
        "the unrelated tenant's pending value survives the clear — per-slot, not a wipe"
    );
    assert_eq!(window.pending_len(), 1, "and the window holds one entry, not zero");
    assert_eq!(
        window.unpersisted(),
        budget_before - 1,
        "one bump's worth of budget retires with the entry whose record is gone"
    );

    // The surviving tenant still batches: bumping it does not write, because
    // the window is still open under the same contract as before the reuse.
    region.reset_log();
    let b_again = bump_once(&mut region, &mut window, slot_b, &mut draws);
    assert!(b_again > b_signed, "and still monotonic");
    assert_eq!(
        region.erases(),
        0,
        "a clear of one slot must not close the window or force a write for the others"
    );

    // A clear of a slot with no pending entry is a no-op — no budget spent,
    // nothing dropped — because the steady-state path clears absent slots on
    // every enrolment.
    window.clear_slot(slot_c);
    assert_eq!(window.pending_len(), 1);
    assert_eq!(window.unpersisted(), budget_before, "the no-op clear spends nothing");

    // And the batch still flushes exactly what is pending — B's counters, in
    // one durable write.
    with_store(&mut region, |creds| {
        let mut next_nonce = || {
            draws += 1;
            nonce(draws)
        };
        let written = creds.flush_counters(&mut window, &mut next_nonce).expect("flush succeeds");
        assert_eq!(written, 1, "one pending entry, one record written");
    });
    let durable_b = with_store(&mut region, |creds| creds.durable_counter(slot_b).unwrap());
    assert_eq!(
        durable_b, b_again,
        "the surviving tenant's batched counter reaches the medium intact"
    );
    assert_eq!(window.pending_len(), 0, "and the window closes on the write");
}
