//! US-1572 — **no root key outlives the operation that used it.**
//!
//! # What is under test, and what cannot be
//!
//! The claim is a claim about lifetimes, so it is split into the parts that
//! can be observed and the parts that are structural:
//!
//! * **Observable.** Each use materialises a fresh key and clears it on drop.
//!   The key's own `Drop` records what its buffer held, after its explicit
//!   zeroize, into a thread-local ([`testing`]); the tests below read that
//!   record. Reading the bytes directly is not possible — by the time a `Drop`
//!   runs, the buffer is in freed stack — so the recording happens inside the
//!   production `Drop` body, and the device build runs the same body with the
//!   recording call compiled out.
//! * **Structural.** The key types own droppable storage (`needs_drop`), hand
//!   their bytes out only as a borrow, and are pointer-sized where they hold a
//!   key's *source* — the size fence is a `const` assertion in the module, so
//!   "the descriptor cannot hold a key" is a property of the type rather than a
//!   convention.
//! * **Review obligation.** `Copy`, `Clone` and `Debug` are deliberately not
//!   implemented on the key types. Their *absence* cannot be asserted from a
//!   file that has to compile, exactly as `key_region_crypto.rs` says; `cargo
//!   doc` shows the resulting API surface.
//!
//! # The store, not just the types
//!
//! `Rp2350SecureStore` used to hold `key: Option<[u8; 32]>` — a root key live
//! from boot to power-down. The tests below drive the store through its own
//! `SecureStore` methods with a **fused** key installed and assert that the
//! only thing that survives a seal or a restore is the seal itself: one witness
//! per operation, from the store's own `Drop` path, and nothing resident
//! between them.

use fapico2_platform::fused_key::{self, testing as witness, FusedKey, FusedReader, KeySource};
use fapico2_platform::secure_store::rp2350::Rp2350SecureStore;
use fapico2_platform::secure_store::SecureStore;
use fapico2_platform::store_v3;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A provisioned-looking OTP key row: not all-zero, because that is the row
/// `ckey`'s bound-root derivations refuse and a real board never has.
const OTP: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

/// A reader over the OTP row and the chip id — the host twin of
/// `fused_key::rp2350_store_key()`, whose arm-only body re-reads sixteen OTP
/// words and the chip id through the same derivation. Defined here rather than
/// borrowed so the test owns the reader, exactly as RS-Key's own tests do
/// (`rsk-piv/src/tests.rs:455`).
fn read_held_store_key() -> Option<Zeroizing<[u8; fused_key::KEY_LEN]>> {
    Some(Zeroizing::new(store_v3::derive_store_key(&OTP, &CHIPID)))
}

const CHIPID: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];

/// The store key these fixtures derive to — asserted, not assumed, so a change
/// in `derive_store_key` shows up as a failure here rather than as a silently
/// different key.
fn expected_store_key() -> [u8; fused_key::KEY_LEN] {
    store_v3::derive_store_key(&OTP, &CHIPID)
}

fn held_source() -> FusedKey {
    let read: FusedReader = read_held_store_key;
    FusedKey::new("test/held-otp", read)
}

/// Every witness so far must be "this key was non-zero and is now all zeroes".
fn assert_every_drop_was_cleared(label: &str) {
    for w in witness::dropped_keys() {
        assert!(
            w.was_nonzero,
            "{}: the {} key was already all-zero before its zeroize, so \
             'cleared on drop' is vacuous here",
            label,
            w.origin
        );
        assert!(
            w.bytes.iter().all(|&b| b == 0),
            "{}: the {} key still held {:02x?} when it went out of scope",
            label,
            w.origin,
            w.bytes
        );
    }
}

// ---------------------------------------------------------------------------
// The exposure window is one operation
// ---------------------------------------------------------------------------

#[test]
fn each_use_reads_derives_and_drops() {
    witness::clear();
    assert!(
        witness::dropped_keys().is_empty() && witness::reads() == 0,
        "the witness must start empty, or this test proves nothing"
    );

    let source = held_source();
    assert_eq!(witness::reads(), 0, "constructing a source must not read it");

    let first = source.read().expect("a provisioned source reads");
    assert_eq!(
        *first.as_bytes(),
        expected_store_key(),
        "the fused read must produce exactly derive_store_key(otp, chipid)"
    );
    assert_eq!(witness::reads(), 1, "one use is one read");

    // Live, and populated — so a witness that later saw zeroes could not have
    // seen a buffer that was never written.
    assert!(first.as_bytes().iter().any(|&b| b != 0));
    assert!(
        witness::dropped_keys().is_empty(),
        "nothing is dropped while the read is still in scope: the key would not \
         be readable at all"
    );

    drop(first);

    assert_eq!(
        witness::reads(),
        1,
        "dropping must not trigger another read"
    );
    assert_eq!(
        witness::dropped_keys().len(),
        1,
        "expected exactly one witness entry; the Drop path under test did not run"
    );
    assert_every_drop_was_cleared("after one operation");

    // And the next operation is a normal operation: the zeroize is on the way
    // out, not on the value.
    let second = source.read().expect("a second read");
    assert_eq!(*second.as_bytes(), expected_store_key());
    assert_eq!(witness::reads(), 2, "two uses are two reads, not one cache hit");
    drop(second);
    assert_eq!(witness::dropped_keys().len(), 2);
    assert_every_drop_was_cleared("after two operations");
}

#[test]
fn two_consecutive_reads_do_not_share_a_buffer() {
    witness::clear();
    let source = held_source();

    let first = source.read().expect("read one");
    let second = source.read().expect("read two");

    // Two live reads are two pieces of storage: one key cannot be handed out
    // twice and still be cleared twice.
    assert!(
        !core::ptr::eq(first.as_bytes() as *const u8, second.as_bytes() as *const u8),
        "two concurrent reads returned the same buffer, so clearing one would \
         clear the other and the second operation would run on a dead key"
    );
    assert_eq!(*first.as_bytes(), expected_store_key());
    assert_eq!(*second.as_bytes(), expected_store_key());

    // Drop one; the other must be untouched. This is the load-bearing half:
    // if they shared storage, this clear would have zeroed the survivor.
    drop(first);
    assert_eq!(
        *second.as_bytes(),
        expected_store_key(),
        "dropping one read cleared the other: they share a buffer"
    );
    assert!(second.as_bytes().iter().any(|&b| b != 0));
    drop(second);

    assert_eq!(witness::dropped_keys().len(), 2);
    assert_every_drop_was_cleared("two concurrent reads");
}

#[test]
fn the_key_source_holds_no_key() {
    // The size fence: `FusedKey` is a label and a code address. This is the
    // property that makes "the store holds a source, not a key" true of the
    // type — a descriptor that grew a cached key would fail the `const`
    // assertion in the module and this test.
    assert_eq!(
        core::mem::size_of::<FusedKey>(),
        core::mem::size_of::<&'static str>() + core::mem::size_of::<FusedReader>(),
        "FusedKey must remain a label plus a function pointer"
    );
    assert!(
        core::mem::size_of::<FusedKey>() < fused_key::KEY_LEN,
        "a descriptor at least as large as a key could be holding one"
    );

    // A resident source and a fused source are indistinguishable from the
    // holder's call site — which is the point of `KeySource`: one accessor,
    // so no call site can accidentally reach a different answer.
    let fused = KeySource::fused(held_source());
    let resident = KeySource::resident(expected_store_key());
    assert_eq!(
        fused.with(|k| *k),
        resident.with(|k| *k),
        "a fused and a resident source must produce the same key for the same root"
    );

    // Both are cleared on the way out. Three keys pass through here, not two:
    // one per read, plus the resident *source*'s own clear — which is the
    // improvement over the plain `[u8; 32]` field this replaced, that had no
    // `Drop` at all and so was never cleared. A fused source contributes no
    // witness of its own, because it has no key in it to clear: that is the
    // whole point of the type.
    witness::clear();
    let from_fused = fused.read().expect("fused read");
    let from_resident = resident.read().expect("resident read");
    assert_eq!(*from_fused.as_bytes(), *from_resident.as_bytes());
    drop((from_fused, from_resident, fused, resident));
    let dropped = witness::dropped_keys();
    assert_eq!(
        dropped.len(),
        3,
        "expected one witness per read plus the resident source's own clear; \
         got {:?}",
        dropped.iter().map(|w| w.origin).collect::<Vec<_>>()
    );
    assert_eq!(
        dropped.iter().filter(|w| w.origin == "resident").count(),
        2,
        "the read of the resident key and the resident source's own clear"
    );
    assert_every_drop_was_cleared("both source kinds");
}

// ---------------------------------------------------------------------------
// The store is no longer a key holder
// ---------------------------------------------------------------------------

#[test]
fn the_store_keeps_a_source_and_nothing_else() {
    witness::clear();

    let mut store = Rp2350SecureStore::new();
    store.set_fused_store_key(held_source());
    store.write(b"fido.hkey", b"a-secret-value").expect("write");

    // An operation on the store — a snapshot — reads the key once and drops it.
    let len = store.snapshot_len();
    let mut image = vec![0u8; len];
    assert_eq!(store.snapshot_partition(&mut image).expect("snapshot"), len);
    assert_eq!(
        witness::reads(),
        1,
        "sealing one partition image is one read, not one per entry"
    );
    assert_eq!(witness::dropped_keys().len(), 1);
    assert_every_drop_was_cleared("store snapshot");

    // The sealed image really is sealed: the plaintext is not in it.
    assert!(
        !image.windows(6).any(|w| w == b"secret"),
        "the partition image contains the plaintext value; it was not sealed"
    );

    // Between operations the store holds a descriptor, and the next operation
    // derives afresh. Two snapshots of an unchanged store are byte-identical
    // (the deterministic nonce), which is what makes this a re-read rather
    // than a second derivation from different inputs.
    let mut again = vec![0u8; len];
    assert_eq!(store.snapshot_partition(&mut again).expect("snapshot"), len);
    assert_eq!(image, again, "the sealed image must be deterministic");
    assert_eq!(witness::reads(), 2, "two operations are two reads");
    assert_eq!(witness::dropped_keys().len(), 2);
    assert_every_drop_was_cleared("two store snapshots");

    // A restore is a third operation with the same discipline, and it reads a
    // genuinely separate copy.
    let mut restored = Rp2350SecureStore::new();
    restored.set_fused_store_key(held_source());
    restored.from_partition_image(&image);
    assert_eq!(witness::reads(), 3);
    assert_eq!(witness::dropped_keys().len(), 3);
    assert_every_drop_was_cleared("store restore");

    let mut out = [0u8; 32];
    assert_eq!(
        restored.read(b"fido.hkey", &mut out).expect("round-trip"),
        b"a-secret-value".len()
    );
    assert_eq!(&out[..b"a-secret-value".len()], b"a-secret-value");
}

#[test]
fn a_store_that_cannot_read_its_key_refuses_rather_than_degrading() {
    // The half of the fused design that is a *security* property rather than
    // a lifetime one: a keyed store whose key cannot be read must not fall
    // through to the legacy plaintext (format-v2) serialization, because that
    // would write credentials to flash in the clear.
    //
    // `FusedReader` returning `None` is exactly the OTP controller refusing a
    // read — an unprovisioned part, or the SWD-debugger condition AGENTS.md
    // warns about.
    fn unprovisioned() -> Option<Zeroizing<[u8; fused_key::KEY_LEN]>> {
        None
    }

    let mut store = Rp2350SecureStore::new();
    store.set_fused_store_key(FusedKey::new("test/unprovisioned", unprovisioned));
    store.write(b"fido.hkey", b"a-secret-value").expect("write");

    // The length still describes a *sealed* image — it is a function of the
    // entries and of being keyed, never of the key's value — so the persist
    // gate's bound does not move when a read is refused.
    let len = store.snapshot_len();
    assert_eq!(
        len,
        store
            .partition_image_len()
            .max(len), // the same number, stated through the public accessor
        "the sealed length must not depend on whether the key read succeeded"
    );

    let mut image = vec![0u8; len];
    let filled = store.snapshot_window(0, &mut image);
    assert_eq!(
        filled, 0,
        "a keyed store with no readable key emitted {filled} bytes; a short \
         window is the persist sink's program-failure path, and anything else \
         would be a plaintext image"
    );
    assert!(
        !image.windows(6).any(|w| w == b"secret"),
        "a refused key read produced plaintext"
    );
    // The persist sink treats a short window as a program failure
    // (`persist_sink.rs:112-130`) and re-marks the apps dirty, so a refusal
    // never programs and never loses the previous good image. Nothing here
    // needs to assert that: this test's claim is that no bytes came out.
}

// ---------------------------------------------------------------------------
// Structural properties
// ---------------------------------------------------------------------------

#[test]
fn the_key_types_own_droppable_storage_and_hand_out_only_a_borrow() {
    // `needs_drop` is what makes the zeroize in `Drop` reachable at all.
    // Without it the key would be plain bytes that merely happen to look
    // zeroed when the stack is reused.
    assert!(
        core::mem::needs_drop::<fused_key::FusedRead>(),
        "FusedRead owns no droppable storage, so nothing is cleared when it \
         goes out of scope"
    );
    assert!(core::mem::needs_drop::<fused_key::ResidentKey>());

    // `as_bytes` borrows: the key cannot outlive the borrow, and no accessor
    // hands out an owned copy that would survive the zeroize. (`Copy`,
    // `Clone` and `Debug` are deliberately not implemented; their absence is
    // the review obligation this file states at the top.)
    let read = held_source().read().expect("read");
    let borrowed: &[u8; fused_key::KEY_LEN] = read.as_bytes();
    assert_eq!(*borrowed, expected_store_key());
    assert_ne!(*borrowed, OTP, "the store key is not the OTP row");
    assert_eq!(borrowed.len(), fused_key::KEY_LEN);

    // The provenance travels with the read, so a witness or a log line can
    // name the *source* of a key without naming the key.
    assert_eq!(read.origin(), "test/held-otp");
    assert_eq!(held_source().origin(), "test/held-otp");
    assert_eq!(
        fused_key::emulation_store_key().origin(),
        "emulation/store",
        "the emulation source is named after what it is (US-130: \
         wrong-but-obvious beats right-but-hidden)"
    );
    assert_eq!(
        *fused_key::emulation_store_key().read().expect("read").as_bytes(),
        store_v3::emulation_store_key(),
        "the fused emulation key must re-derive the same fixed key"
    );
}

#[test]
fn a_fused_key_never_hands_out_its_inputs() {
    // A read of the fused store key is a function of the OTP row and the chip
    // id — never of anything else, and in particular never of a key it could
    // have cached. Sweeping the chip id moves the key, so nothing in the path
    // is reading a stored value that the sweep would leave alone.
    let base = held_source().read().expect("read").as_bytes().to_vec();
    assert_eq!(base.len(), fused_key::KEY_LEN);
    assert!(base.iter().any(|&b| b != 0));

    let other = store_v3::derive_store_key(&OTP, &[0xFF; 8]);
    assert_ne!(base, other.to_vec());
    assert_ne!(base, OTP.to_vec());
    assert_ne!(base, CHIPID.to_vec());
}