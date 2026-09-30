//! US-380 — secure storage baseline. Host tests for the platform
//! [`SecureStore`] abstraction.
//!
//! EPIC bar: keys/seeds live in the RP2350 secure partition (never plain
//! flash), survive a reboot, and are readable back. On host the secure
//! partition is stood in by an in-memory store with a serializable "partition
//! image", and a separate plain-flash region proves secrets don't leak there.

use fapico2_platform::secure_store::{rp2350::Rp2350SecureStore, HostSecureStore, SecureStore};

const SECRET: &[u8] = b"attest-priv-key-SECRET-VALUE-1234";

/// Write → power-down snapshot → reboot (restore) → read back, and the secret
/// must never appear in the plain-flash dump before or after the reboot.
#[test]
fn write_reboot_read_back_and_never_in_plain_flash() {
    let mut store = HostSecureStore::new();

    // Plain flash holds ordinary app data — and must NOT hold our secret.
    store.set_plain_flash(b"plain application data".to_vec());
    assert!(!store.plain_flash_dump().windows(SECRET.len()).any(|w| w == SECRET));

    store.write(b"attest_key", SECRET).unwrap();
    assert!(store.contains(b"attest_key"));

    // The secret must still not be in plain flash after being stored.
    assert!(
        !store.plain_flash_dump().windows(SECRET.len()).any(|w| w == SECRET),
        "secret must never appear in the plain-flash dump"
    );

    // Power-down: snapshot the secure partition and drop the store (reboot).
    let image = store.partition_image();
    drop(store);

    let mut restored = HostSecureStore::new();
    restored.from_partition_image(&image);

    let mut out = [0u8; 128];
    let n = restored.read(b"attest_key", &mut out).unwrap();
    assert_eq!(
        &out[..n],
        SECRET,
        "secret must survive a reboot from the secure partition"
    );
}

/// US-715 (POLISH-PUB) — windowed image I/O round-trip: the store's
/// partition image produced (snapshot) and consumed (restore) strictly
/// through small windows — never a whole-image buffer — must be
/// byte-identical to the whole-image form and restore the identical store
/// state. This is the host-verifiable half of the bss reclaim (the three
/// `PARTITION_IMAGE_MAX` device statics go away in favor of this path).
#[test]
fn windowed_image_io_roundtrips() {
    use fapico2_platform::secure_store::{rp2350::Rp2350SecureStore, SliceReader};

    /// The image I/O window. The compile-time bound keeps the window small
    /// forever: a whole-image-sized "window" would silently reintroduce the
    /// 27 KiB bss the windowed path reclaimed.
    const WINDOW: usize = 128;
    const _: () = assert!(WINDOW <= 512, "US-715: image I/O window must stay small");

    let mut store = Rp2350SecureStore::new();
    // A mix of small secrets and a chunked (multi-part) logical slot, so the
    // windowed encoder/decoder must walk a multi-entry image layout.
    store.write(b"fido.hkey", SECRET).unwrap();
    store.write(b"seed", b"0123456789abcdef").unwrap();
    let mut value = vec![0u8; 800];
    for (i, b) in value.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    fapico2_platform::secure_store::chunked::write_chunked(
        &mut store,
        b"fido.keystore.v1",
        &value,
    )
    .unwrap();

    // Produce the image strictly through windows and assemble it — the
    // caller never holds more than WINDOW bytes in flight at a time.
    let len = store.snapshot_len();
    let mut windowed_img = Vec::with_capacity(len);
    let mut win = [0u8; WINDOW];
    let mut at = 0;
    while at < len {
        let n = WINDOW.min(len - at);
        let filled = store.snapshot_window(at, &mut win[..n]);
        assert!(filled > 0, "snapshot_window underran at {at}");
        windowed_img.extend_from_slice(&win[..filled]);
        at += filled;
    }

    // Byte-identical to the whole-image serialization (same format, same
    // bytes — the window is an I/O change, not a format change).
    let mut whole = vec![0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let whole_len = store.partition_image(&mut whole).unwrap();
    assert_eq!(len, whole_len, "windowed and whole-image lengths must agree");
    assert_eq!(&windowed_img[..], &whole[..whole_len], "windowed image bytes must be identical");
    // A second window walk re-derives the same bytes (the persist gate
    // reads the image twice: compare pass, then program pass).
    let mut again = [0u8; WINDOW];
    let mut replay = Vec::with_capacity(len);
    let mut at = 0;
    while at < len {
        let n = WINDOW.min(len - at);
        let filled = store.snapshot_window(at, &mut again[..n]);
        replay.extend_from_slice(&again[..filled]);
        at += filled;
    }
    assert_eq!(replay, windowed_img, "window re-derivation must be stable");

    // Consume the image strictly through windows (the device boot path's
    // shape: a flash-slot reader) and restore the identical state.
    let mut restored = Rp2350SecureStore::new();
    restored.from_partition_image_reader(&mut SliceReader::new(&windowed_img));
    let mut out = [0u8; 64];
    let n = restored.read(b"fido.hkey", &mut out).unwrap();
    assert_eq!(&out[..n], SECRET);
    let mut out = [0u8; fapico2_platform::secure_store::chunked::MAX_LOGICAL_LEN];
    let n = fapico2_platform::secure_store::chunked::read_chunked(
        &mut restored,
        b"fido.keystore.v1",
        &mut out,
    )
    .unwrap();
    assert_eq!(n, value.len());
    assert_eq!(&out[..n], &value);
    // Full backing-memory equivalence (slot layout, not just readable keys).
    assert_eq!(
        restored.slot_bytes_dump(),
        store.slot_bytes_dump(),
        "windowed restore must reproduce the exact store state"
    );

    // And the restored store re-snapshots to the same bytes (round-trip).
    assert_eq!(restored.snapshot_len(), len);
    let mut rt = [0u8; WINDOW];
    let mut at = 0;
    while at < len {
        let n = WINDOW.min(len - at);
        let filled = restored.snapshot_window(at, &mut rt[..n]);
        assert_eq!(&rt[..filled], &windowed_img[at..at + filled]);
        at += filled;
    }
}

/// A corrupted (truncated) partition image must not yield a partial secret —
/// the restore is all-or-nothing.
#[test]
fn truncated_partition_image_restores_empty() {
    let mut store = HostSecureStore::new();
    store.write(b"seed", b"0123456789abcdef").unwrap();
    let mut image = store.partition_image();
    image.truncate(image.len() - 1); // corrupt the image

    let mut restored = HostSecureStore::new();
    restored.from_partition_image(&image);
    assert!(
        !restored.contains(b"seed"),
        "a truncated partition image must not restore a partial secret"
    );
}

/// Delete removes the entry; a subsequent read is NotFound.
#[test]
fn delete_removes_secret() {
    let mut store = HostSecureStore::new();
    store.write(b"pin_hash", b"abcdef").unwrap();
    assert!(store.contains(b"pin_hash"));
    store.delete(b"pin_hash").unwrap();
    assert!(!store.contains(b"pin_hash"));
    let mut out = [0u8; 16];
    assert!(store.read(b"pin_hash", &mut out).is_err());
}

/// US-704 — freeing a slot must zeroize the secret in the static backing
/// memory: `delete()` and `reset()` leave no key/value bytes behind, so a
/// stale secret cannot be read out of RAM after the entry is gone.
#[test]
fn delete_and_reset_zeroize_slot_bytes() {
    // The device store backs its slots with fixed-size static arrays; the
    // host build compiles the same pure-static-memory module.
    let mut store = Rp2350SecureStore::new();
    store.write(b"attest_key", SECRET).unwrap();

    // Precondition: the secret is resident in the slot backing bytes.
    assert!(
        store.slot_bytes_dump().iter().any(|(_, v)| v.windows(SECRET.len()).any(|w| w == SECRET)),
        "secret must be resident in the slot backing memory before the free"
    );

    store.delete(b"attest_key").unwrap();
    assert!(
        store.slot_bytes_dump().iter().all(|(k, v)| k.iter().all(|&b| b == 0)
            && v.iter().all(|&b| b == 0)),
        "delete() must zero the freed slot's key and value bytes"
    );

    // `reset()` is reached from outside the crate through the corrupt-image
    // path (`from_partition_image` validation-fails → reset).
    store.write(b"attest_key", SECRET).unwrap();
    store.from_partition_image(b"garbage");
    assert!(
        store.slot_bytes_dump().iter().all(|(k, v)| k.iter().all(|&b| b == 0)
            && v.iter().all(|&b| b == 0)),
        "reset() must zero every slot's key and value bytes"
    );
}
