//! US-1535 — the reported four-credential ceiling, reproduced against the
//! **device** command path.
//!
//! The report: on a soak board carrying other applets' state, four real
//! browser passkeys enroll and the fifth is refused. This file turns that into
//! a regression test on `device_app::FidoApp` / `device_core.rs` — never
//! `app.rs::FidoApp`, which is a host-only twin (AGENTS.md §1: a fix applied
//! to one twin passes every host test and changes nothing on hardware).
//!
//! # The arithmetic, and where each number comes from
//!
//! `Rp2350SecureStore` charges **one physical entry per key**, whatever the
//! value's length (`secure_store.rs:1308-1337`: `write` scans for a free slot
//! and returns `SecureStoreError::Full` only when none is). Its bounds are
//!
//! | constant | value | source |
//! |---|---|---|
//! | entries per store | 24 | `secure_store.rs:872` (`DEV_MAX_ENTRIES`) |
//! | bytes per entry value | 512 | `secure_store.rs:873` (`DEV_MAX_VALUE_LEN`) |
//! | bytes per chunked part payload | 496 | `secure_store.rs:1649` (`PART_PAYLOAD_MAX` = 512 − 16 header) |
//! | parts per generation | 12 | `secure_store.rs:1689` (`MAX_PARTS`) |
//!
//! So the FIDO keystore snapshot (`device_keystore.rs:29`, `KEYSTORE_SLOT`)
//! is stored as `ceil(len / 496)` parts, and `chunked::write_chunked` writes
//! the new generation **into the buffer that does not hold the current one**,
//! retiring the old buffer's parts only after the last part lands
//! (`secure_store.rs:1823-1906`). Both generations are therefore live
//! simultaneously, and the binding constraint on every durable write is
//!
//! ```text
//! other_slots + old_parts + new_parts ≤ 24
//! ```
//!
//! — the same expression `chunked`'s own capacity assertion checks
//! (`secure_store.rs:1718`) and the same one `soak_finding_1.rs` derives its
//! occupancy cases from. `DEVICE_MAX_CREDS = 12`
//! (`device_keystore.rs:34`) is the *parser* bound on how many credentials the
//! snapshot decoder accepts; it is **not** what a four-credential ceiling is
//! made of, and its doc comment's "fits the 5,952-B payload capacity" is
//! arithmetic about `MAX_LOGICAL_LEN` that says nothing about the store's
//! 24-entry occupancy.
//!
//! `other_slots` here is 12, not 9:
//!
//! | entries | owner |
//! |---|---|
//! | 9 | the other applets (see [`FOREIGN_SLOTS`]) |
//! | 1 | `fido.hkey`, written by `device_app.rs:396` on a fresh partition |
//! | 1 | the attestation scalar, `attestation.rs:180` |
//! | 1 | the attestation certificate, one chunked part, `attestation.rs:179` |
//!
//! (`soak_finding_1.rs` compensates for the same two attestation slots when it
//! wants an exact `other_slots`.)
//!
//! A credential's snapshot cost is dominated by its own field lengths, and
//! [`REALISTIC_MC`] sends the largest ones a browser may: a 63-character RP ID
//! and a 58-character `user.name`, both under the snapshot's 64-byte
//! `NAME_MAX`, a 43-character `displayName`, a spec-legal 64-byte `user.id`
//! (CTAP 2.1 §6.5.1 caps it at 64; `ID_MAX` is 64), a 32-byte `credBlob`
//! (the CTAP 2.1 §6.5.4 maximum), a `largeBlobKey` and `hmac-secret`
//! requested. Measured on this path, the snapshot grows **611 B per
//! credential** on top of a 105-B floor (the auth map: PIN state, cred
//! counter, sealed device random — see the `AUTH_SCRATCH` table at
//! `device_keystore.rs:154-192`). `2,549 / 496 = 5.14` → 6 parts, and the
//! parts ladder is
//!
//! | credentials | snapshot bytes | parts (`ceil(len/496)`) |
//! |---|---|---|
//! | 1 | 716 | 2 |
//! | 2 | 1,327 | 3 |
//! | 3 | 1,938 | 4 |
//! | 4 | 2,549 | 6 |
//! | 5 | 3,160 | 7 |
//!
//! so the fourth registration's rewrite needs `12 + 4 + 6 = 22 ≤ 24` and the
//! fifth needs `12 + 6 + 7 = 25 > 24`. The fifth is refused. That is the
//! reported ceiling, and it is a *storage* ceiling, not the credential-count
//! bound: `12 + 12 = 24` would be the whole store.
//!
//! Two things this file deliberately does **not** do, because both would hide
//! the arithmetic it exists to pin:
//!
//! * **Foreign slot value lengths are irrelevant.** Every one of the nine is
//!   filled to a realistic size, but `write` charges one entry per key
//!   regardless (`secure_store.rs:1308-1337`), so the ceiling is set by the
//!   *count*. Shrinking them changes nothing; adding one more entry does.
//! * **`hmac-secret` costs nothing in the snapshot.** The device returns the
//!   `hmac-secret-mc` output in `authData` but stores
//!   `hmac_secret: HeaplessVec::new()` (`device_core.rs:1166`), so a real
//!   browser's synced passkey is 611 B here, not 611 + 94 B.
//!
//! # Why `Rp2350SecureStore` and not `HostSecureStore`
//!
//! `HostSecureStore` is a `BTreeMap` with no entry bound and no per-value
//! bound (`secure_store.rs:596-605`: `write` only checks `MAX_KEY_LEN` /
//! `MAX_VALUE_LEN` = 48 / 16 KiB). Over it, the chunked rewrite can never
//! run out of entries, so **the four-credential ceiling is not expressible
//! against it** — the nearest reachable limit is `DEVICE_MAX_CREDS`, and a
//! test written there would have asserted the wrong number for the right
//! reason. `the_host_stand_in_store_cannot_express_this_ceiling` pins that
//! finding so the substitution is not made again. `Rp2350SecureStore` is pure
//! static memory with no arm-specific code, so it compiles and runs on the
//! host (`secure_store.rs:809`, `#[cfg(feature = "device")]`) and is the
//! store the board actually has.

use fapico2_fido::FidoApp;
use fapico2_platform::dispatch::App as _;
use fapico2_platform::secure_store::chunked;
use fapico2_platform::secure_store::rp2350::Rp2350SecureStore;
use fapico2_platform::secure_store::SecureStore;
use fapico2_platform::trng::HostTrng;

const CTAP2_MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;

/// CTAP2 error the fifth registration must be answered with.
const KEY_STORE_FULL: u8 = 0x28; // `ctap2.rs:121`, `Ctap2Response::KeyStoreFull`.

/// The nine entries owned by applets other than FIDO.
///
/// Real slot names, cited to their owners. Each is written with a plain
/// `SecureStore::write`, i.e. **one physical entry apiece**. That is the
/// *lightest* reading of "nine entries": the OATH and PIV tables are
/// chunked on device and would span several parts each, so a board running
/// this firmware plus a populated OATH would sit at or below this ceiling
/// rather than above it.
///
/// | slot | owner |
/// |---|---|
/// | `oath.keystore.v1` | `apps/oath/src/oath_core.rs:283` |
/// | `oath.seal.gen.v1` | `apps/oath/src/oath_core.rs:307` |
/// | `otp.slots.v2` | `apps/oath/src/otp.rs:227` |
/// | `piv.keystore.v1` | `apps/piv/src/keystore.rs:18` |
/// | `openpgp.keystore.v1` | `platform/src/migration.rs:42` |
/// | `mgmt.conf.v1` | `apps/mgmt/src/lib.rs:206` |
/// | `vled.conf.v1` | `apps/vendor_led/src/lib.rs:196` |
/// | `boot.fwmanifest.v1` | `platform/src/fw_manifest.rs:39` |
/// | `mig.done.v1` | `platform/src/migration.rs:37` |
///
/// The value lengths are the applets' realistic ones (a PIV/OATH table blob,
/// a short config record) and are here only so the fixture looks like a real
/// partition: `Rp2350SecureStore::write` charges one entry per key regardless
/// of length, so they do not enter the arithmetic.
const FOREIGN_SLOTS: &[(&[u8], usize)] = &[
    (b"oath.keystore.v1", 512),
    (b"oath.seal.gen.v1", 8),
    (b"otp.slots.v2", 480),
    (b"piv.keystore.v1", 512),
    (b"openpgp.keystore.v1", 512),
    (b"mgmt.conf.v1", 24),
    (b"vled.conf.v1", 17),
    (b"boot.fwmanifest.v1", 512),
    (b"mig.done.v1", 4),
];

/// Physical entries the fixture holds before FIDO's first write, and
/// therefore the `other_slots` term of every transient below.
const OTHER_SLOTS: usize = 9 + 3; // nine foreign + hkey + attest scalar + attest cert part.

/// A store shaped like a soak board's: the nine foreign entries, plus the
/// `fido.hkey` the boot path expects to find so it takes the
/// "already-provisioned" arm (`device_app.rs:384`) instead of re-minting.
///
/// The store key is set because the board's is (`Rp2350SecureStore`'s
/// US-915 note: "the boot path always sets the key"), and because the
/// snapshot's sensitive fields are only sealed under it
/// (`DeviceKeystore::persist`, `device_keystore.rs:1617`). Without it the
/// credentials cost 112 B less each and the ceiling moves to five — the same
/// sensitivity the module docs warn about.
fn soak_store() -> Rp2350SecureStore {
    let mut store = Rp2350SecureStore::new();
    store.set_store_key([0x5au8; 32]);
    store.write(b"fido.hkey", &[0x11u8; 32]).unwrap();
    for (slot, len) in FOREIGN_SLOTS {
        store.write(slot, &vec![0x22u8; *len]).unwrap();
    }
    assert_eq!(
        FOREIGN_SLOTS.len(),
        9,
        "the scenario fixes nine foreign entries; changing that number moves \
         the ceiling (see the module docs)"
    );
    store
}

/// The device twin, booted over the fixture store with an always-grant
/// presence hook.
///
/// Presence is not optional: every `makeCredential` asserts user presence
/// whatever `uv` says (`device_core.rs:1001-1008`, US-907), and `up: false`
/// is refused `InvalidOption` before that (`device_core.rs:988-990`). The
/// hook stands in for the button so the test exercises the *storage*
/// ceiling and not the touch window.
fn booted() -> (FidoApp, Rp2350SecureStore, HostTrng) {
    let mut trng = HostTrng::new();
    let mut store = soak_store();
    let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();
    app.set_presence_grant(|_tag| true);
    (app, store, trng)
}

/// A `user.id` of 64 bytes — CTAP 2.1 §6.5.1's maximum, and exactly
/// `ID_MAX` (`device_keystore.rs:148`).
fn user_handle(n: u8) -> [u8; 64] {
    let mut h = [0u8; 64];
    for (i, b) in h.iter_mut().enumerate() {
        *b = n.wrapping_mul(31).wrapping_add(i as u8).wrapping_add(0x11);
    }
    h
}

/// One realistic browser passkey registration: CTAP2 `makeCredential` (0x01)
/// with `rk: true`, `up: true`, a 63-byte RP ID, a 58-byte `user.name`, a
/// 43-byte `displayName`, a 64-byte `user.id`, a 32-byte `credBlob` (the
/// CTAP 2.1 §6.5.4 maximum), and `largeBlobKey` + `hmac-secret` +
/// `thirdPartyPayment` requested — the extensions a site asking for a synced
/// passkey sends.
///
/// Hand-encoded with `cbor::no_heap` because `device_core.rs` parses off the
/// same streaming writer; `n` distinguishes the registrations (it feeds both
/// `clientDataHash` and `user.id`, and the device derives the credential ID
/// from RP ID + user handle, so each `n` is a distinct credential).
fn mc_request(n: u8) -> Vec<u8> {
    use fapico2_fido::cbor::no_heap as nh;

    let mut r: heapless::Vec<u8, 1024> = heapless::Vec::new();
    // 1 clientDataHash, 2 rp, 3 user, 4 pubKeyCredParams, 5 excludeList,
    // 6 extensions, 7 options.
    nh::push_map_header(&mut r, 7).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_bstr(&mut r, &[n.wrapping_mul(17).wrapping_add(3); 32]).unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_tstr(&mut r, "login.webauthn.secure-passkey-demo.enterprise.example-site.test").unwrap();
    nh::push_tstr(&mut r, "name").unwrap();
    nh::push_tstr(&mut r, "Passkey Demo Site").unwrap();
    nh::push_uint(&mut r, 3).unwrap();
    nh::push_map_header(&mut r, 3).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_bstr(&mut r, &user_handle(n)).unwrap();
    nh::push_tstr(&mut r, "name").unwrap();
    nh::push_tstr(&mut r, "alice.thompson.whitfield@corp.enterprise.example-site.test").unwrap();
    nh::push_tstr(&mut r, "displayName").unwrap();
    nh::push_tstr(&mut r, "Alice Thompson-Whitfield (Contractor, EMEA)").unwrap();
    nh::push_uint(&mut r, 4).unwrap();
    nh::push_array_header(&mut r, 1).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "type").unwrap();
    nh::push_tstr(&mut r, "public-key").unwrap();
    nh::push_tstr(&mut r, "alg").unwrap();
    nh::push_neg(&mut r, -7).unwrap(); // ES256, the device's advertised alg
    nh::push_uint(&mut r, 5).unwrap();
    nh::push_array_header(&mut r, 0).unwrap();
    nh::push_uint(&mut r, 6).unwrap();
    nh::push_map_header(&mut r, 4).unwrap();
    nh::push_tstr(&mut r, "credBlob").unwrap();
    nh::push_bstr(&mut r, &[n.wrapping_add(0x5a); 32]).unwrap();
    nh::push_tstr(&mut r, "hmac-secret").unwrap();
    nh::push_bool(&mut r, true).unwrap();
    nh::push_tstr(&mut r, "largeBlobKey").unwrap();
    nh::push_bool(&mut r, true).unwrap();
    nh::push_tstr(&mut r, "thirdPartyPayment").unwrap();
    nh::push_bool(&mut r, true).unwrap();
    nh::push_uint(&mut r, 7).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "rk").unwrap();
    nh::push_bool(&mut r, true).unwrap();
    nh::push_tstr(&mut r, "up").unwrap();
    nh::push_bool(&mut r, true).unwrap();
    r.as_slice().to_vec()
}

/// Drive one CTAP2 command through the device path **with the store bound**,
/// exactly as `firmware/src/hid_serve.rs` does, then run the durable-before-ack
/// persist gate.
///
/// The store must be passed: `process_ctap2` leaves it `None`, and the
/// `None` arm takes the legacy mutate-and-mark-dirty path
/// (`device_core.rs:1192-1194`), which never refuses anything. Returns
/// `(status, gate_wrote)`.
fn call(app: &mut FidoApp, store: &mut Rp2350SecureStore, cmd: u8, req: &[u8]) -> (u8, bool) {
    let mut out = heapless::Vec::<u8, CTAP2_MAX_MSG>::new();
    app.process_ctap2_with_store(cmd, req, [1, 2, 3, 4], &mut out, Some(store));
    let status = out.as_slice()[0];
    let wrote = app.persist_if_dirty(store);
    (status, wrote)
}

/// The stored snapshot's exact bytes, or `None` when the slot is empty.
///
/// Byte-exact comparison is the point: "no partial credential remains" is a
/// statement about the whole image, not just about the credential count.
fn snapshot(store: &mut Rp2350SecureStore) -> Option<Vec<u8>> {
    let mut out = [0u8; chunked::MAX_LOGICAL_LEN];
    match chunked::read_chunked(store, fapico2_fido::device_keystore::KEYSTORE_SLOT, &mut out) {
        Ok(n) => Some(out[..n].to_vec()),
        Err(_) => None,
    }
}

/// Physical part slots the `fido.keystore.v1` chunked family occupies across
/// **both** buffers — an orphan left by a failed rewrite would show up here,
/// which is the self-cleaning property S-731-2 pins.
fn keystore_parts(store: &Rp2350SecureStore) -> usize {
    let mut count = 0;
    for buf in 0..2u8 {
        for index in 0..chunked::MAX_PARTS {
            if let Some((pk, pklen)) =
                chunked::physical_part_key(fapico2_fido::device_keystore::KEYSTORE_SLOT, buf, index)
            {
                if store.contains(&pk[..pklen]) {
                    count += 1;
                }
            }
        }
    }
    count
}

/// Physical entries the whole store holds, read out of the partition image's
/// count field (`secure_store.rs:973-987`).
fn occupancy(store: &Rp2350SecureStore) -> usize {
    let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    store.partition_image(&mut img).unwrap();
    u32::from_le_bytes([img[4], img[5], img[6], img[7]]) as usize
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

/// Given nine foreign slots and four realistic browser credentials, all four
/// persist — each durable in the store before its ack, and still there after
/// a power cycle.
///
/// The 4-part → 6-part step is where the fourth registration lands: the
/// snapshot jumps from 1,938 B to 2,549 B, so it is the *first* registration
/// whose rewrite is not a same-width rewrite, and its transient
/// (`12 + 4 + 6 = 22 ≤ 24`) is the largest one that fits.
#[test]
fn four_realistic_credentials_persist_with_nine_foreign_slots_resident() {
    let (mut app, mut store, mut trng) = booted();

    for n in 0..4u8 {
        let (status, wrote) = call(&mut app, &mut store, 0x01, &mc_request(n));
        assert_eq!(status, 0x00, "credential {} must enroll", n + 1);
        assert!(wrote, "credential {}: durable-before-ack must persist", n + 1);
        assert!(!app.is_dirty(), "credential {}: gate left clean", n + 1);
    }

    assert_eq!(app.keystore().cred_count(), 4);
    // The arithmetic the whole file rests on.
    let snap = snapshot(&mut store).expect("snapshot written");
    assert_eq!(snap.len(), 2_549, "four-credential snapshot size");
    assert_eq!(chunked::MAX_PARTS * chunked::PART_PAYLOAD_MAX, 5_952);
    assert_eq!(snap.len().div_ceil(chunked::PART_PAYLOAD_MAX), 6, "6 parts");
    assert_eq!(keystore_parts(&store), 6, "one generation, no orphans");
    assert_eq!(
        occupancy(&store),
        OTHER_SLOTS + 6,
        "12 other slots + a 6-part keystore = 18/24"
    );

    // Durable: a power cycle through the partition image keeps all four.
    let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let len = store.partition_image(&mut img).unwrap();
    let mut restored = Rp2350SecureStore::new();
    restored.set_store_key([0x5au8; 32]);
    restored.from_partition_image(&img[..len]);
    let mut rebooted = FidoApp::boot(&mut trng, &mut restored).unwrap();
    assert_eq!(
        rebooted.keystore().cred_count(),
        4,
        "all four credentials survive the reboot"
    );
}

/// When a fifth is enrolled the result is `KeyStoreFull` (0x28).
///
/// `12 + 6 + 7 = 25 > 24`: the live generation is 6 parts, the new one needs
/// 7, and `write_chunked` refuses the seventh part write with
/// `SecureStoreError::Full` (`secure_store.rs:1336`) rather than evicting
/// anything. `store_credential_checked` rolls the credential back
/// (`device_keystore.rs:1686-1712`) and `make_credential_inner` maps the
/// failure to `CTAP2_ERR_KEY_STORE_FULL` (`device_core.rs:1189-1199`).
#[test]
fn a_fifth_credential_is_refused_with_key_store_full() {
    let (mut app, mut store, _trng) = booted();
    for n in 0..4u8 {
        assert_eq!(call(&mut app, &mut store, 0x01, &mc_request(n)).0, 0x00);
    }

    let (status, wrote) = call(&mut app, &mut store, 0x01, &mc_request(4));
    assert_eq!(
        status, KEY_STORE_FULL,
        "the fifth credential is a storage refusal, and it says so on the wire"
    );
    assert!(!wrote, "nothing may be persisted after a refusal");
    assert!(!app.is_dirty(), "no un-persistable dirty state survives");

    // The refusal is repeatable and does not degrade: a sixth is refused the
    // same way rather than the device wedging on the second failure.
    let (status, _) = call(&mut app, &mut store, 0x01, &mc_request(5));
    assert_eq!(status, KEY_STORE_FULL, "the refusal is not one-shot");
}

/// No partial credential remains.
///
/// `store_credential_checked` is the transactional wrapper that makes this
/// true: it pushes, attempts the persist, and pops on failure
/// (`device_keystore.rs:1705-1712`). Four assertions, because "partial" can
/// mean four different things here — the in-RAM model, the signature counter,
/// the snapshot image, and the physical store.
#[test]
fn no_partial_credential_remains_after_a_refusal() {
    let (mut app, mut store, mut trng) = booted();
    for n in 0..4u8 {
        assert_eq!(call(&mut app, &mut store, 0x01, &mc_request(n)).0, 0x00);
    }
    let before = snapshot(&mut store).expect("snapshot");
    let occ_before = occupancy(&store);
    let parts_before = keystore_parts(&store);
    let counter_before = app.keystore().cred_counter;
    let refused_id = fapico2_fido::crypto::sha256(b"refused").to_vec();

    assert_eq!(call(&mut app, &mut store, 0x01, &mc_request(4)).0, KEY_STORE_FULL);

    assert_eq!(app.keystore().cred_count(), 4, "no fifth credential in RAM");
    assert_eq!(
        app.keystore().cred_counter, counter_before,
        "the reserved signature counter is handed back (`device_core.rs:1196`)"
    );
    assert_eq!(
        snapshot(&mut store).as_deref(),
        Some(before.as_slice()),
        "the stored snapshot is byte-identical: not one byte of a partial \
         credential reached the store"
    );
    assert_eq!(keystore_parts(&store), parts_before, "self-cleaning: no orphan parts");
    assert_eq!(occupancy(&store), occ_before, "occupancy returned to its pre-write value");
    // Every surviving credential is one of the four that enrolled — the
    // refused registration's `user.id` appears in none of them, and no
    // credential frame was left half-written (an unsealed private key would
    // read back as zeros, which the RPC gate would treat as unusable).
    for c in app.keystore().credentials.iter() {
        assert!(
            (0..4u8).any(|n| c.user_handle.as_slice() == user_handle(n).as_slice()),
            "a credential whose user.id is not one of the four enrolled ones survived"
        );
        assert_ne!(c.private_key, [0u8; 32], "a credential frame was left unsealed");
    }
    assert!(
        app.keystore().get_credential(&refused_id).is_none(),
        "the refused credential is not addressable"
    );

    // And it stays that way across a power cycle — the durable image is the
    // image the reader will see.
    let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let len = store.partition_image(&mut img).unwrap();
    let mut restored = Rp2350SecureStore::new();
    restored.set_store_key([0x5au8; 32]);
    restored.from_partition_image(&img[..len]);
    let mut rebooted = FidoApp::boot(&mut trng, &mut restored).unwrap();
    assert_eq!(rebooted.keystore().cred_count(), 4, "still exactly four after the reboot");
}

/// The device stays responsive.
///
/// The SOAK-FINDING-1 wedge this file descends from answered *every* CTAPHID
/// command — reads included — with `ERROR`/`INVALID_COMMAND`, because an
/// un-persistable snapshot latched `dirty` and the durable-before-ack gate
/// (US-425/427) then masked everything. The difference between a clean
/// `KeyStoreFull` and that wedge is precisely whether reads still come back
/// normally, so this is the assertion that tells them apart.
#[test]
fn the_device_stays_responsive_after_a_refusal() {
    let (mut app, mut store, _trng) = booted();
    for n in 0..4u8 {
        assert_eq!(call(&mut app, &mut store, 0x01, &mc_request(n)).0, 0x00);
    }
    assert_eq!(call(&mut app, &mut store, 0x01, &mc_request(4)).0, KEY_STORE_FULL);

    // A read is unmasked.
    let (status, _) = call(&mut app, &mut store, 0x04, &[]);
    assert_eq!(status, 0x00, "getInfo after a refusal: a normal reply, not ERROR");
    assert!(!app.is_dirty(), "a read never dirties the gate");

    // A registered credential still authenticates, which proves the store is
    // readable end-to-end and the four survivors are intact. The counter bump
    // is batched (`COUNTER_PERSIST_INTERVAL`, `device_keystore.rs:96`) and
    // this bump stays inside the window the fourth registration closed, so it
    // costs no rewrite — it is a read that happens to write a counter.
    let cred_id: Vec<u8> = app.keystore().credentials[0].credential_id.to_vec();
    let ga = {
        use fapico2_fido::cbor::no_heap as nh;
        let mut g: heapless::Vec<u8, 256> = heapless::Vec::new();
        nh::push_map_header(&mut g, 3).unwrap();
        nh::push_uint(&mut g, 1).unwrap();
        nh::push_tstr(&mut g, "login.webauthn.secure-passkey-demo.enterprise.example-site.test").unwrap();
        nh::push_uint(&mut g, 2).unwrap();
        nh::push_bstr(&mut g, &[0x77u8; 32]).unwrap();
        nh::push_uint(&mut g, 3).unwrap();
        nh::push_array_header(&mut g, 1).unwrap();
        nh::push_map_header(&mut g, 2).unwrap();
        nh::push_tstr(&mut g, "type").unwrap();
        nh::push_tstr(&mut g, "public-key").unwrap();
        nh::push_tstr(&mut g, "id").unwrap();
        nh::push_bstr(&mut g, &cred_id).unwrap();
        g.as_slice().to_vec()
    };
    let (status, _) = call(&mut app, &mut store, 0x02, &ga);
    assert_eq!(status, 0x00, "an enrolled credential still authenticates");
    assert!(!app.is_dirty(), "the in-window counter bump left the gate clean");

    // Writes are refused cleanly, never wedged.
    let (status, wrote) = call(&mut app, &mut store, 0x01, &mc_request(6));
    assert_eq!(status, KEY_STORE_FULL, "a later registration is still answered");
    assert!(!wrote);
}

/// Why the fixture cannot be built on `HostSecureStore`.
///
/// The brief for this story named `HostSecureStore`, on the reasonable
/// assumption that it bounds entries the way the board does. It does not: its
/// `write` is a `BTreeMap::insert` with only `MAX_KEY_LEN` / `MAX_VALUE_LEN`
/// checks (`secure_store.rs:596-605`), so the chunked rewrite can never run
/// out of physical entries and the four-credential ceiling is *inexpressible*
/// against it. What it does reach is `DEVICE_MAX_CREDS` — a different limit,
/// reached for a different reason, and off by one credential here. This test
/// pins the finding so the substitution is not repeated: anyone porting
/// `key_store_ceiling.rs` to the host store will see this fail.
#[test]
fn the_host_stand_in_store_cannot_express_this_ceiling() {
    use fapico2_platform::secure_store::HostSecureStore;

    let mut host = HostSecureStore::new();
    // The same nine entries fit with room to spare — there is no bound to
    // exceed.
    for (slot, len) in FOREIGN_SLOTS {
        host.write(slot, &vec![0x22u8; *len]).unwrap();
    }
    let mut trng = HostTrng::new();
    let mut app = FidoApp::boot(&mut trng, &mut host).unwrap();
    app.set_presence_grant(|_tag| true);

    // Every registration this fixture would refuse is accepted.
    for n in 0..4u8 {
        let mut out = heapless::Vec::<u8, CTAP2_MAX_MSG>::new();
        app.process_ctap2_with_store(0x01, &mc_request(n), [1, 2, 3, 4], &mut out, Some(&mut host));
        assert_eq!(out.as_slice()[0], 0x00);
    }
    for n in 4..8u8 {
        let mut out = heapless::Vec::<u8, CTAP2_MAX_MSG>::new();
        app.process_ctap2_with_store(0x01, &mc_request(n), [1, 2, 3, 4], &mut out, Some(&mut host));
        assert_eq!(
            out.as_slice()[0],
            0x00,
            "an unbounded store never reaches the occupancy ceiling — only \
             DEVICE_MAX_CREDS ({}) can stop it",
            fapico2_fido::device_keystore::DEVICE_MAX_CREDS
        );
    }
    assert_eq!(
        app.keystore().cred_count(),
        8,
        "8 of the 12 `DEVICE_MAX_CREDS` fit, so what stopped the earlier \
         registrations was not the credential-count bound"
    );
}
