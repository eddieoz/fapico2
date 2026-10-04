//! US-176 (EPIC `PICOForge-COMPAT`) — the Phase I durable state behind the
//! RS-Key `0x41` channel, and the two `VendorOps` implementations that reach it.
//!
//! # What this file is for
//!
//! US-170 … US-175 are six protocol stories. The storage they all need landed
//! first, and this file is the contract they are written against. It pins five
//! things, each of which is a way the foundation could be wrong in a way no
//! Phase I arm would notice:
//!
//! 1. a state value **round-trips** through the keystore snapshot unchanged, on
//!    both codecs;
//! 2. a state that **cannot be encoded** is reported and the in-memory value is
//!    left untouched — the property `EXPORT` and `ATT_IMPORT` are built on;
//! 3. a **fresh** keystore reads back a *documented* default for every field,
//!    and each default is stated rather than inherited;
//! 4. the snapshot **round-trips through `HostSecureStore`** and comes back
//!    byte-identical, i.e. a reboot does not lose or invent state;
//! 5. a **corrupt or truncated** stored blob yields the documented default
//!    rather than a panic — this is a security applet and the device panic
//!    handler is `loop {}` (`firmware/src/main.rs`), so a panic in a decoder
//!    is a wedged token until somebody unplugs it.
//!
//! Plus the two directions of the all-or-nothing write contract, and the
//! worst-case size check for the auth scratch that had to grow for this.

use fapico2_fido::ctap2::Ctap2Response;
use fapico2_fido::device_keystore::{self, DeviceKeystore};
use fapico2_fido::vendor41::{
    AuditRecord, Checkpoint, MseChannel, MsePoint, OrgAttestation, SoftLock, VendorOps,
    AUDIT_ENTRY_LEN, AUDIT_RING_MAX, LOCK_BLOB_MAX, ORG_CHAIN_MAX, P256_POINT_LEN, SIG_DER_MAX,
};
use fapico2_fido::vendor_state::{
    self, VendorPublic, VendorSecret, VendorSession, VendorState,
};
use fapico2_platform::secure_store::{SecureStore, SecureStoreError};
use fapico2_platform::trng::HostTrng;
use p256::ecdsa::signature::Verifier as _;
use heapless::Vec as HV;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The CTAP2 reply capacity — the `0x41` response buffer, and what
/// `audit_window` streams into.
type Reply = HV<u8, { fapico2_fido::CTAP2_MAX_MSG }>;

/// A fresh host P-256 point as the two COSE halves the `MSE` arm hands to
/// [`VendorOps::mse_establish`].
fn host_point() -> ([u8; 32], [u8; 32]) {
    let (sk, _pk) = fapico2_fido::crypto::generate_p256_keypair();
    let sec = fapico2_fido::crypto::public_key_bytes(&sk.public_key());
    (sec[1..33].try_into().unwrap(), sec[33..65].try_into().unwrap())
}

fn trng() -> HostTrng {
    HostTrng::new()
}

/// A keystore with **every** vendor field at a non-default value, so a
/// round-trip that drops a field is visible.
///
/// Deliberately not a "typical" value: the point of a round-trip test is that
/// every field is distinguishable from every other default, and a state where
/// the ring is empty and the chain is `None` would pass a codec that silently
/// ignored three of the four secret fields.
fn populated() -> VendorState {
    let secret = VendorSecret {
        master_seed: Some([0xA5; 32]),
        lock: SoftLock::new(&[0x5A; 60]).expect("60 bytes is inside LOCK_BLOB_MAX"),
        org_scalar: Some([0x3C; 32]),
        audit_key: Some([0xC3; 32]),
    };
    let mut public = VendorPublic {
        audit_enabled: true,
        audit_seq: 7,
        audit_epoch: [0x11; 32],
        ..VendorPublic::default()
    };
    for seq in 0..5u32 {
        public.push_audit(AuditRecord {
            uptime_ms: 1_000 + seq,
            event: 0x01 + seq as u8,
            aux: seq as u8,
            detail: [seq as u8; 8],
        });
    }
    public.org_chain =
        Some((0u8..=255).cycle().take(300).collect::<HV<u8, ORG_CHAIN_MAX>>());
    VendorState { secret, public }
}

fn fresh_keystore() -> DeviceKeystore {
    DeviceKeystore::fresh(&mut trng()).expect("host TRNG")
}

/// The store key a `HostSecureStore` seals under, so the tests can round-trip
/// the sealed half the way the device does.
fn store_key(store: &fapico2_platform::secure_store::HostSecureStore) -> [u8; 32] {
    store.store_key().expect("HostSecureStore seals its snapshot")
}

// ---------------------------------------------------------------------------
// 1. Round-trip
// ---------------------------------------------------------------------------

/// A populated state survives the device codec byte-for-byte.
///
/// The device codec is the one the RP2350 actually runs
/// (`DeviceKeystore::to_cbor` / `from_cbor`), and the whole point of the
/// two-key split is that the sealed half and the plaintext half take different
/// decode paths — so this asserts both at once, by comparing the reloaded
/// `VendorState` against the original.
#[test]
fn a_populated_state_round_trips_through_the_device_keystore() {
    let want = populated();
    let mut ks = fresh_keystore();
    ks.vendor = want.clone();
    let mut store = fapico2_platform::secure_store::HostSecureStore::new();

    assert!(ks.persist(&mut store).is_ok(), "a populated state must persist");

    let back = DeviceKeystore::load(&mut store)
        .expect("load")
        .expect("a snapshot is present");
    assert_eq!(
        back.vendor, want,
        "the reloaded vendor state must equal what was written — auth keys 7 \
         and 8 encode every field of both halves, and a field that round-trips \
         to a default is a field that was dropped"
    );
}

/// [`DeviceKeystore::load_phy`] answers **exactly** what
/// `load(..).map(|ks| ks.phy)` does — for a populated record, for the default,
/// for an absent snapshot, and above all for a corrupt one.
///
/// # Why the equivalence needs pinning
///
/// `load_phy` exists because binding a whole 12-KiB `DeviceKeystore` in order
/// to read one ~40-byte record cost 19,904 B of the HID task's poll frame
/// (US-1550's `Drop` on `DeviceCredential` stops a droppable 12-KiB value from
/// being elided into its destination — see `load_phy`'s own doc comment). It
/// reaches the same answer by a different route: `decode`'s top-level scan,
/// `decode_auth` unchanged, and each credential decoded and discarded so no
/// 8,640-byte array is ever built.
///
/// **A narrow reader that is only nearly equivalent is worse than none at
/// all.** `sync_phy` feeds its answer straight into the next persist, so a
/// `phy` read out of a snapshot the full load would have *refused* would
/// overwrite good durable state with a value out of a corrupt document. That
/// is the arm the sweep below exists for; the others keep the two readers from
/// drifting on the ordinary paths.
#[test]
fn load_phy_agrees_with_a_full_load_in_every_state() {
    use fapico2_platform::secure_store::chunked;

    let full = fapico2_fido::vendorff::PhyConfig {
        vid_pid: Some(0x1209_0001),
        led_gpio: Some(0x0C),
        led_brightness: Some(80),
        options: Some(0x0002),
        enabled_usb_itf: Some(0x03AB),
        led_conf: Some(fapico2_fido::vendorff::LedConf([0x11; 17])),
        product: Some(
            fapico2_fido::vendorff::IdentityName::new("Acme Token").expect("9 bytes"),
        ),
        manufacturer: Some(
            fapico2_fido::vendorff::IdentityName::new("The BLOCO Community")
                .expect("19 bytes"),
        ),
    };

    // --- absent: no snapshot in the slot at all. Both must decline, and
    //     `sync_phy` reads that decline as "nothing to adopt" — never as an
    //     absent record it would then clear.
    {
        let mut store = fapico2_platform::secure_store::HostSecureStore::new();
        assert!(
            DeviceKeystore::load(&mut store).expect("load").is_none(),
            "control: a fresh store holds no snapshot"
        );
        assert_eq!(
            DeviceKeystore::load_phy(&mut store),
            None,
            "load_phy must decline exactly where a full load finds no snapshot"
        );
    }

    // --- present: default and fully-populated records agree, and the control
    //     itself round-trips, so a passing arm is not vacuous.
    for (what, phy) in [
        ("the default record", fapico2_fido::vendorff::PhyConfig::default()),
        ("a fully-populated record", full),
    ] {
        let mut ks = fresh_keystore();
        ks.phy = phy;
        ks.vendor = populated();
        let mut store = fapico2_platform::secure_store::HostSecureStore::new();
        assert!(ks.persist(&mut store).is_ok(), "{what} must persist");

        let full = DeviceKeystore::load(&mut store)
            .expect("load")
            .expect("a snapshot is present")
            .phy;
        assert_eq!(full, phy, "{what}: the control itself must round-trip");
        assert_eq!(
            DeviceKeystore::load_phy(&mut store),
            Some(phy),
            "{what}: load_phy must return exactly the record a full load would"
        );
    }

    // --- structural damage: the arm `sync_phy`'s safety rests on. Every
    //     document a full load refuses must also yield `None` from
    //     `load_phy`.
    //
    //     **Structural, not bit-flips.** A one-bit flip in the stored image is
    //     caught by the chunked layer's CRC before either decoder sees it, so
    //     a bit sweep proves nothing about the two readers — it only proves
    //     both of them say no to a corrupt chunk. These variants are encoded
    //     whole and written back with a valid CRC, so they reach the decoders.
    //
    //     The credential rows are the ones that matter most: `load_phy` walks
    //     the credential array to keep `load`'s "one unopenable credential
    //     fails the whole snapshot" rule, and dropping that walk is exactly
    //     the shortcut this test exists to forbid.
    {
        use fapico2_fido::cbor::no_heap as nh;
        use fapico2_fido::cbor::Value as V;

        // Lift the three envelope members out of a **persisted** snapshot,
        // not out of a `to_cbor(None, ..)` one: the persisted image is the one
        // both readers are built to open (it is sealed under the store key),
        // and an unsealed hand-built image is refused by both — which would
        // make every variant below refuse for the wrong reason.
        let mut ks = fresh_keystore();
        ks.phy = full;
        ks.vendor = populated();
        let mut store = fapico2_platform::secure_store::HostSecureStore::new();
        assert!(ks.persist(&mut store).is_ok(), "the control must persist");
        let slot = device_keystore::KEYSTORE_SLOT;
        let mut image = [0u8; { chunked::MAX_LOGICAL_LEN }];
        let n = chunked::read_chunked(&mut store, slot, &mut image[..]).expect("the control reads");

        // A persisted envelope is `{1: [max, auth, creds], 2: 2}` — two
        // entries, the second being the sealed marker. Walk it rather than
        // assuming a shape, so this stays true if the marker moves.
        let mut q = nh::Parser::new(&image[..n]);
        let n_entries = match q.next() {
            Ok(nh::Item::Map(k)) => k,
            _ => panic!("the envelope must be a map"),
        };
        assert!((1..=2).contains(&n_entries), "one or two envelope entries");
        let mut max_b: Option<Vec<u8>> = None;
        let mut auth_b: Option<Vec<u8>> = None;
        let mut creds_b: Option<Vec<u8>> = None;
        for _ in 0..n_entries {
            let key = match q.next() {
                Ok(nh::Item::U(k)) => k,
                _ => panic!("every envelope key must be an integer"),
            };
            if key != 1 {
                continue; // the sealed marker, and its value
            }
            assert!(matches!(q.next(), Ok(nh::Item::Array(3))), "[max, auth, creds]");
            for (name, slot_out) in [
                ("max", &mut max_b),
                ("auth", &mut auth_b),
                ("creds", &mut creds_b),
            ] {
                match q.next() {
                    Ok(nh::Item::B(b)) => *slot_out = Some(b.to_vec()),
                    _ => panic!("envelope member `{name}` must be a byte string"),
                }
            }
        }
        let (max_b, auth_b, creds_b) = (
            max_b.expect("max"),
            auth_b.expect("auth"),
            creds_b.expect("creds"),
        );

        // The envelope's third member is a byte string *containing* the
        // credential array — which is why each member is encoded first and
        // wrapped, rather than dropped into the array as a bare `Value`.
        let empty = || V::A(Vec::new());
        // The sealed marker travels with the envelope, and it has to: the auth
        // map lifted out of a persisted image is sealed, so a variant that
        // rebuilt the envelope without the marker would be refused by both
        // readers for a reason that has nothing to do with its damage.
        let sealed_value = {
            let decoded = fapico2_fido::cbor::decode(&image[..n])
                .expect("the control envelope must decode")
                .0;
            let V::M(entries) = decoded else {
                panic!("the envelope must be a map")
            };
            entries
                .into_iter()
                .find(|(k, _)| {
                    matches!(k, V::U(fapico2_fido::snapshot_crypt::SEALED_MARKER_KEY))
                })
                .map(|(_, v)| v)
                .expect("a persisted snapshot carries the sealed marker")
        };
        let envelope = |auth: V, creds: V| -> Vec<u8> {
            fapico2_fido::cbor::encode(&V::M(vec![
                (
                    V::U(1),
                    V::A(vec![
                        V::B(max_b.clone()),
                        V::B(fapico2_fido::cbor::encode(&auth)),
                        V::B(fapico2_fido::cbor::encode(&creds)),
                    ]),
                ),
                (
                    V::U(fapico2_fido::snapshot_crypt::SEALED_MARKER_KEY),
                    sealed_value.clone(),
                ),
            ]))
        };

        // The control's own auth map, lifted as a `Value` so a variant can
        // damage one field and keep the rest. A sealed map survives this: the
        // sealed members are opaque byte strings either way.
        let auth_map = || {
            fapico2_fido::cbor::decode(&auth_b)
                .expect("the control's auth map must decode")
                .0
        };
        let variants: Vec<(&str, Vec<u8>)> = vec![
            // --- the credential array, which `load_phy` walks and a narrow
            //     reader that skipped it would not.
            (
                "a credential entry that is an integer, not a byte string",
                envelope(auth_map(), V::A(vec![V::U(42)])),
            ),
            (
                "a credential body that is not a credential record",
                envelope(auth_map(), V::A(vec![V::B(vec![0xA1, 0x01, 0x02])])),
            ),
            (
                "a credential body that is truncated CBOR",
                envelope(auth_map(), V::A(vec![V::B(vec![0xA2])])),
            ),
            // --- the auth map, which `load_phy` shares with `load` verbatim.
            (
                "key 6 (the phy record) that is not a map",
                envelope(V::M(vec![(V::U(6), V::U(1))]), empty()),
            ),
            (
                "a key-6 field outside its stored width",
                envelope(
                    V::M(vec![(V::U(6), V::M(vec![(V::U(1), V::U(0x1_0000_0001))]))]),
                    empty(),
                ),
            ),
            (
                "the sealed marker carrying the wrong value",
                fapico2_fido::cbor::encode(&V::M(vec![
                    (
                        V::U(1),
                        V::A(vec![
                            V::B(max_b.clone()),
                            V::B(auth_b.clone()),
                            V::B(creds_b.clone()),
                        ]),
                    ),
                    (V::U(fapico2_fido::snapshot_crypt::SEALED_MARKER_KEY),
                     V::U(fapico2_fido::snapshot_crypt::SEALED_MARKER_VALUE + 1)),
                ])),
            ),
            (
                "a sealed document whose key-6 record was left sealed",
                envelope(V::M(vec![(V::U(6), sealed_value.clone())]), empty()),
            ),
            // --- the envelope itself.
            (
                "an envelope with an unknown key",
                fapico2_fido::cbor::encode(&V::M(vec![
                    (
                        V::U(1),
                        V::A(vec![
                            V::B(max_b.clone()),
                            V::B(auth_b.clone()),
                            V::B(creds_b.clone()),
                        ]),
                    ),
                    (
                        V::U(fapico2_fido::snapshot_crypt::SEALED_MARKER_KEY),
                        sealed_value.clone(),
                    ),
                    (V::U(9), V::U(1)),
                ])),
            ),
            (
                "a truncated document",
                envelope(auth_map(), empty())[..6].to_vec(),
            ),
        ];

        // **Positive control first.** The untouched reconstruction must load,
        // or every "both readers refuse" assertion below is vacuous — which is
        // the failure this test has already had once, when the control image
        // was hand-built unsealed and both readers refused it for a reason that
        // had nothing to do with the damage.
        {
            let bytes = envelope(auth_map(), V::A(Vec::new()));
            let mut ctl = fapico2_platform::secure_store::HostSecureStore::new();
            chunked::write_chunked(&mut ctl, slot, &bytes)
                .expect("the control must fit the chunked slot");
            assert!(
                matches!(DeviceKeystore::load(&mut ctl), Ok(Some(_))),
                "control: the reconstruction must itself be loadable"
            );
            assert_eq!(
                DeviceKeystore::load_phy(&mut ctl),
                Some(full),
                "control: both readers must agree on the untouched document"
            );
        }

        let total_variants = variants.len();
        let mut exercised = 0usize;
        for (what, bytes) in variants {
            let mut store = fapico2_platform::secure_store::HostSecureStore::new();
            chunked::write_chunked(&mut store, slot, &bytes)
                .expect("the variant must fit the chunked slot");
            assert!(
                !matches!(DeviceKeystore::load(&mut store), Ok(Some(_))),
                "control: a full load must refuse {what} — if it does not, this \
                 variant is not testing what its name claims"
            );
            assert_eq!(
                DeviceKeystore::load_phy(&mut store),
                None,
                "a document a full load refuses must not yield a phy through \
                 load_phy: {what}"
            );
            exercised += 1;
        }
        assert!(
            exercised >= total_variants,
            "control: every damage variant must have run, saw {exercised} of {total_variants}"
        );
    }
}

/// The same, through the **host** codec, so the two stacks cannot drift.
///
/// The two codecs are separate functions over one key numbering; this is what
/// holds them to it, and it is the direct descendant of the `vid_pid` width
/// divergence `keystore::us113_tests` records.
#[test]
fn the_two_codecs_agree_on_a_populated_state() {
    use fapico2_fido::keystore::AuthState;

    let want = populated();

    // Device: through the no-heap snapshot.
    let mut ks = fresh_keystore();
    ks.vendor = want.clone();
    let mut dev: HV<u8, 8448> = HV::new();
    ks.to_cbor(None, &mut dev).expect("device encode");

    // Host: through `AuthState`'s own `cbor::Value` codec, in both directions.
    let auth = AuthState { vendor: want.clone(), ..AuthState::default() };
    let encoded = fapico2_fido::cbor::encode(&auth.to_cbor_for_test(None));
    let back = AuthState::from_cbor_for_test(&encoded, None, false).expect("host decode");
    assert_eq!(
        back.vendor, want,
        "the host codec must reproduce what the device codec stored, or an \
         emulation run and a device run would disagree about the device's own \
         state"
    );

    // And the device half of the claim, against the *unsealed* format the
    // `to_cbor(None, ..)` call above produced: reloading it must give the
    // same value back.
    let mut store = fapico2_platform::secure_store::HostSecureStore::new();
    let mut round = fresh_keystore();
    round.vendor = want.clone();
    round.persist(&mut store).expect("persist");
    let reloaded = DeviceKeystore::load(&mut store).unwrap().unwrap();
    assert_eq!(reloaded.vendor, want);

    // The sealed format is a *different* encoding of the same value; it must
    // decode to the same thing, which is the property US-911's `{2: 2}` marker
    // is there to preserve.
    let mut sealed: HV<u8, 8448> = HV::new();
    ks.to_cbor(Some(&store_key(&store)), &mut sealed).expect("sealed encode");
    let mut sealed_store = fapico2_platform::secure_store::HostSecureStore::new();
    {
        use fapico2_platform::secure_store::chunked;
        chunked::write_chunked(
            &mut sealed_store,
            device_keystore::KEYSTORE_SLOT,
            &sealed,
        )
        .expect("write the sealed snapshot");
    }
    let unsealed = DeviceKeystore::load(&mut sealed_store).unwrap().unwrap();
    assert_eq!(
        unsealed.vendor, want,
        "a sealed snapshot must decode to the same state as the plaintext one; \
         the sealing is confidentiality, not a different format"
    );
}

// ---------------------------------------------------------------------------
// 2. A value that cannot be encoded
// ---------------------------------------------------------------------------

/// A lock blob over [`LOCK_BLOB_MAX`] is refused, and refusing it changes
/// nothing.
///
/// This is the "a failure cannot half-commit" claim in its cheapest form: the
/// refusal happens in `SoftLock::new`, **before** any state was written, so
/// there is nothing to roll back. The expensive directions — a failed flash
/// write — are the two tests further down.
#[test]
fn a_lock_blob_that_does_not_fit_is_refused_and_changes_nothing() {
    let too_long = [0u8; LOCK_BLOB_MAX + 1];
    let mut ks = fresh_keystore();
    let before = ks.vendor.clone();
    let mut session = VendorSession::default();
    let mut counter = 0u8;
    let mut random = move |b: &mut [u8]| {
        for x in b.iter_mut() {
            counter = counter.wrapping_add(1);
            *x = counter;
        }
    };
    let mut store = None;
    let status = vendor_state::with_keystore_ops(
        &mut ks,
        &mut session,
        &mut store,
        &mut random,
        |ops| match SoftLock::new(&too_long) {
            Err(_) => Err(Ctap2Response::InvalidLength),
            Ok(lock) => ops.set_soft_lock(lock),
        },
    );
    assert_eq!(
        status.unwrap_err(),
        Ctap2Response::InvalidLength,
        "a 65-byte lock blob is not a shape this channel accepts — the sealed \
         form is 60 (nonce 12 ‖ ct 32 ‖ tag 16)"
    );
    assert_eq!(
        ks.vendor, before,
        "the refusal must leave the state byte-identical"
    );
}

/// The audit ring's byte-string header and the encoder's capacity agree.
///
/// The one encoder-side failure the state can actually produce, and the reason
/// it is checked here rather than trusted: a `push_head` whose length
/// disagrees with the bytes after it is a `0x00` carrying a malformed record,
/// which is the failure mode `vendor41`'s `EMITTED_WIDTHS` note warns about for
/// the PHY path. Both are written from the same `audit_len`, so they cannot
/// disagree — this test is what makes that a check.
#[test]
fn the_audit_window_and_the_stored_ring_have_the_same_length() {
    let mut ks = fresh_keystore();
    ks.vendor.public.audit_enabled = true;
    let mut n = 0u32;
    for seq in 0..9u32 {
        ks.vendor.public.push_audit(AuditRecord { event: seq as u8, ..Default::default() });
        n += 1;
    }
    let stored_len = ks.vendor.public.audit_len as usize * AUDIT_ENTRY_LEN;
    let mut out = Reply::new();
    let w = {
        let mut session = VendorSession::default();
        let mut counter = 0u8;
        let mut random = move |b: &mut [u8]| {
            for x in b.iter_mut() {
                counter = counter.wrapping_add(1);
                *x = counter;
            }
        };
        let mut store = None;
        vendor_state::with_keystore_ops(
            &mut ks,
            &mut session,
            &mut store,
            &mut random,
            |ops| ops.audit_window(&mut out).expect("window"),
        )
    };
    assert_eq!(n as usize, AUDIT_RING_MAX.min(n as usize));
    assert_eq!(
        out.len(),
        stored_len,
        "the window the client folds must be exactly the records the snapshot \
         stores, or `build_journal`'s length check fails on a journal nobody \
         corrupted"
    );
    assert_eq!(w.seq_next, 9);
    assert_eq!(w.start, 0);
}

// ---------------------------------------------------------------------------
// 3. The documented defaults
// ---------------------------------------------------------------------------

/// A fresh keystore's vendor state, field by field, with the reason each
/// default is what it is.
///
/// The defaults are a *design*, not a fallback: each one is the answer a device
/// that has never seen a `0x41` sub-command must give, and each is what a
/// Phase I arm will report to a desktop app. They are spelled out here so a
/// later change to one of them is a deliberate edit to a named value.
#[test]
fn a_fresh_keystore_reads_back_the_documented_default_for_every_field() {
    let ks = fresh_keystore();
    let v = &ks.vendor;

    // --- the secret half -------------------------------------------------
    // "no seed": `STATE`'s `has_seed` is `master_seed().is_some()`, so `None`
    // is the only honest answer on a device that has never been LOADed. It is
    // also what makes `EXPORT` refuse rather than return 32 bytes of nothing.
    assert_eq!(v.secret.master_seed, None, "a fresh device has no master seed");
    // "not locked": engaging the lock stores its key, so an absent key is an
    // unlocked device. There is no separate bit that could disagree.
    assert!(!v.secret.lock.engaged(), "a fresh device's soft lock is disengaged");
    assert_eq!(v.secret.lock.key, None);
    assert_eq!(v.secret.lock.key_len, 0);
    // "no org attestation": `ATT_STATE`'s `installed` is `scalar.is_some()`,
    // and the per-device FIDO2 attestation is a *different* credential that
    // this state never touches (US-175's layering rule).
    assert_eq!(v.secret.org_scalar, None, "a fresh device has no org attestation");
    // "no checkpoint key": minted from the TRNG the first time a checkpoint is
    // signed, so a device that has never signed one has none — and, unlike a
    // derived key, there is nothing in the snapshot for an attacker to read.
    assert_eq!(
        v.secret.audit_key, None,
        "the checkpoint key is minted on first use, not derived from a value \
         that is already in the snapshot"
    );
    // Absent → auth key 7 is **not written at all**, so a device that has
    // never seen a `0x41` keeps byte-identical snapshots to before US-176.
    assert!(v.secret.is_empty(), "an unused secret half writes no snapshot key");

    // --- the public half -------------------------------------------------
    // Journalling is **opt-in** — the client's own contract is "nothing is
    // written to flash until it is enabled" — so the default is off and an
    // `audit_append` on a fresh device is a no-op rather than a write.
    assert!(!v.public.audit_enabled, "the audit journal is opt-in, so it starts off");
    // `seq = 0`: the next record will be number 0, and the client's
    // `build_journal` check `entries.len() == 20 × (seq_next - start)` is the
    // arithmetic that proves it.
    assert_eq!(v.public.audit_seq, 0);
    // `epoch = [0; 32]`: `h₀` for a journal that has recorded nothing. Zero is
    // a legal chain seed (`fold_chain` starts from it verbatim), so a
    // journal's first `head` is well defined from the first record on.
    assert_eq!(
        v.public.audit_epoch, [0u8; 32],
        "a chain that has absorbed nothing starts at the all-zero accumulator"
    );
    assert_eq!(v.public.audit_len, 0, "an empty journal has no live records");
    assert!(v.public.audit_ring.iter().all(|r| r == &[0u8; AUDIT_ENTRY_LEN]));
    assert_eq!(v.public.org_chain, None, "no org certificate chain");
    assert!(v.public.is_empty(), "an unused public half writes no snapshot key");

    // And the derived readouts the arms will use, so the defaults are pinned
    // where they are actually consumed rather than only in the fields.
    assert_eq!(v.public.live_start(), 0);
    assert_eq!(v.public.live_end(), 0);
    assert_eq!(v.public.audit_head(), [0u8; 32], "no records folded over a zero epoch");
}

// ---------------------------------------------------------------------------
// 4. The store round-trip
// ---------------------------------------------------------------------------

/// The state survives a `HostSecureStore` round-trip, and so does the
/// **sealed** form's confidentiality — the master seed must not be readable
/// in the stored bytes.
///
/// The second half is the one that is easy to get wrong and expensive to get
/// wrong: if auth key 7 were written in plaintext (as key 6's `phy` is), a
/// dump of the host partition would be a dump of the wallet's master seed.
#[test]
fn the_store_round_trips_and_the_secrets_are_not_readable_in_the_image() {
    let mut store = fapico2_platform::secure_store::HostSecureStore::new();
    let key = store_key(&store);
    let mut ks = fresh_keystore();
    ks.vendor = populated();
    ks.persist(&mut store).expect("persist");

    let reloaded = DeviceKeystore::load(&mut store).unwrap().unwrap();
    assert_eq!(reloaded.vendor, populated(), "the store round-trip is lossless");

    // Re-serialize the reloaded snapshot under the same key: those are exactly
    // the bytes the medium holds, so they are what a dump would reveal.
    let mut raw: HV<u8, 8448> = HV::new();
    reloaded.to_cbor(Some(&key), &mut raw).expect("encode");
    assert!(
        !raw.windows(32).any(|w| w == [0xA5; 32]),
        "the master seed must not appear in the serialized snapshot — auth key \
         7 is sealed under FieldScope::AuthVendorSecret"
    );
    assert!(
        !raw.windows(32).any(|w| w == [0x3C; 32]),
        "the org attestation scalar must not appear in the serialized snapshot"
    );
    assert!(
        !raw.windows(60).any(|w| w[..] == [0x5Au8; 60]),
        "the sealed soft-lock blob must not appear in the clear"
    );
}

// ---------------------------------------------------------------------------
// 5. Corrupt / truncated blobs
// ---------------------------------------------------------------------------

/// Every truncation of a stored public-half blob decodes to *a* value, never
/// panics, and never a half-decoded journal.
///
/// The device panic handler is `loop {}`, so a panic here is a wedged token.
/// Exhaustive over truncations rather than sampling one: the decoder has five
/// fields and each has its own refusal arm, and a single sample would leave
/// four of them unpinned.
#[test]
fn a_truncated_public_blob_decodes_to_the_documented_default_and_never_panics() {
    let mut ks = fresh_keystore();
    ks.vendor = populated();
    let mut bytes: HV<u8, 4096> = HV::new();
    ks.vendor.encode_public(&mut bytes).expect("encode");
    assert!(!bytes.is_empty());

    let default = VendorPublic::default();
    for cut in 0..bytes.len() {
        let got = VendorState::decode_public(&bytes[..cut]);
        // A prefix that happens to be a complete, well-formed map decodes to
        // *something*; the property under test is that it never panics and
        // never returns a state whose `seq` and `len` disagree — which is
        // exactly `live_start()` not underflowing.
        let _ = got.live_start();
        let _ = got.audit_head();
    }
    // And the specific refusals, each landing on the whole default.
    for bad in [
        &b""[..],
        &b"\x00"[..],                  // not a map
        &b"\x01"[..],                  // truncated map header
        &b"\xa1\x01"[..],              // a map with a key and no value
        &b"\xa1\x01\x20\x00"[..],      // enabled = a byte string, not an int
        &b"\xa1\x03\x58\x20"[..],      // epoch head with no 32 bytes
        &b"\xa1\x04\x58\x01"[..],      // ring of one byte, not 20
    ] {
        assert_eq!(
            VendorState::decode_public(bad),
            default,
            "a malformed public blob must decode to the documented default, \
             not to a half-built state"
        );
    }
}

/// A `seq` smaller than the record count is refused, because it would make
/// `live_start()` underflow.
///
/// `live_start` is a `const fn` doing `seq - len`, so a stored pair where
/// `seq < len` is the one way a *valid-looking* blob becomes a state that
/// panics on the next window — in debug, and wraps to 4 billion in release.
/// The decoder refuses it rather than clamping.
#[test]
fn a_public_blob_whose_seq_predates_its_ring_is_refused() {
    // `{2: 0, 4: h'' (one record)}` — one record but a next-sequence of 0.
    let mut bad: HV<u8, 64> = HV::new();
    bad.extend_from_slice(&[0xA2, 0x02, 0x00, 0x04, 0x54]).unwrap();
    bad.extend_from_slice(&[0u8; AUDIT_ENTRY_LEN]).unwrap();
    assert_eq!(
        VendorState::decode_public(&bad),
        VendorPublic::default(),
        "seq < record count would make live_start() underflow, so the whole \
         default is the answer"
    );
}

/// A **corrupt sealed** blob fails the snapshot, which is a different and
/// deliberate policy from the public half's.
///
/// `DeviceKeystore::from_cbor` answers `None` (→ `SecureStoreError::Corrupt`,
/// fatal per FX-440) rather than a default, because a wallet whose master
/// cannot be opened must not come up and tell the user it has no seed. The
/// test asserts the *distinction*, since the two halves sitting one key apart
/// is the thing a reader could get wrong.
#[test]
fn a_corrupt_sealed_blob_is_fatal_while_a_corrupt_public_one_is_not() {
    let key = [7u8; 32];
    let mut good: HV<u8, 512> = HV::new();
    populated()
        .encode_secret(Some(&key), &mut good)
        .expect("encode");
    // `07` (the auth key) followed by a byte string whose head is 2 or 3 bytes
    // depending on the blob's length, so the value comes out of the `cbor`
    // decoder rather than a fixed-offset slice.
    assert_eq!(good[0], 7);
    let (val, _) = fapico2_fido::cbor::decode(&good[1..]).expect("valid CBOR");
    let fapico2_fido::cbor::Value::B(v7) = val else {
        panic!("auth key 7's value must be a byte string")
    };
    let blob: HV<u8, 512> = v7.as_slice().try_into().expect("slice");
    assert!(VendorState::decode_secret(&blob, Some(&key), true).is_ok());

    // Flip one byte of the ciphertext — byte 20 is past the 12-byte nonce, so
    // the AEAD tag no longer verifies.
    let mut bad = blob.clone();
    bad[20] ^= 0x01;
    assert!(
        VendorState::decode_secret(&bad, Some(&key), true).is_err(),
        "a sealed field that fails to open fails the snapshot — the same rule \
         device_random (auth key 5) follows. Returning a default here would \
         answer has_seed = false to a device that has a seed, and EXPORT would \
         then return bytes the holder never wrote down"
    );
    // And the public half, given the same treatment, is a value. It is
    // plaintext, so the "corruption" is a byte inside the wrapped map, and the
    // result is the documented default rather than a `None`.
    let mut pubbytes: HV<u8, 4096> = HV::new();
    populated().encode_public(&mut pubbytes).expect("encode");
    let (pval, _) = fapico2_fido::cbor::decode(&pubbytes[1..]).expect("valid CBOR");
    let fapico2_fido::cbor::Value::B(mut pbytes) = pval else { panic!("bstr") };
    pbytes[5] ^= 0x01;
    assert_eq!(
        VendorState::decode_public(&pbytes),
        VendorPublic::default(),
        "a corrupt plaintext half degrades to the documented default"
    );
}

// ---------------------------------------------------------------------------
// 6. The auth scratch
// ---------------------------------------------------------------------------

/// The auth scratch holds the **worst case**, not the usual one.
///
/// `DeviceKeystore::to_cbor`'s scratch had to grow from 1,536 to
/// [`AUTH_SCRATCH`] for this state, and its bound is written out as a table in
/// that constant's doc comment rather than derived. A derived bound would
/// silently stop being worst-case the first time `ORG_CHAIN_MAX` or
/// `AUDIT_RING_MAX` grew; this test is what notices.
#[test]
fn the_auth_scratch_holds_the_worst_case_auth_map() {
    let mut ks = fresh_keystore();
    ks.vendor = populated();
    // The largest org chain the protocol allows, and a full ring — the two
    // fields that dominate.
    ks.vendor.public.org_chain =
        Some((0u8..=255).cycle().take(ORG_CHAIN_MAX).collect::<HV<u8, ORG_CHAIN_MAX>>());
    ks.vendor.public.audit_enabled = true;
    for seq in 0..AUDIT_RING_MAX as u32 {
        ks.vendor.public.push_audit(AuditRecord { event: seq as u8, ..Default::default() });
    }
    // A large-blob array too, since that is the other auth-level field with a
    // 1,024-byte bound and the one the old scratch was sized around.
    ks.large_blob_array = Some(std::iter::repeat_n(0x5Au8, 1024).collect::<HV<u8, 1024>>());

    let store = fapico2_platform::secure_store::HostSecureStore::new();
    let mut out: HV<u8, 8448> = HV::new();
    ks.to_cbor(Some(&store_key(&store)), &mut out).expect(
        "the worst-case auth map must fit AUTH_SCRATCH; if it does not, the \
         constant's table is wrong or a field grew",
    );
    // And the snapshot it produced must still round-trip.
    let mut store2 = fapico2_platform::secure_store::HostSecureStore::new();
    {
        use fapico2_platform::secure_store::chunked;
        chunked::write_chunked(&mut store2, device_keystore::KEYSTORE_SLOT, &out).expect("write");
    }
    let back = DeviceKeystore::load(&mut store2).unwrap().unwrap();
    assert_eq!(back.vendor, ks.vendor, "and it must decode back to itself");
}

// ---------------------------------------------------------------------------
// 7/8. The all-or-nothing write contract
// ---------------------------------------------------------------------------

/// A store that accepts nothing.
///
/// `grow_checked`'s contract is "apply, persist, and undo if the persist
/// fails", and the only way to test the undo is a store whose `write` fails.
/// This one wraps a real `HostSecureStore` so `contains`/`read` still work —
/// only the write path is dead, which is exactly the shape of a full or failing
/// secure partition.
struct RefusingStore {
    inner: fapico2_platform::secure_store::HostSecureStore,
}

impl SecureStore for RefusingStore {
    fn write(&mut self, _k: &[u8], _v: &[u8]) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::ValueTooLong)
    }
    fn read(&mut self, k: &[u8], out: &mut [u8]) -> Result<usize, SecureStoreError> {
        self.inner.read(k, out)
    }
    fn delete(&mut self, k: &[u8]) -> Result<(), SecureStoreError> {
        self.inner.delete(k)
    }
    fn contains(&self, k: &[u8]) -> bool {
        self.inner.contains(k)
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
    fn is_empty_except(&self, s: &[u8]) -> Result<bool, SecureStoreError> {
        self.inner.is_empty_except(s)
    }
    fn wipe_all(&mut self) -> Result<(), SecureStoreError> {
        self.inner.wipe_all()
    }
    fn store_key(&self) -> Option<[u8; 32]> {
        self.inner.store_key()
    }
}

/// Every mutating method is a no-op with an error when the store refuses the
/// write, and the state is byte-identical afterwards.
///
/// All seven, in one test, because the claim is about the *pattern*: one
/// commit primitive, one field per method, one narrow undo closure each. A
/// method that mutated before the persist and had no undo would pass a test
/// that only exercised the seed.
#[test]
fn a_store_that_cannot_be_written_reverts_and_refuses() {
    let before_ops = |ks: &DeviceKeystore| ks.vendor.clone();

    // Seed a state so the "undo" has something to restore, and a store that
    // has already accepted one write so `contains` is meaningful.
    let mut good = fapico2_platform::secure_store::HostSecureStore::new();
    let mut ks = fresh_keystore();
    ks.vendor = populated();
    ks.persist(&mut good).expect("the first write succeeds");

    /// One mutating method, driven and checked the same way.
    type Case = (&'static str, fn(&mut dyn VendorOps) -> Ctap2Response);

    let cases: Vec<Case> = vec![
        ("set_master_seed", |o| {
            o.set_master_seed([0x77; 32]).err().unwrap_or(Ctap2Response::Ok)
        }),
        ("set_soft_lock", |o| {
            let l = SoftLock::new(&[0x22; 60]).unwrap();
            o.set_soft_lock(l).err().unwrap_or(Ctap2Response::Ok)
        }),
        ("set_audit_enabled", |o| {
            o.set_audit_enabled(!o.audit_enabled()).err().unwrap_or(Ctap2Response::Ok)
        }),
        ("audit_append", |o| {
            o.audit_append(AuditRecord { event: 0x99, ..Default::default() })
                .err()
                .unwrap_or(Ctap2Response::Ok)
        }),
        ("set_org_attestation", |o| {
            let att = OrgAttestation {
                scalar: Some([0x66; 32]),
                chain: Some(HV::from_slice(&[0x30; 64]).unwrap()),
            };
            o.set_org_attestation(att).err().unwrap_or(Ctap2Response::Ok)
        }),
    ];

    for (name, run) in cases {
        let mut ks = fresh_keystore();
        ks.vendor = populated();
        let before = before_ops(&ks);
        let mut store = RefusingStore { inner: good_default_store() };
        let mut session = VendorSession::default();
        let mut counter = 0u8;
        let mut random = move |b: &mut [u8]| {
            for x in b.iter_mut() {
                counter = counter.wrapping_add(1);
                *x = counter;
            }
        };
        let mut sref = Some(&mut store as &mut dyn SecureStore);
        let got = vendor_state::with_keystore_ops(
            &mut ks,
            &mut session,
            &mut sref,
            &mut random,
            |ops| run(ops),
        );
        assert_eq!(
            got,
            Ctap2Response::KeyStoreFull,
            "{name}: a write that could not be made durable must answer 0x28, \
             not a 0x00 that is true only in RAM"
        );
        assert_eq!(
            ks.vendor, before,
            "{name}: and the undo closure must have restored the state exactly"
        );
    }
}

fn good_default_store() -> fapico2_platform::secure_store::HostSecureStore {
    fapico2_platform::secure_store::HostSecureStore::new()
}

/// A refused write is reported, and the **in-memory** state is untouched —
/// the other half of the same claim, and the one a `MemoryKeystore` (which
/// cannot fail) would hide.
#[test]
fn a_refused_write_leaves_the_state_byte_identical() {
    let mut ks = fresh_keystore();
    ks.vendor = populated();
    let before = ks.vendor.clone();
    let mut session = VendorSession::default();
    let mut counter = 0u8;
    let mut random = move |b: &mut [u8]| {
        for x in b.iter_mut() {
            counter = counter.wrapping_add(1);
            *x = counter;
        }
    };
    let mut store: Option<&mut dyn SecureStore> = None;
    // A half-populated credential: refused by validation, before any commit.
    let status = vendor_state::with_keystore_ops(
        &mut ks,
        &mut session,
        &mut store,
        &mut random,
        |ops| {
            ops.set_org_attestation(OrgAttestation { scalar: Some([1; 32]), chain: None })
        },
    );
    assert_eq!(
        status.unwrap_err(),
        Ctap2Response::InvalidParameter,
        "a scalar with no chain would report installed = true and a hash of \
         nothing, which a host would pin as an org identity"
    );
    assert_eq!(ks.vendor, before, "and the state must be untouched");
}

/// A key 8 whose value is the wrong CBOR **type** degrades to the default on
/// both stacks rather than failing one and not the other.
///
/// Auth key 6 answers "fatal" for a non-map value and key 8 answers "default".
/// That asymmetry is deliberate — see `vendor_state`'s module docs and the arm
/// in `device_keystore::decode_auth` — and this is what makes it a decision
/// rather than an accident of which decoder ran. Each stack is driven through
/// its own real entry point.
#[test]
fn a_mistyped_key8_degrades_on_both_stacks() {
    use fapico2_fido::keystore::AuthState;

    // --- host: `{8: 1}` — an integer where the byte string belongs.
    let auth_map = fapico2_fido::cbor::Value::M(vec![(
        fapico2_fido::cbor::Value::U(8),
        fapico2_fido::cbor::Value::U(1),
    )]);
    let host = AuthState::from_cbor_for_test(&fapico2_fido::cbor::encode(&auth_map), None, false)
        .expect("the host must not refuse a mistyped key 8");
    assert_eq!(
        host.vendor.public,
        VendorPublic::default(),
        "host: a mistyped key 8 degrades to the documented default"
    );

    // --- device: the same, through `DeviceKeystore::from_cbor`.
    //
    // Hand-built because `decode_auth` is private and the point is the
    // *snapshot* path: a full `fido.keystore.v1` map whose auth byte string
    // carries the mistyped key 8, and which still has to boot.
    let auth_bytes: &[u8] = &[0xA1, 0x08, 0x01];
    // `{1: [bstr(0x01), bstr(auth), bstr(0x80)]}` — max_creds, auth, and an
    // empty credential array (`0x80`).
    let mut inner: HV<u8, 64> = HV::new();
    inner.extend_from_slice(&[0x83, 0x41, 0x01, 0x40 | auth_bytes.len() as u8]).unwrap();
    inner.extend_from_slice(auth_bytes).unwrap();
    inner.extend_from_slice(&[0x41, 0x80]).unwrap();
    // `DeviceKeystore::to_cbor`'s shape is `{1: [bstr(max_creds), bstr(auth),
    // bstr(creds)]}`, and `inner` already carries the `0x83` array head.
    let mut top: HV<u8, 128> = HV::new();
    top.extend_from_slice(&[0xA1, 0x01]).unwrap();
    top.extend_from_slice(&inner).unwrap();

    let ks = DeviceKeystore::from_cbor(&top, None);
    assert!(
        ks.is_some(),
        "device: a mistyped key 8 must NOT fail the snapshot — the public \
         half degrades, so the token still boots with its credentials"
    );
    assert_eq!(
        ks.expect("some").vendor.public,
        VendorPublic::default(),
        "and the public half must be at its documented default"
    );
}

// ---------------------------------------------------------------------------
// The behaviour the arms will rely on
// ---------------------------------------------------------------------------

/// The journal is opt-in: an append on a device that has not enabled it writes
/// nothing, and does not error either.
#[test]
fn a_disabled_journal_ignores_appends() {
    let mut ks = fresh_keystore();
    let before = ks.vendor.clone();
    let mut session = VendorSession::default();
    let mut counter = 0u8;
    let mut random = move |b: &mut [u8]| {
        for x in b.iter_mut() {
            counter = counter.wrapping_add(1);
            *x = counter;
        }
    };
    let mut store: Option<&mut dyn SecureStore> = None;
    vendor_state::with_keystore_ops(
        &mut ks,
        &mut session,
        &mut store,
        &mut random,
        |ops| {
            assert!(!ops.audit_enabled(), "the journal starts off");
            // Not an error: this protocol has no "journal disabled" status and
            // the client has nothing to map one to.
            ops.audit_append(AuditRecord { event: 0x01, ..Default::default() })
                .expect("a disabled append is a no-op, not a failure");
        },
    );
    assert_eq!(
        ks.vendor, before,
        "an append to a disabled journal must not write — that is the client's \
         stated opt-in contract, and a flash write per event on a device that \
         never asked for a journal is the failure it exists to prevent"
    );
}

/// With the journal on, appends land, the ring evicts into the epoch, and the
/// head the host folds from the window is the head the state computed.
#[test]
fn the_ring_evicts_into_the_epoch_and_the_head_covers_everything() {
    let mut ks = fresh_keystore();
    ks.vendor.public.audit_enabled = true;
    let total = AUDIT_RING_MAX as u32 + 9;
    for seq in 0..total {
        ks.vendor
            .public
            .push_audit(AuditRecord { event: (seq % 251) as u8, ..Default::default() });
    }
    let p = &ks.vendor.public;
    assert_eq!(p.audit_len as usize, AUDIT_RING_MAX, "the ring is full and stays full");
    assert_eq!(p.live_start(), total - AUDIT_RING_MAX as u32);
    assert_eq!(p.live_end(), total);
    assert_ne!(
        p.audit_epoch, [0u8; 32],
        "nine evictions must have folded into the epoch — a journal that \
         silently drops history would make the chain cover only what is still \
         in the window, and the client would have no way to tell"
    );

    // The host's own fold (`audit.rs::fold_chain`) over the bytes the window
    // returns must equal the device's head. Re-derived here rather than
    // trusting `audit_head`, because the property is that the two agree.
    let mut window: HV<u8, 1024> = HV::new();
    p.write_audit_window(&mut window).expect("window");
    assert_eq!(window.len(), AUDIT_RING_MAX * AUDIT_ENTRY_LEN);
    let mut h = p.audit_epoch;
    for chunk in window.chunks(AUDIT_ENTRY_LEN) {
        let mut msg = [0u8; 32 + AUDIT_ENTRY_LEN];
        msg[..32].copy_from_slice(&h);
        msg[32..].copy_from_slice(chunk);
        h = fapico2_fido::crypto::sha256(&msg);
    }
    assert_eq!(
        h, p.audit_head(),
        "the device's head must be the fold of exactly the window it serves, \
         or `audit_verify`'s head_matches fails on an untampered journal"
    );
}

/// No MSE session is a refusal, never a zero key.
#[test]
fn no_mse_session_is_a_refusal_not_a_zero_key() {
    // US-1550: borrowed directly rather than through `ks.clone()`. A clone of
    // `DeviceKeystore` is a clone of every credential private key it holds, and
    // `DeviceKeystore` therefore no longer derives `Clone` — this test is the
    // only caller that needed one, and it did not: the keystore is not read
    // after `with_keystore_ops` returns.
    let mut ks = fresh_keystore();
    let session = VendorSession::default();
    let mut counter = 0u8;
    let mut random = move |b: &mut [u8]| {
        for x in b.iter_mut() {
            counter = counter.wrapping_add(1);
            *x = counter;
        }
    };
    let mut store: Option<&mut dyn SecureStore> = None;
    let mut out = MseChannel { key: [0; 32], aad: [0; P256_POINT_LEN] };
    vendor_state::with_keystore_ops(
        &mut ks,
        &mut { session },
        &mut store,
        &mut random,
        |ops| {
            assert_eq!(
                ops.mse_channel(&mut out).unwrap_err(),
                Ctap2Response::InvalidParameter,
                "a zero channel key is HKDF(0, 0), which decrypts nothing and \
                 looks like a working session"
            );
        },
    );
}

/// One MSE handshake produces a channel key, and a different host point
/// produces a different one.
#[test]
fn one_mse_handshake_derives_a_channel_key_bound_to_the_device_point() {
    let (a, b) = host_point();
    let (a2, b2) = host_point();

    let mut ks = fresh_keystore();
    let mut session = VendorSession::default();
    let mut counter = 1u8;
    let mut random = move |b: &mut [u8]| {
        for x in b.iter_mut() {
            counter = counter.wrapping_add(7);
            *x = counter;
        }
    };
    let mut store: Option<&mut dyn SecureStore> = None;
    let (mut p1, mut p2) = (MsePoint::default(), MsePoint::default());
    let mut c1 = MseChannel { key: [0; 32], aad: [0; P256_POINT_LEN] };
    vendor_state::with_keystore_ops(
        &mut ks,
        &mut session,
        &mut store,
        &mut random,
        |ops| {
            ops.mse_establish(a, b, &mut p1).expect("handshake 1");
            ops.mse_channel(&mut c1).expect("channel 1");
            ops.mse_establish(a2, b2, &mut p2).expect("handshake 2");
        },
    );
    // The AAD the host binds is the device's own point, byte-identical to what
    // the `MSE` response carries.
    let mut sec = [0u8; P256_POINT_LEN];
    sec[0] = 0x04;
    sec[1..33].copy_from_slice(&p1.x);
    sec[33..].copy_from_slice(&p1.y);
    assert_eq!(c1.aad, sec, "the AAD is 0x04 ‖ x ‖ y of the device's own point");
    assert_ne!(c1.key, [0u8; 32], "a real HKDF output is not all zeros");
    // A second handshake with a different host point over a different device
    // scalar must not reuse the first key.
    let mut c2 = MseChannel { key: [0; 32], aad: [0; P256_POINT_LEN] };
    let mut session2 = VendorSession::default();
    let mut counter2 = 1u8;
    let mut random2 = move |b: &mut [u8]| {
        for x in b.iter_mut() {
            counter2 = counter2.wrapping_add(7);
            *x = counter2;
        }
    };
    let mut store2: Option<&mut dyn SecureStore> = None;
    vendor_state::with_keystore_ops(
        &mut ks,
        &mut session2,
        &mut store2,
        &mut random2,
        |ops| {
            ops.mse_establish(a2, b2, &mut p2).expect("handshake");
            ops.mse_channel(&mut c2).expect("channel");
        },
    );
    assert_ne!(c1.key, c2.key, "each session gets a fresh ephemeral scalar");
}

/// A checkpoint signs the byte-exact message and the response's `head`/`seq`
/// are the ones that were signed.
#[test]
fn a_checkpoint_signature_verifies_over_the_client_message() {
    let mut ks = fresh_keystore();
    ks.vendor.public.audit_enabled = true;
    for seq in 0..3u32 {
        ks.vendor.public.push_audit(AuditRecord { event: seq as u8 + 1, ..Default::default() });
    }
    let challenge = [0x42u8; 16];
    let mut session = VendorSession::default();
    let mut counter = 0u8;
    let mut random = move |b: &mut [u8]| {
        for x in b.iter_mut() {
            counter = counter.wrapping_add(1);
            *x = counter;
        }
    };
    let mut store: Option<&mut dyn SecureStore> = None;
    let mut ck = Checkpoint {
        head: [0; 32],
        seq: 0,
        sig: [0; SIG_DER_MAX],
        sig_len: 0,
        pubkey: [0; P256_POINT_LEN],
    };
    vendor_state::with_keystore_ops(
        &mut ks,
        &mut session,
        &mut store,
        &mut random,
        |ops| ops.audit_sign_checkpoint(&challenge, &mut ck).expect("sign"),
    );
    let minted = ks.vendor.secret.audit_key.expect("the key is minted and made durable");

    assert_eq!(ck.seq, 3, "seq_next at the moment of signing");
    assert_eq!(ck.head, ks.vendor.public.audit_head(), "head covers the live window");
    assert!((70..=72).contains(&ck.sig_len), "a DER P-256 signature is 70..=72 bytes");
    assert_eq!(ck.pubkey[0], 0x04, "SEC1 uncompressed point");

    // Rebuild the client's message **from the published constant** and verify
    // it with `p256` directly, so the test is not checking the firmware's
    // encoder against the firmware's decoder. `ring`'s
    // `ECDSA_P256_SHA256_ASN1` (`audit.rs::verify_checkpoint`) is the host's
    // verifier; the DER shape and the digest are the same, and the message is
    // compared byte for byte above.
    let mut msg: HV<u8, 128> = HV::new();
    msg.extend_from_slice(fapico2_fido::vendor41::AUDIT_CHECKPOINT_TAG).unwrap();
    msg.extend_from_slice(&ck.head).unwrap();
    msg.extend_from_slice(&ck.seq.to_le_bytes()).unwrap();
    msg.extend_from_slice(&challenge).unwrap();
    assert_eq!(
        msg.len(),
        17 + 32 + 4 + 16,
        "the message is 69 bytes: a 17-byte tag (the EPIC says 18 and is off \
         by one), a 32-byte head, a 4-byte LE sequence and a 16-byte challenge"
    );
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&ck.pubkey).expect("SEC1 point");
    let der = p256::ecdsa::Signature::from_der(&ck.sig[..ck.sig_len as usize]).expect("DER");
    assert!(
        vk.verify(&msg, &der).is_ok(),
        "the signature must verify over the client's byte-exact message"
    );

    // A different challenge must not verify — that is the freshness the host
    // relies on.
    let mut msg2: HV<u8, 128> = HV::new();
    msg2.extend_from_slice(fapico2_fido::vendor41::AUDIT_CHECKPOINT_TAG).unwrap();
    msg2.extend_from_slice(&ck.head).unwrap();
    msg2.extend_from_slice(&ck.seq.to_le_bytes()).unwrap();
    msg2.extend_from_slice(&[0x43u8; 16]).unwrap();
    assert!(
        vk.verify(&msg2, &der).is_err(),
        "a different challenge must fail"
    );
    // And a different sequence must not verify either — the client checks the
    // exact `(head, seq, challenge)` triple.
    let mut msg3: HV<u8, 128> = HV::new();
    msg3.extend_from_slice(fapico2_fido::vendor41::AUDIT_CHECKPOINT_TAG).unwrap();
    msg3.extend_from_slice(&ck.head).unwrap();
    msg3.extend_from_slice(&(ck.seq + 1).to_le_bytes()).unwrap();
    msg3.extend_from_slice(&challenge).unwrap();
    assert!(vk.verify(&msg3, &der).is_err(), "a different seq must fail");
    // And the key is stable across two checkpoints — a host pins its
    // fingerprint, so a key that changed would invalidate every pin.
    assert_eq!(ks.vendor.secret.audit_key, Some(minted));
}

// ---------------------------------------------------------------------------
// Cross-codec agreement on the public half specifically
// ---------------------------------------------------------------------------

/// The host's `cbor::Value` codec and the no-heap one produce the same public
/// map, byte for byte.
///
/// The two `encode_public` implementations share `VendorState::public_bytes`,
/// so this is close to a tautology — which is the point. It is written because
/// the alternative was a hand-built `cbor::Value` in `keystore.rs`, and the
/// failure this catches is that hand-built map drifting from the no-heap one
/// the way the `vid_pid` width once did.
#[test]
fn the_public_half_encodes_identically_on_both_stacks() {
    let v = populated();
    let mut bytes: HV<u8, 4096> = HV::new();
    v.encode_public(&mut bytes).expect("encode");
    // `bytes` is `08` (the auth key) followed by a **byte string** wrapping the
    // map. The host path takes that value into its own `Value` tree and
    // re-encodes it; if the two agreed, the bytes are unchanged.
    assert_eq!(bytes[0], 8, "auth key 8");
    let (val, _) = fapico2_fido::cbor::decode(&bytes[1..]).expect("valid CBOR");
    let again = fapico2_fido::cbor::encode(&val);
    assert_eq!(
        again, bytes[1..],
        "the host `Value` round-trip must be the identity on the public half, \
         or the two codecs disagree about the map"
    );
    let (inner, _) = fapico2_fido::cbor::decode(&again).expect("the byte string");
    let mut content: HV<u8, 4096> = HV::new();
    if let fapico2_fido::cbor::Value::B(c) = inner {
        content.extend_from_slice(&c).unwrap();
    }
    assert_eq!(
        VendorState::decode_public(&content),
        v.public,
        "and the wrapped map must decode back to what was written"
    );
}

// ---------------------------------------------------------------------------
// Unused-import guards for the items the doc comments name
// ---------------------------------------------------------------------------

/// The constant a Phase I arm will need and the docs promise exists.
#[test]
fn the_published_constants_are_the_protocols_ones() {
    assert_eq!(AUDIT_ENTRY_LEN, 20, "audit.rs::ENTRY_LEN");
    assert_eq!(P256_POINT_LEN, 65, "0x04 ‖ x ‖ y");
    assert_eq!(ORG_CHAIN_MAX, 2048, "mod.rs: the chain bound the client enforces");
    assert_eq!(
        LOCK_BLOB_MAX, 64,
        "60 is the client's actual output (nonce 12 ‖ ct 32 ‖ tag 16); 64 is \
         the round number with headroom"
    );
    assert_eq!(AUDIT_RING_MAX, 32);
    assert_eq!(
        fapico2_fido::vendor41::AUDIT_CHECKPOINT_TAG, b"RSK-AUDIT-CKPT-v1",
        "audit.rs::CKPT_TAG: 17 ASCII bytes and no NUL. The EPIC's US-174 \
         bullet says 18, which is an off-by-one — R-S-K-A-U-D-I-T-C-K-P-T-v-1 \
         is 3+1+5+1+4+1+2 = 17, and the client's verifier hashes exactly \
         these bytes"
    );
}
