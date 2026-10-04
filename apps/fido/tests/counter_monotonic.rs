//! US-1012 TDD: the FIDO signature counter can never go backwards, and can
//! never repeat, across a power cut.
//!
//! US-1011 made the counter's persistence a batch: N assertions cost
//! `ceil(N / COUNTER_PERSIST_INTERVAL)` whole-image rewrites, and the reply
//! signs a counter that is **not yet durable**. That is only legal because of
//! the property this file pins:
//!
//! > A power cut at *any* point in the batch window, followed by a restore,
//! > leaves the next `signCount` **strictly greater** than any value the
//! > client has already seen.
//!
//! Strictly greater, not greater-or-equal. A repeat is a clone-detection
//! failure (a value that authenticates twice); a regression is worse. Both are
//! tested here by cutting the power at **every** point of the window — before
//! the first assertion of a window, at each of the intermediate points, and at
//! the point where the window's rewrite lands — and asserting on the value the
//! restored device signs next.
//!
//! And the cuts are taken **twice**, from a *restored* session, because that is
//! the only state in which the second half of the mechanism is load-bearing.
//! US-1012's mechanism has two halves which are only safe together: a restore
//! *grants* a whole window of slack above the durable image, and it *spends*
//! that window immediately so the in-RAM counter can never run a second window
//! past the skip. Spending without granting resumes at the durable value;
//! granting without spending lets a restored device run a whole extra window
//! and sign a value the client has already seen. Only the second case is
//! invisible to a single cut from a fresh boot, because a fresh boot is
//! granted slack it never spends — so a test that only ever cuts once proves
//! nothing about the spend. The headline test therefore takes its second cut
//! from a device that was itself restored.
//!
//! The cut is modelled the way a power cut actually works: the durable
//! partition image is all that survives; the in-RAM app is discarded and a new
//! one boots from that image. The assertion that follows the restore is also
//! checked to still **verify** against the credential's public key, because a
//! counter scheme that broke the signature would be no consolation.

use fapico2_fido::FidoApp;
use fapico2_fido::device_keystore::{DeviceCoseKey, DeviceCredential, DeviceKeystore, PrivateScalar};
use fapico2_platform::secure_store::rp2350::Rp2350SecureStore;
use fapico2_platform::trng::HostTrng;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

const CTAP2_MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;
const U2F_SW_OK: [u8; 2] = [0x90, 0x00];
const KEY_HANDLE_LEN: usize = 64;
/// The app parameter the fixture credential is registered under.
const APP_PARAM: [u8; 32] = [0xA0; 32];
/// The fixture credential's private scalar. Its public half is what every
/// post-restore assertion is verified against.
const FIXTURE_SCALAR: [u8; 32] = [0x0B; 32];

fn sw(reply: &[u8]) -> [u8; 2] {
    [reply[reply.len() - 2], reply[reply.len() - 1]]
}

fn reply_counter(reply: &[u8]) -> u32 {
    u32::from_be_bytes([reply[1], reply[2], reply[3], reply[4]])
}

fn register_apdu(client: u8) -> Vec<u8> {
    let mut apdu = vec![0x00, 0x01, 0x00, 0x00, 0x40];
    apdu.extend_from_slice(&[client; 32]);
    apdu.extend_from_slice(&APP_PARAM);
    apdu
}

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

fn fixture_credential(id: &[u8; 32]) -> DeviceCredential {
    let mut cid = heapless::Vec::<u8, 64>::new();
    cid.extend_from_slice(id).unwrap();
    DeviceCredential {
        credential_id: cid,
        public_key: DeviceCoseKey::es256([1; 32], [2; 32]),
        private_key: PrivateScalar::from_bytes(FIXTURE_SCALAR),
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
    }
}

fn u2f_and_persist(app: &mut FidoApp, store: &mut Rp2350SecureStore, apdu: &[u8]) -> Vec<u8> {
    let mut out = heapless::Vec::<u8, CTAP2_MAX_MSG>::new();
    let n = app.process_u2f_with_store(apdu, &mut out, Some(store));
    let reply = out.as_slice()[..n].to_vec();
    let _ = app.persist_if_dirty(store);
    reply
}

fn authenticate(app: &mut FidoApp, store: &mut Rp2350SecureStore, kh: &[u8], client: u8) -> Vec<u8> {
    let reply = u2f_and_persist(app, store, &authenticate_apdu(client, kh));
    assert_eq!(sw(&reply), U2F_SW_OK, "U2F authenticate must succeed");
    reply
}

/// The device's public key for the fixture credential.
fn fixture_verifying_key() -> VerifyingKey {
    let sk = p256::SecretKey::from_slice(&FIXTURE_SCALAR).unwrap();
    let sec1 = fapico2_fido::crypto::public_key_bytes(&sk.public_key());
    VerifyingKey::from_sec1_bytes(&sec1).expect("fixture key is on the curve")
}

/// Check the ES256 signature an AUTHENTICATE reply carries, over
/// `app_param ‖ user_presence ‖ counter ‖ client_param` — the U2F sign base.
fn assert_assertion_verifies(reply: &[u8], client: u8) {
    let counter = reply_counter(reply);
    let sig = Signature::from_der(&reply[5..reply.len() - 2]).expect("DER signature");
    let mut sign_base = Vec::new();
    sign_base.extend_from_slice(&APP_PARAM);
    sign_base.push(0x01);
    sign_base.extend_from_slice(&counter.to_be_bytes());
    sign_base.extend_from_slice(&[client; 32]);
    fixture_verifying_key()
        .verify(&sign_base, &sig)
        .expect("the post-restore assertion must still verify against the credential's key");
}

/// Everything a power cut leaves behind: the durable partition image.
fn cut(store: &Rp2350SecureStore) -> Rp2350SecureStore {
    let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let len = store.partition_image(&mut img).unwrap();
    let mut restored = Rp2350SecureStore::new();
    restored.from_partition_image(&img[..len]);
    restored
}

// ---------------------------------------------------------------------------
// The property
// ---------------------------------------------------------------------------

/// HEADLINE (US-1012): cut the power at **every** point of the batch window —
/// `k` in `0 ..= COUNTER_PERSIST_INTERVAL`, which includes the point where the
/// window's own rewrite lands — and the next `signCount` the restored device
/// signs is **strictly greater** than the highest value seen before the cut.
///
/// The window length is the same constant US-1011 chose, so this test is
/// exhaustive over the window rather than sampling it: if the restore slack
/// were one short, or the rewrite fired one bump late, the `k` that sits in
/// that gap would sign a value at or below the one already seen.
///
/// ## Two cuts, not one — and the second one is the load-bearing one
///
/// The first cut above is taken from a **freshly booted** device
/// (`Rp2350SecureStore::new()`), so its restore is granted a window of slack
/// that it never spends. That makes the first cut blind to half the
/// mechanism: drop the *spend* half — leave the window open on a restore —
/// and every first cut still passes, because an un-spent window only starts
/// letting the counter run ahead on the **second** restore, when the durable
/// image the first session's slack bought is the one being read back.
///
/// So the test takes the power away again, from the restored device, and
/// requires the same property across that cut too. `after_3 > seen_2` is the
/// assertion that fails when the slack is granted but not spent; the numbers
/// in the mutation demo in the report come from exactly this shape.
#[test]
fn sign_count_is_strictly_greater_after_a_cut_at_every_point_in_the_window() {
    // Pinned here for the same reason it is pinned in `counter_batching.rs`:
    // the number is a reasoned choice, not a measured one (US-1011, no board).
    const PINNED_INTERVAL: u16 = 32;
    /// Assertions the **restored** session runs before the second cut. One is
    /// the window-closing write US-1012 hands it for free; the rest ride in
    /// the window that write opens, so the second cut lands mid-window —
    /// which is the state only a restored device can be in.
    const RESTORED_SESSION_ASSERTS: usize = 10;

    for k in 0..=PINNED_INTERVAL as usize {
        let mut trng = HostTrng::new();
        let kh = [0x5Au8; 32];
        // The whole pre-cut life of the device lives in this block: when it
        // ends, the in-RAM app is gone and only `restored` (the durable
        // partition image) survives — which is what a power cut is.
        let (seen, restored) = {
            let mut store = Rp2350SecureStore::new();
            let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();
            let _ = app.persist_if_dirty(&mut store);

            app.keystore()
                .store_credential(fixture_credential(&kh))
                .unwrap();
            assert!(
                app.persist_if_dirty(&mut store),
                "the fixture credential must be durable before the window opens"
            );

            // The client observes this many signatures, then the power goes.
            let mut seen = 0u32;
            for i in 0..k {
                let reply = authenticate(&mut app, &mut store, &kh, i as u8);
                seen = reply_counter(&reply);
                assert_assertion_verifies(&reply, i as u8);
            }
            (seen, cut(&store))
        };
        let mut restored = restored;
        let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();

        // CUT 1 -> restore. The first assertion after the restore.
        let reply = authenticate(&mut app2, &mut restored, &kh, 0xEE);
        let after_2 = reply_counter(&reply);
        assert!(
            after_2 > seen,
            "cut after {k} un-persisted assertion(s): the restored device \
             signed signCount {after_2}, which is not strictly greater than the \
             value the client had already seen ({seen}) — a repeat is a \
             clone-detection failure and a regression is worse"
        );
        assert_assertion_verifies(&reply, 0xEE);

        // The restored session keeps signing, then loses power again. This is
        // the cut a fresh-boot-only test never takes.
        let mut seen_2 = after_2;
        for i in 1..RESTORED_SESSION_ASSERTS {
            seen_2 = reply_counter(&authenticate(
                &mut app2,
                &mut restored,
                &kh,
                0xE0 + i as u8,
            ));
        }
        let mut restored2 = cut(&restored);

        // CUT 2 -> restore, from a device that was itself restored.
        let mut app3 = FidoApp::boot(&mut trng, &mut restored2).unwrap();
        let reply = authenticate(&mut app3, &mut restored2, &kh, 0xEF);
        let after_3 = reply_counter(&reply);
        assert!(
            after_3 > seen_2,
            "second cut, taken from a device restored after {k} \
             un-persisted assertion(s): the twice-restored device signed \
             signCount {after_3}, which is not strictly greater than the \
             {seen_2} the restored session had already signed — the restore \
             grants a window of slack it must also SPEND, and a window granted \
             but left open lets the counter run a whole extra window past the \
             skip and sign a value the client has already seen"
        );
        assert_assertion_verifies(&reply, 0xEF);
    }
}

/// The same property for the keystore-wide counter that **stateless** U2F
/// credentials sign against (US-714's `ef_counter` parity). US-1011 batches
/// it on the same window, so US-1012's slack has to cover it too — otherwise
/// the CTAP1 path would be the one place the counter can go backwards.
#[test]
fn the_global_stateless_counter_is_also_strictly_monotonic_across_a_cut() {
    const PINNED_INTERVAL: u16 = 32;

    for k in 0..=PINNED_INTERVAL as usize {
        let mut trng = HostTrng::new();
        let (kh, seen, restored) = {
            let mut store = Rp2350SecureStore::new();
            let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();
            let _ = app.persist_if_dirty(&mut store);

            let reg = u2f_and_persist(&mut app, &mut store, &register_apdu(0x42));
            assert_eq!(reg[0], 0x05, "U2F register must succeed");
            let kh = key_handle_of(&reg);
            assert_eq!(kh.len(), KEY_HANDLE_LEN);

            let mut seen = 0u32;
            for i in 0..k {
                seen = reply_counter(&authenticate(&mut app, &mut store, &kh, i as u8));
            }
            (kh, seen, cut(&store))
        };
        let mut restored = restored;
        let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();

        let after = reply_counter(&authenticate(&mut app2, &mut restored, &kh, 0xEE));
        assert!(
            after > seen,
            "stateless cut after {k}: the restored global counter signed \
             {after}, not strictly greater than the value already seen"
        );
    }
}

/// The **Rescue applet's whole-keystore write** does not break monotonicity.
///
/// `DeviceRescueConfigHandler::commit` (`firmware/src/boot.rs:740`) does
/// `DeviceKeystore::load(store)` → mutate `ks.phy` → `ks.persist(store)`. Under
/// US-1012 that `load` is a **restore**, so it hands itself a whole window of
/// slack above the durable image, and the `persist` writes that slack down:
/// a Rescue WRITE advances the durable per-credential counters by a full
/// window. Meanwhile the FIDO app's own `counter_unpersisted` is *not* reset,
/// so the app's window accounting and the store's durable state genuinely
/// diverge, and `FidoApp::sync_phy` (`device_app.rs:481`, called from
/// `firmware/src/tasks.rs:583`) reconciles only `phy`, not the counters.
///
/// The divergence is safe **because it is forward-only**: a Rescue write only
/// ever moves the durable image forward, so the next restore is still above
/// everything any client has seen. This test runs the commit sequence over
/// **every** offset in the batch window and pins that, so a future placement of
/// `note_durable_write()` in (or out of) the commit path fails here rather than
/// silently on a device.
///
/// **What this does NOT cover.** The full on-device sequence cannot be
/// exercised from a host test: the `RESCUE_PHY_GENERATION` handshake
/// (`boot.rs:795`) and the HID catch-up that follows it live in the firmware
/// task loop and have no host harness. What is replicated here is exactly the
/// **store effect** of `commit` — the load, the `phy` mutation and the
/// `persist` — against the real [`Rp2350SecureStore`], which is the part that
/// touches the counter. The generation handshake is plumbing that cannot move
/// a counter by itself; what it could do is skip the catch-up, and the
/// catch-up is `phy`-only by construction.
#[test]
fn a_rescue_whole_keystore_write_stays_forward_only_across_a_cut() {
    const PINNED_INTERVAL: u16 = 32;

    for j in 0..=PINNED_INTERVAL as usize {
        let mut trng = HostTrng::new();
        let kh = [0x5Au8; 32];
        let (seen, restored) = {
            let mut store = Rp2350SecureStore::new();
            let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();
            let _ = app.persist_if_dirty(&mut store);
            app.keystore()
                .store_credential(fixture_credential(&kh))
                .unwrap();
            assert!(app.persist_if_dirty(&mut store));

            let mut seen = 0u32;
            for i in 0..j {
                seen = reply_counter(&authenticate(&mut app, &mut store, &kh, i as u8));
            }

            // --- `DeviceRescueConfigHandler::commit`, store effect only ---
            // The same three steps `firmware/src/boot.rs:740` performs, on the
            // real store. The `phy` mutation is the one field this test
            // changes; what matters is that the `load` is a restore and the
            // `persist` writes what it produced.
            let Some(mut ks) = DeviceKeystore::load(&mut store).expect("a durable snapshot") else {
                panic!("a durable snapshot must exist: boot persisted one");
            };
            ks.phy.vid_pid = Some(fapico2_fido::vendorff::pack_vidpid(0x1209, 0x0001));
            ks.persist(&mut store)
                .expect("the Rescue write is durable-before-ack; a failure is 0x6F00");

            (seen, cut(&store))
        };

        let mut restored = restored;
        let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();
        let after = reply_counter(&authenticate(&mut app2, &mut restored, &kh, 0xEE));
        assert!(
            after > seen,
            "a Rescue WRITE taken {j} assertion(s) into the batch window \
             advanced the durable counter by a whole window, and the restore \
             after it signed signCount {after}, which is not strictly greater \
             than the {seen} the client had already seen — the commit path is \
             supposed to be forward-only"
        );
        assert_assertion_verifies(&authenticate(&mut app2, &mut restored, &kh, 0xEF), 0xEF);
    }
}

/// The slack is **forward only**: a restore never hands back a value the
/// device has not already skipped past, so the counter a restored device
/// starts from is strictly above its durable image even when the window had
/// not been entered at all (`k = 0` above is that case, pinned directly here
/// so a future edit that "optimises" the fresh-boot case cannot quietly remove
/// the skip).
#[test]
fn a_restore_always_starts_above_the_durable_image() {
    const PINNED_INTERVAL: u16 = 32;

    let mut trng = HostTrng::new();
    let mut store = Rp2350SecureStore::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();
    let _ = app.persist_if_dirty(&mut store);
    let kh = [0x5Au8; 32];
    app.keystore()
        .store_credential(fixture_credential(&kh))
        .unwrap();
    assert!(app.persist_if_dirty(&mut store));

    // No assertion at all before the cut: the durable counter is 0.
    let mut restored = cut(&store);
    let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();
    let after = reply_counter(&authenticate(&mut app2, &mut restored, &kh, 1));
    assert!(
        after > PINNED_INTERVAL as u32,
        "a device that has never asserted signed {after} after a bare \
         restore: the restored counter must sit a whole window above the \
         durable image (0 + {PINNED_INTERVAL}), not at it — signing the \
         durable value again is the repeat clone detection exists to catch"
    );
    assert!(after > 0);
}
