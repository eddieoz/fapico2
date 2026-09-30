//! SOAK-FINDING-1 TDD (S-731-2) + DARK-BOOT-1: device keystore capacity,
//! durable-ack latch, and chunked-rewrite transient headroom on the
//! **24-entry** device store (US-715 raised the cap 16 → 24 and
//! hardware-verified the boot; 32 dark-boots even post-reclaim).
//!
//! The 24-h soak wedged the FIDO app at round 4: the 7th U2F register pushed
//! the `fido.keystore.v1` snapshot past what the store can durably hold,
//! `persist_if_dirty` failed forever, the dirty flag latched and the
//! US-425/427 durable-before-ack gate answered every CTAPHID command — reads
//! included — with ERROR/INVALID_COMMAND.
//!
//! US-714 (POLISH-PUB) made U2F registrations STATELESS (C parity — a U2F
//! register no longer writes the store at all; see
//! `stateless_keyhandle.rs`), so the growth driver in these capacity tests
//! is now CTAP2 makeCredential (rk) — the mutation that actually grows the
//! chunked snapshot. The U2F AUTHENTICATE driver exercises the store-backed
//! legacy path's transactional counter bump.
//!
//! Platform mechanics under test here (on the 24-entry store — the 32-entry
//! variant was hardware-rejected twice: DARK-BOOT-1 pre-reclaim, and again
//! post-reclaim in US-715 — the bss→MSPLIM stack distance scales with the
//! entry count, so the cap is hardware-pinned at 24):
//!
//! * the `Rp2350SecureStore` entry cap (16) under the chunked rewrite's
//!   **transient old+new generation**: EVERY durable rewrite (counter bumps
//!   included — they rewrite the snapshot) transiently needs
//!   `other_slots + old_parts + new_parts ≤ 16`; a growth mutation that
//!   cannot meet that bound is rejected cleanly;
//! * the self-cleaning `write_chunked` (a failed rewrite removes its own
//!   parts — no orphans, the store stays usable) plus the transactional
//!   mutations (`store_credential_checked` / `grow_checked` /
//!   `bump_credential_counter_checked`): no latched dirty state, reads
//!   unmasked, the durable counter never regresses.

use fapico2_fido::FidoApp;
use fapico2_fido::device_keystore::COUNTER_PERSIST_INTERVAL;
use fapico2_platform::dispatch::App as _;
use fapico2_platform::secure_store::chunked;
use fapico2_platform::secure_store::rp2350::Rp2350SecureStore;
use fapico2_platform::secure_store::SecureStore;
use fapico2_platform::trng::HostTrng;

const CTAP2_MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;
const U2F_SW_OK: [u8; 2] = [0x90, 0x00];

/// Soak-board-like store: `fido.hkey` plus `fillers` filler slots standing
/// for the other apps' OATH/OpenPGP/migration occupancy. With 15 fillers
/// (16 other slots) a 4-part keystore rewrite's transient
/// (16 + 4 + 4 = 24) exactly exhausts the 24-entry bound — the widest
/// occupancy at which a counter bump is still durable; an 8th-credential
/// growth mutation (needing a 5th part) cannot be made durable.
fn store_with_fillers(fillers: usize) -> Rp2350SecureStore {
    let mut store = Rp2350SecureStore::new();
    store.write(b"fido.hkey", &[0x11u8; 32]).unwrap();
    for i in 0..fillers {
        let key = format!("other.app.slot.{i}");
        store.write(key.as_bytes(), &[0x22u8; 512]).unwrap();
    }
    store
}

/// Number of physical part slots the `fido.keystore.v1` chunked family
/// currently occupies (both buffers — an orphan from a failed rewrite would
/// show up here).
fn keystore_parts(store: &Rp2350SecureStore) -> usize {
    let mut count = 0;
    for buf in 0..2u8 {
        for index in 0..chunked::MAX_PARTS {
            if let Some((pk, pklen)) = chunked::physical_part_key(b"fido.keystore.v1", buf, index)
            {
                if store.contains(&pk[..pklen]) {
                    count += 1;
                }
            }
        }
    }
    count
}

/// CTAP2 makeCredential (rk) request body: a distinct user handle per call
/// so each registration is a distinct credential (the device derives the
/// credential id from rp_id + user_handle).
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

/// Drive one CTAP2 makeCredential through the device path and the persist
/// gate, exactly as the HID serve loop does. Returns the CTAP2 status byte
/// and whether the gate persisted.
fn mc_and_persist(app: &mut FidoApp, store: &mut Rp2350SecureStore, req: &[u8]) -> (u8, bool) {
    let mut out = heapless::Vec::<u8, CTAP2_MAX_MSG>::new();
    let _ = app.process_ctap2_with_store(0x01, req, [1, 2, 3, 4], &mut out, Some(store));
    let status = out.as_slice()[0];
    let wrote = app.persist_if_dirty(store);
    (status, wrote)
}

/// U2F AUTHENTICATE APDU (P1 = enforce user presence) over a **stored**
/// credential's id: `00 02 03 00 Lc ‖ client(32) ‖ app(32) ‖ kh_len ‖ kh`.
/// `app_param` must equal the credential's rp_id_hash (SHA-256 of the RP ID
/// the credential was registered with).
fn authenticate_apdu(client: u8, app_param: &[u8; 32], kh: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0x02, 0x03, 0x00, (64 + 1 + kh.len()) as u8];
    apdu.extend_from_slice(&[client; 32]);
    apdu.extend_from_slice(app_param);
    apdu.push(kh.len() as u8);
    apdu.extend_from_slice(kh);
    apdu
}

/// Drive one U2F command through the device path and the persist gate,
/// exactly as the HID serve loop does (process, then durable-before-ack).
/// Returns the raw reply payload.
fn u2f_and_persist(
    app: &mut FidoApp,
    store: &mut Rp2350SecureStore,
    apdu: &[u8],
) -> (Vec<u8>, bool) {
    let mut out = heapless::Vec::<u8, CTAP2_MAX_MSG>::new();
    let n = app.process_u2f_with_store(apdu, &mut out, Some(store));
    let reply = out.as_slice()[..n].to_vec();
    let wrote = app.persist_if_dirty(store);
    (reply, wrote)
}

fn sw(reply: &[u8]) -> [u8; 2] {
    [reply[reply.len() - 2], reply[reply.len() - 1]]
}

/// HEADLINE (review round 2, adapted to the 24-entry store and to US-714):
/// at a soak-board-like occupancy the signature-counter bump of a stored
/// credential's authenticate rewrites the keystore snapshot, whose transient
/// `other_slots + old_parts + new_parts` must fit 24 entries — and it does,
/// exactly (16 + 4 + 4). The authenticate SUCCEEDS durably, a growth
/// mutation that cannot meet its (strictly larger) transient rejects
/// cleanly with no latch, no orphans, and a normal getInfo afterwards, and
/// the store stays fully usable. On the pre-fix 16-entry store this exact
/// sequence wedged one authentication after the 6th register.
#[test]
fn authenticate_counter_bump_stays_durable_at_soak_occupancy() {
    let mut trng = HostTrng::new();
    // US-916: boot provisions the attestation identity into 2 extra slots
    // (the 32-byte scalar + 1 chunked cert part), so the filler count
    // compensates to keep the tuned 16-other-slot arithmetic exact.
    let mut store = store_with_fillers(13); // 16 other slots
    let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();

    // Registrations 1–7 (CTAP2 makeCredential rk — US-714 made U2F
    // registrations stateless, so MC is the growth driver), each durable
    // before ack. The 7th is a same-size rewrite (the 6th already grew the
    // keystore to 4 parts), so its transient is 16 others + 4 old parts +
    // 4 new parts = 24/24 — exactly at the bound.
    for user in 0..7u8 {
        let (status, wrote) = mc_and_persist(&mut app, &mut store, &mc_rk_req(user));
        assert_eq!(status, 0x00, "MC rk {user}: must succeed");
        assert!(wrote, "MC rk {user}: the gate must persist before the ack");
    }
    let app_param = fapico2_fido::crypto::sha256(b"example.com");
    let kh: Vec<u8> = app.keystore().credentials[0]
        .credential_id
        .clone()
        .into_iter()
        .collect();
    assert_eq!(app.keystore().cred_count(), 7);
    assert_eq!(keystore_parts(&store), 4, "the 7-credential snapshot is 4 parts");
    assert_eq!(
        store_occupancy(&store),
        16 + 4,
        "steady state: 16 other slots + a 4-part keystore = 20/24"
    );

    // The previously-wedging operation: authenticate (counter bump) at a
    // 4-part keystore. The rewrite's transient is 16 + 4 + 4 = 24/24 — fits.
    //
    // US-1011: the counter's persist is batched, so a single authenticate
    // inside an open window does not rewrite anything. The window is
    // `COUNTER_PERSIST_INTERVAL` bumps wide, and the loop below starts from a
    // **closed** window (the 7th registration's persist closed it), so it
    // drives `0..=INTERVAL` = exactly one full window plus the closing bump —
    // one rewrite, and no second one is reachable inside the loop. Exactly one
    // is therefore the assertable number, and it is the number that pins the
    // batching: `> 0` would also pass if 32 of the 33 rounds had unexpectedly
    // persisted, i.e. if US-1011 had stopped working. At 24/24 the rewrite is
    // the operation that would wedge, and it is the only one attempted.
    let mut persisted = 0usize;
    for round in 0..=COUNTER_PERSIST_INTERVAL as u8 {
        let (reply, wrote) =
            u2f_and_persist(&mut app, &mut store, &authenticate_apdu(round, &app_param, &kh));
        assert_eq!(sw(&reply), U2F_SW_OK, "auth {round}: must succeed");
        persisted += usize::from(wrote);
        assert!(!app.is_dirty(), "auth {round}: no latched dirty state");
    }
    assert_eq!(
        persisted, 1,
        "{} counter bumps from a closed window must cost exactly one rewrite — \
         the window-closing one. The soak wedge this test pins is a rewrite \
         that cannot fit its 24/24 transient, so a run that never rewrites \
         would not have tested anything, and a run that rewrote on every bump \
         is US-1011 failing (and would have wedged 32 times over, not once)",
        COUNTER_PERSIST_INTERVAL as usize + 1
    );

    // A growth mutation that cannot be made durable rejects cleanly: the
    // 8th registration needs a 5th keystore part → transient 16 + 4 + 5 = 25
    // > 24 → CTAP2_ERR_KEY_STORE_FULL (0x28), nothing persisted, no latch,
    // no orphans.
    let (status, wrote) = mc_and_persist(&mut app, &mut store, &mc_rk_req(8));
    assert_eq!(status, 0x28, "8th registration: clean KEY_STORE_FULL reject");
    assert!(!wrote, "overflow: nothing was persisted");
    assert!(!app.is_dirty(), "overflow: no un-persistable dirty state");
    assert_eq!(app.keystore().cred_count(), 7, "no credential leaked in");
    assert_eq!(keystore_parts(&store), 4, "self-cleaning: no orphan parts left");
    assert_eq!(store_occupancy(&store), 20, "store returned to its pre-write occupancy");

    // No read masking: a following getInfo must get a normal reply.
    let mut out = heapless::Vec::<u8, CTAP2_MAX_MSG>::new();
    let n = app.process_ctap2_with_store(0x04, &[], [1, 2, 3, 4], &mut out, Some(&mut store));
    assert!(n > 1);
    assert_eq!(out.as_slice()[0], 0x00, "getInfo after rejection: normal reply");
    assert!(!app.is_dirty(), "getInfo left the gate clean");

    // The store remains fully usable: the counter bump still fits its
    // 24/24 transient after the rejected registration, and consecutive
    // authenticates keep counting monotonically.
    let (reply1, _) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(30, &app_param, &kh));
    assert_eq!(sw(&reply1), U2F_SW_OK, "authenticate at the limit: normal reply");
    assert!(!app.is_dirty(), "authenticate left no latched dirty state");
    let (reply2, _) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(31, &app_param, &kh));
    assert_eq!(sw(&reply2), U2F_SW_OK);
    assert_eq!(
        u32::from_be_bytes([reply2[1], reply2[2], reply2[3], reply2[4]]),
        u32::from_be_bytes([reply1[1], reply1[2], reply1[3], reply1[4]]) + 1,
        "counter bytes advance monotonically after the rejected registration"
    );

    // And the store image still boots with every credential.
    let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let len = store.partition_image(&mut img).unwrap();
    let mut restored = Rp2350SecureStore::new();
    restored.from_partition_image(&img[..len]);
    let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();
    assert_eq!(app2.keystore().cred_count(), 7, "reboot keeps all 7 creds");
}

/// The counter bump itself can hit the occupancy bound: with 19 other
/// slots, a 3-part snapshot's same-size rewrite transient (19 + 3 + 3 = 25,
/// which exceeds 24) cannot be made durable — so the window-closing bump
/// reverts: the reply signs the durable counter, consecutive authenticates
/// return the SAME counter byte-sequence (the durable counter repeats: never
/// regresses), and nothing latches.
#[test]
fn authenticate_counter_bump_reverts_cleanly_at_the_occupancy_limit() {
    let mut trng = HostTrng::new();
    // US-916: boot provisions the attestation identity into 2 extra slots
    // (the 32-byte scalar + 1 chunked cert part), so the filler count
    // compensates to keep the tuned 19-other-slot arithmetic exact.
    let mut store = store_with_fillers(16); // 19 other slots
    let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();

    // Growth to 2 parts (19+1+2=22) and then to 3 parts (19+2+3=24) fit;
    // the 4-credential snapshot is 3 parts. The 5th registration (a
    // same-size 3-part rewrite, transient 19+3+3=25) and the growth to a
    // 4th part (19+3+4=26) both exceed the bound.
    for user in 1..=4u8 {
        let (status, _) = mc_and_persist(&mut app, &mut store, &mc_rk_req(user));
        assert_eq!(status, 0x00, "MC rk {user}: must succeed");
    }
    assert_eq!(keystore_parts(&store), 3);
    let (status5, wrote5) = mc_and_persist(&mut app, &mut store, &mc_rk_req(5));
    assert_eq!(status5, 0x28, "5th registration must be occupancy-rejected");
    assert!(!wrote5);
    assert_eq!(keystore_parts(&store), 3, "no orphan parts");

    let app_param = fapico2_fido::crypto::sha256(b"example.com");
    let kh: Vec<u8> = app.keystore().credentials[0]
        .credential_id
        .clone()
        .into_iter()
        .collect();

    // US-1011: inside an open batch window the counter advances in RAM and
    // nothing is written — that is the point of the window, and it holds at
    // the occupancy limit too, because it never reaches the store. Only the
    // bump that CLOSES the window attempts the rewrite whose transient
    // (19 + 3 + 3 = 25) exceeds the bound; that one reverts, so the counter
    // freezes at its last in-window value and stays there.
    let mut last: Option<[u8; 4]> = None;
    for round in 0..=COUNTER_PERSIST_INTERVAL as u8 {
        let (reply, _wrote) =
            u2f_and_persist(&mut app, &mut store, &authenticate_apdu(round, &app_param, &kh));
        assert_eq!(sw(&reply), U2F_SW_OK, "authenticate at the limit: normal reply");
        assert!(!app.is_dirty(), "the reverted bump leaves the gate clean");
        let c = [reply[1], reply[2], reply[3], reply[4]];
        if let Some(prev) = last {
            let rising = u32::from_be_bytes(c) == u32::from_be_bytes(prev) + 1;
            let frozen = c == prev;
            assert!(
                rising || frozen,
                "counter bytes must advance by one inside the window, or stay \
                 put when the closing rewrite reverts — never anything else \
                 (prev {prev:?}, now {c:?})"
            );
        }
        last = Some(c);
    }
    let (tail1, _) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(90, &app_param, &kh));
    let (tail2, _) = u2f_and_persist(&mut app, &mut store, &authenticate_apdu(91, &app_param, &kh));
    assert_eq!(
        tail1[1..5],
        tail2[1..5],
        "the window is spent and every further bump tries to rewrite: the \
         rewrite cannot be made durable, so the counter freezes at the durable \
         value and repeats (never regresses)"
    );
    assert!(!app.is_dirty(), "no latched dirty state after the reverts");
}

/// Store occupancy (physical entries) from the partition image's count field.
fn store_occupancy(store: &Rp2350SecureStore) -> usize {
    let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    store.partition_image(&mut img).unwrap();
    u32::from_le_bytes([img[4], img[5], img[6], img[7]]) as usize
}

/// CTAP2 makeCredential (rk) at the device credential bound must answer the
/// CTAP2 error KEY_STORE_FULL (0x28 per the CTAP2 spec's error table) —
/// never a success, never the CTAPHID-level INVALID_COMMAND the latch
/// produced.
#[test]
fn mc_rk_overflow_maps_key_store_full() {
    let mut trng = HostTrng::new();
    let mut store = Rp2350SecureStore::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();

    // Fill the keystore to its device bound (12) with resident credentials.
    for user in 0..12u8 {
        let (status, wrote) = mc_and_persist(&mut app, &mut store, &mc_rk_req(user));
        assert_eq!(status, 0x00, "MC rk {user} below capacity succeeds");
        assert!(wrote, "MC rk {user}: gate persists before the ack");
    }

    // The 13th: keystore full → CTAP2_ERR_KEY_STORE_FULL (0x28).
    let (status, _) = mc_and_persist(&mut app, &mut store, &mc_rk_req(0xFF));
    assert_eq!(
        status, 0x28,
        "MC rk overflow must map to CTAP2_ERR_KEY_STORE_FULL (0x28)"
    );
    assert!(!app.is_dirty(), "overflow leaves no dirty state behind");
}

/// Minor 3 (review round 2): the KEY_STORE_FULL mapping must also cover the
/// occupancy-limited overflow — makeCredential with enough other-app slots
/// that the chunked rewrite transient cannot fit — with the same clean
/// no-side-effects contract.
#[test]
fn mc_occupancy_limited_overflow_maps_key_store_full() {
    let mut trng = HostTrng::new();
    let mut store = store_with_fillers(10);
    let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();

    let mut accepted = 0usize;
    for user in 0..12u8 {
        let (status, wrote) = mc_and_persist(&mut app, &mut store, &mc_rk_req(user));
        if status == 0x00 {
            assert!(wrote, "MC rk {user}: must persist");
            accepted += 1;
        } else {
            assert_eq!(
                status, 0x28,
                "MC rk {user}: occupancy overflow must map to KEY_STORE_FULL"
            );
            assert!(!app.is_dirty(), "overflow leaves no dirty state behind");
            break;
        }
    }
    assert!(
        (2..12).contains(&accepted),
        "overflow must be occupancy-limited (accepted {accepted})"
    );
    assert_eq!(app.keystore().cred_count(), accepted, "no credential leaked in");
}

/// Regression: registrations below the occupancy bound keep working —
/// every registration persists durably before its ack and the credentials
/// survive a reboot round-trip. (US-714: U2F registrations are stateless,
/// so the growth driver is CTAP2 makeCredential rk.)
#[test]
fn registrations_below_capacity_persist_and_round_trip() {
    let mut trng = HostTrng::new();
    let mut store = store_with_fillers(8);
    let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();

    for user in 0..4u8 {
        let (status, wrote) = mc_and_persist(&mut app, &mut store, &mc_rk_req(user));
        assert_eq!(status, 0x00);
        assert!(wrote);
    }

    let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let len = store.partition_image(&mut img).unwrap();
    let mut restored = Rp2350SecureStore::new();
    restored.from_partition_image(&img[..len]);
    let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();
    assert_eq!(app2.keystore().cred_count(), 4);
}
