//! US-1562 — `getAssertion` over a **region-backed** device.
//!
//! ```gherkin
//! Scenario: an assertion on a device whose credentials live in the key region
//!   Given a credential enrolled into the key region
//!   When the client asserts
//!   Then the assertion is served (not CTAP2_ERR_NO_CREDENTIALS)
//!   And the signCount it signs is the counter the record now holds
//!   And 31 further assertions erase nothing, and the 32nd costs one live-record-sector erase
//!   And the counter never repeats across a power cut inside the window
//!   And a flash that refuses the durable write rolls the bump back
//!   And the CTAP1 surface, which shares the bump, keeps working
//! ```
//!
//! # The defect this exists for
//!
//! `device_core.rs::build_assertion` resolved the signature counter through
//! `DeviceKeystore::bump_credential_counter_checked`, which looks the
//! credential up in the **snapshot's** resident array. A region-backed
//! credential is not in that array, so the lookup answered `None` and **every**
//! `getAssertion` on a region-backed device was refused with
//! `CTAP2_ERR_NO_CREDENTIALS` (0x2E) — after the credential had been opened and
//! its private key wiped. The device held 856 passkeys and could authenticate
//! with none of them.
//!
//! # Every test here drives the **device** twin
//!
//! `device_app::FidoApp` + `process_ctap2_with_store`, never `app.rs`'s
//! `FidoApp` (`AGENTS.md` §1). The host twin has no key region at all —
//! `region_keys_for` answers `None` there — so a test written against it would
//! take the snapshot path and pass against the code that was broken.
//!
//! # Why the first assertion after a power-on is itself a durable write
//!
//! The erase profile below is stated as "31 assertions erase nothing, the 32nd
//! costs one live-record-sector erase", and that is exactly what is measured —
//! over the batch **after** the restore window has closed, not from the first
//! assertion of a session. On a region-backed device every power-on starts
//! restored (`device_keystore.rs::decode`'s own arm: S8/S9 forbid the boot path
//! from reading the region, so the applet cannot know whether a record has ever
//! been signed, and the safe answer is the one that skips forward). US-1012's
//! **spend** half then makes the first assertion write down. So the shipped
//! sequence is
//!
//! ```text
//! boot ─▶ assertion 1: the durable write (the restore window closes here)
//!       ├▶ assertions 2..32: no erase at all
//!       └▶ assertion 33: the next durable write, one live-record-sector erase
//! ```
//!
//! and the "31 then the 32nd" of `region_counter_batching.rs` is the same
//! profile from a `CounterWindow::fresh()` — a state a unit test can reach and
//! a board cannot. Both are asserted; neither is rounded into the other.
//!
//! # What a "power cut" is here
//!
//! The [`Device`] is **dropped** and a new one booted over the same region file
//! and the same secure store, after the transport's persist gate has run
//! ([`Device::persist`]). Nothing about the medium survives in RAM:
//! `FidoRecordStore` is stateless by design (`fido_store.rs`'s module docs),
//! which is what makes dropping the app as faithful as pulling the plug. The
//! persist gate is part of the simulation and not an afterthought — the snapshot
//! is still where `device_random` lives, and `region_pin_secret` mixes it into
//! the region's payload key, so a reboot without it would be a factory reset
//! rather than a power cut.

mod region_boot;

use fapico2_platform::keyregion::host::Faults;
use fapico2_platform::keyregion::on_demand::CredentialWindow;
use fapico2_platform::keyregion::{Slot, SlotRead, SLOTS_PER_SECTOR};
use region_boot::*;

/// `CTAP2_OK`.
const OK: u8 = 0x00;
/// `CTAP2_ERR_NO_CREDENTIALS` — the answer the defect produced.
const NO_CREDENTIALS: u8 = 0x2E;
/// U2F's `SW_NO_ERROR`.
const SW_NO_ERROR: u8 = 0x00;

/// The batch interval, taken from the code rather than repeated — a literal
/// `31` here would silently become a lie the day the constant moves.
const W: u16 = fapico2_fido::device_keystore::COUNTER_PERSIST_INTERVAL;

/// The relying party every fixture enrols against.
const RP: &str = "example.test";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// SHA-256 through the applet's own `crypto`, so the RP-hash assertions below
/// are not asserting a second derivation.
fn rp_of(s: &str) -> [u8; 32] {
    fapico2_fido::crypto::sha256(s.as_bytes())
}

/// One resident credential for [`RP`], encoded by the applet's own codec.
///
/// [`credential`](region_boot::credential)'s fixture gives every credential its
/// own RP, which is right for an enumeration test and wrong here: the erase
/// profile needs `SLOTS_PER_SECTOR` credentials **sharing one record sector**,
/// and the lowest-free-slot allocator only puts them together if they share an
/// RP (and one index entry per RP). `region_delete_compaction.rs` makes the same
/// override for the same reason.
fn fixture_credential(n: u32) -> DeviceCredential {
    let mut cred = credential(n, true);
    cred.rp_id_hash = rp_of(RP);
    cred
}

/// A PIN-set device whose credentials live in the key region, behind a
/// **counting** region so a test can measure what a command path wrote.
fn region_device(tag: &str) -> (InstalledRegion, Device) {
    let region_file = install_counting(tag);
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    device.set_pin(b"123456");
    // The transport's persist gate. Without it `device_random` is still only in
    // RAM, the payload key is redrawn on the next boot, and every record in the
    // region becomes unreadable — which would read as a region bug.
    assert!(device.persist(), "the PIN write must reach the secure store");
    (region_file, device)
}

/// The applet's own region keys, from the durable snapshot.
fn keys_of(device: &mut Device) -> RegionKeys {
    device.with_store(|store| {
        let ks = fapico2_fido::device_keystore::DeviceKeystore::load(store)
            .expect("a readable snapshot")
            .expect("a snapshot on the store, because the transport's persist gate has run");
        region_keys(store, &ks)
    })
}

/// Register [`fixture_credential`] `n` straight into the region.
///
/// The applet's own codec and its own key derivation, and no clientPIN leg or
/// presence window: the subject of every test here is what happens *after* an
/// enrolment, and paying the makeCredential handshake on every fixture would
/// make each one about the handshake.
fn enrol(region_file: &InstalledRegion, keys: &RegionKeys, n: u32) {
    region_file
        .with_counting(|region| {
            let mut creds = RegionCredentials::new(region, keys);
            creds.put(&nonce(n), &fixture_credential(n)).expect("the fixture must enrol");
        })
        .expect("a counting region is installed");
}

/// The slot fixture `n` occupies, and the counter its **durable** record holds.
///
/// One walk for both, and `durable_counter` rather than `counter_value`: the
/// window is deliberately not consulted, because "what the region holds" and
/// "what the device is holding" are different questions and a test that wants
/// the medium must ask for the medium.
fn record_of(
    region_file: &InstalledRegion,
    keys: &RegionKeys,
    n: u32,
) -> (Slot, u32) {
    let mut out = None;
    region_file
        .with_counting(|region| {
            let mut creds = RegionCredentials::new(region, keys);
            let mut window = CredentialWindow::new();
            let slot = match creds.load_by_id_at(Some(&rp_of(RP)), &credential_id(n), &mut window) {
                SlotRead::Present(slot) => slot,
                _ => panic!("credential {n} must be in the region"),
            };
            let counter = creds.durable_counter(slot).expect("the record must read");
            out = Some((slot, counter));
        })
        .expect("a counting region is installed");
    out.expect("a slot and a counter")
}

/// The `signCount` an assertion's `authData` carries.
///
/// `authData` is `rpIdHash(32) || flags(1) || signCount(4, big endian)`, and the
/// **reply's** copy is what a relying party reads. Read off the wire
/// ([`bstr_at`] key 2) rather than recomputed from the record: the property
/// under test is that the reply says what the device signed, and a helper that
/// read the same field twice would agree with itself.
fn sign_count_of(assertion: &[u8]) -> u32 {
    let auth_data = bstr_at(assertion, 2).expect("a getAssertion reply carries authData at key 2");
    assert!(auth_data.len() >= 37, "authData must be at least rpIdHash + flags + signCount");
    u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]])
}

/// Assert one assertion for fixture credential `n`, and answer its `signCount`.
fn assert_once(device: &mut Device, n: u32) -> u32 {
    let (status, assertion) = device.get_assertion(RP, Some(&credential_id(n)));
    assert_eq!(
        status, OK,
        "credential {n}: a getAssertion on a region-backed device must be served, not refused \
         with CTAP2_ERR_NO_CREDENTIALS — got {assertion:02x?}"
    );
    assert_ne!(status, NO_CREDENTIALS);
    sign_count_of(&assertion)
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

/// **An assertion on a region-backed device is served.**
///
/// The defect itself. Before US-1562 this command was refused with `0x2E`,
/// after the credential had been opened and its key wiped — and it was refused
/// for a credential the device had just found, which is the shape of a bug that
/// reads as "my passkeys vanished" rather than as a counter bug.
#[test]
fn get_assertion_is_served_on_a_region_backed_device() {
    let _guard = lock();
    let (_region_file, mut device) = region_device("served");
    assert_eq!(
        device.backend(),
        fapico2_fido::device_keystore::CredentialBackend::KeyRegion,
        "the fixture must be region-backed, or it would be testing the snapshot path"
    );

    // The real enrolment path first: a passkey a browser made.
    let (status, created) = device.make_cred(RP, b"user-1");
    assert_eq!(status, OK, "makeCredential into the region: {created:02x?}");

    let (status, assertion) = device.get_assertion(RP, None);
    assert_eq!(status, OK, "getAssertion on the makeCredential-issued passkey: {assertion:02x?}");

    let signature = bstr_at(&assertion, 3).expect("key 3 carries the signature");
    assert!(!signature.is_empty(), "an assertion with no signature is not an assertion");
    let auth_data = bstr_at(&assertion, 2).expect("key 2 carries authData");
    assert_eq!(&auth_data[..32], &rp_of(RP)[..], "authData must be bound to the RP");
    assert_ne!(
        sign_count_of(&assertion), 0,
        "a served assertion signs a counter the device has advanced past zero"
    );

    // And the resident enumeration, which is the arm that finds the credential
    // in the first place, answers with the same credential rather than refusing.
    let (status, again) = device.get_assertion(RP, None);
    assert_eq!(status, OK, "a second assertion: {again:02x?}");
    assert!(
        sign_count_of(&again) > sign_count_of(&assertion),
        "two assertions of one credential must sign two different counters"
    );
}

/// **The reply signs the counter its record now holds.**
///
/// The other half of the same fix: a served assertion whose `signCount` came
/// from somewhere other than the record it signed with is the failure mode a
/// "does it return 0x00?" assertion cannot see.
#[test]
fn the_reply_signs_the_counter_the_record_holds() {
    let _guard = lock();
    let (region_file, mut device) = region_device("signs-the-record");
    let keys = keys_of(&mut device);
    enrol(&region_file, &keys, 0);
    let (_slot, before) = record_of(&region_file, &keys, 0);

    let signed = assert_once(&mut device, 0);
    let (_slot, after) = record_of(&region_file, &keys, 0);
    assert!(
        signed > before,
        "the assertion must sign a counter above the record's own ({before}), got {signed}"
    );
    assert_eq!(
        after, signed,
        "the first assertion of a restored session is written down, so the signed counter and \
         the durable one must be the same number"
    );
}

/// **31 assertions erase nothing, the 32nd erases one live record sector and
/// reprograms it.**
///
/// `SLOTS_PER_SECTOR` credentials are enrolled first, because the budget's
/// divisor is a per-sector figure and measuring the sparse case would under-
/// report the wear (`docs/erase-budget.md` §4c.2 says so).
#[test]
fn thirty_one_assertions_erase_nothing_and_the_thirty_second_costs_one_live_sector() {
    let _guard = lock();
    let (region_file, mut device) = region_device("erase-profile");
    let keys = keys_of(&mut device);
    for n in 0..SLOTS_PER_SECTOR {
        enrol(&region_file, &keys, n);
    }
    let (target, _) = record_of(&region_file, &keys, 0);

    // The restore window: the first assertion writes down (see the module docs).
    let mut signed = vec![assert_once(&mut device, 0)];

    // The batch, measured.
    region_file.with_counting(|r| r.reset_log()).expect("a counting region is installed");
    for _ in 1..W {
        signed.push(assert_once(&mut device, 0));
    }
    region_file
        .with_counting(|r| {
            assert_eq!(
                r.erases(),
                0,
                "{} assertions inside an open batch window must not erase a single sector",
                W - 1
            );
            assert_eq!(
                r.programs_on(target),
                0,
                "and must not program the record's sector either — rewriting the whole keystore \
                 image per assertion is the wear defect US-1011 and US-1561 exist to remove"
            );
        })
        .expect("a counting region is installed");
    assert!(
        signed.windows(2).all(|w| w[1] > w[0]),
        "the counters signed inside the window must be strictly increasing: {signed:?}"
    );
    assert_eq!(
        record_of(&region_file, &keys, 0).1,
        signed[0],
        "nothing has been written since the restore window closed, so the durable counter is \
         still the one the first assertion put there — the weakening US-1011 made, asserted \
         rather than assumed"
    );

    // The 32nd: one live-record-sector erase, one sector reprogram.
    region_file.with_counting(|r| r.reset_log()).expect("a counting region is installed");
    let last = assert_once(&mut device, 0);
    region_file
        .with_counting(|r| {
            assert_eq!(
                r.erases_on(target),
                1,
                "the criterion's 'one erase': exactly one erase of the sector holding the record. \
                 The other five land on the index and the commit scratchpad, which \
                 `region_counter_batching.rs::the_32nd_assertion_costs_the_whole_counter_write` \
                 accounts for."
            );
            assert_eq!(
                r.programs_on(target),
                SLOTS_PER_SECTOR,
                "the criterion's 'one program', at sector granularity: one reprogram of the live \
                 sector, which is {SLOTS_PER_SECTOR} slot programs because the erase left nothing \
                 to keep"
            );
        })
        .expect("a counting region is installed");
    assert_eq!(
        record_of(&region_file, &keys, 0).1,
        last,
        "the window-closing assertion is the one that writes, so its counter must be the durable one"
    );
    assert!(last > signed[W as usize - 1], "the last signed counter must exceed the window's");
}

/// **The counter is monotonic across a power cut inside the window.**
///
/// The cut is taken at the point where the in-RAM counter is furthest ahead of
/// the durable one, because that is the dangerous one. Both halves of US-1012
/// are exercised — the "spend" (the first assertion after the power-on writes
/// down) and the "grant" (it writes down a value *above* everything the
/// cut-away session signed).
#[test]
fn the_counter_is_monotonic_across_a_power_cut_inside_the_window() {
    let _guard = lock();
    let (region_file, mut device) = region_device("power-cut");
    let keys = keys_of(&mut device);
    enrol(&region_file, &keys, 0);

    let mut signed = Vec::new();
    for _ in 0..W {
        signed.push(assert_once(&mut device, 0));
    }
    let highest = *signed.iter().max().expect("at least one assertion was signed");

    // **The cut.** The transport gate runs, then the app is thrown away: nothing
    // of this session survives in RAM, and the durable image is whatever the
    // last window-closing write put there.
    device.persist();
    let store = device.into_store();
    let mut rebooted = Device::boot(store);
    rebooted.grant_presence_always();
    // The PIN is already set — it came back in the snapshot — so this is the
    // token leg only. `set_pin` would be refused with `CTAP2_ERR_PIN_INVALID`.
    rebooted.unlock_with_pin(b"123456");

    let keys_after = keys_of(&mut rebooted);
    let after = assert_once(&mut rebooted, 0);
    assert!(
        after > highest,
        "the cut-away session signed up to {highest}; the rebooted device signed {after}, which \
         does not exceed it — repeating a signCount is the clone-detection failure a signature \
         counter exists to prevent"
    );
    assert_eq!(
        record_of(&region_file, &keys_after, 0).1,
        after,
        "US-1012's 'spend': the restore window arrives already spent, so the first assertion \
         after a power-on writes down rather than riding in RAM for another whole window"
    );
}

/// **A flash that refuses the durable write rolls the bump back, and the reply
/// signs the value the window held.**
///
/// SOAK-FINDING-1's discipline, on the region path: the device must never sign a
/// `signCount` it has not committed. The rollback is asserted in both halves —
/// the reply repeats the previous assertion's counter rather than advancing,
/// and the durable record is untouched — because a rollback that signed the
/// *new* value would pass the first and fail the second.
#[test]
fn a_persist_failure_rolls_the_bump_back_and_signs_the_durable_value() {
    let _guard = lock();
    let (region_file, mut device) = region_device("persist-failure");
    let keys = keys_of(&mut device);
    enrol(&region_file, &keys, 0);

    // Open a full window: the restore write, then W - 1 batched assertions.
    let mut previous = assert_once(&mut device, 0);
    for _ in 1..W {
        previous = assert_once(&mut device, 0);
    }
    let (_slot, durable_before) = record_of(&region_file, &keys, 0);

    // **The flash says no.** Erases and programs are refused, which is what a
    // `commit` on a sick part looks like; reads are not, so the applet can still
    // find the credential and read the counter it is about to bump.
    region_file
        .with_counting(|r| {
            r.inject_faults(Faults { erases: true, programs: true, ..Faults::default() })
        })
        .expect("a counting region is installed");
    let signed = assert_once(&mut device, 0);
    assert_eq!(
        signed, previous,
        "the durable write failed, so the bump must be rolled back and the reply must sign the \
         value the window held before this command rather than the one the flash refused"
    );

    // The record is untouched, and the flash recovers.
    region_file
        .with_counting(|r| r.inject_faults(Faults::default()))
        .expect("a counting region is installed");
    assert_eq!(
        record_of(&region_file, &keys, 0).1,
        durable_before,
        "a refused write must leave the record at the value it already held"
    );

    // And the next assertion moves forward again from the rolled-back value —
    // never below it, which would repeat an assertion the client has seen.
    let next = assert_once(&mut device, 0);
    assert!(
        next > previous,
        "after a rollback the counter must resume above the rolled-back value, not below it"
    );
}

/// **The CTAP1 surface, which calls the same bump, works over the region too.**
///
/// The legacy store-backed `AUTHENTICATE` path is the one a pre-US-714
/// authenticator uses exclusively, so it is where this defect would have been
/// *most* visible — and it is the path the epic's migration exists to feed, since
/// `u2f_register` is stateless and mints no record. A credential enrolled
/// directly into the region under a known ID is exactly what such a device holds
/// after US-1558's migration, so that is what this drives.
#[test]
fn the_u2f_authenticate_surface_bumps_the_record_on_the_region_path() {
    let _guard = lock();
    let (region_file, mut device) = region_device("u2f");
    let keys = keys_of(&mut device);
    // `cred_protect` is 0 on the fixture, so no UV is owed: the legacy arm
    // refuses only `== 3` (`device_core.rs`).
    enrol(&region_file, &keys, 0);

    // U2F `AUTHENTICATE`, enforce-only (P1 = 0x03 — `0x07` is check-only and
    // signs nothing). The body is
    // `challenge(32) || appParam(32) || keyHandleLen(1) || keyHandle`
    // (`device_core.rs::u2f_authenticate`), in a short APDU whose `data[4]` is
    // the Lc.
    let kh = credential_id(0);
    let mut body: Vec<u8> = vec![0x22; 32];
    body.extend_from_slice(&rp_of(RP));
    body.push(kh.len() as u8);
    body.extend_from_slice(&kh);
    let mut apdu: Vec<u8> = vec![0x00, 0x02, 0x03, 0x00, body.len() as u8];
    apdu.extend_from_slice(&body);

    let response = device.u2f(&apdu);
    assert_eq!(
        *response.last().expect("an APDU always ends in a status word"),
        SW_NO_ERROR,
        "U2F AUTHENTICATE over a region-backed credential must succeed: {response:02x?}"
    );
    let counter = u32::from_be_bytes([response[1], response[2], response[3], response[4]]);
    assert!(
        counter > 0,
        "the CTAP1 reply's signature counter must be the record's, not a constant"
    );
    assert_eq!(
        record_of(&region_file, &keys, 0).1,
        counter,
        "the CTAP1 path must bump the credential's **record**; before US-1562 it looked the handle \
         up in the snapshot's resident array, found nothing, and answered SW_WRONG_DATA"
    );

    // And a second authenticate advances it rather than repeating it.
    let response = device.u2f(&apdu);
    assert_eq!(*response.last().expect("a status word"), SW_NO_ERROR, "the second AUTHENTICATE");
    let again = u32::from_be_bytes([response[1], response[2], response[3], response[4]]);
    assert!(again > counter, "two CTAP1 authenticates must not sign the same counter");
}