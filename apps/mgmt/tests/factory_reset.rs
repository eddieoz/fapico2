//! US-711: management RESET (INS 0x1E) = full factory reset.
//!
//! The C firmware routes management INS 0x1E through the device-wide reset
//! path (`management.c:209` `cmd_factory_reset` → `cbor_reset()`): every
//! app's durable state is wiped, not just the management config blob. The
//! device-side hook (`DeviceFactoryResetHandler` in `firmware/src/boot.rs`)
//! is injected like the US-413 migration hook; these tests exercise the
//! mgmt APDU path against a store holding real FIDO keystore, OATH, OTP,
//! and OpenPGP durable state, through the same reset primitives the
//! firmware handler uses.

use core::sync::atomic::{AtomicUsize, Ordering};
use fapico2_mgmt::{FactoryResetHandler, ManagementApp};
use fapico2_oath::OathSeal;
use fapico2_platform::dispatch::{App, MAX_RESPONSE};
use fapico2_oath::oath_core::{device_id_from_chipid, DEVICE_ID_LEN, EMULATION_CHIPID};
use fapico2_platform::secure_store::{chunked, HostSecureStore, SecureStore};
use heapless::Vec as HeaplessVec;

static PRESENCE_CALLS: AtomicUsize = AtomicUsize::new(0);

/// US-130: the emulation stand-in device-id the OATH constructor now
/// requires (see `oath_core::new`).
fn emul_device_id() -> [u8; DEVICE_ID_LEN] {
    device_id_from_chipid(EMULATION_CHIPID)
}

fn presence_granted() -> bool {
    PRESENCE_CALLS.fetch_add(1, Ordering::SeqCst);
    true
}

fn presence_denied() -> bool {
    PRESENCE_CALLS.fetch_add(1, Ordering::SeqCst);
    false
}

// OATH INS codes (oath_core keeps them private; C `oath.c` values).
const OATH_INS_PUT: u8 = 0x01;
const OATH_INS_LIST: u8 = 0xA1;
// OTP durable-state slot (otp.rs keeps it private). US-140 versioned this
// key `otp.slots.v1` → `otp.slots.v2` when the slot table widened 2 → 4; the
// v1 record is retired, never read. This constant must track the rename
// (it is the only consumer of the key name outside the crate) or every
// assertion below silently stops inspecting anything real.
const OTP_STATE_SLOT: &[u8] = b"otp.slots.v2";
// The retired 2-slot record, named here only so the tests can prove the
// firmware neither reads nor (post-fix) preserves it across a reset.
const OTP_STATE_SLOT_V1: &[u8] = b"otp.slots.v1";
// `dump_state` layout: 4 slots × (1 presence byte + 52-byte config) + a
// 1-byte access-code presence flag + 6 access-code bytes. Mirrors
// `STATE_SIZE` in `apps/oath/src/otp.rs` (private there).
const OTP_SLOT_COUNT: usize = 4;
const OTP_CONFIG_SIZE: usize = 52;
const OTP_ACCESS_CODE_SIZE: usize = 6;
const OTP_STATE_SIZE: usize =
    OTP_SLOT_COUNT * (1 + OTP_CONFIG_SIZE) + 1 + OTP_ACCESS_CODE_SIZE;
// OpenPGP durable-state slots (platform::migration): the migrated keystore
// (DO records, PIN hashes) and the wrapped private-key DEK.
const OPENPGP_KEYSTORE_SLOT: &[u8] = fapico2_platform::migration::SLOT_OPENPGP;
const OPENPGP_DEK_SLOT: &[u8] = fapico2_platform::migration::SLOT_OPENPGP_DEK;

/// US-711 fixture handler: the host mirror of the device wiring
/// (`DeviceFactoryResetHandler`). Wipes each app's durable state through the
/// shared secure store, using each app's own reset primitive where one
/// exists — never a re-implementation.
struct FixtureReset {
    store: HostSecureStore,
    oath: fapico2_oath::oath_core::OathApp,
    otp: fapico2_oath::OtpApp,
}

impl FixtureReset {
    /// The OATH credential table is empty (host parity: the C reset wipes
    /// every credential record).
    fn oath_is_empty(&mut self) -> bool {
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        self.oath
            .process(&[0x00, OATH_INS_LIST, 0x00, 0x00, 0x00], &mut resp);
        // No credential TLVs — only the status word.
        resp.len() == 2
    }
}

impl FactoryResetHandler for FixtureReset {
    /// Review-fix layering parity with `DeviceFactoryResetHandler`: the
    /// reset hook deletes the FIDO **and OpenPGP** durable slots (plus, on
    /// device, bumping the reset generation). The OATH/OTP/OpenPGP apps sit
    /// behind the CCID dispatcher, which holds the sole `&mut` per app —
    /// the hook must not alias them; the owning transport wipes them via
    /// [`App::factory_wipe`] (mimicked by [`factory_wipe_dispatcher_apps`]).
    fn factory_reset(&mut self) -> u16 {
        // FIDO: the durable keystore + hkey slots (the app re-derives
        // factory-fresh state on the next boot from the emptied store).
        let _ = chunked::delete_chunked(
            &mut self.store,
            fapico2_fido::device_keystore::KEYSTORE_SLOT,
        );
        let _ = self.store.delete(fapico2_fido::device_app::HKEY_KEY);
        // OpenPGP: the migrated keystore (DO records, PIN hashes) + the
        // wrapped private-key DEK — a prior owner's keys must not survive
        // a handover.
        let _ = chunked::delete_chunked(&mut self.store, OPENPGP_KEYSTORE_SLOT);
        let _ = self.store.delete(OPENPGP_DEK_SLOT);
        fapico2_platform::dispatch::SW_OK
    }
}

/// Drive one APDU through the app and return (response_bytes, sw).
fn drive(app: &mut ManagementApp, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    app.process(apdu, &mut resp);
    let bytes: Vec<u8> = resp.as_slice().to_vec();
    assert!(bytes.len() >= 2, "response must carry a status word");
    let sw = u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
    (bytes[..bytes.len() - 2].to_vec(), sw)
}

fn reset_apdu() -> [u8; 5] {
    [0x00, 0x1E, 0x00, 0x00, 0x00]
}

/// Seed device-wide state: a FIDO keystore snapshot + hkey, an OATH
/// credential (through the app's own PUT + persist), and an OTP slot. Hands
/// back the leaked fixture (the reset-hook target, mirroring the device
/// handler static) and the mgmt app wired to it, with a config blob seeded.
///
/// SAFETY: the fixture reference is `Box::leak`ed so the mgmt app can hold
/// it as `&'static mut dyn FactoryResetHandler` — the same write-once
/// discipline as the device's `DeviceFactoryResetHandler` static; each test
/// leaks its own fixture.
fn seed_fixture() -> (&'static mut FixtureReset, ManagementApp) {
    let mut store = HostSecureStore::new();
    let mut trng = fapico2_platform::trng::HostTrng::new();

    // FIDO: a durable keystore snapshot (with a non-default marker so the
    // post-reset boot provably starts fresh) + the persisted hkey.
    let mut ks = fapico2_fido::device_keystore::DeviceKeystore::fresh(&mut trng).expect("host TRNG");
    ks.cred_counter = 7;
    assert!(ks.persist_if_dirty(&mut store), "keystore snapshot persisted");
    let hkey: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0x5A);
    store.write(fapico2_fido::device_app::HKEY_KEY, &hkey).unwrap();

    // OATH: a real credential through the app's own PUT (TLVs: TAG_NAME
    // 0x71 + TAG_KEY 0x73 = [alg 0x31 (SHA256), digits 6, secret..]).
    let mut oath =
        fapico2_oath::oath_core::OathApp::boot(&mut trng, &mut store, emul_device_id(), OathSeal::emul()).unwrap();
    let mut data = vec![0x71, 5, b'a', b'b', b'c', b'd', b'e', 0x73, 6, 0x31, 6];
    data.extend_from_slice(&[0x11u8; 4]);
    let mut put = vec![0x00, OATH_INS_PUT, 0x00, 0x00, data.len() as u8];
    put.extend_from_slice(&data);
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    oath.process(&put, &mut resp);
    let n = resp.len();
    assert_eq!(
        u16::from_be_bytes([resp[n - 2], resp[n - 1]]),
        0x9000,
        "OATH PUT seeded a credential"
    );
    assert!(oath.persist_state(&mut store), "OATH state persisted");

    // OTP: two configured slots, seeded in the current `dump_state` layout
    // (4 × (presence byte + 52-byte config), then access-code presence +
    // 6 access-code bytes). The app the assertions inspect is booted from
    // THIS store — booting it from an empty one would make every
    // `slot_configured` assertion below vacuously true.
    let mut otp_state = Vec::with_capacity(OTP_STATE_SIZE);
    for slot in 0..OTP_SLOT_COUNT {
        if slot < 2 {
            otp_state.push(1u8);
            otp_state.extend_from_slice(&[0x42u8 ^ slot as u8; OTP_CONFIG_SIZE]);
        } else {
            otp_state.push(0u8);
            otp_state.extend_from_slice(&[0u8; OTP_CONFIG_SIZE]);
        }
    }
    otp_state.push(0u8); // no device-wide access code
    otp_state.extend_from_slice(&[0u8; OTP_ACCESS_CODE_SIZE]);
    assert_eq!(otp_state.len(), OTP_STATE_SIZE, "the v2 record is the size boot() reads");
    store.write(OTP_STATE_SLOT, &otp_state).unwrap();
    // The retired v1 record, so the management RESET path is proven to
    // remove it too (not merely to leave it be).
    store.write(OTP_STATE_SLOT_V1, &[0x5Au8; 119]).unwrap();
    let otp = fapico2_oath::OtpApp::boot(&mut store);
    assert!(otp.slot_configured(0) && otp.slot_configured(1), "OTP slots really seeded");

    // OpenPGP: a migrated keystore record stream + a 48-byte wrapped DEK
    // (the private-key import), seeded as raw slot bytes.
    let openpgp_record = [0x5Fu8, 0x30, 4, b'W', b'i', b'l', b'l'];
    chunked::write_chunked(&mut store, OPENPGP_KEYSTORE_SLOT, &openpgp_record).unwrap();
    let dek: [u8; 48] = core::array::from_fn(|i| (i as u8) ^ 0x3C);
    store.write(OPENPGP_DEK_SLOT, &dek).unwrap();

    // Prove the seeded state is observable before the reset runs. The FIDO
    // and OATH slots are chunked (physical keys are derived), so probe them
    // through the chunked probe; the OTP and hkey slots are plain keys.
    assert!(chunked::contains_chunked(&mut store, fapico2_fido::device_keystore::KEYSTORE_SLOT));
    assert!(store.contains(fapico2_fido::device_app::HKEY_KEY));
    assert!(chunked::contains_chunked(&mut store, b"oath.keystore.v1"));
    assert!(store.contains(OTP_STATE_SLOT));
    assert!(chunked::contains_chunked(&mut store, OPENPGP_KEYSTORE_SLOT));
    assert!(store.contains(OPENPGP_DEK_SLOT));

    // Management: a config blob (so the reset has mgmt state to clear too).
    let mut app = ManagementApp::new();
    let (_, sw) = drive(&mut app, &[0x00, 0x1C, 0x00, 0x00, 3, 2, 0xAA, 0xBB]);
    assert_eq!(sw, 0x9000, "mgmt config seeded (host presence auto-acks)");

    let fixture = Box::leak(Box::new(FixtureReset { store, oath, otp }));
    // SAFETY: the leaked fixture backs both handles — the test's own access
    // and the app's hook — the same single-fixture discipline as the lib
    // tests' `static mut HANDLER` accessors (single-threaded tests).
    let handler = unsafe {
        &mut *(fixture as *mut FixtureReset as *mut dyn FactoryResetHandler)
    };
    let app = app.with_user_presence(presence_granted).with_factory_reset(handler);
    (fixture, app)
}

/// Mimic the transport's dispatcher-level reset + persist gate after the
/// RESET APDU: the CCID task observes the reset generation, runs
/// [`Dispatcher::factory_wipe_apps`] (here: each app's `App::factory_wipe`
/// through the fixture — the dispatcher holds the sole `&mut` per app), and
/// the persist gate flushes the emptied state durable-before-ack (US-421),
/// exactly what `persist_reply_with_scratch` runs on device. Disjoint field
/// borrows through the fixture reference.
fn factory_wipe_dispatcher_apps(fx: &mut FixtureReset) {
    let FixtureReset { store, oath, otp } = fx;
    oath.factory_wipe();
    otp.factory_wipe();
    assert!(oath.persist_state(store), "OATH emptied state persisted");
    assert!(otp.persist_state(store), "OTP emptied state persisted");
}

/// The story's test: management RESET wipes FIDO + OATH (+ OTP) durable
/// state and the mgmt config — the device is factory-fresh.
#[test]
fn reset_wipes_fido_and_oath_state() {
    let (fx, mut app) = seed_fixture();

    // FIDO state observable before the reset (the snapshot with the marker).
    let ks = fapico2_fido::device_keystore::DeviceKeystore::load(&mut fx.store).unwrap();
    // US-1012: `load` is the keystore's RESTORE path, and a restore starts a
    // whole counter window above the durable image so a batched sign counter
    // can never repeat a value after a power cut. The seeded durable value is
    // 7, so the restored one is 7 + one window. (`from_cbor` is the decoder
    // and reports the stored bytes unchanged.)
    assert_eq!(
        ks.expect("fido keystore seeded").cred_counter,
        7 + fapico2_fido::device_keystore::COUNTER_PERSIST_INTERVAL as u32
    );
    assert!(fx.store.contains(fapico2_fido::device_app::HKEY_KEY));

    let (_, sw) = drive(&mut app, &reset_apdu());
    assert_eq!(sw, 0x9000, "management RESET succeeds");

    // Mimic the transport persist gate (durable-before-ack).
    assert!(app.persist_state(&mut fx.store), "mgmt config cleared");
    factory_wipe_dispatcher_apps(fx);

    // FIDO: no keystore snapshot and no hkey left — the next boot is
    // factory-fresh.
    let ks = fapico2_fido::device_keystore::DeviceKeystore::load(&mut fx.store).unwrap();
    assert!(ks.is_none(), "FIDO keystore snapshot must be wiped");
    assert!(
        !fx.store.contains(fapico2_fido::device_app::HKEY_KEY),
        "the FIDO hkey must be wiped"
    );

    // OATH: the running app's table is empty and a freshly booted app
    // lists no credentials.
    assert!(fx.oath_is_empty(), "OATH credential table must be wiped");
    let mut trng = fapico2_platform::trng::HostTrng::new();
    let mut booted =
        fapico2_oath::oath_core::OathApp::boot(&mut trng, &mut fx.store, emul_device_id(), OathSeal::emul()).unwrap();
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    booted.process(&[0x00, OATH_INS_LIST, 0x00, 0x00, 0x00], &mut resp);
    assert_eq!(resp.len(), 2, "booted OATH app must hold no credentials");

    // OTP: the slot configuration is gone from the durable state. The app
    // was seeded *configured* (see `seed_fixture`), so these assert a real
    // transition — and a freshly booted app proves the durable record, not
    // just the in-RAM table, is empty.
    let otp = fapico2_oath::OtpApp::boot(&mut fx.store);
    assert!(!otp.slot_configured(0), "OTP slot 1 must be wiped");
    assert!(!otp.slot_configured(1), "OTP slot 2 must be wiped");
    assert!(
        !fx.store.contains(OTP_STATE_SLOT_V1),
        "the retired otp.slots.v1 record must be wiped by a factory reset"
    );

    // Management: back to the factory-default config (the blob is cleared).
    assert!(!app.has_config(), "the mgmt config blob must be cleared");
}

/// The story's OpenPGP half: management RESET must not leave OpenPGP
/// durable state behind — the migrated keystore (DO records, PIN hashes)
/// and the wrapped private-key DEK are wiped with the rest, so a prior
/// owner's keys cannot survive a handover.
#[test]
fn reset_wipes_openpgp_durable_state() {
    let (fx, mut app) = seed_fixture();

    // The OpenPGP state is observable before the reset (seeded raw slot
    // bytes: the keystore record stream + the wrapped DEK).
    assert!(chunked::contains_chunked(&mut fx.store, OPENPGP_KEYSTORE_SLOT));
    assert!(fx.store.contains(OPENPGP_DEK_SLOT));

    let (_, sw) = drive(&mut app, &reset_apdu());
    assert_eq!(sw, 0x9000, "management RESET succeeds");

    // Mimic the transport persist gate (durable-before-ack).
    assert!(app.persist_state(&mut fx.store), "mgmt config cleared");
    factory_wipe_dispatcher_apps(fx);

    // OpenPGP: neither the keystore record stream nor the DEK is left —
    // the next boot boots a factory-fresh OpenPGP card.
    assert!(
        !chunked::contains_chunked(&mut fx.store, OPENPGP_KEYSTORE_SLOT),
        "the OpenPGP keystore slot must be wiped"
    );
    assert!(
        !fx.store.contains(OPENPGP_DEK_SLOT),
        "the OpenPGP DEK slot must be wiped"
    );
}

/// US-702 discipline on the reset path: without a user-presence grant the
/// device-wide reset is refused and NOTHING is wiped (fail closed).
#[test]
fn reset_denied_without_user_presence() {
    let (fx, app) = seed_fixture();
    let mut app = app.with_user_presence(presence_denied);

    let (_, sw) = drive(&mut app, &reset_apdu());
    assert_eq!(sw, 0x6985, "RESET without user presence must be refused");

    // Nothing changed: FIDO, OATH, OTP, OpenPGP, and mgmt state all survive.
    let ks = fapico2_fido::device_keystore::DeviceKeystore::load(&mut fx.store).unwrap();
    assert!(ks.is_some(), "FIDO keystore must survive a denied reset");
    assert!(fx.store.contains(fapico2_fido::device_app::HKEY_KEY));
    assert!(chunked::contains_chunked(&mut fx.store, b"oath.keystore.v1"));
    assert!(fx.store.contains(OTP_STATE_SLOT));
    assert!(fx.store.contains(OTP_STATE_SLOT_V1));
    assert!(chunked::contains_chunked(&mut fx.store, OPENPGP_KEYSTORE_SLOT));
    assert!(fx.store.contains(OPENPGP_DEK_SLOT));
    assert!(app.has_config(), "the mgmt config blob must survive");
}

/// RESET on a factory-fresh device: accepted, no state created.
#[test]
fn reset_on_empty_device_is_a_no_op() {
    let mut store = HostSecureStore::new();
    let mut app = ManagementApp::new().with_user_presence(presence_granted);
    let (_, sw) = drive(&mut app, &reset_apdu());
    assert_eq!(sw, 0x9000);
    assert!(app.persist_state(&mut store));
    assert!(!app.has_config());
}

/// A data-bearing RESET APDU is executed (C parity: `cmd_factory_reset`
/// ignores the APDU data field) — no bounds panic, full wipe still runs.
#[test]
fn reset_ignores_apdu_data() {
    let (fx, mut app) = seed_fixture();
    let (_, sw) = drive(&mut app, &[0x00, 0x1E, 0x00, 0x00, 2, 0xFF, 0xFF]);
    assert_eq!(sw, 0x9000);
    assert!(!app.has_config());
    let ks = fapico2_fido::device_keystore::DeviceKeystore::load(&mut fx.store).unwrap();
    assert!(ks.is_none(), "the device-wide wipe still runs");
}
