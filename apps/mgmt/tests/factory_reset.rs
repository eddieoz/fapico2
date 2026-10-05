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

// ---------------------------------------------------------------------------
// US-1606 — the tripwire for the double-touch regression
// ---------------------------------------------------------------------------
//
// **These three tests are serialised against each other**, and the lock is not
// optional. `US1606_CALLS` is process-global and `with_user_presence` takes
// `fn() -> bool`, so a test cannot capture its own counter — the same constraint
// `tests/presence_gating.rs` and `region_boot::lock` document. Without the lock
// the three counters interleave and the counts below read as each other's.
//
// This is not hypothetical: the first version of these tests ran unlocked and
// turned the four pre-existing `seed_fixture` tests red, because they share the
// binary and therefore the global. A test that breaks its neighbours while
// claiming to guard them is worse than no test.

/// US-1606's **own** counter, separate from the file's [`PRESENCE_CALLS`].
///
/// The obvious move — reusing `PRESENCE_CALLS` — is wrong, and it was wrong in
/// the first version of this file: the pre-existing tests in this binary use
/// that global through `presence_granted`/`presence_denied` and do **not**
/// take this lock, so `cargo test`'s per-file parallelism interleaves the two
/// sets and a count of 2 appears out of nowhere. The failure looks exactly
/// like the double-touch regression this story exists to detect, which is the
/// worst possible place to have a look-alike.
///
/// A private counter cannot be perturbed by a neighbour, so the numbers below
/// mean what they say. The lock is still needed — for the three tests in this
/// section against **each other**.
static US1606_CALLS: AtomicUsize = AtomicUsize::new(0);

fn us1606_granted() -> bool {
    US1606_CALLS.fetch_add(1, Ordering::SeqCst);
    true
}

fn us1606_denied() -> bool {
    US1606_CALLS.fetch_add(1, Ordering::SeqCst);
    false
}

/// Serialise this section's tests against each other.
///
/// `unwrap_or_else(|e| e.into_inner())` rather than `unwrap()`: a test that
/// panicked while holding the lock poisons it, and every later test would then
/// fail on the *poison*, hiding the real failure. Same reason as
/// `region_boot::lock`.
fn presence_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// A handler that drives the **real** `device_app::FidoApp::factory_reset`, so
/// the grant count is observable end to end.
///
/// US-711's own fixture (`FixtureReset`) wipes the durable slots and stops
/// there, which is correct for what it tests but cannot see this story: the
/// question is whether the FIDO app's *in-RAM* reset asks for a second touch,
/// and only the real app can answer that.
struct FidoHook {
    app: &'static mut fapico2_fido::FidoApp,
    /// How many times the hook was reached at all. Zero would mean the
    /// management applet refused before calling us — the denied case.
    fired: usize,
}

impl FactoryResetHandler for FidoHook {
    fn factory_reset(&mut self) -> fapico2_platform::dispatch::Sw {
        self.fired += 1;
        self.app.factory_reset();
        fapico2_platform::dispatch::SW_OK
    }
}

/// A `ManagementApp` whose reset hook reaches the real device twin, plus the
/// leaked hook so the test can read `fired` afterwards.
///
/// `Box::leak` is [`seed_fixture`]'s discipline, for the same reason: the
/// `&'static mut dyn FactoryResetHandler` the applet takes has to outlive the
/// local, and a leaked box is the least surprising way to say so in a test.
/// The FIDO app is leaked separately because the hook holds a `&'static mut`
/// of it and `with_user_presence` returns the app **by value**, so there is no
/// owned value left to move once the hook is built.
fn mgmt_with_fido_hook(present: fn() -> bool) -> (&'static mut FidoHook, ManagementApp) {
    let mut store = HostSecureStore::new();
    let mut trng = fapico2_platform::trng::HostTrng::new();

    // The counter has to be on the **FIDO app** too, not just on the
    // management applet, or the regression this story guards is invisible: a
    // gate added inside `handle_reset` would consult the FIDO app's own
    // source, which nothing else here counts. `with_user_presence` takes
    // `fn() -> bool` and `us1606_granted` is exactly that, so one global
    // counts both sides of the boundary.
    let app = fapico2_fido::FidoApp::boot(&mut trng, &mut store)
        .expect("boot the device twin")
        .with_user_presence(present);

    let app: &'static mut fapico2_fido::FidoApp = Box::leak(Box::new(app));
    let hook = Box::leak(Box::new(FidoHook { app, fired: 0 }));
    // SAFETY: the leaked hook backs both handles — the test's own `&mut` and
    // the applet's `&mut dyn` — the same single-fixture discipline
    // `seed_fixture` states. The test never uses the two at once: the read of
    // `fired` happens after the `ManagementApp` has been dropped.
    let handler = unsafe { &mut *(hook as *mut FidoHook as *mut dyn FactoryResetHandler) };
    let app = ManagementApp::new()
        .with_user_presence(present)
        .with_factory_reset(handler);
    (hook, app)
}

/// **The management factory reset consumes exactly ONE presence grant, across
/// both applets.**
///
/// This story encodes the epic's constraint 1, and its whole purpose is to
/// fail if anyone later "helpfully" moves the presence gate out of the CTAP2
/// command boundary and into the shared `handle_reset` primitive.
///
/// ## Why the count and not the outcome
///
/// Asserting only that the reset succeeded would pass against **both** the
/// correct code and the double-gated version — a double-gated reset still
/// succeeds, it just makes the owner press the button twice. The regression is
/// invisible in the status word and visible only in how many grants were
/// consumed, so **the count is the assertion**.
///
/// ## What the 1 is, and why that is not luck
///
/// Exactly one: the management applet's own `cmd_reset` → `user_present`
/// (`INS_RESET`, tag 0x1E). The FIDO half contributes **zero** — US-1602
/// pointed `factory_reset` at `handle_reset` directly, bypassing the gate the
/// CTAP2 command boundary carries. Both sides read the same counter, so if that
/// indirection is ever removed this reads 2 and the double touch is back.
#[test]
fn the_management_factory_reset_consumes_exactly_one_presence_grant() {
    let _g = presence_lock();
    US1606_CALLS.store(0, Ordering::SeqCst);
    let (hook, mut app) = mgmt_with_fido_hook(us1606_granted);

    let (_, sw) = drive(&mut app, &reset_apdu());
    assert_eq!(sw, 0x9000, "the management factory reset must still succeed");
    drop(app);

    let calls = US1606_CALLS.load(Ordering::SeqCst);
    assert_eq!(
        calls, 1,
        "the management factory reset consumed {calls} presence grant(s), not 1 — counted \
         across BOTH applets, which share this counter. The management applet gates once \
         (cmd_reset → user_present(INS_RESET), tag 0x1E) and the FIDO half must not gate again: \
         presence is press→consume and one-shot, and the two tags differ (0x1E vs \
         0x8000_0001), so a second gate is a second window and a second touch for one reset. \
         Move the gate, never add to it.",
    );
    assert_eq!(hook.fired, 1, "the hook must have run exactly once");
}

/// **The counter is attached to the FIDO app's gate too — proved, not assumed.**
///
/// A tripwire that cannot fail is worse than none, because it reads as
/// coverage. This drives the path where the FIDO gate **does** apply (the
/// CTAP2 command boundary) and shows the same counter move, which is what
/// makes the `1` above mean "the FIDO half contributed zero" rather than "the
/// FIDO half is not wired to anything".
#[test]
fn the_counter_sees_the_fido_gate_on_the_ctap2_command_boundary() {
    let _g = presence_lock();
    let mut store = HostSecureStore::new();
    let mut trng = fapico2_platform::trng::HostTrng::new();
    let mut app = fapico2_fido::FidoApp::boot(&mut trng, &mut store)
        .expect("boot the device twin")
        .with_user_presence(us1606_granted);

    US1606_CALLS.store(0, Ordering::SeqCst);
    let mut out = heapless::Vec::<u8, { fapico2_fido::CTAP2_MAX_MSG }>::new();
    let n = app.process_ctap2(0x07, &[], [1, 2, 3, 4], &mut out);

    // The host build auto-acks (`default_user_present`), so the gate grants
    // and the reset succeeds — which is exactly why the assertion is on the
    // counter rather than on the status byte. The gate *ran*; that is the claim.
    assert_eq!(out[..n][0], 0x00, "the host build auto-acks a presence gate");
    assert_eq!(
        US1606_CALLS.load(Ordering::SeqCst),
        1,
        "the CTAP2 command boundary's gate must consult the shared counter. If this reads 0, \
         the management test above is counting only the management side and its '1' says \
         nothing about the FIDO half — which is the whole question.",
    );
}

/// **A denied management reset never reaches the FIDO half, and costs one
/// refused grant.**
///
/// The other half of constraint 1. `reset_denied_without_user_presence` covers
/// the durable slots; this covers the *in-RAM* app the hook would have reset —
/// which on hardware is the state that would otherwise survive to the next
/// power cycle.
#[test]
fn a_denied_management_reset_never_reaches_the_fido_half() {
    let _g = presence_lock();
    US1606_CALLS.store(0, Ordering::SeqCst);
    let (hook, mut app) = mgmt_with_fido_hook(us1606_denied);

    let (_, sw) = drive(&mut app, &reset_apdu());
    assert_eq!(sw, 0x6985, "RESET without a press must be refused");
    drop(app);

    assert_eq!(hook.fired, 0, "the hook must not run on a denied reset");
    assert_eq!(
        US1606_CALLS.load(Ordering::SeqCst),
        1,
        "a denied management reset consumes exactly one grant — its own, refused. A second \
         would mean the denial is being paid for twice.",
    );
}
