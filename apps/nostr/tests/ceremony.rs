//! US-1714/1715 — the custody ceremony's applet verbs: the sealed-unavailable
//! state, the migration-pending flag, and `CEREMONY_START`.
//!
//! The world these tests build is the device's, twice over. The OTP page is
//! the same injected fixture `platform/tests/custody_ceremony.rs` models
//! (rows at their real page-59 indexes, raw zero = erased), and the region
//! always arrives through a **provider** — the `with_region_provider` path —
//! whose policy mirrors `firmware/src/boot.rs::nostr_custody_region` row for
//! row: the ceremony drops the applet's region view and re-enters, which the
//! boot-eager path (`NostrApp::boot`) cannot survive, because a boot region
//! is handed once and never re-derived.
//!
//! The provider is a capture-free `fn` pointer, exactly like the device's
//! `|| boot::nostr_region()` — so the per-test world (region path + OTP
//! fixture) lives in a thread-local the provider reads. Tests run on
//! separate threads and never see each other's world.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;

use fapico2_nostr::{
    FLAG_MIGRATION_PENDING, FLAG_PIN_SET, FLAG_SESSION_UNLOCKED, NostrApp, INS_CEREMONY_START,
    INS_GET_INFO, INS_GET_PUBKEY, INS_SET_PIN, INS_VERIFY_PIN, SW_CEREMONY_NOT_NEEDED,
    SW_PIN_NOT_SET, SW_SEALED_UNAVAILABLE,
};
use fapico2_platform::custody::{assess, burn, custody_secret_bytes, CeremonyState};
use fapico2_platform::dispatch::{App, Sw, SW_OK};
use fapico2_platform::keyregion::crypto::{
    derive_nostr_payload_key, NostrKeySource, PayloadKey,
};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::nostr_store::{
    Entry, NostrIdentity, NostrRegion, NostrStore, PinEntry,
};
use fapico2_platform::keyregion::TOTAL_SLOTS;
use fapico2_platform::otp_cus::{OtpAccess, OtpError};
use heapless::Vec as HeaplessVec;

const PIN: &[u8] = b"731742";

// ---------------------------------------------------------------------------
// The OTP fixture — `custody_ceremony.rs`'s model, plus a faulted page
// ---------------------------------------------------------------------------

const ECC_META: u32 = 0x5500_0000; // a burned word's ECC metadata, in the raw view

/// Rows are `(raw, ecc)`; a raw of `0` is the erased mark. `faulted` turns
/// every row into the debug-refusal artifact (`0xFFFF_FFFF` raw) — the one
/// classification `assess` maps to [`CeremonyState::Abort`], which is what a
/// device with unreadable custody rows reads.
struct Fixture {
    rows: RefCell<BTreeMap<usize, (u32, u16)>>,
    writes: RefCell<Vec<(usize, u16)>>,
    faulted: bool,
}

impl Fixture {
    /// Leak the fixture and hand back both handles: the `&'static dyn` the
    /// applet holds, and the concrete reference the write-ledger assertions
    /// read. They are the same object — the ledger is test observability,
    /// not a second truth.
    fn leak(fx: Fixture) -> (&'static dyn OtpAccess, &'static Fixture) {
        let leaked: &'static Fixture = Box::leak(Box::new(fx));
        (leaked as &'static dyn OtpAccess, leaked)
    }

    fn virgin() -> (&'static dyn OtpAccess, &'static Fixture) {
        Self::leak(Self {
            rows: RefCell::new(BTreeMap::new()),
            writes: RefCell::new(Vec::new()),
            faulted: false,
        })
    }

    /// A complete page: every secret row, the lock and the marker burned.
    /// The entropy is deterministic — the values are the identity of the
    /// rows, not anything secret in these tests.
    fn complete() -> (&'static dyn OtpAccess, &'static Fixture) {
        let fx = Self {
            rows: RefCell::new(BTreeMap::new()),
            writes: RefCell::new(Vec::new()),
            faulted: false,
        };
        burn(&fx, || 0x4B1Du16).expect("a virgin fixture page burns to Complete");
        Self::leak(fx)
    }

    /// Every row reads as the SWD artifact: `assess` classifies the page
    /// Abort, and no payload key can exist.
    fn faulted() -> (&'static dyn OtpAccess, &'static Fixture) {
        Self::leak(Self {
            rows: RefCell::new(BTreeMap::new()),
            writes: RefCell::new(Vec::new()),
            faulted: true,
        })
    }
}

impl OtpAccess for Fixture {
    fn raw_word(&self, row: usize) -> Result<u32, OtpError> {
        if self.faulted {
            return Ok(0xFFFF_FFFF);
        }
        match self.rows.borrow().get(&row) {
            Some((raw, _)) => Ok(*raw),
            None => Ok(0),
        }
    }
    fn ecc_word(&self, row: usize) -> Result<u16, OtpError> {
        if self.faulted {
            return Ok(0);
        }
        match self.rows.borrow().get(&row) {
            Some((_, ecc)) => Ok(*ecc),
            None => Ok(0),
        }
    }
    fn write_ecc_word(&self, row: usize, data: u16) -> Result<(), OtpError> {
        self.writes.borrow_mut().push((row, data));
        self.rows
            .borrow_mut()
            .insert(row, (ECC_META | data as u32, data));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The provider world — boot.rs's custody policy, mirrored
// ---------------------------------------------------------------------------

struct World {
    path: PathBuf,
    otp: &'static dyn OtpAccess,
    fixture: &'static Fixture,
}

thread_local! {
    static WORLD: RefCell<Option<World>> = const { RefCell::new(None) };
    static ATTACHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn set_world(tag: &str, otp: &'static dyn OtpAccess, fixture: &'static Fixture) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("fapico2-nostr-ceremony-{tag}-{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&path);
    WORLD.with(|w| *w.borrow_mut() = Some(World { path: path.clone(), otp, fixture }));
    ATTACHES.with(|a| a.set(0));
    path
}

/// Re-point the world's OTP page in place — the "power cycle met different
/// rows" leg of the latch test. The region path is untouched.
fn set_world_otp(otp: &'static dyn OtpAccess, fixture: &'static Fixture) {
    WORLD.with(|w| {
        if let Some(world) = w.borrow_mut().as_mut() {
            world.otp = otp;
            world.fixture = fixture;
        }
    });
}

fn attaches() -> usize {
    ATTACHES.with(|a| a.get())
}

fn world_assess() -> CeremonyState {
    WORLD.with(|w| assess(w.borrow().as_ref().unwrap().otp))
}

fn world_writes() -> Vec<(usize, u16)> {
    WORLD.with(|w| w.borrow().as_ref().unwrap().fixture.writes.borrow().clone())
}

fn otp_row() -> [u8; 32] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(0x23))
}

fn chip_id() -> [u8; 8] {
    [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
}

/// The device's attach policy (`boot.rs::nostr_custody_region`), mirrored
/// against the fixture. The ceremony drops its region view and re-enters
/// through this, and the mirror is what makes the re-entry honest — if the
/// policy drifted from the device's, these tests would pass a ceremony the
/// device cannot run.
fn custody_provider() -> Option<NostrRegion> {
    ATTACHES.with(|a| a.set(a.get() + 1));
    WORLD.with(|w| {
        let guard = w.borrow();
        let world = guard.as_ref()?;
        // The device's region is always there (flash); a host region file
        // that was never seeded is created on first attach instead — the
        // same "a region exists" fact, not a different policy.
        let region = match FileKeyRegion::open(&world.path) {
            Ok(region) => region,
            Err(_) => FileKeyRegion::create(&world.path, TOTAL_SLOTS).ok()?,
        };
        match assess(world.otp) {
            CeremonyState::Abort => None,
            CeremonyState::Virgin | CeremonyState::Torn => {
                let key = derive_nostr_payload_key(
                    &otp_row(),
                    &chip_id(),
                    NostrKeySource::LegacyConstant,
                )?;
                Some(NostrRegion::new(Box::new(region), key))
            }
            // Sealed or complete: the custody key over the read-back rows,
            // plus the legacy window exactly while the flash reseat marker
            // does not stand.
            _ => {
                let secret = custody_secret_bytes(world.otp)?;
                let key = derive_nostr_payload_key(
                    &otp_row(),
                    &chip_id(),
                    NostrKeySource::Custody(&secret),
                )?;
                let legacy = derive_nostr_payload_key(
                    &otp_row(),
                    &chip_id(),
                    NostrKeySource::LegacyConstant,
                )?;
                let mut region = NostrRegion::with_legacy_window(Box::new(region), key, legacy);
                if region.store().reseat_complete().unwrap_or(false) {
                    region.close_legacy_window();
                }
                Some(region)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// APDU plumbing (the pin.rs set)
// ---------------------------------------------------------------------------

fn apdu(ins: u8, p1: u8, data: &[u8]) -> HeaplessVec<u8, 300> {
    let mut a = HeaplessVec::new();
    a.extend_from_slice(&[0x00, ins, p1, 0x00]).unwrap();
    a.push(data.len() as u8).unwrap();
    a.extend_from_slice(data).unwrap();
    a
}

/// Drive one APDU through the applet, returning (data, SW).
fn call(app: &mut NostrApp, apdu: &[u8]) -> (HeaplessVec<u8, 4096>, Sw) {
    let mut resp = HeaplessVec::new();
    app.process(apdu, &mut resp);
    assert!(resp.len() >= 2, "the applet must always answer with a status word");
    let n = resp.len();
    let sw = u16::from_be_bytes([resp[n - 2], resp[n - 1]]);
    (resp[..n - 2].iter().copied().collect(), sw)
}

/// A deterministic fill — the entropy the ceremony draws its burn words
/// through.
fn rng_constant(out: &mut [u8]) {
    out.fill(0x5A);
}

fn identity(n: u8) -> NostrIdentity {
    let scalar: [u8; 32] =
        core::array::from_fn(|i| n.wrapping_mul(7).wrapping_add(i as u8).wrapping_add(1));
    let npub: [u8; 32] =
        core::array::from_fn(|i| n.wrapping_mul(11).wrapping_add(i as u8).wrapping_add(3));
    NostrIdentity::new(scalar, npub, b"alice", 0x01).expect("a short utf-8 label")
}

/// Seed identity 0 directly, under the legacy key, before the applet ever
/// attaches — the deployed-board shape.
fn seed_legacy_identity(path: &std::path::Path) {
    let mut region = FileKeyRegion::create(path, TOTAL_SLOTS).expect("a fresh region file");
    let key = legacy_key();
    let mut store = NostrStore::new(&mut region, &key);
    store.write(0, &identity(1)).expect("write idx0");
}

/// The legacy key, for the behind-the-applet assertions.
fn legacy_key() -> PayloadKey {
    derive_nostr_payload_key(&otp_row(), &chip_id(), NostrKeySource::LegacyConstant)
        .expect("the legacy key derives")
}

// ---------------------------------------------------------------------------
// US-1714 — the sealed-unavailable state
// ---------------------------------------------------------------------------

/// **A faulted custody read answers `SW_SEALED_UNAVAILABLE` on every
/// command.** The gate sits at the head of `process`, before the header
/// guard — even a malformed or unknown APDU hears the honest word, because
/// the condition is "no key can be derived", not "this command is wrong".
/// With the device's OTP unreadable (`0xFFFF_FFFF` everywhere, the SWD
/// artifact), no payload key exists and nothing else may run.
#[test]
fn faulted_custody_read_yields_sealed_unavailable() {
    let (otp, _) = Fixture::faulted();
    let mut app = NostrApp::new().with_custody_otp(otp);

    // GET_INFO — the command every client sends first.
    let (_, sw) = call(&mut app, &apdu(INS_GET_INFO, 0, &[]));
    assert_eq!(sw, SW_SEALED_UNAVAILABLE);

    // A well-formed secret command, and the ceremony verb itself.
    let (_, sw) = call(&mut app, &apdu(INS_GET_PUBKEY, 0, &[]));
    assert_eq!(sw, SW_SEALED_UNAVAILABLE);
    let (_, sw) = call(&mut app, &apdu(INS_CEREMONY_START, 0, &[]));
    assert_eq!(sw, SW_SEALED_UNAVAILABLE);

    // Even a malformed APDU (sub-4-byte) is the sealed word, not the
    // length refusal — the custody gate stands in front of the header
    // guard by design.
    let mut resp = HeaplessVec::new();
    app.process(&[0x00, 0x04], &mut resp);
    let n = resp.len();
    assert_eq!(
        u16::from_be_bytes([resp[n - 2], resp[n - 1]]),
        SW_SEALED_UNAVAILABLE
    );
}

/// **The sealed-unavailable state neither latches nor writes.** The health
/// decision is RAM-only (a reboot re-derives from the rows), the provider is
/// never consulted (no region is opened, so nothing can be repaired or
/// tombstoned), the region file is byte-identical after any number of
/// refused commands, and a fresh applet on the same world runs normally.
#[test]
fn sealed_unavailable_does_not_latch_and_never_tombstones() {
    let (otp, fixture) = Fixture::faulted();
    let path = set_world("unlatch", otp, fixture);
    seed_legacy_identity(&path);
    let before = std::fs::read(&path).expect("the seeded region file reads");

    let mut app = NostrApp::new()
        .with_region_provider(custody_provider)
        .with_custody_otp(otp)
        .with_rng_provider(rng_constant);

    for _ in 0..3 {
        let (_, sw) = call(&mut app, &apdu(INS_GET_INFO, 0, &[]));
        assert_eq!(sw, SW_SEALED_UNAVAILABLE);
        let (_, sw) = call(&mut app, &apdu(INS_GET_PUBKEY, 0, &[]));
        assert_eq!(sw, SW_SEALED_UNAVAILABLE);
    }

    // The provider was never consulted: no region view was opened, so no
    // Undecodable force-tombstone path, no occupancy rewrite — the one
    // thing worse than reading nothing is writing over records nobody can
    // read — was even reachable.
    assert_eq!(attaches(), 0, "the faulted applet never opened its region");
    let after = std::fs::read(&path).expect("the region file still reads");
    assert_eq!(before, after, "the sealed state never wrote the region");

    // And the health is RAM-only: nothing about the fault was persisted —
    // the region bytes above are the proof — so a fresh applet over a
    // healthy page (the world swapped, as a power cycle would meet) runs
    // normally. If the fault ever latched into the region or the OTP, this
    // leg would fault too.
    let (healthy, healthy_fx) = Fixture::complete();
    set_world_otp(healthy, healthy_fx);
    let mut fresh = NostrApp::new()
        .with_region_provider(custody_provider)
        .with_custody_otp(healthy)
        .with_rng_provider(rng_constant);
    let (_, sw) = call(&mut fresh, &apdu(INS_GET_INFO, 0, &[]));
    assert_eq!(sw, SW_OK);
    std::fs::remove_file(&path).ok();
}

/// **A custody fault is not a boot failure.** The pre-custody design parked
/// a board whose root was unreadable in `fatal_boot` — USB never came up,
/// and the only diagnosis was a probe. The custody policy replaces that
/// with a board that enumerates and answers every command with the distinct
/// refusal word: the provider is never asked (no attach, no region), and
/// the applet stays alive and responsive after the refusal.
#[test]
fn no_fatal_boot_on_custody_fault() {
    let (otp, fixture) = Fixture::faulted();
    let path = set_world("no-fatal", otp, fixture);
    let mut app = NostrApp::new()
        .with_region_provider(custody_provider)
        .with_custody_otp(otp);

    // The construction itself is the claim — a fatal_boot here would park
    // the test process — and the board answers, repeatedly.
    for _ in 0..2 {
        let (_, sw) = call(&mut app, &apdu(INS_GET_INFO, 0, &[]));
        assert_eq!(sw, SW_SEALED_UNAVAILABLE);
    }
    assert_eq!(attaches(), 0, "the degraded applet never opened a region");
    std::fs::remove_file(&path).ok();
}

/// **The ceremony rides `process` through the CCID proxy, so the proxy
/// carries it by construction — but that is exactly why it must be pinned.**
/// The F-A3 twin trap: a surface the `NostrViaMutex` proxy does not forward
/// is a silent no-op on hardware while every direct test passes. The
/// ceremony deliberately added **no** new `App` trait method — it rides
/// `process` — so the pin is the forwarding line itself, plus the absence
/// of any per-verb override that could have forgotten it.
#[test]
fn ceremony_verbs_forward_through_proxy() {
    let shared = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../firmware/src/nostr_shared.rs"
    ))
    .expect("firmware/src/nostr_shared.rs is readable from the nostr test crate");
    let tail = shared
        .split("impl fapico2_platform::dispatch::App for NostrViaMutex")
        .nth(1)
        .expect("the proxy implements App");
    assert!(
        tail.contains("with_nostr(|app| app.process(apdu, resp))"),
        "the proxy's process must forward through the shared mutex — the \
         ceremony rides process, so this forwarding is the whole claim"
    );
    // No new trait surface to forget: if a future edit adds a per-verb
    // method to the applet trait, this test stops describing reality and
    // must be revisited with the trap in mind.
    assert!(
        !tail.contains("fn ceremony"),
        "the ceremony must ride process, not gain a proxy-forwarded method \
         (the F-A3 trap: an unforwarded method is a silent no-op on hardware)"
    );
}

// ---------------------------------------------------------------------------
// US-1715 — CEREMONY_START
// ---------------------------------------------------------------------------

/// **No verb burns the custody page except `CEREMONY_START`.** The PIN
/// lifecycle and the operations a busy session runs complete against a
/// virgin page and leave it virgin — the burn is an irreversible spend of
/// the one OTP page the device has for this, and it happens exactly when
/// the user says the verb, never as a side effect of a PIN set or a key
/// written.
#[test]
fn verify_never_implicitly_burns() {
    let (otp, fixture) = Fixture::virgin();
    let path = set_world("no-implicit-burn", otp, fixture);
    let mut app = NostrApp::new()
        .with_region_provider(custody_provider)
        .with_custody_otp(otp)
        .with_rng_provider(rng_constant);

    // The whole PIN lifecycle, plus the operations a busy session runs.
    let (_, sw) = call(&mut app, &apdu(INS_SET_PIN, 0, PIN));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &apdu(INS_VERIFY_PIN, 0, PIN));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &apdu(INS_GET_INFO, 0, &[]));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &apdu(INS_GET_PUBKEY, 0, &[]));
    assert_eq!(sw, 0x6A82, "an empty identity range is the honest miss");

    // The page never changed. Not one row, not by any verb.
    assert_eq!(world_assess(), CeremonyState::Virgin, "the page is still virgin");
    assert!(world_writes().is_empty(), "no verb wrote the OTP page");

    std::fs::remove_file(&path).ok();
}

/// **`CEREMONY_START` without a PIN is refused before anything else.** The
/// custody page's one irreversible burn must not be reachable on a board
/// where the PIN — the root the migration protects — does not even exist.
#[test]
fn ceremony_start_refuses_without_pin() {
    let (otp, fixture) = Fixture::virgin();
    let path = set_world("start-nopin", otp, fixture);
    let mut app = NostrApp::new()
        .with_region_provider(custody_provider)
        .with_custody_otp(otp)
        .with_rng_provider(rng_constant);

    let (_, sw) = call(&mut app, &apdu(INS_CEREMONY_START, 0, &[]));
    assert_eq!(sw, SW_PIN_NOT_SET);

    // The refusal precedes the burn: the page is untouched. The one attach
    // is US-1718's boot substitute, not the gate — the cache the gate
    // consults derives from the store at the one-shot attach (the device
    // path has no eager `boot`), and on a PIN-less board the derivation
    // reads Empty. Everything after it — the gate, the OTP gate, the
    // identity walk — is a cache read and a refusal.
    assert_eq!(world_assess(), CeremonyState::Virgin);
    assert_eq!(attaches(), 1, "one attach: the boot substitute, never the gate's own");
    std::fs::remove_file(&path).ok();
}

/// **A PIN record alone does not justify the burn.** A PIN-set board whose
/// identity slots are all empty has nothing to migrate — the honest answer
/// is `SW_CEREMONY_NOT_NEEDED`, and no OTP word is spent. The lazy-burn
/// alternative (burning at the first identity write) was considered and
/// deferred: it would put the irreversible spend inside a write path
/// instead of behind the user's verb.
#[test]
fn ceremony_start_refuses_without_legacy_records() {
    let (otp, fixture) = Fixture::virgin();
    let path = set_world("start-empty", otp, fixture);
    let mut app = NostrApp::new()
        .with_region_provider(custody_provider)
        .with_custody_otp(otp)
        .with_rng_provider(rng_constant);

    // A PIN, and nothing else.
    let (_, sw) = call(&mut app, &apdu(INS_SET_PIN, 0, PIN));
    assert_eq!(sw, SW_OK);

    let (_, sw) = call(&mut app, &apdu(INS_CEREMONY_START, 0, &[]));
    assert_eq!(sw, SW_CEREMONY_NOT_NEEDED);

    // And the refusal kept the page virgin.
    assert_eq!(world_assess(), CeremonyState::Virgin);
    assert!(world_writes().is_empty(), "the refusal never burns");
    std::fs::remove_file(&path).ok();
}

/// **Declining the ceremony leaves the board exactly as it was — and the
/// pending flag says so.** With the custody page burned (a previous
/// ceremony's rows) but the flash reseat marker absent, every attach opens
/// the custody-keyed region with the legacy window: records still read,
/// nothing migrates until the user says `CEREMONY_START`, and GET_INFO
/// raises bit 2 — `FLAG_MIGRATION_PENDING` — derived from the same
/// completeness predicate the ceremony itself consults.
#[test]
fn declined_migration_stays_pending() {
    let (otp, fixture) = Fixture::complete();
    let path = set_world("declined", otp, fixture);
    seed_legacy_identity(&path);

    let mut app = NostrApp::new()
        .with_region_provider(custody_provider)
        .with_custody_otp(otp)
        .with_rng_provider(rng_constant);

    // The board's PIN lives in the custody-keyed view now (the page is
    // burned; the provider's policy decides the key). Set and unlock.
    let (_, sw) = call(&mut app, &apdu(INS_SET_PIN, 0, PIN));
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &apdu(INS_VERIFY_PIN, 0, PIN));
    assert_eq!(sw, SW_OK);

    // GET_INFO: PIN set, session unlocked, migration pending — bit 2.
    let (data, sw) = call(&mut app, &apdu(INS_GET_INFO, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(
        data[7],
        FLAG_PIN_SET | FLAG_SESSION_UNLOCKED | FLAG_MIGRATION_PENDING,
        "the pending bit rides the flags byte"
    );

    // The legacy records still read through the window: the pre-custody
    // identity answers at idx 0, session unlocked.
    let (npub, sw) = call(&mut app, &apdu(INS_GET_PUBKEY, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(&npub[..32], &identity(1).npub, "the legacy record reads untouched");

    // The pending flag survives more traffic: no verb but START migrates.
    let (data, sw) = call(&mut app, &apdu(INS_GET_INFO, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert_ne!(data[7] & FLAG_MIGRATION_PENDING, 0, "still pending");

    // And the region itself confirms the state: a custody-keyed store (the
    // only reader that can see the marker at all) finds no marker, and a
    // legacy-keyed store still opens the record — nothing was reseated
    // behind the user's back.
    let mut region = FileKeyRegion::open(&path).expect("the region file reads");
    let secret = WORLD.with(|w| custody_secret_bytes(w.borrow().as_ref().unwrap().otp));
    let custody = derive_nostr_payload_key(
        &otp_row(),
        &chip_id(),
        NostrKeySource::Custody(secret.as_ref().expect("the custody rows read back")),
    )
    .expect("the custody key derives");
    let mut store = NostrStore::new(&mut region, &custody);
    assert!(!store.reseat_complete().unwrap_or(true), "no marker stands");
    let mut region = FileKeyRegion::open(&path).expect("the region file reads");
    let key = legacy_key();
    let mut store = NostrStore::new(&mut region, &key);
    assert!(
        matches!(store.read(0).expect("idx0 readable"), Entry::Live(_)),
        "idx0 still opens under the legacy key"
    );
    std::fs::remove_file(&path).ok();
}

/// The reseat's happy path, end to end through the verb: burn, re-enter
/// through the provider, migrate, re-enter again, and report the counts.
/// The story's named eight pin the gates; this one pins the walk the gates
/// guard.
#[test]
fn ceremony_start_migrates_and_closes_the_window() {
    let (otp, fixture) = Fixture::virgin();
    let path = set_world("happy", otp, fixture);
    seed_legacy_identity(&path);

    let mut app = NostrApp::new()
        .with_region_provider(custody_provider)
        .with_custody_otp(otp)
        .with_rng_provider(rng_constant);

    // The deployed-board shape: a PIN, set while the page is still virgin,
    // so the PIN record itself is legacy-sealed and must migrate too.
    let (_, sw) = call(&mut app, &apdu(INS_SET_PIN, 0, PIN));
    assert_eq!(sw, SW_OK);

    // The verb. The walk is identities-then-PIN (US-1713), so idx0 and the
    // PIN record both migrate: 2 migrated, 0 already custody-sealed.
    let (data, sw) = call(&mut app, &apdu(INS_CEREMONY_START, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(&data[..2], &[0x00, 0x02], "idx0 and the PIN record migrated");
    assert_eq!(&data[2..4], &[0x00, 0x00], "nothing was already migrated");

    // The page burned exactly once — the fixture's ledger pins it.
    assert!(!world_writes().is_empty(), "the ceremony burned the page");

    // The very next attach finds the marker standing: GET_INFO's pending
    // bit is gone (the same predicate the provider closes the window by).
    let (data, sw) = call(&mut app, &apdu(INS_GET_INFO, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(
        data[7] & FLAG_MIGRATION_PENDING,
        0,
        "the reseat completed; nothing is pending"
    );

    // The migrated records answer under the custody key — and only there.
    // A legacy-keyed store finds no live record and no readable PIN (the
    // G1 wall, from the verb side): after the marker, the legacy key is
    // dead.
    let (npub, sw) = call(&mut app, &apdu(INS_GET_PUBKEY, 0, &[]));
    assert_eq!(sw, SW_OK, "GET_PUBKEY is a public read, ungated");
    assert_eq!(&npub[..32], &identity(1).npub, "the identity survived the migration");

    let mut region = FileKeyRegion::open(&path).expect("the region file reads");
    // The marker opens only under the custody key (the store's own rule —
    // a legacy-keyed reader must not even learn that the reseat ran), so
    // the marker check is a custody-keyed store; the G1 wall below is the
    // legacy-keyed one.
    let secret = WORLD.with(|w| custody_secret_bytes(w.borrow().as_ref().unwrap().otp));
    let custody = derive_nostr_payload_key(
        &otp_row(),
        &chip_id(),
        NostrKeySource::Custody(secret.as_ref().expect("the custody rows read back")),
    )
    .expect("the custody key derives");
    let mut store = NostrStore::new(&mut region, &custody);
    assert!(store.reseat_complete().unwrap_or(false), "the marker stands");
    let mut region = FileKeyRegion::open(&path).expect("the region file reads");
    let key = legacy_key();
    let mut store = NostrStore::new(&mut region, &key);
    for index in 0..8u16 {
        assert!(
            !matches!(store.read(index).expect("slot readable"), Entry::Live(_)),
            "slot {index} still opens under the legacy key after the ceremony"
        );
    }
    assert!(
        matches!(
            store.read_pin().expect("pin slot readable"),
            PinEntry::Undecodable | PinEntry::Empty
        ),
        "the PIN record no longer opens under the legacy key"
    );
    std::fs::remove_file(&path).ok();
}
