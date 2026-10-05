//! US-1600 — the **baseline** for the `authenticatorReset` presence gate.
//!
//! ```gherkin
//! Scenario: unauthenticated reset currently destroys the device
//!   Given a device with a PIN set and one resident credential
//!   When authenticatorReset (0x07) is sent with an empty body and no pinUvAuthToken
//!   Then the command answers 0x00
//!   And the credential is gone and the PIN is cleared
//!   And the response arrives without a consent window
//! ```
//!
//! # What this file is, and what it is not
//!
//! **It is a characterisation test, not a specification.** Every assertion
//! below passes on today's tree, and that is the point: it records the
//! measured behaviour *before* US-1602/US-1603 put a gate on this command, so
//! the flip is visible as red→green rather than as a change nobody can date.
//! The measurement came from the live board (red-team assessment,
//! `redteam/SECURITY_ASSESSMENT.md`, 2026-10-05): one frame, opcode `0x07`,
//! empty CBOR body, no `pinUvAuthToken`, answered `0x00` in **498 ms**.
//!
//! **It is not the gate's test.** US-1601's red test and US-1602's green
//! pair live in the same file, below the baseline section, so the two states
//! of this command can be read side by side rather than in separate commits.
//!
//! # Why "no consent window" is asserted by *elapsed latency* here
//!
//! The transport half of the gate is US-1604/US-1605
//! (`firmware/src/hid_serve.rs`'s `presence_windowed`), and that test belongs
//! against the transport seam, not against a host-timed call. What this file
//! can honestly assert from the app side is the thing that *proves* no window
//! opened: a windowed command parks for up to `CTAP_TOUCH_WINDOW_MS` (30 s)
//! while a dispatch-immediate one returns in well under a second. 498 ms is
//! three orders of magnitude below the window, so a sub-second answer is
//! positive evidence that the command was never parked — not merely an absence
//! of evidence that it was.
//!
//! # The twin trap (AGENTS.md §1)
//!
//! Both twins are driven, because both are ungated today and only fixing one
//! is the failure this epic is written against. `device_core.rs` is what runs
//! on the RP2350; `app.rs` is a host twin whose `0x07` arm answers `Ok`
//! unconditionally (`app.rs:698-702`). The host twin has no key region, so the
//! "credential is gone" half is asserted on the device twin only, and the
//! *status* half is asserted on both — which is the half a client sees.
//!
//! # The presence source is a global, so the tests serialise
//!
//! `set_presence_grant` takes a bare `fn(u32) -> bool` and cannot capture, so
//! the injected source reads a process-global flag — exactly the constraint
//! `tests/presence_gating.rs` documents. `cargo test` runs a file's tests in
//! one process across threads, so every test here holds [`TEST_LOCK`] for its
//! whole body.

mod region_boot;

use fapico2_fido::app::FidoApp as HostApp;
use fapico2_fido::keystore::{Keystore, MemoryKeystore};
use region_boot::{lock, Device};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// The presence source
// ---------------------------------------------------------------------------

/// `true` = the injected source **denies** a press.
///
/// Fail-by-default is the deliberate starting posture: every scenario here is
/// about what happens when a human has *not* consented, and a test that
/// defaulted to "consented" would only ever exercise the answer nobody is
/// trying to change.
static PRESENCE_DENIED: AtomicBool = AtomicBool::new(true);

fn injected_presence() -> bool {
    !PRESENCE_DENIED.load(Ordering::SeqCst)
}

static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Serialise against the process-global presence flag.
///
/// `unwrap_or_else(|e| e.into_inner())` rather than `unwrap()`: a test that
/// panicked while holding the lock poisons it, and every later test would then
/// fail on the *poison*, hiding the real failure. Same reason as
/// `region_boot::lock`.
fn presence_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Constants, transcribed not derived
// ---------------------------------------------------------------------------

/// `CTAP2_OK`.
const OK: u8 = 0x00;
/// `CTAP2_ERR_PIN_NOT_SET` — what credMgmt answers once the reset cleared the
/// PIN, and therefore how "the PIN is cleared" is observed from the wire.
const PIN_NOT_SET: u8 = 0x35;
/// `existingResidentCredentialsCount`, key 1 of credMgmt `getCredsMetadata`.
const METADATA_RESIDENT_COUNT: u64 = 0x01;

/// The ceiling this file asserts against the reset's wall-clock.
///
/// The device's consent window is `CTAP_TOUCH_WINDOW_MS` = 30 s. Anything
/// under a second is therefore not a parked command: a windowed command
/// cannot answer sooner than the button is pressed or the window closes, and
/// the measurement was 498 ms with no button anywhere near the board.
///
/// The constant is deliberately a **thousand** below the window rather than
/// "some small number": it is a claim about an order of magnitude, which is
/// what actually distinguishes the two behaviours, and it would survive a
/// slower CI machine while still failing a command that parked.
const WINDOWLESS_CEILING_MS: u128 = 1_000;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// A device twin with a PIN set, one resident credential, and the
/// **toggleable** presence source attached.
///
/// The region is installed (so the credential really lives on the medium the
/// gate must not erase) and the caller must already hold [`lock`].
///
/// The grant attached after the fixture is built is **not** a hard `false`: it
/// is the same flag-reading source the host twin gets, so one `PRESENCE_DENIED`
/// flip drives both twins and the parity test compares like with like. A hard
/// `deny` here would have made this fixture refuse unconditionally, which is
/// right for the refusal scenarios and wrong for the parity matrix — a bug
/// worth naming because it produced a green suite once already.
fn pinned_device(tag: &str) -> (region_boot::InstalledRegion, Device) {
    let region_file = region_boot::install(tag);
    let mut device = Device::boot(region_boot::keyed_store());
    // Presence has to be granted for setPIN/makeCredential to get anywhere, so
    // enrolment uses the hard-true grant. **The flag is deliberately not
    // touched here** — that hard grant is what carries the fixture, so the
    // caller's value survives the build and there is no ordering trap between
    // "set the flag" and "make the fixture". The flagged source is installed
    // last, replacing it.
    device.grant_presence_always();
    device.set_pin(b"123456");
    let (status, cbor) = device.make_cred("example.test", b"user-1");
    assert_eq!(status, OK, "fixture enrolment: {cbor:02x?}");

    // From here on, the caller's flag decides. `fn` pointers cannot capture, so
    // this reads the same process-global the host twin reads — which is what
    // makes one flip drive both twins in the parity matrix.
    device.with_presence_grant(flagged_presence);
    (region_file, device)
}

/// The flag-reading presence source, in the `fn(u32) -> bool` shape the device
/// twin's grant seam takes. Named rather than inlined so the fixture and any
/// future caller install the *same* function.
fn flagged_presence(_tag: u32) -> bool {
    injected_presence()
}

/// The host twin in the same state: PIN set, one resident credential, presence
/// denied.
///
/// The host twin's keystore is private, so the PIN is seeded the way
/// `tests/selection.rs` seeds it — through the keystore, before the app is
/// built around it. Its credential store is host-file CBOR with no key region
/// at all (`twin_parity.rs`'s module docs), so only the **status** and the PIN
/// advertisement are comparable across the twins, and that is what is asserted.
fn pinned_host() -> HostApp {
    let mut ks = MemoryKeystore::new();
    {
        let state = Keystore::get_pin_state_mut(&mut ks);
        state.pin_hash = Some(fapico2_fido::crypto::sha256(b"123123")[..16].try_into().unwrap());
        state.retries = 8;
    }
    HostApp::with_keystore(ks).with_user_presence(injected_presence)
}

// ---------------------------------------------------------------------------
// US-1600 — the baseline, as it stood before the gate. These pass today; that
// is the finding.
//
// **They are `#[ignore]`d now, and that is the record of the flip.** US-1600's
// acceptance was that they *pass* against the ungated tree, which they did.
// US-1602 changed the behaviour they characterise, so they would now fail —
// and a test that fails after the fix is a test that has to be deleted, which
// is the one way a measurement can be lost. Kept and ignored, they say what
// the device did on 2026-10-05, and `cargo test -- --ignored` runs them
// whenever someone wants to see the before-state reproduced.
// ---------------------------------------------------------------------------

/// **Before US-1602: an unauthenticated `0x07` destroyed the device.**
///
/// Red-team F1 as measured: one frame, one opcode, no PIN, no access code, no
/// touch. Ignored rather than deleted — see the section header.
#[test]
#[ignore = "US-1600 baseline. Characterises the UNGATED tree; the gate landed in US-1602 and \
             this test now fails by design. Kept as the measured before-state."]
fn unauthenticated_reset_currently_answers_ok_and_destroys_the_device() {
    let _presence = presence_lock();
    PRESENCE_DENIED.store(true, Ordering::SeqCst);
    let _lock = lock();
    let (_region_file, mut device) = pinned_device("us1600-baseline");

    // Before: the credential is really enrolled, or the wipe proves nothing.
    {
        let (status, cbor) = device.cm_get_metadata();
        assert_eq!(status, OK, "getCredsMetadata before the reset: {cbor:02x?}");
        assert_eq!(
            region_boot::uint_at(&cbor, METADATA_RESIDENT_COUNT),
            Some(1),
            "the fixture must hold one resident credential before the reset",
        );
    }

    // The attack: opcode `0x07`, empty CBOR body, **no pinUvAuthToken** in
    // `subCommandParams` because there are no sub-command parameters at all.
    // `python-fido2` sends exactly this frame.
    let (status, body) = device.call(0x07, &[]);

    assert_eq!(
        status, OK,
        "the baseline IS that this answers OK: unauthenticated {status:#04x} / {body:02x?} — \
         if this now fails, the gate landed and this characterisation belongs in \
         the section below",
    );

    // The PIN is cleared. `reset_from_seed` rotates `device_random`, and credMgmt
    // is PIN-gated, so the wire symptom is `PIN_NOT_SET`.
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(
        status, PIN_NOT_SET,
        "an authenticatorReset clears the PIN; if this is now OK, the PIN survived the reset \
         ({cbor:02x?})",
    );

    // And the credential set is empty: re-establish a session and read the
    // number a user would actually check.
    device.set_pin(b"87654321");
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(status, OK, "getCredsMetadata after the reset: {cbor:02x?}");
    assert_eq!(
        region_boot::uint_at(&cbor, METADATA_RESIDENT_COUNT),
        Some(0),
        "the credential the owner enrolled is gone — that is the destruction F1 reports",
    );
}

/// **The reset answers without ever asking for a consent window.**
///
/// Split from the scenario above because it is a *different* claim about a
/// *different layer*, and conflating them is how the root cause stayed hidden
/// for as long as it did: the app arm has no gate and the transport predicate
/// has no `0x07`, so there are **two** independent reasons the command was
/// dispatched immediately. Fixing only one still destroys the device on the
/// other's path.
///
/// The 30 s window is the discriminator, and it is the transport's own
/// constant — `CTAP_TOUCH_WINDOW_MS` — restated here as a ceiling rather than
/// imported, because the firmware crate is not a dependency of this one and a
/// second literal that agreed with the first would be a second thing to keep
/// in step. See `firmware/src/hid_serve.rs` for the transport half.
#[test]
#[ignore = "US-1600 baseline. The UNGATED tree answered in 498ms with no window; the gate \
             landed in US-1602/1605 and this now fails by design. Kept as the measurement."]
fn reset_currently_answers_windowless() {
    let _presence = presence_lock();
    PRESENCE_DENIED.store(true, Ordering::SeqCst);
    let _lock = lock();
    let (_region_file, mut device) = pinned_device("us1600-latency");

    let start = std::time::Instant::now();
    let (status, _) = device.call(0x07, &[]);
    let elapsed = start.elapsed();

    assert_eq!(status, OK, "the baseline answer is OK: {status:#04x}");
    assert!(
        elapsed.as_millis() < WINDOWLESS_CEILING_MS,
        "an authenticatorReset answered in {}ms. The consent window is 30s, so a sub-second \
         answer is positive proof that no window was ever opened for this command — which is \
         the second half of the root cause (the transport's `presence_windowed` predicate does \
         not name 0x07, just as `handle_reset` asks for no presence)",
        elapsed.as_millis(),
    );
}

/// **Before US-1603: the host twin was identically ungated.**
///
/// `AGENTS.md` §1 is why this was worth its own assertion: a fix applied to
/// only one twin passes every host test and changes nothing on hardware.
/// `app.rs`'s `0x07` arm was a bare `Ok` with no gate at all.
///
/// The credential half is not assertable on the host twin — it has no key
/// region, and `twin_parity.rs` records that divergence at the type level
/// rather than papering over it. The PIN advertisement is: the host twin's
/// `getInfo` reads `pin_hash`, and an `authenticatorReset` clears it, so
/// `clientPin` going `true → false` is the same destruction the device twin
/// shows, observable through the twin's own encoder.
#[test]
#[ignore = "US-1600 baseline. Characterises the UNGATED host twin; the gate landed in US-1603 \
             and this now fails by design. Kept as the measured before-state."]
fn the_host_twin_is_identically_ungated_today() {
    let _presence = presence_lock();
    PRESENCE_DENIED.store(true, Ordering::SeqCst);
    let mut app = pinned_host();

    assert_eq!(
        client_pin_option(&mut app),
        Some(true),
        "the fixture must start with a PIN set, or this asserts nothing",
    );

    let status = app.process_ctap2(0x07, &[], [1, 2, 3, 4])[0];
    assert_eq!(
        status, OK,
        "the host twin answers OK unconditionally at this command today ({status:#04x})"
    );
    assert_eq!(
        client_pin_option(&mut app),
        Some(false),
        "app.rs's 0x07 arm resets the keystore, so the PIN is gone — the same destruction the \
         device twin shows, through the twin's own encoder",
    );
}

/// Read getInfo's `clientPin` option off the host twin's wire response.
///
/// The **encoded** bytes rather than a struct field: `app.rs` builds a
/// `Ctap2Info` and encodes it, and a test that read the struct would be
/// asserting against the thing the encoder was fed rather than the thing a
/// client decodes. This is the same discipline `reset_wipes_region.rs` states
/// about reading CBOR off the wire.
fn client_pin_option(app: &mut HostApp) -> Option<bool> {
    use fapico2_fido::cbor::{self, Value};
    let resp = app.process_ctap2(0x04, &[], [1, 2, 3, 4]);
    assert_eq!(resp[0], OK, "getInfo must succeed");
    let (decoded, _) = cbor::decode(&resp[1..]).expect("getInfo body must be valid CBOR");
    let Value::M(map) = decoded else {
        panic!("getInfo must be a CBOR map")
    };
    // `options` is key 0x04 and is itself a map of string keys.
    let Value::M(options) = map
        .iter()
        .find(|(k, _)| matches!(k, Value::U(0x04)))
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("getInfo must carry an options map at key 0x04"))
    else {
        panic!("getInfo options (key 0x04) must be a map")
    };
    options
        .iter()
        .find(|(k, _)| matches!(k, Value::T(s) if s == "clientPin"))
        .and_then(|(_, v)| match v {
            Value::Bool(b) => Some(*b),
            _ => None,
        })
}

// ---------------------------------------------------------------------------
// US-1601 — red. Presence denial is not expressible for reset.
// ---------------------------------------------------------------------------

/// **With no presence grant, `0x07` must be refused and nothing erased.**
///
/// This is the red half, and on today's tree it fails at the **first**
/// assertion — the answer is `0x00` rather than a presence-required status.
/// The second assertion (nothing erased) is the one that would catch a fix
/// placed *after* the erase, which is the ordering this epic's constraint 4
/// forbids and which a status-only fix would sail past.
///
/// ## The byte
///
/// `UP_REQUIRED` = `0x3B`, read from `tests/status_table.rs`'s `REFERENCE`
/// table (executed against `CtapError.ERR` in `fido2` 2.2.1 and
/// `CTAP2_ERR_*` in `pico-fido2/src/fido/ctap.h`), and it is the byte
/// `handle_authenticator_selection` already answers for the same situation.
///
/// The epic's own draft guessed `0x24`. That is `OperationPending`, a
/// different sentence — "an operation is already pending", which is a claim
/// about another request rather than about a missing human — and it is the
/// byte the transport itself uses when it *refuses* a mid-window command
/// (`hid_serve.rs`, `presence_windowed && slot.is_occupied()`). Pinning it
/// against the executed table rather than the guess is what the epic asked
/// for.
const UP_REQUIRED: u8 = 0x3B;

/// Two constants, never derived: a test that computed its expectation from the
/// table it is testing would pass no matter how wrong the table got. These are
/// transcribed from `tests/status_table.rs`'s `REFERENCE`, which is itself
/// transcribed from the reference and the client library.
#[test]
fn reset_with_no_presence_grant_is_refused_and_erases_nothing() {
    let _presence = presence_lock();
    PRESENCE_DENIED.store(true, Ordering::SeqCst);
    let _lock = lock();
    let (_region_file, mut device) = pinned_device("us1601-red");

    let (status, body) = device.call(0x07, &[]);
    assert_eq!(
        status, UP_REQUIRED,
        "an authenticatorReset with no press must answer UP_REQUIRED (0x3B). It answered \
         {status:#04x} / {body:02x?} — `device_app.rs`'s dispatch arm calls `self.handle_reset(out)` \
         with no presence check, and `handle_reset` itself asks for none, so the one operation \
         that cannot be undone is the one operation nobody has to touch the key for.",
    );

    // And the credential survives — read *before* the PIN is disturbed, so the
    // evidence is the count itself and not a `PIN_NOT_SET` that would pass just
    // as well against a device that destroyed everything.
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(
        status, OK,
        "the session token must still be live: a refusal that also killed the PIN would be \
         {status:#04x} / {cbor:02x?}",
    );
    assert_eq!(
        region_boot::uint_at(&cbor, METADATA_RESIDENT_COUNT),
        Some(1),
        "the owner's credential must survive a refused reset — consent is obtained BEFORE the \
         durable erase, so a refusal after the wipe would be a lie about state that is already gone",
    );
}

// ---------------------------------------------------------------------------
// US-1602 — green, device twin.
// ---------------------------------------------------------------------------

/// **A refused reset erases nothing *on the medium*, not merely in RAM.**
///
/// The assertion above reads the count over the wire, which is what a client
/// sees. This one reads the flash, because the two failures are different and
/// only one of them is what F1 is about: a gate placed after
/// `wipe_region_credentials()` would still leave every record **on flash**
/// while reporting a clean refusal, and the index key is device-rooted and
/// PIN-free (`crypto::derive_index_key_from_root`), so those records would be
/// readable by anyone with a dump.
#[test]
fn a_refused_reset_erases_nothing_from_the_region() {
    let _presence = presence_lock();
    PRESENCE_DENIED.store(true, Ordering::SeqCst);
    let _lock = lock();
    let (region_file, mut device) = pinned_device("us1602-no-erase");

    // Before: the region really holds the record, or "still there" is vacuous.
    {
        let mut r = region_boot::FileKeyRegion::open(region_file.path()).expect("reopen the region");
        assert!(
            !region_boot::all_erased(&mut r, region_boot::FIDO_FIRST_SLOT, region_boot::FIDO_SLOT_LIMIT),
            "the fixture must not start with an already-erased FIDO range",
        );
    }

    let (status, _) = device.call(0x07, &[]);
    assert_eq!(status, UP_REQUIRED, "with no press the reset is refused");

    region_file.with(|r| {
        assert!(
            !region_boot::all_erased(r, region_boot::FIDO_FIRST_SLOT, region_boot::FIDO_SLOT_LIMIT),
            "a REFUSED authenticatorReset erased the FIDO record range. The gate must run before \
             the durable wipe, not after it: a refusal that has already destroyed the records is \
             a lie about state that is gone, and the index key is device-rooted and PIN-free, so \
             the survivors would be readable from a flash dump without ever knowing the PIN",
        );
        assert!(
            !region_boot::all_erased(r, region_boot::INDEX_FIRST_SLOT, region_boot::TOTAL_SLOTS),
            "a refused reset erased the index. The index is device-rooted and PIN-free — it is the \
             thing US-1547/S1 called out precisely because it survives everything else",
        );
    });
}

/// **With a press, the reset proceeds exactly as before.**
///
/// The guard against "always refuse", and the reason the story carries both
/// halves. A device that cannot be reset at all is not more secure than one
/// that can be reset by anyone — it is broken, and AGENTS.md §5's capacity
/// floor argument applies to the owner's ability to *use* the device too.
#[test]
fn reset_with_a_presence_grant_proceeds_and_destroys_the_device() {
    let _presence = presence_lock();
    let _lock = lock();
    let (region_file, mut device) = pinned_device("us1602-granted");
    // After the fixture, which needs a touch to enrol: this is the state the
    // reset is exercised in.
    PRESENCE_DENIED.store(false, Ordering::SeqCst);

    let (status, body) = device.call(0x07, &[]);
    assert_eq!(
        status, OK,
        "with a presence grant the reset must still succeed — a gate that can only refuse is not \
         a gate ({status:#04x} / {body:02x?})",
    );

    // The PIN is cleared and the credential set emptied: the primitive did its
    // job, unchanged.
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(
        status, PIN_NOT_SET,
        "an accepted authenticatorReset clears the PIN ({status:#04x} / {cbor:02x?})",
    );
    device.set_pin(b"87654321");
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(status, OK, "getCredsMetadata after the reset: {cbor:02x?}");
    assert_eq!(
        region_boot::uint_at(&cbor, METADATA_RESIDENT_COUNT),
        Some(0),
        "an accepted reset must still empty the credential set — the gate changed when the \
         command is allowed, not what it does",
    );

    region_file.with(|r| {
        assert!(
            region_boot::all_erased(r, region_boot::FIDO_FIRST_SLOT, region_boot::FIDO_SLOT_LIMIT),
            "an accepted reset must still erase the FIDO record range",
        );
    });
}

// ---------------------------------------------------------------------------
// US-1603 — green, host twin, and twin parity.
// ---------------------------------------------------------------------------

/// **The host twin refuses with the same byte and keeps its PIN.**
///
/// `AGENTS.md` §1 in its most direct form: a gate on one twin only passes
/// every host test and changes nothing on hardware. The PIN advertisement is
/// the observable here — the host twin has no key region, and
/// `twin_parity.rs` records that divergence at the type level rather than
/// hiding it.
#[test]
fn the_host_twin_refuses_reset_with_presence_denied() {
    let _presence = presence_lock();
    PRESENCE_DENIED.store(true, Ordering::SeqCst);
    let mut app = pinned_host();

    assert_eq!(client_pin_option(&mut app), Some(true), "the fixture starts with a PIN");

    let status = app.process_ctap2(0x07, &[], [1, 2, 3, 4])[0];
    assert_eq!(
        status, UP_REQUIRED,
        "the host twin must refuse an unauthenticated reset with the same byte the device twin \
         uses ({status:#04x})",
    );
    assert_eq!(
        client_pin_option(&mut app),
        Some(true),
        "a REFUSED reset must not clear the PIN on the host twin either — the refusal is \
         upstream of every effect",
    );
}

/// **The host twin still resets when the press lands.**
#[test]
fn the_host_twin_resets_with_a_presence_grant() {
    let _presence = presence_lock();
    PRESENCE_DENIED.store(false, Ordering::SeqCst);
    let mut app = pinned_host();

    let status = app.process_ctap2(0x07, &[], [1, 2, 3, 4])[0];
    assert_eq!(status, OK, "with a grant the host twin still resets");
    assert_eq!(
        client_pin_option(&mut app),
        Some(false),
        "an accepted reset clears the PIN on the host twin",
    );
}

/// **The twins agree, on both presence states.**
///
/// Asserted on *equal inputs* rather than on defaults, because the two twins
/// have deliberately different build defaults: the host build auto-acks and the
/// device build fails closed (`device_core::default_user_present`). Comparing
/// defaults would assert a divergence and prove nothing about the command.
#[test]
fn the_twins_agree_on_the_reset_gate() {
    let _presence = presence_lock();
    let _lock = lock();

    for denied in [true, false] {
        let expected = if denied { UP_REQUIRED } else { OK };

        // Build the fixtures first: `pinned_device` sets the flag itself (the
        // enrolment needs a touch), so the value under test is set *after* both
        // twins are in their post-fixture state.
        let mut h = pinned_host();
        let (_region_file, mut d) = pinned_device(if denied { "twin-deny" } else { "twin-grant" });
        // The flag is set once, for both twins, and `pinned_device` leaves it
        // alone — so there is no ordering question about which value each
        // fixture ended up with.
        PRESENCE_DENIED.store(denied, Ordering::SeqCst);

        let host = h.process_ctap2(0x07, &[], [1, 2, 3, 4])[0];
        let (device, _) = d.call(0x07, &[]);
        assert_eq!(
            host, expected,
            "host twin, denied={denied}: {host:#04x}",
        );
        assert_eq!(
            device, expected,
            "device twin, denied={denied}: {device:#04x} — the twins must answer the same byte \
             for the same injected presence state, or the emulator and the board disagree about \
             whether destroying the device needs a touch",
        );
    }
}