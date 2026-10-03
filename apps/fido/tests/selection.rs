//! authenticatorSelection (CTAP2.1 §6.9, command 0x0B).
//!
//! ## What this file asserts, and what it deliberately refuses to assert
//!
//! US-1514 shipped this command as an unconditional `CTAP2_OK`. It is now
//! gated on user presence: `CTAP2_OK` **only** once a touch has landed,
//! `CTAP2_ERR_UP_REQUIRED` (0x3B) otherwise.
//!
//! There is deliberately **no `{up, uv}` matrix here**, because no such
//! parameters exist. The bug report for the X regression asked for one; it
//! was checked against the source before it was acted on and it is not real:
//!
//! * CTAP 2.1 PS-20210615 §6.9 and CTAP 2.2 RD-20241003 §6.9 are identical
//!   here and say "**The command has no input parameters.**"
//! * Chromium's request struct is empty — `struct
//!   CtapAuthenticatorSelectionRequest {};`, and `AsCTAPRequestValuePair`
//!   returns `std::nullopt` as the payload
//!   (`device/fido/ctap_authenticator_selection_request.{h,cc}`).
//! * `fido2` 2.2.1's `Ctap2.selection()` calls `send_cbor(CMD.SELECTION)`
//!   with `data=None`, so the frame is the bare opcode byte
//!   (`fido2/ctap2/base.py:576-591`, and `send_cbor` only encodes when
//!   `data is not None`).
//! * the reference dispatches it with no payload at all
//!   (`pico-fido2/src/fido/cbor.c:74` → `cbor_selection()`).
//!
//! So the only real dimension is *has the user touched the key*, and the
//! tests below pin that, on both twins, across the whole PIN/UV matrix — and
//! pin that the answer is **independent** of PIN state, which is the
//! assertion that would fail if anyone later invented an `up`/`uv` check.
//!
//! ## The twin trap (AGENTS.md §1)
//!
//! `app.rs` is a host-only twin; `device_core.rs` is what runs on the board.
//! Every assertion here runs on **both**, because a host-only test is what
//! let the original defect through: the host twin had `0x0B` since FX-415
//! while `device_app::process_ctap2` fell through to `_ =>` with
//! `CTAP1_ERR_INVALID_COMMAND`.
//!
//! ## The transport leg
//!
//! A gated answer is only reachable if the transport can carry it. `0x0B` is
//! in `presence_windowed` (`firmware/src/hid_serve.rs`), which is what turns
//! a bare `0x3B` into a consent window, a keepalive and a retry. The
//! membership of that predicate is pinned where it is defined, in
//! `hid_serve.rs`'s own scope test; `transport_predicate_covers_selection`
//! below re-reads the same source so this file fails on its own if the two
//! files disagree.

use fapico2_fido::app::FidoApp as HostApp;
use fapico2_fido::device_keystore::DeviceKeystore;
use fapico2_fido::keystore::{Keystore, MemoryKeystore};
use fapico2_fido::FidoApp as DeviceApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;

const OK: u8 = 0x00;
const UP_REQUIRED: u8 = 0x3B;

/// The four PIN/UV configurations the matrix runs. `alwaysUv` without a PIN
/// is not a state the `authenticatorConfig` UI will produce, but the kernel
/// can hold it after a `reset_from_seed` or a snapshot from another build, so
/// it is in the matrix: the point is that the answer does not move with any
/// of it.
const PIN_CONFIGS: [(&str, bool, bool); 4] = [
    ("no PIN, no alwaysUv", false, false),
    ("PIN set", true, false),
    ("PIN set + alwaysUv", true, true),
    ("no PIN + alwaysUv (synthetic)", false, true),
];

/// `with_user_presence` takes a bare `fn() -> bool`, so the two presence
/// answers are named functions rather than a captured bool.
fn no_press() -> bool {
    false
}

fn pressed() -> bool {
    true
}

/// A verifier in the shape a real `setPIN` leaves behind. The value is
/// irrelevant to selection — which is exactly what the matrix asserts.
fn fake_verifier() -> [u8; 16] {
    fapico2_fido::crypto::sha256(b"123123")[..16].try_into().unwrap()
}

/// The host twin, seeded with a chosen PIN/UV state and a chosen presence
/// answer. The keystore is seeded *before* it is moved into the app, because
/// `app.rs` keeps it private.
fn host(pin: bool, always_uv: bool, present: fn() -> bool) -> HostApp {
    let mut ks = MemoryKeystore::new();
    {
        let state = Keystore::get_pin_state_mut(&mut ks);
        if pin {
            state.pin_hash = Some(fake_verifier());
            state.retries = 8;
        }
        state.always_uv = always_uv;
    }
    HostApp::with_keystore(ks).with_user_presence(present)
}

/// The device twin — the app the RP2350 actually runs. Seeded by writing a
/// keystore snapshot into the store *before* `boot`, which is the only
/// supported way to reach a booted app in a chosen PIN/UV state without
/// running the ECDH `setPIN` ceremony.
fn device(pin: bool, always_uv: bool, present: fn() -> bool) -> DeviceApp {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    if pin || always_uv {
        let mut ks = DeviceKeystore::fresh(&mut trng).expect("host TRNG mints a fresh keystore");
        if pin {
            ks.pin_state.pin_hash = Some(fake_verifier());
            ks.pin_state.retries = 8;
        }
        ks.pin_state.always_uv = always_uv;
        ks.persist(&mut store).expect("the seeded snapshot must persist");
    }
    DeviceApp::boot(&mut trng, &mut store)
        .expect("host TRNG + store boot the device app")
        .with_user_presence(present)
}

fn selection_host(app: &mut HostApp) -> u8 {
    app.process_ctap2(0x0B, &[], [1, 2, 3, 4])[0]
}

fn selection_device(app: &mut DeviceApp) -> u8 {
    let mut out = HV::<u8, { fapico2_fido::CTAP2_MAX_MSG }>::new();
    let n = app.process_ctap2(0x0B, &[], [1, 2, 3, 4], &mut out);
    out[..n][0]
}

// ---------------------------------------------------------------------------
// The gate itself
// ---------------------------------------------------------------------------

/// CTAP2.1 §6.9: "If User Presence is received, the authenticator will return
/// CTAP2_OK." With no touch observed, `UpRequired` is the only other answer
/// this firmware can make truthfully — and it is the one the transport turns
/// into a prompt.
#[test]
fn selection_is_up_required_until_a_touch_lands() {
    let mut h = host(true, false, no_press);
    assert_eq!(selection_host(&mut h), UP_REQUIRED, "no touch → no selection");

    let mut d = device(true, false, no_press);
    assert_eq!(
        selection_device(&mut d),
        UP_REQUIRED,
        "the device twin is what runs on the board; it must not claim a user \
         selected it while nobody has touched it"
    );
}

#[test]
fn selection_is_ok_once_presence_is_granted() {
    let mut h = host(true, false, pressed);
    assert_eq!(selection_host(&mut h), OK);

    let mut d = device(true, false, pressed);
    assert_eq!(selection_device(&mut d), OK);
}

/// Parity across the whole matrix, driven on equal inputs. The two twins have
/// *different* presence defaults — the host build auto-acks, the device build
/// fails closed (`device_core::default_user_present` → `false`) — so parity
/// is asserted on equal inputs rather than on defaults.
#[test]
fn twins_agree_on_the_whole_matrix() {
    for (label, pin, always_uv) in PIN_CONFIGS {
        for p in [no_press, pressed] {
        let present = p();
        let _ = present;
            let expected = if present { OK } else { UP_REQUIRED };
            let mut h = host(pin, always_uv, p);
            let mut d = device(pin, always_uv, p);
            assert_eq!(
                selection_device(&mut d),
                selection_host(&mut h),
                "twins disagree on [{label}, present={present}]"
            );
            assert_eq!(selection_host(&mut h), expected, "[{label}, present={present}]");
            assert_eq!(
                selection_device(&mut d),
                expected,
                "[{label}, present={present}] device twin"
            );
        }
    }
}

/// The negative-form assertion, which is the one that actually pins the
/// *absence* of an `up`/`uv` check. If someone later parses an `up`/`uv` map
/// and varies the answer by PIN state or `alwaysUv`, this goes red — which is
/// correct, because no client sends those parameters.
#[test]
fn selection_answer_does_not_vary_with_pin_or_uv_state() {
    for p in [no_press, pressed] {
        let present = p();
        let _ = present;
        let baseline = selection_device(&mut device(false, false, p));
        for (label, pin, always_uv) in PIN_CONFIGS {
            let got = selection_device(&mut device(pin, always_uv, p));
            assert_eq!(
                got, baseline,
                "[{label}, present={present}]: the command has no input \
                 parameters, so PIN/UV state cannot and must not move the answer"
            );
        }
    }
}

/// Every payload shape a client can actually produce, on both twins. The
/// shapes that look like an `up`/`uv` request are here **on purpose**: they
/// are what a hypothetical client would send if the command had parameters,
/// and the assertion is that they change nothing, because it does not.
#[test]
fn selection_ignores_its_payload() {
    const SHAPES: [&[u8]; 6] = [
        b"",                     // bare opcode — `fido2`, Chromium
        b"\xa0",                 // empty map
        b"\xa2\x01\x00\x02\x00", // {1: up=false, 2: uv=false}
        b"\xa2\x01\x01\x02\x01", // {1: up=true,  2: uv=true}
        b"\xa2\x01\x01\x02\x00", // {1: up=true,  2: uv=false}
        b"\xff\xff\xff",         // not CBOR at all
    ];
    for p in [no_press, pressed] {
        let present = p();
        let _ = present;
        for shape in SHAPES {
            let expected = if present { OK } else { UP_REQUIRED };

            let mut h = host(true, true, p);
            assert_eq!(
                h.process_ctap2(0x0B, shape, [1, 2, 3, 4])[0],
                expected,
                "host twin must ignore the payload"
            );

            let mut d = device(true, true, p);
            let mut out = HV::<u8, { fapico2_fido::CTAP2_MAX_MSG }>::new();
            let n = d.process_ctap2(0x0B, shape, [1, 2, 3, 4], &mut out);
            assert_eq!(
                out[..n][0],
                expected,
                "device twin must ignore the payload exactly as the host twin does"
            );
        }
    }
}

/// Before US-1514 the device dispatch had no `0x0B` arm at all and the `_ =>`
/// fallthrough produced `CTAP1_ERR_INVALID_COMMAND`. Naming that byte keeps
/// it from coming back through some other route to the same answer.
#[test]
fn device_twin_does_not_answer_invalid_command() {
    for p in [no_press, pressed] {
        let present = p();
        let _ = present;
        let got = selection_device(&mut device(false, false, p));
        assert_ne!(
            got, 0x01,
            "0x0B fell through to the `_ =>` arm again: the emulator can \
             select and the board cannot"
        );
    }
}

// ---------------------------------------------------------------------------
// Coherence: the answer must agree with what the next command actually does
// ---------------------------------------------------------------------------

/// The same rule US-1529 applied to `makeCredUvNotRqd`: a status byte is
/// worthless unless it is coherent with the behaviour it advertises.
///
/// Coherence has exactly two directions, and both are checked on the device
/// twin across the matrix:
///
/// * with no touch, selection says `UpRequired` **and** the makeCredential
///   that follows it does not succeed. The refusal code differs by PIN state
///   and both are honest, which is why this asserts the class and not one
///   byte: on a PIN-less device the presence gate is what fires (`0x3B`), and
///   on a PIN-set device the UV gate fires first (`0x36` — `make_credential_inner`
///   checks `always_uv`/`pinUvAuthToken` *before* `user_present`, so UV wins).
///   A selection that answered `OK` here would be promising a ceremony the
///   device then refuses — the "I can satisfy whatever you're asking"
///   incoherence this change exists to remove;
/// * with a touch, selection says `OK` **and** the makeCredential is no
///   longer refused *for presence*. It is still refused with `0x36` on a
///   PIN-set device, which is correct and orthogonal; what must not happen is
///   a `0x3B` after a selection that already said `OK`.
#[test]
fn selection_is_coherent_with_the_make_credential_that_follows_it() {
    // A bare makeCredential: clientHash, rp, user, pubKeyCredParams — no
    // `options`, no `pinUvAuthParam`. Exactly what a client sends first.
    fn mc_bare() -> Vec<u8> {
        use fapico2_fido::cbor::no_heap as nh;
        let mut r: HV<u8, 512> = HV::new();
        nh::push_map_header(&mut r, 4).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_bstr(&mut r, &[0x5Au8; 32]).unwrap();
        nh::push_uint(&mut r, 2).unwrap();
        nh::push_map_header(&mut r, 2).unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_tstr(&mut r, "example.com").unwrap();
        nh::push_tstr(&mut r, "name").unwrap();
        nh::push_tstr(&mut r, "RP").unwrap();
        nh::push_uint(&mut r, 3).unwrap();
        nh::push_map_header(&mut r, 2).unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_bstr(&mut r, b"user-1").unwrap();
        nh::push_tstr(&mut r, "name").unwrap();
        nh::push_tstr(&mut r, "U").unwrap();
        nh::push_uint(&mut r, 4).unwrap();
        nh::push_array_header(&mut r, 1).unwrap();
        nh::push_map_header(&mut r, 2).unwrap();
        nh::push_tstr(&mut r, "type").unwrap();
        nh::push_tstr(&mut r, "public-key").unwrap();
        nh::push_tstr(&mut r, "alg").unwrap();
        nh::push_neg(&mut r, -7).unwrap();
        r.to_vec()
    }

    fn mc_device(app: &mut DeviceApp) -> u8 {
        let mut out = HV::<u8, { fapico2_fido::CTAP2_MAX_MSG }>::new();
        let n = app.process_ctap2(0x01, &mc_bare(), [1, 2, 3, 4], &mut out);
        out[..n][0]
    }

    for (label, pin, always_uv) in PIN_CONFIGS {
        // (a) no touch: selection demands a human, and makeCredential does
        // not succeed. The refusal code differs by PIN state (see the doc
        // comment); both are "a human is required" answers.
        let mut d = device(pin, always_uv, no_press);
        assert_eq!(selection_device(&mut d), UP_REQUIRED, "[{label}] selection");
        let mc = mc_device(&mut d);
        assert_ne!(
            mc, OK,
            "[{label}] a selection that demanded a touch, followed by a \
             makeCredential that minted a credential without one, is the \
             incoherence this change removes"
        );
        assert!(
            matches!(mc, 0x3B | 0x36 | 0x35),
            "[{label}] the refusal must be a \"a human is required\" code \
             (UpRequired 0x3B / PuatRequired 0x36 / PinNotSet 0x35), got {mc:#04x}"
        );

        // (b) touch granted: selection says OK, and makeCredential is not
        // then refused for presence.
        let mut d = device(pin, always_uv, pressed);
        assert_eq!(selection_device(&mut d), OK, "[{label}] selection");
        assert_ne!(
            mc_device(&mut d),
            UP_REQUIRED,
            "[{label}] makeCredential asked for a touch that selection had \
             already been granted — the answer and the behaviour disagree"
        );
    }
}

// ---------------------------------------------------------------------------
// The transport leg
// ---------------------------------------------------------------------------

/// A gated answer is unreachable unless the transport carries it. This reads
/// the same source `hid_serve.rs`'s own scope test reads, so the two files
/// cannot drift without one of them failing.
#[test]
fn transport_predicate_covers_selection() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../firmware/src/hid_serve.rs"
    ))
    .expect("firmware/src/hid_serve.rs must be readable from this crate");
    let start = src
        .find("let up_request =")
        .expect("the dispatch must bind `up_request`");
    let end = src[start..]
        .find("if presence_windowed && slot.is_occupied()")
        .map(|i| start + i)
        .expect("the predicates must precede the refusal arm");
    let preds = &src[start..end];
    assert!(
        preds.contains("ctap_cmd == 0x0B"),
        "0x0B answers UpRequired until a touch lands, so it must be in \
         `presence_windowed` or that status goes out as a bare error frame \
         and no window ever opens: {preds}"
    );
    assert!(
        !preds.contains("ctap_cmd == 0x09"),
        "0x09 (bio enrollment) is still unimplemented and must not be \
         presence_windowed"
    );
}