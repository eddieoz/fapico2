//! FX-415 / US-1514: authenticatorSelection (CTAP2.1 §6.3, command 0x0B).
//!
//! The story is a **parity** story. Before it, `0x0B` had an arm on the host
//! twin (`app.rs`) and none on the device twin (`device_app.rs`), so the
//! `process_ctap2` dispatch fell through to `_ =>` with
//! `CTAP2_ERR_INVALID_COMMAND` — the emulator could do something the board
//! could not. Every test here drives **both** twins and asserts the same
//! bytes, because a host-twin-only test is what let the hole through in the
//! first place (AGENTS.md §1: `app.rs` is a twin, not the shipped firmware).

use fapico2_fido::app::FidoApp as HostApp;
use fapico2_fido::keystore::MemoryKeystore;
use fapico2_fido::FidoApp as DeviceApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;

/// The host twin: `FidoApp<K: Keystore>`, `process_ctap2 -> Vec<u8>`.
fn host() -> HostApp {
    HostApp::with_keystore(MemoryKeystore::new())
}

/// The device twin: the app the RP2350 actually runs, booted through the
/// platform `SecureStore` (the in-memory store + partition image on host).
/// `fapico2_fido::FidoApp` is re-exported from `device_app.rs` at the crate
/// root; the host twin is `fapico2_fido::app::FidoApp`. Mixing those two up
/// is the easiest mistake in this area, so the aliases are spelled out above.
fn device() -> DeviceApp {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    DeviceApp::boot(&mut trng, &mut store).expect("host TRNG + store boot the device app")
}

/// Run `0x0B` against both twins and return `(host_bytes, device_bytes)`.
fn selection_on_both(payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut h = host();
    let host_resp = h.process_ctap2(0x0B, payload, [1, 2, 3, 4]);

    let mut d = device();
    let mut out = HV::<u8, { fapico2_fido::CTAP2_MAX_MSG }>::new();
    let n = d.process_ctap2(0x0B, payload, [1, 2, 3, 4], &mut out);

    (host_resp, out[..n].to_vec())
}

#[test]
fn test_authenticator_selection_returns_ok() {
    let mut app = host();
    // The reference C firmware auto-accepts selection in its default build
    // (`cbor_selection.c`'s button gate is behind `#ifdef FORCE_BUTTON_WAIT`,
    // which CMake does not define unless asked); the command must be
    // dispatched (previously unhandled → InvalidCommand).
    let resp = app.process_ctap2(0x0B, &[], [1, 2, 3, 4]);
    assert_eq!(resp, vec![0x00], "authenticatorSelection must return CTAP2_OK");
}

/// US-1514's acceptance criterion, stated as the test that can fail: the two
/// twins answer the same request with the same bytes. The host-only
/// assertion above passed while the board answered INVALID_COMMAND, so this
/// is the one that has to be here.
#[test]
fn device_twin_answers_selection_exactly_as_the_host_twin() {
    let (host_resp, device_resp) = selection_on_both(&[]);
    assert_eq!(
        device_resp, host_resp,
        "the device twin is what runs on the board; it must answer \
         authenticatorSelection exactly as the host twin does"
    );
    assert_eq!(device_resp, vec![0x00]);
}

/// `fido2`'s `Ctap2.selection()` sends a **bare** command byte — no CBOR
/// body at all (`send_cbor(Cmd.SELECTION, ...)`, and `send_cbor` only
/// appends `cbor.encode(data)` when `data is not None`). The device arm must
/// therefore not parse `data`: the empty payload is the shape a real client
/// sends, and a parser that demanded a map would reject the common case.
/// A stray trailing byte is equally irrelevant — the reference ignores it.
#[test]
fn selection_ignores_its_payload() {
    let (empty, empty_device) = selection_on_both(&[]);
    let (garbage, garbage_device) = selection_on_both(b"anything");
    assert_eq!(garbage, empty, "host twin must ignore the payload");
    assert_eq!(
        garbage_device, empty_device,
        "device twin must ignore the payload exactly as the host twin does"
    );
}

/// The answer is not `INVALID_COMMAND`. Before US-1514 the device dispatch had
/// no `0x0B` arm and the `_ =>` fallthrough produced this byte; naming the
/// regression directly keeps it from coming back quietly through some other
/// route to the same answer.
#[test]
fn device_twin_does_not_answer_invalid_command() {
    let (_, device_resp) = selection_on_both(&[]);
    assert_ne!(
        device_resp,
        vec![0x01],
        "0x0B fell through to the `_ =>` arm again: the emulator can select \
         and the board cannot"
    );
}

/// US-1514 deliberately does **not** gate selection on a touch, so this pins
/// that the device answers without one — including with the fail-closed
/// presence source attached, which is what the device build default resolves
/// to (`device_core::default_user_present` → `false`). A future story that
/// *does* add the gate has to change this test deliberately, at the same
/// time as it adds `0x0B` to `presence_windowed` in
/// `firmware/src/tasks.rs` (the `UpRequired` → keepalive → retry loop) — the
/// gate is not reachable from `process_ctap2` alone, and the reasoning is in
/// `device_core::handle_authenticator_selection`.
#[test]
fn selection_answers_without_user_presence() {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    // Fail closed, mirroring the device build default: no press, ever.
    let mut app = DeviceApp::boot(&mut trng, &mut store)
        .expect("host TRNG + store boot the device app")
        .with_user_presence(|| false);
    let mut out = HV::<u8, { fapico2_fido::CTAP2_MAX_MSG }>::new();
    let n = app.process_ctap2(0x0B, &[], [0; 4], &mut out);
    assert_eq!(
        out[..n].to_vec(),
        vec![0x00],
        "selection is ungated by decision (US-1514); a gated answer would be \
         unreachable from process_ctap2 because the transport's keepalive \
         loop does not name 0x0B"
    );
}