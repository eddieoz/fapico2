//! US-1515: `SET_REPORT` on the CTAP interface must service the payload or
//! STALL — never ACK and discard it.
//!
//! # What was wrong
//!
//! `HidInterfacesHandler::control_out_ctap` (`platform/src/usb.rs`) matched on
//! `bRequest` alone and never forwarded the data stage, and
//! `hid_control::control_out` took no data argument at all. The two together
//! meant a `SET_REPORT` was ACKed while its payload went nowhere: the host was
//! told a configuration had been applied when the device had done nothing.
//!
//! # What these tests can and cannot reach
//!
//! `platform/src/usb.rs` is `#[cfg(all(feature = "device", target_arch =
//! "arm"))]` (`platform/src/lib.rs:21`), so **the arm-side glue is not
//! compiled by any host test** — the blind spot `platform/tests/usb.rs`
//! already documents for the serial. What is reachable is the decision layer
//! `hid_control::control_out`, which is where the ACK used to be returned and
//! where the STALL is now returned, and which US-391 (E7) put there for exactly
//! this reason. A green run here proves the CTAP interface never ACKs a
//! SET_REPORT *by decision*; it cannot prove the arm glue forwards `data` into
//! that decision. That wiring is one call argument, guarded by the
//! `thumbv8m` build and by review.
//!
//! # Why the tests are not constant checks
//!
//! `assert_eq!(control_out(0x09, ..), OutReply::Rejected)` on its own would
//! only pin the answer for one input, and would keep passing if the
//! implementation regressed elsewhere in the request space. The tests below
//! therefore *sweep* the space and assert properties over it — every report
//! type the HID spec allows (HID 1.11 §7.2.1), every payload shape a host can
//! legally send, and every `bRequest` in the HID class block — using **wire**
//! constants (`0x09`, `0x0A`, `0x0B`, report types `0..=3`) rather than the
//! module's private aliases, so a rename inside `hid_control` cannot silently
//! move the goalposts.
//!
//! # Invocation
//!
//! `cargo test --target x86_64-unknown-linux-gnu -p fapico2-platform --test
//! hid_set_report`. The `--target` is required: `.cargo/config.toml` pins the
//! default target to `thumbv8m.main-none-eabi`.

use fapico2_platform::hid_control::{control_out, OutReply};
use fapico2_platform::otp_hid;

/// HID class requests, at their wire `bRequest` values (HID 1.11 §7.2).
const GET_REPORT: u8 = 0x01;
const SET_REPORT: u8 = 0x09;
const SET_IDLE: u8 = 0x0A;
const SET_PROTOCOL: u8 = 0x0B;

/// `wValue` high byte on GET/SET_REPORT — the report *type* (HID 1.11 §7.2.1).
const REPORT_TYPE_CONFIG: u16 = 0;
const REPORT_TYPE_INPUT: u16 = 1;
const REPORT_TYPE_OUTPUT: u16 = 2;
const REPORT_TYPE_FEATURE: u16 = 3;

/// The low byte of `wValue` on GET/SET_REPORT: the report ID. This interface
/// declares no report IDs (the report descriptor has no Report ID items), so
/// every request here uses 0.
const REPORT_ID_NONE: u16 = 0;

/// The CTAPHID packet size (`HID_RPT_SIZE`, `pico-keys-sdk/src/usb/hid/
/// ctap_hid.h:35`) — the report size of both directions on the CTAP interface.
const CTAP_REPORT_SIZE: usize = 64;

/// Builds a well-formed 64-byte CTAPHID packet: CID, then the frame byte
/// `TYPE_INIT | cmd`, then the 16-bit payload length, then the payload.
///
/// The point of the helper is that the payload in the sweep below is a
/// *meaningful* request, not noise: it is exactly the shape the C reference
/// accepts on the SET_REPORT path it services
/// (`pico-keys-sdk/src/usb/hid/hid.c:282-302`). A STALL to this payload is a
/// decision, not an accident of malformed input.
fn ctaphid_packet(cmd: u8, payload: &[u8]) -> [u8; CTAP_REPORT_SIZE] {
    const TYPE_INIT: u8 = 0x80;

    let mut report = [0u8; CTAP_REPORT_SIZE];
    report[0..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]); // CID
    report[4] = TYPE_INIT | cmd;
    report[5] = payload.len() as u8;
    report[6] = (payload.len() >> 8) as u8;
    report[7..7 + payload.len()].copy_from_slice(payload);
    report
}

/// What the host observes for an `OutReply`.
///
/// Embassy maps `Accepted` to a zero-length status packet and `Rejected` to a
/// STALL, so the two replies are distinguishable at the host by whether
/// `ctrl_transfer` returns an error. Naming that here keeps the assertions
/// below stated in terms of what the *host* learns, not in terms of a variant.
fn host_sees_ack(reply: &OutReply) -> bool {
    matches!(reply, OutReply::Accepted)
}

/// Every payload shape a host can legally put in a SET_REPORT data stage on
/// this interface — including the two that matter: the full CTAPHID report and
/// the one-byte YubiOTP-style reset, which is the shape that resets the OTP
/// interface's transfer state.
fn payload_shapes() -> Vec<Vec<u8>> {
    vec![
        // Empty: a malformed SET_REPORT (HID always has a data stage) — still
        // must not be ACKed.
        Vec::new(),
        // The 1-byte `0xFF` transfer reset the OTP interface understands.
        vec![0xFF],
        // The 8-byte YubiOTP feature report.
        vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xC1, 0x0F],
        // A real CTAPHID PING packet — the strongest form of the request.
        ctaphid_packet(0x01, &[0x2A]).to_vec(),
        // One byte short of a CTAPHID report, and one byte over.
        ctaphid_packet(0x01, &[0x2A])[..CTAP_REPORT_SIZE - 1].to_vec(),
        {
            let mut over = ctaphid_packet(0x01, &[0x2A; 40]).to_vec();
            over.push(0x00);
            over
        },
        // 256 bytes — the largest a single SET_REPORT can be.
        vec![0x5A; 256],
    ]
}

/// Every report type the HID spec defines for GET/SET_REPORT.
fn report_types() -> [u16; 4] {
    [
        REPORT_TYPE_CONFIG,
        REPORT_TYPE_INPUT,
        REPORT_TYPE_OUTPUT,
        REPORT_TYPE_FEATURE,
    ]
}

/// **The story's core test.** A SET_REPORT on the CTAP interface is STALLed for
/// every report type and every payload — the host is never ACKed for
/// configuration the device did not apply.
///
/// The four report types are swept because the descriptor decides the answer:
/// `CTAP_REPORT_DESCRIPTOR` (`hid_control.rs:18-35`) declares only Input
/// (usage 0x20) and Output (usage 0x21) reports, so Config and Feature have no
/// backing report to write into. If a future descriptor gains a Feature report
/// this test is where that fact has to be argued.
#[test]
fn set_report_on_the_ctap_interface_is_stalled_not_acked() {
    // Sanity: the strongest payload really is a well-formed CTAPHID frame, so
    // "STALL" below is a decision about a request the host was entitled to
    // make, not a side effect of feeding it garbage.
    let ping = ctaphid_packet(0x01, &[0x2A]);
    assert_eq!(ping[4], 0x81, "CTAPHID frame byte must be TYPE_INIT | PING");
    assert_eq!(u16::from_le_bytes([ping[5], ping[6]]), 1, "bcnt");
    assert_eq!(ping[7], 0x2A, "ping nonce");

    let mut checked = 0usize;
    for report_type in report_types() {
        for payload in payload_shapes() {
            // Report ID 0: this interface declares no report IDs.
            let value = (report_type << 8) | REPORT_ID_NONE;
            let reply = control_out(SET_REPORT, value, &payload);
            assert!(
                !host_sees_ack(&reply),
                "SET_REPORT (type {report_type}, {} byte payload) was ACKed on \
                 the CTAP interface, but the device has no setter for it — the \
                 host was told a configuration was applied when none was",
                payload.len(),
            );
            assert_eq!(reply, OutReply::Rejected);
            checked += 1;
        }
    }
    assert_eq!(checked, 4 * 7, "sweep must cover every report type x payload");
}

/// The invariant the previous code violated, stated over the whole request
/// space rather than as a single assertion: **the CTAP interface ACKs exactly
/// two control-OUT requests, and they are the two that have no data stage.**
///
/// This is the assertion that outlives the specific SET_REPORT case. Re-adding
/// a bRequest to the accepted arm fails it; over-correcting the fix into
/// "STALL everything" fails it too.
#[test]
fn only_the_data_stage_less_requests_are_acked() {
    // The HID class request block (0x00..=0x0F), plus the reserved/vendor
    // range above it — a control-OUT with any bRequest at all must not be able
    // to reach Accepted unless it is one of the two.
    let mut accepted: Vec<u8> = Vec::new();

    for request in 0u8..=0x30 {
        // One reply per bRequest, however the request is dressed up. A
        // decision that changes with the data stage is exactly the shape the
        // old bug took if it were ever "fixed" by special-casing a payload
        // instead of refusing the request.
        let mut first_ack: Option<bool> = None;
        for report_type in report_types() {
            for payload in payload_shapes() {
                let value = (report_type << 8) | REPORT_ID_NONE;
                let acked = host_sees_ack(&control_out(request, value, &payload));
                match first_ack {
                    None => first_ack = Some(acked),
                    Some(seen) => assert_eq!(
                        acked, seen,
                        "bRequest {request:#04x} was {} for one data stage and \
                         {} for another — the reply must not depend on the \
                         payload, or the device is guessing at what it applied",
                        if seen { "ACKed" } else { "STALLed" },
                        if acked { "ACKed" } else { "STALLed" },
                    ),
                }
            }
        }
        if first_ack.expect("sweep is not empty") {
            accepted.push(request);
        }
    }

    // SET_IDLE (usbhid issues it at bind time — STALLing it would be a
    // gratuitous behaviour change to the E6c fix, not a correction) and
    // SET_PROTOCOL. Both carry their parameter in `wValue` and have no device
    // state behind them, so neither can discard anything.
    assert_eq!(
        accepted,
        vec![SET_IDLE, SET_PROTOCOL],
        "the CTAP interface must ACK exactly the two control-OUT requests that \
         have no data stage; anything else ACKed is an ACK-and-discard lie",
    );
}

/// The over-correction guard, stated directly: the two requests that *do* carry
/// a data stage on the HID spec's terms are STALLed, and the two that do not
/// are still accepted.
///
/// This also pins the device-vs-host asymmetry that makes the answer honest:
/// `control_in(GET_REPORT, ..)` is rejected for the same reason SET_REPORT is —
/// there is no backing report — so the interface consistently refuses to
/// pretend it has report storage it does not have.
#[test]
fn report_bearing_requests_are_refused_in_both_directions() {
    // Host → device, with a payload: STALL.
    assert_eq!(
        control_out(SET_REPORT, REPORT_TYPE_OUTPUT << 8, &[0u8; 64]),
        OutReply::Rejected
    );
    assert_eq!(
        control_out(0x0C, 0, &[]),
        OutReply::Rejected,
        "a control-OUT with an unrecognised bRequest must not fall into the \
         accepted arm"
    );
    // Device → host, GET_REPORT: already rejected (`hid_control::control_in`).
    assert_eq!(
        fapico2_platform::hid_control::control_in(GET_REPORT, 0),
        fapico2_platform::hid_control::InReply::Rejected
    );
    // No data stage: still accepted, so the E6c bind path is untouched.
    assert_eq!(control_out(SET_IDLE, 0, &[]), OutReply::Accepted);
    assert_eq!(control_out(SET_PROTOCOL, 0, &[]), OutReply::Accepted);
}

/// **The OTP-side regression guard.** The YubiOTP interface in the same
/// composite device receives the *same* `bRequest` with the *same* report type
/// and must reach the opposite answer, because its payload *is* serviced
/// (`otp_hid::set_report`, `otp_hid.rs:215`) and its report descriptor really
/// does declare a Feature report.
///
/// The two interfaces are routed by `wIndex`, not by `bRequest`
/// (`usb.rs:167-183`), so this is the assertion that the CTAP STALL did not
/// leak across: if someone ever routes both HID interfaces through one
/// decision function, this test is what notices.
///
/// Scope note: this test pins the *decision*, not the OTP path's own US-1515
/// defect — `HidInterfacesHandler::control_out_otp` (`usb.rs:149-155`) still
/// ACKs a Feature SET_REPORT whose payload is not `FEATURE_REPORT_SIZE`, which
/// is the same class of lie on the other interface. Reported, not fixed here.
#[test]
fn the_otp_interface_still_services_its_set_report() {
    let feature_value = (REPORT_TYPE_FEATURE << 8) | REPORT_ID_NONE;

    // OTP: serviced, so ACKed. `otp_hid::set_report` consumes the 8-byte
    // feature report, so this ACK is backed by work done.
    assert_eq!(
        otp_hid::control_out(SET_REPORT, feature_value),
        OutReply::Accepted,
        "the OTP interface's SET_REPORT must keep ACKing — US-1515 changed the \
         CTAP interface only"
    );

    // CTAP: same request, same report type, opposite answer. The payload is a
    // real OTP feature report — the shape the OTP path *does* service — so the
    // divergence is the interface's, not the payload's.
    assert_eq!(
        control_out(SET_REPORT, feature_value, &[0u8; 8]),
        OutReply::Rejected,
        "CTAP and OTP share bRequest 0x09 but must not share a decision",
    );

    // And the report-descriptor claim both answers rest on is true. `0x81`/
    // `0x91` are Input/Output items and `0xB1` is a Feature item (HID short
    // item descriptor). Scanned as two-byte item sequences — enough to pin
    // "does this interface declare a Feature report at all", which is the
    // question; not a full descriptor parse.
    let ctap = fapico2_platform::hid_control::CTAP_REPORT_DESCRIPTOR;
    let otp = otp_hid::OTP_HID_REPORT_DESCRIPTOR;
    let declares_feature = |d: &[u8]| d.windows(2).any(|w| w[0] == 0xB1);
    let declares_output = |d: &[u8]| d.windows(2).any(|w| w[0] == 0x91);

    assert!(
        declares_output(ctap),
        "CTAP descriptor must declare its Output report — the interrupt OUT \
         endpoint is how CTAPHID actually carries commands",
    );
    assert!(
        !declares_feature(ctap),
        "CTAP descriptor unexpectedly declares a Feature report — if this ever \
         fires, SET_REPORT may have become serviceable and US-1515's STALL \
         needs re-deciding against hid_control::control_out",
    );
    assert!(
        declares_feature(otp),
        "the OTP descriptor must declare a Feature report for its ACK to be honest",
    );
}