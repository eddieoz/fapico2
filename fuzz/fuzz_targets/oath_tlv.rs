#![no_main]
//! US-1054 — the OATH TLV parser, `oath_core::nth_tlv` and the `PUT` /
//! `load_stream` paths that consume it.
//!
//! `nth_tlv` is a hand-written walker over the YkOath request dialect
//! (tag / one length byte / value, plus the bare two-byte `0x78 <props>`
//! property object US-133 added), reached straight off a host APDU. The
//! failure this target exists for is **a truncated record being partly
//! applied rather than rejected**: a walker that clamps an overrunning
//! length instead of refusing it hands the caller a short key or a short
//! name, the applet stores a credential nobody asked for, and answers
//! `0x9000` — a silent write from a malformed request. Absence of panic
//! would not catch that; the applet is perfectly happy.
//!
//! So the target carries its own **bounds-respecting reference walk** of the
//! same wire dialect and cross-checks the applet against it. Note what the
//! oracle does *not* claim: a malformed **tail** is not grounds for a
//! refusal. `cmd_put` reads the objects it needs and ignores what trails
//! them, which is YkOath parity, and the reference clients send well-formed
//! TLV. What must never happen is a truncated **object** being stored as if
//! it were whole.
//!
//! 1. **every length is validated against the remaining buffer before a
//!    read** — if a bounds-respecting walk cannot reach the `KEY` or the
//!    `NAME` object, the applet must answer something other than `0x9000`;
//! 2. **a rejected PUT applies nothing** — the applet's `LIST` output must
//!    be byte-identical before and after any non-`0x9000` `PUT`, and an app
//!    that stops being virgin (a stored credential closes the auto-validated
//!    session) is itself a stored credential. The unenforceable-property-bit
//!    refusal (US-133) is asserted from the other direction on its own.
//! 3. **a truncated persisted record is rejected, not partly applied** — a
//!    store carrying a truncated `oath.keystore.v1` stream either refuses to
//!    boot, leaving the store untouched, or reaches a canonical fixed point
//!    (persist → re-boot → the store image is stable).
//!
//! # Red-under-mutation (the evidence that these assertions bite)
//!
//! Clamping `nth_tlv`'s overrunning length instead of returning `None` turns
//! assertion 1 red. See `.superpowers/sdd/report-P6.md`.

use std::vec::Vec;

use fapico2_oath::oath_core::{device_id_from_chipid, OathApp, EMULATION_CHIPID};
use fapico2_oath::OathSeal;
use fapico2_platform::dispatch::{App, Sw, MAX_RESPONSE};
use fapico2_platform::secure_store::{HostSecureStore, SecureStore};
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HVec;

const SW_OK: Sw = 0x9000;
const INS_PUT: u8 = 0x01;
const INS_LIST: u8 = 0xA1;

const TAG_NAME: u8 = 0x71;
const TAG_KEY: u8 = 0x73;
const TAG_PROPERTY: u8 = 0x78;

/// The same slot name `oath_core` uses for its persisted record stream. It is
/// a private constant there, but `migration::SLOT_OATH` is the same bytes and
/// the migration is what writes this stream into an existing device — so this
/// is a genuinely reachable, attacker-adjacent input, not a synthetic one.
const STATE_SLOT: &[u8] = b"oath.keystore.v1";

/// What a **bounds-respecting** walk of a request reaches: which of the
/// applet's required objects it saw, and the first bare property byte.
///
/// A tag is reported only if the walk reached it with a declared length
/// lying entirely inside the buffer — exactly the set a parser that
/// validates every length before it reads could hand to `cmd_put`. A walker
/// that clamps an overrunning length instead of refusing it reports things
/// here that no honest walk can reach; that difference is what assertion 1
/// measures.
#[derive(Default, Debug)]
struct Reachable {
    key: bool,
    name: bool,
    /// The first bare `0x78 <props>` object's value byte, as `cmd_put` reads
    /// it: the byte *after* the tag, or none for a lone trailing `0x78`.
    props: Option<u8>,
}

fn strictly_reachable(data: &[u8]) -> Reachable {
    let mut r = Reachable::default();
    let mut i = 0usize;
    while i < data.len() {
        if data[i] == TAG_PROPERTY {
            // Bare two-byte property object; a lone trailing tag is the same
            // shape with an empty value and ends the stream.
            if i + 1 < data.len() {
                if r.props.is_none() {
                    r.props = Some(data[i + 1]);
                }
                i += 2;
            } else {
                if r.props.is_none() {
                    r.props = Some(0);
                }
                i += 1;
            }
            continue;
        }
        if i + 1 == data.len() {
            // Bare trailing tag: a zero-length value, end of the stream.
            r.key |= data[i] == TAG_KEY;
            r.name |= data[i] == TAG_NAME;
            return r;
        }
        let len = data[i + 1] as usize;
        if i + 2 + len > data.len() {
            // Overrun: the walk ends here and nothing past it was read.
            return r;
        }
        r.key |= data[i] == TAG_KEY;
        r.name |= data[i] == TAG_NAME;
        i += 2 + len;
    }
    r
}

/// Send one APDU through the applet and return `(sw, body)`.
///
/// ISO 7816-4 case 3 (no `Le`) with data: `CLA INS P1 P2 Lc data`, so the
/// applet's short-form `parse_apdu` sees exactly `data`. Appending a `Le`
/// byte here would push the frame past `apdu.len() == 5 + Lc`, and the
/// applet would silently read one byte fewer than the oracle walked — a
/// harness artefact that would read as an applet defect.
fn send(app: &mut OathApp, ins: u8, p1: u8, p2: u8, data: &[u8]) -> (Sw, Vec<u8>) {
    let mut apdu = vec![0x00, ins, p1, p2];
    if !data.is_empty() {
        apdu.push(data.len() as u8);
        apdu.extend_from_slice(data);
    }
    let mut resp = HVec::<u8, MAX_RESPONSE>::new();
    app.process(&apdu, &mut resp);
    assert!(resp.len() >= 2, "applet answered {} bytes -- no status word", resp.len());
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    (sw, resp[..resp.len() - 2].to_vec())
}

/// `LIST` with the extended flag: the credential table as a byte string.
/// A virgin app answers `0x9000` with an empty body; once a credential
/// exists the app is no longer auto-validated and answers `0x6982` — which
/// is itself the observable that something was stored.
fn list(app: &mut OathApp) -> (Sw, Vec<u8>) {
    send(app, INS_LIST, 0, 0, &[0x01])
}

fn new_app() -> OathApp {
    let mut trng = HostTrng::new();
    OathApp::new(&mut trng, device_id_from_chipid(EMULATION_CHIPID), OathSeal::emul())
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // `Lc` is one byte, so the wire caps the body at 255 by construction.
    // This target is about how the applet *reads* a request, not about how
    // large a request may be, and it runs in a 15-minute CI smoke.
    let body: Vec<u8> = data.iter().copied().take(255).collect();
    let reach = strictly_reachable(&body);

    // ---- 1 & 2. the PUT path --------------------------------------------
    let mut app = new_app();
    let before = list(&mut app);
    let (sw, _resp) = send(&mut app, INS_PUT, 0, 0, &body);
    let after = list(&mut app);

    // ---- 1. every length validated against the remaining buffer ---------
    if !(reach.key && reach.name) {
        assert_ne!(
            sw,
            SW_OK,
            "a request whose KEY/NAME TLV length overruns the remaining buffer was \
             accepted (0x9000) -- a truncated record was partly applied \
             (key={}, name={}, body={body:02x?})",
            reach.key, reach.name,
        );
    }

    // ---- 2. a rejected PUT applies nothing ------------------------------
    if sw != SW_OK {
        assert_eq!(
            before, after,
            "a rejected PUT changed the credential table: LIST {before:?} -> {after:?}",
        );
    } else {
        // A successful PUT on a virgin app stores a credential, which closes
        // the auto-validated session. A still-virgin table would mean the
        // applet answered 0x9000 without storing anything.
        assert_ne!(
            before, after,
            "PUT answered 0x9000 but left the credential table untouched",
        );
    }

    // US-133: an unenforceable property bit is a refusal, never an
    // accept-and-drop — the same property, from the other direction. `0x02`
    // is `PROP_TOUCH`, the one bit this firmware enforces (`PROP_ENFORCED`);
    // a host that asks for `PROP_PWS` (0x01) must be told `0x6A80` rather
    // than have the credential silently stored without it.
    const PROP_ENFORCED: u8 = 0x02;
    if reach.props.is_some_and(|p| p & !PROP_ENFORCED != 0) {
        let mut app = new_app();
        let before = list(&mut app);
        let (sw, _) = send(&mut app, INS_PUT, 0, 0, &body);
        let after = list(&mut app);
        assert_ne!(
            sw, SW_OK,
            "an unenforceable property bit {:#04x} was accepted-and-dropped (body={body:02x?})",
            reach.props.unwrap(),
        );
        assert_eq!(before, after, "a refused property put changed the table");
    }

    // ---- 3. the persisted record stream ---------------------------------
    // A store carrying a truncated or malformed `oath.keystore.v1` value is
    // the migration's output shape and a torn write at once.
    let mut store = HostSecureStore::new();
    store.write(STATE_SLOT, &body).expect("the store accepts the raw value");
    let before_image = store.partition_image();

    let mut trng = HostTrng::new();
    match OathApp::boot(
        &mut trng,
        &mut store,
        device_id_from_chipid(EMULATION_CHIPID),
    , OathSeal::emul()) {
        Err(_) => {
            // Fail closed, and the refused store is untouched.
            assert_eq!(
                store.partition_image(),
                before_image,
                "a refused boot modified the store",
            );
        }
        Ok(mut app) => {
            // Accepted: whatever survived must be canonical, so a
            // persist/re-boot cycle is a fixed point. Anything only partly
            // representable in the canonical stream would drift here.
            app.persist_state(&mut store);
            let once = store.partition_image();
            let mut trng = HostTrng::new();
            let mut app2 = OathApp::boot(
                &mut trng,
                &mut store,
                device_id_from_chipid(EMULATION_CHIPID),
            , OathSeal::emul())
            .expect("the store the applet itself just wrote must boot");
            app2.persist_state(&mut store);
            assert_eq!(
                store.partition_image(),
                once,
                "an accepted record stream is not a fixed point of persist/re-boot",
            );
        }
    }
});
