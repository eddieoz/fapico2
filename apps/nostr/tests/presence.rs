//! US-1646/US-1647 — the touch gates and the presence tag binding
//! (EPIC design §2.3, §2.3.1, §2.6).
//!
//! Three properties, each of which fails differently when ignored:
//!
//! * the touch is the *execution* gate — a deny grant refuses `SIGN` with
//!   `6985` after every shape and state refusal has passed, and the device
//!   wiring (the §2.6 required builder call) is asserted against
//!   `firmware/src/main.rs` itself, because a forgotten builder call
//!   degrades to `default_user_present()` and fails silently either way;
//! * the presence tag is bound to the **identity**, not the opcode —
//!   `0x4000_0000 | idx` (bit 30), collision-free by construction, because
//!   an earlier draft's `0x50 | ins | idx<<4` encoding collapsed 8
//!   identities onto 2 tags (§2.3.1's own reproduced bug);
//! * the strict request path — `begin_request` refuses any second pending
//!   request whatever its tag, and a grant is consumed exactly once — so a
//!   press armed for one `SIGN` can never authorise another.

use fapico2_nostr::{NostrApp, INS_SIGN, SW_TOUCH_REQUIRED};
use fapico2_platform::dispatch::App;
use fapico2_platform::keyregion::crypto::{derive_payload_key, NOSTR_PAYLOAD_SECRET};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::nostr_store::{NostrIdentity, NostrRegion, NOSTR_SLOTS};
use fapico2_platform::keyregion::TOTAL_SLOTS;
use fapico2_platform::presence::PresenceService;
use heapless::Vec as HeaplessVec;

// ---------------------------------------------------------------------------
// Fixtures (the keymgmt/wire shape)
// ---------------------------------------------------------------------------

fn region_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fapico2-nostr-us1646-{tag}-{}.bin",
        std::process::id()
    ))
}

fn fixture_key(region: FileKeyRegion) -> NostrRegion {
    let otp_row: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x11));
    let chipid: [u8; 8] = 0x0000_BADC_0FFE_EE01_0203_u64.to_be_bytes();
    let key = derive_payload_key(&otp_row, &chipid, &NOSTR_PAYLOAD_SECRET)
        .expect("a non-zero OTP row");
    NostrRegion::new(Box::new(region), key)
}

/// An applet whose slot 1 holds a live identity (SIGN's state refusals must
/// all have passed before the touch gate is consulted).
fn app_with_identity(tag: &str) -> (NostrApp, std::path::PathBuf) {
    let path = region_path(tag);
    std::fs::remove_file(&path).ok();
    let region = FileKeyRegion::create(&path, TOTAL_SLOTS).expect("a fixture region");
    {
        let mut region = fixture_key(region);
        let mut store = region.store();
        let scalar: [u8; 32] = core::array::from_fn(|i| i as u8);
        let npub = fapico2_nostr::crypto::xonly_pubkey(&scalar).expect("a valid scalar");
        store
            .write(1, &NostrIdentity::new(scalar, npub, b"", 0).expect("a valid identity"))
            .expect("fill slot 1");
    }
    let reopened = FileKeyRegion::open(&path).expect("reopen the fixture region");
    let app = NostrApp::boot(fixture_key(reopened));
    (app, path)
}

fn call(app: &mut NostrApp, apdu: &[u8]) -> (HeaplessVec<u8, 4096>, u16) {
    let mut resp = HeaplessVec::new();
    app.process(apdu, &mut resp);
    assert!(resp.len() >= 2, "the applet must always answer");
    let n = resp.len();
    let sw = u16::from_be_bytes([resp[n - 2], resp[n - 1]]);
    let data: HeaplessVec<u8, 4096> = resp[..n - 2].iter().copied().collect();
    (data, sw)
}

fn apdu_sign(idx: u8) -> HeaplessVec<u8, 300> {
    let mut a = HeaplessVec::new();
    a.extend_from_slice(&[0x00, INS_SIGN, idx, 0x00]).unwrap();
    a.push(32).unwrap();
    a.extend_from_slice(&[0x5A; 32]).unwrap();
    a
}

// ---------------------------------------------------------------------------
// US-1646 — the touch is the execution gate, and the device wiring is a
// required edit
// ---------------------------------------------------------------------------

/// `SIGN` with the grant withheld answers `6985` — the touch is the last
/// gate in the order (shape, state, touch, execute), so a refusal here
/// proves every earlier gate passed.
#[test]
fn sign_refused_without_presence_grant() {
    let (app, path) = app_with_identity("deny");
    let mut app = app.with_presence_grant(|_| false);
    let (_, sw) = call(&mut app, &apdu_sign(1));
    assert_eq!(sw, SW_TOUCH_REQUIRED, "a denied touch refuses with 6985");
    std::fs::remove_file(&path).ok();
}

/// The §2.6 required edit, asserted against the firmware source itself:
/// `App::process` carries no presence parameter, so the ONLY way presence
/// reaches the device applet is the provider installation in `main.rs` —
/// and if it is forgotten, the fallback (`default_user_present()`, `false`
/// on device) bricks every private operation with no failing test to point
/// at. Since US-1658 the applet is constructed once in `nostr_shared.rs`
/// behind the shared Mutex (`NostrApp::new()` lives there now, not in
/// `main.rs`), and the boot path wires presence through
/// `install_nostr_providers(...)` — so THIS gate asserts the property at
/// the place it now lives: the call exists in `main.rs`, its grant
/// argument is `fapico2_firmware::presence::nostr_grant` (the
/// domain-discriminating gate — the HID vendor arm's tags resolve inside
/// the window that arm itself opened, and the CCID arm blocks in the
/// OpenPGP touch-wait shape under the command's own request-bound tag,
/// D7), and the call site never names the
/// join-or-open `window_grant` (§2.3.1's forbidden path — the negative
/// assertion is the half that catches the join-or-open regression this
/// gate exists for).
#[test]
fn main_rs_wires_nostr_presence_through_the_strict_builder() {
    let main_rs = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../firmware/src/main.rs"
    ))
    .expect("firmware/src/main.rs is readable from the nostr test crate");

    let nostr_chain = main_rs
        .split("install_nostr_providers(")
        .nth(1)
        .expect("main.rs installs the nostr providers");
    let nostr_chain = &nostr_chain[..nostr_chain
        .find(";")
        .expect("the install_nostr_providers statement terminates")];

    // The negative assertion comes FIRST so a wiring that degraded to the
    // forbidden path fails naming the join-or-open hazard, not the missing
    // strict path.
    assert!(
        !nostr_chain.contains("window_grant"),
        "the nostr applet must never be wired to the join-or-open \
         window_grant (§2.3.1): a same-tag SIGN would join another SIGN's \
         open window and inherit its press"
    );
    assert!(
        nostr_chain.contains("fapico2_firmware::presence::nostr_grant"),
        "the §2.6 required edit is missing: main.rs's install_nostr_providers \
         call is not wired to presence::nostr_grant — presence would fall back \
         to default_user_present() and fail silently"
    );

    // US-1646's second half: the emulator needs the deny hook, or the
    // presence suites only ever run against an auto-ack and prove nothing
    // (the OATH hook precedent, `FAPICO2_OATH_PRESENCE=deny`).
    let emul = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../firmware/src/emul_main.rs"
    ))
    .expect("firmware/src/emul_main.rs is readable from the nostr test crate");
    assert!(
        emul.contains("FAPICO2_NOSTR_PRESENCE"),
        "emul_main.rs must expose FAPICO2_NOSTR_PRESENCE=deny — without it the \
         emulator's auto-ack cannot be withheld and the 6985 refusal is \
         un-exercisable over CCID"
    );
}

// ---------------------------------------------------------------------------
// US-1647 — the presence tag is bound to the request, not the opcode
// ---------------------------------------------------------------------------

/// All 8 identities yield 8 distinct tags. The draft encoding
/// (`0x50 | ins | idx<<4`) collapsed these to 2 — the trap §2.3.1 records.
#[test]
fn all_distinct_tags_for_distinct_idx() {
    let tags: Vec<u32> = (0..NOSTR_SLOTS as u16)
        .map(fapico2_nostr::presence_tag)
        .collect();
    for (i, a) in tags.iter().enumerate() {
        for (j, b) in tags.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "identities {i} and {j} collapsed onto one tag");
            }
        }
    }
    // The encoding itself: bit 30 set, the identity in the low 16 bits,
    // nothing else mixed in.
    for idx in 0..NOSTR_SLOTS as u16 {
        let t = fapico2_nostr::presence_tag(idx);
        assert_eq!(t & 0x4000_0000, 0x4000_0000, "bit 30 must be set");
        assert_eq!(t & 0xFFFF, idx as u32, "the low 16 bits carry the identity");
        assert_eq!(
            t & !0x4000_0000 & !0xFFFF,
            0,
            "no other bits are mixed in (the INS is deliberately absent)"
        );
    }
}

/// The strict-path property: a second pending request is refused whatever
/// its tag — including the same tag again — and a grant is consumed
/// exactly once, so a press armed for one request can never be harvested
/// by another.
#[test]
fn second_sign_in_flight_is_refused() {
    let t = fapico2_nostr::presence_tag(3);
    let mut svc = PresenceService::new();

    assert!(svc.begin_request(t), "the first request takes the slot");
    assert!(
        !svc.begin_request(t),
        "a same-tag re-begin is refused (commands begin once)"
    );
    assert!(
        !svc.begin_request(fapico2_nostr::presence_tag(4)),
        "a second concurrent request under a different identity is refused too"
    );

    // A press arms the pending tag's grant; `request` consumes it once.
    svc.observe_press(0);
    assert!(svc.request(t, 0).is_some(), "the armed grant is granted once");
    assert!(
        svc.request(t, 0).is_none(),
        "the same request cannot be granted twice from one press"
    );
    svc.end_request(t);
}

/// Cross-domain: a Nostr CCID tag (bit 30) cannot equal a FIDO HID tag
/// (bit 31) or any tag in the §2.3.1 inventory — disjoint by construction,
/// asserted against the actual inventory values.
#[test]
fn nostr_tag_never_collides_with_another_domain() {
    for idx in 0..NOSTR_SLOTS as u16 {
        let t = fapico2_nostr::presence_tag(idx);
        // FIDO's HID domain sets bit 31 (device_app.rs:139); Nostr never can.
        assert_eq!(t & 0x8000_0000, 0);
        assert!(0x8000_0000 | (t & 0x7FFF_FFFF) != t, "HID domain disjoint");

        // The §2.3.1 inventory of tags sharing the service, all below bit 30:
        // mgmt, rescue, OATH, OTP, OpenPGP. Nostr's bit-30 tag is disjoint
        // from every one of them by the bit alone — asserted value-by-value
        // so the inventory cannot drift silently.
        const INVENTORY: [u32; 10] = [
            0x1C, // mgmt WRITE_CONFIG (mgmt/src/lib.rs)
            0x1E, // mgmt INS_READ
            0x03, 0x04, 0xA2, 0xA4, // oath_core
            0x0527_2001, // OTP
            0x002A_9E9A, // OpenPGP PSO_SIGN
            0x002A_8086, // OpenPGP PSO_DECIPHER
            0x0088_0000, // OpenPGP INT_AUTH
        ];
        for tag in INVENTORY {
            assert_ne!(t, tag, "nostr tag for idx {idx} collides with {tag:#x}");
        }
    }
}

/// D6 (docs/nostr-presence-audit.md F-A3): the device registers the
/// `NostrViaMutex` proxy, not the applet, and `App::factory_wipe`'s trait
/// default is a silent no-op — management RESET would wipe every applet
/// except Nostr while the emulator (which registers the inner app) wiped
/// it: the AGENTS §1 twin trap. The proxy must forward the wipe.
#[test]
fn the_ccid_proxy_forwards_factory_wipe() {
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
        tail.contains("fn factory_wipe(&mut self)"),
        "the CCID proxy must override factory_wipe — the trait default is a \
         silent no-op, and management RESET would spare Nostr while wiping \
         every other applet (F-A3)"
    );
    assert!(
        tail.contains("with_nostr(|app| app.factory_wipe())"),
        "the proxy's factory_wipe must forward through the shared mutex, \
         not re-implement (or worse, no-op)"
    );
}

/// D7 (docs/nostr-presence-audit.md F-A4): the CCID arm's grant must be
/// the OpenPGP wait shape — the strict one-shot poll can never grant on
/// hardware, so a CCID-built `nostr_grant` that still routes to
/// `request_grant` would answer `6985` forever with no prompt. The wait
/// body is the device bin's (`button.rs` is bin-only), so the lib takes it
/// through a boot-installed hook — the touch-prompt hook's own pattern —
/// and the gate pins both halves against the firmware source: the lib's
/// hook consultation and the bin's install.
#[test]
fn the_ccid_arm_uses_the_wait_shape_not_the_one_shot() {
    let presence_rs = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../firmware/src/presence.rs"
    ))
    .expect("firmware/src/presence.rs is readable from the nostr test crate");
    let nostr_grant_body = presence_rs
        .split("pub fn nostr_grant")
        .nth(1)
        .expect("nostr_grant exists");
    assert!(
        nostr_grant_body.contains("nostr_ccid_wait_hook()"),
        "nostr_grant's non-HID branch must consult the boot-installed wait \
         hook (D7) — a one-shot poll can never grant on hardware, and a \
         missing hook must fail closed, not degrade to request_grant"
    );
    assert!(
        presence_rs.contains("pub fn set_nostr_ccid_wait_hook"),
        "presence.rs must publish the write-once CCID wait hook (the \
         touch-prompt hook's pattern)"
    );
    let main_rs = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../firmware/src/main.rs"
    ))
    .expect("firmware/src/main.rs is readable from the nostr test crate");
    assert!(
        main_rs.contains("set_nostr_ccid_wait_hook(Some(button::nostr_wait_grant))"),
        "main.rs must install button::nostr_wait_grant as the CCID wait \
         hook at boot — without the install the arm fails closed (dead CCID \
         key management), the same silence the §2.6 gate exists to catch"
    );
    let button_rs = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../firmware/src/button.rs"
    ))
    .expect("firmware/src/button.rs is readable from the nostr test crate");
    assert!(
        button_rs.contains("pub fn nostr_wait_grant"),
        "button.rs must publish nostr_wait_grant (the OpenPGP pattern's \
         Nostr entry point)"
    );
}
