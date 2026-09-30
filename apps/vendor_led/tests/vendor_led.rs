//! US-160a / US-160b (PICOForge-COMPAT) — the RS-Key vendor LED applet.
//!
//! Everything here is driven through the **wire**, not through the app's
//! setters: an APDU goes in, the response bytes come out, and the assertions
//! are made against the 17 data bytes the PicoForge client would receive
//! (`picoforge/src/hal/common/led.rs:25-41`). The few places the tests set up
//! state through [`VendorLedApp::set_slot`] are marked as such — that setter
//! exists because `effect` and `speed` are *unreachable from the wire*, and
//! the merge tests need a profile with non-zero values in them.

use fapico2_platform::dispatch::{App, MAX_RESPONSE, Sw};
use fapico2_platform::secure_store::{HostSecureStore, SecureStore};
use fapico2_vendor_led::{
    LedSlot, VendorLedApp, INS_GET, INS_SET, LED_BLOCK_LEN, LED_COLOR_NAMES, LED_COLOR_OFF,
    LED_STATUS_BOOT, LED_STATUS_NAMES, LED_STATUS_PROCESSING, LED_STATUS_TOUCH, SLOT_COUNT,
    VENDOR_LED_AID,
};
use heapless::Vec as HeaplessVec;

/// Drive one APDU through the app and return `(data, sw)` — the status word
/// split off the tail, the same shape `apps/mgmt/tests/apdu_bounds.rs` uses.
fn drive(app: &mut VendorLedApp, apdu: &[u8]) -> (Vec<u8>, Sw) {
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    app.process(apdu, &mut resp);
    let bytes: Vec<u8> = resp.as_slice().to_vec();
    assert!(bytes.len() >= 2, "response must carry a status word");
    let sw = u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
    (bytes[..bytes.len() - 2].to_vec(), sw)
}

/// The client's GET wire, byte for byte: `00 11 00 00 00`
/// (`picoforge/src/hal/rescue/ops.rs:719-725`).
const GET_APDU: [u8; 5] = [0x00, INS_GET, 0x00, 0x00, 0x00];

/// Build the client's SET wire, byte for byte: `00 10 <brightness> <p2>`,
/// four bytes, no Lc and no Le (`ops.rs:768-773`).
///
/// The P2 packing here is transcribed from the client (`ops.rs:765-766`)
/// rather than imported from the applet, so a test that mirrors the applet's
/// own helper cannot pass by construction:
///
/// ```text
/// let steady_bit = if steady { 0x08 } else { 0x00 };
/// let p2 = (color & 0x07) | steady_bit | ((status & 0x03) << 4);
/// ```
fn set_apdu(brightness: u8, color: u8, status: u8, steady: bool) -> [u8; 4] {
    let steady_bit: u8 = if steady { 0x08 } else { 0x00 };
    let p2 = (color & 0x07) | steady_bit | ((status & 0x03) << 4);
    [0x00, INS_SET, brightness, p2]
}

/// Read the block back over the wire.
fn get_block(app: &mut VendorLedApp) -> Vec<u8> {
    let (data, sw) = drive(app, &GET_APDU);
    assert_eq!(sw, 0x9000);
    data
}

/// A profile with distinct non-zero `effect` and `speed` in every slot, so a
/// merge that zeroes either one is visible. Installed through the profile
/// seam (`set_slot`) because the wire cannot carry these bytes — which is the
/// entire reason the merge matters.
fn profile_with_effects_and_speeds() -> [u8; LED_BLOCK_LEN] {
    let mut app = VendorLedApp::new();
    for (i, (effect, color, speed)) in [
        (0x11u8, 0x01u8, 0x22u8),
        (0x33, 0x02, 0x44),
        (0x55, 0x03, 0x66),
        (0x77, 0x04, 0x88),
    ]
    .into_iter()
    .enumerate()
    {
        app.set_slot(
            i,
            LedSlot {
                effect,
                color,
                brightness: 0x10,
                speed,
            },
        );
    }
    app.set_steady(true);
    *app.block()
}

// ── US-160a: SELECT + GET ────────────────────────────────────────────────

/// US-160a RED. The GET response is **exactly 17** data bytes, then `9000`.
///
/// The length is the assertion, not an implementation detail: the client
/// computes `stride = (data.len() - 1) / 4` and buckets positionally
/// (`led.rs:25-33`), so a 13–16 byte response is silently read as the
/// pre-speed 13-byte layout and a 9–12 byte one as the pre-effect 9-byte
/// layout. A device that miscounts here produces wrong colours with no error.
#[test]
fn led_get_returns_17_byte_block() {
    let mut app = VendorLedApp::new();
    let (data, sw) = drive(&mut app, &GET_APDU);
    assert_eq!(sw, 0x9000, "GET must answer 9000");
    assert_eq!(
        data.len(),
        17,
        "GET must return exactly 17 data bytes — the client derives its record \
         stride from the length, so any other length is silently misparsed \
         (led.rs:25-33)"
    );
    assert_eq!(LED_BLOCK_LEN, 17);
}

/// Every offset of the 17-byte block carries the field the client reads at
/// that offset (`led.rs:5`, fixture `led.rs:51-57`):
/// `[steady, (effect, color, brightness, speed) × 4]`.
#[test]
fn led_get_field_offsets_match_client_layout() {
    // Install one distinguishable value per field per slot, through the
    // profile seam.
    let mut app = VendorLedApp::new();
    for i in 0..SLOT_COUNT {
        app.set_slot(
            i,
            LedSlot {
                effect: (0xA0 + i as u8) | 0x01,
                color: (i as u8) + 1,
                brightness: 0x30 + i as u8,
                speed: 0xC0 | i as u8,
            },
        );
    }
    app.set_steady(true);

    let block = get_block(&mut app);
    assert_eq!(block.len(), 17);
    assert_eq!(block[0], 0x01, "offset 0: global `steady`");
    for i in 0..SLOT_COUNT {
        let b = 1 + 4 * i;
        assert_eq!(block[b], 0xA0 | i as u8 | 0x01, "slot {i} effect at {b}");
        assert_eq!(
            block[b + 1],
            (i as u8) + 1,
            "slot {i} color at {}",
            b + 1
        );
        assert_eq!(
            block[b + 2],
            0x30 + i as u8,
            "slot {i} brightness at {}",
            b + 2
        );
        assert_eq!(block[b + 3], 0xC0 | i as u8, "slot {i} speed at {}", b + 3);
    }
}

/// The client parses the block positionally from the stride, so the block
/// must survive a round trip through its own parser unchanged. This is the
/// applet-side mirror of `led.rs`'s stride arithmetic: it re-implements
/// `parse_led_block` rather than importing it (the client is a separate
/// repository), and asserts the colours come back where the client will look
/// for them.
#[test]
fn led_get_survives_the_client_stride_parser() {
    let mut app = VendorLedApp::new();
    let want = [
        (0x02u8, 0x40u8), // Idle:     green, 0x40
        (0x03, 0x20),     // Processing: blue, 0x20
        (0x04, 0x10),     // Touch:     yellow, 0x10
        (0x01, 0x08),     // Boot:      red, 0x08
    ];
    for (i, (color, brightness)) in want.iter().enumerate() {
        // Effect bytes deliberately differ from the colours — the regression
        // `led.rs:64-78` guards against is the old stride-2 parse reading the
        // effect byte as the colour.
        app.set_slot(
            i,
            LedSlot {
                effect: 0x03,
                color: *color,
                brightness: *brightness,
                speed: 0x0F,
            },
        );
    }
    app.set_steady(true);

    let block = get_block(&mut app);
    // `parse_led_block`, transcribed from `led.rs:20-41`.
    let parsed = parse_led_block(&block).expect("17-byte block must parse");
    assert_eq!(parsed, (true, want));
}

/// The transcription of `led.rs:20-41` these tests assert against. Kept here
/// (rather than only in the applet) so the applet's byte layout is checked
/// against the *client's* reading of it, not against the applet's own idea of
/// its own layout.
fn parse_led_block(data: &[u8]) -> Option<(bool, [(u8, u8); 4])> {
    if data.is_empty() {
        return None;
    }
    let stride = (data.len() - 1) / 4;
    if stride < 2 {
        return None;
    }
    let color_off = if stride >= 3 { 1 } else { 0 };
    let steady = data[0] != 0;
    let mut statuses = [(0u8, 0u8); 4];
    for (i, slot) in statuses.iter_mut().enumerate() {
        let base = 1 + stride * i + color_off;
        *slot = (*data.get(base)?, *data.get(base + 1)?);
    }
    Some((steady, statuses))
}

/// A GET is a pure read: repeated calls are byte-identical, and it never
/// changes the applet's dirty state — so a read never reaches the secure
/// store, and a GET issued after a write does not re-dirty an app the
/// persist gate has already flushed.
#[test]
fn led_get_is_byte_stable_and_non_dirtying() {
    let mut app = VendorLedApp::new();

    // On a clean applet a GET leaves it clean.
    let first = get_block(&mut app);
    for _ in 0..4 {
        assert_eq!(get_block(&mut app), first, "GET must be byte-stable");
    }
    assert!(
        !app.is_dirty(),
        "GET on a clean applet must not dirty it — a read must not reach the \
         secure store"
    );
    let mut store = HostSecureStore::new();
    assert!(
        !app.persist_state(&mut store),
        "a run of GETs must persist nothing"
    );

    // Move off the factory profile, so "stable" afterwards is a statement about
    // a non-trivial block rather than about a run of zeroes.
    let (_, sw) = drive(&mut app, &set_apdu(0x7F, 0x05, LED_STATUS_BOOT, true));
    assert_eq!(sw, 0x9000);
    assert!(app.is_dirty(), "the SET dirtied the applet");
    assert!(app.persist_state(&mut store));
    assert!(!app.is_dirty());

    let after = get_block(&mut app);
    for _ in 0..4 {
        assert_eq!(get_block(&mut app), after, "GET must be byte-stable");
    }
    assert!(
        !app.is_dirty(),
        "a GET after a flushed write must not re-dirty the applet"
    );
}

/// The applet is selectable by the standard AID path with no special casing:
/// the client opens it with `00 A4 04 04 05 <AID>` and only checks the
/// status word (`picoforge/src/hal/transport/pcsc.rs:54-71`).
#[test]
fn led_select_accepts_p2_return_fci() {
    let mut app = VendorLedApp::new();
    assert_eq!(app.aid(), VENDOR_LED_AID);
    assert_eq!(VENDOR_LED_AID, [0xF0, 0x00, 0x00, 0x00, 0x01]);

    // The client's exact SELECT, `P2 = 0x04` (return FCI).
    let mut sel = vec![0x00, 0xA4, 0x04, 0x04, VENDOR_LED_AID.len() as u8];
    sel.extend_from_slice(VENDOR_LED_AID);

    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    let sw = app.select_apdu(false, &sel, &mut resp);
    assert_eq!(sw, 0x9000, "P2 = 0x04 (return FCI) must be accepted");
    // A well-formed FCID template carrying the DF name, so a generic
    // ISO 7816-4 tool asking for an FCI gets one.
    assert_eq!(
        resp.as_slice(),
        &[0x62, 0x07, 0x4F, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x01]
    );

    // `P2 = 0x00` (no response data) is the same applet, just quieter.
    let mut sel0 = vec![0x00, 0xA4, 0x04, 0x00, VENDOR_LED_AID.len() as u8];
    sel0.extend_from_slice(VENDOR_LED_AID);
    let mut resp0 = HeaplessVec::<u8, MAX_RESPONSE>::new();
    assert_eq!(app.select_apdu(false, &sel0, &mut resp0), 0x9000);
    assert!(resp0.is_empty(), "P2 = 0x00 must return no FCI data");
}

// ── US-160b: SET with the packed P2 ──────────────────────────────────────

/// US-160b RED. P2 packs colour in bits 0–2, the `steady` flag in bit 3 and
/// the status index in bits 4–5, for **every** `LedColor` 0..7 and **every**
/// `LedStatus` 0..3 (`ops.rs:765-766`, `constants.rs:514-538, 599-622`).
#[test]
fn led_set_packs_p2_per_spec() {
    // Every colour, every status, both values of the `steady` bit: 8 × 4 × 2.
    for color in 0..8u8 {
        for status in 0..4u8 {
            for steady in [false, true] {
                let mut app = VendorLedApp::new();
                let brightness = 0x42;
                let (_, sw) = drive(
                    &mut app,
                    &set_apdu(brightness, color, status, steady),
                );
                assert_eq!(sw, 0x9000, "SET color={color} status={status} steady={steady}");

                let block = get_block(&mut app);
                assert_eq!(block[0], u8::from(steady), "global steady bit");
                let b = 1 + 4 * status as usize;
                assert_eq!(
                    block[b + 1], color,
                    "{} (code {color}) must land at the target slot's colour \
                     offset, not slot {status}'s only",
                    LED_COLOR_NAMES[color as usize]
                );
                assert_eq!(block[b + 2], brightness, "P1 carries brightness raw");
                // No other slot was touched.
                for other in 0..SLOT_COUNT {
                    if other != status as usize {
                        assert_eq!(block[1 + 4 * other + 1], 0, "slot {other} untouched");
                        assert_eq!(block[1 + 4 * other + 2], 0, "slot {other} untouched");
                    }
                }
            }
        }
    }
}

/// The `steady` bit is bit 3 of P2 and **global**, not per-slot: the client
/// sends it on all four of its per-slot writes (`picoforge/src/hal/io.rs:199-205`),
/// so a SET for slot 2 legitimately moves block offset 0.
#[test]
fn led_set_steady_is_global_across_slots() {
    for status in 0..4u8 {
        let mut app = VendorLedApp::new();
        // First write with steady = true, on each status in turn.
        drive(&mut app, &set_apdu(0x10, 0x02, status, true));
        assert_eq!(get_block(&mut app)[0], 0x01, "steady set from slot {status}");

        // Then one write with steady = false, again on each status: the flag
        // must come back down rather than latching per slot.
        drive(&mut app, &set_apdu(0x10, 0x02, status, false));
        assert_eq!(
            get_block(&mut app)[0],
            0x00,
            "steady cleared from slot {status} — it is one global flag"
        );
    }
}

/// A SET followed by a GET round-trips colour and brightness for the targeted
/// slot.
#[test]
fn led_set_then_get_round_trips_target_slot() {
    let mut app = VendorLedApp::new();
    for status in 0..4u8 {
        for color in 0..8u8 {
            let brightness = status * 0x20 + color;
            let (_, sw) = drive(&mut app, &set_apdu(brightness, color, status, true));
            assert_eq!(sw, 0x9000);

            let block = get_block(&mut app);
            let slot = app.slot(status as usize).unwrap();
            assert_eq!(slot.color, color, "slot {status} ({})", LED_STATUS_NAMES[status as usize]);
            assert_eq!(slot.brightness, brightness);
            // And the block the client reads back agrees.
            let b = 1 + 4 * status as usize;
            assert_eq!(block[b + 1], color);
            assert_eq!(block[b + 2], brightness);
        }
    }
}

/// **The merge test.** The SET APDU has no field for `effect` or `speed`, so a
/// SET targeting slot *k* must leave all eight of those bytes alone — the
/// three *other* slots' effect/speed and the *targeted* slot's own. A
/// rebuild-the-record implementation zeroes them, and the only symptom the
/// host can observe is its own next GET: LEDs that lose their animation
/// because someone edited a colour.
#[test]
fn led_set_preserves_effect_and_speed_in_every_slot() {
    let profile = profile_with_effects_and_speeds();
    // Sanity: the setup really did install non-zero effect/speed everywhere,
    // so a zeroing regression below is observable.
    for i in 0..SLOT_COUNT {
        let s = app_slot(&profile, i);
        assert_ne!(s.effect, 0, "fixture slot {i} effect must be non-zero");
        assert_ne!(s.speed, 0, "fixture slot {i} speed must be non-zero");
    }

    // One SET per status, exactly as the client's four-session loop does
    // (`picoforge/src/hal/io.rs:199-205`).
    for status in 0..4u8 {
        let mut app = VendorLedApp::with_block(profile);
        let (_, sw) = drive(&mut app, &set_apdu(0x99, 0x06, status, false));
        assert_eq!(sw, 0x9000);

        let block = get_block(&mut app);
        for i in 0..SLOT_COUNT {
            let want = app_slot(&profile, i);
            let b = 1 + 4 * i;
            assert_eq!(
                block[b], want.effect,
                "slot {i} effect must survive a SET aimed at slot {status}"
            );
            assert_eq!(
                block[b + 3], want.speed,
                "slot {i} speed must survive a SET aimed at slot {status}"
            );
        }
    }
}

/// The narrow form of the merge: even the **targeted** slot keeps its own
/// effect and speed. A merge that copies the other three slots' values but
/// zeroes the one it wrote would pass a test that only checks the untouched
/// slots, and would still silently cancel the animation of the slot the user
/// just edited.
#[test]
fn led_set_preserves_target_slot_effect_and_speed() {
    let profile = profile_with_effects_and_speeds();
    for status in 0..4u8 {
        let mut app = VendorLedApp::with_block(profile);
        let before = app_slot(&profile, status as usize);
        drive(&mut app, &set_apdu(0x01, 0x07, status, true));

        let after = app.slot(status as usize).unwrap();
        assert_eq!(after.effect, before.effect, "slot {status} effect");
        assert_eq!(after.speed, before.speed, "slot {status} speed");
        // …while the two fields the APDU *does* carry did move.
        assert_eq!(after.color, 0x07);
        assert_eq!(after.brightness, 0x01);
    }
}

/// The client's four SETs in sequence, as `write_led_config` issues them
/// (`picoforge/src/hal/io.rs:199-205`): each is an independent full update and
/// the run is **not** atomic. The device side need not be atomic, but the
/// partial outcome must be exactly "the slots written so far" — no slot may
/// pick up another's colour.
#[test]
fn led_set_sequence_writes_each_slot_independently() {
    let mut app = VendorLedApp::new();
    let colors = [0x01u8, 0x03, 0x04, 0x07]; // Red, Blue, Yellow, White
    for (status, color) in colors.iter().enumerate() {
        let status = status as u8;
        let (_, sw) = drive(&mut app, &set_apdu(0x20 + status * 0x10, *color, status, true));
        assert_eq!(sw, 0x9000);
    }
    let block = get_block(&mut app);
    assert_eq!(block[0], 0x01, "steady set by every session");
    for (status, color) in colors.iter().enumerate() {
        let b = 1 + 4 * status;
        assert_eq!(block[b + 1], *color, "{} slot", LED_STATUS_NAMES[status]);
        assert_eq!(block[b + 2], 0x20 + status as u8 * 0x10);
    }
}

// ── refusals ─────────────────────────────────────────────────────────────

/// A non-zero CLA is refused `6E00` — the same gate `apps/mgmt` applies. The
/// LED applet speaks CLA `0x00`; the Rescue applet's `0x80` belongs to a
/// different applet and must not reach these commands.
#[test]
fn led_nonzero_cla_is_refused() {
    let mut app = VendorLedApp::new();
    for cla in [0x80u8, 0x01, 0x7F, 0xFF] {
        let mut apdu = GET_APDU;
        apdu[0] = cla;
        let (data, sw) = drive(&mut app, &apdu);
        assert_eq!(sw, 0x6E00, "CLA 0x{cla:02X} must be refused 6E00");
        assert!(data.is_empty(), "a refused command returns no data");

        // …on SET as well as GET.
        let (data, sw) = drive(&mut app, &[cla, INS_SET, 0x10, 0x02]);
        assert_eq!(sw, 0x6E00, "CLA 0x{cla:02X} must be refused on SET too");
        assert!(data.is_empty());
    }
    // The refusals changed nothing.
    assert_eq!(get_block(&mut app), vec![0u8; 17]);
}

/// A short APDU (< 4 bytes) is refused `6700` — the header guard, so a
/// truncated frame can never index past the header (the US-701 panic class).
#[test]
fn led_short_apdu_is_refused() {
    let mut app = VendorLedApp::new();
    for apdu in [
        vec![],
        vec![0x00],
        vec![0x00, INS_GET],
        vec![0x00, INS_GET, 0x00],
        vec![0x00, INS_SET],
        vec![0x00, INS_SET, 0x10],
    ] {
        let (_, sw) = drive(&mut app, &apdu);
        assert_eq!(sw, 0x6700, "truncated APDU {apdu:?} must answer 6700");
    }
    // The applet keeps serving after malformed input.
    let block = get_block(&mut app);
    assert_eq!(block.len(), 17);
}

/// SET is exactly four bytes on this wire (`ops.rs:768-773`). A fifth byte is
/// an Lc (or an Le this applet does not define) and is refused rather than
/// absorbed — silently ignoring unexpected framing is how a host comes to
/// believe it wrote a colour it did not.
#[test]
fn led_set_off_length_is_refused() {
    let mut app = VendorLedApp::new();
    // 5 bytes: the GET-shaped trailing `Le` byte on a SET.
    let (data, sw) = drive(&mut app, &[0x00, INS_SET, 0x10, 0x02, 0x00]);
    assert_eq!(sw, 0x6700, "a 5-byte SET must be refused");
    assert!(data.is_empty());
    // Nothing was written.
    assert_eq!(get_block(&mut app), vec![0u8; 17]);
}

/// An unknown INS is `6D00`, and it writes nothing.
#[test]
fn led_unknown_ins_is_refused() {
    let mut app = VendorLedApp::new();
    for ins in [0x00u8, 0x0F, 0x12, 0x1D, 0xA4, 0xFF] {
        let (data, sw) = drive(&mut app, &[0x00, ins, 0x00, 0x00, 0x00]);
        assert_eq!(sw, 0x6D00, "INS 0x{ins:02X} must be refused 6D00");
        assert!(data.is_empty());
    }
    assert_eq!(get_block(&mut app), vec![0u8; 17]);
}

// ── durability ───────────────────────────────────────────────────────────

/// The block is durable: a SET reaches a `HostSecureStore` and comes back
/// after a `boot()` from that same store.
#[test]
fn led_state_survives_boot_persist_round_trip() {
    let mut store = HostSecureStore::new();
    let mut app = VendorLedApp::boot(&mut store);

    // Four SETs, one per slot, each with a different colour and brightness.
    for status in 0..4u8 {
        let (_, sw) = drive(&mut app, &set_apdu(0xA0 | status, status + 1, status, true));
        assert_eq!(sw, 0x9000);
    }
    let want = *app.block();
    assert_eq!(want.len(), 17);
    assert!(
        app.persist_state(&mut store),
        "a SET must dirty the applet so the persist gate writes it"
    );
    assert!(!app.is_dirty(), "a successful persist clears the dirty flag");

    // A fresh app instance boots from the same store.
    let mut app2 = VendorLedApp::boot(&mut store);
    let got = get_block(&mut app2);
    assert_eq!(got, want, "boot must reload the persisted LED block");
    assert_eq!(got[0], 0x01, "steady survived");
    for (status, name) in LED_STATUS_NAMES.iter().enumerate() {
        let s = app2.slot(status).unwrap();
        assert_eq!(s.color, (status as u8) + 1, "{name} colour");
        assert_eq!(s.brightness, 0xA0 | status as u8, "{name} brightness");
    }

    // A read on the rebooted applet persists nothing.
    assert!(
        !app2.persist_state(&mut store),
        "a clean applet must not write to the store"
    );
}

/// The effect/speed bytes survive the same round trip — they are durable
/// state like any other, even though the wire cannot set them.
#[test]
fn led_effect_and_speed_survive_the_boot_round_trip() {
    let mut store = HostSecureStore::new();
    let profile = profile_with_effects_and_speeds();
    let mut app = VendorLedApp::with_block(profile);
    drive(&mut app, &set_apdu(0x55, 0x02, LED_STATUS_PROCESSING, false));
    assert!(app.persist_state(&mut store));

    let app2 = VendorLedApp::boot(&mut store);
    for i in 0..SLOT_COUNT {
        let want = app_slot(&profile, i);
        let got = app2.slot(i).unwrap();
        assert_eq!(got.effect, want.effect, "slot {i} effect survived the reboot");
        assert_eq!(got.speed, want.speed, "slot {i} speed survived the reboot");
    }
}

/// `boot()` on a fresh (empty) store is the factory block — the same bytes a
/// factory reset restores, so "first boot" and "reset" are one state.
#[test]
fn led_boot_on_fresh_store_is_the_factory_block() {
    let mut store = HostSecureStore::new();
    let mut app = VendorLedApp::boot(&mut store);
    let block = get_block(&mut app);
    assert_eq!(block.len(), 17);
    assert_eq!(block, vec![0u8; 17]);
    assert!(!app.steady());
    for i in 0..SLOT_COUNT {
        assert_eq!(app.slot(i).unwrap(), LedSlot { effect: 0, color: LED_COLOR_OFF, brightness: 0, speed: 0 });
    }
}

/// A management factory reset wipes the LED profile back to factory-fresh
/// through the owning transport's `factory_wipe_apps` + persist gate.
#[test]
fn led_factory_wipe_restores_the_factory_block() {
    let mut store = HostSecureStore::new();
    let mut app = VendorLedApp::with_block(profile_with_effects_and_speeds());
    drive(&mut app, &set_apdu(0x33, 0x05, LED_STATUS_TOUCH, true));
    assert!(app.persist_state(&mut store));

    app.factory_wipe();
    assert!(app.is_dirty(), "a wipe must ride the persist gate");
    assert!(app.persist_state(&mut store));

    let mut app2 = VendorLedApp::boot(&mut store);
    assert_eq!(get_block(&mut app2), vec![0u8; 17], "wipe is durable");
}

/// A store record of the wrong length is refused, not reinterpreted: the
/// length is the format's only self-describing field, so a differently-sized
/// blob is a foreign layout rather than a truncated one.
#[test]
fn led_boot_refuses_a_foreign_sized_record() {
    let mut store = HostSecureStore::new();
    // A 13-byte (pre-speed) record: the legacy layout is a real thing on the
    // wire, and reading it as the 17-byte layout would shift every field.
    let legacy: [u8; 13] = [0x01, 0x00, 0x02, 0x40, 0x00, 0x03, 0x20, 0x00, 0x04, 0x10, 0x00, 0x01, 0x08];
    store
        .write(b"vled.conf.v1", &legacy)
        .unwrap();
    let mut app = VendorLedApp::boot(&mut store);
    assert_eq!(
        get_block(&mut app),
        vec![0u8; 17],
        "a 13-byte record must not be reinterpreted as the 17-byte layout"
    );
}

// ── helpers ──────────────────────────────────────────────────────────────

/// Read slot `i` out of a raw block.
fn app_slot(block: &[u8; LED_BLOCK_LEN], i: usize) -> LedSlot {
    let b = 1 + 4 * i;
    LedSlot {
        effect: block[b],
        color: block[b + 1],
        brightness: block[b + 2],
        speed: block[b + 3],
    }
}
