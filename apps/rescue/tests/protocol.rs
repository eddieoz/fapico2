//! US-161a / US-161b / US-162 / US-163 (PICOForge-COMPAT) — the RS-Key Rescue
//! applet.
//!
//! Everything here is driven through the **wire**: an APDU in, response bytes
//! out, assertions made against what the PicoForge client would receive. The
//! fixture handlers exist because the applet owns no record — the
//! [`RescueConfigHandler`] / [`RescueDeviceHandler`] seams are the whole design
//! (see the crate module docs), and a test that reached the owner directly
//! would not be testing the surface.
//!
//! The APDU bytes are transcribed from the client
//! (`picoforge/src/hal/rescue/ops.rs`) rather than assembled from this crate's
//! own constants where a transcription is possible, so that a test mirroring
//! the applet cannot pass by construction. Where a constant *is* used
//! (`INS_READ` and friends) the test also pins the byte it stands for.

use fapico2_platform::dispatch::{App, MAX_RESPONSE, Sw, SW_CLA_NOT_SUPPORTED};
use fapico2_rescue::{
    FlashStats, PhySnapshot, PhyUpdate, RebootMode, RescueApp, RescueConfigHandler,
    RescueDeviceHandler, SecureBootStatus, CLA_PROPRIETARY, INS_READ, INS_REBOOT, INS_SECURE,
    INS_WRITE, MCU_TYPE_RP2350, PRODUCT_TYPE_FIDO, READ_P1_FLASH_INFO, READ_P1_PHY_CONFIG,
    READ_P1_SECURE_BOOT_STATUS, READ_P2_PHY_CONFIG, RESCUE_AID, RSKEY_SDK_MAJOR, RSKEY_SDK_MINOR,
    WRITE_P1_PHY_CONFIG,
};
use heapless::Vec as HeaplessVec;
use std::cell::RefCell;
use std::rc::Rc;

// ── fixtures ─────────────────────────────────────────────────────────────

/// Everything the fixtures observe, in one place.
///
/// The applet holds `&'static mut dyn` handles to its handlers, so a test
/// cannot also hold a borrow of the handler structs themselves — the same
/// single-fixture discipline `apps/mgmt/tests/factory_reset.rs` works around
/// with a raw-pointer cast. The fixtures here share a `RefCell` log instead,
/// which is the same single-threaded arrangement with no `unsafe` in it, so
/// "the owner was never called" is assertable rather than inferred from a
/// status word.
struct Log {
    /// The record the fake owner currently holds — i.e. the durable state a
    /// real owner's `commit` would have merged into.
    stored: PhySnapshot,
    /// Every proposal the applet handed the owner, in order.
    commits: Vec<PhyUpdate>,
    /// Every reboot the applet asked for.
    reboots: Vec<RebootMode>,
    /// Every `(boot_key_index, lock)` pair, in order.
    secure_calls: Vec<(u8, bool)>,
    /// Statuses the fake owner answers. `9000` unless a test overrides them,
    /// which is why this is a hand-written `Default` rather than a derive: a
    /// derived one would default a `u16` status to `0x0000` and every
    /// owner-refusal test would pass for the wrong reason.
    commit_answer: Sw,
    reboot_answer: Sw,
    secure_answer: Sw,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            stored: PhySnapshot::default(),
            commits: Vec::new(),
            reboots: Vec::new(),
            secure_calls: Vec::new(),
            commit_answer: 0x9000,
            reboot_answer: 0x9000,
            secure_answer: 0x9000,
        }
    }
}

impl Log {
    /// A record with every field set, so an omitted tag's value is
    /// distinguishable from an absent one.
    fn populated() -> Self {
        Self {
            stored: PhySnapshot {
                vid_pid: Some(0xFA20_0002),
                led_gpio: Some(25),
                led_brightness: Some(60),
                options: Some(0x0002),
                enabled_usb_itf: Some(0x01 | 0x04),
                // Deliberately unset: this fixture is the "every numeric field
                // configured" case, and seeding it with a name would make the
                // existing assertions about the emitted blob depend on two
                // more tags being present. The names have their own tests.
                product: None,
                manufacturer: None,
            },
            ..Self::default()
        }
    }

    /// Merge `update` the way a real owner must: an absent field keeps its
    /// stored value. Doing it here rather than in the applet is the point —
    /// the applet proposes, the owner merges.
    fn merge(&mut self, update: &PhyUpdate) {
        if update.vid_pid.is_some() {
            self.stored.vid_pid = update.vid_pid;
        }
        if update.led_gpio.is_some() {
            self.stored.led_gpio = update.led_gpio;
        }
        if update.led_brightness.is_some() {
            self.stored.led_brightness = update.led_brightness;
        }
        if update.options.is_some() {
            self.stored.options = update.options;
        }
        if update.enabled_usb_itf.is_some() {
            self.stored.enabled_usb_itf = update.enabled_usb_itf;
        }
        if update.product.is_some() {
            self.stored.product = update.product;
        }
        if update.manufacturer.is_some() {
            self.stored.manufacturer = update.manufacturer;
        }
    }
}

/// A stand-in for the firmware's PHY-record owner.
struct FixtureConfig {
    log: Rc<RefCell<Log>>,
}

impl RescueConfigHandler for FixtureConfig {
    fn snapshot(&self) -> PhySnapshot {
        self.log.borrow().stored
    }

    fn commit(&mut self, update: &PhyUpdate) -> Sw {
        let mut log = self.log.borrow_mut();
        log.commits.push(*update);
        if log.commit_answer == 0x9000 {
            log.merge(update);
        }
        log.commit_answer
    }
}

/// A stand-in for the privileged device actions. Records what was asked for
/// so a test can assert the P1/P2 placement *and* that the mode decoded is the
/// mode requested.
struct FixtureDevice {
    log: Rc<RefCell<Log>>,
}

impl RescueDeviceHandler for FixtureDevice {
    fn reboot(&mut self, mode: RebootMode) -> Sw {
        let mut log = self.log.borrow_mut();
        log.reboots.push(mode);
        log.reboot_answer
    }

    fn set_secure_boot(&mut self, key_index: u8, lock: bool) -> Sw {
        let mut log = self.log.borrow_mut();
        log.secure_calls.push((key_index, lock));
        log.secure_answer
    }
}

/// A fully wired applet plus the log its fixtures share: the record owner, the
/// device actions, and the chip / flash / secure-boot state the firmware
/// supplies at boot.
struct Harness {
    app: RescueApp,
    log: Rc<RefCell<Log>>,
}

impl Harness {
    /// Bare — no record owner, no device handler. For the `None`-handler arms.
    fn bare() -> Self {
        Self {
            app: RescueApp::new().with_chipid(0x1122_3344_5566_7788),
            log: Rc::new(RefCell::new(Log::default())),
        }
    }

    /// Wired to a record owner and a device handler, over an empty record.
    fn wired() -> Self {
        Self::with_log(Log::default())
    }

    /// Wired over a record with every field set.
    fn populated() -> Self {
        Self::with_log(Log::populated())
    }

    fn with_log(log: Log) -> Self {
        let shared = Rc::new(RefCell::new(log));
        // `Box::leak` so the applet can hold the `&'static mut dyn` handle its
        // injection seam takes — the same write-once discipline the device's
        // `DeviceFactoryResetHandler` static uses, and here the leaked box
        // holds only an `Rc` clone, so nothing aliases what the test reads.
        let config = Box::leak(Box::new(FixtureConfig {
            log: Rc::clone(&shared),
        }));
        let device = Box::leak(Box::new(FixtureDevice {
            log: Rc::clone(&shared),
        }));
        let app = RescueApp::new()
            .with_chipid(0x1122_3344_5566_7788)
            .with_flash_stats(FlashStats {
                free: 1_000,
                used: 2_000,
                total: 3_000,
                nfiles: 0,
                chip_size: 4 * 1024 * 1024,
            })
            .with_secure_boot_status(SecureBootStatus {
                enabled: false,
                locked: false,
            })
            .with_config_handler(config)
            .with_device_handler(device);
        Self { app, log: shared }
    }

    fn drive(&mut self, apdu: &[u8]) -> (Vec<u8>, Sw) {
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        self.app.process(apdu, &mut resp);
        split(resp.as_slice())
    }

    fn select(&mut self) -> (Vec<u8>, Sw) {
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        let sw = self.app.select_apdu(false, &select_apdu(), &mut resp);
        (resp.as_slice().to_vec(), sw)
    }

    /// `READ PhyConfig` with the client's P2 = `0x01`.
    fn read_phy(&mut self) -> (Vec<u8>, Sw) {
        self.drive(&READ_PHY_APDU)
    }

    fn stored(&self) -> PhySnapshot {
        self.log.borrow().stored
    }

    fn commits(&self) -> Vec<PhyUpdate> {
        self.log.borrow().commits.clone()
    }

    fn reboots(&self) -> Vec<RebootMode> {
        self.log.borrow().reboots.clone()
    }

    fn secure_calls(&self) -> Vec<(u8, bool)> {
        self.log.borrow().secure_calls.clone()
    }
}

/// The client's SELECT wire, byte for byte: `00 A4 04 04 08 <AID>` — CLA `0x00`,
/// INS `0xA4`, P1 `0x04` (select by DF name), P2 `0x04` (return FCI), `Lc = 0x08`
/// and **no `Le`** (`picoforge/src/hal/transport/pcsc.rs:53-61`).
///
/// P2 = `0x04` does not constrain the dispatcher's AID path —
/// `platform::dispatch::is_select_apdu` checks `P1 == 0x04` and nothing else —
/// so this arrives as an ordinary SELECT and the applet's `select_apdu` runs.
fn select_apdu() -> Vec<u8> {
    let mut apdu = vec![0x00, 0xA4, 0x04, 0x04, RESCUE_AID.len() as u8];
    apdu.extend_from_slice(RESCUE_AID);
    apdu
}

fn split(bytes: &[u8]) -> (Vec<u8>, Sw) {
    assert!(bytes.len() >= 2, "response must carry a status word");
    let sw = u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
    (bytes[..bytes.len() - 2].to_vec(), sw)
}

/// READ PhyConfig, **P2 = 0x01** — unlike the other two reads (`ops.rs:292-296`).
const READ_PHY_APDU: [u8; 5] = [0x80, INS_READ, READ_P1_PHY_CONFIG, READ_P2_PHY_CONFIG, 0x00];
/// `80 1E 02 00 00` — FlashInfo, P2 unused (`ops.rs:275-279`).
const READ_FLASH_APDU: [u8; 5] = [0x80, INS_READ, READ_P1_FLASH_INFO, 0x00, 0x00];
/// `80 1E 03 00 00` — SecureBootStatus, P2 unused (`ops.rs:288-292`).
const READ_SECURE_APDU: [u8; 5] = [0x80, INS_READ, READ_P1_SECURE_BOOT_STATUS, 0x00, 0x00];

/// The client's WRITE wire: `80 1C 01 00 <Lc> <TLV>`, no `Le`
/// (`ops.rs:601-609`).
fn write_apdu(tlv: &[u8]) -> Vec<u8> {
    let mut apdu = vec![
        CLA_PROPRIETARY,
        INS_WRITE,
        WRITE_P1_PHY_CONFIG,
        0x00,
        tlv.len() as u8,
    ];
    apdu.extend_from_slice(tlv);
    apdu
}

// ── US-161a: SELECT ───────────────────────────────────────────────────────

/// US-161a RED. The SELECT response is a **raw 12-byte block**, not BER-TLV,
/// and the client keeps the trailing status word in the same buffer
/// (`picoforge/src/hal/transport/pcsc.rs:73`, `:89`), so the wire is 14 bytes.
///
/// The EPIC's test name is `rescue_select_returns_14_byte_block`; asserting 12
/// *data* bytes here is the same number from the other end, and asserting 14
/// data bytes would pin the wrong thing (the threat model's §10.1 makes the
/// same point).
#[test]
fn rescue_select_returns_12_data_bytes_plus_status() {
    let mut h = Harness::wired();
    let (data, sw) = h.select();
    assert_eq!(sw, 0x9000, "the client refuses to go further on any other SW");
    assert_eq!(
        data.len(),
        12,
        "12 data bytes (4 identity + 8 chip id); the client's 14 counts the 2 status bytes"
    );
    assert_eq!(data[0], 1, "byte 0 is the MCU type, 1 = RP2350");
    assert_eq!(data[1], 2, "byte 1 is the product type, 2 = FIDO");
    assert_eq!(data[2], 8, "byte 2 is the SDK major and must be >= 8");
    assert_eq!(data[3], 0, "byte 3 is the SDK minor");
}

/// The version byte is the RS-Key **SDK** major, and pinning it at 8 is the
/// whole of US-161a's client-visible contract: `data[2] >= 8` is what
/// classifies the device as RS-Key rather than PicoFido
/// (`picoforge/src/hal/transport/pcsc.rs:75-81`).
///
/// The second assertion is the one that matters for a future reader: byte 2 is
/// **not** the firmware version, and `fapico2_mgmt::VERSION_MAJOR` is `1`
/// (`apps/mgmt/src/lib.rs:42`). A "consistency" edit that set it to 1 would
/// satisfy the EPIC's "align it with US-102's version constant" and silently
/// disable every RS-Key-only client path. Failing here is the intended outcome.
#[test]
fn select_byte_two_is_eight_so_the_client_classifies_rsk_ey() {
    let mut h = Harness::wired();
    let (data, _) = h.select();
    assert!(data[2] >= 8, "byte 2 must satisfy the client's `>= 8` test");
    assert_eq!(data[2], RSKEY_SDK_MAJOR);
    assert_eq!(data[3], RSKEY_SDK_MINOR);
    assert_eq!(data[0], MCU_TYPE_RP2350);
    assert_eq!(data[1], PRODUCT_TYPE_FIDO);
    assert_ne!(
        RSKEY_SDK_MAJOR,
        fapico2_mgmt::VERSION_MAJOR,
        "RSKEY_SDK_MAJOR answers \"which RS-Key SDK protocol do I speak\" and \
         must not be sourced from the firmware version"
    );
}

/// The AID is the protocol's, not this firmware's to choose — the client's
/// `RESCUE_AID` (`picoforge/src/hal/rescue/constants.rs:106`). A typo is
/// silent: SELECT answers `6A82` and nothing else in the tree fails.
#[test]
fn the_aid_is_the_one_the_client_selects() {
    assert_eq!(
        RESCUE_AID,
        &[0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21],
        "the Rescue AID must match the client's RESCUE_AID"
    );
    assert_eq!(RescueApp::new().aid(), RESCUE_AID);
}

/// Bytes `[4..12]` are the chip id, big-endian — the full 8 raw OTP bytes, from
/// which the client derives a serial out of `[4..7]` with the top two bits of
/// byte 4 masked off (`ops.rs:234-236`).
#[test]
fn select_block_carries_the_chipid_big_endian() {
    let mut h = Harness::wired();
    let (data, _) = h.select();
    assert_eq!(&data[4..12], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    // The client's serial derivation, transcribed rather than imported.
    let serial = u32::from_be_bytes([data[4] & 0x03, data[5], data[6], data[7]]);
    assert_eq!(serial, 0x0122_3344, "the client's masked serial, computed here");
}

// ── US-161a: READ FlashInfo ───────────────────────────────────────────────

/// US-161a RED. Five big-endian `u32`s in the client's order: free, used,
/// total, nfiles, chip size (`ops.rs:264-270`).
#[test]
fn flash_info_is_five_big_endian_u32s_in_order() {
    let mut h = Harness::wired();
    let (data, sw) = h.drive(&READ_FLASH_APDU);
    assert_eq!(sw, 0x9000);
    assert_eq!(data.len(), 20, "five u32 BE words, no framing");
    let word = |i: usize| u32::from_be_bytes(data[i * 4..i * 4 + 4].try_into().unwrap());
    assert_eq!(word(0), 1_000, "free");
    assert_eq!(word(1), 2_000, "used");
    assert_eq!(word(2), 3_000, "total");
    assert_eq!(word(3), 0, "nfiles — see FlashStats::nfiles for why this is always 0");
    assert_eq!(word(4), 4 * 1024 * 1024, "chip size");
}

// ── US-161b: READ SecureBootStatus + PhyConfig ────────────────────────────

/// US-161b RED. Two bytes, `[enabled, locked]`, read from `rx[0]` / `rx[1]`
/// only when SW is `9000` and the reply carries at least 4 bytes including it
/// (`ops.rs:284-289`).
#[test]
fn secureboot_status_is_two_bytes() {
    let mut h = Harness::wired();
    let (data, sw) = h.drive(&READ_SECURE_APDU);
    assert_eq!(sw, 0x9000);
    assert_eq!(
        data,
        vec![0, 0],
        "both false: nothing in this firmware implements secure boot (threat model §0.3)"
    );
    assert_eq!(
        data.len() + 2,
        4,
        "2 data bytes + SW is exactly the 4 the client requires to read the pair"
    );
}

/// US-161b RED. The PhyConfig read is a PHY TLV blob — the same format US-116
/// writes over `0x41` — and it carries **P2 = 0x01**, unlike the other two
/// reads. Getting that wrong makes the Config screen unreadable.
#[test]
fn phy_read_accepts_p2_one_and_returns_the_tlv_blob() {
    let mut h = Harness::populated();
    let (data, sw) = h.read_phy();
    assert_eq!(sw, 0x9000, "P2 = 0x01 must be accepted");
    assert_eq!(
        data,
        vec![
            0x00, 0x04, 0xFA, 0x20, 0x00, 0x02, //
            0x04, 0x01, 0x19, //
            0x05, 0x01, 0x3C, //
            0x06, 0x02, 0x00, 0x02, //
            0x0B, 0x01, 0x05,
        ],
        "ascending tag order, one record per field, no header and no terminator"
    );
}

/// The read and the write disagree about P2 — the client reads with `0x01`
/// (`ops.rs:295`) and writes with `0x00` (`ops.rs:606`) — so **both** are
/// accepted on the read, and nothing else is.
#[test]
fn phy_read_also_accepts_p2_zero_because_the_client_is_internally_inconsistent() {
    let mut h = Harness::populated();
    let (_, sw) = h.drive(&[0x80, INS_READ, READ_P1_PHY_CONFIG, 0x00, 0x00]);
    assert_eq!(
        sw, 0x9000,
        "P2 = 0x00 is what the WRITE uses, so a device accepting only 0x01 \
         would be unreachable from whichever client build chose 0x00"
    );
    // A third P2 names nothing and is refused rather than ignored.
    let (data, sw) = h.drive(&[0x80, INS_READ, READ_P1_PHY_CONFIG, 0x02, 0x00]);
    assert_eq!(sw, 0x6A86);
    assert!(data.is_empty(), "a refusal carries no data");
}

/// A record the firmware cannot store is **not** emitted by the read. That is
/// what keeps the client's read-modify-write inside the writable set: the
/// client only writes back the tags it parsed, so a tag this read omits is a
/// tag the client has no reason to send.
#[test]
fn phy_read_emits_only_tags_a_write_would_accept() {
    let mut h = Harness::populated();
    let (data, _) = h.read_phy();
    for undestined in [0x08u8, 0x09, 0x0A, 0x0C, 0x0D, 0x0E, 0x0F] {
        assert!(
            !data.contains(&undestined),
            "tag {undestined:#04x} has no field in the persisted record; \
             emitting it would make the client write back a tag we then refuse"
        );
    }
    for dest in [0x00u8, 0x04, 0x05, 0x06, 0x0B] {
        assert!(data.contains(&dest), "tag {dest:#04x} has a field and is served");
    }
}

/// A `None` owner is an empty blob, not a refusal: a read cannot lie by
/// omission the way a write can.
#[test]
fn phy_read_with_no_owner_is_an_empty_blob() {
    let mut h = Harness::bare();
    let (data, sw) = h.read_phy();
    assert_eq!(sw, 0x9000);
    assert!(data.is_empty(), "no record owner means no record to report");
}

// ── US-162: WRITE PhyConfig ───────────────────────────────────────────────

/// US-162 RED: the write round-trips through the record the read serves.
#[test]
fn phy_write_roundtrips_through_the_record() {
    let mut h = Harness::populated();
    // `0B 01 03` — WCID + HID, CCID retained. Exactly the courtesy the client
    // volunteers for us (`ops.rs:580-582`).
    let (data, sw) = h.drive(&write_apdu(&[0x0B, 0x01, 0x03]));
    assert_eq!(sw, 0x9000);
    assert!(data.is_empty(), "WRITE answers 9000 and nothing else");
    assert_eq!(h.stored().enabled_usb_itf, Some(0x03));

    // Back over the wire, the mask reads back changed and nothing else moved.
    let (data, sw) = h.read_phy();
    assert_eq!(sw, 0x9000);
    assert_eq!(data[16..19], [0x0B, 0x01, 0x03]);
    assert_eq!(data[6..9], [0x04, 0x01, 0x19], "led_gpio preserved");
}

/// The WRITE is a **merge**: an omitted tag keeps its stored value
/// (`ops.rs:584-585`). A one-record write therefore changes exactly one field,
/// which is what makes the CCID guard a whole-blob pre-check rather than a
/// rollback.
#[test]
fn a_write_merges_and_an_omitted_tag_is_preserved() {
    let mut h = Harness::populated();
    let before = h.stored();
    let (_, sw) = h.drive(&write_apdu(&[0x05, 0x01, 0x64]));
    assert_eq!(sw, 0x9000);
    let after = h.stored();
    assert_eq!(after.led_brightness, Some(100));
    assert_eq!(after.led_gpio, before.led_gpio);
    assert_eq!(after.vid_pid, before.vid_pid);
    assert_eq!(after.options, before.options);
    assert_eq!(after.enabled_usb_itf, before.enabled_usb_itf);
}

/// The proposal the applet hands the owner names **only** the tags that were
/// in the blob; every other field is `None` and therefore a preserve. This is
/// the mechanism, asserted at the seam rather than inferred from the result.
#[test]
fn the_proposal_omits_every_field_the_blob_did_not_carry() {
    let mut h = Harness::populated();
    h.drive(&write_apdu(&[0x04, 0x01, 0x0C]));
    let commits = h.commits();
    assert_eq!(commits.len(), 1, "one commit, one proposal");
    let proposed = commits[0];
    assert_eq!(proposed.led_gpio, Some(0x0C));
    assert_eq!(proposed.vid_pid, None);
    assert_eq!(proposed.led_brightness, None);
    assert_eq!(proposed.options, None);
    assert_eq!(proposed.enabled_usb_itf, None);
}

/// **The CCID-mask guard.** A write that would clear bit `0x01`
/// (`USB_ITF_CCID`) is refused, whole — and "whole" is asserted rather than
/// assumed: the blob also carries a perfectly good `0x04` record, so if the
/// applet applied as it parsed, that record would already be committed.
#[test]
fn a_write_that_would_clear_ccid_is_refused_whole() {
    let mut h = Harness::populated();
    let before = h.stored();
    // `0B 01 02` (WCID, no CCID) alongside a legitimate `0x04 01 0D`.
    let (data, sw) = h.drive(&write_apdu(&[0x0B, 0x01, 0x02, 0x04, 0x01, 0x0D]));
    assert_eq!(sw, 0x6A80, "6A80: the value conflicts with a device requirement");
    assert!(data.is_empty());
    assert!(
        h.commits().is_empty(),
        "the guard is a whole-blob pre-check: the owner must not have been \
         called at all, so the good 0x04 record in the same blob is not applied"
    );
    assert_eq!(h.stored(), before, "and the record is byte-for-byte unchanged");
}

/// A **zero** mask is the value `vendor41` refuses unconditionally
/// (`apps/fido/src/vendor41.rs:1409-1415`) — and on this surface it is also
/// the one that bricks the applet's own transport.
#[test]
fn a_zero_mask_is_refused_by_the_ccid_guard() {
    let mut h = Harness::populated();
    // The minimal brick, with `Lc` as the client would spell it: a `0x0B`
    // record is three bytes, so `Lc` is `0x03`.
    let (data, sw) = h.drive(&[0x80, INS_WRITE, 0x01, 0x00, 0x03, 0x0B, 0x01, 0x00]);
    assert_eq!(sw, 0x6A80);
    assert!(data.is_empty());
    assert!(h.commits().is_empty());
}

/// The Rescue guard is **strictly stronger** than the `0x41` zero-mask rule,
/// which would accept `0x02`. Asserted because the two rules converging is a
/// tripwire (threat model §9.4): a copy that lost the "bit must be *retained*"
/// half would still pass a test written against the `0x41` rule.
#[test]
fn the_ccid_guard_is_stronger_than_the_zero_mask_refusal() {
    let mut h = Harness::populated();
    // `0x02` is non-zero — the value `0x41` accepts — and equally a brick.
    let (_, sw) = h.drive(&write_apdu(&[0x0B, 0x01, 0x02]));
    assert_eq!(
        sw, 0x6A80,
        "a non-zero mask with no CCID bit is still refused; the rule is \
         'bit 0x01 must be retained', not 'the mask must be non-zero'"
    );
    assert!(h.commits().is_empty());
}

/// Every mask that keeps bit `0x01` is accepted, whatever the other bits are —
/// the guard constrains one bit, not the mask.
#[test]
fn any_mask_retaining_ccid_is_accepted() {
    for mask in [0x01u8, 0x05, 0x1F, 0xFF] {
        let mut h = Harness::populated();
        let (_, sw) = h.drive(&write_apdu(&[0x0B, 0x01, mask]));
        assert_eq!(sw, 0x9000, "mask {mask:#04x} retains CCID");
        assert_eq!(h.stored().enabled_usb_itf, Some(u16::from(mask)));
    }
}

/// The width is checked **before** the value, so a three-byte `0x0B` that
/// merely starts with `0x00` is a *length* refusal and not a *mask* one — the
/// same separation `zero_mask_refusal` makes
/// (`apps/fido/src/vendor41.rs:1424-1437`), so neither status means two
/// things.
#[test]
fn a_wrong_width_record_is_refused_on_width_not_on_value() {
    let mut h = Harness::populated();
    // Three bytes starting with 0x00: a zero-mask lookalike at the wrong width.
    let (_, sw) = h.drive(&write_apdu(&[0x0B, 0x03, 0x00, 0x00, 0x00]));
    assert_eq!(sw, 0x6700, "width, not value");
    assert!(h.commits().is_empty());
    // And the right width with a bad value is the other status.
    let (_, sw) = h.drive(&write_apdu(&[0x0B, 0x01, 0x00]));
    assert_eq!(sw, 0x6A80, "value, at the right width");
}

/// The **five** tags with no field in the persisted record are refused **as a
/// group and whole**, with the status that says "this firmware does not support
/// this record". Accepted-and-ignored is not available: the client skips a tag
/// it does not know and would then report the write as successful
/// (threat model §10.3).
///
/// The count is the point of the test, which is why the list is written out
/// rather than derived: it was **seven** until the two USB identity names
/// (`0x09` product, `0x0F` manufacturer) were given fields, and a test that
/// recomputed the list from the codec would have stopped noticing when the
/// seventh left. Dropping a tag from this list without giving it a field is
/// how one of these stops being refused at all.
#[test]
fn the_five_undestined_tags_are_refused_whole() {
    for tag in [0x08u8, 0x0A, 0x0C, 0x0D, 0x0E] {
        let mut h = Harness::populated();
        // A well-formed record of the tag's declared width, next to a good one.
        let value: &[u8] = match tag {
            0x08 | 0x0C | 0x0D | 0x0E => &[0x01],
            _ => &[0x00, 0x00, 0x00, 0x01],
        };
        let mut tlv = vec![0x04, 0x01, 0x0D, tag, value.len() as u8];
        tlv.extend_from_slice(value);
        let (_, sw) = h.drive(&write_apdu(&tlv));
        assert_eq!(sw, 0x6A86, "tag {tag:#04x} has no field in the record");
        assert!(
            h.commits().is_empty(),
            "tag {tag:#04x}: the good 0x04 record beside it must not be applied either"
        );
    }
}

/// The two tags that *were* in that list are now written and read back, which
/// is the whole point of giving them fields: before, a `0x09` record was
/// refused `6A86`, and the client's device-details screen showed a blank
/// product name it could not do anything about.
///
/// Driven through the wire, in the client's own NUL-terminated spelling
/// (`ops.rs:543-560`), and read back off the `READ PhyConfig` path the client's
/// `read_phy_config` actually walks — not off the applet's internal state,
/// because a name that reached the record but never reached the read would
/// pass an applet-level test and still show blank in the app.
#[test]
fn the_two_identity_names_round_trip_through_the_read() {
    let mut h = Harness::populated();
    let tlv = [
        0x09, 0x09, b'A', b'c', b'm', b'e', b' ', b'T', b'o', b'k', 0x00, //
        0x0F, 0x14, b'T', b'h', b'e', b' ', b'B', b'L', b'O', b'C', b'O', b' ', b'C', b'o',
        b'm', b'm', b'u', b'n', b'i', b't', b'y', 0x00,
    ];
    let (_, sw) = h.drive(&write_apdu(&tlv));
    assert_eq!(sw, 0x9000, "a well-formed name pair is accepted");

    let (body, sw) = h.read_phy();
    assert_eq!(sw, 0x9000);
    assert!(
        body.windows(2).any(|w| w == [0x09, 0x09]),
        "the product record must be on the read blob: {body:02X?}"
    );
    assert!(
        body.windows(2).any(|w| w == [0x0F, 0x14]),
        "the manufacturer record must be on the read blob: {body:02X?}"
    );
    // Name **and** terminator as one window, because that is the property
    // the client's `trim_matches(char::from(0))` depends on: a name whose NUL
    // is missing would arrive with its padding attached. One assertion for
    // both halves — a separate "the name is there" check would pass on a blob
    // with no terminator, which is the case that breaks.
    assert!(
        body.windows(9).any(|w| w == b"Acme Tok\0"),
        "the product name must survive whole and NUL-terminated: {body:02X?}"
    );
    assert!(
        body.windows(20).any(|w| w == b"The BLOCO Community\0"),
        "the manufacturer name must survive whole and NUL-terminated: {body:02X?}"
    );
}

/// A name that is not NUL-terminated is refused rather than guessed at.
///
/// The client's writer always appends the terminator, so a value without one
/// did not come from the client — and guessing where the name ends is how a
/// name silently becomes a name-plus-garbage. The refusal is whole: the good
/// `0x04` record beside it must not be applied either.
#[test]
fn an_unterminated_name_is_refused_and_takes_the_blob_with_it() {
    let mut h = Harness::populated();
    let tlv = [
        0x04, 0x01, 0x0D, //
        0x09, 0x03, b'a', b'b', b'c',
    ];
    let (_, sw) = h.drive(&write_apdu(&tlv));
    assert_eq!(sw, 0x6A80, "no terminator");
    assert!(h.commits().is_empty(), "the good 0x04 record must not land");
}

/// A thirteenth tag cannot be spelled — `PhyTag::from_byte` has no `_` arm —
/// but a raw-APDU writer can still send one, and it is refused like any other
/// record with nowhere to go.
#[test]
fn an_unknown_tag_byte_is_refused() {
    let mut h = Harness::populated();
    let (_, sw) = h.drive(&write_apdu(&[0x7A, 0x01, 0xAB]));
    assert_eq!(sw, 0x6A86);
    assert!(h.commits().is_empty());
}

/// A blob that ends mid-record is a length problem and nothing else.
#[test]
fn a_truncated_tlv_blob_is_a_length_refusal() {
    let mut h = Harness::populated();
    // Declares 4 bytes of value, supplies 1.
    let (_, sw) = h.drive(&write_apdu(&[0x00, 0x04, 0xFA]));
    assert_eq!(sw, 0x6700);
    assert!(h.commits().is_empty());
    // A lone tag byte with no length byte is truncation too.
    let (_, sw) = h.drive(&write_apdu(&[0x04]));
    assert_eq!(sw, 0x6700);
}

/// An empty blob is a legal, empty merge: nothing to change, `9000`, and the
/// owner is asked to commit a proposal that names no field.
#[test]
fn an_empty_blob_is_a_no_op_merge() {
    let mut h = Harness::populated();
    let before = h.stored();
    let (_, sw) = h.drive(&write_apdu(&[]));
    assert_eq!(sw, 0x9000);
    assert_eq!(h.stored(), before);
    assert_eq!(h.commits(), vec![PhyUpdate::default()]);
}

/// `Lc` bounds the write body. A trailing byte past it is ignored, the way
/// `apps/mgmt`'s `parse_data` ignores one; an `Lc` longer than the data that
/// arrived is a length refusal.
#[test]
fn lc_bounds_the_write_body() {
    let mut h = Harness::populated();
    let (_, sw) = h.drive(&[0x80, INS_WRITE, 0x01, 0x00, 0x10, 0x05, 0x01, 0x32]);
    assert_eq!(sw, 0x6700, "Lc = 0x10 with 3 bytes of data");
    let mut apdu = write_apdu(&[0x05, 0x01, 0x32]);
    apdu.push(0x00); // a trailing Le the client does not send
    let (_, sw) = h.drive(&apdu);
    assert_eq!(sw, 0x9000, "a byte past Lc is ignored, not fatal");
    assert_eq!(h.stored().led_brightness, Some(0x32));
}

/// Every one of the five supported records applies, at the width and byte
/// order the client writes (`ops.rs:470-620`): VID/PID and options
/// big-endian, everything else one byte.
#[test]
fn all_five_supported_records_apply_at_the_clients_widths() {
    let mut h = Harness::wired();
    let tlv = [
        0x00, 0x04, 0xFA, 0x20, 0x00, 0x03, //
        0x04, 0x01, 0x19, //
        0x05, 0x01, 0x64, //
        0x06, 0x02, 0x00, 0x0A, //
        0x0B, 0x01, 0x0D,
    ];
    let (_, sw) = h.drive(&write_apdu(&tlv));
    assert_eq!(sw, 0x9000);
    assert_eq!(
        h.stored(),
        PhySnapshot {
            vid_pid: Some(0xFA20_0003),
            led_gpio: Some(0x19),
            led_brightness: Some(100),
            options: Some(0x000A),
            enabled_usb_itf: Some(0x0D),
            product: None,
            manufacturer: None,
        }
    );
}

/// The owner owns the commit, so the owner owns the failure: a non-`9000` from
/// `commit` is propagated verbatim and the applet does no follow-on work.
#[test]
fn a_refused_commit_propagates_the_owners_status() {
    let mut h = Harness::populated();
    h.log.borrow_mut().commit_answer = 0x6A80;
    let before = h.stored();
    let (_, sw) = h.drive(&write_apdu(&[0x05, 0x01, 0x50]));
    assert_eq!(sw, 0x6A80, "the owner's status reaches the host unchanged");
    assert_eq!(h.stored(), before, "and the fake owner did not merge either");
}

/// A `None` owner is a refusal, not an accepted write that goes nowhere. The
/// status is the same `6A86` the undestined tags get, deliberately, because
/// both mean "there is no destination for this record in this build".
#[test]
fn a_write_with_no_owner_is_refused() {
    let mut h = Harness::bare();
    let (data, sw) = h.drive(&write_apdu(&[0x05, 0x01, 0x32]));
    assert_eq!(sw, 0x6A86, "accepting a write with nowhere to go is the lie §10.3 rules out");
    assert!(data.is_empty());
}

/// The WRITE's P1 is `0x01` (`WriteParam::PhyConfig`, `constants.rs:171`) and
/// its P2 is `0x00` (`P2_UNUSED`, `ops.rs:606`) — the mirror image of the
/// read's P2, which is why accepting both on the read is not merely defensive.
#[test]
fn the_write_uses_p1_one_and_p2_zero() {
    let mut h = Harness::populated();
    let (_, sw) = h.drive(&[0x80, INS_WRITE, 0x01, 0x00, 0x03, 0x05, 0x01, 0x32]);
    assert_eq!(sw, 0x9000);
    // The other P1/P2 pair names nothing here.
    let (_, sw) = h.drive(&[0x80, INS_WRITE, 0x02, 0x00, 0x03, 0x05, 0x01, 0x32]);
    assert_eq!(sw, 0x6A86);
    let (_, sw) = h.drive(&[0x80, INS_WRITE, 0x01, 0x01, 0x03, 0x05, 0x01, 0x32]);
    assert_eq!(sw, 0x6A86, "the WRITE's P2 is 0x00, unlike the read's 0x01");
}

// ── US-163: REBOOT + SECURE ───────────────────────────────────────────────

/// US-163 RED. **The mode is in P1**, against the client's own enum doc
/// comment which says P2 (`constants.rs:143-145`). The code is at
/// `ops.rs:646-652` and three other call sites agree with it.
#[test]
fn reboot_mode_is_read_from_p1_not_p2() {
    let mut h = Harness::wired();
    // `80 1F 01 00 00` — BOOTSEL.
    let (data, sw) = h.drive(&[0x80, INS_REBOOT, 0x01, 0x00, 0x00]);
    assert_eq!(sw, 0x9000);
    assert!(data.is_empty(), "REBOOT answers 9000 and nothing else");
    // `80 1F 00 00 00` — normal.
    let (_, sw) = h.drive(&[0x80, INS_REBOOT, 0x00, 0x00, 0x00]);
    assert_eq!(sw, 0x9000);
    assert_eq!(
        h.reboots(),
        vec![RebootMode::Bootsel, RebootMode::Normal],
        "P1 = 0x01 is BOOTSEL and P1 = 0x00 is normal; had P2 been read, the \
         first request would have silently normal-rebooted"
    );
}

/// The mode byte is validated rather than clamped: a third value is refused
/// rather than answered `9000` for a mode we did not perform.
#[test]
fn a_reboot_mode_the_protocol_does_not_define_is_refused() {
    assert_eq!(RebootMode::from_p1(0x00), Some(RebootMode::Normal));
    assert_eq!(RebootMode::from_p1(0x01), Some(RebootMode::Bootsel));
    assert_eq!(RebootMode::from_p1(0x01).unwrap().p1(), 0x01);
    assert_eq!(RebootMode::from_p1(0x02), None);
    let mut h = Harness::wired();
    let (_, sw) = h.drive(&[0x80, INS_REBOOT, 0x02, 0x00, 0x00]);
    assert_eq!(sw, 0x6A86);
    assert!(h.reboots().is_empty(), "and nothing was rebooted");
}

/// REBOOT is case-3 with no data field, so an off-length wire is refused: a
/// frame with a body nobody looked at is a reboot the caller did not intend.
#[test]
fn reboot_refuses_an_off_length_wire() {
    let mut h = Harness::wired();
    // Six bytes — one more than the client sends.
    let (_, sw) = h.drive(&[0x80, INS_REBOOT, 0x01, 0x00, 0x00, 0x00]);
    assert_eq!(sw, 0x6700);
    assert!(h.reboots().is_empty(), "a refused frame must not reboot");
}

/// SECURE's **lock byte is in P2** and P1 is a boot-key index — the exact
/// inverse of REBOOT, which is why the two arms do not share a helper.
#[test]
fn secure_lock_is_read_from_p2_and_p1_is_the_boot_key_index() {
    let mut h = Harness::wired();
    let (data, sw) = h.drive(&[0x80, INS_SECURE, 0x00, 0x01, 0x00]);
    assert_eq!(sw, 0x9000);
    assert!(data.is_empty(), "SECURE answers 9000 and nothing else");
    let (_, sw) = h.drive(&[0x80, INS_SECURE, 0x00, 0x00, 0x00]);
    assert_eq!(sw, 0x9000);
    assert_eq!(
        h.secure_calls(),
        vec![(0x00, true), (0x00, false)],
        "P2 = 0x01 locks, P2 = 0x00 unlocks; P1 is passed through as the \
         boot-key index and is not validated"
    );
}

/// A non-zero P1 reaches the owner unchanged. Only `0x00` is ever observed
/// (`ops.rs:694`), and nothing in the client documents what another index
/// means — so the applet must not invent a meaning, and must not refuse one
/// either.
#[test]
fn the_secure_boot_key_index_is_passed_through_unvalidated() {
    let mut h = Harness::wired();
    let (_, sw) = h.drive(&[0x80, INS_SECURE, 0x07, 0x01, 0x00]);
    assert_eq!(sw, 0x9000, "a key index we cannot interpret is the owner's problem, not a refusal");
    assert_eq!(h.secure_calls(), vec![(0x07, true)]);
}

/// Only `0x00` and `0x01` are lock states. A third byte is refused rather than
/// read as a boolean.
#[test]
fn secure_refuses_an_undefined_lock_byte() {
    let mut h = Harness::wired();
    let (_, sw) = h.drive(&[0x80, INS_SECURE, 0x00, 0x02, 0x00]);
    assert_eq!(sw, 0x6A86);
    assert!(h.secure_calls().is_empty());
    // SECURE is fixed-length too, like REBOOT.
    let (_, sw) = h.drive(&[0x80, INS_SECURE, 0x00, 0x01, 0x00, 0x00]);
    assert_eq!(sw, 0x6700);
    assert!(h.secure_calls().is_empty());
}

/// A `None` device handler is fail-closed for both privileged actions: there
/// is no local fallback that could pretend to have rebooted.
#[test]
fn privileged_actions_fail_closed_with_no_handler() {
    let mut h = Harness::bare();
    assert_eq!(h.drive(&[0x80, INS_REBOOT, 0x00, 0x00, 0x00]).1, 0x6A86);
    assert_eq!(h.drive(&[0x80, INS_SECURE, 0x00, 0x01, 0x00]).1, 0x6A86);
}

// ── CLA, length, and the INS collision with the Management applet ─────────

/// Every non-SELECT command is CLA `0x80`
/// (`APDU_CLA_PROPRIETARY`, `constants.rs:68`). Anything else is `6E00` — and
/// this is load-bearing, not a formality: the Rescue *SELECT* is `CLA 0x00`, so
/// a `0x00` APDU reaching this applet through the dispatcher's
/// non-AID-SELECT fallthrough is a real path (threat model §3.2).
#[test]
fn a_non_proprietary_cla_is_refused() {
    let mut h = Harness::populated();
    for cla in [0x00u8, 0x90, 0xA0, 0x7F] {
        for ins in [INS_READ, INS_WRITE, INS_REBOOT, INS_SECURE] {
            let apdu = [cla, ins, 0x01, 0x00, 0x00];
            let (data, sw) = h.drive(&apdu);
            assert_eq!(sw, SW_CLA_NOT_SUPPORTED, "CLA {cla:#04x} INS {ins:#04x}");
            assert!(data.is_empty());
        }
    }
    assert!(h.commits().is_empty(), "and no write reached the owner");
    assert!(h.reboots().is_empty(), "and nothing rebooted");
}

/// The reverse direction is already closed by Management's own gate, so the
/// worst outcome of a dispatch mistake cannot be an unauthenticated `RESET`.
/// Asserted as a property of the *pair* of applets, because the collision is
/// a property of the pair and not of either alone.
#[test]
fn a_proprietary_cla_reaching_the_management_applet_is_refused_not_mis_executed() {
    // `apps/mgmt`'s class gate is `if cla != Some(&0x00) { SW_CLA_NOT_SUPPORTED }`
    // (`apps/mgmt/src/lib.rs:429-431`). `0x1E` at CLA `0x80` is the dangerous
    // shape: on *this* applet it is a READ, on Management it would be a RESET.
    assert_eq!(
        SW_CLA_NOT_SUPPORTED, 0x6E00,
        "Management refuses a non-0x00 CLA with 6E00, so 80 1E on the \
         Management AID is refused rather than reset"
    );
    let mut mgmt = fapico2_mgmt::ManagementApp::new();
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    mgmt.process(&[0x80, 0x1E, 0x00, 0x00, 0x00], &mut resp);
    let (data, sw) = split(resp.as_slice());
    assert_eq!(sw, SW_CLA_NOT_SUPPORTED, "a 0x80 RESET-shaped APDU on Management");
    assert!(data.is_empty(), "and it cleared nothing");
    assert!(!mgmt.has_config(), "no config was written by the refused APDU");
    // And the same four bytes on this applet are a FlashInfo read.
    let mut h = Harness::wired();
    assert_eq!(h.drive(&[0x80, INS_READ, READ_P1_FLASH_INFO, 0x00, 0x00]).1, 0x9000);
}

/// An APDU shorter than the 4-byte header is a length refusal, checked
/// **before** the CLA so it cannot be indexed (the US-701 panic class).
#[test]
fn a_short_apdu_is_a_length_refusal() {
    let mut h = Harness::wired();
    for len in 0..4usize {
        let apdu = vec![0x80u8; len];
        let (data, sw) = h.drive(&apdu);
        assert_eq!(sw, 0x6700, "{len}-byte APDU");
        assert!(data.is_empty());
    }
}

/// An INS outside the four is `6D00`. The set is *enumeration*, not vigilance:
/// the crate defines no other INS, so a fifth command would have to be added
/// here before it could be reached at all.
#[test]
fn an_unknown_ins_is_refused() {
    let mut h = Harness::wired();
    for ins in [0x00u8, 0x10, 0x1B, 0x20, 0xA4, 0xFF] {
        let (_, sw) = h.drive(&[0x80, ins, 0x01, 0x00, 0x00]);
        assert_eq!(sw, 0x6D00, "INS {ins:#04x}");
    }
}

/// A READ P1 outside the three targets is refused rather than answered with an
/// empty blob — the read has no operands, so a fourth P1 names nothing.
#[test]
fn an_unknown_read_p1_is_refused() {
    let mut h = Harness::wired();
    for p1 in [0x00u8, 0x04, 0x10, 0xFF] {
        let (data, sw) = h.drive(&[0x80, INS_READ, p1, 0x00, 0x00]);
        assert_eq!(sw, 0x6A86, "P1 {p1:#04x}");
        assert!(data.is_empty());
    }
}

/// SELECT and the four INS are the entire command set, and `select` /
/// `select_apdu` both answer `9000` — the client refuses to go further
/// otherwise (`pcsc.rs:66-71`).
#[test]
fn select_answers_ok_and_holds_no_session_state() {
    let mut app = RescueApp::new();
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    assert_eq!(app.select(false), 0x9000);
    // An internal re-select preserves nothing here, because there is nothing
    // to preserve: the applet has no security state to reset.
    assert_eq!(app.select_apdu(true, &select_apdu(), &mut resp), 0x9000);
    app.deselect();
    let mut h = Harness::bare();
    let (data, sw) = h.select();
    assert_eq!(sw, 0x9000);
    assert_eq!(data, h.app.select_block().to_vec(), "stable across selections");
}

// ── the properties the threat model says must hold ────────────────────────

/// Threat model §2: *no sequence of `CLA 0x80` APDUs against this AID changes
/// any byte of any credential.* The applet holds no durable state at all — no
/// store slot, no dirty flag, no RAM copy of the record — so the invariant
/// holds by construction rather than by a per-command refusal.
///
/// This test drives the **full command matrix** through the store the persist
/// gate would use, and asserts the gate is a clean no-op throughout: a snapshot
/// diff over the matrix is the shape §2 asks for, and with an empty store and
/// an inert persist hook it is also the strongest statement this crate can
/// make about what it does not touch.
#[test]
fn no_command_in_the_matrix_writes_durable_state() {
    use fapico2_platform::secure_store::{HostSecureStore, SecureStore};
    let mut store = HostSecureStore::new();
    // Seed one unrelated record so a stray write is visible rather than a
    // write into an empty store that happens to be a no-op.
    store.write(b"unrelated.key", &[0xAA, 0xBB, 0xCC]).unwrap();

    let mut h = Harness::populated();
    for apdu in [
        vec![0x80, INS_READ, READ_P1_PHY_CONFIG, READ_P2_PHY_CONFIG, 0x00],
        vec![0x80, INS_READ, READ_P1_FLASH_INFO, 0x00, 0x00],
        vec![0x80, INS_READ, READ_P1_SECURE_BOOT_STATUS, 0x00, 0x00],
        write_apdu(&[0x00, 0x04, 0xFA, 0x20, 0x00, 0x09]),
        write_apdu(&[0x05, 0x01, 0x32]),
        write_apdu(&[0x0B, 0x01, 0x00]),
        write_apdu(&[0x09, 0x01, 0x00]),
        vec![0x80, INS_REBOOT, 0x00, 0x00, 0x00],
        vec![0x80, INS_SECURE, 0x00, 0x01, 0x00],
        vec![0x00, INS_READ, READ_P1_PHY_CONFIG, 0x01, 0x00],
        vec![0x80, 0x99, 0x01, 0x00, 0x00],
        vec![0x80, INS_WRITE],
    ] {
        h.drive(&apdu);
        assert!(
            !h.app.persist_state(&mut store),
            "{apdu:02X?}: the Rescue applet must never ask the persist gate to write"
        );
        assert!(!h.app.is_dirty(), "{apdu:02X?}: and must never be left dirty");
    }
    let mut buf = [0u8; 3];
    assert_eq!(store.read(b"unrelated.key", &mut buf).unwrap(), 3);
    assert_eq!(buf, [0xAA, 0xBB, 0xCC], "the unrelated record is untouched");
    assert_eq!(h.stored().vid_pid, Some(0xFA20_0009), "the owner's own record did move");
}

/// The persist and factory-wipe hooks are the inert defaults, which is what
/// makes "the applet cannot reach key material" checkable rather than asserted:
/// there is no slot for it to write and no state for it to wipe.
#[test]
fn the_applet_persists_nothing_and_wipes_nothing() {
    use fapico2_platform::secure_store::HostSecureStore;
    let mut store = HostSecureStore::new();
    let mut app = RescueApp::new();
    assert!(
        !app.persist_state(&mut store),
        "no durable state of the applet's own, so the persist gate is always a clean no-op"
    );
    assert!(!app.is_dirty(), "and it can never be left dirty");
    app.mark_dirty();
    assert!(!app.is_dirty(), "mark_dirty has nothing to mark");
    // A management factory reset calls every applet; this one stores nothing,
    // so the correct action is the no-op default and the identity block must
    // survive it unchanged.
    app.factory_wipe();
    let mut h = Harness::bare();
    let (data, sw) = h.select();
    assert_eq!(sw, 0x9000);
    assert_eq!(data, h.app.select_block().to_vec());
}

/// The four INS values and the CLA are stated as constants, and the constants
/// are the client's bytes. A drift between the two is the failure this applet is
/// most exposed to, because the client is the only consumer and there is no
/// second implementation to catch it.
#[test]
fn the_ins_and_cla_constants_are_the_client_bytes() {
    assert_eq!(INS_READ, 0x1E, "RescueInstruction::Read, constants.rs:139");
    assert_eq!(INS_WRITE, 0x1C, "RescueInstruction::Write, constants.rs:120");
    assert_eq!(INS_SECURE, 0x1D, "RescueInstruction::Secure, constants.rs:127");
    assert_eq!(INS_REBOOT, 0x1F, "RescueInstruction::Reboot, constants.rs:146");
    assert_eq!(CLA_PROPRIETARY, 0x80, "APDU_CLA_PROPRIETARY, constants.rs:68");
    assert_eq!(WRITE_P1_PHY_CONFIG, 0x01, "WriteParam::PhyConfig, constants.rs:171");
    assert_eq!(READ_P1_PHY_CONFIG, 0x01, "ReadParam::PhyConfig, constants.rs:156");
    assert_eq!(READ_P1_FLASH_INFO, 0x02, "ReadParam::FlashInfo, constants.rs:159");
    assert_eq!(READ_P1_SECURE_BOOT_STATUS, 0x03, "ReadParam::SecureBootStatus, constants.rs:162");
    assert_eq!(READ_P2_PHY_CONFIG, 0x01, "the read's P2, ops.rs:295");
}
