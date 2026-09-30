//! RS-Key vendor LED applet — AID `F0 00 00 00 01` (US-160a / US-160b,
//! PICOForge-COMPAT).
//!
//! One AID-dispatched CCID applet with two commands, both over CLA `0x00`
//! (the Rescue applet, by contrast, uses CLA `0x80` — the two share no trust
//! level, which is why they are separate crates; see
//! `docs/tasks/phase-gj-decision-validation-laya.md`, D-GJ-1):
//!
//! * `GET` (INS `0x11`) — emit the 17-byte `EF_LED_CONF` block.
//! * `SET` (INS `0x10`) — write one status slot's colour + brightness and the
//!   global `steady` flag.
//!
//! # Why this is its own crate and not a module in `apps/mgmt`
//!
//! The workspace convention is one applet per crate, and this applet has no
//! relationship with the management applet beyond being reachable through the
//! same AID dispatcher. The Phase G/H split in the EPIC exists precisely so
//! the unauthenticated Rescue surface is reviewed *apart* from this benign LED
//! work; folding both into `fapico2-mgmt` would re-merge what the EPIC
//! deliberately separated. The EPIC's RED test name (`vendor_led.rs`) is
//! unchanged — it lives at `apps/vendor_led/tests/vendor_led.rs`.
//!
//! # The wire, byte-exact
//!
//! All line references are to the PicoForge client, the reference
//! implementation this applet is written to.
//!
//! | | |
//! |---|---|
//! | AID | `F0 00 00 00 01` — `picoforge/src/hal/rescue/constants.rs:484` |
//! | SELECT | `00 A4 04 04 05 F0 00 00 00 01` — CLA `0x00`, INS `0xA4`, P1 `0x04` (select by DF name), P2 `0x04` (return FCI) — `picoforge/src/hal/transport/pcsc.rs:54-61` |
//! | GET | `00 11 00 00 00` — no Lc, no data, trailing `Le = 0x00` — `ops.rs:719-725` |
//! | SET | `00 10 <brightness> <p2>` — 4 bytes, **no Lc and no Le** — `ops.rs:768-773` |
//! | P2 | `(color & 0x07) \| (steady ? 0x08 : 0) \| ((status & 0x03) << 4)` — `ops.rs:765-766` |
//!
//! The **doc comments** on the client's own `VendorLedInstruction` are wrong in
//! two places and the code above is what was implemented: `SetLed`
//! (`constants.rs:491-497`) documents "P1: Status indicator / P2: LED color",
//! but `ops.rs:768-773` puts *brightness* in P1 and the packed triple in P2;
//! and `GetLed` (`constants.rs:499-505`) documents a per-slot "P1: Status
//! indicator … Response: LED color byte", but `ops.rs:719-725` sends P1 = 0
//! and parses the **whole** 17-byte block. A GET is therefore slot-agnostic
//! and this applet ignores P1/P2 on it.
//!
//! The client **discards** the SELECT response data and checks only that the
//! status word is `9000` (`pcsc.rs:66-71`), so this applet is selectable
//! through the ordinary `dispatch.rs` AID path with no special casing — which
//! matters because the dispatcher's SELECT recogniser keys on P1 (`P1 == 0x04`,
//! `platform/src/dispatch.rs` `is_select_apdu`) and does not constrain P2, so
//! the client's `P2 = 0x04` arrives as a plain AID SELECT.
//!
//! ## GET emits exactly 17 bytes — never 16, never padded
//!
//! The block layout is `[steady, (effect, color, brightness, speed) × 4]`
//! (`picoforge/src/hal/common/led.rs:5`, fixture at `led.rs:51-57`), and the
//! client does **not** match the length against 9 / 13 / 17. It derives the
//! per-status stride by integer division and buckets the bytes positionally:
//!
//! ```text
//! let stride = (data.len() - 1) / N_STATUS;   // led.rs:25
//! ```
//!
//! so the buckets are `stride = 4` for a 17–20 byte response (the current
//! `[effect, color, brightness, speed]` record), `stride = 3` for 13–16 (read
//! as the pre-speed layout, `color_off = 1`) and `stride = 2` for 9–12 (read
//! as the pre-effect layout, `color_off = 0`, `led.rs:33`). A device that
//! miscounts by one to three bytes therefore produces **silently wrong
//! colours with no error on the host** — the client cannot tell a 16-byte
//! block from a 13-byte one, and a 16-byte block is read with every colour
//! offset by one. This applet has exactly one correct response length and
//! [`LED_BLOCK_LEN`] is the single constant that fixes it.
//!
//! ## SET merges: it never zeroes `effect` or `speed`
//!
//! The SET APDU carries four values — brightness (P1), colour, `steady` and
//! status index (P2) — and **no field for `effect` or `speed`**. Those two
//! live in the 17-byte block at record offsets 0 and 3 (`led.rs:51-57`) and
//! the client never reads them back (`led.rs:9`: "Only `color` and
//! `brightness` are surfaced to the config UI"), but they are still *stored*.
//!
//! A SET targeting slot *k* must therefore leave `block[1 + 4k]` (effect) and
//! `block[4 + 4k]` (speed) exactly as they were — including the targeted
//! slot's own, which are as unreachable by SET as any other slot's. The
//! obvious implementation (rebuild the whole block from the four decoded
//! values) silently animates the device's LEDs off, and the only symptom the
//! host can see is its own next GET. See [`VendorLedApp::set_slot_field`],
//! which writes single bytes precisely so the untouched fields cannot be
//! clobbered by construction.
//!
//! ## The client's write loop is four independent sessions
//!
//! `write_led_config` issues four complete SELECT-then-SET cycles, one per
//! status slot (`picoforge/src/hal/io.rs:199-205`), and nothing makes the run
//! atomic — a failure at slot 2 leaves slots 0 and 1 already written. The
//! device side is not required to be atomic (there is no journal to roll
//! back), but it must not make the partial outcome worse than it already is:
//! each SET is a single durable-block update applied before its `9000`.
//!
//! ## `steady` is global, not per-slot
//!
//! The bit rides P2 on every one of the client's four writes, and the block
//! holds a single `steady` byte at offset 0. So a SET for slot 2 also updates
//! the global flag — it is not a per-slot property, and storing it per slot
//! would be a format the client cannot express.

#![cfg_attr(not(feature = "host"), no_std)]

use fapico2_platform::dispatch::{
    App, MAX_RESPONSE, Sw, SW_INS_NOT_SUPPORTED, SW_OK, SW_WRONG_LENGTH,
};
use fapico2_platform::secure_store::{SecureStore, SecureStoreError};
use heapless::Vec as HeaplessVec;

/// RS-Key vendor LED AID (`picoforge/src/hal/rescue/constants.rs:484`).
pub const VENDOR_LED_AID: &[u8] = &[0xF0, 0x00, 0x00, 0x00, 0x01];

/// `SET` — write one status slot's colour + brightness (`ops.rs:768-773`).
pub const INS_SET: u8 = 0x10;
/// `GET` — read the whole block (`ops.rs:719-725`).
pub const INS_GET: u8 = 0x11;

/// The only class byte this applet accepts. The reference client sends
/// `APDU_CLA_ISO` (`ops.rs:721`, `ops.rs:769`); anything else is refused,
/// matching the gate `apps/mgmt` already applies to its own commands.
pub const CLA_ISO: u8 = 0x00;

/// Number of device-status slots, in `LedStatus` order (idle, processing,
/// touch, boot — `picoforge/src/hal/types.rs:180-186`).
pub const SLOT_COUNT: usize = 4;

/// The wire length of `EF_LED_CONF`: `1 + 4 × 4` (`led.rs:5`). See the module
/// docs for why this exact value is load-bearing.
pub const LED_BLOCK_LEN: usize = 1 + SLOT_COUNT * 4;

/// Byte stride of one status record inside the block (the "per-status stride"
/// the client recomputes as `(len - 1) / 4`, `led.rs:25`).
const RECORD_STRIDE: usize = 4;

/// Offset of record `index` within the block (the `1` skips `steady`).
const RECORD_BASE: fn(usize) -> usize = |index| 1 + RECORD_STRIDE * index;

// Record field offsets, relative to `RECORD_BASE(index)`.
const OFF_EFFECT: usize = 0;
const OFF_COLOR: usize = 1;
const OFF_BRIGHTNESS: usize = 2;
const OFF_SPEED: usize = 3;

// `LedColor` — a 3-bit R/G/B triple, not an arbitrary palette
// (`picoforge/src/hal/rescue/constants.rs:514-538`).
pub const LED_COLOR_OFF: u8 = 0;
pub const LED_COLOR_RED: u8 = 1;
pub const LED_COLOR_GREEN: u8 = 2;
pub const LED_COLOR_BLUE: u8 = 3;
pub const LED_COLOR_YELLOW: u8 = 4;
pub const LED_COLOR_MAGENTA: u8 = 5;
pub const LED_COLOR_CYAN: u8 = 6;
pub const LED_COLOR_WHITE: u8 = 7;

/// Human-readable `LedColor` names, indexed by the 3-bit colour code
/// (`constants.rs:514-538`).
pub const LED_COLOR_NAMES: [&str; 8] = [
    "Off", "Red", "Green", "Blue", "Yellow", "Magenta", "Cyan", "White",
];

// `LedStatus` — the slot index the client's P2 names
// (`picoforge/src/hal/rescue/constants.rs:599-622`).
pub const LED_STATUS_IDLE: u8 = 0;
pub const LED_STATUS_PROCESSING: u8 = 1;
pub const LED_STATUS_TOUCH: u8 = 2;
pub const LED_STATUS_BOOT: u8 = 3;

/// Human-readable `LedStatus` names, in slot order (`constants.rs:599-622`).
/// The order is the block's record order (`led.rs:51-57`).
pub const LED_STATUS_NAMES: [&str; 4] = ["Idle", "Processing", "Touch", "Boot"];

/// P2 bit masks (`ops.rs:765-766`).
const P2_COLOR_MASK: u8 = 0x07;
const P2_STEADY_BIT: u8 = 0x08;
/// Bits 6–7 of P2 are reserved. The client never sets them — `ops.rs:766`
/// masks colour to 3 bits and status to 2, so the byte's high pair is always
/// zero — and the decode below ignores them, so a future client revision
/// that does set them cannot be misread as a colour or a status.
const P2_STATUS_SHIFT: u32 = 4;
const P2_STATUS_MASK: u8 = 0x03;

/// ISO 7816-4 status words. `SW_CLA_NOT_SUPPORTED` is spelled out here rather
/// than imported so this crate's refusal reasons are readable in one place,
/// matching `apps/mgmt`.
const SW_CLA_NOT_SUPPORTED: Sw = 0x6E00;

/// Secure-store slot for the durable `EF_LED_CONF` block. The RP2350 secure
/// partition backs the store on device — never plain flash. The `v1` suffix
/// leaves room for a format bump without silently reading an older layout as
/// the current one ([`VendorLedApp::boot`] length-checks precisely so a
/// foreign-sized blob is refused rather than reinterpreted).
const LED_SLOT: &[u8] = b"vled.conf.v1";

/// The factory block: every byte zero.
///
/// Chosen deliberately rather than as a plausible-looking colour profile.
/// Nothing in the client pins a default (`LedStatusConfig` is built entirely
/// from what the device returns — `ops.rs:730-740`), so any non-zero value
/// here would be this firmware inventing a brand profile it has no way to
/// honour: the applet stores what the host wrote, it does not drive an RGB
/// LED. Reporting "no LED configuration" on a fresh token is also the state
/// the factory-reset contract can be asserted against — [`App::factory_wipe`]
/// restores exactly these bytes, so "reset" and "first boot" are the same
/// state, byte for byte.
pub const FACTORY_BLOCK: [u8; LED_BLOCK_LEN] = [0u8; LED_BLOCK_LEN];

/// One status slot's stored LED configuration, in block record order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedSlot {
    /// Animation effect. Not on the wire — see the module docs.
    pub effect: u8,
    /// `LedColor`, 0..=7 (`constants.rs:514-538`).
    pub color: u8,
    /// Raw brightness, `0..=255`; carried in P1 of the SET APDU.
    pub brightness: u8,
    /// Animation speed. Not on the wire — see the module docs.
    pub speed: u8,
}

pub struct VendorLedApp {
    /// The durable 17-byte `EF_LED_CONF` block, always exactly
    /// [`LED_BLOCK_LEN`] bytes: a fixed array, so the GET length cannot drift
    /// with a short write or a corrupt store read.
    block: [u8; LED_BLOCK_LEN],
    /// Durable state changed since the last persist. Mirrors the `apps/mgmt`
    /// pattern (`persist_state` / `mark_dirty` / `is_dirty`), which the
    /// platform persist gate drives after every dispatched APDU.
    dirty: bool,
}

impl Default for VendorLedApp {
    fn default() -> Self {
        Self::new()
    }
}

impl VendorLedApp {
    /// A factory-fresh applet holding [`FACTORY_BLOCK`].
    pub const fn new() -> Self {
        Self {
            block: FACTORY_BLOCK,
            dirty: false,
        }
    }

    /// An applet pre-loaded with a complete block — the **profile install**
    /// seam.
    ///
    /// `effect` and `speed` are unreachable from the wire protocol (see the
    /// module docs), so this is the only way they can ever be set to anything
    /// but zero on a shipped device: a factory-provisioned profile, or the
    /// setup step of a test that then proves a SET leaves them alone. It is
    /// deliberately not reachable from any INS.
    pub const fn with_block(block: [u8; LED_BLOCK_LEN]) -> Self {
        Self { block, dirty: false }
    }

    /// Boot: reload the durable block from the platform secure store (the
    /// RP2350 secure partition on device). A missing, short, or oversized
    /// record boots to [`FACTORY_BLOCK`] rather than to a partial block —
    /// the length is the format's only self-describing field, and a
    /// differently-sized blob is a foreign layout, not a truncated one.
    pub fn boot(store: &mut dyn SecureStore) -> Self {
        let mut app = Self::new();
        let mut buf = [0u8; LED_BLOCK_LEN];
        if let Ok(n) = store.read(LED_SLOT, &mut buf) {
            if n == LED_BLOCK_LEN {
                app.block = buf;
            }
        }
        app
    }

    /// Persist the block through the secure store (unconditional write; the
    /// [`App::persist_state`] hook gates this on dirtiness).
    pub fn save(&self, store: &mut dyn SecureStore) -> Result<(), SecureStoreError> {
        store.write(LED_SLOT, &self.block)
    }

    /// The exact bytes a GET returns.
    pub const fn block(&self) -> &[u8; LED_BLOCK_LEN] {
        &self.block
    }

    /// The global `steady` flag (block offset 0). Any non-zero byte means
    /// steady, on the client's side (`led.rs:34`); this applet stores `0x01`
    /// / `0x00` so the byte is canonical either way.
    pub fn steady(&self) -> bool {
        self.block[0] != 0
    }

    /// Slot `index`'s four stored bytes. `None` for an index outside
    /// `0..SLOT_COUNT` — the block is a fixed-size format, so a bad index is
    /// a caller error and there is nothing to read.
    pub fn slot(&self, index: usize) -> Option<LedSlot> {
        if index >= SLOT_COUNT {
            return None;
        }
        let b = RECORD_BASE(index);
        Some(LedSlot {
            effect: self.block[b + OFF_EFFECT],
            color: self.block[b + OFF_COLOR],
            brightness: self.block[b + OFF_BRIGHTNESS],
            speed: self.block[b + OFF_SPEED],
        })
    }

    /// Write the whole record for `index` (profile install / factory wipe).
    /// Unlike a wire SET this *does* touch `effect` and `speed` — that is the
    /// distinction the merge in [`VendorLedApp::cmd_set`] exists to preserve.
    /// `None` slot index → no change.
    pub fn set_slot(&mut self, index: usize, slot: LedSlot) {
        if index >= SLOT_COUNT {
            return;
        }
        let b = RECORD_BASE(index);
        self.block[b + OFF_EFFECT] = slot.effect;
        self.block[b + OFF_COLOR] = slot.color;
        self.block[b + OFF_BRIGHTNESS] = slot.brightness;
        self.block[b + OFF_SPEED] = slot.speed;
        self.dirty = true;
    }

    /// Set the global `steady` flag (block offset 0). Stored canonically as
    /// `0x01` / `0x00` — the client treats any non-zero byte as steady
    /// (`led.rs:34`), so a canonical byte is what a GET must show.
    pub fn set_steady(&mut self, steady: bool) {
        self.block[0] = u8::from(steady);
        self.dirty = true;
    }

    /// Write **one** byte of one record, leaving every other byte of the
    /// block untouched.
    ///
    /// This is the whole point of the SET implementation. The client's APDU
    /// carries `color` and `brightness` and nothing else, so a SET that
    /// rebuilt the record from decoded values would have to invent `effect`
    /// and `speed` — and inventing them means zero, which silently cancels
    /// whatever animation the profile installed. Writing the two fields
    /// individually makes "the other two fields are preserved" true by
    /// construction rather than by remembering to copy them.
    ///
    /// `steady` is written by the same call: it is a *global* flag, and the
    /// client sends it on all four of its per-slot writes (`io.rs:199-205`),
    /// so a SET for slot 2 legitimately moves it.
    fn set_slot_field(&mut self, index: usize, steady: bool, color: u8, brightness: u8) {
        let b = RECORD_BASE(index);
        self.block[0] = u8::from(steady);
        self.block[b + OFF_COLOR] = color;
        self.block[b + OFF_BRIGHTNESS] = brightness;
        // `block[b + OFF_EFFECT]` and `block[b + OFF_SPEED]` are deliberately
        // not written: they are not on the wire and must survive.
        self.dirty = true;
    }

    /// SET (INS `0x10`), P1 = brightness, P2 = the packed triple
    /// (`ops.rs:765-766`).
    fn cmd_set(&mut self, p1: u8, p2: u8) {
        let color = p2 & P2_COLOR_MASK;
        let steady = p2 & P2_STEADY_BIT != 0;
        // The client never sets bits 6–7 (see `P2_STATUS_SHIFT`); the shift
        // below simply drops them along with the colour and steady bits.
        let status = ((p2 >> P2_STATUS_SHIFT) & P2_STATUS_MASK) as usize;
        self.set_slot_field(status, steady, color, p1);
    }
}

impl App for VendorLedApp {
    fn aid(&self) -> &[u8] {
        VENDOR_LED_AID
    }

    fn select(&mut self, _internal: bool) -> Sw {
        SW_OK
    }

    fn deselect(&mut self) {}

    fn select_apdu(
        &mut self,
        _internal: bool,
        apdu: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        // P1 is 0x04 (select by DF name) per ISO 7816-4; the client also sets
        // P2 = 0x04 (return FCI, `pcsc.rs:58`). This applet holds no
        // per-selection state, so the only thing P2 can decide is whether an
        // FCI comes back.
        let p2 = apdu.get(3).copied().unwrap_or(0);
        if p2 & 0x0C == 0 {
            return SW_OK;
        }
        // Minimal ISO 7816-4 FCID template carrying the DF name:
        // `62 07 4F 05 F0 00 00 00 01`. The client throws this away
        // (`pcsc.rs:66-71` checks only the status word), but a standard
        // SELECT-with-FCI is answered with a well-formed FCI rather than an
        // empty one — and the side effect is in the client's favour: its
        // firmware sniff reads `data[2] >= 8` as "this is an RS-Key device"
        // (`pcsc.rs:75-80`), and the DF-name tag `0x4F` lands there. Nothing
        // on the LED path reads the sniffed type — `read_led_config` /
        // `write_led_status` dispatch on the caller's `DeviceMethod`
        // (`picoforge/src/hal/io.rs:180-205`), not on it — so this is a
        // courtesy to any generic ISO 7816-4 tool, not a load-bearing choice.
        resp.extend_from_slice(&FCI_TEMPLATE).ok();
        SW_OK
    }

    fn process(&mut self, apdu: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        // Header guard first: a sub-4-byte APDU passes the CLA comparison
        // below and would then index `apdu[2]`/`apdu[3]` out of bounds
        // (the US-701 panic class, `apps/mgmt` `process`).
        if apdu.len() < 4 {
            write_sw(resp, SW_WRONG_LENGTH);
            return;
        }
        if apdu[0] != CLA_ISO {
            write_sw(resp, SW_CLA_NOT_SUPPORTED);
            return;
        }
        match apdu[1] {
            // GET is case-4 on this wire: the client appends `Le = 0x00`
            // (`ops.rs:719-725`), so its APDU is 5 bytes. Nothing after the
            // 4-byte header is load-bearing for a read, so a longer wire is
            // unambiguous and is accepted rather than refused.
            INS_GET => {
                // `self.block` is a `[u8; LED_BLOCK_LEN]`, so this appends
                // exactly 17 bytes and the response length is a property of
                // the type, not of a `len` computed somewhere else.
                resp.extend_from_slice(&self.block).ok();
                write_sw(resp, SW_OK);
            }
            // SET is case-3 with no data: exactly 4 bytes, no Lc and no Le
            // (`ops.rs:768-773`). A fifth byte would be an Lc (or an Le this
            // applet does not define), and silently ignoring an unexpected
            // framing is how a host ends up believing it wrote a colour it
            // did not — so an off-length SET is refused rather than absorbed.
            INS_SET => {
                let sw = if apdu.len() == 4 {
                    self.cmd_set(apdu[2], apdu[3]);
                    SW_OK
                } else {
                    SW_WRONG_LENGTH
                };
                write_sw(resp, sw);
            }
            _ => write_sw(resp, SW_INS_NOT_SUPPORTED),
        }
    }

    fn persist_state(&mut self, store: &mut dyn SecureStore) -> bool {
        if !self.dirty {
            return false;
        }
        // Failure contract (US-421): a failed store write leaves the app
        // dirty so the next persist run retries.
        let wrote = self.save(store).is_ok();
        if wrote {
            self.dirty = false;
        }
        wrote
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// A management factory reset returns every applet to factory-fresh
    /// (`platform/src/dispatch.rs` `factory_wipe_apps`, called by the owning
    /// transport before the persist gate so the emptied state reaches the
    /// store in the same gate run). A host that can reset the token can
    /// restore its LED profile, so the profile is part of the wiped state.
    fn factory_wipe(&mut self) {
        self.block = FACTORY_BLOCK;
        self.dirty = true;
    }
}

/// `62 07 4F 05 F0 00 00 00 01` — see [`VendorLedApp::select_apdu`].
const FCI_TEMPLATE: [u8; 9] = [
    0x62, 0x07, // FCI template (tag 62, length 7)
    0x4F, 0x05, // DF name (tag 4F, length 5)
    0xF0, 0x00, 0x00, 0x00, 0x01, // …the AID
];

fn write_sw(resp: &mut HeaplessVec<u8, MAX_RESPONSE>, sw: Sw) {
    resp.extend_from_slice(&sw.to_be_bytes()).ok();
}
