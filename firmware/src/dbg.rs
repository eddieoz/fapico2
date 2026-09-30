//! Temporary on-device RAM event log — **diagnostic build only**.
//!
//! Gated behind the `dbg-log` cargo feature (off by default: the production
//! binary is byte-identical and the `dlog!` call sites compile to nothing).
//! Exists to root-cause the CCID wedge (S-721-2 live diagnosis,
//! 2026-09-16): the serve-loop tasks are instrumented at every point that
//! can block forever (EP OUT reads, the parse/dispatch/persist pipeline,
//! the EP IN reply write), and the ring is drained over the CTAP-HID
//! transport — `hid_task` and its endpoints are independent of
//! `ccid_task`, so the log is retrievable **after** a CCID wedge, with no
//! SWD probe or UART attached.
//!
//! Layout: a fixed 12 KiB static ring of 24-byte records
//! (`t_us u64, seq u32, task u8, event u8, pad u16, a u32, b u32`), fed by
//! [`log`] via the `dlog!` macro and read back by [`handle_dbg`] (CTAP-HID
//! vendor command [`DBG_CMD`] on the per-boot random channel — US-922).
//!
//! Writer safety: the executor is cooperative (one core, no preemption) and
//! [`log`] completes without `.await`, so a record is written atomically
//! with respect to task switching — the same rationale as the `static mut`
//! slots in [`crate::boot`].

// US-933: this module also compiles for the release-allowed `apdu-trace`
// capture builds (which feed the ring only via
// `apdu_trace::trace_exchange`), so some event codes / helpers are
// legitimately unreferenced there — allow, don't cfg-spray each const.
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use embassy_rp::gpio::Output;
use embassy_rp::peripherals::USB;
use embassy_time::Instant;
use fapico2_platform::usb::{Endpoint, In};

use crate::tasks::send_hid_report;
use fapico2_firmware::ctap_hid::HID_FIRST_PAYLOAD;

/// Record size in bytes.
pub const ENTRY: usize = 24;
/// Ring capacity: 512 × 24 B = 12 KiB static RAM (RP2350 has 520 KiB).
pub const ENTRIES: usize = 512;

// Writer task ids (record byte 12).
pub const T_MAIN: u8 = 0;
pub const T_CCID: u8 = 1;
pub const T_HID: u8 = 2;

// Event codes (record byte 13; the host-side name table lives in
// /tmp/pull_dbg_log.py).
pub const E_BOOT: u8 = 1; // a: boot stage
pub const E_OUTRD0: u8 = 10; // a: `have` — zero-byte EP OUT read
pub const E_OUTRDE: u8 = 11; // a: `have` — EP OUT read error
pub const E_HDR: u8 = 12; // a: (msg_type << 16) | have, b: dw_length
pub const E_HDRBIG: u8 = 13; // a: (slot << 8) | seq — oversized-length error path (US-920)
pub const E_PREAD: u8 = 14; // a: `have`, b: dw_length — payload chunk read
pub const E_PARSE: u8 = 15; // a: request variant code, 255 = parse None
pub const E_DISP: u8 = 16; // a: (sw << 16) | apdu_len, b: dispatch elapsed µs
pub const E_PST: u8 = 17; // a: dirty-app count — persist gate start
pub const E_PSD: u8 = 18; // a: ok | (still_dirty << 1), b: persist elapsed µs
pub const E_IW0: u8 = 19; // a: reply length — EP IN write start
pub const E_IW1: u8 = 20; // a: ok, b: EP IN write elapsed µs
pub const E_ERR: u8 = 21; // a: site code — misc error/drop
pub const E_RESYNC: u8 = 22; // a: dropped bytes — US-920 stale-partial resync
pub const E_HIDCMD: u8 = 30; // a: (cmd << 8) | len, b: channel cid
pub const E_HIDPERS: u8 = 31; // a: wrote | (ok << 1), b: persist elapsed µs

// US-930: the US-919 foreign-image wipe decision path (`boot::ensure_fw_manifest`).
// One record per decision point so a D7 replay shows exactly how far the path
// got (hash → slot read → decision → stamp/wipe), and the hash prefixes make
// the two sides of the comparison visible in the trace itself.
pub const E_FWLEN: u8 = 32; // a: manifest region length (bytes)
pub const E_FWHASH: u8 = 33; // a: first 4 bytes (BE) of the computed hash
pub const E_FWSTORED: u8 = 34; // a: stored slot bytes (32 | 0 = absent/corrupt), b: first 4 bytes (BE) of the stored hash (0 when absent)
pub const E_FWDECIDE: u8 = 35; // a: decision (0 = Load, 1 = WipeAndFresh), b: first 4 bytes (BE) of the current hash
pub const E_FWSTAMP: u8 = 36; // a: last-known-good stamp ok (1) | failed (0)
pub const E_FWWIPE: u8 = 37; // a: wipe_all ok (1) | failed (0), b: wipe compiled in (1) | dev log-only knob (0)

// US-933: APDU-level CCID trace (`apdu-trace` feature — release-allowed
// capture build, see `apdu_trace.rs`). Header records name direction +
// length + SW; `E_APDU_CHUNK` records stream the raw bytes 8 per record
// (a = bytes 0–4 BE, b = bytes 4–8 BE). Decoder:
// tests/scripts/us933_pull_trace.py.
pub const E_APDU_SESS: u8 = 40; // a: per-boot session tag (BE u32)
pub const E_APDU_REQ: u8 = 41; // a: request length, b: per-session APDU seq
pub const E_APDU_RSP: u8 = 42; // a: response length (incl. SW), b: status word
pub const E_APDU_CHUNK: u8 = 43; // a: bytes 0–4 BE, b: bytes 4–8 BE

// US-1020: the presence handshake. `firmware/src/presence.rs` stamps one of
// these per press / arm / discard / window / grant, with the runtime's
// monotonic clock, and the device bin installs the sink that routes them
// here. `a` is the presence tag (0 where none applies), `b` the clock in ms —
// except `E_PGRANT`, whose `b` is the **touch→consent latency** in ms, which
// is the figure US-1022 is judged against. These are the only presence
// records the tree has: there is no vendor counter sub-command
// (`docs/erase-budget.md` §2.3), so the US-922 ring is the whole surface.
pub const E_PRESS: u8 = 50; // a: 0, b: press clock (ms)
pub const E_PARM: u8 = 51; // a: armed tag, b: arm clock (ms)
pub const E_PDISCARD: u8 = 52; // a: 0, b: press clock (ms) — anti-harvest discard
pub const E_PWINDOW: u8 = 53; // a: window tag, b: open clock (ms)
pub const E_PGRANT: u8 = 54; // a: grant tag, b: arm→grant latency (ms)

// `boot-timeline` capture: one record per boot-phase boundary. `a` is the
// phase id below, `b` is 0. The record's own `t_us` is the measurement —
// `log` already stamps `Instant::now().as_micros()`, so the decoder takes
// deltas between consecutive phases and needs no second field.
//
// Ids are ordered by where they sit on the boot path. Gaps are deliberate:
// each id was added for one measurement, and a gap is cheaper than
// renumbering a table a host decoder may already hold.
pub const E_PHASE: u8 = 60;

pub const P_MAIN_ENTERED: u32 = 1; // top of `main`, before `embassy_rp::init`
pub const P_HAL_INIT: u32 = 2; // `embassy_rp::init` returned
pub const P_TRNG_READY: u32 = 3; // clock proven + sanity draw done
pub const P_STORE_KEY: u32 = 4; // OTP key row read + store key derived
pub const P_STORE_MOUNTED: u32 = 5; // slot decided, winning image in `STORE`
pub const P_BOOT_ENTROPY: u32 = 6; // `ensure_boot_entropy` done
pub const P_DRBG: u32 = 7; // `init_drbg` done — a DRBG now exists
pub const P_FW_MANIFEST: u32 = 8; // `ensure_fw_manifest` decided
pub const P_MIGRATION: u32 = 9; // `run_first_boot_migration` done
pub const P_BOOT_FIDO: u32 = 10; // FIDO app constructed in place
pub const P_BOOT_OATH: u32 = 11; // OATH app constructed in place
pub const P_GATE1_PRE: u32 = 12; // entering persist gate #1
pub const P_GATE1_POST: u32 = 13; // persist gate #1 done (any flash program)
pub const P_BACKEND: u32 = 14; // `DeviceBackend::boot` done (trussed mount)
pub const P_DISPATCHER: u32 = 15; // all apps registered
pub const P_GATE2_PRE: u32 = 16; // entering persist gate #2
pub const P_GATE2_POST: u32 = 17; // persist gate #2 done
pub const P_USB_UP: u32 = 18; // `Usb::new` + `usb_task` spawned
pub const P_SERVING: u32 = 19; // every serve-loop task spawned

static mut BUF: [[u8; ENTRY]; ENTRIES] = [[0u8; ENTRY]; ENTRIES];
static mut COUNT: u32 = 0;

/// Append one record. Synchronous (no `.await`) — see the module doc for
/// the writer-safety rationale. Pointer-based (no mutable reference to the
/// static) so the record write is a plain store sequence.
pub fn log(task: u8, event: u8, a: u32, b: u32) {
    unsafe {
        let t = Instant::now().as_micros();
        let i = (COUNT % ENTRIES as u32) as usize;
        // SAFETY: `BUF` is a `static mut` (see the module doc); `log` is the
        // sole writer and completes without `.await`, so the store sequence
        // below is atomic with respect to task switching.
        let base = core::ptr::addr_of_mut!(BUF[0][0]).add(i * ENTRY);
        let t_b = t.to_le_bytes();
        let c_b = COUNT.to_le_bytes();
        let a_b = a.to_le_bytes();
        let b_b = b.to_le_bytes();
        core::ptr::copy_nonoverlapping(t_b.as_ptr(), base, 8);
        core::ptr::copy_nonoverlapping(c_b.as_ptr(), base.add(8), 4);
        *base.add(12) = task;
        *base.add(13) = event;
        core::ptr::copy_nonoverlapping(a_b.as_ptr(), base.add(16), 4);
        core::ptr::copy_nonoverlapping(b_b.as_ptr(), base.add(20), 4);
        COUNT = COUNT.wrapping_add(1);
    }
}

/// Total records appended so far (wraps at 2^32).
pub fn count() -> u32 {
    unsafe { COUNT }
}

/// Per-`(task, event)` last-record timestamps for [`log_throttled`]
/// (3 tasks × 32 event codes).
static mut LAST_THROTTLE: [u64; 96] = [0; 96];

/// Rate-limited variant of [`log`]: records at most once per `min_us` per
/// `(task, event)` pair. For error-class events that can fire in a tight
/// back-off loop (endpoint read errors) — unthrottled, such a loop would
/// wrap the 512-record ring in ~5 s and destroy the pre-wedge history.
pub fn log_throttled(task: u8, event: u8, a: u32, b: u32, min_us: u64) {
    unsafe {
        let key = (task as usize) * 32 + (event as usize) % 32;
        let t = Instant::now().as_micros();
        if t.saturating_sub(LAST_THROTTLE[key]) >= min_us {
            LAST_THROTTLE[key] = t;
            log(task, event, a, b);
        }
    }
}

/// CTAP-HID debug command code (vendor range; `0x41` is the existing
/// vendor vault, so `0x42` is the debug log).
pub const DBG_CMD: u8 = 0x42;

/// The active drain channel (US-922): per-boot random, seeded from the
/// hardware TRNG by [`init_channel`] before the serve tasks spawn. `0`
/// = not initialized — and the selected channel can never be all-zero
/// (see `fapico2_firmware::dbg_cid`: degenerate draws are redrawn), so a
/// zero channel refuses every drain attempt instead of opening one.
static CID: AtomicU32 = AtomicU32::new(0);

/// Seed the per-boot drain channel and print it to the SWD/RTT console
/// **only** — never over USB, and not derivable from enumeration (US-922).
/// `cid` is the already-selected channel (full 32-bit TRNG entropy,
/// degenerate values redrawn away — see `fapico2_firmware::dbg_cid`); the
/// host-side pull script reads the value from the RTT stream (probe-rs
/// attach), then drives cmd [`DBG_CMD`].
pub fn init_channel(cid: [u8; 4]) {
    debug_assert!(
        fapico2_firmware::dbg_cid::dbg_cid_checked(cid).is_some(),
        "dbg channel must be non-degenerate (dbg_cid::dbg_cid_new)"
    );
    CID.store(u32::from_be_bytes(cid), Ordering::Release);
    defmt::info!(
        "dbg-log drain cid {:02x}{:02x}{:02x}{:02x} (RTT only)",
        cid[0], cid[1], cid[2], cid[3]
    );
}

/// The active drain channel (all-zero until [`init_channel`] ran).
pub fn channel() -> [u8; 4] {
    CID.load(Ordering::Acquire).to_be_bytes()
}

/// Drain/clear protocol (payload → response):
/// * `[0x01]` → `[count_le32, entries u8, entry_size u8]` (6 bytes)
/// * `[0x02, off_le32]` → raw ring bytes from `off`, ≤ 57 bytes
/// * `[0x03]` → clear (`COUNT = 0`), one ack byte
pub async fn handle_dbg<'d>(
    hid_in: &mut Endpoint<'d, USB, In>,
    channel: &[u8; 4],
    payload: &[u8],
) {
    let mut out = [0u8; HID_FIRST_PAYLOAD];
    let n = match payload.first() {
        Some(&0x01) => {
            out[0..4].copy_from_slice(&count().to_le_bytes());
            out[4] = ENTRIES as u8;
            out[5] = ENTRY as u8;
            6
        }
        Some(&0x02) => {
            let off = if payload.len() >= 5 {
                u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize
            } else {
                0
            };
            let bytes = ENTRIES * ENTRY;
            let start = off.min(bytes);
            let len = (bytes - start).min(HID_FIRST_PAYLOAD);
            // SAFETY: `BUF` is a contiguous `[[u8; ENTRY]; ENTRIES]`; this is
            // a read-only view taken in `hid_task` on the cooperative
            // executor — no writer can be mid-write (writes complete
            // synchronously, see module doc).
            let slice = unsafe {
                // SAFETY: read-only view of the same `static mut` ring — no
                // writer can be mid-write (see the module doc + `log`).
                core::slice::from_raw_parts(core::ptr::addr_of!(BUF[0][0]), bytes)
            };
            out[..len].copy_from_slice(&slice[start..start + len]);
            len
        }
        Some(&0x03) => {
            unsafe {
                COUNT = 0;
            }
            out[0] = 1;
            1
        }
        _ => 0,
    };
    if n > 0 {
        let _ = send_hid_report(hid_in, channel, DBG_CMD, &out[..n]).await;
    }
}

// ---------------------------------------------------------------------------
// US-929: the boot-stage ladder — a `dlog!` stage event AND a distinct LED
// pattern per boot stage, so a dark stage is identifiable from the LAST
// pattern shown (debug builds only: this whole module is behind the
// release-forbidden `dbg-log` feature, US-922).
//
// The LED is driven SYNCHRONOUSLY here (direct `Output` writes + a busy-wait
// on the 1 MHz RP2350 TIMER counter) — at the early stages the async
// executor/timers are not running yet, so a `Timer::after` would never wake.
// The single board LED (GPIO25, active-low) is the shared heartbeat /
// trussed-UI pin (`boot::LED_OUT`); during the boot stages the heartbeat task
// has not been polled yet, so the synchronous blinks own the pin.
//
// Stage mapping (the real boundaries in `main.rs`; `E_BOOT` record field
// `a` == the LED's blink count minus one):
//   1 = main entered / `.bss` cleared + embassy HAL + board LED mounted
//       (the very first `a=1` record is emitted at the top of `main`, BEFORE
//       the HAL init — a second `a=1` with the LED pattern means the HAL and
//       LED were mounted; seeing only the first localizes the gap in between)
//   2 = secure store mounted (slot decision + image restored into `STORE`)
//   3 = USB configured (the `Usb` device constructed and `usb_task` spawned)
//   4 = executor running (all serve-loop tasks spawned; `main` parks into the
//       executor loop — the 1 Hz heartbeat takes the LED over from here)
// The pre-Rust stages (cortex-m reset handler, `.bss` clearing, `.data`
// copy, `__pre_init`) live in the cortex-m-rt startup assembly / the build's
// link.x — not reachable from Rust — so "main entered" (stage 1) is the
// earliest observable rung (documented limitation; US-929).
// ---------------------------------------------------------------------------

/// Set once the board LED slot ([`crate::boot::LED_OUT`]) is initialized (at
/// the top of `main`). Before that the ladder's blink helper must no-op —
/// stage 1's `dlog!` fires, but there is no LED to pattern on yet.
/// (`allow(dead_code)`: only dbg-log builds call this — an apdu-trace-only
/// build compiles the module too, US-933.)
#[allow(dead_code)]
static LED_READY: AtomicBool = AtomicBool::new(false);

/// Mark the LED slot initialized (called by `main` right after the
/// write-once `LED_OUT` slot is filled). dbg-log and boot-timeline builds.
#[allow(dead_code)]
pub fn mark_led_ready() {
    LED_READY.store(true, Ordering::Release);
}

/// `boot-timeline`: blink the phase id, so a **frozen** board reports how far
/// it got with no debugger, no probe and no RTT.
///
/// # Why this exists
///
/// The CTAP-HID ring in [`log`] is the precise instrument, and it is useless
/// on a device that never enumerates — the ring is in RAM, and the only way
/// to read RAM on a dead board is the SWD probe. When the probe is not
/// attached, the LED is the only channel left, and "solid, not blinking"
/// says only that the boot stopped *somewhere*.
///
/// So each [`crate::P_*`] phase emits that many short blinks. The count is
/// read as a **transition count, not a light level**, which matters: the
/// board LED's polarity is a hardware fact this crate only assumes, and a
/// reading that depended on "on means on" would be a reading that could be
/// inverted by a board revision. N blinks-then-frozen names the phase
/// whichever way the pin is wired.
///
/// Phase 1 (`P_MAIN_ENTERED`) deliberately produces **no** blink: it fires
/// before `embassy_rp::init` and before the `LED_OUT` slot exists, and
/// touching that slot there would write through an uninitialised pointer.
/// The LED is no-op'd until [`mark_led_ready`], so the absence of a blink is
/// itself the answer for "froze before or during HAL init".
///
/// # The cost, and how to read a timing anyway
///
/// 40 ms on / 40 ms off per blink, so phase N costs 80·N ms and the whole
/// ladder adds **at most 1.5 s** to a boot that reaches phase 19. That is
/// not free, and a timing pulled from a `boot-timeline` build includes it.
/// Subtract `80 ms × (sum of the phase ids seen)`; the CTAP-HID ring's own
/// `t_us` values do **not** include it, because the ring record is written
/// *before* the blinks — which is why the ring is authoritative when it is
/// reachable and this is the fallback for when it is not.
#[allow(dead_code)]
pub fn phase_blinks(id: u8) {
    if !LED_READY.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: the `LED_OUT` slot was written exactly once at the top of
    // `main` before `mark_led_ready()`; this is the pre-task boot path,
    // single-core, so no heartbeat or trussed-UI driver exists to share the
    // pin yet. Same contract as `stage_blinks` below.
    let led: &mut Output<'static> = unsafe {
        (&mut *core::ptr::addr_of_mut!(crate::boot::LED_OUT)).assume_init_mut()
    };
    for _ in 0..id {
        led.set_low(); // ON (active-low)
        busy_wait_us(40_000);
        led.set_high(); // OFF
        busy_wait_us(40_000);
    }
}

/// Emit one boot-stage event: a `(E_BOOT, stage)` record into the RAM ring
/// **and** the stage's LED pattern — `stage + 1` short blinks, then a long
/// gap — on the shared board LED, synchronously. dbg-log builds only; the
/// release binary never compiles this module at all (US-922 gate).
#[allow(dead_code)]
pub fn boot_stage(stage: u8) {
    log(T_MAIN, E_BOOT, stage as u32, 0);
    stage_blinks(stage);
}

/// The stage LED pattern: `stage + 1` short (120 ms on / 120 ms off) blinks
/// followed by a 500 ms inter-stage gap. No-ops before [`mark_led_ready`].
#[allow(dead_code)]
fn stage_blinks(stage: u8) {
    if !LED_READY.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: the `LED_OUT` slot was initialized exactly once at the top of
    // `main` (see [`mark_led_ready`], the same write-once discipline as the
    // boot statics); this borrow is on the pre-task boot path, single-core —
    // no heartbeat/trussed-UI driver exists yet to share the pin.
    let led: &mut Output<'static> = unsafe {
        (&mut *core::ptr::addr_of_mut!(crate::boot::LED_OUT)).assume_init_mut()
    };
    for _ in 0..=stage {
        led.set_low(); // ON (active-low)
        busy_wait_us(120_000);
        led.set_high(); // OFF
        busy_wait_us(120_000);
    }
    busy_wait_us(500_000);
}

/// Synchronous µs busy-wait over the RP2350 TIMER's raw 32-bit microsecond
/// counter (`TIMERAWL` — the same 1 MHz tick the embassy time-driver config;
/// reading it has no side effects, unlike `TIMELR`). 32-bit µs wraps every
/// ~71 min; the signed-difference form below is wrap-correct for any wait
/// far under that. Used only by the dbg-log ladder (no async needed at the
/// early boot stages).
#[allow(dead_code)]
fn busy_wait_us(us: u32) {
    let target = rp_pac::TIMER0.timerawl().read().wrapping_add(us);
    while ((rp_pac::TIMER0.timerawl().read().wrapping_sub(target)) as i32) < 0 {}
}
