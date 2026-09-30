//! Device serve-loop tasks (PB-M6, US-427): `ccid_task`, `hid_task` and
//! their command dispatchers, moved verbatim from `main.rs`.
//!
//! The store / flash handles are the single-core write-once statics owned by
//! `boot.rs`; the aliasing rationale lives at the spawn in `main()`. The
//! US-425 durable-before-ack persist gate calls run strictly synchronously
//! (no `.await` inside the persist window).

use embassy_executor::task;
use embassy_rp::peripherals::USB;
use embassy_time::Timer;
use fapico2_fido::FidoApp;
use fapico2_platform::ccid;
use fapico2_platform::dispatch::{App, Dispatcher, MAX_RESPONSE};
use fapico2_platform::persist::{persist_reply_windowed, persist_one};
use fapico2_platform::persist_sink::FlashSlotSink;
use crate::boot::DeviceStore;
use fapico2_platform::usb::{Endpoint, EndpointIn, EndpointOut, In, Out};
use heapless::Vec as HeaplessVec;

use crate::boot::{DevFlash, HID_RESP, SECURE_PRIMARY_OFFSET, SECURE_SHADOW_OFFSET, SECURE_SLOT_BYTES};
use fapico2_firmware::ccid_reasm::{CcidReassembler, Reasm, MAX_WIRE};
use fapico2_firmware::ctap_hid::*;
use fapico2_firmware::presence::{TouchWindow, CTAP_KEEPALIVE_PERIOD_MS, CTAP_TOUCH_WINDOW_MS};
use fapico2_platform::usb::EndpointError;

/// Fixed ATR answered to the CCID ATR-reset command (1-byte body `0x04`).
///
/// C parity: `atr_openpgp` in `pico-openpgp/src/openpgp/openpgp.c:294` — a
/// T=1 ATR (TA1 Fi/Di = `18`) carrying the OpenPGP historical bytes. The
/// earlier `3B 00` + zeros placeholder advertised T=0 only, so gpg's
/// built-in scd (host `disable-ccid`) negotiated T=0 against the T=1-only
/// CCID stack and hung on every APDU (found in the S-721-2 flash cycle,
/// 2026-09-15; pcscd/libccid negotiates T=1 anyway, which is why the
/// pyscard path never hit it).
const ATR: &[u8] = &[
    0x3B, 0xDA, 0x18, 0xFF, 0x81, 0xB1, 0xFE, 0x75, 0x1F, 0x03, 0x00, 0x31, 0xF5,
    0x73, 0xC0, 0x01, 0x60, 0x00, 0x90, 0x00, 0x1C,
];

/// CCID serve loop: reassemble standard CCID 1.10 messages (10-byte bulk
/// headers, per pcscd's CCID driver and the C firmware's `ccid.c`) from the
/// 64-byte bulk-OUT packets, answer IccPowerOn/PowerOff/SlotStatus/
/// Parameters/Abort, and dispatch XfrBlock APDUs through the AID dispatcher
/// to the registered apps.
///
/// US-920: reassembly runs through the pure [`CcidReassembler`]
/// (`ccid_reasm`), so a partial message older than 2 s is dropped and the
/// state resyncs (CCID aborted-bulk semantics: `6F 00`-class fail + the
/// existing `Abort` handling) and the loop can never park on half a
/// message — one aborted message can no longer wedge the transport.
#[task]
pub async fn ccid_task(
    ccid_in: Endpoint<'static, USB, In>,
    ccid_out: Endpoint<'static, USB, Out>,
    mut store: DeviceStore,
    dispatcher: &'static mut Dispatcher<'static, 6>,
    flash: &'static mut DevFlash,
) {
    defmt::info!("ccid serve loop up: 6 apps registered (standard CCID)");

    let mut ccid_in = ccid_in;
    let mut ccid_out = ccid_out;
    let mut reasm = CcidReassembler::new(now_ms);
    // One bulk-OUT packet per read (64 B full-speed bulk parity).
    let mut pkt = [0u8; CCID_IN_MAX_PACKET];
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    let mut out_buf = [0u8; MAX_WIRE];
    // ICC lifecycle (C parity, `ccid_status`): present-inactive until the
    // first IccPowerOn, back to inactive on IccPowerOff.
    let mut icc_active = false;
    // US-711 review fix: the management factory reset deletes the FIDO
    // durable slots and bumps `boot::RESET_GENERATION`; this task owns the
    // OATH/OTP apps, so it wipes them through the dispatcher on the next
    // command (before the persist gate flushes the emptied state).
    let mut reset_gen = crate::boot::RESET_GENERATION.load(core::sync::atomic::Ordering::Acquire);

    loop {
        // --- US-920: drive the reassembly state machine BEFORE parking on
        // the next bulk-OUT read. Complete messages, oversize-length
        // resyncs and stale-partial drops all resolve here — the loop can
        // never park on half a message.
        match reasm.poll() {
            Reasm::Idle | Reasm::Partial => {}
            Reasm::Ready(msg) => {
                // `msg` borrows the reassembler; capture the length before
                // the await so `consume` can re-borrow afterwards.
                let len = msg.len();
                handle_ccid_message(
                    &mut ccid_in,
                    &mut *dispatcher,
                    &mut store,
                    flash,
                    &mut resp,
                    &mut out_buf,
                    &mut icc_active,
                    &mut reset_gen,
                    msg,
                )
                .await;
                reasm.consume(len);
                continue;
            }
            Reasm::Overflow { slot, seq } => {
                // C parity (`ccid.c` invalid-length path): error DataBlock
                // `6F 00`, then drop the buffer and resync (poll already
                // reset the assembly state).
                defmt::warn!("ccid dwLength too large; error reply + resync");
                dlog!(crate::dbg::T_CCID, crate::dbg::E_HDRBIG, u32::from(seq) | (u32::from(slot) << 8), 0);
                ccid_fail_reply(&mut ccid_in, slot, seq, &mut out_buf).await;
                continue;
            }
            Reasm::TimedOut(resync) => {
                defmt::warn!(
                    "ccid partial message timed out; dropped {} bytes (resync)",
                    resync.dropped
                );
                dlog!(
                    crate::dbg::T_CCID, crate::dbg::E_RESYNC,
                    resync.dropped as u32,
                    u32::from(resync.seq.unwrap_or(0)) | (u32::from(resync.slot.unwrap_or(0)) << 8)
                );
                if let (Some(slot), Some(seq)) = (resync.slot, resync.seq) {
                    ccid_fail_reply(&mut ccid_in, slot, seq, &mut out_buf).await;
                }
                continue;
            }
        }
        // --- park on the next bulk-OUT packet ---
        let n = match ccid_out.read(&mut pkt).await {
            Ok(n) => n,
            Err(_) => {
                defmt::warn!("ccid out read failed");
                dlog_throttle!(crate::dbg::T_CCID, crate::dbg::E_OUTRDE, 0, 0, 1_000_000);
                Timer::after_millis(10).await;
                continue;
            }
        };
        if n == 0 {
            dlog_throttle!(crate::dbg::T_CCID, crate::dbg::E_OUTRD0, 0, 0, 1_000_000);
            Timer::after_millis(10).await;
            continue;
        }
        // --- feed the reassembler ---
        // `feed` drops a stale partial BEFORE accepting the fresh bytes
        // (US-920 resync): the aborted message can never desynchronize the
        // next one — the wedge attack's fresh SELECT always processes.
        if let Some(resync) = reasm.feed(&pkt[..n]) {
            defmt::warn!(
                "ccid stale partial dropped; {} bytes resynced",
                resync.dropped
            );
            dlog!(
                crate::dbg::T_CCID, crate::dbg::E_RESYNC,
                resync.dropped as u32,
                u32::from(resync.seq.unwrap_or(0)) | (u32::from(resync.slot.unwrap_or(0)) << 8)
            );
            if let (Some(slot), Some(seq)) = (resync.slot, resync.seq) {
                ccid_fail_reply(&mut ccid_in, slot, seq, &mut out_buf).await;
            }
        }
    }
}

/// The CCID bulk-IN endpoint's max packet size, in bytes.
///
/// The value is the allocation-site literal: `endpoint_bulk_in(None, 64)` in
/// `platform/src/usb.rs` (USB full-speed caps bulk at 64 B, and embassy-rp's
/// `Driver` rejects a larger non-isochronous bulk allocation). It cannot be
/// read off the endpoint at runtime from this crate: embassy-rp 0.10 exposes
/// it only through the `embassy_usb::driver::Endpoint::info()` trait method,
/// and that supertrait is not nameable here — `fapico2_platform::usb`
/// re-exports the endpoint *struct*, the `In`/`Out` parameters,
/// `EndpointError` and the `EndpointIn`/`EndpointOut` subtraits (plus
/// `UsbDevice`), but not `driver::Endpoint` — and rustc does not surface a
/// supertrait's methods through a subtrait import (E0599). If the platform
/// changes the CCID IN allocation, update this.
const CCID_IN_MAX_PACKET: usize = 64;

/// US-920 reply-write park guard: a host whose read URB is gone never
/// ACKs, and `EndpointIn::write` awaits the ACK of every chunk past the
/// first — without a deadline the reply write parks forever (the prime
/// wedge suspect). The deadline drops the frame instead; the serve loop
/// logs and continues. Cancellation is safe: the embassy-rp write future
/// only awaits BEFORE arming the endpoint (arming happens in the
/// synchronous tail after the wait), so a dropped future leaves nothing
/// armed on the endpoint.
const CCID_REPLY_WRITE_TIMEOUT_MS: u64 = 500;

/// Write a CCID reply to the IN endpoint, segmented into
/// [`CCID_IN_MAX_PACKET`] (64 B on this full-speed bulk EP) chunks, under
/// the US-920 reply-write deadline.
///
/// embassy-rp 0.10's `EndpointIn::write` rejects a buffer larger than the
/// endpoint's max_packet_size with `EndpointError::BufferOverflow` instead of
/// streaming it as multiple packets (the Pico SDK's `usb_device_send`, used
/// by the C firmware, segments internally; embassy does not). Unsegmented,
/// every CCID reply > 64 B was dropped device-side and the host waited its
/// full T=1 timeout — the root cause of gpg's "selecting card failed".
/// Returns `true` iff every chunk was written.
async fn ccid_write_reply(ccid_in: &mut Endpoint<'static, USB, In>, data: &[u8]) -> bool {
    match embassy_time::with_timeout(
        embassy_time::Duration::from_millis(CCID_REPLY_WRITE_TIMEOUT_MS),
        async {
            let mut ok = true;
            for chunk in data.chunks(CCID_IN_MAX_PACKET) {
                if ccid_in.write(chunk).await.is_err() {
                    ok = false;
                    break;
                }
            }
            ok
        },
    )
    .await
    {
        Ok(ok) => ok,
        Err(_) => {
            defmt::warn!("ccid reply write timed out; frame dropped (serve loop continues)");
            false
        }
    }
}

/// Answer the CCID aborted-bulk / oversize fail (US-920): an error
/// DataBlock carrying SW `6F 00`, seq-matched to the failed request when
/// its header completed (C parity `ccid.c` invalid-length path).
async fn ccid_fail_reply(
    ccid_in: &mut Endpoint<'static, USB, In>,
    slot: u8,
    seq: u8,
    out_buf: &mut [u8; MAX_WIRE],
) {
    if let Some(n) = ccid::message::data_block(
        slot,
        seq,
        ccid::message::ICC_PRESENT_ACTIVE,
        &[0x6F, 0x00],
        out_buf,
    ) {
        dlog!(crate::dbg::T_CCID, crate::dbg::E_IW0, n as u32, 0);
        #[cfg(feature = "dbg-log")]
        {
            let t = embassy_time::Instant::now();
            let ok = ccid_write_reply(ccid_in, &out_buf[..n]).await;
            dlog!(crate::dbg::T_CCID, crate::dbg::E_IW1, u32::from(ok), t.elapsed().as_micros() as u32);
            if !ok {
                defmt::warn!("ccid in write failed");
            }
        }
        #[cfg(not(feature = "dbg-log"))]
        {
            if !ccid_write_reply(ccid_in, &out_buf[..n]).await {
                defmt::warn!("ccid in write failed");
            }
        }
    }
}

/// Answer one parsed standard CCID message (US-391 E7): ICC power/status/
/// parameter housekeeping, and XfrBlock APDU dispatch through the AID
/// dispatcher. Framing per CCID 1.10; semantics mirror the C firmware's
/// `pico-keys-sdk/src/usb/ccid/ccid.c` (ATR on power-on, gnuk T=1
/// parameters, error DataBlock on unsupported input).
#[allow(clippy::too_many_arguments)]
async fn handle_ccid_message(
    ccid_in: &mut Endpoint<'static, USB, In>,
    dispatcher: &mut Dispatcher<'_, 6>,
    store: &mut DeviceStore,
    flash: &mut DevFlash,
    resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    out_buf: &mut [u8; MAX_WIRE],
    icc_active: &mut bool,
    reset_gen: &mut u32,
    msg: &[u8],
) {
    let icc_status = |active: bool| {
        if active {
            ccid::message::ICC_PRESENT_ACTIVE
        } else {
            ccid::message::ICC_PRESENT_INACTIVE
        }
    };

    let reply_len = match ccid::message::parse(msg) {
        Some(ccid::message::Request::IccPowerOn { slot, seq }) => {
            dlog!(crate::dbg::T_CCID, crate::dbg::E_PARSE, 1, 0);
            *icc_active = true;
            ccid::message::data_block(slot, seq, ccid::message::ICC_PRESENT_ACTIVE, ATR, out_buf)
        }
        Some(ccid::message::Request::IccPowerOff { slot, seq }) => {
            dlog!(crate::dbg::T_CCID, crate::dbg::E_PARSE, 2, 0);
            *icc_active = false;
            ccid::message::slot_status(slot, seq, ccid::message::ICC_PRESENT_INACTIVE, out_buf)
        }
        Some(ccid::message::Request::GetSlotStatus { slot, seq })
        | Some(ccid::message::Request::Abort { slot, seq }) => {
            dlog!(crate::dbg::T_CCID, crate::dbg::E_PARSE, 3, 0);
            ccid::message::slot_status(slot, seq, icc_status(*icc_active), out_buf)
        }
        Some(ccid::message::Request::GetParameters { slot, seq })
        | Some(ccid::message::Request::SetParameters { slot, seq, .. }) => {
            dlog!(crate::dbg::T_CCID, crate::dbg::E_PARSE, 5, 0);
            // Accepted/echoed: the gnuk T=1 parameter set the C firmware answers.
            ccid::message::parameters(slot, seq, icc_status(*icc_active), out_buf)
        }
        Some(ccid::message::Request::XfrBlock { slot, seq, data }) => {
            dlog!(crate::dbg::T_CCID, crate::dbg::E_PARSE, 6, data.len() as u32);
            resp.clear();
            #[cfg(feature = "dbg-log")]
            {
                let t = embassy_time::Instant::now();
                dispatcher.dispatch(data, resp);
                let sw = if resp.len() >= 2 {
                    (u32::from(resp[resp.len() - 2]) << 8) | u32::from(resp[resp.len() - 1])
                } else {
                    0
                };
                dlog!(crate::dbg::T_CCID, crate::dbg::E_DISP, (sw << 16) | data.len() as u32, t.elapsed().as_micros() as u32);
            }
            #[cfg(not(feature = "dbg-log"))]
            dispatcher.dispatch(data, resp);
            // US-933: full-APDU trace (capture build only — the
            // `apdu-trace` feature, release-allowed; see `apdu_trace`).
            // Logged AFTER dispatch (so `resp` carries the response bytes +
            // SW) and BEFORE the persist gate, so the trace shows the
            // exchange the card actually served. No behavior change: the
            // feature compiles out entirely in ordinary builds.
            #[cfg(feature = "apdu-trace")]
            crate::apdu_trace::trace_exchange(data, resp);
            // US-711 review fix: a management factory reset signalled since
            // the last command — wipe the OATH/OTP apps through the
            // dispatcher (sole `&mut` per app, no aliasing) so the persist
            // gate below flushes their emptied state durable-before-ack.
            let gen = crate::boot::RESET_GENERATION.load(core::sync::atomic::Ordering::Acquire);
            if gen != *reset_gen {
                *reset_gen = gen;
                dispatcher.factory_wipe_apps();
            }
            // US-715: the windowed gate — the snapshot never materializes
            // (no scratch static any more); same durable-before-ack
            // semantics (6F 00 on persist failure, before CCID framing or
            // any endpoint write can occur).
            #[cfg(any(feature = "dbg-log", feature = "boot-timeline"))]
            let persist_start = embassy_time::Instant::now();
            dlog!(crate::dbg::T_CCID, crate::dbg::E_PST, 0, 0);
            let persisted = persist_reply_windowed(
                dispatcher.apps_mut(), store, &mut secure_slot_sink(flash),
                resp,
            );
            dlog!(crate::dbg::T_CCID, crate::dbg::E_PSD,
                u32::from(persisted.is_ok()), persist_start.elapsed().as_micros() as u32);
            if persisted.is_err() {
                defmt::error!("ccid persist failed; answering 6F 00 (durable-before-ack)");
            }
            ccid::message::data_block(
                slot, seq, ccid::message::ICC_PRESENT_ACTIVE, resp.as_slice(), out_buf,
            )
        }
        None => {
            dlog!(crate::dbg::T_CCID, crate::dbg::E_PARSE, 255, 0);
            defmt::warn!("ccid: unsupported/truncated message dropped");
            return;
        }
    };
    match reply_len {
        Some(n) => {
            // The reply write. Wedge suspect at assessment time: the write
            // awaits the host's ACK and a host whose read URB is gone
            // never ACKs. US-920 now bounds this await
            // ([`CCID_REPLY_WRITE_TIMEOUT_MS`]): E_IW0 → (timeout warn) ⇒
            // the frame was dropped and the loop continues; E_IW1 ⇒ the
            // reply left, so the task is back in the OUT read loop.
            dlog!(crate::dbg::T_CCID, crate::dbg::E_IW0, n as u32, 0);
            #[cfg(feature = "dbg-log")]
            {
                let t = embassy_time::Instant::now();
                let ok = ccid_write_reply(ccid_in, &out_buf[..n]).await;
                dlog!(crate::dbg::T_CCID, crate::dbg::E_IW1, u32::from(ok), t.elapsed().as_micros() as u32);
                if !ok {
                    defmt::warn!("ccid in write failed");
                }
            }
            #[cfg(not(feature = "dbg-log"))]
            {
                if !ccid_write_reply(ccid_in, &out_buf[..n]).await {
                    defmt::warn!("ccid in write failed");
                }
            }
            // US-163 (PICOForge-COMPAT Phase H): a Rescue `REBOOT` answered
            // `9000` on the way out; the reset itself happens **here**, after
            // the reply is on the wire. Doing it inside the applet handler
            // would outrun the reply and surface to the operator as a
            // transport error on a command that in fact succeeded — the
            // client treats a non-`9000` as a failed reboot
            // (`picoforge/src/hal/rescue/ops.rs:653-656`).
            //
            // A normal reboot on the RP2350 is a `SYSRESETREQ` and a BOOTSEL
            // reboot is the bootrom's watchdog-armed `reboot2`; both are
            // `-> !` (`boot::perform_rescue_reboot`), so the CCID serve loop
            // does not come back.
            let pending = crate::boot::RESCUE_REBOOT_PENDING
                .swap(crate::boot::NO_REBOOT_PENDING, core::sync::atomic::Ordering::AcqRel);
            if pending != crate::boot::NO_REBOOT_PENDING {
                defmt::info!("rescue: rebooting, mode {}", pending);
                crate::boot::perform_rescue_reboot(pending);
            }
        }
        None => {
            dlog!(crate::dbg::T_CCID, crate::dbg::E_ERR, 2, 0);
            defmt::warn!("ccid response exceeds buffer; dropped");
        }
    }
}

/// US-705.1/US-920: monotonic millisecond clock for the pure assemblers'
/// timeouts (`HidAssembler` transaction window, [`CcidReassembler`] partial
/// window) — injected so both stay HAL-free and host-testable.
fn now_ms() -> u64 {
    embassy_time::Instant::now().as_millis()
}

/// Send `payload` to the host as one or more 64-byte CTAP HID reports on the
/// interrupt IN endpoint (INIT report + continuation reports as needed).
/// Moved here from the (now pure, US-705.1) `ctap_hid` module — endpoint I/O
/// has no host-testable core.
pub async fn send_hid_report(
    hid_in: &mut Endpoint<'_, USB, In>,
    channel: &[u8; 4],
    cmd: u8,
    payload: &[u8],
) -> Result<(), EndpointError> {
    let total = payload.len();
    let mut report = [0u8; HID_REPORT_SIZE];

    if total <= HID_FIRST_PAYLOAD {
        report[..4].copy_from_slice(channel);
        report[4] = cmd | 0x80;
        report[5..7].copy_from_slice(&(total as u16).to_be_bytes());
        report[7..7 + total].copy_from_slice(payload);
        hid_in.write(&report).await?;
        return Ok(());
    }

    // INIT report
    report[..4].copy_from_slice(channel);
    report[4] = cmd | 0x80;
    report[5..7].copy_from_slice(&(total as u16).to_be_bytes());
    report[7..7 + HID_FIRST_PAYLOAD].copy_from_slice(&payload[..HID_FIRST_PAYLOAD]);
    hid_in.write(&report).await?;

    // Continuation reports
    let mut offset = HID_FIRST_PAYLOAD;
    let mut seq: u8 = 0;
    while offset < total {
        let end = (offset + HID_CONT_PAYLOAD).min(total);
        report = [0u8; HID_REPORT_SIZE];
        report[..4].copy_from_slice(channel);
        report[4] = seq;
        report[5..5 + (end - offset)].copy_from_slice(&payload[offset..end]);
        hid_in.write(&report).await?;
        offset = end;
        seq = seq.wrapping_add(1);
    }
    Ok(())
}

/// HID serve loop: CTAP-HID framing (see `ctap_hid`) + FIDO command dispatch.
///
/// US-425: after every state-mutating FIDO command, the platform persist
/// gate runs BEFORE the CTAP-HID reply (durable-before-ack, CCID-arm parity)
/// — PINs and credentials reach the flash secure partition before the host
/// is told the command succeeded. The store/flash handles are the same
/// single-core write-once statics the `ccid_task` was spawned with; the
/// aliasing rationale lives at the spawn in `main`.
///
/// US-939: the FIDO app rides the same write-once static discipline
/// ([`boot::FIDO_APP`]) — the spawn receives the sole `&'static mut` instead
/// of the app by value, which had bloated the Embassy async-main frame to
/// 95,232 B against a ~20.8 KiB main stack.
#[task]
pub async fn hid_task(
    hid_in: Endpoint<'static, USB, In>,
    hid_out: Endpoint<'static, USB, Out>,
    fido_app: &'static mut FidoApp,
    mut store: DeviceStore,
    flash: &'static mut DevFlash,
) {
    let mut hid_in = hid_in;
    let mut hid_out = hid_out;
    // US-711 review fix: observe the management factory reset generation
    // (bumped after the durable FIDO slot wipe) and re-initialize this
    // task's FIDO app in RAM before the next command — a later mutating
    // command then persists only the FRESH snapshot and can never
    // re-persist the pre-reset one the wipe deleted (C `cbor_reset` →
    // `init_fido()` parity). Synchronous check → wipe window (no `.await`
    // inside), the same cooperative discipline as the persist gate.
    let mut reset_gen = crate::boot::RESET_GENERATION.load(core::sync::atomic::Ordering::Acquire);
    // US-162: the Rescue applet's durable `phy` generation, seeded from the
    // same counter the commit side bumps. Checked in the same window as
    // `reset_gen` for the same reason.
    let mut phy_gen_seen =
        crate::boot::RESCUE_PHY_GENERATION.load(core::sync::atomic::Ordering::Acquire);
    let mut assembler = HidAssembler::new(now_ms);
    // US-705.1: per-INIT channel allocation (nonce-derived, counter-backed).
    let mut cid_alloc = fapico2_firmware::ctap_hid::CidAllocator::new();
    let mut report = [0u8; HID_REPORT_SIZE];
    // SAFETY: S-701-1 — static CTAPHID_MAX_MSG-sized response buffer (never the stack).
    let ctap_out: &'static mut HeaplessVec<u8, { fapico2_fido::CTAP2_MAX_MSG }> =
        unsafe { &mut *core::ptr::addr_of_mut!(HID_RESP) };

    loop {
        // 500 ms transaction timeout (CTAP-HID §11.2.3).
        if let Some((channel, code)) = assembler.check_timeout() {
            reply_hid(&mut hid_in, &channel, CTAP_HID_ERROR, &[code]).await;
        }

        let n = match hid_out.read(&mut report).await {
            Ok(n) => n,
            Err(_) => {
                defmt::warn!("hid out read failed");
                dlog_throttle!(crate::dbg::T_HID, crate::dbg::E_ERR, 1, 0, 1_000_000);
                Timer::after_millis(10).await;
                continue;
            }
        };
        if n == 0 {
            continue;
        }

        match assembler.feed(&report[..n]) {
            HidFeed::NeedMore => {}
            HidFeed::Err(channel, code) => {
                reply_hid(&mut hid_in, &channel, CTAP_HID_ERROR, &[code]).await;
            }
            HidFeed::Ready(cmd) => {
                // The reply goes to the transaction's channel, which `feed`
                // recorded. It must be read AFTER feed: copying the
                // assembler's channel before feeding sent every reply after
                // the first to the *previous* transaction's channel (E7c —
                // the CBOR reply carried the INIT's broadcast CID and
                // python-fido2 rejected it, "Wrong channel").
                let channel = assembler.channel();
                dlog!(
                    crate::dbg::T_HID,
                    crate::dbg::E_HIDCMD,
                    (u32::from(cmd) << 8) | assembler.payload().len() as u32,
                    u32::from_be_bytes(channel)
                );
                // Diagnostic ring drain (`dbg-log` feature only; US-933:
                // also the `apdu-trace` and `boot-timeline` capture
                // builds): a vendor command on the drain channel (US-922 —
                // per-boot random and printed to RTT under `dbg-log`;
                // pinned by the two capture builds so a drain needs no
                // probe) answers from `dbg::handle_dbg` and never reaches
                // the FIDO dispatch. This task + endpoints are independent
                // of `ccid_task`, so the ring is retrievable after a CCID
                // wedge.
                //
                // `boot-timeline` has to be named HERE, and separately from
                // the `dlog!` arms in `main.rs`. Getting it wrong is silent
                // and total: the build compiles, the ring fills with exactly
                // the phase records the capture exists for, and the drain
                // command falls through to the FIDO dispatcher, which
                // answers a 1-byte unknown-command error on every channel.
                // The symptom is "the pull script says wrong cid" for a
                // device whose cid is right — which is what happened the
                // first time this image was flashed.
                #[cfg(any(feature = "dbg-log", feature = "apdu-trace", feature = "boot-timeline"))]
                if cmd == crate::dbg::DBG_CMD && channel == crate::dbg::channel() {
                    crate::dbg::handle_dbg(&mut hid_in, &channel, assembler.payload()).await;
                    continue;
                }
                // US-711 review fix: a management factory reset signalled
                // since the last command — re-initialize the FIDO app in
                // RAM (CTAP2 Reset) so this command runs against
                // factory-fresh state.
                let gen =
                    crate::boot::RESET_GENERATION.load(core::sync::atomic::Ordering::Acquire);
                if gen != reset_gen {
                    reset_gen = gen;
                    fido_app.factory_reset();
                }
                // US-162 (PICOForge-COMPAT Phase H): a Rescue `WRITE PhyConfig`
                // committed durably on the CCID task since the last HID
                // command — adopt the new `phy` into this task's in-RAM
                // keystore copy, so the next `0x41 CONFIG_WRITE` cannot
                // re-persist a stale snapshot over it. Same
                // generation-then-act discipline, checked in the same
                // synchronous window (no `.await` between check and act).
                let phy_gen =
                    crate::boot::RESCUE_PHY_GENERATION.load(core::sync::atomic::Ordering::Acquire);
                if phy_gen != phy_gen_seen {
                    phy_gen_seen = phy_gen;
                    if !fido_app.sync_phy(&mut store) {
                        defmt::warn!("rescue: phy adopt failed; keeping RAM copy");
                    }
                }
                // `assembler.payload()` borrows the reassembled message for
                // the dispatch; the next `feed` call resets it.
                dispatch_hid_cmd(
                    &mut hid_in,
                    &mut cid_alloc,
                    fido_app,
                    ctap_out,
                    &channel,
                    cmd,
                    assembler.payload(),
                    &mut store,
                    flash,
                )
                .await;
            }
        }
    }
}

/// The secure-partition image sink (US-422/US-391): the primary/shadow slot
/// layout applied to a flash handle, in one place. `main()` reuses it for the
/// boot-time persist (`persist_boot_change`).
pub fn secure_slot_sink(flash: &mut DevFlash) -> FlashSlotSink<crate::boot::DevSlotFlash<'_>> {
    FlashSlotSink::new(
        crate::boot::DevSlotFlash(flash),
        SECURE_PRIMARY_OFFSET,
        SECURE_SHADOW_OFFSET,
        SECURE_SLOT_BYTES,
    )
}

/// US-425/US-427: durable-before-ack persist for the FIDO HID path.
/// Synchronous (no `.await` inside) so the cooperative executor makes the
/// window atomic — mirrors the CCID arm's gate call. Returns `true` iff the
/// command's durable state stands — programmed now, or no durable change was
/// needed — so the dispatch arms answer the CTAP-HID success reply only on
/// `true` (a `false` gets the 0xBF/INVALID_COMMAND error reply). The gate's
/// raw `false` conflates the two (see the CCID arm); the app's dirty flag
/// disambiguates — `persist_one` leaves the app dirty on a store/program
/// failure and re-marks it.
fn persist_hid(fido_app: &mut FidoApp, store: &mut DeviceStore, flash: &mut DevFlash) -> bool {
    let mut sink = secure_slot_sink(flash);
    #[cfg(feature = "dbg-log")]
    {
        let t = embassy_time::Instant::now();
        let wrote = persist_one(fido_app, store, &mut sink);
        let ok = wrote || !fido_app.is_dirty();
        dlog!(
            crate::dbg::T_HID,
            crate::dbg::E_HIDPERS,
            u32::from(wrote) | (u32::from(ok) << 1),
            t.elapsed().as_micros() as u32
        );
        if wrote {
            defmt::info!("secure partition: hid persist: programmed");
        }
        ok
    }
    #[cfg(not(feature = "dbg-log"))]
    {
        let wrote = persist_one(fido_app, store, &mut sink);
        if wrote {
            defmt::info!("secure partition: hid persist: programmed");
        }
        wrote || !fido_app.is_dirty()
    }
}

/// Dispatch one complete CTAP-HID message to the FIDO app and send the reply.
///
/// The store/flash handles feed the US-425 persist gate: every
/// state-mutating branch runs [`persist_hid`] after `process_*` and before
/// the reply, so the reply only goes out once the change is durable.
#[allow(clippy::too_many_arguments)]
async fn dispatch_hid_cmd(
    hid_in: &mut Endpoint<'static, USB, In>,
    cid_alloc: &mut fapico2_firmware::ctap_hid::CidAllocator,
    fido_app: &mut FidoApp,
    ctap_out: &mut HeaplessVec<u8, { fapico2_fido::CTAP2_MAX_MSG }>,
    channel: &[u8; 4],
    cmd: u8,
    payload: &[u8],
    store: &mut DeviceStore,
    flash: &mut DevFlash,
) {
    if cmd == CTAP_HID_INIT {
        // INIT response: nonce(8) + cid(4) + ver_iface(1) + ver_major(1) +
        // ver_minor(1) + version_build(1) + cap_flags(1) = 17 bytes.
        let nonce = if payload.len() >= 8 {
            &payload[..8]
        } else {
            payload
        };
        // US-705.1: derive the channel from the INIT handshake (nonce +
        // counter) instead of the constant [0, 0, 0, 1]; the reply frame
        // itself goes out on the requesting (broadcast) channel per spec.
        let new_channel = cid_alloc.allocate(nonce);
        let mut inner = [0u8; 17];
        inner[..nonce.len()].copy_from_slice(nonce);
        inner[8..12].copy_from_slice(&new_channel);
        inner[12] = 0x02; // versionInterface (2 = CTAP HID v2)
        inner[13] = 0x02; // versionMajor
        inner[14] = 0x01; // versionMinor
        inner[15] = 0x00; // versionBuild
        inner[16] = 0x04; // capFlags: CBOR supported
        reply_hid(hid_in, channel, 0x06, &inner).await;
    } else if cmd == CTAP_HID_CBOR {
        if !payload.is_empty() {
            let ctap_cmd = payload[0];
            // User-presence requests emit a CTAPHID keepalive (UP NEEDED)
            // before completing (FX-402 parity).
            //
            // US-115 adds the `0x41` vendor channel to `presence_windowed`
            // below, and *not* to this one. The pre-command keepalive is
            // unconditional for 0x01/0x02, which always need a touch; `0x41`
            // only needs one for the *benign tier* of `CONFIG_WRITE`, and
            // emitting a keepalive for the identity tier — which answers `0x00`
            // on the first pass — would put a frame on the wire that the client
            // has no reason to expect and that says nothing true about progress.
            let up_request = ctap_cmd == 0x01 || ctap_cmd == 0x02;
            if up_request {
                reply_hid(hid_in, channel, CTAP_HID_KEEPALIVE, &[0x02]).await;
            }
            // US-115: the commands whose arm may answer `UpRequired`, and so
            // may need the cross-call consent window below.
            //
            // `vendor41::config_write` answers `UpRequired` for a benign PHY
            // blob with no presence grant, and this loop is the only thing that
            // turns that into a prompt, a keepalive and a retry. The window is
            // entered on the *answer* — the conditions below still require a
            // one-byte `UpRequired` reply — so the identity tier, gated on a
            // pinUvAuth token and answering `0x00` first time, never opens a
            // window and never waits for a button. That is also the
            // compatibility point: PicoForge sends no touch for `CONFIG_WRITE`
            // (`picoforge/src/hal/fido/ops.rs:1514-1554`), so a touch
            // requirement on the token-authorised path would hang the Config
            // screen until its 30 s timeout (`ops.rs:1550`).
            let presence_windowed =
                up_request || ctap_cmd == fapico2_fido::vendor41::CMD;
            // SOAK-FINDING-1: the store is bound for the command so growth
            // mutations commit transactionally (durable or rejected) — the
            // gate below then finds either a persistable dirty state or a
            // clean app, never an un-persistable latch.
            let mut len = fido_app.process_ctap2_with_store(
                ctap_cmd,
                &payload[1..],
                *channel,
                ctap_out,
                Some(store),
            );
            // US-921: an UpRequired answer no longer dead-ends the
            // request — the app's gate can never grant (one synchronous
            // poll inside a non-preemptive serve section), so open the
            // cross-call consent window and re-drive the command inside
            // it: each keepalive + yield lets the button task's tick arm
            // the grant, and the app's own gate consumes it (its injected
            // closure is the join-only `request_grant_in_window`).
            // US-921 review (P0-1): the tag is domain-separated into the HID
            // space (bit 31 set) — a raw CID would eventually equal a CCID
            // presence tag and the same-tag join would let a CCID command
            // consume a press consented to a FIDO touch.
            let tag = fapico2_fido::presence_tag_from_channel(*channel);
            if presence_windowed
                && len == 1
                && ctap_out[0] == fapico2_fido::ctap2::Ctap2Response::UpRequired.code()
                && fapico2_firmware::presence::begin_window(tag, CTAP_TOUCH_WINDOW_MS)
            {
                let win = TouchWindow::open(tag, now_ms());
                fapico2_firmware::presence::touch_prompt(true);
                loop {
                    if win.expired(now_ms()) {
                        // The window ran out on an unanswered touch: the
                        // UpRequired below goes out as the final reply.
                        fapico2_firmware::presence::end_window(tag);
                        fapico2_firmware::presence::touch_prompt(false);
                        break;
                    }
                    // Progress frame, then a yield — the button task's
                    // tick runs here and drains the press latch.
                    reply_hid(hid_in, channel, CTAP_HID_KEEPALIVE, &[0x02]).await;
                    Timer::after_millis(CTAP_KEEPALIVE_PERIOD_MS).await;
                    // Re-assert the prompt: the heartbeat flickers it off
                    // between iterations (shared-pin contract).
                    fapico2_firmware::presence::touch_prompt(true);
                    len = fido_app.process_ctap2_with_store(
                        ctap_cmd,
                        &payload[1..],
                        *channel,
                        ctap_out,
                        Some(store),
                    );
                    if len == 1
                        && ctap_out[0] == fapico2_fido::ctap2::Ctap2Response::UpRequired.code()
                    {
                        continue;
                    }
                    // Final response (the retry consumed the grant, or a
                    // non-UP error): close the window, clear the prompt.
                    fapico2_firmware::presence::end_window(tag);
                    fapico2_firmware::presence::touch_prompt(false);
                    break;
                }
            }
            // US-425/US-427: durable-before-ack — persist before the success
            // reply (the keepalives above are progress notifications, not the
            // ack); the final reply (success, non-UP error, or the expired
            // UpRequired) goes out only if the gate is `true`, else the
            // closest existing CTAPHID error — 0xBF ERROR /
            // INVALID_COMMAND (the CTAPHID set has no "authenticator
            // internal/persistence failure" code; INVALID_COMMAND is the
            // generic reject this module already uses for unprocessable
            // commands, so the host sees an error frame, never a false ack).
            if persist_hid(fido_app, store, flash) {
                reply_hid(hid_in, channel, CTAP_HID_CBOR, &ctap_out[..len]).await;
            } else {
                defmt::error!("hid persist failed; CTAPHID ERROR/INVALID_COMMAND (durable-before-ack)");
                reply_hid(hid_in, channel, CTAP_HID_ERROR, &[HID_ERR_INVALID_CMD]).await;
            }
        } else {
            reply_hid(hid_in, channel, CTAP_HID_CBOR, &[HID_ERR_INVALID_CMD]).await;
        }
    } else if cmd == CTAP_HID_PING {
        reply_hid(hid_in, channel, CTAP_HID_PING, payload).await;
    } else if cmd == CTAP_HID_WINK {
        // WINK: acknowledge with an empty response frame.
        reply_hid(hid_in, channel, CTAP_HID_WINK, &[]).await;
    } else if cmd == 0x41 && !payload.is_empty() && payload[0] == 0x05 {
        // Vendor vault function (pico-fido2 vendor protocol).
        //
        // R-7 / US-106: this is the *frame-CMD* `0x41`, and it is NOT the same
        // thing as the CTAP2 *opcode* `0x41` that the `CTAP_HID_CBOR` arm
        // above now routes to `vendor41` (the RS-Key channel, PicoForge vendor
        // framing C). They cannot alias, on two independent grounds — plus one
        // coincidence that is a trap:
        //
        // 1. They are disjoint fields of disjoint frames. This arm reads the
        //    CTAPHID frame's CMD byte; the other reads the first byte of the
        //    payload *inside* a standard `CTAPHID_CBOR` frame. A given frame
        //    has one CMD byte, so at most one of the two `else if` chains can
        //    ever match it. There is no `0xC1` handler anywhere in the tree.
        // 2. Their sub-command numbering overlaps with different meanings, so
        //    they must not share a decoder. Sub-command `1` is vault STATUS
        //    (return the enrolled vault id) and RS-Key MSE (ephemeral ECDH
        //    setup). Their pinUvAuth messages differ for the same reason: the
        //    vault MACs `0xff*32 || 0x0D || sub || params` (the
        //    authenticatorConfig domain) where RS-Key MACs
        //    `0xff*32 || 0x41 || sub || params`.
        //
        //    The coincidence, which is NOT a difference and so is not a third
        //    ground: the two channels share the *same* response framing — a
        //    status byte followed by a CBOR map, with the map present only on
        //    success (`device_core.rs:3148-3157`, `vault::ok_response`, and
        //    `vendor41::handle`). Identical framing on two protocols with
        //    colliding sub-command numbers is exactly the combination that
        //    tempts someone into sharing a decoder later. Don't.
        //
        //    `apps/fido/tests/vendor41.rs::vault_framing_does_not_alias_ctap2_vendor_0x41`
        //    asserts this rather than trusting the comment.
        //
        // SOAK-FINDING-1: store bound for the transactional enroll commit
        // (as in the CBOR arm above).
        let len = fido_app.process_vendor_vault_with_store(&payload[1..], ctap_out, Some(store));
        // US-425/US-427: durable-before-ack — success reply only on a `true`
        // gate, else 0xBF / INVALID_COMMAND (as in the CBOR arm above).
        if persist_hid(fido_app, store, flash) {
            reply_hid(hid_in, channel, 0x41, &ctap_out[..len]).await;
        } else {
            defmt::error!("hid persist failed; CTAPHID ERROR/INVALID_COMMAND (durable-before-ack)");
            reply_hid(hid_in, channel, CTAP_HID_ERROR, &[HID_ERR_INVALID_CMD]).await;
        }
    } else if cmd == CTAP_HID_MSG {
        // U2F (CTAP1) APDU over HID. The payload is the raw APDU.
        // US-921: the app derives its presence tag from the transaction
        // channel — the U2F entry predates the channel plumbing, so set it
        // explicitly (process_ctap2 re-derives it per call).
        fido_app.set_channel(*channel);
        // SOAK-FINDING-1: store bound for the transactional register (as in
        // the CBOR arm above) — an overflow registers as a clean U2F
        // WrongData, not an un-persistable dirty state.
        let mut len = fido_app.process_u2f_with_store(payload, ctap_out, Some(store));
        // US-921: a bare UP refusal (6985 / the US-908 NOT_PRESENT shape)
        // opens the cross-call consent window — same discipline as the
        // CBOR arm: keepalive + yield arms the grant, the app's gate
        // consumes it on the retry.
        // US-921 review (P1-2): decode the APDU head BEFORE consulting the
        // refusal shape — only REGISTER (INS 0x01) and AUTHENTICATE in
        // enforce mode (INS 0x02, any P1 but check-only 0x07) consult
        // presence in the app. Check-only (P1=0x07) answers 6985 by spec
        // WITHOUT a touch, so it never opens the 30 s window: a flood of
        // check-only requests cannot keep the prompt lit / the slot hogged
        // for 30 s, and a press during it is never latched for a command
        // that needed no presence. (The finding's "INS 0x04 / P1=0x03" is
        // adjusted to this codebase's dispatch: INS 0x02 is AUTHENTICATE —
        // 0x04 would be VERSION, never presence-gated — and P1=0x08
        // don't-enforce runs the same presence-gated enforce path as 0x03,
        // so excluding only 0x07 keeps both signing modes windowed.)
        let tag = fapico2_fido::presence_tag_from_channel(*channel);
        let presence_gated_u2f = payload.len() >= 3
            && matches!(payload[1], 0x01 | 0x02)
            && payload[2] != 0x07;
        if presence_gated_u2f
            && fapico2_firmware::presence::u2f_up_refusal(&ctap_out[..len])
            && fapico2_firmware::presence::begin_window(tag, CTAP_TOUCH_WINDOW_MS)
        {
            let win = TouchWindow::open(tag, now_ms());
            fapico2_firmware::presence::touch_prompt(true);
            loop {
                if win.expired(now_ms()) {
                    // Window expired on an unanswered touch: the captured
                    // refusal below goes out verbatim as the final reply.
                    fapico2_firmware::presence::end_window(tag);
                    fapico2_firmware::presence::touch_prompt(false);
                    break;
                }
                reply_hid(hid_in, channel, CTAP_HID_KEEPALIVE, &[0x02]).await;
                Timer::after_millis(CTAP_KEEPALIVE_PERIOD_MS).await;
                fapico2_firmware::presence::touch_prompt(true);
                len = fido_app.process_u2f_with_store(payload, ctap_out, Some(store));
                if fapico2_firmware::presence::u2f_up_refusal(&ctap_out[..len]) {
                    continue;
                }
                fapico2_firmware::presence::end_window(tag);
                fapico2_firmware::presence::touch_prompt(false);
                break;
            }
        }
        // US-425/US-427: durable-before-ack — success reply only on a `true`
        // gate, else 0xBF / INVALID_COMMAND (as in the CBOR arm above).
        if persist_hid(fido_app, store, flash) {
            reply_hid(hid_in, channel, CTAP_HID_MSG, &ctap_out[..len]).await;
        } else {
            defmt::error!("hid persist failed; CTAPHID ERROR/INVALID_COMMAND (durable-before-ack)");
            reply_hid(hid_in, channel, CTAP_HID_ERROR, &[HID_ERR_INVALID_CMD]).await;
        }
    } else {
        // Unknown init command — CTAPHID ERROR frame, INVALID_COMMAND.
        reply_hid(hid_in, channel, CTAP_HID_ERROR, &[HID_ERR_INVALID_CMD]).await;
    }
}

/// Send one CTAP-HID reply report (logs and drops on USB error; the host
/// re-sends or re-enumerates).
async fn reply_hid(
    hid_in: &mut Endpoint<'static, USB, In>,
    channel: &[u8; 4],
    cmd: u8,
    payload: &[u8],
) {
    if send_hid_report(hid_in, channel, cmd, payload).await.is_err() {
        defmt::warn!("hid reply failed");
    }
}
