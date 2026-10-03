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

/// The device's 4-byte chipid-derived serial, published once at boot.
///
/// Serves the `CTAP_READ_CONFIG` (`0x42`) answer below, which must carry the
/// *same* serial the management applet and the USB descriptor present — all
/// three derive from `usb_ident::serial_hash4(chipid)`. Kept as a static
/// rather than a task argument because the HID task does not own (and must
/// not borrow) the management applet, which the CCID task holds mutably.
pub static DEVICE_SERIAL: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

use crate::boot::{
    DevFlash, HID_RESP, PENDING_UP, SECURE_PRIMARY_OFFSET, SECURE_SHADOW_OFFSET,
    SECURE_SLOT_BYTES,
};
use fapico2_firmware::ccid_reasm::{CcidReassembler, Reasm, MAX_WIRE};
use fapico2_firmware::ctap_hid::*;
use fapico2_firmware::hid_serve::{FidoDispatch, HidIo, HidNote, HidServe};
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

/// US-1504 reply-write park guard: a host that has stopped polling the
/// interrupt IN endpoint never ACKs, and `EndpointIn::write` awaits that ACK
/// for **every** report — the INIT report and each of the continuation
/// reports — so a 7609-byte `largeBlob` reply was 129 sequential unbounded
/// awaits. One of them never returning parked the HID serve loop forever: the
/// device was dead until unplug, and stayed dead for the next host. This is
/// the CTAPHID twin of [`CCID_REPLY_WRITE_TIMEOUT_MS`], with the same value,
/// the same whole-message scope (not per report) and the same
/// cancellation-safety argument: embassy-rp 0.10's `EndpointIn::write` only
/// awaits BEFORE arming the endpoint (arming happens in the synchronous tail
/// after the wait), so a dropped future leaves nothing armed.
///
/// The framing + deadline live in [`fapico2_firmware::hid_reply`] (the lib,
/// not this module) precisely so they are testable on the host: this adapter
/// is the only device-specific part, and it is the only thing a host test
/// cannot have.
struct HidInWriter<'a>(&'a mut Endpoint<'static, USB, In>);

impl fapico2_firmware::hid_reply::ReportWriter for HidInWriter<'_> {
    type Error = EndpointError;
    fn write_report(
        &mut self,
        report: &[u8; HID_REPORT_SIZE],
    ) -> impl core::future::Future<Output = Result<(), EndpointError>> {
        self.0.write(report)
    }
}

/// Send `payload` to the host as one or more 64-byte CTAP HID reports on the
/// interrupt IN endpoint (INIT report + continuation reports as needed),
/// under the US-1504 reply-write deadline.
///
/// Returns `true` iff every report of the reply was written. `false` covers
/// both failures — a refused write and a host that never ACKed — and in both
/// the frame is abandoned: the caller logs, drops the reply and returns to
/// its serve loop. It never retries, never re-enumerates and never disables
/// the endpoint; a partially framed message on a CTAPHID channel is garbage
/// to the host anyway.
///
/// The endpoint lifetime is `'static` (the task's own `hid_in`) rather than
/// the anonymous `'_` this used to take, because the borrow now lives inside
/// the writer adapter for the whole reply. Both callers already own a
/// `'static` endpoint.
pub async fn send_hid_report(
    hid_in: &mut Endpoint<'static, USB, In>,
    channel: &[u8; 4],
    cmd: u8,
    payload: &[u8],
) -> bool {
    use fapico2_firmware::hid_reply::{write_reply, ReplyOutcome};
    let mut writer = HidInWriter(hid_in);
    match write_reply(&mut writer, channel, cmd, payload).await {
        ReplyOutcome::Sent => true,
        ReplyOutcome::WriteFailed => {
            defmt::warn!("hid reply write failed; frame dropped (serve loop continues)");
            false
        }
        ReplyOutcome::TimedOut => {
            defmt::warn!("hid reply write timed out; frame dropped (serve loop continues)");
            false
        }
    }
}

/// The device's two HID endpoints, behind [`HidIo`].
///
/// US-1509: this adapter and [`DeviceFido`] below are the *only* device part
/// of the serve loop. The framing, the dispatch, the consent-window policy
/// and the published bound all live in [`fapico2_firmware::hid_serve`], which
/// is where the host can drive them — which is the only reason the blackout
/// had a chance to ship behind a green suite.
struct DeviceHid {
    hid_in: Endpoint<'static, USB, In>,
    hid_out: Endpoint<'static, USB, Out>,
}

impl HidIo for DeviceHid {
    // `async fn`, not a hand-rolled `-> impl Future`: the trait declares the
    // return type so that a `#[cfg]`-gated method can sit beside it, but the
    // body is a plain await and clippy's `manual_async_fn` is right that the
    // explicit `async move` block here says nothing the body does not.
    async fn read_report(
        &mut self,
        report: &mut [u8; HID_REPORT_SIZE],
    ) -> Result<usize, ()> {
        self.hid_out.read(report).await.map_err(|_| ())
    }

    fn send_frame(
        &mut self,
        channel: &[u8; 4],
        cmd: u8,
        payload: &[u8],
    ) -> impl core::future::Future<Output = bool> {
        send_hid_report(&mut self.hid_in, channel, cmd, payload)
    }

    fn note(&mut self, note: HidNote) {
        match note {
            HidNote::ReadFailed => defmt::warn!("hid out read failed"),
            HidNote::ReplyDropped => {
                // US-1504: the deadline fired inside `send_hid_report`, which
                // already warned; this is the caller's half of the same fact.
                defmt::warn!("hid reply dropped (write failed or host never acked)");
            }
            HidNote::PersistFailed => defmt::error!("hid persist failed; CTAPHID ERROR/INVALID_COMMAND (durable-before-ack)"),
        }
    }

    fn note_command(&mut self, cmd: u8, payload_len: u16, channel: u32) {
        // `dlog!` vanishes in a build with neither diagnostic feature, and
        // the arguments are now function parameters rather than locals of the
        // serve loop — so the drop has to be stated here.
        let _ = (cmd, payload_len, channel);
        dlog!(
            crate::dbg::T_HID,
            crate::dbg::E_HIDCMD,
            (u32::from(cmd) << 8) | u32::from(payload_len),
            channel
        );
    }

    #[cfg(any(feature = "dbg-log", feature = "apdu-trace", feature = "boot-timeline"))]
    async fn debug_drain(&mut self, cmd: u8, channel: &[u8; 4], payload: &[u8]) -> bool {
        // US-922: a vendor command on the drain channel (per-boot random,
        // printed to RTT under `dbg-log`) answers from `dbg::handle_dbg` and
        // never reaches the FIDO dispatch. This task and its endpoints are
        // independent of `ccid_task`, so the ring stays retrievable after a
        // CCID wedge. The rationale for the feature list is on the call site
        // in `hid_serve`, where it has to be named.
        if cmd == crate::dbg::DBG_CMD && *channel == crate::dbg::channel() {
            crate::dbg::handle_dbg(&mut self.hid_in, channel, payload).await;
            return true;
        }
        false
    }
}

/// The FIDO app, the store and the flash handle, behind [`FidoDispatch`].
///
/// The `store`/`flash` handles are the same single-core write-once statics
/// the `ccid_task` was spawned with; the aliasing rationale lives at the
/// spawn in `main`.
///
/// US-425: after every state-mutating FIDO command the platform persist gate
/// runs BEFORE the CTAP-HID reply (durable-before-ack, CCID-arm parity) —
/// PINs and credentials reach the flash secure partition before the host is
/// told the command succeeded.
///
/// US-939: the FIDO app rides the same write-once static discipline
/// ([`boot::FIDO_APP`]) — the spawn receives the sole `&'static mut` instead
/// of the app by value, which had bloated the Embassy async-main frame to
/// 95,232 B against a ~20.8 KiB main stack.
struct DeviceFido<'a> {
    app: &'a mut FidoApp,
    store: &'a mut DeviceStore,
    flash: &'a mut DevFlash,
    /// US-711 review fix: observe the management factory-reset generation
    /// (bumped after the durable FIDO slot wipe) and re-initialize the app in
    /// RAM before the next command — a later mutating command then persists
    /// only the FRESH snapshot and can never re-persist the pre-reset one
    /// the wipe deleted (C `cbor_reset` → `init_fido()` parity). Synchronous
    /// check → wipe window (no `.await` inside), the same cooperative
    /// discipline as the persist gate.
    reset_gen: u32,
    /// US-162: the Rescue applet's durable `phy` generation, seeded from the
    /// same counter the commit side bumps. Checked in the same window as
    /// `reset_gen` for the same reason.
    phy_gen_seen: u32,
}

impl FidoDispatch for DeviceFido<'_> {
    fn sync_generations(&mut self) {
        let gen = crate::boot::RESET_GENERATION.load(core::sync::atomic::Ordering::Acquire);
        if gen != self.reset_gen {
            self.reset_gen = gen;
            self.app.factory_reset();
        }
        // US-162 (PICOForge-COMPAT Phase H): a Rescue `WRITE PhyConfig`
        // committed durably on the CCID task since the last HID command —
        // adopt the new `phy` into this task's in-RAM keystore copy, so the
        // next `0x41 CONFIG_WRITE` cannot re-persist a stale snapshot over
        // it. Same generation-then-act discipline, checked in the same
        // synchronous window (no `.await` between check and act).
        let phy_gen = crate::boot::RESCUE_PHY_GENERATION.load(core::sync::atomic::Ordering::Acquire);
        if phy_gen != self.phy_gen_seen {
            self.phy_gen_seen = phy_gen;
            if !self.app.sync_phy(self.store) {
                defmt::warn!("rescue: phy adopt failed; keeping RAM copy");
            }
        }
    }

    fn device_info_page(&self, _page: u8, out: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        let serial = DEVICE_SERIAL.load(core::sync::atomic::Ordering::Relaxed).to_be_bytes();
        fapico2_mgmt::default_config_tlv(serial, out);
    }

    fn process_ctap2(
        &mut self,
        ctap_cmd: u8,
        payload: &[u8],
        channel: [u8; 4],
        out: &mut HeaplessVec<u8, { fapico2_fido::CTAP2_MAX_MSG }>,
    ) -> usize {
        self.app
            .process_ctap2_with_store(ctap_cmd, payload, channel, out, Some(&mut *self.store))
    }

    fn process_vendor_vault(
        &mut self,
        payload: &[u8],
        out: &mut HeaplessVec<u8, { fapico2_fido::CTAP2_MAX_MSG }>,
    ) -> usize {
        self.app
            .process_vendor_vault_with_store(payload, out, Some(&mut *self.store))
    }

    fn set_channel(&mut self, channel: [u8; 4]) {
        self.app.set_channel(channel);
    }

    fn process_u2f(
        &mut self,
        apdu: &[u8],
        out: &mut HeaplessVec<u8, { fapico2_fido::CTAP2_MAX_MSG }>,
    ) -> usize {
        self.app
            .process_u2f_with_store(apdu, out, Some(&mut *self.store))
    }

    fn persist(&mut self) -> bool {
        persist_hid(self.app, self.store, self.flash)
    }
}

/// HID serve loop task: the two endpoints, the app, and the serve loop itself.
///
/// The body is three adapters and a call into
/// [`fapico2_firmware::hid_serve::serve_loop`]. Everything that used to be
/// here — CTAP-HID framing, the FIDO dispatch, and the user-presence consent
/// path — moved into that module so the host can drive it; see its docs.
#[task]
pub async fn hid_task(
    hid_in: Endpoint<'static, USB, In>,
    hid_out: Endpoint<'static, USB, Out>,
    fido_app: &'static mut FidoApp,
    mut store: DeviceStore,
    flash: &'static mut DevFlash,
) {
    let mut io = DeviceHid { hid_in, hid_out };
    let mut app = DeviceFido {
        app: fido_app,
        store: &mut store,
        flash,
        reset_gen: crate::boot::RESET_GENERATION.load(core::sync::atomic::Ordering::Acquire),
        phy_gen_seen: crate::boot::RESCUE_PHY_GENERATION.load(core::sync::atomic::Ordering::Acquire),
    };
    // SAFETY: S-701-1 — static CTAP2_MAX_MSG-sized response buffer, never the
    // stack. Write-once, single owner (this task), reached by an
    // `addr_of_mut!` borrow: the HID task is the only reader of the CTAP-HID
    // reply path, so there is no second owner to alias.
    let ctap_out: &'static mut HeaplessVec<u8, { fapico2_fido::CTAP2_MAX_MSG }> =
        unsafe { &mut *core::ptr::addr_of_mut!(HID_RESP) };
    // SAFETY: the parked consent window, US-1509. Same write-once, single-
    // owner discipline as `HID_RESP` above, and for the same reason it is a
    // static rather than a task local: the 1024-byte payload buffer would
    // otherwise sit in this task's async frame, which `TASK_ARENA_DEMAND_B`
    // accounts for byte by byte. `hid_task` is the only writer — the boot.rs
    // `RESCUE_PHY_GENERATION` rule about counters is for state that crosses
    // between two *tasks*, and nothing here does.
    let slot: &'static mut fapico2_firmware::pending_up::PendingUp =
        unsafe { &mut *core::ptr::addr_of_mut!(PENDING_UP) };
    let mut srv = HidServe::new(now_ms, ctap_out);
    fapico2_firmware::hid_serve::serve_loop(&mut srv, &mut io, &mut app, slot).await
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
///
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

