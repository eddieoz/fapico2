//! US-1509: the CTAP-HID serve loop and its command dispatch, extracted out
//! of `firmware/src/tasks.rs` so the consent-window behaviour is host-testable.
//!
//! # Why this is in the lib and not in `tasks.rs`
//!
//! `hid_task` could not be exercised on the host at all: it is an embassy
//! `#[task]` over two real `embassy_rp::usb::Endpoint`s. Everything it proved
//! about CTAP-HID therefore had to be re-proved by a *copy* — the framing in
//! `ctap_hid`, the reply deadline in `hid_reply` — and a copy is exactly what
//! let the US-1501 wedge through a green suite.
//!
//! US-1504 set the precedent this module follows: split the step behind a
//! trait, keep the policy in the lib, and drive it on the host against a
//! writer that never ACKs. Here there are two seams:
//!
//! * [`HidIo`] — the transport: read one 64-byte report from the OUT
//!   endpoint, send one CTAP-HID message on the IN endpoint. On the host it
//!   is a script; on the device it is `EndpointOut` / `HidInWriter`.
//! * [`FidoDispatch`] — the app: the four `process_*` entry points, the
//!   channel stamp, the durable-before-ack persist gate, and the device-info
//!   page. Everything that needs `FidoApp`, `DeviceStore`, `DevFlash` or a
//!   `&mut` lives behind this and stays in `tasks.rs`.
//!
//! [`serve_once`] is then *the* serve-loop iteration: `hid_task` calls it in
//! a loop, and the US-1502 / US-1508 / US-1509 / US-1510 tests call the same
//! function against a scripted transport, so they exercise the shipped
//! control flow rather than a model of it.
//!
//! # The consent window (US-1509)
//!
//! A user-presence command that answers `UpRequired` is **parked** in
//! [`PendingUp`] instead of looping here. The serve loop returns to the top,
//! re-asserts the prompt, re-drives the parked command, emits one keepalive,
//! and reads the OUT endpoint again. The window ends on a grant, on its
//! deadline, or — from US-1505 — on a `CTAPHID_CANCEL`.
//!
//! The outbound read is *bounded* by one keepalive period while a window is
//! open ([`read_one`]). That bound is not a refinement: without it the loop
//! parks in `hid_out.read()` on an idle bus, the host sees exactly one
//! keepalive and then 30 s of silence, and the fix would have traded one
//! broken promise (FX-402 progress frames) for another.
//!
//! # What the parked command can and cannot reach
//!
//! The slot holds `(channel, ctap_cmd, payload, deadline)` and nothing else.
//! It does not own the app, the `store` borrow, or the response buffer: the
//! serve loop does, and a re-drive hands the request back. A second consent
//! request is **refused, not queued** (US-1510) — see the CBOR and MSG arms
//! of [`dispatch`].

use core::future::Future;

use fapico2_fido::ctap2::Ctap2Response;
use fapico2_fido::CTAP2_MAX_MSG;
use fapico2_platform::dispatch::MAX_RESPONSE;
use heapless::Vec as HeaplessVec;

use crate::ctap_hid::{
    init_reply, CidAllocator, HidAssembler, HidFeed, HID_REPORT_SIZE, CTAP_HID_CBOR,
    CTAP_HID_ERROR, CTAP_HID_INIT, CTAP_HID_KEEPALIVE, CTAP_HID_MSG, CTAP_HID_PING, CTAP_HID_WINK,
    HID_ERR_INVALID_CMD,
};
use crate::pending_up::{ParkRefusal, PendingKind, PendingUp, WindowTicket};
use crate::presence::{self, CTAP_KEEPALIVE_PERIOD_MS, CTAP_TOUCH_WINDOW_MS, TouchWindow};

/// `CTAP_READ_CONFIG` (`0x42`) — yubikit's `CTAP_VENDOR_FIRST + 2`.
///
/// The rationale is unchanged from `tasks.rs`: when a host reads `DeviceInfo`
/// through the **FIDO** interface this is how it asks, and if it fails ykman
/// synthesises a "YubiKey 3.0, U2F only, no serial" record with no FIDO2 bit
/// — which is what left `ykman fido info` printing `CTAP2: Not supported`
/// and the desktop app's Slots/Passkeys screens loading forever.
const CTAP_READ_CONFIG: u8 = 0x42;

/// US-1504's CTAPHID reply-write deadline, re-exported because the bound
/// this loop publishes is stated in terms of the constant that sets it.
pub use crate::hid_reply::HID_REPLY_WRITE_TIMEOUT_MS;

/// US-1502's **stated bound**, in milliseconds: how long a request that
/// arrives on any channel waits for its answer while a consent window is
/// open.
///
/// It is four CTAPHID reply writes plus the one keepalive period the
/// outbound read is bounded by, and that is the whole argument — every term
/// is a deadline the loop actually holds itself to:
///
/// * while a window is live, a frame that arrives on the OUT endpoint is
///   picked up within [`CTAP_KEEPALIVE_PERIOD_MS`] (100 ms), because
///   [`read_one`] is bounded by it;
/// * then, worst case, the rest of *that* pass still has to run: the live
///   window's keepalive, a `check_timeout` error (only if a fragmented
///   transaction really is stale), and the dispatched answer. That is three
///   further replies, and
/// * every reply is bounded by [`HID_REPLY_WRITE_TIMEOUT_MS`] (500 ms), so a
///   host that has stopped reading the IN endpoint costs a bounded 500 ms per
///   frame rather than parking the loop forever (US-1504).
///
/// So **2100 ms worst case**, and **200 ms (2 x the keepalive period)
/// against a host that is actually reading the IN endpoint** — the case the
/// blackout is about.
///
/// The re-drive is one synchronous app call and the persist gate is one flash
/// program; neither is in the arithmetic.
///
/// If US-1506 moves the keepalive cadence, the second number moves with it
/// and the `+ CTAP_KEEPALIVE_PERIOD_MS` term with the first. The reply
/// deadline still dominates both.
///
/// The earlier figure of `3 x HID_REPLY_WRITE_TIMEOUT_MS` (1500 ms) was
/// published by the first cut of this story and **under-counted**: it dropped
/// the read's own bound and counted three replies for a pass that can make
/// four — the live window's keepalive, the assembler's timeout error, the
/// dispatched command's pre-command keepalive, and its answer. A bound that is
/// 600 ms optimistic is not a bound.
pub const SERVE_BOUND_MS: u64 = 4 * HID_REPLY_WRITE_TIMEOUT_MS + CTAP_KEEPALIVE_PERIOD_MS;

/// Something the serve loop wants the transport to say in its log. The loop
/// itself has no logger: `defmt` is a device concern, and US-1504 moved the
/// logging out for exactly this reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidNote {
    /// The OUT endpoint refused the read; the loop backs off and retries.
    ReadFailed,
    /// A reply was abandoned — a refused write, or a host that never ACKed.
    ReplyDropped,
    /// The durable-before-ack gate refused, so a success reply became an
    /// error frame instead.
    PersistFailed,
}

/// The transport half of the serve loop.
pub trait HidIo {
    /// Read one 64-byte report from the OUT endpoint.
    ///
    /// Cancellation safety is the caller's contract, exactly as
    /// [`crate::hid_reply::ReportWriter`]'s is and for the same reason:
    /// embassy-rp 0.10's `EndpointOut::read` (`src/usb.rs:574`) only awaits
    /// the `available` poll — the buffer-control re-arm happens in the
    /// synchronous tail after it — so a dropped read leaves the packet in the
    /// endpoint buffer and the next read picks it up. This matters here
    /// because the loop *does* drop reads, on purpose, while a window is
    /// open (see [`SERVE_BOUND_MS`]).
    fn read_report(
        &mut self,
        report: &mut [u8; HID_REPORT_SIZE],
    ) -> impl Future<Output = Result<usize, ()>>;

    /// Send one CTAP-HID message. `false` means the frame was dropped (a
    /// refused write, or a host that never ACKed); the loop logs and
    /// continues — it never retries, re-enumerates or disables the endpoint.
    fn send_frame(
        &mut self,
        channel: &[u8; 4],
        cmd: u8,
        payload: &[u8],
    ) -> impl Future<Output = bool>;

    /// Transport-side instrumentation. No default body: an implementation
    /// that silently dropped notes would be indistinguishable from one that
    /// had none.
    fn note(&mut self, note: HidNote);

    /// US-933: one record per inbound command, on the device drain ring.
    fn note_command(&mut self, cmd: u8, payload_len: u16, channel: u32);

    /// US-922: the diagnostic drain. `true` means the command was answered
    /// from the ring and must not reach the FIDO dispatch.
    #[cfg(any(feature = "dbg-log", feature = "apdu-trace", feature = "boot-timeline"))]
    async fn debug_drain(&mut self, cmd: u8, channel: &[u8; 4], payload: &[u8]) -> bool;
}

/// The app half of the serve loop.
///
/// Every method is synchronous, and each one borrows the app's own `store`
/// handle internally — the `Some(store)` binding that
/// `process_ctap2_with_store` needs for a transactional growth mutation
/// (SOAK-FINDING-1) stays where the store is, which is what lets the
/// consent slot hand the parked command back for a re-drive instead of
/// owning it.
pub trait FidoDispatch {
    /// US-711 / US-162: adopt durable state another task committed since the
    /// last command (a management factory reset, a Rescue `WRITE PhyConfig`).
    ///
    /// One synchronous call, so the check → act window stays atomic on the
    /// cooperative executor exactly as it was inline.
    fn sync_generations(&mut self);

    /// `CTAP_READ_CONFIG` (`0x42`) page 0: the same `default_config_tlv`
    /// body the management applet and the USB descriptor carry, so all three
    /// `DeviceInfo` interfaces agree.
    fn device_info_page(&self, page: u8, out: &mut HeaplessVec<u8, MAX_RESPONSE>);

    /// `process_ctap2_with_store`, with the store bound.
    fn process_ctap2(
        &mut self,
        ctap_cmd: u8,
        payload: &[u8],
        channel: [u8; 4],
        out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    ) -> usize;

    /// `process_vendor_vault_with_store`, with the store bound.
    fn process_vendor_vault(
        &mut self,
        payload: &[u8],
        out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    ) -> usize;

    /// US-921: stamp the transaction channel the U2F presence tag derives
    /// from, before `process_u2f`.
    fn set_channel(&mut self, channel: [u8; 4]);

    /// `process_u2f_with_store`, with the store bound.
    fn process_u2f(&mut self, apdu: &[u8], out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>) -> usize;

    /// US-425/US-427 durable-before-ack. `false` means the change is not
    /// durable and the caller must answer with an error frame instead.
    fn persist(&mut self) -> bool;
}

/// One serve loop's worth of state.
pub struct HidServe<'a> {
    assembler: HidAssembler,
    cid_alloc: CidAllocator,
    report: [u8; HID_REPORT_SIZE],
    /// The response buffer, owned by the caller (`boot::HID_RESP` on the
    /// device, a local in the tests).
    ctap_out: &'a mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    now_ms: fn() -> u64,
    /// How many times the loop has asked the OUT endpoint for a report.
    /// Test-only instrumentation: it is what makes US-1509 ("the serve loop
    /// keeps calling `hid_out.read()`") an assertion rather than a claim.
    #[cfg(test)]
    reads: u32,
    /// Serve passes the harness had to cut short while a consent window was
    /// still live. See [`HidServe::note_blocked_live_pass`].
    #[cfg(test)]
    blocked_live_passes: u32,
}

impl<'a> HidServe<'a> {
    pub fn new(now_ms: fn() -> u64, ctap_out: &'a mut HeaplessVec<u8, CTAP2_MAX_MSG>) -> Self {
        Self {
            assembler: HidAssembler::new(now_ms),
            cid_alloc: CidAllocator::new(),
            report: [0u8; HID_REPORT_SIZE],
            ctap_out,
            now_ms,
            #[cfg(test)]
            reads: 0,
            #[cfg(test)]
            blocked_live_passes: 0,
        }
    }

    /// OUT-endpoint reads so far — US-1509's assertion hook.
    #[cfg(test)]
    pub fn reads(&self) -> u32 {
        self.reads
    }

    /// Record a pass the test harness had to abandon while a consent window
    /// was still open.
    ///
    /// This is the instrument that makes the blackout **detectable at all**,
    /// and it exists because of a hole the first version of this suite had.
    /// The harness models an idle OUT endpoint as a future that never
    /// completes (correctly — that is what the real endpoint does), so a drive
    /// has to abandon a parked pass for its own budget to elapse. Reintroduce
    /// the pre-fix consent `loop` and that same 150 ms abandonment silently
    /// **rescues** the test: the pass is cut in half every 150 ms, the loop
    /// starts another, and the cross-channel requests the tests assert about
    /// get answered anyway. US-1502 and US-1508 stayed green under exactly
    /// that revert while the loop they exist to forbid was back.
    ///
    /// Counting is conditioned on the slot *still being occupied after* the
    /// pass: a pass that closed the window and then parked on an idle bus is
    /// correct behaviour and is not counted. What is counted is a pass that
    /// could not return while a window was open — which is the blackout,
    /// measured.
    #[cfg(test)]
    fn note_blocked_live_pass(&mut self) {
        self.blocked_live_passes += 1;
    }

    /// Passes abandoned by the harness while a consent window was live.
    /// Every test that drives the loop with a window open asserts this is
    /// zero.
    #[cfg(test)]
    pub fn blocked_live_passes(&self) -> u32 {
        self.blocked_live_passes
    }
}

/// The serve loop. Never returns: `hid_task` is a `#[task]`.
pub async fn serve_loop<S: HidIo, A: FidoDispatch>(
    srv: &mut HidServe<'_>,
    io: &mut S,
    app: &mut A,
    slot: &mut PendingUp,
) -> ! {
    loop {
        serve_once(srv, io, app, slot).await;
    }
}

/// One iteration of the CTAP-HID serve loop. The order is the contract:
///
/// 1. **re-drive the parked consent window** — prompt, command, keepalive,
///    then fall through. This is US-1509: the window is re-asserted, never
///    awaited;
/// 2. expire a stale fragmented transaction (CTAP-HID §11.2.3);
/// 3. **read the OUT endpoint** — bounded by one keepalive period while a
///    window is open so the cadence survives an idle bus, unbounded
///    otherwise;
/// 4. feed the assembler and dispatch a complete message.
///
/// Step 1 is the whole story: before US-1509 the consent `loop` lived inside
/// step 4's dispatch and this function never came back for 30 s.
pub async fn serve_once<S: HidIo, A: FidoDispatch>(
    srv: &mut HidServe<'_>,
    io: &mut S,
    app: &mut A,
    slot: &mut PendingUp,
) {
    // Counted at the CALL, not on a delivery: US-1509's assertion is that the
    // loop keeps asking the OUT endpoint for reports, and a bounded read that
    // finds nothing still counts — it is the ask that the blackout removed.
    #[cfg(test)]
    {
        srv.reads += 1;
    }

    // Destructured so the assembler (which owns the inbound payload being
    // dispatched) and the response buffer are disjoint borrows: passing
    // `&mut HidServe` alongside `assembler.payload()` would alias.
    let HidServe {
        assembler,
        cid_alloc,
        report,
        ctap_out,
        now_ms,
        ..
    } = srv;
    let ctap_out = &mut **ctap_out;
    let now_ms = *now_ms;

    redrive_window(now_ms, ctap_out, io, app, slot).await;

    if let Some((channel, code)) = assembler.check_timeout() {
        reply(io, &channel, CTAP_HID_ERROR, &[code]).await;
    }

    let Ok(n) = read_one(report, io, slot.is_occupied()).await else {
        io.note(HidNote::ReadFailed);
        embassy_time::Timer::after_millis(10).await;
        return;
    };
    if n == 0 {
        return;
    }

    match assembler.feed(&report[..n]) {
        HidFeed::NeedMore => {}
        HidFeed::Err(channel, code) => {
            reply(io, &channel, CTAP_HID_ERROR, &[code]).await;
        }
        HidFeed::Ready(cmd) => {
            // The reply goes to the transaction's channel, which `feed`
            // recorded. It must be read AFTER feed: copying the assembler's
            // channel before feeding sent every reply after the first to the
            // *previous* transaction's channel (E7c — the CBOR reply carried
            // the INIT's broadcast CID and python-fido2 rejected it, "Wrong
            // channel").
            let channel = assembler.channel();
            io.note_command(
                cmd,
                assembler.payload().len() as u16,
                u32::from_be_bytes(channel),
            );

            // US-922: a vendor command on the drain channel answers from the
            // diagnostic ring and never reaches the FIDO dispatch. The
            // feature list has to be named here, and separately from the
            // `dlog!` arms in `main.rs`: getting it wrong is silent and
            // total — the build compiles, the ring fills with exactly the
            // phase records the capture exists for, and the drain command
            // falls through to the FIDO dispatcher, which answers a 1-byte
            // unknown-command error on every channel. The symptom is "the
            // pull script says wrong cid" for a device whose cid is right.
            #[cfg(any(feature = "dbg-log", feature = "apdu-trace", feature = "boot-timeline"))]
            if io.debug_drain(cmd, &channel, assembler.payload()).await {
                return;
            }

            app.sync_generations();
            // `assembler.payload()` borrows the reassembled message for the
            // dispatch; the next `feed` call resets it.
            dispatch(
                cid_alloc,
                ctap_out,
                now_ms,
                io,
                app,
                slot,
                &channel,
                cmd,
                assembler.payload(),
            )
            .await;
        }
    }
}

/// One read of the OUT endpoint, bounded by one keepalive period while a
/// window is open.
///
/// This is the US-1504 idiom applied to the other direction: a single
/// whole-operation deadline, the future dropped on expiry, the loop
/// continuing. A dropped read leaves the packet in the endpoint buffer, so
/// nothing is lost — it is simply picked up by the next read a keepalive
/// period later.
async fn read_one<S: HidIo>(
    report: &mut [u8; HID_REPORT_SIZE],
    io: &mut S,
    bounded: bool,
) -> Result<usize, ()> {
    if !bounded {
        return io.read_report(report).await;
    }
    match embassy_time::with_timeout(
        embassy_time::Duration::from_millis(CTAP_KEEPALIVE_PERIOD_MS),
        io.read_report(report),
    )
    .await
    {
        Ok(result) => result,
        // Nothing arrived inside one keepalive period. Not an error: the
        // window is still live and the next pass re-drives it.
        Err(_) => Ok(0),
    }
}

/// US-1509: one pass over the parked consent window.
///
/// Re-asserts the prompt, re-drives the command and emits a keepalive — then
/// returns. It never waits for the touch; only the window's own deadline (or
/// a grant, or US-1505's cancel) ends it.
async fn redrive_window<S: HidIo, A: FidoDispatch>(
    now_ms: fn() -> u64,
    ctap_out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    io: &mut S,
    app: &mut A,
    slot: &mut PendingUp,
) {
    if !slot.is_occupied() {
        return;
    }
    let now = now_ms();

    if slot.is_expired(now) {
        // The window ran out on an unanswered touch. The refusal the command
        // last produced goes out verbatim — the command is deliberately NOT
        // re-driven one last time, so a press landing on the closing tick
        // cannot retroactively authorise what the window already refused
        // (US-921's rule, in the time dimension).
        let mut refusal = [0u8; 2];
        let n = slot.refusal().len().min(refusal.len());
        refusal[..n].copy_from_slice(&slot.refusal()[..n]);
        let ticket = close_window(slot);
        if app.persist() {
            reply(
                io,
                &ticket.channel,
                frame_cmd(ticket.kind),
                &refusal[..n],
            )
            .await;
        } else {
            io.note(HidNote::PersistFailed);
            reply(io, &ticket.channel, CTAP_HID_ERROR, &[HID_ERR_INVALID_CMD]).await;
        }
        return;
    }

    let Some(parked) = slot.parked() else { return };

    // Re-assert the prompt: the heartbeat flickers it off between passes
    // (the shared-pin contract, and the same reason the old inline loop
    // re-asserted it after every keepalive).
    presence::touch_prompt(true);

    let kind = parked.ticket.kind;
    let channel = parked.ticket.channel;
    let (still_owed, len) = match kind {
        PendingKind::Ctap2 => {
            let len = app.process_ctap2(
                parked.ticket.ctap_cmd,
                &parked.payload[1..],
                channel,
                ctap_out,
            );
            (len == 1 && ctap_out[0] == Ctap2Response::UpRequired.code(), len)
        }
        PendingKind::U2f => {
            // US-921: the U2F entry predates the channel plumbing, so the
            // channel is stamped explicitly before every re-drive — a stale
            // stamp would make the app consult a tag the window is not under.
            app.set_channel(channel);
            let len = app.process_u2f(parked.payload, ctap_out);
            (presence::u2f_up_refusal(&ctap_out[..len]), len)
        }
    };

    if still_owed {
        slot.note_refusal(&ctap_out[..len]);
        reply(io, &channel, CTAP_HID_KEEPALIVE, &[0x02]).await;
        return;
    }

    // The grant was consumed (or the command answered a non-UP error): the
    // window is over and this is the final reply.
    close_window(slot);
    if app.persist() {
        reply(io, &channel, frame_cmd(kind), &ctap_out[..len]).await;
    } else {
        io.note(HidNote::PersistFailed);
        reply(io, &channel, CTAP_HID_ERROR, &[HID_ERR_INVALID_CMD]).await;
    }
}

/// The CTAP-HID frame command a window's answer goes out on.
const fn frame_cmd(kind: PendingKind) -> u8 {
    match kind {
        PendingKind::Ctap2 => CTAP_HID_CBOR,
        PendingKind::U2f => CTAP_HID_MSG,
    }
}

/// Close the parked window: release its presence slot, clear its prompt and
/// empty the slot, in that order.
///
/// **Every** exit path from a window goes through here. `end_window` without
/// the prompt clear leaves the LED lit until the next boot; the prompt clear
/// without `end_window` leaves a permanently held presence slot, and nothing
/// can grant again for the life of the process. One function, so the three
/// calls cannot drift apart — this is the pairing US-921's leak analysis
/// turned on, and it is why there is no other way out of a window.
fn close_window(slot: &mut PendingUp) -> WindowTicket {
    match slot.take() {
        Some(ticket) => {
            presence::end_window(ticket.tag);
            presence::touch_prompt(false);
            ticket
        }
        // Nothing parked. The empty ticket is never used for a reply — both
        // callers reach here only with a live window — but returning one
        // keeps the signature total rather than panicking inside a serve loop.
        None => WindowTicket {
            kind: PendingKind::Ctap2,
            channel: [0; 4],
            tag: 0,
            ctap_cmd: 0,
            deadline_ms: 0,
        },
    }
}

/// Send one CTAP-HID reply, logging a dropped frame (US-1504) and
/// continuing. A reply that never left the device is not retried: a
/// partially framed message on a CTAPHID channel is garbage to the host, and
/// the host re-sends or re-enumerates.
async fn reply<S: HidIo>(io: &mut S, channel: &[u8; 4], cmd: u8, payload: &[u8]) {
    if !io.send_frame(channel, cmd, payload).await {
        io.note(HidNote::ReplyDropped);
    }
}

/// Dispatch one complete CTAP-HID message to the FIDO app and send the reply.
///
/// The store/flash handles behind [`FidoDispatch`] feed the US-425 persist
/// gate: every state-mutating branch runs [`FidoDispatch::persist`] after
/// its `process_*` call and before the reply, so the reply only goes out
/// once the change is durable.
#[allow(clippy::too_many_arguments)]
async fn dispatch<S: HidIo, A: FidoDispatch>(
    cid_alloc: &mut CidAllocator,
    ctap_out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    now_ms: fn() -> u64,
    io: &mut S,
    app: &mut A,
    slot: &mut PendingUp,
    channel: &[u8; 4],
    cmd: u8,
    payload: &[u8],
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
        // US-1507: bytes 12..16 of the reply — versionInterface, the YubiKey
        // firmware version, and capFlags — are built by `ctap_hid::init_reply`.
        // The rationale for all of them lives on that function and on
        // `CTAPHID_INIT_CAP_FLAGS`, so it is not restated here.
        let inner = init_reply(
            nonce,
            &new_channel,
            fapico2_mgmt::VERSION_MAJOR,
            fapico2_mgmt::VERSION_MINOR,
            0x00, // versionBuild
        );
        reply(io, channel, CTAP_HID_INIT, &inner).await;
    } else if cmd == CTAP_READ_CONFIG {
        // DeviceInfo page 0 over the FIDO interface. The payload is the page
        // number (yubikit sends `int2bytes(page)`, i.e. a single zero byte
        // for page 0); anything past page 0 is a page this device does not
        // paginate, and the blob below is complete in one page, so those get
        // the empty page the client expects at the end of a sequence.
        if payload.len() > 1 || (payload.len() == 1 && payload[0] != 0) {
            reply(io, channel, cmd, &[0x00]).await;
            return;
        }
        let mut tlv: HeaplessVec<u8, MAX_RESPONSE> = HeaplessVec::new();
        app.device_info_page(0, &mut tlv);
        reply(io, channel, cmd, tlv.as_slice()).await;
    } else if cmd == CTAP_HID_CBOR {
        if payload.is_empty() {
            reply(io, channel, CTAP_HID_CBOR, &[HID_ERR_INVALID_CMD]).await;
            return;
        }
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
            reply(io, channel, CTAP_HID_KEEPALIVE, &[0x02]).await;
        }
        // US-115: the commands whose arm may answer `UpRequired`, and so may
        // need the cross-call consent window below.
        //
        // `vendor41::config_write` answers `UpRequired` for a benign PHY blob
        // with no presence grant, and this arm is the only thing that turns
        // that into a prompt, a keepalive and a retry. The window is entered
        // on the *answer* — the conditions below still require a one-byte
        // `UpRequired` reply — so the identity tier, gated on a pinUvAuth
        // token and answering `0x00` first time, never opens a window and
        // never waits for a button. That is also the compatibility point:
        // PicoForge sends no touch for `CONFIG_WRITE`
        // (`picoforge/src/hal/fido/ops.rs:1514-1554`), so a touch requirement
        // on the token-authorised path would hang the Config screen until its
        // 30 s timeout (`ops.rs:1550`).
        //
        // authenticatorClientPIN (0x06) joins them because its
        // `getPinUvAuthTokenUsingUvWithPermissions` (sub-command 0x06)
        // answers `UpRequired` when no press has been observed — that is the
        // only way a client on a PIN-less key can obtain a pinUvAuthToken at
        // all. The window is entered on the *answer*, so the PIN-based
        // sub-commands (0x05/0x09), which never answer `UpRequired`, are
        // unaffected and send no keepalive.
        let presence_windowed =
            up_request || ctap_cmd == fapico2_fido::vendor41::CMD || ctap_cmd == 0x06;
        // US-921 review (P0-1): the tag is domain-separated into the HID
        // space (bit 31 set) — a raw CID would eventually equal a CCID
        // presence tag and the same-tag join would let a CCID command consume
        // a press consented to a FIDO touch.
        let tag = fapico2_fido::presence_tag_from_channel(*channel);

        // US-1510: a second consent request is **refused, not queued** — and
        // decided BEFORE the app runs, because the app's own gate is
        // join-only *and tag-bound*: two commands on one channel share a
        // presence tag, so letting the second run could have it consume the
        // grant the first is waiting for. `up_request` is refused outright
        // (a second MakeCredential/GetAssertion is what US-1510 names);
        // `0x41`/`0x06` are refused only on the same tag, so an unrelated
        // window never breaks the Config screen or a PIN-token fetch.
        //
        // No persist gate here: nothing ran, so there is no durable change to
        // acknowledge, and the reply is a refusal rather than a success.
        if presence_windowed && slot.is_occupied() && (up_request || slot.contends_with(tag)) {
            reply(
                io,
                channel,
                CTAP_HID_CBOR,
                &[Ctap2Response::OperationPending.code()],
            )
            .await;
            return;
        }

        // SOAK-FINDING-1: the store is bound for the command so growth
        // mutations commit transactionally (durable or rejected) — the gate
        // below then finds either a persistable dirty state or a clean app,
        // never an un-persistable latch.
        let len = app.process_ctap2(ctap_cmd, &payload[1..], *channel, ctap_out);

        // US-921 + US-1509: an UpRequired answer no longer dead-ends the
        // request — the app's gate can never grant (one synchronous poll
        // inside a non-preemptive serve section), so the request is
        // **parked** in the consent slot and re-driven by later serve-loop
        // passes instead of by a nested `loop`. The reply is deferred: it
        // goes out when the window closes, on whichever pass observes the
        // grant or the deadline.
        if presence_windowed && len == 1 && ctap_out[0] == Ctap2Response::UpRequired.code() {
            let ticket = WindowTicket {
                kind: PendingKind::Ctap2,
                channel: *channel,
                tag,
                ctap_cmd,
                deadline_ms: TouchWindow::open(tag, now_ms()).deadline_ms,
            };
            match slot.park(ticket, payload) {
                Ok(()) => {
                    if presence::begin_window(tag, CTAP_TOUCH_WINDOW_MS) {
                        presence::touch_prompt(true);
                        return;
                    }
                    // The platform presence slot is busy — a CCID window
                    // (mgmt / OATH) owns it. The pre-fix code reached the
                    // same state and fell through to the plain `UpRequired`
                    // answer; keep that, and un-park. No `end_window` and no
                    // prompt clear here: this window never began, and clearing
                    // the prompt would put out a light the *other* window lit.
                    slot.take();
                }
                Err(refused) => {
                    // US-1510: never queued, and never a fallback to the
                    // blocking wait. Both refusals answer immediately.
                    let code = match refused {
                        // "another request is in progress" — the honest code
                        // for a consent slot that is already busy.
                        ParkRefusal::Occupied => Ctap2Response::OperationPending,
                        // There is no `CTAP2_ERR_INVALID_REQUEST` to reach
                        // for: neither this firmware's `Ctap2Response` nor
                        // `pico-fido`'s `ctap.h` has such a code, and the CTAP
                        // error space both do have names 0x39
                        // `CTAP2_ERR_REQUEST_TOO_LARGE` for exactly this.
                        ParkRefusal::PayloadTooLarge => Ctap2Response::RequestTooLarge,
                    };
                    reply(io, channel, CTAP_HID_CBOR, &[code.code()]).await;
                    return;
                }
            }
        }

        // US-425/US-427: durable-before-ack — persist before the success
        // reply (the keepalives are progress notifications, not the ack); the
        // final reply (success or non-UP error) goes out only if the gate is
        // `true`, else the closest existing CTAPHID error — 0xBF ERROR /
        // INVALID_COMMAND (the CTAPHID set has no "authenticator
        // internal/persistence failure" code; INVALID_COMMAND is the generic
        // reject this module already uses for unprocessable commands, so the
        // host sees an error frame, never a false ack).
        if app.persist() {
            reply(io, channel, CTAP_HID_CBOR, &ctap_out[..len]).await;
        } else {
            io.note(HidNote::PersistFailed);
            reply(io, channel, CTAP_HID_ERROR, &[HID_ERR_INVALID_CMD]).await;
        }
    } else if cmd == CTAP_HID_PING {
        reply(io, channel, CTAP_HID_PING, payload).await;
    } else if cmd == CTAP_HID_WINK {
        // WINK: acknowledge with an empty response frame.
        reply(io, channel, CTAP_HID_WINK, &[]).await;
    } else if cmd == 0x41 && !payload.is_empty() && payload[0] == 0x05 {
        // Vendor vault function (pico-fido2 vendor protocol).
        //
        // R-7 / US-106: this is the *frame-CMD* `0x41`, and it is NOT the same
        // thing as the CTAP2 *opcode* `0x41` that the `CTAP_HID_CBOR` arm
        // above now routes to `vendor41` (the RS-Key channel, PicoForge
        // vendor framing C). They cannot alias, on two independent grounds —
        // plus one coincidence that is a trap:
        //
        // 1. They are disjoint fields of disjoint frames. This arm reads the
        //    CTAPHID frame's CMD byte; the other reads the first byte of the
        //    payload *inside* a standard `CTAP_HID_CBOR` frame. A given frame
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
        let len = app.process_vendor_vault(&payload[1..], ctap_out);
        // US-425/US-427: durable-before-ack — success reply only on a `true`
        // gate, else 0xBF / INVALID_COMMAND (as in the CBOR arm above).
        if app.persist() {
            reply(io, channel, 0x41, &ctap_out[..len]).await;
        } else {
            io.note(HidNote::PersistFailed);
            reply(io, channel, CTAP_HID_ERROR, &[HID_ERR_INVALID_CMD]).await;
        }
    } else if cmd == CTAP_HID_MSG {
        // U2F (CTAP1) APDU over HID. The payload is the raw APDU.
        // US-921: the app derives its presence tag from the transaction
        // channel — the U2F entry predates the channel plumbing, so set it
        // explicitly (process_ctap2 re-derives it per call).
        app.set_channel(*channel);
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
        let presence_gated_u2f =
            payload.len() >= 3 && matches!(payload[1], 0x01 | 0x02) && payload[2] != 0x07;
        // US-1510: every presence-gated U2F request needs the touch, so a
        // second one while the slot is busy is refused with the same shape
        // the app itself would have answered — `6985`. Queuing it would mean
        // holding a second APDU for 30 s behind a slot that is single by
        // construction.
        if presence_gated_u2f && slot.is_occupied() {
            reply(io, channel, CTAP_HID_MSG, &[0x69, 0x85]).await;
            return;
        }
        // SOAK-FINDING-1: store bound for the transactional register (as in
        // the CBOR arm above) — an overflow registers as a clean U2F
        // WrongData, not an un-persistable dirty state.
        let len = app.process_u2f(payload, ctap_out);
        if presence_gated_u2f && presence::u2f_up_refusal(&ctap_out[..len]) {
            let ticket = WindowTicket {
                kind: PendingKind::U2f,
                channel: *channel,
                tag,
                // No CTAP2 opcode for this arm; the payload is the APDU.
                ctap_cmd: 0,
                deadline_ms: TouchWindow::open(tag, now_ms()).deadline_ms,
            };
            match slot.park(ticket, payload) {
                Ok(()) => {
                    if presence::begin_window(tag, CTAP_TOUCH_WINDOW_MS) {
                        presence::touch_prompt(true);
                        return;
                    }
                    // As in the CBOR arm: the platform presence slot is busy,
                    // so fall through to the captured refusal. Nothing began,
                    // so there is no window to unwind beyond the slot itself.
                    slot.take();
                }
                Err(refused) => {
                    let sw = match refused {
                        ParkRefusal::Occupied => [0x69, 0x85],
                        // CTAP1's status word has no size code. `6A80`
                        // (WRONG_DATA) is the closest honest shape for "this
                        // APDU cannot be served as asked"; the alternative —
                        // reusing `6985` — would report a presence condition
                        // that does not exist.
                        ParkRefusal::PayloadTooLarge => [0x6A, 0x80],
                    };
                    reply(io, channel, CTAP_HID_MSG, &sw).await;
                    return;
                }
            }
        }
        // US-425/US-427: durable-before-ack — success reply only on a `true`
        // gate, else 0xBF / INVALID_COMMAND (as in the CBOR arm above).
        if app.persist() {
            reply(io, channel, CTAP_HID_MSG, &ctap_out[..len]).await;
        } else {
            io.note(HidNote::PersistFailed);
            reply(io, channel, CTAP_HID_ERROR, &[HID_ERR_INVALID_CMD]).await;
        }
    } else {
        // Unknown init command — CTAPHID ERROR frame, INVALID_COMMAND.
        reply(io, channel, CTAP_HID_ERROR, &[HID_ERR_INVALID_CMD]).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::{pending, Future};
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::Wake;
    use std::thread::JoinHandle;
    use std::time::{Duration as StdDuration, Instant as StdInstant};

    use crate::ctap_hid::HID_CONT_PAYLOAD;
    use crate::pending_up::PENDING_UP_PAYLOAD_MAX;

    /// Wall-clock ceiling for one drive of the serve loop in the harness.
    ///
    /// The device's own bound is [`SERVE_BOUND_MS`] and is **not** lowered for
    /// these tests — they drive the real constants. The ceiling is here so
    /// that the defect this file exists for FAILS the test in seconds rather
    /// than hanging the suite: an unbounded await is otherwise invisible to
    /// `cargo test`, which is exactly how the US-1501 wedge survived a green
    /// suite (and how the "stickiness" — dead for the next site too — went
    /// unnoticed).
    const DRIVE_CEILING: StdDuration = StdDuration::from_millis(4_000);

    /// How long a *drive-loop* pass may park before the harness abandons it.
    ///
    /// [`Script::read_report`] models an empty OUT endpoint as a future that
    /// never completes, because that is the device's real behaviour and it is
    /// what made the blackout visible. It has a cost: once a test has granted
    /// its window, the slot empties, the read goes back to being unbounded
    /// (correctly — an idle bus must park the loop), and `drive`'s own stop
    /// condition never gets to run.
    ///
    /// 150 ms sits deliberately between the two regimes: longer than the
    /// 100 ms bounded read a *live window* imposes, so a live window's pass
    /// is never cut short and no real frame is dropped; shorter than any
    /// budget a test hands to `drive`, so an idle pass costs a fixed, small
    /// amount and the loop exits. This is a harness stop condition and nothing
    /// else — no assertion reads it, and the device build has no counterpart.
    ///
    /// The number is an `embassy_time::Duration`, because it is spent inside
    /// the same `with_timeout` the loop uses; a `std::time::Duration` here
    /// would not be the same clock the keepalive bound is stated in.
    const DRIVE_IDLE_PARK: embassy_time::Duration =
        embassy_time::Duration::from_millis(DRIVE_IDLE_PARK_MS);
    const DRIVE_IDLE_PARK_MS: u64 = 150;

    /// The device clock. Real time, from the same driver the device reads, so
    /// the 30 s `CTAP_TOUCH_WINDOW_MS` and the 100 ms keepalive period are
    /// the shipped numbers rather than test-local ones.
    fn host_now_ms() -> u64 {
        embassy_time::Instant::now().as_millis()
    }

    // ── the transport ──────────────────────────────────────────────────────

    /// One message the device sent.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Sent {
        channel: [u8; 4],
        cmd: u8,
        payload: Vec<u8>,
    }

    #[derive(Default)]
    struct Bus {
        /// Reports the host writes to the OUT endpoint, in order.
        inbound: VecDeque<[u8; HID_REPORT_SIZE]>,
        /// Messages the device sent, in order.
        sent: Vec<Sent>,
    }

    /// A host with an OUT endpoint that delivers a script and then goes
    /// quiet — and, crucially, an IN endpoint the device can always write to.
    struct Script {
        bus: Arc<Mutex<Bus>>,
        notes: Vec<HidNote>,
    }

    impl Script {
        fn new(bus: Arc<Mutex<Bus>>) -> Self {
            Self {
                bus,
                notes: Vec::new(),
            }
        }

        fn sent(&self) -> Vec<Sent> {
            self.bus.lock().unwrap().sent.clone()
        }

        /// The first message the device sent on `channel`, if any.
        fn first_on(&self, channel: [u8; 4]) -> Option<Sent> {
            self.sent().into_iter().find(|s| s.channel == channel)
        }
    }

    impl HidIo for Script {
        fn read_report(
            &mut self,
            report: &mut [u8; HID_REPORT_SIZE],
        ) -> impl Future<Output = Result<usize, ()>> {
            let next = self.bus.lock().unwrap().inbound.pop_front();
            async move {
                match next {
                    Some(frame) => {
                        report.copy_from_slice(&frame);
                        Ok(HID_REPORT_SIZE)
                    }
                    // An OUT endpoint with nothing on it. This future never
                    // completes — the exact shape of a host that has stopped
                    // writing, and the shape the device sat in for the whole
                    // 30 s window before US-1509.
                    None => pending::<Result<usize, ()>>().await,
                }
            }
        }

        fn send_frame(
            &mut self,
            channel: &[u8; 4],
            cmd: u8,
            payload: &[u8],
        ) -> impl Future<Output = bool> {
            self.bus.lock().unwrap().sent.push(Sent {
                channel: *channel,
                cmd,
                payload: payload.to_vec(),
            });
            core::future::ready(true)
        }

        fn note(&mut self, note: HidNote) {
            self.notes.push(note);
        }

        fn note_command(&mut self, _cmd: u8, _payload_len: u16, _channel: u32) {}
    }

    // ── the shared presence runtime ─────────────────────────────────────────

    /// The serve loop touches the *shared* presence runtime (one pending slot,
    /// one prompt) — the same single instance the device has. Tests therefore
    /// serialise the way `presence/tests.rs` does, and every test **closes
    /// the window it opened** before releasing the lock, so a leaked slot
    /// cannot make the next test fail for the wrong reason.
    static SERVE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static PRESENCE_ONCE: std::sync::Once = std::sync::Once::new();

    fn serve_test_guard() -> std::sync::MutexGuard<'static, ()> {
        PRESENCE_ONCE.call_once(|| {
            // Write-once, exactly as the device bin does at boot. `init`
            // returns `false` on a second call, which is fine: only the first
            // one installs the slot.
            presence::init(host_now_ms);
        });
        SERVE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ── the app ────────────────────────────────────────────────────────────

    /// An app whose presence gate never grants until `grant` is set — the
    /// shape of the one-shot synchronous poll US-921 opened a window for.
    ///
    /// Every answer is a distinct byte pattern so the harness can tell a
    /// `MakeCredential` re-drive from a `getInfo` answer without parsing
    /// CBOR.
    struct FakeApp {
        /// Shared with the injector thread: a "press".
        grant: Arc<AtomicBool>,
        /// Every UP command the app was asked to run, in order. Its length
        /// is how a test sees a re-drive.
        up_calls: Vec<u8>,
        window_open: bool,
    }

    impl FakeApp {
        fn new(grant: Arc<AtomicBool>) -> Self {
            Self {
                grant,
                up_calls: Vec::new(),
                window_open: false,
            }
        }
    }

    impl FidoDispatch for FakeApp {
        fn sync_generations(&mut self) {}

        fn device_info_page(&self, _page: u8, out: &mut HeaplessVec<u8, MAX_RESPONSE>) {
            out.extend_from_slice(&[0xDE, 0x01]).ok();
        }

        fn process_ctap2(
            &mut self,
            ctap_cmd: u8,
            _payload: &[u8],
            _channel: [u8; 4],
            out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
        ) -> usize {
            match ctap_cmd {
                // authenticatorMakeCredential / authenticatorGetAssertion.
                0x01 | 0x02 => {
                    self.up_calls.push(ctap_cmd);
                    if self.grant.load(Ordering::SeqCst) {
                        out.clear();
                        out.extend_from_slice(&[0xAA, ctap_cmd]).ok();
                        2
                    } else {
                        out.clear();
                        out.extend_from_slice(&[fapico2_fido::ctap2::Ctap2Response::UpRequired.code()])
                            .ok();
                        self.window_open = true;
                        1
                    }
                }
                // authenticatorGetInfo.
                0x04 => {
                    out.clear();
                    out.extend_from_slice(&[0xBB]).ok();
                    1
                }
                other => {
                    out.clear();
                    out.extend_from_slice(&[other]).ok();
                    1
                }
            }
        }

        fn process_vendor_vault(
            &mut self,
            _payload: &[u8],
            out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
        ) -> usize {
            out.clear();
            0
        }

        fn set_channel(&mut self, _channel: [u8; 4]) {}

        fn process_u2f(
            &mut self,
            _apdu: &[u8],
            out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
        ) -> usize {
            out.clear();
            if self.grant.load(Ordering::SeqCst) {
                out.extend_from_slice(&[0x90, 0x00]).ok();
                2
            } else {
                out.extend_from_slice(&[0x69, 0x85]).ok();
                2
            }
        }

        fn persist(&mut self) -> bool {
            true
        }
    }

    // ── harness ────────────────────────────────────────────────────────────

    /// Parked (unparked from another thread) waker for the `embassy-time`
    /// std driver's alarm thread.
    struct ThreadWaker {
        thread: std::thread::Thread,
    }

    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.thread.unpark();
        }
    }

    /// Drive `fut` on the calling thread, failing the test if it has not
    /// finished inside [`DRIVE_CEILING`].
    fn block_on<F: Future>(what: &str, fut: F) -> F::Output {
        let start = StdInstant::now();
        let mut fut = pin!(fut);
        let parker = Arc::new(ThreadWaker {
            thread: std::thread::current(),
        });
        let waker = Waker::from(parker);
        let mut cx = Context::from_waker(&waker);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
            let elapsed = start.elapsed();
            assert!(
                elapsed < DRIVE_CEILING,
                "{what}: still parked after {elapsed:?} — the serve loop did not \
                 come back. Before US-1509 a live consent window held it for the \
                 whole 30 s CTAP_TOUCH_WINDOW_MS with the OUT endpoint undrained, \
                 which is the blackout this loop is supposed to have ended."
            );
            std::thread::park_timeout(StdDuration::from_millis(1));
        }
    }

    /// CTAPHID fragmentation, host side: an INIT report plus continuations.
    fn frame(channel: [u8; 4], cmd: u8, payload: &[u8]) -> Vec<[u8; HID_REPORT_SIZE]> {
        let mut out = Vec::new();
        let first = payload.len().min(crate::ctap_hid::HID_FIRST_PAYLOAD);
        let mut init = [0u8; HID_REPORT_SIZE];
        init[..4].copy_from_slice(&channel);
        init[4] = cmd | 0x80;
        init[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        init[7..7 + first].copy_from_slice(&payload[..first]);
        out.push(init);
        let mut offset = first;
        let mut seq = 0u8;
        while offset < payload.len() {
            let end = (offset + HID_CONT_PAYLOAD).min(payload.len());
            let mut cont = [0u8; HID_REPORT_SIZE];
            cont[..4].copy_from_slice(&channel);
            cont[4] = seq;
            cont[5..5 + (end - offset)].copy_from_slice(&payload[offset..end]);
            out.push(cont);
            offset = end;
            seq = seq.wrapping_add(1);
        }
        out
    }

    fn cbor(channel: [u8; 4], cbor: &[u8]) -> Vec<[u8; HID_REPORT_SIZE]> {
        frame(channel, CTAP_HID_CBOR, cbor)
    }

    /// A host that writes `frames` onto the OUT endpoint at the given
    /// offsets after the drive starts.
    ///
    /// The `t=0` batch is delivered **synchronously, before this returns**,
    /// not from the spawned thread. That is not a convenience: with nothing
    /// parked, `read_one` is deliberately *unbounded* (an idle bus must park
    /// the loop — that is what the OUT endpoint read is for), and
    /// [`Script::read_report`] models an empty endpoint as a future that
    /// never completes. So a first frame that lost a thread race would hang
    /// the very first pass and every assertion after it. On the device the
    /// equivalent ordering is the host's write already sitting in the
    /// endpoint's buffer before the loop's first poll.
    fn script(
        bus: &Arc<Mutex<Bus>>,
        script: &[(StdDuration, Vec<[u8; HID_REPORT_SIZE]>)],
    ) -> JoinHandle<()> {
        let mut later = Vec::new();
        for (at, frames) in script {
            if at.is_zero() {
                bus.lock().unwrap().inbound.extend(frames.iter().copied());
            } else {
                later.push((*at, frames.clone()));
            }
        }
        let bus = bus.clone();
        std::thread::spawn(move || {
            let start = StdInstant::now();
            for (at, frames) in later {
                let due = start + at;
                while StdInstant::now() < due {
                    std::thread::sleep(StdDuration::from_millis(1));
                }
                bus.lock().unwrap().inbound.extend(frames);
            }
        })
    }

    async fn drive<S: HidIo, A: FidoDispatch>(
        srv: &mut HidServe<'_>,
        io: &mut S,
        app: &mut A,
        slot: &mut PendingUp,
        budget: StdDuration,
    ) {
        let start = StdInstant::now();
        // `serve_loop` is exactly `loop { serve_once(..).await }`
        // (`hid_serve.rs`); this harness is that loop plus a stop condition
        // and nothing else, so what the tests drive is the shipped iteration.
        //
        // The only addition is [`DRIVE_IDLE_PARK`], which ends a pass that
        // parks on an empty OUT endpoint so `budget` can elapse. It is longer
        // than the bounded read a live window imposes, so it never cuts a pass
        // that had real work.
        while start.elapsed() < budget {
            drive_one_pass(srv, io, app, slot).await;
        }
    }

    /// One harness pass: run `serve_once`, abandoning it if it parks, and
    /// record it if it parked **with a consent window still open**.
    ///
    /// The conditioning is what keeps the instrument honest. A pass that
    /// closes the window and then parks on an idle OUT endpoint is the loop
    /// doing exactly what it should, so it is not counted; a pass that could
    /// not return while a window was open is the blackout, so it is. See
    /// [`HidServe::note_blocked_live_pass`].
    async fn drive_one_pass<S: HidIo, A: FidoDispatch>(
        srv: &mut HidServe<'_>,
        io: &mut S,
        app: &mut A,
        slot: &mut PendingUp,
    ) {
        let abandoned = embassy_time::with_timeout(DRIVE_IDLE_PARK, serve_once(srv, io, app, slot))
            .await
            .is_err();
        if abandoned && slot.is_occupied() {
            srv.note_blocked_live_pass();
        }
    }

    /// [`drive`] with a *condition* instead of a wall-clock budget.
    ///
    /// Same loop, same stop shape — the only difference is what ends it. A
    /// fixed budget makes an assertion about the firmware depend on how many
    /// 100 ms keepalive-bounded reads happen to fit on a loaded host, which
    /// is not a property of the firmware at all; a condition asserts the
    /// behaviour directly and lets [`DRIVE_CEILING`] be the only time bound.
    async fn drive_until<S: HidIo, A: FidoDispatch>(
        srv: &mut HidServe<'_>,
        io: &mut S,
        app: &mut A,
        slot: &mut PendingUp,
        done: impl Fn(&HidServe<'_>, &A) -> bool,
    ) {
        while !done(srv, app) {
            drive_one_pass(srv, io, app, slot).await;
        }
    }

    /// The blackout assertion, shared by every test that drives the loop with
    /// a consent window open.
    ///
    /// Two halves, and the order matters. `slot.is_occupied()` is the
    /// *premise*: US-1509's change is that the request is parked in the slot,
    /// so a suite that asserts cross-channel answers without first asserting
    /// the window is parked will happily go green against firmware that has
    /// the slot but refuses to use it. The pass count is the *measurement*:
    /// it catches a blocking await reintroduced anywhere on the live path,
    /// including inside `redrive_window`, where the slot **is** occupied and
    /// so the cross-channel assertions alone would not notice for one pass.
    #[track_caller]
    fn assert_the_window_is_live_and_unblocked(srv: &HidServe<'_>, slot: &PendingUp) {
        assert!(
            slot.is_occupied(),
            "the consent window must be PARKED in `PendingUp`. US-1509 replaced the \
             serve loop's nested consent `loop` with this slot; without it the \
             `MakeCredential` is being answered on some other path, and every \
             cross-channel assertion below is measuring that other path instead."
        );
        assert_eq!(
            srv.blocked_live_passes(),
            0,
            "US-1502/US-1509: {} serve pass(es) could not return while a consent \
             window was open. The window is re-asserted and the command re-driven \
             per pass; it is never awaited. A pass that blocks is the blackout.",
            srv.blocked_live_passes()
        );
    }

    // ── the tests ──────────────────────────────────────────────────────────

    /// US-1502 (RED before the fix, green after): *given* a consent window is
    /// open, *when* a request arrives on another channel, *then* it is
    /// answered inside [`SERVE_BOUND_MS`].
    ///
    /// The host opens the window with a `MakeCredential` at t=0 and writes a
    /// `PING` on a **second** channel at t=200 ms. The device must echo it.
    ///
    /// Before US-1509 this never happened: `dispatch` was awaited inline in
    /// the arm that consumed the read, its consent loop held the serve loop
    /// for the whole window, and `hid_out.read()` was never reached again —
    /// the one `PING` in the script stayed in the endpoint buffer and the
    /// harness ran into its ceiling.
    #[test]
    fn us1502_a_request_on_another_channel_is_answered_while_a_window_is_open() {
        let _g = serve_test_guard();
        let bus = Arc::new(Mutex::new(Bus::default()));
        let chan_a = [0x00, 0x00, 0x00, 0x01];
        let chan_b = [0x00, 0x00, 0x00, 0x02];
        let injector = script(
            &bus,
            &[
                // t=0: MakeCredential on A. No grant ever arrives, so the
                // window stays open for the whole drive.
                (StdDuration::from_millis(0), cbor(chan_a, &[0x01, 0xA0])),
                (StdDuration::from_millis(200), frame(chan_b, CTAP_HID_PING, b"ping")),
            ],
        );
        // No "press": the window is never granted.
        let grant = Arc::new(AtomicBool::new(false));

        let mut ctap_out: HeaplessVec<u8, CTAP2_MAX_MSG> = HeaplessVec::new();
        let mut srv = HidServe::new(host_now_ms, &mut ctap_out);
        let mut io = Script::new(bus.clone());
        let mut app = FakeApp::new(grant.clone());
        let mut slot = PendingUp::new();

        block_on(
            "US-1502: PING on a second channel during a consent window",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(1_200)),
        );
        injector.join().unwrap();

        assert!(app.window_open, "the harness must actually be inside a window");
        assert_the_window_is_live_and_unblocked(&srv, &slot);
        let echoed = io
            .sent()
            .into_iter()
            .find(|s| s.channel == chan_b && s.cmd == CTAP_HID_PING)
            .expect(
                "US-1502: a request that arrived on another channel during a consent \
                 window was never answered. The serve loop is not reading the OUT \
                 endpoint while the window is open — the blackout is still there.",
            );
        assert_eq!(echoed.payload, b"ping", "CTAPHID_PING echoes its payload");

        // Close the window before releasing the shared presence slot: the
        // parked command is granted and answered, so the pending slot and the
        // touch prompt go with it.
        grant.store(true, Ordering::SeqCst);
        block_on(
            "US-1502: release the consent window",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(400)),
        );
        assert!(
            io.sent().into_iter().any(|s| s.channel == chan_a
                && s.cmd == CTAP_HID_CBOR
                && s.payload == vec![0xAA, 0x01]),
            "the parked MakeCredential must be answered once the touch arrives — the \
             window's final reply is the granted answer, not another keepalive"
        );
    }

    /// US-1508 (RED before the fix): the extension of US-1502 to the command
    /// a browser actually probes with during a window — `authenticatorGetInfo`
    /// on a **different** channel.
    #[test]
    fn us1508_get_info_on_a_different_channel_is_answered_during_a_window() {
        let _g = serve_test_guard();
        let bus = Arc::new(Mutex::new(Bus::default()));
        let chan_a = [0x00, 0x00, 0x00, 0x01];
        let chan_b = [0x00, 0x00, 0x00, 0x02];
        let injector = script(
            &bus,
            &[
                (StdDuration::from_millis(0), cbor(chan_a, &[0x01, 0xA0])),
                // `authenticatorGetInfo` is CTAP2 opcode 0x04 in this
                // firmware's dialect (AGENTS.md §2: the fido2 2.2.1 numbering,
                // deliberately NOT the spec's 0x03).
                (StdDuration::from_millis(200), cbor(chan_b, &[0x04])),
            ],
        );
        let grant = Arc::new(AtomicBool::new(false));

        let mut ctap_out: HeaplessVec<u8, CTAP2_MAX_MSG> = HeaplessVec::new();
        let mut srv = HidServe::new(host_now_ms, &mut ctap_out);
        let mut io = Script::new(bus.clone());
        let mut app = FakeApp::new(grant.clone());
        let mut slot = PendingUp::new();

        block_on(
            "US-1508: getInfo on a second channel during a consent window",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(1_200)),
        );
        injector.join().unwrap();

        assert_the_window_is_live_and_unblocked(&srv, &slot);
        let answered = io
            .sent()
            .into_iter()
            .find(|s| s.channel == chan_b && s.cmd == CTAP_HID_CBOR)
            .expect(
                "US-1508: authenticatorGetInfo on a different channel went unanswered for \
                 the whole consent window. That is the discovery symptom: a browser \
                 probing this key during a window learns nothing about it.",
            );
        assert_eq!(
            answered.payload,
            vec![0xBB],
            "the getInfo answer must be the app's own, byte for byte"
        );

        grant.store(true, Ordering::SeqCst);
        block_on(
            "US-1508: release the consent window",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(400)),
        );
    }

    /// US-1509: the serve loop keeps calling `hid_out.read()` while the slot
    /// is occupied. The window is re-asserted and the command re-driven; it
    /// is never awaited.
    #[test]
    fn us1509_the_serve_loop_keeps_reading_the_out_endpoint_during_a_window() {
        let _g = serve_test_guard();
        let bus = Arc::new(Mutex::new(Bus::default()));
        let chan_a = [0x00, 0x00, 0x00, 0x01];
        let injector = script(
            &bus,
            &[(StdDuration::from_millis(0), cbor(chan_a, &[0x01, 0xA0]))],
        );
        let grant = Arc::new(AtomicBool::new(false));

        let mut ctap_out: HeaplessVec<u8, CTAP2_MAX_MSG> = HeaplessVec::new();
        let mut srv = HidServe::new(host_now_ms, &mut ctap_out);
        let mut io = Script::new(bus.clone());
        let mut app = FakeApp::new(grant.clone());
        let mut slot = PendingUp::new();

        block_on(
            "US-1509: serve loop keeps reading during a window",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(600)),
        );
        injector.join().unwrap();

        assert!(app.window_open, "the window must still be open at the end");
        assert_the_window_is_live_and_unblocked(&srv, &slot);

        // Re-driven, not merely retried once: a parked MakeCredential that
        // is re-asserted every pass is re-run every pass.
        //
        // This waits for the *condition* under [`DRIVE_CEILING`] rather than
        // counting passes inside a fixed 600 ms budget. The property US-1509
        // claims is that the loop keeps reading and keeps re-driving — not
        // how many times it manages to in half a second on a loaded machine.
        // A fixed budget made this the one intermittently-red assertion in
        // the file (observed once in ~25 runs, never reproduced in 22
        // subsequent ones including 8 run concurrently): the count depends
        // on how many 100 ms keepalive-bounded reads fit, which depends on
        // the host's scheduling, not on the firmware.
        block_on(
            "US-1509: the window is re-driven, repeatedly",
            drive_until(&mut srv, &mut io, &mut app, &mut slot, |srv, app| {
                srv.reads() >= 2 && app.up_calls.len() >= 2
            }),
        );

        assert!(
            srv.reads() >= 2,
            "US-1509: the loop made {} read(s); it must keep returning to \
             hid_out.read() while a window is open (and re-driving it each pass, \
             not awaiting it).",
            srv.reads()
        );
        assert!(
            app.up_calls.len() >= 2,
            "US-1509: the parked command was driven {} time(s); a re-asserted \
             window re-drives it on every pass.",
            app.up_calls.len()
        );
        // And the host is told the device is still waiting (FX-402).
        let keepalives = io
            .sent()
            .into_iter()
            .filter(|s| s.cmd == CTAP_HID_KEEPALIVE && s.channel == chan_a)
            .count();
        assert!(
            keepalives >= 2,
            "US-1509: only {keepalives} keepalive(s) in 600 ms; the progress-frame \
             cadence must survive the restructure."
        );

        grant.store(true, Ordering::SeqCst);
        block_on(
            "US-1509: release the consent window",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(400)),
        );
    }

    /// The bound is stated, not assumed: a request that arrives at the very
    /// moment a window opens is answered within [`SERVE_BOUND_MS`] of arriving.
    #[test]
    fn the_answer_lands_inside_the_stated_bound() {
        let _g = serve_test_guard();
        let bus = Arc::new(Mutex::new(Bus::default()));
        let chan_a = [0x00, 0x00, 0x00, 0x01];
        let chan_b = [0x00, 0x00, 0x00, 0x02];
        let arrive = StdDuration::from_millis(100);
        let injector = script(
            &bus,
            &[
                (StdDuration::from_millis(0), cbor(chan_a, &[0x01, 0xA0])),
                (arrive, cbor(chan_b, &[0x04])),
            ],
        );
        let grant = Arc::new(AtomicBool::new(false));

        let mut ctap_out: HeaplessVec<u8, CTAP2_MAX_MSG> = HeaplessVec::new();
        let mut srv = HidServe::new(host_now_ms, &mut ctap_out);
        let mut io = Script::new(bus.clone());
        let mut app = FakeApp::new(grant.clone());
        let mut slot = PendingUp::new();
        let sent: Arc<Mutex<Vec<(StdInstant, Sent)>>> = Arc::new(Mutex::new(Vec::new()));

        let bound = StdDuration::from_millis(SERVE_BOUND_MS);
        let sent_for_bound = sent.clone();
        let elapsed = block_on("US-1502: the stated bound", async {
            let start = StdInstant::now();
            let deadline = start + arrive + bound;
            while StdInstant::now() < deadline {
                let before = io.sent().len();
                serve_once(&mut srv, &mut io, &mut app, &mut slot).await;
                // EVERY frame this pass produced, not just the first: a pass
                // over a live window emits the window's keepalive before the
                // answer to the new command, and timestamping only the first
                // frame would report the keepalive's time and never log the
                // answer at all.
                let produced = io.sent();
                let at = StdInstant::now();
                sent_for_bound
                    .lock()
                    .unwrap()
                    .extend(produced[before..].iter().map(|s| (at, s.clone())));
            }
            start.elapsed()
        });
        injector.join().unwrap();

        assert_the_window_is_live_and_unblocked(&srv, &slot);
        let start = StdInstant::now();
        let log = sent.lock().unwrap();
        let answer = log
            .iter()
            .find(|(_, s)| s.channel == chan_b)
            .unwrap_or_else(|| {
                panic!(
                    "no answer on the second channel within {bound:?} of it arriving \
                     (the drive ran {elapsed:?}). US-1502 requires one."
                )
            });
        let waited = answer.0.saturating_duration_since(start + arrive);
        assert!(
            waited <= bound,
            "answered after {waited:?}, past the published {SERVE_BOUND_MS} ms bound"
        );

        grant.store(true, Ordering::SeqCst);
        block_on(
            "bound: release the consent window",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(400)),
        );
    }

    /// US-1510, at the seam that matters: a **second** `MakeCredential` while
    /// a window is open is refused immediately, and — the part that makes it
    /// a refusal rather than a reroute — **it never reaches the app**.
    ///
    /// The app is not a neutral witness here. Its presence gate is
    /// `request_grant_in_window`, which is *join-only and tag-bound*: two
    /// commands on one channel derive the same tag, so a second command that
    /// ran would be able to consume the grant the first is waiting for. That
    /// is why the occupancy check sits in the CBOR arm, above
    /// `process_ctap2`, and not inside the slot.
    #[test]
    fn us1510_a_second_up_request_is_refused_and_never_reaches_the_app() {
        let _g = serve_test_guard();
        let bus = Arc::new(Mutex::new(Bus::default()));
        let chan_a = [0x00, 0x00, 0x00, 0x01];
        let injector = script(
            &bus,
            &[
                (StdDuration::from_millis(0), cbor(chan_a, &[0x01, 0xA0])),
                // Same channel, so the same presence tag: the case where a
                // queued second command could steal the first one's grant.
                (StdDuration::from_millis(250), cbor(chan_a, &[0x01, 0xB1])),
            ],
        );
        let grant = Arc::new(AtomicBool::new(false));

        let mut ctap_out: HeaplessVec<u8, CTAP2_MAX_MSG> = HeaplessVec::new();
        let mut srv = HidServe::new(host_now_ms, &mut ctap_out);
        let mut io = Script::new(bus.clone());
        let mut app = FakeApp::new(grant.clone());
        let mut slot = PendingUp::new();

        block_on(
            "US-1510: second UP request while a window is open",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(1_200)),
        );
        injector.join().unwrap();

        assert_the_window_is_live_and_unblocked(&srv, &slot);
        let refused = io
            .sent()
            .into_iter()
            .find(|s| {
                s.channel == chan_a
                    && s.cmd == CTAP_HID_CBOR
                    && s.payload == vec![Ctap2Response::OperationPending.code()]
            })
            .expect(
                "US-1510: a second MakeCredential during a live window was not answered \
                 with OPERATION_PENDING. Either it was queued — which the single slot \
                 must never do — or it was parked, which would give the consent slot \
                 two holders.",
            );

        // The refusal went out on the *second* command's channel and nothing
        // else answered it: the request is answered now, not after the first
        // window closes 30 s from now.
        assert_eq!(refused.channel, chan_a);
        assert!(
            !io.sent().iter().any(|s| s.payload == vec![0xAA, 0x01]),
            "the second MakeCredential must not be answered at all while the slot is busy"
        );
        assert!(
            slot.is_occupied(),
            "the first window is still the slot's only occupant"
        );

        grant.store(true, Ordering::SeqCst);
        block_on(
            "US-1510: release the consent window",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(400)),
        );
        // The original command, and only the original, is answered on close.
        assert!(
            io.sent().iter().any(|s| s.payload == vec![0xAA, 0x01]),
            "the parked command must still be answered when its window closes"
        );
    }

    /// US-1510's bound, at the dispatch seam: a request above
    /// [`PENDING_UP_PAYLOAD_MAX`] is answered `CTAP2_ERR_REQUEST_TOO_LARGE`
    /// (`0x39`) and never becomes a window.
    ///
    /// The code is `RequestTooLarge`, not `InvalidRequest`: `Ctap2Response`
    /// has no `InvalidRequest` variant — neither does `pico-fido`'s `ctap.h`
    /// — and `0x39` is the code the CTAP error space names for exactly this
    /// condition. The assertion is written against the enum, so a future
    /// renumbering cannot make this test pass on the wrong byte.
    #[test]
    fn us1510_an_oversize_request_is_refused_with_request_too_large() {
        let _g = serve_test_guard();
        let bus = Arc::new(Mutex::new(Bus::default()));
        let chan_a = [0x00, 0x00, 0x00, 0x01];
        // One byte of CTAP2 opcode plus a body above the 1024 B static.
        let mut over = vec![0x01u8];
        over.extend(core::iter::repeat(0x5A).take(PENDING_UP_PAYLOAD_MAX));
        assert!(
            over.len() > PENDING_UP_PAYLOAD_MAX,
            "the request must actually exceed the pinned bound"
        );
        let injector = script(&bus, &[(StdDuration::from_millis(0), cbor(chan_a, &over))]);
        let grant = Arc::new(AtomicBool::new(false));

        let mut ctap_out: HeaplessVec<u8, CTAP2_MAX_MSG> = HeaplessVec::new();
        let mut srv = HidServe::new(host_now_ms, &mut ctap_out);
        let mut io = Script::new(bus.clone());
        let mut app = FakeApp::new(grant.clone());
        let mut slot = PendingUp::new();

        block_on(
            "US-1510: oversize request",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(800)),
        );
        injector.join().unwrap();

        let answered = io
            .sent()
            .into_iter()
            .find(|s| s.channel == chan_a && s.cmd == CTAP_HID_CBOR)
            .expect("US-1510: the oversize request was never answered at all");
        assert_eq!(
            answered.payload,
            vec![Ctap2Response::RequestTooLarge.code()],
            "an oversize request must answer REQUEST_TOO_LARGE (0x39)"
        );
        assert!(
            !slot.is_occupied(),
            "an oversize request must not leave a window behind — the whole point is \
             that it cannot convert into a 30 s wait"
        );

        // And the slot is still usable: the refusal is not a wedge.
        grant.store(true, Ordering::SeqCst);
        block_on(
            "US-1510: slot still usable after a refusal",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(200)),
        );
        assert!(!slot.is_occupied(), "no window to release");
    }

    /// US-921's anti-harvest rule, through the new structure: a press that
    /// arrives with **nothing pending** must arm nothing, and a press during
    /// this key's window must not become anybody else's grant.
    ///
    /// The restructuring replaced a `loop` with a slot and moved the touch
    /// across serve-loop passes, so "is there a stretch where a stray press
    /// is harvestable" is exactly the question a reviewer should ask of it.
    #[test]
    fn us921_a_press_with_nothing_pending_arms_nothing() {
        let _g = serve_test_guard();
        let tag_a = fapico2_fido::presence_tag_from_channel([0, 0, 0, 1]);
        let tag_b = fapico2_fido::presence_tag_from_channel([0, 0, 0, 7]);

        // Nothing pending, no slot occupied — the state a latched press lands
        // in on the device. The join-only HID gate must refuse here.
        assert!(
            !crate::presence::request_grant_in_window(tag_b),
            "the join-only HID grant must refuse with nothing pending: `poll_press` \
             discarded the press, and a discarded press arms nothing, anywhere"
        );

        // And a press observed while *another* window holds the single slot
        // must not be harvestable by this command either. The window is
        // opened and closed here explicitly: `window_grant` would leave it
        // open for its whole `CCID_WINDOW_MS` on a failed grant, and the
        // presence runtime is a process-wide singleton — one test leaking a
        // window into it starves every later test's `begin_window`, which is
        // exactly the failure US-921's single slot exists to prevent.
        assert!(crate::presence::begin_window(tag_a, CTAP_TOUCH_WINDOW_MS));
        assert!(
            !crate::presence::request_grant_in_window(tag_b),
            "a mismatched tag must not consume another window's grant"
        );
        crate::presence::end_window(tag_a);
    }

    /// The U2F twin of the whole story. `CTAP_HID_MSG` had a **structurally
    /// identical** keepalive loop in the same dispatcher, so a slot that only
    /// works for `CTAP_HID_CBOR` leaves half the blackout in place — and the
    /// two arms genuinely differ: the parked payload is the raw APDU rather
    /// than an opcode plus CBOR, the kind is [`PendingKind::U2f`], the answer
    /// goes out on `CTAP_HID_MSG` with a two-byte status word, and the
    /// re-drive has to re-stamp the app's channel (`set_channel`) because
    /// `process_u2f` derives the presence tag from the app's remembered
    /// channel instead of taking it as an argument.
    ///
    /// So: register (INS `0x01`, P1 `0x03`) parks, the loop keeps reading and
    /// keeps answering a `PING` on a second channel, and the window's final
    /// reply is the granted `9000` — not another `6985`.
    #[test]
    fn us1509_the_u2f_arm_parks_and_re_drives_like_the_cbor_arm() {
        let _g = serve_test_guard();
        let bus = Arc::new(Mutex::new(Bus::default()));
        let chan_a = [0x00, 0x00, 0x00, 0x01];
        let chan_b = [0x00, 0x00, 0x00, 0x02];
        // CLA=00 INS=01 (REGISTER) P1=03 P2=00 Lc=00 — a presence-gated
        // U2F request under `presence_gated_u2f` (INS 0x01, P1 != 0x07).
        let register = [0x00u8, 0x01, 0x03, 0x00, 0x00];
        let injector = script(
            &bus,
            &[
                (StdDuration::from_millis(0), frame(chan_a, CTAP_HID_MSG, &register)),
                (StdDuration::from_millis(200), frame(chan_b, CTAP_HID_PING, b"ping")),
            ],
        );
        let grant = Arc::new(AtomicBool::new(false));

        let mut ctap_out: HeaplessVec<u8, CTAP2_MAX_MSG> = HeaplessVec::new();
        let mut srv = HidServe::new(host_now_ms, &mut ctap_out);
        let mut io = Script::new(bus.clone());
        let mut app = FakeApp::new(grant.clone());
        let mut slot = PendingUp::new();

        block_on(
            "U2F: register parks and the loop keeps reading",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(1_200)),
        );
        injector.join().unwrap();

        assert_the_window_is_live_and_unblocked(&srv, &slot);
        assert_eq!(
            slot.parked().expect("the U2F request is parked").ticket.kind,
            PendingKind::U2f,
            "the U2F arm must park as `PendingKind::U2f`: its final reply goes out on \
             CTAP_HID_MSG, and a CBOR-kind ticket would answer a U2F register with a \
             one-byte CBOR status the client cannot parse"
        );
        assert!(
            io.sent()
                .iter()
                .any(|s| s.channel == chan_b && s.cmd == CTAP_HID_PING && s.payload == b"ping"),
            "US-1502 on the U2F path: a PING that arrived on another channel during a U2F \
             consent window was never answered — the MSG arm's window is still a blackout"
        );

        grant.store(true, Ordering::SeqCst);
        block_on(
            "U2F: release the consent window",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(400)),
        );
        assert!(
            io.sent()
                .iter()
                .any(|s| s.channel == chan_a && s.cmd == CTAP_HID_MSG && s.payload == vec![0x90, 0x00]),
            "the parked U2F register must be answered with its granted 9000 on close, not \
             left as a refusal"
        );
    }

    /// US-1510 on the U2F arm: a second presence-gated U2F request while the
    /// slot is live is refused with the shape the app itself would answer —
    /// `6985` — and is never parked behind the first. The single slot is
    /// shared across *both* arms, so this is a distinct path from the CBOR
    /// refusal and needs its own assertion.
    #[test]
    fn us1510_a_second_u2f_request_is_refused_while_the_slot_is_live() {
        let _g = serve_test_guard();
        let bus = Arc::new(Mutex::new(Bus::default()));
        let chan_a = [0x00, 0x00, 0x00, 0x01];
        let register = [0x00u8, 0x01, 0x03, 0x00, 0x00];
        let authenticate = [0x00u8, 0x02, 0x03, 0x00, 0x00];
        let injector = script(
            &bus,
            &[
                (StdDuration::from_millis(0), frame(chan_a, CTAP_HID_MSG, &register)),
                (StdDuration::from_millis(250), frame(chan_a, CTAP_HID_MSG, &authenticate)),
            ],
        );
        let grant = Arc::new(AtomicBool::new(false));

        let mut ctap_out: HeaplessVec<u8, CTAP2_MAX_MSG> = HeaplessVec::new();
        let mut srv = HidServe::new(host_now_ms, &mut ctap_out);
        let mut io = Script::new(bus.clone());
        let mut app = FakeApp::new(grant.clone());
        let mut slot = PendingUp::new();

        block_on(
            "US-1510: second U2F request while a window is open",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(1_200)),
        );
        injector.join().unwrap();

        assert_the_window_is_live_and_unblocked(&srv, &slot);
        // Two `6985`s reach the wire — the app's own answer to the first, and
        // the refusal for the second. Both are refusals, and neither is a
        // signature.
        assert!(
            !io.sent().iter().any(|s| s.payload == vec![0x90, 0x00]),
            "nothing may be answered while the window is live: the second request must be \
             refused, not queued behind the first and answered after it"
        );
        assert_eq!(
            slot.parked().expect("the first window survives").payload,
            register.as_slice(),
            "a refused second request must not evict or overwrite the parked one"
        );

        grant.store(true, Ordering::SeqCst);
        block_on(
            "US-1510: release the U2F window",
            drive(&mut srv, &mut io, &mut app, &mut slot, StdDuration::from_millis(400)),
        );
    }
}
