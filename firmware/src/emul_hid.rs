//! US-1524: the emulator's half of the CTAP-HID seam — the transport adapter
//! and the serve iteration — with the parity tests that keep it on the shipped
//! loop.
//!
//! # The defect this removes
//!
//! Until US-1524, `emul_main.rs` carried a **second** `HidAssembler`
//! (`emul_main.rs:356-488` before this story), a second `HidFeed`, a second
//! reply framer (`send_hid_response`, `:490-525`) and **two more** blocking
//! consent loops (`:1093-1126` CBOR, `:1216-1234` U2F) plus the
//! `emul_consent_tick` helper at `:316`. The shipped loop was
//! `hid_serve::serve_once`, driven by `tasks.rs::hid_task`; the emulator ran a
//! hand-written copy of it.
//!
//! That is the twin trap one level above the one `AGENTS.md` §1 warns about.
//! The blackout this epic exists to fix (US-1501/1502: the serve loop stops
//! reading the USB OUT endpoint for the whole 30 s consent window, so a host's
//! `PING`/`CANCEL` never complete) was **reproducible in the emulator** —
//! because the emulator had the nested `loop` too — and was fixed only on the
//! board. Every host test built on the emulator was therefore certifying code
//! that is not the shipped code, which is how US-1501's wedge got through a
//! green suite (see `hid_serve.rs`'s module docs and
//! `HidServe::note_blocked_live_pass`).
//!
//! # What is left in this file
//!
//! Only what genuinely differs between the two transports:
//!
//! * [`HidLink`] — "one 64-byte report in, one 64-byte report out". On the host
//!   that is a length-prefixed TCP frame; on the device it is two
//!   `embassy_rp` endpoints. The emulator's implementation over
//!   `EmulationTransport` lives in `emul_main.rs`, because `EmulationTransport`
//!   is behind the platform's `emulation` feature.
//! * [`EmulHid`] — the [`HidIo`] adapter over a [`HidLink`], the twin of
//!   `tasks.rs`'s `DeviceHid`. It is deliberately **thin**: the framing is
//!   `hid_reply::write_reply`, the same function `DeviceHid` reaches through
//!   `send_hid_report`, so there is no second reply framer left to drift.
//! * [`serve_pass`] — **one** iteration of the shared serve loop. The emulator's
//!   main loop calls this; it does not contain a dispatch of its own.
//!
//! The consent-window policy is [`PendingUp`] and the loop is
//! [`crate::hid_serve::serve_once`], both of them the *shipped* ones. There is
//! no second assembler and no second consent loop anywhere in the tree.
//!
//! # Why `extern crate std` here, and why this module is `emulation`-only
//!
//! [`serve_pass`] needs a `block_on`: the device drives `serve_once` from the
//! embassy executor, and the emulator is a single-threaded poll loop over TCP
//! sockets. `std` is pulled in explicitly because `lib.rs` is `#![no_std]`
//! outside `cfg(test)`, and the module is gated on `feature = "emulation"`
//! because a `std` dependency has no business in the `thumbv8m` release image.
//!
//! # Parity, and — precisely — what these tests can and cannot fail on
//!
//! The parity tests compare **raw 64-byte reports**, in order, between the
//! emulator's [`serve_pass`] and the shipped `serve_once` driven through a
//! device-shaped adapter. But after US-1524 both halves call the *same*
//! [`crate::hid_serve::serve_once`], so the honest description of what the
//! equality proves is narrow, and it is stated here rather than left for a
//! reader to assume:
//!
//! * **What it proves.** The two *transports* are interchangeable. Reaching
//!   the bus through `EmulHid` over a [`HidLink`] produces the same 64-byte
//!   reports, in the same order, as reaching it through the device-shaped
//!   `HidIo`. A reply framer that disagreed about continuation sequence
//!   numbers, or forgot fragmentation, would show up here and nowhere else.
//! * **What it does not prove.** Anything about `serve_once` itself. A
//!   mutation in shared code — the cancel byte `0x2D`→`0x3B`, the keepalive
//!   cadence, the expiry arm — changes **both** halves identically, so the
//!   comparison holds. This was verified, not assumed: with the pre-US-1509
//!   blackout reinstated (the OUT endpoint not read at all while a window is
//!   live), `the_emulator_and_the_shipped_loop_agree_report_for_report` and
//!   `a_long_reply_is_fragmented_the_same_way` both stayed **green**, because
//!   both sides blackout together. A comment claiming this suite "is not the
//!   emulator against itself" was exactly the kind of overclaim this repo
//!   treats as a defect.
//! * **What actually catches shared code.** The behavioural tests below, which
//!   assert *absolute answers* rather than an equality: the cross-channel
//!   GetInfo must be answered inside a window, a cancel must answer `0x2D`,
//!   an idle cancel must not latch. Under the same blackout those four are
//!   red, deterministically.
//!
//! The structural guarantee that makes this suite worth keeping at all is the
//! one thing parity *cannot* express, and it has its own check: the emulator
//! contains no second copy of the assembler, the reply framer or a consent
//! loop. That is a property of the source, not of a run — see
//! [`tests::the_emulator_carries_no_second_copy_of_the_serve_loop`].

extern crate std;

use core::future::Future;

use crate::ctap_hid::HID_REPORT_SIZE;
use crate::hid_reply::{write_reply, ReportWriter};
use crate::hid_serve::{serve_once, FidoDispatch, HidIo, HidNote, HidServe};
use crate::pending_up::PendingUp;

/// US-1524: the host-side link the emulator's HID adapter speaks to.
///
/// The smallest thing that is genuinely a *transport*: one 64-byte report in,
/// one 64-byte report out. Everything above it — fragmentation, the CTAPHID
/// command table, the consent window — is shared with the device through
/// [`HidIo`], [`crate::hid_reply`] and [`crate::hid_serve`].
///
/// `take_report` returning `Ok(0)` for an idle bus is the one place the two
/// builds' control flow necessarily differs, and it is not a policy
/// difference: a device OUT endpoint parks (that is what it is for), while the
/// emulator must return to poll its CCID socket and its accept queue. The
/// *answers* — which is what the parity tests compare — are unaffected,
/// because both shapes run the same `serve_once`.
/// The link failed: the host's socket went away.
///
/// A named type rather than `()` so a `?` at a call site says which failure it
/// is; `HidIo` itself is fixed to `Result<usize, ()>` and so
/// [`EmulHid::read_report`] collapses this back down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkDown;

pub trait HidLink {
    /// Copy the next waiting report into `report`.
    ///
    /// `Ok(0)` is "nothing waiting"; `Err(LinkDown)` is a broken link, which
    /// `HidIo::read_report` reports as a failed read (the loop backs off). A
    /// frame longer than one HID report is truncated to the report size, which
    /// is not a limitation this trait invents: a USB HID interrupt endpoint
    /// delivers 64 bytes and never more, so a longer "frame" is a malformed
    /// message either way.
    fn take_report(&mut self, report: &mut [u8; HID_REPORT_SIZE]) -> Result<usize, LinkDown>;

    /// Deliver one already-framed 64-byte report to the host.
    fn put_report(&mut self, report: &[u8; HID_REPORT_SIZE]) -> Result<(), LinkDown>;
}

/// The emulator's [`HidIo`], over a [`HidLink`]. The twin of `tasks.rs`'s
/// `DeviceHid`.
///
/// The reply path is `hid_reply::write_reply` — the same framing function, and
/// the same US-1504 whole-message deadline, that `DeviceHid` reaches through
/// `tasks.rs::send_hid_report`. The emulator used to have its own
/// `send_hid_response` (`emul_main.rs:490-525` before this story), a
/// byte-for-byte copy of `hid_reply::frame_reply`'s two branches that carried
/// none of the deadline; that copy is gone.
pub struct EmulHid<'a, L> {
    link: &'a mut L,
}

impl<'a, L: HidLink> EmulHid<'a, L> {
    pub fn new(link: &'a mut L) -> Self {
        Self { link }
    }
}

/// [`ReportWriter`] over a [`HidLink`]. The twin of `tasks.rs`'s `HidInWriter`,
/// which wraps the interrupt IN endpoint.
struct LinkWriter<'a, L>(&'a mut L);

impl<L: HidLink> ReportWriter for LinkWriter<'_, L> {
    type Error = LinkDown;

    fn write_report(
        &mut self,
        report: &[u8; HID_REPORT_SIZE],
    ) -> impl Future<Output = Result<(), LinkDown>> {
        core::future::ready(self.0.put_report(report))
    }
}

impl<L: HidLink> HidIo for EmulHid<'_, L> {
    fn read_report(
        &mut self,
        report: &mut [u8; HID_REPORT_SIZE],
    ) -> impl Future<Output = Result<usize, ()>> {
        let link: &mut L = &mut *self.link;
        async move { link.take_report(report).map_err(drop) }
    }

    fn send_frame(
        &mut self,
        channel: &[u8; 4],
        cmd: u8,
        payload: &[u8],
    ) -> impl Future<Output = bool> {
        let link: &mut L = &mut *self.link;
        async move {
            let mut writer = LinkWriter(link);
            write_reply(&mut writer, channel, cmd, payload)
                .await
                .is_sent()
        }
    }

    fn note(&mut self, note: HidNote) {
        match note {
            HidNote::ReadFailed => std::eprintln!("hid: OUT read failed"),
            HidNote::ReplyDropped => {
                std::eprintln!("hid: reply dropped (write failed or host never acked)")
            }
            HidNote::PersistFailed => std::eprintln!(
                "hid: persist failed; CTAPHID ERROR/INVALID_COMMAND (durable-before-ack)"
            ),
        }
    }

    fn note_command(&mut self, _cmd: u8, _payload_len: u16, _channel: u32) {
        // US-933: the device drains this onto the boot-time diagnostic ring.
        // The emulation binary installs no `dbg` ring, so there is nothing to
        // record it into; the call site is kept (rather than dropped from the
        // trait) so adding one later is an implementation and not a signature
        // change.
    }

    #[cfg(any(feature = "dbg-log", feature = "apdu-trace", feature = "boot-timeline"))]
    async fn debug_drain(&mut self, _cmd: u8, _channel: &[u8; 4], _payload: &[u8]) -> bool {
        // The device answers `0x42` from the RAM ring on the per-boot drain
        // channel (`tasks.rs::DeviceHid::debug_drain`). The emulation binary
        // never installs a ring, so it has nothing to answer from — the same
        // `false` the reference gives for a non-drain channel, which is why
        // `0x42` reaches the ordinary `CTAP_READ_CONFIG` arm here.
        false
    }
}

/// US-1524: **one iteration of the shared CTAP-HID serve loop**, driven from a
/// blocking host loop.
///
/// This is the whole emulator migration in one line. It used to be ~250 lines
/// of private dispatch — the assembler call, the CBOR/PING/WINK/CANCEL/vendor/
/// U2F arm chain, the keepalive decision and the consent `loop`. Now it is
/// [`crate::hid_serve::serve_once`], the same call `tasks.rs::hid_task` makes,
/// behind an executor.
///
/// The emulator constructs its [`EmulHid`] **per pass** rather than holding one
/// across the loop, because its CCID half and its HID half share the same
/// `&mut EmulationTransport` and the borrow has to end between them.
pub fn serve_pass<L: HidLink, A: FidoDispatch>(
    srv: &mut HidServe<'_>,
    link: &mut L,
    app: &mut A,
    slot: &mut PendingUp,
) {
    // Touch the `embassy-time` std driver once, before the first deadline
    // `serve_once` arms. `read_one` wraps the OUT read in
    // `with_timeout(CTAP_KEEPALIVE_PERIOD_MS, ..)` on every pass in which a
    // consent window is live; the emulator's link resolves it immediately, but
    // an armed deadline whose alarm thread had never been started is the one
    // shape that would park the emulator's main loop forever. The driver
    // initialises lazily on the first `Instant::now()`, so this is the call
    // that starts it.
    let _ = embassy_time::Instant::now();
    let mut io = EmulHid::new(link);
    block_on(serve_once(srv, &mut io, app, slot));
}

/// Drive one future to completion on this thread.
///
/// Minimal by necessity: the device gets this from the embassy executor and
/// the host has no executor dependency to reach for. It parks between polls
/// and relies on the waker, so a future that never completes parks the caller
/// — which is the honest emulation of an idle USB OUT endpoint, not a hazard:
/// every future `serve_once` arms on this path is either the emulator link's
/// immediate result or an `embassy-time` timer whose alarm thread unparks us.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    struct Parker(std::thread::Thread);

    impl std::task::Wake for Parker {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.0.unpark();
        }
    }

    let mut fut = core::pin::pin!(fut);
    let waker = std::task::Waker::from(std::sync::Arc::new(Parker(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    loop {
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::park_timeout(std::time::Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration as StdDuration, Instant as StdInstant};

    use fapico2_fido::CTAP2_MAX_MSG;
    use fapico2_platform::dispatch::MAX_RESPONSE;
    use heapless::Vec as HeaplessVec;

    use crate::ctap_hid::{
        CTAP2_ERR_KEEPALIVE_CANCEL, CTAP_HID_CANCEL, CTAP_HID_CBOR, CTAP_HID_INIT,
        CTAP_HID_KEEPALIVE,
    };

    /// The CTAPHID broadcast channel, as `fido2` sends it.
    const BROADCAST: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

    /// One virtual tick of the drive, in milliseconds.
    ///
    /// The clock these tests run on is **injected and stepped by hand**
    /// ([`VIRTUAL_NOW_MS`]), never read off the wall clock. That is what makes
    /// a drive reproducible: `keepalive_due` is a function of elapsed time,
    /// so a wall-clock drive emits a *scheduling-dependent* number of `0x02`
    /// keepalives, and two independently-timed wires compared byte for byte
    /// are a coin flip once the rates differ at all.
    const STEP_MS: u64 = 50;

    /// How long [`release_window`] drives passes before giving up on a window
    /// the plan never closed. A count of passes, not a duration: the cancel is
    /// delivered synchronously, so a healthy window closes on the next pass
    /// and this bound only fires on a wedged one.
    const RELEASE_PASSES: u32 = 64;

    /// Real-time watchdog on one drive.
    ///
    /// The pass count is a property of the plan, so nothing in a healthy drive
    /// depends on the wall clock: a whole drive is microseconds (all six tests,
    /// well under a millisecond). That makes a *generous* real-time ceiling
    /// free — it cannot perturb a run, because no run comes near it — and it
    /// converts a pass that has become pathologically slow into a named failure
    /// in seconds.
    ///
    /// What it does **not** catch: a pass that never *returns*. The drive can
    /// only reach this check between passes, so a future that parks forever
    /// still hangs. That exposure is not new — the old `while
    /// start.elapsed() < budget` loop could not reach its budget check either,
    /// so the wall-clock ceiling this replaces never bounded that case
    /// either. Catching it properly would mean bounding the production
    /// `block_on`, which is a behaviour change and out of scope here.
    const WATCHDOG: StdDuration = StdDuration::from_secs(20);

    // The injected clock, as a plain `fn() -> u64` because that is what
    // `HidServe::new` and `presence::init` take. (A `//` comment, not `///`:
    // the latter would attach to the `thread_local!` invocation and warn.)
    //
    // Thread-local, not a `static`: `cargo test` runs a crate's tests in
    // parallel threads, and two drives must never share one timeline. Each
    // drive resets it before its first pass, so it starts from a known origin
    // however the thread was reused.
    thread_local! {
        static VIRTUAL_NOW_MS: Cell<u64> = const { Cell::new(0) };
    }

    fn virtual_now_ms() -> u64 {
        VIRTUAL_NOW_MS.with(|c| c.get())
    }

    /// Set the injected clock to `ms`.
    fn set_clock(ms: u64) {
        VIRTUAL_NOW_MS.with(|c| c.set(ms));
    }

    fn reset_clock() {
        set_clock(0);
    }

    /// Virtual milliseconds a scripted offset names.
    fn ms_of(d: StdDuration) -> u64 {
        d.as_millis() as u64
    }

    // ── the two transports ────────────────────────────────────────────────

    /// What the host actually saw: the raw 64-byte reports, in order.
    ///
    /// Reports, not messages. A second reply framer that disagreed about
    /// continuation sequence numbers, or forgot fragmentation entirely, would
    /// still produce the right message bytes, and is caught only here.
    type Wire = Vec<[u8; HID_REPORT_SIZE]>;

    /// A [`HidLink`] standing in for `EmulationTransport`: a script inbound, a
    /// recorded outbound.
    struct FakeLink {
        inbound: Arc<Mutex<VecDeque<[u8; HID_REPORT_SIZE]>>>,
        sent: Wire,
    }

    impl HidLink for FakeLink {
        fn take_report(
            &mut self,
            report: &mut [u8; HID_REPORT_SIZE],
        ) -> Result<usize, LinkDown> {
            match self.inbound.lock().unwrap().pop_front() {
                Some(frame) => {
                    report.copy_from_slice(&frame);
                    Ok(HID_REPORT_SIZE)
                }
                None => Ok(0),
            }
        }

        fn put_report(&mut self, report: &[u8; HID_REPORT_SIZE]) -> Result<(), LinkDown> {
            self.sent.push(*report);
            Ok(())
        }
    }

    /// The device-shaped half of the comparison: the same [`HidServe`] and the
    /// same [`crate::hid_serve::serve_once`], reached directly rather than
    /// through a [`HidLink`].
    ///
    /// It exists to compare the two **transports**, and the comparison is worth
    /// exactly that much. Both sides run `serve_once` — that is the migration —
    /// so this detects a divergence *between* `EmulHid`/`HidLink` and a direct
    /// writer: a second reply framer that disagreed about fragmentation or
    /// continuation sequence numbers would show up here. It cannot detect a
    /// defect in `serve_once` itself, because both halves would carry it. See
    /// the module docs for the measurements behind that statement, and for the
    /// behavioural tests that do cover shared code.
    struct DeviceIo {
        inbound: Arc<Mutex<VecDeque<[u8; HID_REPORT_SIZE]>>>,
        sent: Wire,
    }

    impl HidIo for DeviceIo {
        fn read_report(
            &mut self,
            report: &mut [u8; HID_REPORT_SIZE],
        ) -> impl Future<Output = Result<usize, ()>> {
            let next = self.inbound.lock().unwrap().pop_front();
            async move {
                match next {
                    Some(frame) => {
                        report.copy_from_slice(&frame);
                        Ok(HID_REPORT_SIZE)
                    }
                    // An idle USB OUT endpoint parks. This drive gives up on
                    // its budget instead, exactly as `hid_serve`'s own harness
                    // does with `DRIVE_IDLE_PARK`.
                    None => Ok(0),
                }
            }
        }

        fn send_frame(
            &mut self,
            channel: &[u8; 4],
            cmd: u8,
            payload: &[u8],
        ) -> impl Future<Output = bool> {
            let mut writer = BusWriter {
                sent: &mut self.sent,
            };
            let channel = *channel;
            async move {
                // The device's reply path, verbatim: `tasks.rs::send_hid_report`
                // is `hid_reply::write_reply` with an endpoint writer.
                write_reply(&mut writer, &channel, cmd, payload)
                    .await
                    .is_sent()
            }
        }

        fn note(&mut self, _note: HidNote) {}
        fn note_command(&mut self, _cmd: u8, _payload_len: u16, _channel: u32) {}
    }

    struct BusWriter<'a> {
        sent: &'a mut Wire,
    }

    impl ReportWriter for BusWriter<'_> {
        type Error = ();
        fn write_report(
            &mut self,
            report: &[u8; HID_REPORT_SIZE],
        ) -> impl Future<Output = Result<(), ()>> {
            self.sent.push(*report);
            core::future::ready(Ok(()))
        }
    }

    // ── the app ───────────────────────────────────────────────────────────

    /// A scripted [`FidoDispatch`]: every user-presence command refuses until
    /// `grant` is set, and every answer is a distinct byte pattern so a test
    /// can tell the answers apart without parsing CBOR.
    ///
    /// The same type drives both halves of every parity test. That is
    /// deliberate — the app is **not** what differed between the emulator and
    /// the board; the loop, the assembler and the consent window were.
    /// Holding the app fixed is what makes the byte comparison about those.
    struct ScriptedApp {
        grant: Arc<AtomicBool>,
    }

    impl FidoDispatch for ScriptedApp {
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
            out.clear();
            match ctap_cmd {
                // authenticatorMakeCredential / authenticatorGetAssertion.
                0x01 | 0x02 => {
                    if self.grant.load(Ordering::SeqCst) {
                        out.extend_from_slice(&[0xAA, ctap_cmd]).ok();
                        2
                    } else {
                        out.extend_from_slice(&[
                            fapico2_fido::ctap2::Ctap2Response::UpRequired.code(),
                        ])
                        .ok();
                        1
                    }
                }
                // authenticatorGetInfo — the cross-channel probe.
                0x04 => {
                    out.extend_from_slice(&[0xBB]).ok();
                    1
                }
                // A largeBlob-shaped answer, long enough to force CTAP-HID
                // fragmentation so the emulator's reply path is compared
                // against `hid_reply`'s continuation sequence too.
                0x0C => {
                    for i in 0..200u32 {
                        out.extend_from_slice(&[(i % 251) as u8]).ok();
                    }
                    200
                }
                other => {
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
            } else {
                out.extend_from_slice(&[0x69, 0x85]).ok();
            }
            2
        }

        fn persist(&mut self) -> bool {
            true
        }
    }

    // ── host-side helpers ─────────────────────────────────────────────────

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
            let end = (offset + crate::ctap_hid::HID_CONT_PAYLOAD).min(payload.len());
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

    fn cbor_frame(channel: [u8; 4], body: &[u8]) -> Vec<[u8; HID_REPORT_SIZE]> {
        frame(channel, CTAP_HID_CBOR, body)
    }

    // ── the two drives ────────────────────────────────────────────────────

    /// One batch of host frames, delivered on the pass whose virtual clock has
    /// reached `at`.
    ///
    /// `at` is virtual, not wall-clock: the drive advances [`VIRTUAL_NOW_MS`]
    /// by [`STEP_MS`] per pass, so `at` names a pass index and the same plan
    /// delivers the same frames on the same pass on every run and on every
    /// machine.
    #[derive(Clone)]
    struct Exchange {
        at: StdDuration,
        frames: Vec<[u8; HID_REPORT_SIZE]>,
    }

    /// A scripted exchange: `frames` land at their offsets, and the touch is
    /// granted at `grant_at` (never, when it is zero and `grant` starts
    /// `false` — a window left open to be closed by its deadline or by a
    /// cancel).
    struct Plan {
        script: Vec<Exchange>,
        /// Whether the touch is already granted when the drive starts.
        granted_at_start: bool,
        /// When it becomes granted mid-drive (`None` = never).
        grant_at: Option<StdDuration>,
    }

    impl Plan {
        fn new(script: Vec<Exchange>) -> Self {
            Self {
                script,
                granted_at_start: true,
                grant_at: None,
            }
        }

        /// Never grant: the consent window stays open for the whole drive.
        fn ungranted(mut self) -> Self {
            self.granted_at_start = false;
            self
        }

        /// Grant the touch `at` into the drive, the way a button press lands
        /// while a window is open.
        fn grant_at(mut self, at: StdDuration) -> Self {
            self.granted_at_start = false;
            self.grant_at = Some(at);
            self
        }

        /// How many passes the drive must run: past the last scripted event,
        /// plus enough slack for a bounded OUT read
        /// (`CTAP_KEEPALIVE_PERIOD_MS`) and a pass or two to deliver the
        /// answer.
        ///
        /// A **count of passes**, not a wall-clock duration. The old budget was
        /// `StdDuration` compared against `start.elapsed()`, so the number of
        /// passes — and therefore the number of keepalives each wire carried —
        /// depended on how the OS happened to schedule the two drives. That is
        /// what made this suite nondeterministic: under a mutating build the
        /// same script reported 2 red / 0 red / 1 red / 0 red / 0 red across
        /// five runs. A pass count is a property of the plan, so it is the
        /// same every time.
        fn passes(&self) -> u32 {
            let last = self
                .script
                .iter()
                .map(|e| e.at)
                .chain(self.grant_at)
                .max()
                .unwrap_or(StdDuration::ZERO);
            let slack_ms = crate::presence::CTAP_KEEPALIVE_PERIOD_MS * 4 + 200;
            // Round UP to the next whole tick so a scripted offset that is not
            // a multiple of STEP_MS still lands inside the drive.
            let total_ms = ms_of(last) + slack_ms;
            u32::try_from(total_ms.div_ceil(STEP_MS) + 1).expect("plan horizon fits in u32")
        }
    }

    /// Deliver one batch of host frames into the shared inbound queue.
    fn deliver(
        inbound: &Arc<Mutex<VecDeque<[u8; HID_REPORT_SIZE]>>>,
        frames: &[[u8; HID_REPORT_SIZE]],
    ) {
        inbound.lock().unwrap().extend(frames.iter().copied());
    }

    /// Everything a plan schedules at or before virtual `now_ms`, handed over
    /// in one place so both drives and [`release_window`] apply the plan
    /// identically.
    ///
    /// Deterministic by construction: no thread, no sleep, no race with the
    /// serve loop. The injector used to be a background thread that woke at
    /// wall-clock offsets, so *when* a frame arrived relative to a pass was up
    /// to the scheduler — the root of the nondeterminism.
    fn pump(
        plan: &Plan,
        now_ms: u64,
        inbound: &Arc<Mutex<VecDeque<[u8; HID_REPORT_SIZE]>>>,
        grant: &Arc<AtomicBool>,
        delivered: &mut usize,
    ) {
        for e in plan.script.iter().skip(*delivered) {
            if ms_of(e.at) > now_ms {
                break;
            }
            deliver(inbound, &e.frames);
            *delivered += 1;
        }
        if let Some(at) = plan.grant_at {
            if ms_of(at) <= now_ms {
                grant.store(true, Ordering::SeqCst);
            }
        }
    }

    /// Drive the **emulator's** pass: `emul_hid::serve_pass` over `EmulHid`
    /// over a `HidLink`. This is the shipped emulator call site, the one
    /// `emul_main.rs::serve_loop` calls on every iteration of its main loop.
    fn drive_emulator(plan: &Plan) -> Wire {
        let inbound = Arc::new(Mutex::new(VecDeque::new()));
        // A fresh flag per drive: `both()` runs the two sides back to back on
        // one Plan, and a shared flag would leave the second drive starting
        // with the first one's press already granted — which silently turns
        // the consent-window case into the granted one and makes the
        // comparison pass for the wrong reason.
        let grant = Arc::new(AtomicBool::new(plan.granted_at_start));
        let mut link = FakeLink {
            inbound: inbound.clone(),
            sent: Vec::new(),
        };
        let mut app = ScriptedApp { grant: grant.clone() };
        let mut out = HeaplessVec::<u8, CTAP2_MAX_MSG>::new();
        let mut srv = HidServe::new(virtual_now_ms, &mut out);
        drive_plan(plan, &inbound, &grant, &mut |slot| {
            serve_pass(&mut srv, &mut link, &mut app, slot);
        });
        link.sent
    }

    /// Drive the **shipped** loop (`hid_serve::serve_once`) through the
    /// device-shaped adapter.
    fn drive_device(plan: &Plan) -> Wire {
        let inbound = Arc::new(Mutex::new(VecDeque::new()));
        let grant = Arc::new(AtomicBool::new(plan.granted_at_start));
        let mut io = DeviceIo {
            inbound: inbound.clone(),
            sent: Vec::new(),
        };
        let mut app = ScriptedApp { grant: grant.clone() };
        let mut out = HeaplessVec::<u8, CTAP2_MAX_MSG>::new();
        let mut srv = HidServe::new(virtual_now_ms, &mut out);
        drive_plan(plan, &inbound, &grant, &mut |slot| {
            block_on(serve_once(&mut srv, &mut io, &mut app, slot));
        });
        io.sent
    }

    /// Run one plan to completion on the injected clock: `passes()` passes of
    /// [`STEP_MS`] each, handing the script's frames over on the pass whose
    /// virtual clock reaches them, then releasing any window the plan left
    /// parked.
    ///
    /// This is the whole determinism argument for the parity suite. The drive
    /// used to be `while start.elapsed() < plan.budget()` against a wall
    /// clock, with a background thread delivering frames at wall-clock
    /// offsets: how many passes ran — and therefore how many `0x02` keepalives
    /// each wire carried — was a function of the scheduler. Two independently
    /// timed wires compared byte for byte are then a coin flip, which is how
    /// one script reported 2 red / 0 / 1 / 0 / 0 across five runs. Now the
    /// pass count and every delivery point are functions of the plan alone, so
    /// the same script produces byte-identical wires on every run.
    fn drive_plan<F>(
        plan: &Plan,
        inbound: &Arc<Mutex<VecDeque<[u8; HID_REPORT_SIZE]>>>,
        grant: &Arc<AtomicBool>,
        pass: &mut F,
    ) where
        F: FnMut(&mut PendingUp),
    {
        // A fresh origin: the two drives of one `both()` share this thread, and
        // a leftover value from the first would open the second mid-drive.
        reset_clock();
        let mut slot = PendingUp::new();
        let mut delivered = 0usize;
        let started = StdInstant::now();
        for i in 0..plan.passes() {
            let now = i as u64 * STEP_MS;
            set_clock(now);
            pump(plan, now, inbound, grant, &mut delivered);
            pass(&mut slot);
            assert!(
                started.elapsed() < WATCHDOG,
                "pass {i} of {} is still running after {WATCHDOG:?} of real time. \
                 A healthy pass completes in microseconds, so this is not load.",
                plan.passes()
            );
        }
        release_window(inbound, pass, &mut slot);
    }

    /// Both sides of one exchange, run back to back on the same script.
    fn both(plan: &Plan) -> (Wire, Wire) {
        (drive_emulator(plan), drive_device(plan))
    }

    /// Lowercase hex, so a failing assertion prints the channel the way a
    /// wire capture would.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A report's declared payload, and nothing else. The bytes after it are
    /// the report's zero padding, so a test that compares them is comparing
    /// the padding.
    fn payload_of(r: &[u8; HID_REPORT_SIZE]) -> Vec<u8> {
        let n = usize::from(u16::from_be_bytes([r[5], r[6]]));
        r[7..7 + n].to_vec()
    }

    fn describe(wire: &Wire) -> String {
        wire.iter()
            .map(|r| {
                let n = usize::from(u16::from_be_bytes([r[5], r[6]]));
                format!(
                    "[{} cmd={:02x} len={n} first={:02x?}]",
                    hex(&r[..4]),
                    r[4],
                    &r[7..8.min(7 + n)]
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    // ── the parity tests ──────────────────────────────────────────────────

    /// US-1524: the emulator and the shipped loop put **the same bytes on the
    /// wire, in the same order**, for every command this epic touches — a
    /// granted MakeCredential, a consent window with a cross-channel request
    /// inside it, a `CTAPHID_CANCEL` with nothing pending, a `CTAPHID_CANCEL`
    /// landing inside a window, and a fragmented reply.
    ///
    /// This is the epic's acceptance criterion as an assertion, and it is a
    /// byte comparison rather than a summary because every one of the four
    /// divergences this story removes changed bytes, not only control flow.
    #[test]
    fn the_emulator_and_the_shipped_loop_agree_report_for_report() {
        let _guard = presence_lock();

        // (1) A granted MakeCredential: one CBOR answer and no keepalive. The
        // pre-US-1506 unconditional pre-dispatch `0x02` would appear here.
        let plan = Plan::new(vec![Exchange {
            at: StdDuration::ZERO,
            frames: cbor_frame([0, 0, 0, 9], &[0x01, 0xAA]),
        }]);
        let (emu, dev) = both(&plan);
        assert_eq!(
            emu, dev,
            "granted makeCredential diverged: {}",
            describe(&emu)
        );
        assert!(
            !emu.iter().any(|r| r[4] == CTAP_HID_KEEPALIVE | 0x80),
            "a command that never opened a window must emit no keepalive"
        );

        // (2) A consent window on one channel, with a cross-channel GetInfo
        // inside it. The window is granted afterwards so it closes normally.
        let plan = Plan::new(vec![
            Exchange {
                at: StdDuration::ZERO,
                frames: cbor_frame([0, 0, 0, 9], &[0x01, 0x01]),
            },
            Exchange {
                at: StdDuration::from_millis(60),
                frames: cbor_frame([0, 0, 0, 21], &[0x04]),
            },
        ])
        .grant_at(StdDuration::from_millis(140));
        let (emu, dev) = both(&plan);
        assert_eq!(emu, dev, "consent-window exchange diverged: {}", describe(&emu));

        // (3) A `CTAPHID_CANCEL` landing inside a window.
        let plan = Plan::new(vec![
            Exchange {
                at: StdDuration::ZERO,
                frames: cbor_frame([0, 0, 0, 9], &[0x01, 0x01]),
            },
            Exchange {
                at: StdDuration::from_millis(80),
                frames: frame([0, 0, 0, 9], CTAP_HID_CANCEL, &[]),
            },
        ])
        .ungranted();
        let (emu, dev) = both(&plan);
        assert_eq!(
            emu, dev,
            "cancel-inside-a-window diverged: {}",
            describe(&emu)
        );

        // (4) A reply that does not fit one HID report.
        let plan = Plan::new(vec![Exchange {
            at: StdDuration::ZERO,
            frames: cbor_frame([0, 0, 0, 9], &[0x0C]),
        }]);
        let (emu, dev) = both(&plan);
        assert_eq!(emu, dev, "fragmented reply diverged: {}", describe(&emu));
    }

    /// The consent-window case on its own, because it is the one the epic is
    /// about: with a window open on one channel, a request on **another**
    /// channel is answered inside the window.
    ///
    /// This is the assertion US-1501 could not have been given before. The
    /// emulator's old consent `loop` held the serve loop for the whole window,
    /// so the second request was never read: the emulator side of the
    /// comparison in the test above produced only the opening keepalive, and
    /// this one found no GetInfo answer at all.
    #[test]
    fn a_cross_channel_request_is_answered_inside_a_window() {
        let _guard = presence_lock();

        let a = [0u8, 0, 0, 9];
        let b = [0u8, 0, 0, 21];
        let plan = Plan::new(vec![
            Exchange {
                at: StdDuration::ZERO,
                frames: cbor_frame(a, &[0x01, 0x01]),
            },
            Exchange {
                at: StdDuration::from_millis(60),
                frames: cbor_frame(b, &[0x04]),
            },
        ])
        .grant_at(StdDuration::from_millis(140));

        let wire = drive_emulator(&plan);
        let answer: Option<Vec<u8>> = wire
            .iter()
            .find(|r| r[..4] == b && r[4] == CTAP_HID_CBOR | 0x80)
            .map(|r| payload_of(r));
        assert_eq!(
            answer,
            Some(vec![0xBB]),
            "the cross-channel GetInfo must be answered while the window on the \
             other channel is open; wire was {}",
            describe(&wire)
        );
        assert!(
            wire.iter()
                .any(|r| r[..4] == a && r[4] == CTAP_HID_KEEPALIVE | 0x80),
            "the window on {a:?} must have announced itself; wire was {}",
            describe(&wire)
        );
    }

    /// US-1505 on the migrated path: a `CTAPHID_CANCEL` with nothing in flight
    /// is neither an error **nor** a latch that cancels the next window.
    ///
    /// The emulator's pre-migration dispatcher implemented CANCEL as a boolean
    /// latch its consent loop polled (`EMUL_CANCEL_PENDING`, `emul_main.rs:285`
    /// before this story), so a cancel sent against an idle device cancelled
    /// whatever window opened *next* — a cross-request defect no host hits
    /// deliberately, and one the shipped dispatcher cannot have.
    #[test]
    fn a_cancel_with_nothing_pending_is_dropped_and_cannot_cancel_the_next_window() {
        let _guard = presence_lock();

        let a = [0u8, 0, 0, 9];
        let plan = Plan::new(vec![
            // The cancel arrives first, against an idle channel.
            Exchange {
                at: StdDuration::ZERO,
                frames: frame(a, CTAP_HID_CANCEL, &[]),
            },
            Exchange {
                at: StdDuration::from_millis(80),
                frames: cbor_frame(a, &[0x01, 0x01]),
            },
        ])
        .grant_at(StdDuration::from_millis(160));

        let wire = drive_emulator(&plan);
        assert!(
            !wire.iter().any(|r| r[4] == 0x3F | 0x80),
            "a CANCEL with no transaction in flight must never answer \
             0x3F/INVALID_COMMAND; wire was {}",
            describe(&wire)
        );
        let answer = wire
            .iter()
            .find(|r| r[..4] == a && r[4] == CTAP_HID_CBOR | 0x80)
            .map(|r| r[7]);
        assert_ne!(
            answer,
            Some(CTAP2_ERR_KEEPALIVE_CANCEL),
            "the cancel must not survive to cancel the NEXT window — that is the \
             emulator's old EMUL_CANCEL_PENDING latch; wire was {}",
            describe(&wire)
        );
        assert_eq!(
            answer,
            // The scripted app's granted-answer marker (`0xAA`, opcode).
            Some(0xAA),
            "the granted makeCredential must be answered by its own grant; wire \
             was {}",
            describe(&wire)
        );
    }

    /// A `CTAPHID_CANCEL` landing inside a window answers `0x2D`
    /// (`CTAP2_ERR_KEEPALIVE_CANCEL`) on the cancelled command's channel — the
    /// US-1505 acceptance, re-asserted against the emulator now that its
    /// dispatcher *is* the shipped one.
    #[test]
    fn a_cancel_inside_a_window_answers_keepalive_cancel() {
        let _guard = presence_lock();

        let a = [0u8, 0, 0, 9];
        let plan = Plan::new(vec![
            Exchange {
                at: StdDuration::ZERO,
                frames: cbor_frame(a, &[0x01, 0x01]),
            },
            Exchange {
                at: StdDuration::from_millis(80),
                frames: frame(a, CTAP_HID_CANCEL, &[]),
            },
        ])
        .ungranted();

        let wire = drive_emulator(&plan);
        let answer = wire
            .iter()
            .find(|r| r[..4] == a && r[4] == CTAP_HID_CBOR | 0x80)
            .map(|r| r[7]);
        assert_eq!(
            answer,
            Some(CTAP2_ERR_KEEPALIVE_CANCEL),
            "a cancelled CTAP2 window answers 0x2D, not the 0x3B it was refusing \
             with; wire was {}",
            describe(&wire)
        );
    }

    /// A reply longer than one HID report must be fragmented identically. The
    /// emulator's own framer (`send_hid_response`) used to be a copy of
    /// `hid_reply::frame_reply`; this is the assertion that keeps it a call.
    #[test]
    fn a_long_reply_is_fragmented_the_same_way() {
        let _guard = presence_lock();

        let a = [0u8, 0, 0, 9];
        let plan = Plan::new(vec![Exchange {
            at: StdDuration::ZERO,
            frames: cbor_frame(a, &[0x0C]),
        }]);
        let (emu, dev) = both(&plan);
        assert_eq!(emu, dev, "fragmented reply diverged: {}", describe(&emu));

        let conts: Vec<&[u8; HID_REPORT_SIZE]> = emu
            .iter()
            .filter(|r| r[..4] == a && r[4] < 0x80)
            .collect();
        assert_eq!(
            conts.len(),
            3,
            "a 200-byte reply is 1 INIT (57) + 3 continuations (59 each) = 234 \
             >= 200; wire was {}",
            describe(&emu)
        );
        for (i, r) in conts.iter().enumerate() {
            assert_eq!(r[4], i as u8, "continuation {i}: rolling sequence number");
        }
    }

    /// US-1511, on the epic's DoD item 6: the **whole** consent-window
    /// scenario — a window open on one channel, an `INIT` on the broadcast
    /// channel, a `getInfo` on a second channel, and a latched press — puts
    /// the same 64-byte reports on the wire, in the same order, from the
    /// emulator's `serve_pass` and from the shipped `serve_once` reached
    /// through a device-shaped adapter. The cancel case is the same
    /// comparison with a `CTAPHID_CANCEL` in place of the press.
    ///
    /// The four-way comparison above already covers a window with a
    /// cross-channel request inside it; this one is the *story* rather than
    /// a smoke test of the pieces, and it adds the broadcast `INIT` — the
    /// frame a host sends before it has a channel, and the one that was
    /// stranded in the endpoint buffer through the whole pre-US-1509
    /// blackout.
    ///
    /// The answers are asserted as well as the equality. Equality alone would
    /// be satisfied by both sides being wrong in the same way, and "the
    /// broadcast INIT is answered in a full 17-byte reply echoing the nonce"
    /// is a claim about the answer, not about the two wires matching.
    #[test]
    fn us1511_the_window_scenario_is_identical_on_both_paths() {
        let _guard = presence_lock();

        let a = [0u8, 0, 0, 9];
        let b = [0u8, 0, 0, 0x21];
        let nonce = [0xA1u8, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8];

        // (1) A window opens on `a`; an INIT lands on the broadcast channel
        // and a getInfo on `b`, both while it is open; then a latched press
        // completes the parked command on `a`.
        let plan = Plan::new(vec![
            Exchange {
                at: StdDuration::ZERO,
                frames: cbor_frame(a, &[0x01, 0x01]),
            },
            Exchange {
                at: StdDuration::from_millis(120),
                frames: frame(BROADCAST, CTAP_HID_INIT, &nonce),
            },
            Exchange {
                at: StdDuration::from_millis(180),
                frames: cbor_frame(b, &[0x04]),
            },
        ])
        .grant_at(StdDuration::from_millis(420));
        let (emu, dev) = both(&plan);
        assert_eq!(
            emu, dev,
            "the grant-side window scenario diverged: {}",
            describe(&dev)
        );

        // The three answers, on the device wire; the emulator wire is the same
        // bytes by the assertion above.
        let init_answer: Vec<u8> = dev
            .iter()
            .find(|r| r[..4] == BROADCAST && r[4] == CTAP_HID_INIT | 0x80)
            .map(|r| payload_of(r))
            .unwrap_or_else(|| {
                panic!("the broadcast INIT was not answered; wire was {}", describe(&dev))
            });
        assert_eq!(
            init_answer.len(),
            17,
            "a full INIT reply is nonce(8)+cid(4)+4 version bytes+capFlags(1)"
        );
        assert_eq!(&init_answer[..8], &nonce, "the INIT reply echoes the request nonce");
        assert_eq!(
            dev.iter()
                .find(|r| r[..4] == b && r[4] == CTAP_HID_CBOR | 0x80)
                .map(|r| payload_of(r)),
            Some(vec![0xBB]),
            "the cross-channel getInfo must be answered on its own channel"
        );
        assert_eq!(
            dev.iter()
                .find(|r| r[..4] == a && r[4] == CTAP_HID_CBOR | 0x80)
                .map(|r| payload_of(r)),
            Some(vec![0xAA, 0x01]),
            "the latched press completes the parked command on the parked \
             command's channel"
        );
        // And the window announced itself, so the scenario really did open one
        // rather than passing because nothing was ever owed.
        assert!(
            dev.iter()
                .any(|r| r[..4] == a && r[4] == CTAP_HID_KEEPALIVE | 0x80),
            "the window on {a:?} must have announced itself; wire was {}",
            describe(&dev)
        );

        // (2) The same opening, closed by a CANCEL instead of a press.
        let plan = Plan::new(vec![
            Exchange {
                at: StdDuration::ZERO,
                frames: cbor_frame(a, &[0x01, 0x01]),
            },
            Exchange {
                at: StdDuration::from_millis(120),
                frames: frame(a, CTAP_HID_CANCEL, &[]),
            },
        ])
        .ungranted();
        let (emu, dev) = both(&plan);
        assert_eq!(emu, dev, "the cancel-side window scenario diverged: {}", describe(&dev));
        assert_eq!(
            dev.iter()
                .find(|r| r[..4] == a && r[4] == CTAP_HID_CBOR | 0x80)
                .map(|r| r[7]),
            Some(CTAP2_ERR_KEEPALIVE_CANCEL),
            "a cancelled CTAP2 window answers 0x2D; wire was {}",
            describe(&dev)
        );
    }

    // ── the structural check: no second copy ─────────────────────────────

    /// Strip comments, so the scan below reads code rather than prose.
    ///
    /// These files are full of prose *about* the symbols the scan forbids —
    /// the module docs name `HidAssembler`, `HidFeed` and `send_hid_response`
    /// precisely to say they are gone. Scanning the raw text would make the
    /// check permanently red; scanning the code is what the claim is about.
    fn code_only(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        for line in src.lines() {
            let cut = line.find("//").unwrap_or(line.len());
            out.push_str(&line[..cut]);
            out.push('\n');
        }
        out
    }

    /// US-1524's actual guarantee, as an assertion: the emulator carries **one**
    /// copy of the CTAPHID serve loop, not two.
    ///
    /// The parity tests above cannot express this. Both their halves call
    /// [`crate::hid_serve::serve_once`], so a fork — a second assembler, a
    /// second reply framer, a second consent loop living in the emulator —
    /// would *keep them green*: the two sides would still agree, just about
    /// the wrong implementation. That is the whole reason US-1524 existed (the
    /// emulator's private copy of the blackout), and the parity comparison
    /// would not notice its return.
    ///
    /// This check does. It scans the emulator **binary** (`emul_main.rs` — the
    /// file that actually carried the fork) for the symbols a second copy is
    /// built from, with comments stripped so the prose documenting their
    /// absence is not mistaken for their presence. `emul_hid.rs` is not
    /// scanned because this very test names the symbols; `emul_hid` is the
    /// shared seam itself, and its thinness is asserted by the compiler-level
    /// wiring test in `emul_main.rs`'s own `us1524_tests`.
    ///
    /// Scope, stated so the next reader does not over-read it: this pins the
    /// *types* a duplicate implementation is built from. It cannot see a
    /// consent loop written without naming any of them — that would be a
    /// hand-rolled copy of the window policy, and the honest way to catch it
    /// is a behavioural test, which is what the four above are for.
    #[test]
    fn the_emulator_carries_no_second_copy_of_the_serve_loop() {
        let name = "firmware/src/emul_main.rs";
        let code = code_only(include_str!("emul_main.rs"));
        // A second assembler, a second assembler feed, a second reply
        // framer. `HidServe` is the one type the emulator is *meant* to
        // name, so it is deliberately not on this list.
        for forbidden in ["HidAssembler", "HidFeed", "send_hid_response", "frame_reply"] {
            assert!(
                !code.contains(forbidden),
                "{name} names `{forbidden}` in executable code, so the emulator \
                 has a second copy of the CTAPHID serve loop again. US-1524 \
                 removed exactly this — a private assembler, framer and \
                 consent loop in emul_main.rs that encoded the 30 s blackout \
                 the board had already been fixed for. The parity tests will \
                 NOT catch its return, because both their halves call the \
                 shared serve_once; this check is what does."
            );
        }
    }

    // ── the shared presence runtime ────────────────────────────────────────

    /// The serve loop touches the *shared* presence runtime — one pending
    /// slot, one prompt, one process-wide instance. Every test here takes
    /// `hid_serve`'s own guard rather than a second lock of its own, so this
    /// suite and `hid_serve`'s serialise against each other rather than
    /// against nothing; see the note on [`crate::hid_serve`]'s `test_guard`
    /// for what happens when they do not.
    fn presence_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::hid_serve::tests::test_guard()
    }

    /// US-1524: close whatever window a drive left parked, **through the
    /// shipped close path** — a `CTAPHID_CANCEL` driven by more serve passes,
    /// not a hand-rolled `end_window`.
    ///
    /// A plan that never grants its touch parks a window for the full
    /// `CTAP_TOUCH_WINDOW_MS` (30 s). Without this the drive would hand the
    /// process-wide presence slot to the next test still held, and that test
    /// would fail on a `begin_window` that had nothing to do with what it was
    /// testing — the failure mode `hid_serve`'s harness documents for exactly
    /// this ("leaking the process-wide presence slot into the next nine
    /// tests").
    fn release_window<F>(
        inbound: &Arc<Mutex<VecDeque<[u8; HID_REPORT_SIZE]>>>,
        mut pass: F,
        slot: &mut PendingUp,
    ) where
        F: FnMut(&mut PendingUp),
    {
        if !slot.is_occupied() {
            return;
        }
        deliver(
            inbound,
            &frame([0u8, 0, 0, 9], CTAP_HID_CANCEL, &[]),
        );
        let base = virtual_now_ms();
        for i in 1..=RELEASE_PASSES {
            if !slot.is_occupied() {
                return;
            }
            set_clock(base + i as u64 * STEP_MS);
            pass(slot);
        }
        assert!(
            !slot.is_occupied(),
            "the parked window was never closed — the single presence slot would \
             leak into the next test"
        );
    }
}