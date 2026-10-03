//! US-1511: the consent-window story as an **end-to-end black-box** test
//! over the host seam, through the shared dispatcher.
//!
//! # What this file is, and what it deliberately is not
//!
//! The story is a property of the *whole* path — host frames in on the OUT
//! endpoint, a real window opens on one channel, a real `INIT` and a real
//! `getInfo` land on two other channels while it is open, a real `CANCEL`
//! closes it, a real latched press completes the parked command. None of
//! that is visible from inside [`PendingUp`], which is a pure value type with
//! no clock, no USB and no app, and none of it is visible from
//! `hid_serve`'s own `mod tests`, which are the unit-level seam.
//!
//! So this is a *seam* test and it is built to be as close to the outside as
//! the host allows. Four choices do the work:
//!
//! 1. **The shipped iteration, unmodified.** The driver thread runs
//!    `loop { serve_once(..).await }` — byte for byte what
//!    `tasks.rs::hid_task` runs, and what `emul_main.rs` runs through
//!    `emul_hid::serve_pass`. Nothing here reimplements the assembler, the
//!    reply framer, the command table or the consent policy.
//! 2. **The shipped reply path.** `send_frame` goes through
//!    [`crate::hid_reply::write_reply`] over a `ReportWriter`, so US-1504's
//!    write deadline and CTAPHID fragmentation are the code under test and
//!    not a copy of it.
//! 3. **A real idle OUT endpoint.** [`DeviceIo::read_report`] models an
//!    empty endpoint as a future that *never completes* — which is what
//!    `embassy_rp::usb::EndpointOut::read` does and what the board did for
//!    the whole 30 s window before US-1509. It is the load-bearing fidelity
//!    decision in the file; see "Falsifiability" below.
//! 4. **The real presence gate.** [`ScriptedApp`] does not answer
//!    `UpRequired` from a test-owned boolean. It calls
//!    [`presence::request_grant_in_window`] — the exact function `main.rs:696`
//!    installs on the board's FIDO app (`request_grant_in_window`) — against
//!    the one shared [`presence`] runtime, and the press is a real
//!    `PRESS_LATCH` edge set by [`presence::emul_inject_press`]. So "the
//!    grant was stolen by the cross-channel traffic" is a thing the test can
//!    *observe* (the real service is tag-bound and single-use), not a
//!    sentence in a doc comment.
//!
//! # Falsifiability: the trap this file is built to avoid
//!
//! A previous review of this epic found two of four Phase C tests
//! **unfalsifiable**: they stayed green with the fix reverted, because the
//! harness modelled the idle OUT endpoint as a park and then *abandoned* the
//! pass after its own idle budget. A reintroduced blocking `loop` then got
//! cut in half every budget, the loop started a new pass, and the
//! cross-channel requests the tests assert about were answered anyway — the
//! harness manufactured the very evidence it was supposed to be checking.
//!
//! So: [`poll_pass`] abandons a pass **only when no consent window is
//! live**, which is a lossless cancellation (the `HidIo::read_report`
//! contract, and the same contract `embassy-rp` satisfies). When a window
//! *is* live and the pass does not come back, the rig records a wedge and
//! the driver stops, so the test goes red with a name instead of being
//! rescued. Reintroducing the pre-US-1509 nested consent `loop` in
//! `redrive_window` turns every timing assertion below red; that is measured
//! in `.superpowers/sdd/report-us1511.md`, not assumed.
//!
//! # Why the bound is asserted against `SERVE_BOUND_MS`
//!
//! The published figure is 1750 ms — `3 x HID_REPLY_WRITE_TIMEOUT_MS +
//! CTAP_KEEPALIVE_PERIOD_MS`, re-derived by US-1506 when it deleted the
//! pre-command keepalive (it was 2100 ms, which counted a frame that is no
//! longer sent). Its derivation and the two wrong figures it was corrected
//! away from are on the constant. The tests read the constant, never a
//! literal, so a future re-derivation cannot leave the assertions behind.

use super::*;

use crate::hid_reply::{write_reply, ReportWriter};
use crate::ctap_hid::HID_CONT_PAYLOAD;
use core::future::pending;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::JoinHandle;
use std::time::{Duration as StdDuration, Instant as StdInstant};

/// Wall-clock budget for **one** host request, asserted against
/// [`SERVE_BOUND_MS`] — the constant the firmware publishes, imported through
/// `super::*`. Never a literal.
const BOUND: StdDuration = StdDuration::from_millis(SERVE_BOUND_MS);

/// How long one serve pass that **started with a window open** may take
/// before the rig treats it as a blackout.
///
/// Derived from the shipped constant rather than from a literal: a healthy
/// pass over a live window costs one bounded read
/// ([`CTAP_KEEPALIVE_PERIOD_MS`], 250 ms) plus up to three replies that this
/// host ACKs instantly, so two keepalive periods is generous even on a loaded
/// CI host — and an order of magnitude below the 30 s a reintroduced blind
/// loop runs for, so the two are not confusable.
///
/// It is deliberately **not** [`SERVE_BOUND_MS`]. Making it the published
/// bound looks tidier and is wrong: a pass that *closes* the window (a grant
/// consumed, a cancel) falls through to the OUT read, and with no window live
/// that read is correctly unbounded — so the pass parks, by design, for a
/// whole ceiling. At 1750 ms that is most of a test's own budget, and the
/// first version of this suite failed ~1 run in 5 on exactly that.
const LIVE_PASS_CEILING: StdDuration =
    StdDuration::from_millis(2 * CTAP_KEEPALIVE_PERIOD_MS);

/// The same, for a pass that started with **no** window open.
///
/// Nothing to wait for in that case: the OUT read is unbounded, so the pass
/// returns as soon as there is a report and the only reason to stop it is an
/// idle bus. One keepalive period is far more than delivering an
/// already-queued report takes, and short enough that the rig is polling the
/// wire again before a test's next step times out.
const IDLE_PASS_CEILING: StdDuration =
    StdDuration::from_millis(CTAP_KEEPALIVE_PERIOD_MS);

/// How long a test will **look** for a frame before declaring it missing.
///
/// Separate from [`BOUND`] on purpose. The bound is what the firmware
/// promises and what the assertions compare a measured latency against; this
/// is only how long the test is willing to wait before saying "nothing
/// arrived", and it is three bounds wide so that a late answer is reported as
/// a *latency* failure (with the number) rather than as an absence.
const WAIT: StdDuration = StdDuration::from_millis(3 * SERVE_BOUND_MS);

/// Slack for the harness itself: joining the driver thread after a stop is a
/// scheduling event, not a firmware one.
const JOIN_SLACK: StdDuration = StdDuration::from_millis(3_000);

/// The CTAPHID broadcast channel, as `fido2` sends it (`CTAPHID_BROADCAST_CID`).
const BROADCAST: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

/// The channel a scripted `makeCredential` opens its window on.
const CH_A: [u8; 4] = [0x00, 0x00, 0x00, 0x09];
/// A second channel — the one the story's cross-channel traffic arrives on.
const CH_B: [u8; 4] = [0x00, 0x00, 0x00, 0x21];
/// A third, for the request that proves the state is clean afterwards.
const CH_C: [u8; 4] = [0x00, 0x00, 0x00, 0x2A];
/// A fourth. Distinct from `CH_B` on purpose: a cross-channel assertion that
/// reuses a channel an earlier frame already answered on would match the
/// *stale* frame and pass without the device having done anything.
const CH_D: [u8; 4] = [0x00, 0x00, 0x00, 0x2B];

/// The scripted app's granted-answer marker: `[0xAA, opcode]`, so a
/// `makeCredential` answer is distinguishable from a `getInfo` answer
/// without parsing CBOR.
const ANSWER_UP: u8 = 0xAA;
/// The scripted app's `getInfo` answer.
const ANSWER_INFO: u8 = 0xBB;

// ── the bus ────────────────────────────────────────────────────────────────

/// A report the host observed, with the instant it crossed the wire.
type Stamped = (StdInstant, [u8; HID_REPORT_SIZE]);

#[derive(Default)]
struct Bus {
    /// Reports waiting on the OUT endpoint.
    inbound: VecDeque<[u8; HID_REPORT_SIZE]>,
    /// What the host wrote, in order, stamped at the write.
    wrote: Vec<Stamped>,
    /// What the device put on the IN endpoint, in order, stamped at the
    /// write. This is the whole of what the assertions below read.
    read: Vec<Stamped>,
}

/// The device-shaped transport.
///
/// Not a "device adapter" in the sense of a second implementation: the
/// framing, the reply deadline and the command table all come from
/// `hid_serve`/`hid_reply`. This is two endpoints' worth of plumbing and
/// nothing else.
struct DeviceIo {
    bus: Arc<Mutex<Bus>>,
}

impl HidIo for DeviceIo {
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
                // An idle interrupt OUT endpoint. It **parks**, and that is
                // the point: it is what `embassy_rp::usb::EndpointOut::read`
                // does (`src/usb.rs:574` awaits only the `available` poll), it
                // is what the board did for the whole 30 s window before
                // US-1509, and it is what makes a reintroduced blocking
                // `loop` visible here as a pass that never comes back.
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
        let bus = self.bus.clone();
        let channel = *channel;
        async move {
            // The device's reply path, verbatim: `tasks.rs::send_hid_report`
            // is this call over an endpoint writer.
            let mut w = WireWriter { bus: &bus };
            write_reply(&mut w, &channel, cmd, payload).await.is_sent()
        }
    }

    fn note(&mut self, _note: HidNote) {}

    fn note_command(&mut self, _cmd: u8, _payload_len: u16, _channel: u32) {}
}

/// The IN endpoint: records each 64-byte report with the instant it went out.
struct WireWriter<'a> {
    bus: &'a Arc<Mutex<Bus>>,
}

impl ReportWriter for WireWriter<'_> {
    type Error = ();
    fn write_report(
        &mut self,
        report: &[u8; HID_REPORT_SIZE],
    ) -> impl Future<Output = Result<(), ()>> {
        self.bus.lock().unwrap().read.push((StdInstant::now(), *report));
        core::future::ready(Ok(()))
    }
}

// ── the app ────────────────────────────────────────────────────────────────

/// The scripted [`FidoDispatch`].
///
/// Its presence gate is the real one. `main.rs:696` installs
/// `presence::request_grant_in_window` on the board's FIDO app, and that is
/// the function called here: the serve loop owns the window lifecycle
/// (`begin_window` at the park, `end_window` in `close_window`) and the app
/// only *joins* it under its own tag, which is what makes the grant
/// tag-bound, single-use, and un-stealable by a command on another channel.#[derive(Default)]
struct ScriptedApp;

impl FidoDispatch for ScriptedApp {
    fn sync_generations(&mut self) {}

    fn device_info_page(&self, _page: u8, out: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        out.extend_from_slice(&[0xDE, 0x01]).ok();
    }

    fn process_ctap2(
        &mut self,
        ctap_cmd: u8,
        _payload: &[u8],
        channel: [u8; 4],
        out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    ) -> usize {
        out.clear();
        match ctap_cmd {
            // authenticatorMakeCredential / authenticatorGetAssertion.
            0x01 | 0x02 => {
                let tag = fapico2_fido::presence_tag_from_channel(channel);
                if presence::request_grant_in_window(tag) {
                    out.extend_from_slice(&[ANSWER_UP, ctap_cmd]).ok();
                } else {
                    out.extend_from_slice(&[Ctap2Response::UpRequired.code()])
                        .ok();
                }
            }
            // authenticatorGetInfo. Never presence-gated, which is the whole
            // reason a `getInfo` is the right cross-channel probe: it can be
            // answered while a window is open, and its answer cannot be
            // confused with the parked command's.
            0x04 => {
                out.extend_from_slice(&[ANSWER_INFO]).ok();
            }
            other => {
                out.extend_from_slice(&[other]).ok();
            }
        }
        out.len()
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
        out.extend_from_slice(&[0x90, 0x00]).ok();
        2
    }

    fn persist(&mut self) -> bool {
        true
    }
}

// ── driving the shipped loop ───────────────────────────────────────────────

/// How one serve pass ended.
#[derive(Debug, PartialEq, Eq)]
enum Pass {
    /// It returned. This is the only healthy outcome.
    Ready,
    /// It did not return inside [`PASS_CEILING`]. Whether that is the
    /// blackout or a correctly-parked idle endpoint is decided by the
    /// driver, which is the only place that can read the slot (the future
    /// holds a `&mut` borrow of it).
    Ceiling,
    /// The test asked the rig to stop.
    Stop,
}

struct Parker(std::thread::Thread);

impl Wake for Parker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Poll one serve pass on this thread until it returns, the ceiling expires,
/// or the rig is asked to stop.
///
/// Deliberately **not** `run_to_completion`: a pass that parks on an idle
/// endpoint must not park the test, and the only way to end one is to drop it
/// — which the `HidIo::read_report` contract permits, because embassy-rp's
/// `EndpointOut::read` only awaits the `available` poll and the re-arm happens
/// in the synchronous tail. The safety of that drop is conditional and the
/// condition is the whole design: the caller only *accepts* a `Ceiling` after
/// checking the consent slot is **empty**, so a pass that parked with a window
/// live becomes a wedge and a red test instead of being abandoned and silently
/// retried.
fn poll_pass<F: Future<Output = ()>>(
    mut fut: core::pin::Pin<&mut F>,
    stop: &AtomicBool,
    ceiling: StdDuration,
) -> Pass {
    let waker = Waker::from(Arc::new(Parker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let start = StdInstant::now();
    loop {
        if let Poll::Ready(()) = fut.as_mut().poll(&mut cx) {
            return Pass::Ready;
        }
        if stop.load(Ordering::SeqCst) {
            return Pass::Stop;
        }
        if start.elapsed() >= ceiling {
            return Pass::Ceiling;
        }
        std::thread::park_timeout(StdDuration::from_millis(1));
    }
}

/// The host side of one drive: everything a test can see and do.
struct Rig {
    bus: Arc<Mutex<Bus>>,
    stop: Arc<AtomicBool>,
    wedged: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    /// The drive's `t=0`. Every scripted offset is relative to it, and it is
    /// what the bound is measured against.
    t0: StdInstant,
    scripters: Vec<JoinHandle<()>>,
}

impl Rig {
    /// Start a driver thread running the shipped serve loop.
    fn start() -> Rig {
        let bus = Arc::new(Mutex::new(Bus::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let wedged = Arc::new(AtomicBool::new(false));

        let join = {
            let bus = bus.clone();
            let stop = stop.clone();
            let wedged = wedged.clone();
            std::thread::spawn(move || {
                // Touch the std time driver once, before the first deadline
                // `serve_once` arms (`read_one` wraps the OUT read in
                // `with_timeout` on every pass with a window live). Same
                // reason `emul_hid::serve_pass` does it.
                let _ = embassy_time::Instant::now();
                let mut ctap_out: HeaplessVec<u8, CTAP2_MAX_MSG> = HeaplessVec::new();
                let mut srv = HidServe::new(now_ms, &mut ctap_out);
                let mut io = DeviceIo { bus: bus.clone() };
                let mut app = ScriptedApp;
                let mut slot = PendingUp::new();
                // `serve_loop` is `loop { serve_once(..).await }`
                // (`hid_serve.rs`); this is that loop and the rig's own
                // stop/wedge accounting, and nothing else.
                loop {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    // Read the slot *before* the pass, while the future
                    // does not hold it. A pass can only park on the OUT
                    // read, and a pass that starts with no window can only
                    // park with no window (a window opened mid-pass makes
                    // that read bounded), so "occupied at pass start" is a
                    // sound lower bound on the risky case.
                    let live = slot.is_occupied();
                    let ceiling = if live {
                        LIVE_PASS_CEILING
                    } else {
                        IDLE_PASS_CEILING
                    };
                    // The block exists so the future's `&mut PendingUp`
                    // borrow ends before the slot is inspected.
                    let outcome = {
                        let mut fut =
                            core::pin::pin!(serve_once(&mut srv, &mut io, &mut app, &mut slot));
                        poll_pass(fut.as_mut(), &stop, ceiling)
                    };
                    match outcome {
                        Pass::Ready => {}
                        // The pass ran out its ceiling, and it started with a
                        // window open. It is either wedged, or it closed the
                        // window and then parked on the correctly-unbounded
                        // idle read. The two are told apart by the slot, which
                        // can only be read once the pass has been dropped —
                        // and a drop is lossless in the benign case (nothing
                        // is in the endpoint buffer) while the other case
                        // stops the drive, so the drop never rescues
                        // anything.
                        Pass::Ceiling if live && slot.is_occupied() => {
                            wedged.store(true, Ordering::SeqCst);
                            break;
                        }
                        Pass::Ceiling => {}
                        Pass::Stop => break,
                    }
                }
                // The presence runtime is a process-wide singleton with one
                // pending slot. Whatever brought the drive down — a clean
                // stop, a wedge, or a test that panicked and unwound through
                // `Drop` — the window is closed here, through the **shipped**
                // close path, so no test can hand a held slot to the next one.
                // This is the failure mode `hid_serve`'s harness documents
                // ("leaking the process-wide presence slot into the next nine
                // tests"), and it is why this runs on the driver thread: the
                // `PendingUp` and the serve loop that can close it both live
                // there.
                if slot.is_occupied() {
                    bus.lock()
                        .unwrap()
                        .inbound
                        .extend(frame(CH_A, CTAP_HID_CANCEL, &[]));
                    let never = AtomicBool::new(false);
                    let deadline = StdInstant::now() + StdDuration::from_millis(2_000);
                    while slot.is_occupied() && StdInstant::now() < deadline {
                        let mut fut = core::pin::pin!(serve_once(
                            &mut srv, &mut io, &mut app, &mut slot
                        ));
                        if poll_pass(fut.as_mut(), &never, LIVE_PASS_CEILING) != Pass::Ready {
                            break;
                        }
                    }
                }
                assert!(
                    !slot.is_occupied(),
                    "the rig left a consent window parked; the shared presence slot \
                     would leak into the next test"
                );
            })
        };

        Rig {
            bus,
            stop,
            wedged,
            join: Some(join),
            t0: StdInstant::now(),
            scripters: Vec::new(),
        }
    }

    /// Deliver `frames` on the OUT endpoint `at` after the drive started.
    fn write_at(
        &mut self,
        at: StdDuration,
        frames: Vec<[u8; HID_REPORT_SIZE]>,
    ) -> &mut Rig {
        if at.is_zero() {
            {
                let mut bus = self.bus.lock().unwrap();
                for f in &frames {
                    bus.wrote.push((StdInstant::now(), *f));
                }
                bus.inbound.extend(frames);
            }
            return self;
        }
        let bus = self.bus.clone();
        let due = self.t0 + at;
        self.scripters.push(std::thread::spawn(move || {
            sleep_until(due);
            let mut bus = bus.lock().unwrap();
            for f in &frames {
                // Stamped at the *write*, not at the script's nominal offset:
                // the bound is a claim about arrival, and a loaded host can
                // make a thread late.
                bus.wrote.push((StdInstant::now(), *f));
            }
            bus.inbound.extend(frames);
        }));
        self
    }

    /// Deliver `frames` on the OUT endpoint **now**.
    ///
    /// Every step after the first wait in a test goes through this rather
    /// than `write_at`: a script with absolute offsets races the very events
    /// it is waiting for, because an assertion that returns late can find its
    /// own next input already written *and already answered*. Event-driven
    /// sequencing removes that class of flake without weakening anything — the
    /// bound is still measured from a real arrival, stamped in
    /// [`Rig::wrote_at`].
    fn write_now(&mut self, frames: Vec<[u8; HID_REPORT_SIZE]>) -> &mut Rig {
        self.write_at(StdDuration::ZERO, frames)
    }

    /// Latch one press edge `at` after the drive started — a BOOTSEL
    /// press on the board, `presence::emul_inject_press` on the host.
    fn press_at(&mut self, at: StdDuration) -> &mut Rig {
        let due = self.t0 + at;
        self.scripters.push(std::thread::spawn(move || {
            sleep_until(due);
            presence::emul_inject_press();
        }));
        self
    }

    /// Latch one press edge now.
    fn press_now(&mut self) -> &mut Rig {
        presence::emul_inject_press();
        self
    }

    fn wire(&self) -> Vec<Stamped> {
        self.bus.lock().unwrap().read.clone()
    }

    /// When the host wrote the first report matching `pred`, if it has.
    fn wrote_at<F: Fn(&[u8; HID_REPORT_SIZE]) -> bool>(&self, pred: F) -> Option<StdInstant> {
        self.bus
            .lock()
            .unwrap()
            .wrote
            .iter()
            .find(|(_, r)| pred(r))
            .map(|(at, _)| *at)
    }

    /// The whole wire, one line per report — what a capture would show.
    fn describe(&self) -> String {
        self.wire()
            .iter()
            .map(|(at, r)| {
                let n = usize::from(u16::from_be_bytes([r[5], r[6]]));
                format!(
                    "[+{:>4}ms {:02x?} cmd={:02x} len={n} first={:02x?}]",
                    at.saturating_duration_since(self.t0).as_millis(),
                    &r[..4],
                    r[4],
                    &r[7..8.min(7 + n)]
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The first message the device sent on `channel` with `cmd` (the
    /// *unmasked* command byte, i.e. the frame byte with its `0x80` type bit
    /// cleared), with the instant it went out.
    fn first_on(&self, channel: [u8; 4], cmd: u8) -> Option<(StdInstant, Vec<u8>)> {
        self.wire()
            .into_iter()
            .find(|(_, r)| r[..4] == channel && r[4] == cmd | 0x80)
            .map(|(at, r)| (at, payload_of(&r)))
    }

    /// Every `(cmd, payload)` the device sent on `channel`, in order.
    fn frames_on(&self, channel: [u8; 4]) -> Vec<(u8, Vec<u8>)> {
        self.wire()
            .into_iter()
            .filter(|(_, r)| r[..4] == channel)
            .map(|(_, r)| (r[4] & 0x7F, payload_of(&r)))
            .collect()
    }

    /// Wait for the device to send `cmd` on `channel`, at most `budget`
    /// after `deadline`'s start. `None` means it never arrived.
    fn await_on(
        &self,
        channel: [u8; 4],
        cmd: u8,
        budget: StdDuration,
    ) -> Option<(StdInstant, Vec<u8>)> {
        let deadline = StdInstant::now() + budget;
        loop {
            if let Some(hit) = self.first_on(channel, cmd) {
                return Some(hit);
            }
            assert!(
                !self.wedged.load(Ordering::SeqCst),
                "the serve loop never came back from a pass with a consent \
                 window open — the US-1501 blackout, reintroduced. A live window \
                 is re-asserted and its command re-driven per pass; it is never \
                 awaited."
            );
            if StdInstant::now() >= deadline {
                return None;
            }
            std::thread::sleep(StdDuration::from_millis(2));
        }
    }

    /// The shared blackout assertion: no pass ever failed to return with a
    /// window live. Same meaning as `hid_serve`'s own
    /// `assert_the_window_is_live_and_unblocked`, read from the outside.
    #[track_caller]
    fn assert_unblocked(&self) {
        assert!(
            !self.wedged.load(Ordering::SeqCst),
            "a serve pass could not return while a consent window was open"
        );
    }

    /// Stop the driver and join it.
    ///
    /// The stop flag is enough: the driver's poll loop checks it on every
    /// 1 ms park tick, so a pass parked on the idle OUT endpoint is dropped
    /// and the loop exits without needing a wake-up frame.
    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for s in self.scripters.drain(..) {
            s.join().ok();
        }
        if let Some(j) = self.join.take() {
            let deadline = StdInstant::now() + JOIN_SLACK;
            while !j.is_finished() && StdInstant::now() < deadline {
                std::thread::sleep(StdDuration::from_millis(2));
            }
            assert!(
                j.is_finished(),
                "the serve-loop thread did not stop within {JOIN_SLACK:?}"
            );
        }
    }
}

impl Drop for Rig {
    /// A full stop, not just the flag: `Rig` is declared after the presence
    /// guard in every test, so on an unwinding panic it is dropped first and
    /// its driver thread has to be **joined** here. Releasing the guard while
    /// the driver was still closing its window would hand the next test a
    /// held presence slot, and the next test's failure would be about that
    /// rather than about itself — which is exactly the trap the guard's own
    /// doc comment names.
    fn drop(&mut self) {
        self.stop();
    }
}

fn sleep_until(deadline: StdInstant) {
    while StdInstant::now() < deadline {
        std::thread::sleep(StdDuration::from_millis(1));
    }
}

/// A report's declared payload, and nothing else — the bytes after it are the
/// report's zero padding.
fn payload_of(r: &[u8; HID_REPORT_SIZE]) -> Vec<u8> {
    let n = usize::from(u16::from_be_bytes([r[5], r[6]]));
    r[7..7 + n].to_vec()
}

/// The shared presence runtime, with the rig's clock.
fn now_ms() -> u64 {
    static EPOCH: std::sync::OnceLock<StdInstant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(StdInstant::now).elapsed().as_millis() as u64
}

/// CTAPHID framing, host side: an INIT report plus continuations.
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

/// A `CTAP_HID_CBOR` frame carrying `body`.
fn cbor_frame(channel: [u8; 4], body: &[u8]) -> Vec<[u8; HID_REPORT_SIZE]> {
    frame(channel, CTAP_HID_CBOR, body)
}

/// A `CTAPHID_INIT` with an 8-byte nonce on `channel`.
fn init_frame(channel: [u8; 4], nonce: [u8; 8]) -> Vec<[u8; HID_REPORT_SIZE]> {
    frame(channel, CTAP_HID_INIT, &nonce)
}

// ── the five assertions ────────────────────────────────────────────────────

/// The guard every test takes: the shared presence runtime is a
/// process-wide singleton with exactly one pending slot, and `cargo test`
/// runs a crate's tests in parallel threads. This is `hid_serve`'s own
/// guard, so this suite and that one serialise against each other rather
/// than against nothing — and every test below closes the window it opened,
/// through the shipped close path, before releasing it.
fn guard() -> std::sync::MutexGuard<'static, ()> {
    super::tests::test_guard()
}

/// Open a consent window on [`CH_A`]: a `makeCredential` with no press.
///
/// The write is **synchronous** (offset zero) and the frame is delivered
/// before this returns, not from a spawned thread. That is not a
/// convenience: with nothing parked, `read_one` is deliberately unbounded —
/// an idle bus must park the loop — and a first frame that lost a scheduling
/// race would park the very first pass and every assertion after it. On the
/// device the equivalent ordering is the host's write already sitting in the
/// endpoint buffer before the loop's first poll.
///
/// The window is opened by the *answer*, not by the request, so the rig does
/// not need to know that it opened — it asserts it, on the wire, as the
/// `0x01` PROCESSING keepalive the reference sends the instant the window is
/// really open.
fn open_window(rig: &mut Rig) {
    rig.write_at(StdDuration::ZERO, cbor_frame(CH_A, &[0x01, 0x01]));
    let (at, payload) = rig
        .await_on(CH_A, CTAP_HID_KEEPALIVE, WAIT)
        .unwrap_or_else(|| panic!("the window must announce itself: no KEEPALIVE on the opening channel; wire was {}", rig.describe()));
    assert_eq!(
        payload,
        vec![CTAPHID_KEEPALIVE_PROCESSING],
        "the first keepalive of a window is 0x01 PROCESSING, sent the instant \
         the window is open (it is not 0x02 UP NEEDED, which is a claim about a \
         human's attention and the button wait has not started)"
    );
    let _ = at;
    rig.assert_unblocked();
}

/// **1.** With a window open, an `INIT` on the **broadcast** channel is
/// answered inside the bound.
///
/// The broadcast channel is the interesting one and the reason this is a
/// separate assertion: it is not a channel the device allocated, it is not
/// the window's channel, and it is the one frame type a host sends before it
/// has a channel at all. Before US-1509 the serve loop was inside the
/// consent `loop` when this arrived, so it was never read: it sat in the
/// endpoint buffer and the host blocked until its own timeout.
#[test]
fn an_init_on_the_broadcast_channel_is_answered_inside_the_bound() {
    let _g = guard();
    let probe_at = StdDuration::from_millis(150);
    let mut rig = Rig::start();
    open_window(&mut rig);
    rig.write_at(probe_at, init_frame(BROADCAST, [1, 2, 3, 4, 5, 6, 7, 8]));

    let (answered, payload) = rig
        .await_on(BROADCAST, CTAP_HID_INIT, WAIT)
        .unwrap_or_else(|| {
            panic!(
                "no INIT answer on the broadcast channel within {WAIT:?} of it \
                 arriving. A live window must not stop the loop reading the OUT \
                 endpoint."
            )
        });
    let arrived = rig
        .wrote_at(|r| r[..4] == BROADCAST && r[4] == CTAP_HID_INIT | 0x80)
        .expect("the INIT was written");
    let waited = answered.saturating_duration_since(arrived);
    assert!(
        waited <= BOUND,
        "answered after {waited:?}, past the published {SERVE_BOUND_MS} ms bound"
    );
    // Not just "some answer": an INIT reply is 17 bytes — nonce(8) + cid(4)
    // + versionInterface(1) + versionMajor(1) + versionMinor(1) +
    // versionBuild(1) + capabilities(1) — and it echoes the request's nonce
    // (CTAPHID §11.2.9: 8.1.3).
    assert_eq!(
        payload.len(),
        17,
        "the broadcast answer must be a full INIT reply, not a short frame: {payload:02x?}"
    );
    assert_eq!(
        &payload[..8],
        &[1, 2, 3, 4, 5, 6, 7, 8],
        "the INIT reply must echo the request nonce"
    );
    rig.assert_unblocked();
    rig.stop();
}

/// **2.** With a window open, a `getInfo` on a **second** channel is answered
/// inside the bound.
///
/// This is the epic's own headline claim, re-asserted from outside the
/// module: the parked `makeCredential` is on [`CH_A`], the `getInfo` arrives
/// on [`CH_B`], and the answer must come back on `CH_B` — not on the window's
/// channel, which is the E7c bug the dispatcher documents (reading the
/// assembler's channel before `feed`).
#[test]
fn a_get_info_on_a_second_channel_is_answered_inside_the_bound() {
    let _g = guard();
    let probe_at = StdDuration::from_millis(150);
    let mut rig = Rig::start();
    open_window(&mut rig);
    rig.write_at(probe_at, cbor_frame(CH_B, &[0x04]));

    let (answered, payload) = rig.await_on(CH_B, CTAP_HID_CBOR, WAIT).unwrap_or_else(|| {
        panic!(
            "no answer on the second channel within {WAIT:?} of the getInfo \
             arriving. US-1502 requires one."
        )
    });
    let arrived = rig
        .wrote_at(|r| r[..4] == CH_B && r[4] == CTAP_HID_CBOR | 0x80)
        .expect("the getInfo was written");
    let waited = answered.saturating_duration_since(arrived);
    assert!(
        waited <= BOUND,
        "answered after {waited:?}, past the published {SERVE_BOUND_MS} ms bound"
    );
    assert_eq!(
        payload,
        vec![ANSWER_INFO],
        "the cross-channel answer is the getInfo's own, on the getInfo's own \
         channel"
    );
    // The window is still open and still owes the touch: a getInfo must not
    // have closed it.
    assert!(
        !rig
            .frames_on(CH_A)
            .iter()
            .any(|(c, _)| *c == CTAP_HID_CBOR),
        "the parked makeCredential must still be parked: answering a getInfo may \
         not complete another channel's command. Frames on the window's channel: \
         {:?}",
        rig.frames_on(CH_A)
    );
    rig.assert_unblocked();
    rig.stop();
}

/// **3.** A `CANCEL` closes the window, and the parked request's final answer
/// is the **keepalive-cancel** status.
///
/// Two things are asserted, and the second is the one that is easy to get
/// wrong: the status is `0x2D` (`CTAP2_ERR_KEEPALIVE_CANCEL`) and not the
/// `0x3B` (`UpRequired`) the window was refusing with. `0x3B` means "not yet —
/// touch, and I will ask again", and at a close the request is *finished*;
/// `fido2/ctap2/base.py:285-287` raises on the first non-zero byte and maps
/// `0x2D` to `ClientError.TIMEOUT`, which is what an abandoned ceremony is.
#[test]
fn a_cancel_closes_the_window_with_the_keepalive_cancel_status() {
    let _g = guard();
    let mut rig = Rig::start();
    open_window(&mut rig);

    // The CANCEL is written once the window is observed open, and stamped at
    // the write, so the bound is measured from a real arrival rather than from
    // a script's nominal offset.
    rig.write_now(frame(CH_A, CTAP_HID_CANCEL, &[]));
    let (answered, payload) = rig
        .await_on(CH_A, CTAP_HID_CBOR, WAIT)
        .unwrap_or_else(|| {
            panic!(
                "a CANCEL must answer the cancelled command, not silence; wire was {}",
                rig.describe()
            )
        });
    let arrived = rig
        .wrote_at(|r| r[..4] == CH_A && r[4] == CTAP_HID_CANCEL | 0x80)
        .expect("the CANCEL was written");
    assert!(
        answered.saturating_duration_since(arrived) <= BOUND,
        "the cancelled command's answer must land inside {BOUND:?}"
    );
    assert_eq!(
        payload,
        vec![CTAP2_ERR_KEEPALIVE_CANCEL],
        "a cancelled CTAP2 window answers 0x2D, not the 0x3B it was refusing with"
    );
    // A CANCEL is never answered with a CTAPHID error frame: CTAPHID §11.2.9
    // has no acknowledgement for it, and `fido2/hid/__init__.py:214-230`
    // raises INVALID_COMMAND on the first packet that is not CBOR, KEEPALIVE
    // or ERROR.
    assert!(
        !rig
            .frames_on(CH_A)
            .iter()
            .any(|(c, _)| *c == CTAP_HID_ERROR),
        "a CANCEL must not answer 0xBF/ERROR: {:?}",
        rig.frames_on(CH_A)
    );
    rig.assert_unblocked();

    // The window really closed, and closed the *only* way it can be observed
    // to have closed from outside: the next presence request on the same
    // channel is no longer refused as pending, and opens a window of its own.
    // `CH_D` is a fresh channel, so the keepalive read here cannot be a stale
    // frame from the window above.
    rig.write_now(cbor_frame(CH_D, &[0x01, 0x07]));
    let deadline = StdInstant::now() + WAIT;
    loop {
        if rig
            .frames_on(CH_D)
            .iter()
            .any(|(c, p)| *c == CTAP_HID_KEEPALIVE && *p == vec![CTAPHID_KEEPALIVE_PROCESSING])
        {
            break;
        }
        assert!(
            StdInstant::now() < deadline,
            "after a CANCEL the next presence request must open a NEW window, so \
             the old one was not closed. Frames on {CH_A:?}: {:?}; on {CH_D:?}: {:?}",
            rig.frames_on(CH_A),
            rig.frames_on(CH_D)
        );
        std::thread::sleep(StdDuration::from_millis(2));
    }
    rig.assert_unblocked();
    // Close that one through the shipped path too; `Rig`'s teardown would do
    // it, but doing it here keeps the wire assertion complete.
    rig.write_now(frame(CH_D, CTAP_HID_CANCEL, &[]));
    let deadline = StdInstant::now() + WAIT;
    loop {
        if rig
            .frames_on(CH_D)
            .iter()
            .any(|(c, p)| *c == CTAP_HID_CBOR && *p == vec![CTAP2_ERR_KEEPALIVE_CANCEL])
        {
            break;
        }
        assert!(
            StdInstant::now() < deadline,
            "the second window did not answer 0x2D on a CANCEL: {:?}",
            rig.frames_on(CH_D)
        );
        std::thread::sleep(StdDuration::from_millis(2));
    }
    rig.assert_unblocked();
    rig.stop();
}

/// **4.** A latched press completes the **original** request on the
/// **original** channel.
///
/// The grant is not stolen by the cross-channel traffic that was answered
/// while the window was open, and this is the assertion with teeth because
/// the gate is the real one: [`presence::request_grant_in_window`] is
/// tag-bound and single-use, so a command on another channel cannot consume
/// this window's grant, and a second presence command on another channel is
/// refused outright (US-1510, `OperationPending`) rather than being allowed to
/// run and take it.
///
/// A "latched" press is what the button task produces — an edge in
/// `PRESS_LATCH` that one poll consumes — and a press that lands with nothing
/// pending is *discarded* by the service (anti-harvest). Latching it in the
/// middle of the window and checking the answer arrives on `CH_A` is the
/// closest a host can get to the physical event.
#[test]
fn a_latched_press_completes_the_original_request_on_its_own_channel() {
    let _g = guard();
    let mut rig = Rig::start();
    open_window(&mut rig);

    // Cross-channel traffic inside the window: a getInfo (answered, on its
    // own channel) and a second presence command on a third channel
    // (refused, never run — so it cannot consume the grant).
    rig.write_now(cbor_frame(CH_B, &[0x04]));
    let (_, info) = rig
        .await_on(CH_B, CTAP_HID_CBOR, WAIT)
        .expect("the cross-channel getInfo must be answered while the window is open");
    assert_eq!(info, vec![ANSWER_INFO]);

    rig.write_now(cbor_frame(CH_C, &[0x01, 0x03]));
    let (_, refused) = rig
        .await_on(CH_C, CTAP_HID_CBOR, WAIT)
        .expect("a second presence request must be answered, not queued");
    assert_eq!(
        refused,
        vec![Ctap2Response::OperationPending.code()],
        "a second presence request while a window is open is refused with \
         OperationPending — never queued, and never run, because running it \
         could consume the grant the parked command is waiting for"
    );

    // Now the press, with the window on CH_A still open and the cross-channel
    // traffic already answered.
    rig.press_now();
    let (_, granted) = rig
        .await_on(CH_A, CTAP_HID_CBOR, WAIT)
        .unwrap_or_else(|| {
            panic!(
                "a latched press must complete the parked makeCredential on its own \
                 channel; wire was {}",
                rig.describe()
            )
        });
    assert_eq!(
        granted,
        vec![ANSWER_UP, 0x01],
        "the granted answer is the parked makeCredential's, on the parked \
         makeCredential's channel"
    );

    // And it was the *only* consumer: the other two channels saw their own
    // answers and never this one.
    assert_eq!(
        rig.frames_on(CH_B),
        vec![(CTAP_HID_CBOR, vec![ANSWER_INFO])],
        "the getInfo channel must never see the parked command's answer"
    );
    assert_eq!(
        rig.frames_on(CH_C),
        vec![(CTAP_HID_CBOR, vec![Ctap2Response::OperationPending.code()])],
        "the refused channel must never see the parked command's answer"
    );
    rig.assert_unblocked();
    rig.stop();
}

/// **5.** Afterwards the state is clean: no leaked presence window, and a
/// subsequent normal request is answered normally.
///
/// "Clean" is asserted from the outside, which is the only place it is
/// observable. A leaked window would still hold the shared runtime's single
/// pending-request slot, and the symptom of that is exact and specific: the
/// next presence request cannot open a window of its own, so
/// `presence::begin_window` fails, the dispatch falls through to its
/// `slot.take()` arm, and the host gets a bare `UpRequired` **with no `0x01`
/// PROCESSING keepalive and with the slot immediately empty**. A clean runtime
/// gives the opposite: a new `0x01`, then a granted answer once a press
/// lands. So the assertion reads a leak directly rather than inferring it.
///
/// The window here closes the hard way (a grant), not by CANCEL: the two
/// close paths are different code — `redrive_window`'s grant arm versus its
/// deadline arm — and the grant arm is the one that runs on hardware.
#[test]
fn the_state_is_clean_afterwards_and_the_next_request_is_answered_normally() {
    let _g = guard();
    let mut rig = Rig::start();
    open_window(&mut rig);

    // Cross-channel traffic while the window is open, then the press that
    // closes it.
    rig.write_now(cbor_frame(CH_B, &[0x04]));
    let (_, info) = rig
        .await_on(CH_B, CTAP_HID_CBOR, WAIT)
        .expect("the cross-channel getInfo must be answered while the window is open");
    assert_eq!(info, vec![ANSWER_INFO]);

    rig.press_now();
    let (_, granted) = rig
        .await_on(CH_A, CTAP_HID_CBOR, WAIT)
        .expect("the granted makeCredential must be answered");
    assert_eq!(granted, vec![ANSWER_UP, 0x01]);
    rig.assert_unblocked();

    // (a) No leaked window. A presence request on a **fresh** channel must get
    // a real window, not the bare-UpRequired fall-through a leaked slot causes.
    // `CH_D` is used for it precisely because it has never carried a frame, so
    // the keepalive read cannot be a stale one.
    rig.write_now(cbor_frame(CH_D, &[0x01, 0x05]));
    let deadline = StdInstant::now() + WAIT;
    loop {
        if rig
            .frames_on(CH_D)
            .iter()
            .any(|(c, p)| *c == CTAP_HID_KEEPALIVE && *p == vec![CTAPHID_KEEPALIVE_PROCESSING])
        {
            break;
        }
        assert!(
            StdInstant::now() < deadline,
            "the previous window leaked: the next presence request could not open a \
             window of its own, so `presence::begin_window` failed and it was answered \
             a bare UpRequired. Frames on {CH_D:?}: {:?}; wire was {}",
            rig.frames_on(CH_D),
            rig.describe()
        );
        std::thread::sleep(StdDuration::from_millis(2));
    }
    rig.assert_unblocked();

    // A fresh window that really opened is still *owed* a touch, so a CANCEL
    // must produce the full close: 0x2D on its own channel. A window that had
    // silently completed instead would have nothing to cancel — which is the
    // other half of "clean" and the half a leaked slot cannot produce.
    rig.write_now(frame(CH_D, CTAP_HID_CANCEL, &[]));
    let deadline = StdInstant::now() + WAIT;
    loop {
        if rig
            .frames_on(CH_D)
            .iter()
            .any(|(c, p)| *c == CTAP_HID_CBOR && *p == vec![CTAP2_ERR_KEEPALIVE_CANCEL])
        {
            break;
        }
        assert!(
            StdInstant::now() < deadline,
            "the freshly opened window did not answer 0x2D on a CANCEL, so it had \
             already completed and was not owed a touch: {:?}",
            rig.frames_on(CH_D)
        );
        std::thread::sleep(StdDuration::from_millis(2));
    }
    rig.assert_unblocked();

    // (b) A subsequent **normal** request is answered normally: a getInfo on
    // a fresh channel with no window open is the ordinary path. Exactly one
    // answer on that channel — nothing queued out of the closed windows is
    // still dribbling.
    rig.write_now(cbor_frame(CH_C, &[0x04]));
    let (_, after) = rig
        .await_on(CH_C, CTAP_HID_CBOR, WAIT)
        .expect("a plain getInfo after the window closed must be answered");
    assert_eq!(
        after,
        vec![ANSWER_INFO],
        "the answer must be the getInfo's own and not a late frame from a closed \
         window: {:?}",
        rig.frames_on(CH_C)
    );
    assert_eq!(
        rig.frames_on(CH_C),
        vec![(CTAP_HID_CBOR, vec![ANSWER_INFO])],
        "a plain getInfo is one answer, not a replay of a closed window"
    );
    rig.assert_unblocked();
    rig.stop();
}
