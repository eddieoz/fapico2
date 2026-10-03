//! US-1504: the CTAPHID reply-write park guard — the deadline-bounded half of
//! the device→host reply path, and the pure part of the reply framing it
//! bounds.
//!
//! US-1501 measured the wedge on live hardware: while the device waits for
//! user presence, a host that has stopped polling the interrupt IN endpoint
//! never ACKs, and the unbounded `EndpointIn::write` await parked the HID
//! serve loop **forever** — the device was dead until unplug, and stayed dead
//! for the next site. (The other half of the same measurement — the device
//! also stops reading the OUT endpoint during the window — is a different
//! bug, US-1509; this module bounds the IN side only.)
//!
//! The CCID path solved this first with `ccid_write_reply`
//! (`firmware/src/tasks.rs`), which wraps the **whole** chunked write in
//! `embassy_time::with_timeout`. This module is the same shape for CTAPHID,
//! and it lives in the *lib* rather than in `tasks.rs` for one reason:
//! `send_hid_report` takes a real `Endpoint<'_, USB, In>`, which cannot be
//! constructed on the host, so a deadline living next to it could not be
//! tested at all. Splitting the "write one report" step behind
//! [`ReportWriter`] makes the framing loop and its deadline testable with a
//! writer that simply never completes — the exact shape of the failure.
//!
//! Deadline semantics, matched to `ccid_write_reply` deliberately:
//!
//! * the deadline wraps the **whole message**, not each report. A fragmented
//!   7609-byte reply is 129 sequential writes, so a host that is slow rather
//!   than gone (one polling at `bInterval`, say) would keep a per-report
//!   deadline alive for 129 × 500 ms; one deadline for the message is what
//!   `ccid_write_reply` does and what the serve loop needs.
//! * on expiry the future is **dropped**, the frame is abandoned, and the
//!   caller continues. No retry, no re-enumeration, no endpoint disable.
//! * dropping is safe (cancellation safety, restated from the CCID doc
//!   comment at `tasks.rs`): embassy-rp 0.10's `EndpointIn::write` only awaits
//!   *before* arming the endpoint — arming happens in the synchronous tail
//!   after the wait — so an abandoned future leaves nothing armed.
//!
//! The timeout is a constant of this module, not a parameter: a caller that
//! could widen it (or pass "no deadline") is exactly the defect this story
//! exists to remove, so there is no argument to get wrong.

use core::future::Future;

use crate::ctap_hid::{HID_CONT_PAYLOAD, HID_FIRST_PAYLOAD, HID_REPORT_SIZE};

/// US-1504 reply-write park guard, in milliseconds — the same value, and the
/// same justification, as `CCID_REPLY_WRITE_TIMEOUT_MS`
/// (`firmware/src/tasks.rs`): a host that has stopped reading the IN endpoint
/// never ACKs, and `EndpointIn::write` awaits that ACK for every report past
/// the first. The deadline drops the frame; the serve loop logs and continues.
pub const HID_REPLY_WRITE_TIMEOUT_MS: u64 = 500;

/// How one CTAP-HID reply ended. Every arm is terminal: the caller sends at
/// most one reply and then returns to its serve loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyOutcome {
    /// Every report of the reply reached the host.
    Sent,
    /// The endpoint refused a write (`EndpointError`). The reply is
    /// incomplete, exactly as on the timeout path — there is no resume: a
    /// partially-framed message on a CTAPHID channel is garbage to the host.
    WriteFailed,
    /// The host never ACKed. The in-flight write was abandoned, the frame is
    /// dropped, and the serve loop must continue.
    TimedOut,
}

impl ReplyOutcome {
    /// `true` iff the whole reply left the device.
    pub fn is_sent(self) -> bool {
        matches!(self, ReplyOutcome::Sent)
    }
}

/// "Write one 64-byte report to the host", as far as the reply path is
/// concerned.
///
/// On the device this is the CTAPHID interrupt IN endpoint. The trait exists
/// so the *policy* — fragmentation, and the deadline around the whole
/// sequence — can be driven on the host by a writer that never returns.
pub trait ReportWriter {
    /// What a refused write looks like. The path only distinguishes "refused"
    /// from "delivered", so the concrete error type stays the caller's.
    type Error;

    /// Write one report, awaiting the host's ACK.
    ///
    /// Cancellation-safety is the caller's contract, exactly as
    /// `EndpointIn::write`'s is: dropping the returned future must leave
    /// nothing armed on the writer.
    fn write_report(
        &mut self,
        report: &[u8; HID_REPORT_SIZE],
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

/// Send `payload` to the host as one or more CTAPHID reports (INIT + zero or
/// more continuation reports) under [`HID_REPLY_WRITE_TIMEOUT_MS`].
///
/// The whole fragmented sequence shares one deadline, as in
/// `ccid_write_reply`. This function never awaits longer than that, whatever
/// the writer does: a writer whose futures never complete yields
/// [`ReplyOutcome::TimedOut`], it does not park the caller.
pub async fn write_reply<W: ReportWriter>(
    writer: &mut W,
    channel: &[u8; 4],
    cmd: u8,
    payload: &[u8],
) -> ReplyOutcome {
    match embassy_time::with_timeout(
        embassy_time::Duration::from_millis(HID_REPLY_WRITE_TIMEOUT_MS),
        frame_reply(writer, channel, cmd, payload),
    )
    .await
    {
        Ok(outcome) => outcome,
        // The in-flight report's future is dropped here. Log at the call site
        // (`tasks.rs::send_hid_report`), which is where the CCID equivalent
        // logs too, and which is the only place a `defmt` logger exists.
        Err(_) => ReplyOutcome::TimedOut,
    }
}

/// The CTAP-HID reply framing itself (CTAP-HID §11.2.3): a payload of at most
/// [`HID_FIRST_PAYLOAD`] bytes is one INIT report; anything longer is an INIT
/// report carrying the total length and the first chunk, then continuation
/// reports with a zero CMD byte and a rolling sequence number, each carrying
/// [`HID_CONT_PAYLOAD`] bytes.
async fn frame_reply<W: ReportWriter>(
    writer: &mut W,
    channel: &[u8; 4],
    cmd: u8,
    payload: &[u8],
) -> ReplyOutcome {
    let total = payload.len();
    let mut report = [0u8; HID_REPORT_SIZE];

    if total <= HID_FIRST_PAYLOAD {
        report[..4].copy_from_slice(channel);
        report[4] = cmd | 0x80;
        report[5..7].copy_from_slice(&(total as u16).to_be_bytes());
        report[7..7 + total].copy_from_slice(payload);
        return sent_or_failed(writer, &report).await;
    }

    // INIT report
    report[..4].copy_from_slice(channel);
    report[4] = cmd | 0x80;
    report[5..7].copy_from_slice(&(total as u16).to_be_bytes());
    report[7..7 + HID_FIRST_PAYLOAD].copy_from_slice(&payload[..HID_FIRST_PAYLOAD]);
    if sent_or_failed(writer, &report).await != ReplyOutcome::Sent {
        return ReplyOutcome::WriteFailed;
    }

    // Continuation reports
    let mut offset = HID_FIRST_PAYLOAD;
    let mut seq: u8 = 0;
    while offset < total {
        let end = (offset + HID_CONT_PAYLOAD).min(total);
        report = [0u8; HID_REPORT_SIZE];
        report[..4].copy_from_slice(channel);
        report[4] = seq;
        report[5..5 + (end - offset)].copy_from_slice(&payload[offset..end]);
        if sent_or_failed(writer, &report).await != ReplyOutcome::Sent {
            return ReplyOutcome::WriteFailed;
        }
        offset = end;
        seq = seq.wrapping_add(1);
    }
    ReplyOutcome::Sent
}

/// One report, mapped onto [`ReplyOutcome`].
async fn sent_or_failed<W: ReportWriter>(
    writer: &mut W,
    report: &[u8; HID_REPORT_SIZE],
) -> ReplyOutcome {
    match writer.write_report(report).await {
        Ok(()) => ReplyOutcome::Sent,
        Err(_) => ReplyOutcome::WriteFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::{pending, Future};
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use std::sync::Arc;
    use std::task::Wake;
    use std::time::{Duration as StdDuration, Instant as StdInstant};

    /// Wall-clock ceiling for one reply attempt in the test harness.
    ///
    /// The device deadline is [`HID_REPLY_WRITE_TIMEOUT_MS`] (500 ms) and is
    /// **not** lowered for the tests — they drive the real constant. The
    /// ceiling exists so that a missing (or per-report) deadline FAILS the
    /// test in seconds instead of hanging the suite forever, which is the
    /// whole point: an unbounded await is otherwise invisible to
    /// `cargo test`, which is how the US-1501 wedge survived a green suite.
    /// 3 s is 6x the deadline (a correct run has ample headroom) and below
    /// what each defect costs: forever for a missing deadline, and 129 x
    /// 40 ms = 5.2 s for the per-report deadline the slow-host test builds.
    const REPLY_CEILING: StdDuration = StdDuration::from_millis(3_000);

    /// A [`ReportWriter`] that plays one of the three USB-host shapes that
    /// matter: acking everything, acking then going away (the US-1501 wedge),
    /// and acking slowly (a host that polls the IN endpoint at `bInterval`
    /// rather than in a tight loop).
    struct Scripted {
        reports: Vec<[u8; HID_REPORT_SIZE]>,
        /// Reports to deliver before parking forever. `u32::MAX` = never park.
        ack_budget: u32,
        /// Milliseconds each delivered report stalls before its ACK.
        stall_ms: u32,
    }

    impl Scripted {
        /// A host that ACKs every report promptly.
        fn eager() -> Self {
            Self {
                reports: Vec::new(),
                ack_budget: u32::MAX,
                stall_ms: 0,
            }
        }

        /// A host that ACKs `ack_budget` reports, then stops polling the IN
        /// endpoint — the wedge US-1501 measured.
        fn parking_after(ack_budget: u32) -> Self {
            Self {
                reports: Vec::new(),
                ack_budget,
                stall_ms: 0,
            }
        }

        /// A host that ACKs every report, slowly.
        fn slow(stall_ms: u32) -> Self {
            Self {
                reports: Vec::new(),
                ack_budget: u32::MAX,
                stall_ms,
            }
        }
    }

    impl ReportWriter for Scripted {
        type Error = core::convert::Infallible;
        fn write_report(
            &mut self,
            report: &[u8; HID_REPORT_SIZE],
        ) -> impl Future<Output = Result<(), Self::Error>> {
            let acked = self.reports.len() < self.ack_budget as usize;
            if acked {
                self.reports.push(*report);
            }
            let stall_ms = self.stall_ms;
            async move {
                if !acked {
                    // The failure this story exists for: the host is gone, so
                    // the ACK never arrives and this future never resolves.
                    // Nothing here can complete it — which is exactly the
                    // state the device's serve loop was in.
                    return pending::<Result<(), Self::Error>>().await;
                }
                // A host that is slow rather than gone. A real timer, not a
                // poll count, so the cost of a per-report deadline is real.
                embassy_time::Timer::after_millis(stall_ms.into()).await;
                Ok(())
            }
        }
    }

    /// Parked (unpark from another thread) waker, so the `embassy-time` std
    /// driver's alarm thread can wake the harness loop.
    struct ThreadWaker {
        thread: std::thread::Thread,
        awake: std::sync::atomic::AtomicBool,
    }

    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            ThreadWaker::wake_by_ref(&self);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.awake.store(true, std::sync::atomic::Ordering::SeqCst);
            self.thread.unpark();
        }
    }

    /// Drive `fut` to completion on the calling thread, failing the test if it
    /// does not finish within [`REPLY_CEILING`].
    ///
    /// The ceiling is what makes the deadline *observable*: with the
    /// `with_timeout` in place the future resolves in ~500 ms; without it, or
    /// with one deadline per report, it does not finish inside the ceiling and
    /// this panics with the defect named — instead of hanging the suite.
    fn block_on<F: Future>(what: &str, fut: F) -> F::Output {
        let start = StdInstant::now();
        let mut fut = pin!(fut);
        let parker = Arc::new(ThreadWaker {
            thread: std::thread::current(),
            awake: std::sync::atomic::AtomicBool::new(false),
        });
        let waker = Waker::from(parker.clone());
        let mut cx = Context::from_waker(&waker);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
            let elapsed = start.elapsed();
            assert!(
                elapsed < REPLY_CEILING,
                "{what}: still parked after {elapsed:?} — the CTAPHID reply \
                 write is not bounded by one whole-message deadline (US-1504). \
                 A host that has stopped polling the interrupt IN endpoint \
                 must cost the serve loop HID_REPLY_WRITE_TIMEOUT_MS and no \
                 more."
            );
            std::thread::park_timeout(StdDuration::from_millis(1));
        }
    }

    /// The 7609-byte maximum CTAP-HID message: the worst fragmented reply,
    /// `1 + ceil((7609 - 57) / 59)` = 129 reports, and the shape that turned
    /// this defect into 129 sequential unbounded awaits.
    fn max_message() -> Vec<u8> {
        (0..7609u32).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn a_host_that_never_acks_times_out_instead_of_parking() {
        let mut writer = Scripted::parking_after(0);
        let start = StdInstant::now();
        let outcome = block_on(
            "single report, no ACK",
            write_reply(&mut writer, &[1, 2, 3, 4], 0x10, &[0xAA, 0xBB]),
        );
        let elapsed = start.elapsed();
        assert_eq!(outcome, ReplyOutcome::TimedOut);
        assert!(
            !outcome.is_sent(),
            "an un-ACKed reply must not report itself as sent"
        );
        // It waited about the deadline — long enough for a live host to be
        // scheduled, short enough to leave the serve loop running.
        assert!(
            elapsed >= StdDuration::from_millis(HID_REPLY_WRITE_TIMEOUT_MS),
            "gave up after {elapsed:?}, before the {HID_REPLY_WRITE_TIMEOUT_MS} \
             ms deadline — the timeout fired early"
        );
    }

    #[test]
    fn a_host_that_acks_then_stops_mid_reply_times_out_on_the_continuation_loop() {
        // Five reports delivered, then the host stops polling. The reply is a
        // maximum-size message, so the framing loop is deep in continuations
        // when the ACK stops — the continuation await is exactly the one that
        // used to be unbounded.
        let mut writer = Scripted::parking_after(5);
        let payload = max_message();
        let outcome = block_on(
            "fragmented reply, ACK stops",
            write_reply(&mut writer, &[0xDE, 0xAD, 0xBE, 0xEF], 0x10, &payload),
        );
        assert_eq!(outcome, ReplyOutcome::TimedOut);
        assert_eq!(
            writer.reports.len(),
            5,
            "the loop must abandon the reply in place — no retry of the report \
             that never ACKed, and no continuation past it"
        );
    }

    #[test]
    fn a_slow_host_costs_one_deadline_for_the_whole_reply() {
        // The per-report-deadline mistake, made observable. 7609 bytes is 129
        // reports; a host that ACKs each in 40 ms needs 5.2 s to deliver the
        // message. A deadline per report would let it (and a real host at
        // bInterval would be worse still); the whole-message deadline gives
        // up inside 500 ms and the serve loop continues.
        let mut writer = Scripted::slow(40);
        let payload = max_message();
        let outcome = block_on(
            "129-report reply, slow host",
            write_reply(&mut writer, &[0, 0, 0, 1], 0x10, &payload),
        );
        assert_eq!(
            outcome,
            ReplyOutcome::TimedOut,
            "the reply must not be allowed to run past one deadline"
        );
        assert!(
            writer.reports.len() < 129,
            "{} of 129 reports went out — the deadline is being applied per \
             report, not to the message (US-1504)",
            writer.reports.len()
        );
    }

    #[test]
    fn an_acking_host_receives_every_report_of_a_maximum_reply() {
        let mut writer = Scripted::eager();
        let payload = max_message();
        let channel = [0xAA, 0xBB, 0xCC, 0xDD];
        let outcome = block_on(
            "129-report reply, all ACK",
            write_reply(&mut writer, &channel, 0x10, &payload),
        );
        assert_eq!(outcome, ReplyOutcome::Sent);
        assert_eq!(writer.reports.len(), 129, "CTAP-HID 64-byte framing");

        // INIT report: channel, CMD | 0x80, total length, first 57 bytes.
        let init = &writer.reports[0];
        assert_eq!(&init[..4], &channel);
        assert_eq!(init[4], 0x10 | 0x80);
        assert_eq!(u16::from_be_bytes([init[5], init[6]]), 7609);
        assert_eq!(&init[7..64], &payload[..HID_FIRST_PAYLOAD]);

        // Continuation reports: channel, seq (CMD byte zero), next 59 bytes.
        for (i, cont) in writer.reports[1..].iter().enumerate() {
            assert_eq!(&cont[..4], &channel, "continuation {i}: channel");
            assert_eq!(cont[4], i as u8, "continuation {i}: seq");
            let start = HID_FIRST_PAYLOAD + i * HID_CONT_PAYLOAD;
            let end = (start + HID_CONT_PAYLOAD).min(payload.len());
            assert_eq!(&cont[5..5 + (end - start)], &payload[start..end]);
        }
    }

    #[test]
    fn a_short_reply_is_one_report_and_needs_no_continuation() {
        let mut writer = Scripted::eager();
        let payload: Vec<u8> = (0..HID_FIRST_PAYLOAD).map(|i| i as u8).collect();
        let outcome = block_on(
            "single-report reply",
            write_reply(&mut writer, &[1, 2, 3, 4], 0x3B, &payload),
        );
        assert_eq!(outcome, ReplyOutcome::Sent);
        assert_eq!(writer.reports.len(), 1);
        assert_eq!(writer.reports[0][4], 0x3B | 0x80);
        assert_eq!(
            u16::from_be_bytes([writer.reports[0][5], writer.reports[0][6]]),
            HID_FIRST_PAYLOAD as u16
        );
    }

    /// The deadline's **value**, not only its relationship to the ceiling.
    ///
    /// Every other test here is written in terms of
    /// [`HID_REPLY_WRITE_TIMEOUT_MS`], so each is satisfied by any value: the
    /// `500`→`50` mutation left all six green. That is the direction the
    /// constant's own doc cares about, because it is matched against
    /// `CCID_REPLY_WRITE_TIMEOUT_MS` (`firmware/src/tasks.rs:200`), the CTAP
    /// twin this path was modelled on — and, more sharply, because
    /// [`crate::hid_serve::SERVE_BOUND_MS`] is *derived* from it as
    /// `3 x HID_REPLY_WRITE_TIMEOUT_MS + CTAP_KEEPALIVE_PERIOD_MS` and
    /// published as a number a host is told to wait. Silently shrinking the
    /// deadline to 50 ms would republish a 400 ms bound with no test anywhere
    /// objecting. So the value is asserted directly, and so is the derivation,
    /// so the published bound cannot drift silently.
    #[test]
    fn the_deadline_is_the_published_500_ms_and_bounds_the_serve_bound() {
        assert_eq!(
            HID_REPLY_WRITE_TIMEOUT_MS, 500,
            "the CTAPHID reply-write deadline is matched to CCID_REPLY_WRITE_TIMEOUT_MS \
             (firmware/src/tasks.rs), and SERVE_BOUND_MS is derived from it"
        );
        // The published bound, restated from its own term list (three replies
        // + one keepalive period). If either input moves, the number hosts are
        // told to wait moves with it — which is why the sum is asserted and
        // not just the result.
        assert_eq!(
            crate::hid_serve::SERVE_BOUND_MS,
            3 * HID_REPLY_WRITE_TIMEOUT_MS + crate::presence::CTAP_KEEPALIVE_PERIOD_MS
        );
        assert_eq!(
            crate::hid_serve::SERVE_BOUND_MS, 1_750,
            "500 + 500 + 500 + 250: the published serve bound"
        );
    }

    /// A refused write is reported, not retried.
    #[test]
    fn a_refused_write_is_reported_not_retried() {
        /// A writer whose endpoint refuses every report.
        struct Refusing;
        impl ReportWriter for Refusing {
            type Error = &'static str;
            fn write_report(
                &mut self,
                _report: &[u8; HID_REPORT_SIZE],
            ) -> impl Future<Output = Result<(), Self::Error>> {
                core::future::ready(Err("stalled"))
            }
        }
        let mut writer = Refusing;
        let outcome = block_on(
            "refused write",
            write_reply(&mut writer, &[0, 0, 0, 0], 0x10, &max_message()),
        );
        assert_eq!(
            outcome,
            ReplyOutcome::WriteFailed,
            "a refused write is terminal for the reply — the old code \
             propagated `Err` and dropped it, and must still not loop"
        );
    }
}
