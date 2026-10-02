//! US-1509: the parked user-presence consent window — the slot that replaces
//! the serve loop's nested consent `loop`.
//!
//! # The defect this type exists to remove
//!
//! US-1501 measured it on the flashed board (`1050:0407`, 2026-10-02): a
//! 30 s consent window does not merely go unanswered, the device **stops
//! reading the USB OUT endpoint**. The host's `PING` and `CTAPHID_CANCEL`
//! writes never completed (`ETIMEDOUT`) and the one `INIT` that did land sat
//! undrained. The host blocks.
//!
//! The cause was structural. `dispatch_hid_cmd` was `.await`ed inline in the
//! `match` arm of the serve loop that had just consumed the inbound read, and
//! its consent path was a
//!
//! ```text
//! loop {
//!     Timer::after_millis(CTAP_KEEPALIVE_PERIOD_MS).await;
//!     reply_hid(..).await;
//!     /* re-drive the command */
//! }
//! ```
//!
//! for the whole window — so the serve loop *was* the window loop and never
//! returned to `hid_out.read()`. `assembler.check_timeout()` was starved with
//! it, and no inbound frame could even be observed, let alone answered.
//!
//! # The shape this type is, and why
//!
//! A single-occupancy slot of `(channel, ctap_cmd, payload, deadline)`, with
//! **pure** methods: no clock of its own (every method that needs the time
//! takes `now_ms`), no USB, no embassy, no `fapico2-fido`, no allocation.
//!
//! That last part is the load-bearing decision. The EPIC requires this policy
//! to be importable by **both** `firmware/src/tasks.rs` (the shipped device
//! path, behind `crate::boot`'s statics) and `firmware/src/emul_main.rs` (the
//! emulation binary, which carries a *second* `HidAssembler` and two more
//! copies of the same blocking presence loop). `emul_main.rs` builds with the
//! `emulation` feature and **without** `device`, so this module is declared
//! unconditionally in `lib.rs` with no feature gate and no dependency that
//! only the device build provides — US-1524 can import it as it stands. A
//! `PendingUp` that reached for `embassy_time::Instant` or `CTAP2_MAX_MSG`
//! would have forced a device-only gate onto the shared half and pushed the
//! emulator's parity work back one story.
//!
//! Pure methods are also what make the bound testable with an injected clock
//! and no USB, which is the whole claim the epic rests on.
//!
//! # What it does NOT do
//!
//! It does not own the app. The parked command is *re-driven* by whichever
//! serve loop owns the `store` borrow (`process_ctap2_with_store` takes
//! `Some(store)`), so the slot hands the command back to the caller and never
//! tries to keep the borrow alive itself. It does not own the reply either:
//! the answer of a re-drive lands in the serve loop's own response buffer,
//! and only the *refusal* shape is recorded here (1 byte of CTAP2, or 2 bytes
//! of U2F) because that is what a window that expires unanswered has to send.
//!
//! # Occupancy is fail-closed, and a refusal is a refusal
//!
//! [`PendingUp::park`] refuses when the slot is already occupied
//! ([`ParkRefusal::Occupied`]) and when the payload does not fit
//! ([`ParkRefusal::PayloadTooLarge`]). Neither refusal queues, and neither
//! may fall back to a blocking wait — the caller answers the command
//! immediately and the serve loop keeps reading. That is US-1510, and it is
//! the only honest behaviour for a single consent slot: the alternative (a
//! second window) is the US-921 anti-harvest defect with the sign flipped.

/// US-1510: the parked payload's fixed static bound, in bytes.
///
/// Far above any real `authenticatorMakeCredential` / `authenticatorGetAssertion`
/// request (the largest cred-id/blob combinations in the wild are a few
/// hundred bytes) and far below the 7609-byte CTAPHID message cap, so a real
/// command is never refused for size — only a hostile one that would otherwise
/// make the slot a memory-growth lever is.
pub const PENDING_UP_PAYLOAD_MAX: usize = 1024;

/// Which application command shape is parked.
///
/// The two are structurally different on the wire and in the app: the CTAP2
/// arm carries a one-byte opcode and the request CBOR after it, the U2F arm
/// carries a raw APDU and has to re-stamp the app's channel (`set_channel`)
/// before the re-drive, because `process_u2f` derives the presence tag from
/// the app's remembered channel rather than taking it as an argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    /// A CTAP2 command inside a `CTAP_HID_CBOR` frame.
    Ctap2,
    /// A U2F APDU inside a `CTAP_HID_MSG` frame.
    U2f,
}

/// Why [`PendingUp::park`] declined to take the slot.
///
/// Both arms are terminal: the caller must answer the command now. Neither
/// ever parks, and neither ever blocks — a blocking fallback here is exactly
/// the blackout this module exists to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkRefusal {
    /// The slot is already occupied. US-1510: refused, **not** queued — a
    /// second consent window would be a second place a latched press could be
    /// harvested.
    Occupied,
    /// The request is larger than [`PENDING_UP_PAYLOAD_MAX`]. It is answered
    /// with a status code and never parked, so an oversize request can never
    /// convert into a 30 s wait.
    PayloadTooLarge,
}

/// The identity of one open consent window: everything needed to close it
/// correctly (release its presence slot, clear its prompt, answer its
/// channel) without re-deriving anything from the request that opened it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowTicket {
    pub kind: PendingKind,
    /// The CTAPHID channel the reply must go out on.
    pub channel: [u8; 4],
    /// The presence tag this window holds the pending-request slot under
    /// (`presence_tag_from_channel` of `channel`, domain-separated into the
    /// HID space by the caller).
    pub tag: u32,
    /// The CTAP2 opcode, for [`PendingKind::Ctap2`]. `0` for
    /// [`PendingKind::U2f`].
    pub ctap_cmd: u8,
    /// The loop's exit deadline, as stamped by `TouchWindow::open`.
    pub deadline_ms: u64,
}

/// A borrowed view of the parked command, for one re-drive.
#[derive(Debug, Clone, Copy)]
pub struct Parked<'a> {
    pub ticket: WindowTicket,
    pub payload: &'a [u8],
}

/// What the serve loop must do with the slot on this pass.
#[derive(Debug)]
pub enum SlotPoll<'a> {
    /// Nothing parked. The loop reads the OUT endpoint and nothing else.
    Idle,
    /// A live window: re-assert the prompt, re-drive, and read again. The
    /// window is **re-asserted**, never awaited.
    Live(Parked<'a>),
    /// The window ran out on an unanswered touch. The ticket is returned so
    /// the caller can close it (`end_window`, prompt off, reply) — the slot
    /// is already empty when this is produced.
    Expired(WindowTicket),
}

/// The single parked user-presence window, and the only state the consent
/// path needs to survive across serve-loop passes.
///
/// Single occupancy, fail-closed, bounded payload. See the module docs for
/// why this is a pure value type rather than a set of atomics.
pub struct PendingUp {
    occupied: bool,
    ticket: WindowTicket,
    payload_len: u16,
    payload: [u8; PENDING_UP_PAYLOAD_MAX],
    /// The refusal the parked command last answered with while it still
    /// needed the touch: one byte of CTAP2 (`0x3B`), or the two-byte U2F
    /// `6985` / `0700` shape (`presence::u2f_up_refusal` admits nothing
    /// else). Kept so a window that expires can send back exactly what the
    /// command last said, rather than re-driving it one last time and
    /// answering whatever that produced.
    refusal: [u8; 2],
    refusal_len: u8,
    /// When the last keepalive went out for this window (US-1506).
    ///
    /// The rate limiter that the reference implements as a file-static
    /// `last_keepalive_time` (`pico-keys-sdk/src/usb/hid/hid.c:336`, checked
    /// at `:615`). It lives here rather than in the serve loop because the
    /// two keepalives of a window are sent from two different places — the
    /// `0x01` from the dispatch arm that parks the request, the `0x02`s from
    /// `redrive_window` — and a limiter one of them could not see is not a
    /// limiter. Cleared by [`PendingUp::park`], so a stale stamp from a
    /// previous window can never gate this one's first `0x02`.
    last_keepalive_ms: u64,
    /// Whether a keepalive has actually gone out for this window. A separate
    /// flag rather than a sentinel `0`, because `now_ms` is a real clock
    /// that reads 0 for the first millisecond of uptime and a keepalive
    /// stamped then would leave the next one "due" immediately.
    keepalive_sent: bool,
}

impl Default for PendingUp {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingUp {
    /// An empty slot. `const` so the device can park one in `.bss`
    /// (`boot::PENDING_UP`) with no runtime initialisation.
    pub const fn new() -> Self {
        Self {
            occupied: false,
            ticket: WindowTicket {
                kind: PendingKind::Ctap2,
                channel: [0; 4],
                tag: 0,
                ctap_cmd: 0,
                deadline_ms: 0,
            },
            payload_len: 0,
            payload: [0; PENDING_UP_PAYLOAD_MAX],
            refusal: [0; 2],
            refusal_len: 0,
            last_keepalive_ms: 0,
            keepalive_sent: false,
        }
    }

    /// Is a window parked?
    pub fn is_occupied(&self) -> bool {
        self.occupied
    }

    /// Has the parked window run out? Meaningful only while occupied.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.occupied && now_ms >= self.ticket.deadline_ms
    }

    /// The presence tag of the live window, if any.
    pub fn tag(&self) -> Option<u32> {
        self.occupied.then_some(self.ticket.tag)
    }

    /// Would a command on `tag` contend with the live window for the same
    /// single grant?
    ///
    /// This is the tag-identity question the app answers with
    /// `request_grant_in_window`, which is *join-only* and *mismatched-tag
    /// fails without burning the grant*: two commands on one channel share a
    /// tag, so one can consume the other's armed grant. Callers use this to
    /// refuse a same-channel command before it reaches the app rather than
    /// after (see `hid_serve`).
    pub fn contends_with(&self, tag: u32) -> bool {
        self.occupied && self.ticket.tag == tag
    }

    /// The parked command, for one re-drive.
    pub fn parked(&self) -> Option<Parked<'_>> {
        if self.occupied {
            Some(Parked {
                ticket: self.ticket,
                payload: &self.payload[..self.payload_len as usize],
            })
        } else {
            None
        }
    }

    /// One serve-loop decision: re-drive a live window, or close an expired
    /// one. Never blocks — that is the property the whole story turns on.
    pub fn poll(&self, now_ms: u64) -> SlotPoll<'_> {
        if !self.occupied {
            SlotPoll::Idle
        } else if now_ms >= self.ticket.deadline_ms {
            SlotPoll::Expired(self.ticket)
        } else {
            SlotPoll::Live(self.parked().expect("occupied implies parked"))
        }
    }

    /// Take the slot.
    ///
    /// Single occupancy: a live window is **not** replaced and never queued.
    /// The caller answers the command immediately instead — the alternative
    /// (a second window) is the anti-harvest defect with the sign flipped.
    pub fn park(
        &mut self,
        ticket: WindowTicket,
        payload: &[u8],
    ) -> Result<(), ParkRefusal> {
        if self.occupied {
            return Err(ParkRefusal::Occupied);
        }
        if payload.len() > PENDING_UP_PAYLOAD_MAX {
            return Err(ParkRefusal::PayloadTooLarge);
        }
        self.payload[..payload.len()].copy_from_slice(payload);
        self.payload_len = payload.len() as u16;
        self.ticket = ticket;
        self.refusal = [0; 2];
        self.refusal_len = 0;
        self.last_keepalive_ms = 0;
        self.keepalive_sent = false;
        self.occupied = true;
        Ok(())
    }

    /// Record the answer a re-drive produced while the touch is still owed.
    ///
    /// Called only with a refusal shape — CTAP2 `0x3B`, or the two U2F bytes
    /// `presence::u2f_up_refusal` recognises. Anything longer would not be
    /// the refusal and is ignored rather than silently truncated into a
    /// plausible-looking reply.
    pub fn note_refusal(&mut self, answer: &[u8]) {
        if answer.len() > self.refusal.len() {
            return;
        }
        self.refusal[..answer.len()].copy_from_slice(answer);
        self.refusal_len = answer.len() as u8;
    }

    /// US-1506: is a keepalive due for this window at `now_ms`?
    ///
    /// The first keepalive of a window — the `0x01` the dispatch arm sends
    /// the moment the window opens — is unconditional, which is the
    /// reference's `last_keepalive_time = 0; send_keepalive();` at
    /// `pico-keys-sdk/src/usb/hid/hid.c:586-587` (and its `!= 0` test at
    /// `:615`). Everything after it is rate-limited to
    /// `CTAP_KEEPALIVE_PERIOD_MS`.
    ///
    /// Meaningful only while occupied; an empty slot is due, because a slot
    /// with no window has no cadence to keep.
    pub fn keepalive_due(&self, now_ms: u64) -> bool {
        !self.occupied
            || !self.keepalive_sent
            || now_ms.saturating_sub(self.last_keepalive_ms)
                >= crate::presence::CTAP_KEEPALIVE_PERIOD_MS
    }

    /// Stamp a keepalive that has just gone out, at `now_ms`.
    pub fn note_keepalive(&mut self, now_ms: u64) {
        if self.occupied {
            self.last_keepalive_ms = now_ms;
            self.keepalive_sent = true;
        }
    }

    /// The refusal the parked command last answered with, for a window that
    /// expires unanswered.
    pub fn refusal(&self) -> &[u8] {
        &self.refusal[..self.refusal_len as usize]
    }

    /// Close the slot and hand its ticket back.
    ///
    /// Every caller that closes a window must pair this with
    /// `presence::end_window(ticket.tag)` and
    /// `presence::touch_prompt(false)` — a leaked window is a permanently
    /// held presence slot, and a never-cleared prompt is a light that never
    /// goes out. There is exactly one close path (`take`) so those three
    /// calls cannot drift apart.
    pub fn take(&mut self) -> Option<WindowTicket> {
        if !self.occupied {
            return None;
        }
        self.occupied = false;
        self.payload_len = 0;
        self.refusal_len = 0;
        self.last_keepalive_ms = 0;
        self.keepalive_sent = false;
        Some(self.ticket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    static NOW: AtomicU64 = AtomicU64::new(0);

    fn ticket(tag: u32, deadline_ms: u64) -> WindowTicket {
        WindowTicket {
            kind: PendingKind::Ctap2,
            channel: [0, 0, 0, 9],
            tag,
            ctap_cmd: 0x01,
            deadline_ms,
        }
    }

    /// US-1510: one window at a time. A second UP request is refused, never
    /// queued — a queue would be a second place a latched press could be
    /// harvested, which is US-921's defect with the sign flipped.
    #[test]
    fn a_second_park_is_refused_not_queued() {
        let mut slot = PendingUp::new();
        assert_eq!(slot.park(ticket(0x8000_0009, 30_000), &[1, 2, 3]), Ok(()));
        assert!(slot.is_occupied());
        assert_eq!(
            slot.park(ticket(0x8000_000A, 60_000), &[4, 5, 6]),
            Err(ParkRefusal::Occupied)
        );
        // The first window is untouched: same channel, same deadline, same
        // payload. A refusal must not evict what is already parked.
        let live = slot.parked().expect("first window survives");
        assert_eq!(live.ticket.tag, 0x8000_0009);
        assert_eq!(live.ticket.deadline_ms, 30_000);
        assert_eq!(live.payload, &[1, 2, 3]);
    }

    /// US-1510: the pinned 1024 B bound. A request above it is refused and
    /// leaves the slot empty, so it can never become a 30 s wait; one exactly
    /// at the bound is parked.
    #[test]
    fn the_payload_bound_is_1024_and_is_never_parked_over() {
        let mut slot = PendingUp::new();
        let at_bound = [0x5Au8; PENDING_UP_PAYLOAD_MAX];
        assert_eq!(slot.park(ticket(1, 30_000), &at_bound), Ok(()));
        let live = slot.parked().expect("at the bound parks");
        assert_eq!(live.payload.len(), PENDING_UP_PAYLOAD_MAX);
        assert!(live.payload.iter().all(|b| *b == 0x5A), "payload is copied verbatim");

        let over = [0x5Au8; PENDING_UP_PAYLOAD_MAX + 1];
        assert_eq!(
            slot.park(ticket(2, 30_000), &over),
            Err(ParkRefusal::Occupied),
            "the first window is still open; occupancy is checked first"
        );
        assert_eq!(slot.take(), Some(ticket(1, 30_000)));
        assert_eq!(
            slot.park(ticket(2, 30_000), &over),
            Err(ParkRefusal::PayloadTooLarge)
        );
        assert!(!slot.is_occupied(), "an oversize request must not leave a window behind");
    }

    /// The loop's decision, on an injected clock: idle → live → expired, with
    /// the ticket handed back on the transition that closes it.
    #[test]
    fn poll_walks_idle_live_expired_and_take_closes_once() {
        NOW.store(1_000, Ordering::Relaxed);
        let mut slot = PendingUp::new();
        assert!(matches!(slot.poll(NOW.load(Ordering::Relaxed)), SlotPoll::Idle));
        assert_eq!(slot.take(), None, "nothing to close");

        slot.park(ticket(0x8000_0009, 31_000), &[0x01, 0xA0]).unwrap();
        // Inside the window: the caller re-drives, it does not wait.
        match slot.poll(1_000) {
            SlotPoll::Live(p) => assert_eq!(p.payload, &[0x01, 0xA0]),
            other => panic!("expected a live window, got {other:?}"),
        }
        // One millisecond before the deadline is still live.
        assert!(matches!(slot.poll(30_999), SlotPoll::Live(_)));

        // The deadline is inclusive: at it, the window is over.
        match slot.poll(31_000) {
            SlotPoll::Expired(t) => assert_eq!(t.tag, 0x8000_0009),
            other => panic!("expected expiry at the deadline, got {other:?}"),
        }
        assert!(slot.is_expired(31_000));
        assert!(slot.is_occupied(), "poll reports expiry; it does not close");

        assert_eq!(slot.take().map(|t| t.tag), Some(0x8000_0009));
        assert!(!slot.is_occupied());
        assert!(matches!(slot.poll(31_001), SlotPoll::Idle));
        assert_eq!(slot.take(), None, "a closed window cannot be closed twice");
    }

    /// The refusal a re-drive recorded is what an expired window answers
    /// with — the exact bytes the command last produced, and nothing else.
    #[test]
    fn the_refusal_is_recorded_bounded_and_survives_until_close() {
        let mut slot = PendingUp::new();
        slot.park(ticket(1, 10), &[0x01]).unwrap();
        assert!(slot.refusal().is_empty(), "nothing recorded before the first re-drive");
        slot.note_refusal(&[0x3B]);
        assert_eq!(slot.refusal(), &[0x3B]);
        slot.note_refusal(&[0x69, 0x85]);
        assert_eq!(slot.refusal(), &[0x69, 0x85], "the U2F shape replaces the CTAP2 one");
        // Longer than the two refusal shapes: ignored, not truncated — a
        // plausible-looking half-answer would be worse than none.
        slot.note_refusal(&[0x69, 0x85, 0x00]);
        assert_eq!(slot.refusal(), &[0x69, 0x85]);

        // A re-park starts from a clean refusal, so a stale byte from the
        // previous window can never answer this one.
        slot.take();
        slot.park(ticket(2, 20), &[0x02]).unwrap();
        assert!(slot.refusal().is_empty());
    }

    /// US-921's tag identity: a live window contends only with a command on
    /// the same presence tag (the same channel). This is what lets
    /// `hid_serve` refuse a same-channel command *before* it reaches the
    /// app, instead of letting it consume a grant armed for the parked one.
    #[test]
    fn contention_is_decided_by_presence_tag() {
        let mut slot = PendingUp::new();
        assert!(!slot.contends_with(0x8000_0009), "an empty slot contends with nothing");
        slot.park(ticket(0x8000_0009, 10), &[0x01]).unwrap();
        assert!(slot.contends_with(0x8000_0009));
        assert!(!slot.contends_with(0x8000_000A));
        assert_eq!(slot.tag(), Some(0x8000_0009));
        slot.take();
        assert!(!slot.contends_with(0x8000_0009), "a closed slot holds no grant");
        assert_eq!(slot.tag(), None);
    }
}
