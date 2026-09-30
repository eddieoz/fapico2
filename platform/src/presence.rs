//! US-906: platform presence service — bound, timed, single-use.
//!
//! Root cause (EPIC Phase B): presence existed only as mgmt's injected
//! `fn() -> bool` and the button task's sticky latch, with no binding to a
//! pending command and no expiry — a hostile host script could harvest any
//! user press. This module makes presence a *grant*: armed only by a press
//! that arrives while a command is pending, bound to that command's tag,
//! expiring after a fixed window, and consumable exactly once.
//!
//! # Latch semantics / device queue discipline
//!
//! * **Single pending-request slot.** At most one command pends for presence
//!   at a time (`begin_request`/`end_request`). A device build (US-921) keeps
//!   one slot: the button task arms a grant only while the slot is occupied.
//! * **Anti-harvest.** A press observed with *no* pending request is
//!   discarded — it is never stored for a later host-initiated destructive
//!   command to consume.
//! * **Timing.** The window is the fixed [`PRESENCE_WINDOW_MS`]; the clock is
//!   injected (`now_ms`) so the service stays `core`-only and testable on the
//!   host. Expiry is lazy: a stale grant is consumed (dropped) by the request
//!   that finds it dead.
//! * **Tag binding.** A grant serves only the tag that was pending when the
//!   press arrived. A mismatched request fails *without* burning the grant —
//!   the legitimate command keeps it.

/// Presence window (US-906): a grant expires 10 s after the press that
/// armed it.
pub const PRESENCE_WINDOW_MS: u64 = 10_000;

/// Source of physical user-presence presses. The device implementation
/// (US-921) is the BOOTSEL button edge latch polled by the button task;
/// host/emulation builds inject an auto-acking source (or, as mgmt does
/// today, an `fn() -> bool` press poll) so existing suites stay green.
pub trait PresenceSource {
    /// One poll: returns whether a press edge occurred since the last poll.
    /// Sources must not report a press for a poll that was already consumed.
    fn poll_press(&mut self) -> bool;
}

/// Host/emulation default source: auto-acks (reports a press whenever
/// polled) — matches the pre-US-906 host behavior where presence was always
/// granted outside the device build.
pub struct AutoPresence;

impl PresenceSource for AutoPresence {
    fn poll_press(&mut self) -> bool {
        true
    }
}

/// An opaque presence grant: proof that a user pressed while *this* command
/// tag was pending, within the window. Consume is `PresenceService::request`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresenceGrant {
    tag: u32,
}

impl PresenceGrant {
    /// The command tag this grant is bound to.
    pub fn cmd_tag(&self) -> u32 {
        self.tag
    }
}

/// Armed grant: the tag that was pending when the press arrived, and the
/// deadline (press time + [`PRESENCE_WINDOW_MS`]).
struct Armed {
    tag: u32,
    deadline_ms: u64,
}

/// The presence service (US-906): single pending-request slot, single-use
/// timed tag-bound grants. `core`-only: the clock is injected as `now_ms`.
pub struct PresenceService {
    /// The one pending-request slot (`None` = no command is waiting).
    pending: Option<u32>,
    /// The armed grant, if a press landed while a request was pending.
    armed: Option<Armed>,
    /// US-921: the cross-call window's deadline, when the slot was opened
    /// by `begin_request_window` (`None` = the plain synchronous path, or
    /// the window's deadline already expired). Invariant: `Some` only
    /// while `pending` is `Some`.
    pending_deadline: Option<u64>,
}

impl PresenceService {
    pub const fn new() -> Self {
        Self {
            pending: None,
            armed: None,
            pending_deadline: None,
        }
    }

    /// Declare a command pending for presence. Returns `false` when the
    /// single slot is occupied (by *any* tag, including a re-begin of the
    /// same tag — commands begin once; a re-begin fails closed).
    pub fn begin_request(&mut self, tag: u32) -> bool {
        if self.pending.is_some() {
            return false;
        }
        self.pending = Some(tag);
        true
    }

    /// US-921: declare a command pending with a **cross-call window** —
    /// the slot holds until `deadline_ms` (the transport-level keepalive
    /// loop's exit bound), not until the caller ends the request. Slot
    /// rules are exactly [`PresenceService::begin_request`]'s (single
    /// slot, same-tag re-begin fails closed). The deadline is lazy: a
    /// press or request arriving after it expires the window itself (see
    /// [`PresenceService::observe_press`]/[`PresenceService::expire_pending`]).
    pub fn begin_request_window(&mut self, tag: u32, deadline_ms: u64) -> bool {
        if self.pending.is_some() {
            return false;
        }
        self.pending = Some(tag);
        self.pending_deadline = Some(deadline_ms);
        true
    }

    /// US-921: lazily close a pending window whose deadline has passed.
    /// Frees the slot (so the next command can begin) and returns whether
    /// a window actually closed. A deadline-less pending request (the
    /// plain `begin_request` path) never expires here.
    pub fn expire_pending(&mut self, now_ms: u64) -> bool {
        match self.pending_deadline {
            Some(deadline) if now_ms >= deadline => {
                self.pending = None;
                self.pending_deadline = None;
                true
            }
            _ => false,
        }
    }

    /// Release the pending-request slot (no-op if `tag` is not the owner).
    /// Clears any window deadline too (a window opened by
    /// [`begin_request_window`] is closed only by its owner, its expiry,
    /// or this call).
    pub fn end_request(&mut self, tag: u32) {
        if self.pending == Some(tag) {
            self.pending = None;
            self.pending_deadline = None;
        }
    }

    /// The tag holding the pending-request slot, if any (US-921: lets a
    /// press source report armed-vs-discarded without arming anything).
    pub fn pending_tag(&self) -> Option<u32> {
        self.pending
    }

    /// A press was observed at `now_ms`. Arms a grant bound to the pending
    /// tag, or is **discarded** when nothing is pending (anti-harvest).
    ///
    /// US-921: a pending **window** whose deadline has passed is expired
    /// FIRST — the late press finds nothing pending and is discarded, so a
    /// press can never arm a window that already closed.
    pub fn observe_press(&mut self, now_ms: u64) {
        self.expire_pending(now_ms);
        if let Some(tag) = self.pending {
            self.armed = Some(Armed {
                tag,
                deadline_ms: now_ms.saturating_add(PRESENCE_WINDOW_MS),
            });
        }
    }

    /// Ask for this command's grant at `now_ms`. Consumes the armed grant
    /// exactly once if it is alive, unexpired, and bound to `cmd_tag`; a
    /// mismatched request fails without burning the grant; an expired grant
    /// is consumed (dropped) by the request that finds it dead.
    pub fn request(&mut self, cmd_tag: u32, now_ms: u64) -> Option<PresenceGrant> {
        match self.armed.take() {
            Some(Armed { tag, deadline_ms }) if tag == cmd_tag && now_ms < deadline_ms => {
                Some(PresenceGrant { tag })
            }
            // Alive but bound to a different tag: restore it — the legitimate
            // owner keeps its grant.
            Some(a) if a.deadline_ms > now_ms => {
                self.armed = Some(a);
                None
            }
            // No grant, or an expired one: consumed (dropped) by this request.
            _ => None,
        }
    }
}

impl Default for PresenceService {
    fn default() -> Self {
        Self::new()
    }
}
