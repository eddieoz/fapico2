//! US-906 TDD: the platform presence service — bound, timed, single-use.
//!
//! Host tests (no hardware): the service is `core`-only, so these run on the
//! default host target exactly as they will behave on the device build.

use fapico2_platform::presence::{PresenceService, PRESENCE_WINDOW_MS};

/// Grant consumed exactly once: the second consume fails, even for the same
/// tag in the same instant.
#[test]
fn grant_is_single_use() {
    let mut svc = PresenceService::new();
    assert!(svc.begin_request(7));
    svc.observe_press(1_000);
    let g1 = svc.request(7, 1_000);
    assert_eq!(
        g1.map(|g| g.cmd_tag()),
        Some(7),
        "armed grant must serve its tag once"
    );
    assert_eq!(svc.request(7, 1_000), None, "second consume must fail");
}

/// A grant expires after the fixed window (10 s): still valid one tick
/// before the deadline, dead at it. The stale grant is consumed by the
/// failed request, not left behind.
#[test]
fn expired_grant_fails() {
    let mut svc = PresenceService::new();
    assert!(svc.begin_request(7));
    svc.observe_press(1_000);
    let deadline = 1_000 + PRESENCE_WINDOW_MS;
    assert_eq!(PRESENCE_WINDOW_MS, 10_000, "brief fixes the window at 10 s");
    assert!(
        svc.request(7, deadline - 1).is_some(),
        "grant must live up to the deadline"
    );
    // consumed — a fresh service for the expiry-side check:
    let mut svc = PresenceService::new();
    assert!(svc.begin_request(7));
    svc.observe_press(1_000);
    assert_eq!(
        svc.request(7, deadline),
        None,
        "grant must be dead at the deadline"
    );
    assert_eq!(svc.request(7, deadline + 1_000), None);
}

/// A grant armed while command A is pending cannot serve command B: the tag
/// binding is not forgeable by a different (host-initiated) command.
/// A mismatched request must NOT burn the grant either — the legitimate
/// command keeps it.
#[test]
fn grant_is_bound_to_its_tag() {
    let mut svc = PresenceService::new();
    assert!(svc.begin_request(0xAA));
    svc.observe_press(0);
    assert_eq!(
        svc.request(0xBB, 0),
        None,
        "tag B must not be served by A's grant"
    );
    assert!(
        svc.request(0xAA, 0).is_some(),
        "tag A still holds its grant"
    );
}

/// Anti-harvest: a press with no pending request is discarded — it must
/// never arm a grant for a later host-initiated destructive command.
#[test]
fn press_without_request_never_yields_a_grant() {
    let mut svc = PresenceService::new();
    svc.observe_press(0); // stray press, nothing pending
    assert!(svc.begin_request(3));
    assert_eq!(
        svc.request(3, 0),
        None,
        "pre-request press must not arm a grant"
    );
    // ...and a second press while pending still works normally:
    svc.observe_press(5);
    assert!(svc.request(3, 5).is_some());
}

/// Given one latch press, when two destructive commands race, then exactly
/// one obtains the grant.
#[test]
fn one_press_two_racers_yields_exactly_one_grant() {
    let mut svc = PresenceService::new();
    // Command A is pending when the press lands.
    assert!(svc.begin_request(10));
    svc.observe_press(5_000);
    // Command B races in (slot is single): it cannot even pend alongside A.
    assert!(!svc.begin_request(11), "single pending-request slot");
    // A takes the grant; B, whether it races before or after, gets nothing.
    assert!(svc.request(10, 5_000).is_some());
    assert_eq!(
        svc.request(11, 5_000),
        None,
        "loser of the race must not be served"
    );
    // Even after A ends, B cannot resurrect the spent press.
    svc.end_request(10);
    assert!(svc.begin_request(11));
    assert_eq!(svc.request(11, 5_001), None);
}

/// Slot discipline: `end_request` releases the single slot for the next
/// command; a release by a non-owner tag is a no-op.
#[test]
fn pending_slot_is_single_and_released() {
    let mut svc = PresenceService::new();
    assert!(svc.begin_request(1));
    assert!(!svc.begin_request(2));
    svc.end_request(2); // not the owner — no-op
    assert!(!svc.begin_request(2), "owner still holds the slot");
    svc.end_request(1);
    assert!(svc.begin_request(2));
}

// ---------------------------------------------------------------------------
// US-921: pending-window deadlines — the cross-call window a transport-level
// keepalive loop opens (`begin_request_window`) and lazily closes
// (`expire_pending`). Slot rules are exactly `begin_request`'s.
// ---------------------------------------------------------------------------

/// A pending window opens the single slot under `tag` with the given
/// deadline; a press inside the window arms a grant as usual.
#[test]
fn begin_request_window_opens_slot_and_arms_within_deadline() {
    let mut svc = PresenceService::new();
    assert!(svc.begin_request_window(0x21, 30_000));
    assert_eq!(svc.pending_tag(), Some(0x21), "the window holds the slot");
    svc.observe_press(10_000);
    assert!(
        svc.request(0x21, 10_000).is_some(),
        "a press inside the window arms the grant"
    );
}

/// Slot rules as `begin_request`: any begin — including a same-tag
/// re-begin (commands begin once; a re-begin fails closed) — fails while
/// the slot is occupied.
#[test]
fn begin_request_window_fails_while_slot_busy() {
    let mut svc = PresenceService::new();
    assert!(svc.begin_request_window(0x21, 30_000));
    assert!(
        !svc.begin_request_window(0x22, 30_000),
        "another tag cannot steal the slot"
    );
    assert!(
        !svc.begin_request_window(0x21, 40_000),
        "a same-tag re-begin fails closed (commands begin once)"
    );
    assert_eq!(
        svc.pending_tag(),
        Some(0x21),
        "the failed re-begin must not move the deadline"
    );
}

/// `expire_pending` lazily closes an expired window: the slot frees (the
/// next command can begin), and a press arriving after the deadline is
/// discarded — it arms nothing for the stale tag.
#[test]
fn expire_pending_lazily_closes_an_expired_window() {
    let mut svc = PresenceService::new();
    assert!(svc.begin_request_window(0x21, 30_000));
    // Before the deadline: nothing to expire, slot untouched.
    assert!(!svc.expire_pending(29_999), "the window is still open");
    assert_eq!(svc.pending_tag(), Some(0x21));
    // At/after the deadline: the window closes.
    assert!(svc.expire_pending(30_000), "expired window closed");
    assert_eq!(svc.pending_tag(), None, "the slot must free");
    // A press after the deadline lands with nothing pending: discarded.
    svc.observe_press(30_001);
    // The freed slot accepts the next command's begin.
    assert!(svc.begin_request(0x22));
}

/// A press after the deadline never arms: `observe_press` expires the
/// window first, so the late press is discarded instead of arming a grant
/// for the stale tag.
#[test]
fn press_after_window_deadline_is_discarded_never_armed() {
    let mut svc = PresenceService::new();
    assert!(svc.begin_request_window(0x21, 30_000));
    // The press lands after the deadline: the lazy close fires inside
    // `observe_press`, the press finds nothing pending, and is discarded.
    svc.observe_press(30_001);
    assert!(
        svc.request(0x21, 30_001).is_none(),
        "a late press must never arm the expired window"
    );
    // Sanity (pre-deadline parity): a fresh window arms a press normally.
    let mut svc = PresenceService::new();
    assert!(svc.begin_request_window(0x21, 30_000));
    svc.observe_press(29_999);
    assert!(svc.request(0x21, 29_999).is_some(), "in-window press arms");
}

/// A plain `begin_request` carries no window deadline: `expire_pending`
/// never fires while a deadline-less command holds the slot, and the slot
/// is freed only by `end_request`.
#[test]
fn plain_begin_request_has_no_deadline_and_end_request_clears_it() {
    let mut svc = PresenceService::new();
    assert!(svc.begin_request(0x21));
    assert!(!svc.expire_pending(u64::MAX), "no deadline to expire");
    svc.end_request(0x21);

    // `end_request` also clears a window deadline: the freed slot shows no
    // pending window for the next expire sweep.
    assert!(svc.begin_request_window(0x21, 30_000));
    svc.end_request(0x21);
    assert!(!svc.expire_pending(u64::MAX));
    assert!(svc.begin_request(0x22), "the slot freed");
}
