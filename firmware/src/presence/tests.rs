//! US-921 TDD: presence-latch anti-harvest discipline — the device button
//! latch binds to a *pending* grant request (US-906 `PresenceService`
//! wiring). Host tests, no hardware: presses are injected deterministically
//! through the board-test hook (`emul_inject_press`), the clock manually.

use core::sync::atomic::{AtomicU32, Ordering};
use std::collections::VecDeque;
use std::sync::Mutex as StdMutex;

use super::{
    adopt_wait_level, emul_inject_press, note_wait_level, set_touch_prompt_hook, u2f_up_refusal,
    LatchSource, PresenceRuntime, TouchWindow, CCID_WINDOW_MS, PRESS_LATCH,
};
/// US-1524: the presence suite's serialisation lock is the module-level one
/// (see its doc comment) — shared with `hid_serve`'s harness so a consent
/// window opened there cannot be holding this suite's slot.
use super::TEST_LOCK;
/// Manual clock: tests advance `NOW_MS` explicitly.
static NOW_MS: AtomicU32 = AtomicU32::new(0);

fn tick_to(ms: u32) {
    NOW_MS.store(ms, Ordering::SeqCst);
}

fn latch_held() -> bool {
    PRESS_LATCH.load(Ordering::SeqCst)
}

fn runtime() -> PresenceRuntime<LatchSource> {
    PresenceRuntime::new(LatchSource, || u64::from(NOW_MS.load(Ordering::SeqCst)))
}

/// Case 1 — a press observed with *no* pending request is discarded: the
/// button task's tick drains it, and a later destructive command gets no
/// grant (anti-harvest: the press is never stored for the command).
#[test]
fn press_before_request_is_discarded() {
    let _g = TEST_LOCK.lock().unwrap();
    emul_inject_press();
    assert!(latch_held(), "the press hook must latch the edge");

    let mut rt = runtime();
    rt.poll_press(); // button-task tick while nothing is pending
    assert!(
        !latch_held(),
        "the drain must clear the latch without arming it"
    );
    assert!(
        !rt.request_grant(0x11),
        "a press with no pending request must never arm a grant"
    );
}

/// Case 2 — a press while a request is pending arms a grant bound to that
/// command's tag, consumed exactly once.
#[test]
fn press_during_request_grants_once() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(1_000);
    let mut rt = runtime();
    assert!(rt.begin_request(7), "the pending slot must accept the command");

    emul_inject_press();
    rt.poll_press(); // button-task tick while the request is pending

    let grant = rt.request(7);
    assert_eq!(grant.map(|g| g.cmd_tag()), Some(7), "grant binds to the tag");
    assert!(
        rt.request(7).is_none(),
        "the grant is single-use — a second consume fails"
    );
    rt.end_request(7);
}

/// Case 3 — after the grant is consumed, a second command (even the same
/// tag) gets nothing; a stale press left before a *new* request began is
/// discarded by the button task's tick, not carried into it.
#[test]
fn second_command_gets_nothing() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(2_000);
    let mut rt = runtime();
    assert!(rt.begin_request(7));
    emul_inject_press();
    rt.poll_press();
    assert!(rt.request(7).is_some(), "first command consumes the grant");
    rt.end_request(7);

    // Second command, same tag, no new press: nothing left to grant.
    assert!(
        !rt.request_grant(7),
        "the consumed grant must not serve a second command"
    );

    // A stale press on the latch with nothing pending is discarded by the
    // drain, never carried into the next command's request.
    emul_inject_press();
    rt.poll_press(); // nothing pending → discarded
    assert!(!rt.request_grant(0x42), "no grant for the unrelated command");
}

/// US-921 review fix: the drain reports **armed-vs-discarded** — a press
/// with nothing pending returns `false` and arms nothing anywhere (the
/// legacy raw-latch fall-through that `button.rs` used to keep is gone:
/// OATH RESET consumes its grants from this same runtime), a press while
/// pending returns `true`.
#[test]
fn drain_reports_armed_vs_discarded() {
    let _g = TEST_LOCK.lock().unwrap();
    let mut rt = runtime();

    // Discarded: no pending request → not armed (arms nothing anywhere).
    emul_inject_press();
    assert!(
        !rt.poll_press(),
        "a discarded press must report not-armed"
    );
    assert!(!latch_held(), "the discard must clear the latch");

    // Armed: a request is pending → armed (this press binds to the
    // pending tag only).
    assert!(rt.begin_request(7));
    emul_inject_press();
    assert!(rt.poll_press(), "a press while pending must report armed");
    assert!(rt.request(7).is_some(), "the armed grant is consumable");
    rt.end_request(7);

    // No press at all → not armed.
    assert!(!rt.poll_press(), "no press → not armed");
}

/// Window parity (US-906): a grant expires 10 s after its press even when
/// armed through the device latch wiring.
#[test]
fn armed_grant_expires_after_window() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(5_000);
    let mut rt = runtime();
    assert!(rt.begin_request(9));
    emul_inject_press();
    rt.poll_press();
    tick_to(5_000 + 10_000); // exactly the US-906 window
    assert!(
        rt.request(9).is_none(),
        "the grant must die at the 10 s deadline"
    );
    rt.end_request(9);
}

/// US-914 `wait_grant` sample queue: each `sample()` call pops one level
/// and advances the manual clock 5 ms (device parity: every poll is
/// paced). An empty queue reads as "not pressed".
static SAMPLES: StdMutex<VecDeque<bool>> = StdMutex::new(VecDeque::new());

fn queue_levels(levels: impl IntoIterator<Item = bool>) {
    *SAMPLES.lock().unwrap() = levels.into_iter().collect();
}

fn paced_level() -> bool {
    NOW_MS.fetch_add(5, Ordering::SeqCst);
    let pressed = SAMPLES.lock().unwrap().pop_front().unwrap_or(false);
    // Device parity: `paced_bootsel` publishes every level so the button
    // task can resync its edge baseline after the wait (US-914 review fix).
    note_wait_level(pressed);
    pressed
}

/// US-914: a press *edge* inside the wait window arms and consumes exactly
/// one grant; the consumed grant is gone afterwards.
#[test]
fn wait_grant_edge_within_window_grants_once() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(1_000);
    // Levels: idle at entry, then the press edge.
    queue_levels([false, true, true]);
    let mut rt = runtime();
    assert!(
        rt.wait_grant(0x002A_9E9A, 15_000, paced_level),
        "a press edge while pending must grant"
    );
    // Single-use: a fresh wait with no new press (and a short window)
    // refuses — the earlier grant cannot serve twice.
    queue_levels([false, false, false]);
    assert!(
        !rt.wait_grant(0x002A_9E9A, 60, paced_level),
        "the consumed grant is single-use"
    );
}

/// US-914: no press inside the window ⇒ fail-closed after the timeout.
#[test]
fn wait_grant_no_press_times_out() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(2_000);
    queue_levels([]); // every poll reads "not pressed"
    let mut rt = runtime();
    assert!(
        !rt.wait_grant(0x002A_8086, 100, paced_level),
        "no press ⇒ no grant, fail-closed after the window"
    );
}

/// US-914 anti-harvest at wait entry: a button already held when the wait
/// begins has no edge *while the request is pending* — a press that
/// predates the request is not consent for it.
#[test]
fn wait_grant_held_at_entry_never_grants() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(3_000);
    queue_levels([true, true, true, true, true]);
    let mut rt = runtime();
    assert!(
        !rt.wait_grant(0x0088_0000, 100, paced_level),
        "a held-over press must not grant"
    );
}

/// US-914: a busy pending slot fail-closes the wait immediately (US-906
/// single-slot discipline — commands begin once).
#[test]
fn wait_grant_fail_closed_while_slot_busy() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(4_000);
    queue_levels([true]);
    let mut rt = runtime();
    assert!(rt.begin_request(0x11), "occupy the single pending slot");
    assert!(
        !rt.wait_grant(0x002A_9E9A, 100, paced_level),
        "a busy pending slot must fail-closed the wait"
    );
    rt.end_request(0x11);
}

/// US-914 review fix: the blocking wait's sampler publishes its last
/// observed level and the button task adopts it as its edge baseline — a
/// press consumed by the wait must not reappear as a fresh edge on the
/// button task's next poll (which would re-latch the tail of an
/// already-granted press for a later command).
#[test]
fn wait_level_adoption_resyncs_the_button_baseline() {
    let _g = TEST_LOCK.lock().unwrap();
    // Drain any stray adoption left by earlier tests (they all hold the
    // same lock, but be explicit).
    while adopt_wait_level().is_some() {}
    tick_to(6_000);
    // A wait that consumed a press still HELD at its last sample: the
    // button task's post-wait baseline is "pressed", so its next poll
    // (level still held) is NOT a fresh edge.
    queue_levels([false, true, true]);
    let mut rt = runtime();
    assert!(rt.wait_grant(0x002A_9E9A, 15_000, paced_level));
    assert_eq!(
        adopt_wait_level(),
        Some(true),
        "a held tail must adopt a pressed baseline"
    );
    assert_eq!(
        adopt_wait_level(),
        None,
        "the adoption is one-shot until the next wait samples"
    );
    // A timed-out wait that never saw a press adopts "released" — the
    // button task's baseline stays low.
    tick_to(7_000);
    queue_levels([]);
    assert!(!rt.wait_grant(0x002A_8086, 100, paced_level));
    assert_eq!(
        adopt_wait_level(),
        Some(false),
        "a no-press wait must adopt a released baseline"
    );
    assert_eq!(adopt_wait_level(), None);
}

/// US-914 hardware C5 anomaly (2026-09-23): one physical press with NO
/// pending request, followed ~1 s later by a 10 s touch window, granted.
/// Reproduce the exact interleaving on the host: button task drains the
/// press (discard — arms nothing, US-921 review), the press level is
/// published to the wait sampler, wait starts, user releases → no edge may
/// arm a grant. If this test holds, the hardware grant needed a real second
/// edge (bounce or re-press) — not a runtime leak.
#[test]
fn c5_sequence_press_then_wait_never_grants() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(10_000);
    let mut rt = runtime();

    // Phase 1: press edge with nothing pending — the button task drains.
    emul_inject_press();
    assert!(!rt.poll_press(), "no request ⇒ discarded, not armed");

    // The wait's paced sampler sees the pad level each poll. The press is
    // HELD at command entry (human still holding): the sampler publishes
    // the level (device parity with paced_bootsel/note_wait_level).
    // Sequence of levels over the window: held, held, released, released…
    queue_levels([true, true, false, false, false, false]);
    let granted = rt.wait_grant(0x002A_9E9A, 15_000, paced_level);
    assert!(
        !granted,
        "a held press at entry + release must NEVER grant (no edge while pending)"
    );
    rt.end_request(0x002A_9E9A);
}

/// C5 fix: a single-sample spike (mechanical bounce/EMI on the QSPI-CS
/// read) inside the window does NOT grant — wait_grant requires the
/// pressed level to hold for two consecutive samples before the
/// released→pressed edge is accepted.
#[test]
fn c5_bounce_single_sample_spike_does_not_grant() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(20_000);
    let mut rt = runtime();
    queue_levels([false, true, false, false, false, false]);
    assert!(
        !rt.wait_grant(0x002A_9E9A, 15_000, paced_level),
        "a one-sample spike must not arm a grant"
    );
}

// ---------------------------------------------------------------------------
// US-921: the keepalive-driven cross-call consent window — the runtime
// machinery the HID task's UpRequired loop and the CCID consumers drive.
// ---------------------------------------------------------------------------

/// US-921 `TouchWindow` (pure policy piece): `open` stamps the CTAP touch
/// budget from `now_ms`; `expired` is the HID loop's exit bound (the
/// platform deadline governs the actual grant window; this only bounds the
/// keepalive loop).
#[test]
fn touch_window_open_and_expiry_arithmetic() {
    let w = TouchWindow::open(0x0102_0304, 1_000);
    assert_eq!(w.tag, 0x0102_0304);
    assert_eq!(w.deadline_ms, 1_000 + super::CTAP_TOUCH_WINDOW_MS);
    assert!(!w.expired(1_000), "freshly opened window is not expired");
    assert!(!w.expired(w.deadline_ms - 1));
    assert!(w.expired(w.deadline_ms), "expired exactly at the deadline");
}

/// `u2f_up_refusal`: exactly the two UP-refusal response shapes — the U2F
/// CONDITIONS_NOT_SATISFIED status word and the US-908 enforce-mode NOT
/// PRESENT payload — never a success or any longer frame.
#[test]
fn u2f_up_refusal_matches_only_refusal_shapes() {
    assert!(u2f_up_refusal(&[0x69, 0x85]), "6985 = conditions not satisfied");
    assert!(u2f_up_refusal(&[0x07, 0x00]), "0700 = not present (US-908)");
    assert!(!u2f_up_refusal(&[0x90, 0x00]), "success is not a refusal");
    assert!(!u2f_up_refusal(&[]), "empty is not a refusal");
    assert!(!u2f_up_refusal(&[0x69]), "truncated is not a refusal");
    assert!(
        !u2f_up_refusal(&[0x69, 0x85, 0x00]),
        "a longer frame is not the bare refusal"
    );
    assert!(!u2f_up_refusal(&[0x6A, 0x80]), "wrong-data is not an UP refusal");
}

/// `window_grant` (CCID consumers, join-or-open): with nothing pending it
/// opens a CCID-window slot under the tag and lights the touch prompt; a
/// press arms inside the window; the grant consumes and the slot frees.
#[test]
fn window_grant_opens_window_and_grants_on_press() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(1_000);
    let mut rt = runtime();
    // First call: no press yet → refused, but the window stays open.
    assert!(
        !rt.window_grant(0x1C),
        "no press inside the window must refuse"
    );
    assert_eq!(
        rt.pending_tag(),
        Some(0x1C),
        "the window must stay open until its deadline"
    );

    // The user presses inside the window: the retry grants, consumes the
    // grant, releases the slot and clears the prompt.
    emul_inject_press();
    tick_to(2_000);
    assert!(rt.window_grant(0x1C), "a press inside the window must grant");
    assert_eq!(rt.pending_tag(), None, "the window closes on the grant");
}

/// `window_grant` never steals another command's slot: pending for a
/// different tag ⇒ refused, slot untouched, nothing armed for the thief.
#[test]
fn window_grant_never_steals_another_tags_window() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(1_000);
    let mut rt = runtime();
    assert!(rt.begin_request(0x1E), "mgmt RESET holds the slot");
    emul_inject_press();
    assert!(rt.poll_press(), "the press arms for its pending tag");
    assert!(
        !rt.window_grant(0x1C),
        "a foreign pending slot must not be stolen"
    );
    assert_eq!(rt.pending_tag(), Some(0x1E), "the owner keeps the slot");
    assert!(
        rt.request(0x1E).is_some(),
        "the armed grant must not be burned by the refused join"
    );
    rt.end_request(0x1E);
}

/// `window_grant` expiry: a window left open past its deadline closes
/// lazily — and a press the button task drains AFTER the deadline is
/// discarded by that drain (it arms nothing anywhere), so the retry finds
/// only a fresh, press-less window.
#[test]
fn window_grant_expires_lazily_and_reopens_fresh() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(1_000);
    let mut rt = runtime();
    assert!(!rt.window_grant(0x04), "oath RESET opens the window");
    // The press arrives AFTER the CCID window deadline: the button task's
    // drain expires the window first (lazy close) — the press finds
    // nothing pending and is discarded.
    tick_to((1_000 + CCID_WINDOW_MS) as u32);
    emul_inject_press();
    assert!(
        !rt.poll_press(),
        "the drain after the deadline must discard the late press"
    );
    assert_eq!(
        rt.pending_tag(),
        None,
        "the drain's expiry sweep must have closed the stale window"
    );
    // The retry re-opens a FRESH window (join-or-open), finds no press and
    // refuses; the late press armed nothing and cannot resurrect.
    assert!(
        !rt.window_grant(0x04),
        "a drained late press must never grant on the retry"
    );
    assert_eq!(
        rt.pending_tag(),
        Some(0x04),
        "the retry holds a fresh window slot"
    );
    rt.end_request(0x04);
}

/// `grant_in_window` (join-only — the FIDO app's injected closure): it
/// never begins or ends the slot; it only expires, polls one press and
/// consumes a grant already bound to its tag.
#[test]
fn grant_in_window_joins_never_begins_or_ends() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(1_000);
    let mut rt = runtime();

    // Nothing pending: join is refused and opens NOTHING.
    emul_inject_press();
    assert!(
        !rt.grant_in_window(0x11),
        "join-only: nothing pending ⇒ nothing to consume"
    );
    assert_eq!(
        rt.pending_tag(),
        None,
        "grant_in_window must never begin a slot"
    );

    // A pending request arms a grant; the join consumes it and leaves the
    // slot exactly as it found it.
    assert!(rt.begin_request(0x11));
    emul_inject_press();
    assert!(rt.grant_in_window(0x11), "the armed grant serves its tag");
    assert_eq!(
        rt.pending_tag(),
        Some(0x11),
        "grant_in_window must never end the slot"
    );
    rt.end_request(0x11);
}

/// `grant_in_window` never burns a foreign tag's armed grant (a mismatched
/// request fails without consuming) — the legitimate owner keeps it.
#[test]
fn grant_in_window_mismatch_does_not_burn_the_grant() {
    let _g = TEST_LOCK.lock().unwrap();
    tick_to(1_000);
    let mut rt = runtime();
    assert!(rt.begin_request(0x1E));
    emul_inject_press();
    assert!(!rt.grant_in_window(0x1C), "tag 0x1C is not the owner");
    assert!(rt.request(0x1E).is_some(), "the owner keeps its grant");
    rt.end_request(0x1E);
}

// --- US-921 review (P0-1): the HID/CCID tag domains are disjoint ----------

/// US-921 review (P0-1): the HID tag space is domain-separated (bit 31 set,
/// `presence_tag_from_channel`) from the CCID consumers' small-integer tags
/// — a same-tag "join" can no longer cross the transport boundary. In the
/// old scheme an allocated HID channel eventually equaled a CCID presence
/// tag (e.g. OATH RESET's raw 0x04 vs HID channel [0,0,0,4]) and
/// `window_grant`'s same-tag join let a CCID destructive command consume a
/// press consented to a FIDO touch. The existing foreign-tag refusal stays
/// green in BOTH directions across the domain boundary.
#[test]
fn hid_and_ccid_tag_domains_never_join() {
    use fapico2_fido::presence_tag_from_channel;
    let _g = TEST_LOCK.lock().unwrap();

    // The helper's domain separation: raw tag 0x04 (OATH RESET) is NOT the
    // consent tag of HID channel [0,0,0,4] — the latter carries bit 31.
    assert_eq!(presence_tag_from_channel([0, 0, 0, 4]), 0x8000_0004);
    assert_ne!(0x04, presence_tag_from_channel([0, 0, 0, 4]));
    // Nor does the CCID bridge channel [0,0,0,1] alias (the allocator no
    // longer issues it either — see ctap_hid.rs).
    assert_ne!(0x01, presence_tag_from_channel([0, 0, 0, 1]));

    tick_to(1_000);
    let mut rt = runtime();
    let hid_tag = presence_tag_from_channel([0, 0, 0, 4]);

    // HID side: the FIDO window for HID channel 4 holds the slot and a
    // press armed for it.
    assert!(rt.begin_window(hid_tag, 30_000));
    emul_inject_press();
    assert!(rt.poll_press(), "the press arms for the HID window's tag");
    // CCID side: OATH RESET's RAW tag 0x04 only LOOKS identical in the old
    // scheme — it must NOT join the HID window (no cross-transport theft).
    assert!(
        !rt.window_grant(0x04),
        "raw CCID tag 0x04 must not join the HID channel-4 window"
    );
    assert_eq!(
        rt.pending_tag(),
        Some(hid_tag),
        "the HID owner keeps the slot"
    );
    assert!(
        rt.request(hid_tag).is_some(),
        "the armed FIDO grant survives the refused CCID join"
    );
    rt.end_request(hid_tag);

    // Reverse direction: a CCID window under raw 0x04 is not joinable by
    // the HID tag either — the FIDO side cannot launder a CCID consent.
    tick_to(2_000);
    assert!(!rt.window_grant(0x04), "OATH RESET opens its own window");
    assert_eq!(rt.pending_tag(), Some(0x04));
    emul_inject_press();
    assert!(
        !rt.grant_in_window(hid_tag),
        "the HID tag must not join the CCID 0x04 window"
    );
    assert!(
        rt.request(0x04).is_some(),
        "the armed CCID grant survives the refused HID join"
    );
    rt.end_request(0x04);
}

// --- touch-prompt hook -----------------------------------------------------

/// The hook recorder (a `fn(bool)` cannot capture, so a static log under
/// the test lock).
static PROMPT_LOG: StdMutex<VecDeque<bool>> = StdMutex::new(VecDeque::new());

fn record_prompt(on: bool) {
    PROMPT_LOG.lock().unwrap().push_back(on);
}

fn prompt_log_snapshot() -> VecDeque<bool> {
    PROMPT_LOG.lock().unwrap().clone()
}

/// US-921: the touch-prompt hook is write-once (`set_touch_prompt_hook`
/// returns `false` on a later call) and `touch_prompt` forwards to it —
/// the HID/CCID window lights the LED on open and clears it on exit.
#[test]
fn touch_prompt_hook_is_write_once_and_forwarded() {
    let _g = TEST_LOCK.lock().unwrap();
    // First install wins (this is the only test that installs the hook).
    assert!(
        set_touch_prompt_hook(Some(record_prompt)),
        "the first hook install must win"
    );
    assert!(
        !set_touch_prompt_hook(Some(record_prompt)),
        "the hook is write-once — a second install must be refused"
    );

    let mut rt = runtime();
    rt.touch_prompt(true);
    rt.touch_prompt(false);
    let log = prompt_log_snapshot();
    assert!(log.back() == Some(&false));
    assert!(log.iter().any(|&v| v), "a true (light) call must be recorded");

    // The window helpers drive the hook: an open window lights the prompt
    // and a granted touch clears it.
    PROMPT_LOG.lock().unwrap().clear();
    tick_to(1_000);
    let mut rt = runtime();
    assert!(!rt.window_grant(0x1C), "no press: refused, window open");
    assert_eq!(
        prompt_log_snapshot().back().copied(),
        Some(true),
        "opening the window lights the prompt"
    );
    emul_inject_press();
    tick_to(2_000);
    assert!(rt.window_grant(0x1C));
    assert_eq!(
        prompt_log_snapshot().back().copied(),
        Some(false),
        "the grant clears the prompt"
    );

    // US-921 review (P2-3): the drain's lazy expiry sweep clears the
    // prompt — a window abandoned past its deadline closes in the button
    // task's tick (poll_press), which the CCID host may never revisit.
    PROMPT_LOG.lock().unwrap().clear();
    tick_to(20_000);
    let mut rt = runtime();
    assert!(
        !rt.window_grant(0x1C),
        "no press: refused, but the window stays open"
    );
    assert_eq!(
        prompt_log_snapshot().back().copied(),
        Some(true),
        "the new window lights the prompt"
    );
    tick_to((20_000 + CCID_WINDOW_MS + 500) as u32);
    assert!(!rt.poll_press(), "no press at the sweep tick");
    assert_eq!(
        prompt_log_snapshot().back().copied(),
        Some(false),
        "the drain's expiry sweep must clear the stale window's prompt"
    );
    assert_eq!(rt.pending_tag(), None, "the sweep freed the slot");

    // US-921 review finding 1: the CCID touch prompt is asserted once at
    // window open, and the heartbeat task + trussed Processing→Idle
    // bracketing stomp it within tens of ms — the hardware probe saw the
    // prompt as invisible. The button task's 10 ms tick (`poll_press`)
    // re-asserts the prompt while a request is pending; expiry still
    // clears it and nothing re-asserts after the window closes.
    tick_to(30_000);
    let mut rt = runtime();
    assert!(!rt.window_grant(0x1C), "no press: refused, window open");
    PROMPT_LOG.lock().unwrap().clear();
    tick_to(31_000);
    assert!(!rt.poll_press(), "no press inside the window");
    assert_eq!(
        prompt_log_snapshot().back().copied(),
        Some(true),
        "an in-window tick must re-assert the prompt"
    );
    tick_to(32_000);
    assert!(!rt.poll_press());
    assert_eq!(prompt_log_snapshot().back().copied(), Some(true));
    tick_to((32_000 + CCID_WINDOW_MS + 500) as u32);
    assert!(!rt.poll_press(), "the sweep tick closes the expired window");
    assert_eq!(
        prompt_log_snapshot().back().copied(),
        Some(false),
        "the sweep clears the prompt"
    );
    PROMPT_LOG.lock().unwrap().clear();
    assert!(!rt.poll_press());
    assert_eq!(
        prompt_log_snapshot().back().copied(),
        None,
        "nothing pending: no prompt record at all"
    );
}

// --- US-1020: the presence handshake, instrumented -------------------------

/// The event recorder. A `fn(PresenceEvent)` cannot capture, so the sink
/// pushes into a static log — under its OWN mutex, never `TEST_LOCK`: the
/// hook fires from inside a test that already holds `TEST_LOCK`, and a
/// `std::sync::Mutex` is not reentrant.
static EVENT_LOG: StdMutex<VecDeque<super::PresenceEvent>> = StdMutex::new(VecDeque::new());

fn record_event(ev: super::PresenceEvent) {
    EVENT_LOG.lock().unwrap().push_back(ev);
}

fn event_log_take() -> Vec<super::PresenceEvent> {
    EVENT_LOG.lock().unwrap().drain(..).collect()
}

/// US-1020, red first: a press with nothing pending emits `Press` +
/// `Discarded` and arms nothing; opening a cross-call window emits
/// `Window` under its tag; a press inside the window emits `Press` + `Armed`
/// bound to that tag; consuming the grant emits `Grant` carrying the
/// **touch→consent latency** — the clock from the arm to the consume, not a
/// number the test supplies.
///
/// It runs on the injected [`LatchSource`] (the same one the device button
/// task drains) and the manual clock, so it is a host parity test of the
/// whole instrumentation, not of a mock of it.
#[test]
fn presence_events_are_stamped_per_grant() {
    use super::{PresenceEventKind as K, PresenceStats};
    let _g = TEST_LOCK.lock().unwrap();
    let _ = event_log_take(); // drop anything an earlier test left

    // The sink is write-once, and this is the only test that installs it.
    assert!(
        super::set_presence_event_hook(Some(record_event)),
        "the first event-hook install must win"
    );
    assert!(
        !super::set_presence_event_hook(Some(record_event)),
        "the event hook is write-once — a second install must be refused"
    );

    tick_to(1_000);
    let mut rt = runtime();
    assert_eq!(rt.stats(), PresenceStats::default(), "a fresh runtime is zeroed");

    // 1. A press with nothing pending: the press is seen, and it arms
    //    nothing anywhere. Both halves of the anti-harvest rule are events.
    emul_inject_press();
    assert!(!rt.poll_press());
    let evs = event_log_take();
    assert_eq!(
        evs,
        vec![
            super::PresenceEvent {
                kind: K::Press,
                tag: 0,
                now_ms: 1_000,
                delta_ms: 0,
            },
            super::PresenceEvent {
                kind: K::Discarded,
                tag: 0,
                now_ms: 1_000,
                delta_ms: 0,
            },
        ],
        "a harvest press must be recorded as seen-then-discarded, with the clock"
    );
    let s = rt.stats();
    assert_eq!((s.presses, s.discarded, s.armed, s.grants), (1, 1, 0, 0));
    assert_eq!(s.last_press_ms, 1_000, "the press is stamped on the clock");

    // 2. The cross-call window opens — one `Window` event under its tag.
    assert!(rt.begin_window(0x8000_0004, super::CTAP_TOUCH_WINDOW_MS));
    let evs = event_log_take();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, K::Window);
    assert_eq!(evs[0].tag, 0x8000_0004, "the window event names the tag");
    assert_eq!(rt.stats().windows, 1);

    // 3. A press inside the window arms a grant bound to the window's tag.
    tick_to(1_250);
    emul_inject_press();
    assert!(rt.poll_press(), "a press inside the window must arm");
    let evs = event_log_take();
    assert_eq!(
        evs.iter().map(|e| e.kind).collect::<Vec<_>>(),
        vec![K::Press, K::Armed]
    );
    assert_eq!(evs[1].now_ms, 1_250, "the arm is stamped when it happened");
    assert_eq!(evs[1].tag, 0x8000_0004, "a grant serves only the pending tag");

    // 4. The app's join consumes it 90 ms later — the touch→consent latency
    //    is the runtime's own subtraction, and the Grant event carries it.
    tick_to(1_340);
    assert!(rt.grant_in_window(0x8000_0004));
    let evs = event_log_take();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, K::Grant);
    assert_eq!(evs[0].tag, 0x8000_0004);
    assert_eq!(evs[0].now_ms, 1_340, "the grant is stamped at consumption");
    assert_eq!(
        evs[0].delta_ms, 90,
        "touch→consent latency is measured on the runtime clock, not supplied"
    );
    let s = rt.stats();
    assert_eq!(s.grants, 1);
    assert_eq!(s.last_arm_to_grant_ms, 90, "the same figure, counted");
    assert_eq!(s.last_arm_ms, 1_250);
    assert_eq!(s.last_grant_ms, 1_340);
    assert_eq!(s.last_tag, 0x8000_0004);

    // 5. A foreign tag cannot consume the same arm's grant, so no second
    //    `Grant` is emitted — the event stream cannot over-report consent.
    emul_inject_press();
    rt.poll_press();
    let _ = event_log_take();
    assert!(!rt.grant_in_window(0x11), "a foreign tag must not be served");
    assert!(event_log_take().is_empty(), "a refused join emits no Grant");
    assert_eq!(rt.stats().grants, 1, "the grant count did not move");
    rt.end_request(0x8000_0004);
}

/// The CCID consumers' join-or-open window is instrumented on the same
/// clock: one `Window` event on the open, and a `Grant` whose latency is
/// measured from the arm — not from the (earlier) open, which is the number
/// a "how long did the user have to press?" argument would wrongly quote.
#[test]
fn ccid_window_grant_is_instrumented_on_the_same_clock() {
    let _g = TEST_LOCK.lock().unwrap();

    tick_to(4_000);
    let mut rt = runtime();
    // This one asserts the COUNTERS, not the event log: the hook slot is
    // write-once and the test above owns it, so which of the two sees a
    // sink depends on the runner's order. The counters are the half that is
    // unconditional — the half that survives into a release build, where no
    // hook is installed at all.
    assert!(!rt.window_grant(0x1C), "no press: refused, window open");
    assert_eq!(rt.stats().windows, 1, "the open is counted");

    tick_to(4_400);
    emul_inject_press();
    assert!(rt.poll_press());
    assert_eq!(rt.stats().armed, 1);
    assert_eq!(rt.stats().last_arm_ms, 4_400);

    tick_to(4_500);
    assert!(rt.window_grant(0x1C), "the retry inside the window grants");
    let s = rt.stats();
    assert_eq!(s.grants, 1);
    assert_eq!(
        s.last_arm_to_grant_ms, 100,
        "latency is arm→grant, not open→grant"
    );
    assert_eq!(s.last_tag, 0x1C);
}

// --- US-1021: the cross-call keepalive window, gated ---------------------

/// US-1021: the device button task's tick period. `button.rs`:
///
/// ```text
/// fapico2_firmware::presence::drain_press();
/// Timer::after_millis(10).await;
/// ```
///
/// This is the number the story is about — the cadence at which the BOOTSEL
/// pad is *sampled*, and therefore the shortest press that can possibly be
/// seen at all.
const BUTTON_TICK_MS: u32 = 10;

/// US-1021: the keepalive loop's park between two re-drives of the command
/// (`tasks.rs`: `Timer::after_millis(CTAP_KEEPALIVE_PERIOD_MS).await`). The
/// park is the *only* place the serve task yields inside the window, and
/// therefore the only place the button task can run.
const KEEPALIVE_PARK_MS: u32 = 100;

/// The modelled BOOTSEL pad: half-open `[from, to)` press intervals in ms.
/// The device's real level comes from the QSPI-CS pad read; everything the
/// runtime does with a level is what is under test here, so the pad itself
/// is the model and the sampling cadence is [`BUTTON_TICK_MS`].
static PAD: StdMutex<Vec<(u32, u32)>> = StdMutex::new(Vec::new());

fn set_pad(intervals: &[(u32, u32)]) {
    *PAD.lock().unwrap() = intervals.to_vec();
}

fn pad_pressed_at(now: u32) -> bool {
    PAD.lock().unwrap().iter().any(|(a, b)| now >= *a && now < *b)
}

/// The runtime the FIDO app's injected gate closes over. A `fn` pointer
/// cannot capture, so the gate reaches the runtime through this slot — the
/// same `static mut` + write-once discipline the device uses for
/// `RUNTIME_SLOT`, and the same `TEST_LOCK` serialization.
static mut APP_RT: Option<PresenceRuntime<LatchSource>> = None;

fn install_app_runtime(now_ms: u32) {
    tick_to(now_ms);
    unsafe {
        // SAFETY: every test in this module holds `TEST_LOCK`, and the app's
        // gate is only ever called from the test thread that installed it.
        core::ptr::addr_of_mut!(APP_RT).write(Some(runtime()));
    }
}

fn with_app_rt<R>(f: impl FnOnce(&mut PresenceRuntime<LatchSource>) -> R) -> R {
    // SAFETY: as `install_app_runtime` — `TEST_LOCK` is held.
    unsafe { f((*core::ptr::addr_of_mut!(APP_RT)).as_mut().expect("runtime installed")) }
}

/// The FIDO app's device presence gate — the same closure `main` installs on
/// the app (`fapico2_firmware::presence::request_grant_in_window`, the HID
/// side's join-only consumer), over the test runtime instead of the device
/// slot. The body is `PresenceRuntime::grant_in_window`, unchanged.
fn test_grant_in_window(tag: u32) -> bool {
    with_app_rt(|rt| rt.grant_in_window(tag))
}

/// One tick of `button_poll_task`, in behaviour: sample the pad, edge-detect,
/// latch, then drain through the shared runtime. Returns whether the press
/// armed.
fn button_task_tick(was_pressed: &mut bool) -> bool {
    let now = NOW_MS.load(Ordering::SeqCst);
    let pressed = pad_pressed_at(now);
    let edge = pressed && !*was_pressed;
    if edge {
        emul_inject_press();
    }
    *was_pressed = pressed;
    with_app_rt(|rt| rt.poll_press())
}

/// Park for `ms`, running the button task's ticks across it. This is the
/// keepalive's `Timer::after_millis(...)`: the serve task is off the CPU and
/// the button task gets its ticks back.
fn park_button_task(was_pressed: &mut bool, ms: u32) {
    let mut elapsed = 0u32;
    while elapsed < ms {
        elapsed += BUTTON_TICK_MS;
        tick_to(NOW_MS.load(Ordering::SeqCst) + BUTTON_TICK_MS);
        button_task_tick(was_pressed);
    }
}

/// CTAP2 makeCredential (resident, no PIN set) and getAssertion request
/// bodies — the two commands the CBOR arm windows (`up_request` is
/// `ctap_cmd == 0x01 || ctap_cmd == 0x02`).
mod ctap {
    use fapico2_fido::cbor::no_heap as nh;
    use heapless::Vec as HV;

    pub fn make_credential() -> Vec<u8> {
        let mut r: HV<u8, 512> = HV::new();
        nh::push_map_header(&mut r, 5).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_bstr(&mut r, &[0xCC; 32]).unwrap();
        nh::push_uint(&mut r, 2).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_tstr(&mut r, "example.com").unwrap();
        nh::push_uint(&mut r, 3).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        // `user.id` is a byte string (the user *handle*), not a text
        // string: `parse_mc`'s key-3 arm takes `Item::B` for `id` and
        // answers `0x12` (InvalidCbor) on a text string.
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_bstr(&mut r, b"user-1").unwrap();
        nh::push_uint(&mut r, 4).unwrap();
        nh::push_array_header(&mut r, 1).unwrap();
        nh::push_map_header(&mut r, 2).unwrap();
        nh::push_tstr(&mut r, "type").unwrap();
        nh::push_tstr(&mut r, "public-key").unwrap();
        nh::push_tstr(&mut r, "alg").unwrap();
        nh::push_neg(&mut r, -7).unwrap();
        nh::push_uint(&mut r, 7).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "rk").unwrap();
        nh::push_bool(&mut r, true).unwrap();
        r.as_slice().to_vec()
    }

    pub fn get_assertion() -> Vec<u8> {
        let mut r: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut r, 2).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "example.com").unwrap();
        nh::push_uint(&mut r, 2).unwrap();
        nh::push_bstr(&mut r, &[0xDD; 32]).unwrap();
        r.as_slice().to_vec()
    }
}

const MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;

/// The CTAPHID CBOR arm of `firmware/src/tasks.rs::dispatch_hid_cmd`,
/// modelled: one dispatch; and, when `windowed`, the lazy cross-call
/// consent window on a bare one-byte `UpRequired` answer — open the slot
/// under the channel-derived tag, then alternate *park* (the keepalive's
/// `Timer::after_millis(CTAP_KEEPALIVE_PERIOD_MS)`, across which the button
/// task runs its [`BUTTON_TICK_MS`] ticks) with *re-drive* until the answer
/// is no longer `UpRequired` or the [`TouchWindow`] runs out.
///
/// `windowed: false` is the **single synchronous poll** this window
/// replaced: the command runs once, the serve task never yields, the button
/// task never runs, and the answer goes out as `UpRequired`.
fn ctap_cbor_arm(
    app: &mut fapico2_fido::FidoApp,
    cmd: u8,
    req: &[u8],
    channel: [u8; 4],
    out: &mut heapless::Vec<u8, MAX_MSG>,
    windowed: bool,
) -> (u8, u32) {
    use fapico2_fido::presence_tag_from_channel;
    let up = UpRequired.code();
    let mut len = app.process_ctap2(cmd, req, channel, out);
    let mut re_drives = 0u32;
    if !windowed || len != 1 || out[0] != up {
        return (out[0], re_drives);
    }
    let tag = presence_tag_from_channel(channel);
    if !with_app_rt(|rt| rt.begin_window(tag, super::CTAP_TOUCH_WINDOW_MS)) {
        return (out[0], re_drives);
    }
    let mut was_pressed = false;
    loop {
        let now = u64::from(NOW_MS.load(Ordering::SeqCst));
        // The device's real bound is the 30 s `TouchWindow`; the cap is a
        // test guard so a model that stops granting fails in milliseconds
        // instead of burning 300 expensive re-drives.
        if TouchWindow::open(tag, now).expired(now) || re_drives >= 8 {
            with_app_rt(|rt| rt.end_request(tag));
            break;
        }
        park_button_task(&mut was_pressed, KEEPALIVE_PARK_MS);
        len = app.process_ctap2(cmd, req, channel, out);
        re_drives += 1;
        if len != 1 || out[0] != up {
            with_app_rt(|rt| rt.end_request(tag));
            break;
        }
    }
    (out[0], re_drives)
}

use fapico2_fido::ctap2::Ctap2Response::UpRequired;

/// US-1021, the story's claim: **a press shorter than the button task's
/// 10 ms tick still grants, through the cross-call window.**
///
/// The real stack is under test — the real `FidoApp`, its real
/// channel-derived presence tag, the real `PresenceRuntime` behind the same
/// `fn` closure `main.rs` installs — over a modelled pad and a modelled
/// keepalive park. The press is **5 ms long, half a button tick**, placed so
/// the tick at t=50 ms samples it.
///
/// The two halves are two independent sessions, so each one's counters are
/// unambiguous. A real device runs the second one: it is the first one with
/// the cross-call window in place.
///
/// What the window buys, as the contrast the test actually runs:
///
/// * **No window.** The serve task yields nowhere inside a command, so the
///   button task does not run while the command is in flight. The command
///   polls the press *latch* once, at t=0, and the latch is empty — the pad
///   has not been sampled since the user did anything. The command answers
///   `0x3B` and goes out. The pad sample the button task finally takes at
///   t=50 arrives **after** the command is over, with nothing pending, so it
///   arms nothing: the press is seen and discarded. That is the board's
///   report — `0x3B UP_REQUIRED`, every time.
/// * **Window.** The park between two re-drives *is* the yield. The button
///   task's 10 ms ticks run across it, the pad sample at t=50 latches the
///   5 ms press and the drain arms a grant for the window's tag, and the
///   app's own re-drive — its real `user_present`, joining with
///   `grant_in_window` — consumes it.
#[test]
fn sub_tick_press_grants_through_the_keepalive_window() {
    let _g = TEST_LOCK.lock().unwrap();
    use fapico2_platform::{secure_store::HostSecureStore, trng::HostTrng};
    const CHANNEL: [u8; 4] = [0x00, 0x00, 0x00, 0x07];
    let mut out: heapless::Vec<u8, MAX_MSG> = heapless::Vec::new();
    let mut was_pressed = false;

    // --- session 1: the single synchronous poll this window replaced -----
    {
        let mut trng = HostTrng::new();
        let mut store = HostSecureStore::new();
        let mut app = fapico2_fido::FidoApp::boot(&mut trng, &mut store)
            .unwrap()
            .with_presence_grant(test_grant_in_window);
        install_app_runtime(0);
        // The 5 ms press starts at t=46 — after the command is dispatched,
        // and inside the tick gap the button task would sample at t=50.
        set_pad(&[(46, 51)]);

        let (status, re_drives) =
            ctap_cbor_arm(&mut app, 0x02, &ctap::get_assertion(), CHANNEL, &mut out, false);
        assert_eq!(re_drives, 0, "there is no loop to re-drive");
        assert_eq!(
            status,
            UpRequired.code(),
            "the single synchronous poll cannot see a press that has not happened yet"
        );
        // The button task's next tick *does* sample the press — it simply
        // arrives with nothing pending, so it arms nothing. This is the
        // whole failure mode, and it is invisible without the counters.
        park_button_task(&mut was_pressed, 60);
        let s = with_app_rt(|rt| rt.stats());
        assert_eq!(s.windows, 0, "no cross-call window was ever opened");
        assert_eq!(s.presses, 1, "the pad sample did happen");
        assert_eq!(
            s.discarded, 1,
            "and it armed nothing: nothing was pending by then"
        );
        assert_eq!(s.armed, 0);
        assert_eq!(s.grants, 0, "no touch became consent — 0x3B is the answer");
    }

    // --- session 2: the same press, one keepalive window later -----------
    {
        let mut trng = HostTrng::new();
        let mut store = HostSecureStore::new();
        let mut app = fapico2_fido::FidoApp::boot(&mut trng, &mut store)
            .unwrap()
            .with_presence_grant(test_grant_in_window);
        install_app_runtime(0);
        set_pad(&[(46, 51)]); // the same 5 ms, at the same place on the clock

        let (status, re_drives) =
            ctap_cbor_arm(&mut app, 0x02, &ctap::get_assertion(), CHANNEL, &mut out, true);
        assert_eq!(re_drives, 1, "one park was enough to arm the grant");
        assert_ne!(
            status,
            UpRequired.code(),
            "the 5 ms press granted through the window — the command got past presence"
        );
        let s = with_app_rt(|rt| rt.stats());
        assert_eq!(s.windows, 1, "exactly one cross-call window was opened");
        assert_eq!(s.armed, 1, "the button task armed one grant for it");
        assert_eq!(s.grants, 1, "and the app's re-drive consumed it");
        assert_eq!(
            s.last_tag,
            fapico2_fido::presence_tag_from_channel(CHANNEL),
            "the grant served the tag the app derives from its own channel"
        );
        assert_eq!(
            s.last_arm_ms, 50,
            "armed by the button sample at t=50 ms, inside the 5 ms press"
        );
        assert_eq!(s.last_grant_ms, 100, "consumed by the re-drive after the park");
        assert_eq!(
            s.last_arm_to_grant_ms, 50,
            "touch->consent latency is one keepalive period — the US-1020 measurement"
        );
    }
}

/// The window end to end, with nothing left to it: a **resident credential
/// is minted through a windowed makeCredential and then a getAssertion signs
/// through a second one** — both `0x00`, both driven by presses shorter than
/// the button task's 10 ms tick.
///
/// The other tests in this group stop at "the command got past presence",
/// which is a weaker claim than it looks: any non-`UpRequired` answer would
/// satisfy it. This one is the story's claim in full — a touch became
/// consent, and consent produced an assertion.
#[test]
fn windowed_make_credential_and_assertion_both_sign() {
    let _g = TEST_LOCK.lock().unwrap();
    use fapico2_platform::{secure_store::HostSecureStore, trng::HostTrng};
    const CHANNEL: [u8; 4] = [0x00, 0x00, 0x00, 0x09];
    let mut out: heapless::Vec<u8, MAX_MSG> = heapless::Vec::new();

    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut app = fapico2_fido::FidoApp::boot(&mut trng, &mut store)
        .unwrap()
        .with_presence_grant(test_grant_in_window);
    install_app_runtime(0);

    // Two 4 ms presses, one per command, each straddling a button sample.
    // The MC's window runs 0..100; the GA's opens at t=100, so its press
    // sits in the second window's first park (samples 110..200).
    set_pad(&[(46, 51), (146, 151)]);

    let (mc, mc_drives) =
        ctap_cbor_arm(&mut app, 0x01, &ctap::make_credential(), CHANNEL, &mut out, true);
    assert_eq!(mc_drives, 1);
    assert_eq!(mc, 0x00, "makeCredential answered with a credential, not a refusal");

    let (ga, ga_drives) =
        ctap_cbor_arm(&mut app, 0x02, &ctap::get_assertion(), CHANNEL, &mut out, true);
    assert_eq!(ga_drives, 1);
    assert_eq!(
        ga, 0x00,
        "getAssertion signed: the window turned a sub-tick touch into consent"
    );
    // The reply really is an assertion, not an empty success: CBOR map,
    // key 1 = credential descriptor, key 2 = authData, key 3 = signature.
    assert!(
        out.len() > 8 && out[0] == 0x00,
        "a bare status byte would not be an assertion (len {})",
        out.len()
    );

    let s = with_app_rt(|rt| rt.stats());
    assert_eq!(s.windows, 2, "one window per command, both closed on the grant");
    assert_eq!(s.grants, 2, "two touches became consent");
    assert_eq!(s.armed, 2);
    assert_eq!(
        s.last_tag,
        fapico2_fido::presence_tag_from_channel(CHANNEL),
        "both grants served the one tag the app derives from its channel"
    );
    // One window is never a second grant: a fresh getAssertion with no
    // fresh touch must be refused again.
    let (ga2, _) = ctap_cbor_arm(&mut app, 0x02, &ctap::get_assertion(), CHANNEL, &mut out, false);
    assert_eq!(
        ga2,
        UpRequired.code(),
        "a spent window grants nothing: consent is per command"
    );
    assert_eq!(with_app_rt(|rt| rt.stats().grants), 2);
}

/// The honest boundary of the story's claim, pinned so nobody reads the test
/// above as "the window catches any press".
///
/// A press that falls **entirely between two button samples** is invisible
/// to every path: the pad is edge-detected by *sampling*, and no amount of
/// window will manufacture a sample that the 10 ms tick did not take. Over
/// the 30 s window there are 3,000 samples, so a real press is missed with
/// probability ~(1 - dur/tick)^3000 — but a 4 ms press on its own is a coin
/// flip, and the window's contribution is that a user who presses again
/// gets caught immediately rather than never.
///
/// What the window changes for this press is from **never** to **usually**.
/// That is the finding US-1022 measures, and it is why the measurement
/// exists: a device that refuses every assertion is this test's first case,
/// and a device that occasionally misses a very short tap is this one.
#[test]
fn a_press_between_two_button_samples_is_invisible_to_every_path() {
    let _g = TEST_LOCK.lock().unwrap();
    use fapico2_platform::{secure_store::HostSecureStore, trng::HostTrng};

    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut app = fapico2_fido::FidoApp::boot(&mut trng, &mut store)
        .unwrap()
        .with_presence_grant(test_grant_in_window);
    install_app_runtime(0);
    let channel = [0x00, 0x00, 0x00, 0x08];

    // Samples land at 10, 20, 30 …; this press occupies (52, 56) — inside
    // the gap between the 50 ms and 60 ms samples.
    set_pad(&[(52, 56), (160, 165)]);
    let mut out: heapless::Vec<u8, MAX_MSG> = heapless::Vec::new();
    let (status, re_drives) = ctap_cbor_arm(
        &mut app,
        0x02,
        &ctap::get_assertion(),
        channel,
        &mut out,
        true,
    );
    assert_eq!(
        re_drives, 2,
        "park 1 (samples 10..100) missed the sub-gap press; park 2 (samples \
         110..200) caught the re-press at 160"
    );
    assert_ne!(status, UpRequired.code());
    let s = with_app_rt(|rt| rt.stats());
    assert_eq!(
        s.armed, 1,
        "only the re-press was ever sampled — the sub-gap press armed nothing"
    );
}

/// The host model above assumes a *shape* for the device's consent path:
/// that it is entered on a bare one-byte `UpRequired` answer, that it opens
/// the cross-call window under the channel-derived tag, that it yields for
/// about `CTAP_KEEPALIVE_PERIOD_MS` at a time, and that it re-drives the
/// same command inside the window. Model that shape wrongly and every
/// assertion above is about the model.
///
/// So the shape is pinned against the source. This is a source scan, and
/// it is a weak one — it cannot see a behavioural change, only a removed
/// or renamed step — but it is what stops the model and the device from
/// drifting apart silently, which is the failure mode a hand-written model
/// has and a shared function does not.
///
/// **US-1509 moved the subject.** The consent path is no longer inline in
/// `tasks.rs`'s CBOR arm; it is the parked slot in `firmware/src/hid_serve.rs`,
/// so this scan reads that file. The pin is also now *stronger* in the one
/// place it matters: the pre-fix arm contained
/// `Timer::after_millis(CTAP_KEEPALIVE_PERIOD_MS).await` inside a `loop`, and
/// that is precisely the inline await US-1509 removed — so its ABSENCE is
/// asserted, not just the steps around it. A test that only pins what is
/// present would pass just as happily against a reintroduced blackout.
///
/// **US-1506 changed the shape, and this pin changed with it.** The step it
/// used to require — `reply(io, channel, CTAP_HID_KEEPALIVE, &[0x02])`, the
/// unconditional *pre-dispatch* keepalive — is exactly the frame US-1506
/// deleted: it claimed "waiting for your touch" before the command had been
/// run, 301 times in a 30 s window. A pin that kept requiring it would have
/// made the removal impossible to make, so the pin now requires the two
/// frames that replaced it (`0x01` at the park, `0x02` rate-limited) and
/// **asserts the old one is absent**. Both halves matter: pinning presence
/// alone would pass against a firmware that emits every frame; pinning
/// absence alone would pass against one that emits none.
#[test]
fn the_device_cbor_arm_still_has_the_shape_the_model_assumes() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/hid_serve.rs"))
        .expect("hid_serve.rs must be readable from the test's own crate");
    // The slice opens at the *arm*, not at `presence_windowed`: the CBOR
    // arm's keepalives sit above the `presence_windowed` binding (the `0x01`
    // is sent inside the `park()` match arm, which is below it), and
    // pinning from the narrower start would have quietly stopped checking
    // them.
    let start = src
        .find("} else if cmd == CTAP_HID_CBOR {")
        .expect("the dispatch must have a CBOR arm");
    let end = src[start..]
        .find("if app.persist() {")
        .map(|i| start + i)
        .expect("the CBOR arm must persist before its reply");
    let arm = &src[start..end];

    for step in [
        "let presence_windowed",
        "Ctap2Response::UpRequired.code()",
        "presence::begin_window(tag, CTAP_TOUCH_WINDOW_MS)",
        // US-1506: the window's first keepalive is `0x01` PROCESSING, sent
        // at the park rather than before the command ran, and its `0x02`s
        // are rate-limited inside `redrive_window`.
        "CTAPHID_KEEPALIVE_PROCESSING",
        "slot.note_keepalive(now_ms());",
        // US-1509: the command is PARKED, not looped on. The slot carries
        // the channel-derived tag and the deadline the model derives from
        // `TouchWindow`, so the model's window budget is the device's.
        "slot.park(ticket, payload)",
        "TouchWindow::open(tag, now_ms()).deadline_ms",
    ] {
        assert!(
            arm.contains(step),
            "the device CBOR arm no longer contains `{step}` — the host model above \
             assumes it, and a model that outlives its subject tests nothing"
        );
    }

    // US-1506's regression pin, the negative half: the unconditional
    // pre-dispatch `0x02` must not come back. It is a bare `&[0x02]` literal
    // at the top of the arm, and its return is the single most-reverted line
    // in this file's history — it was correct once (FX-402 wanted a progress
    // frame) and became a 301-frame lie once a window was parked instead of
    // looped over.
    assert!(
        !arm.contains("CTAP_HID_KEEPALIVE, &[0x02]"),
        "US-1506: the CBOR arm is emitting a bare 0x02 keepalive again. That frame \
         says 'waiting for your touch' and must only be sent once the window is \
         open and a re-drive has found the touch still owed."
    );

    // US-1509's regression pin: the consent arm must not wait. The blackout
    // was exactly `Timer::after_millis(CTAP_KEEPALIVE_PERIOD_MS).await`
    // inline in the arm that had just consumed the inbound read — the whole
    // OUT endpoint went undrained for the length of the window, so a
    // `CTAPHID_CANCEL` could not reach the device at all. Re-asserting this
    // string in the arm means the serve loop has gone back to sleeping here.
    assert!(
        !arm.contains("Timer::after_millis(CTAP_KEEPALIVE_PERIOD_MS).await"),
        "US-1509: the CBOR arm awaits a keepalive period again. The consent path must \
         park the command in `PendingUp` and return to the top of the serve loop, or \
         the loop stops reading the OUT endpoint for the whole window and a \
         CTAPHID_CANCEL cannot reach the device."
    );

    // US-1509's structural claim: the re-drive is the *serve loop's* per-pass
    // work, not a nested one. `redrive_window` holds it, and `serve_once`
    // calls it as its first step — which is what "re-asserted each pass,
    // then back to `hid_out.read()`" means in source. Before US-1509 both
    // lived inside the dispatch arm, one nested `loop` deep.
    let redrive = src
        .find("async fn redrive_window")
        .and_then(|at| src.get(at..).map(|s| at + s.find("app.process_ctap2(").unwrap_or(usize::MAX)))
        .filter(|at| *at != usize::MAX)
        .expect("a re-drive in redrive_window");
    let serve_once = src
        .find("pub async fn serve_once")
        .expect("serve_once must exist");
    let drive_call = src
        .get(serve_once..)
        .and_then(|s| s.find("redrive_window(now_ms,"))
        .map(|i| serve_once + i)
        .expect("serve_once must re-drive the window");
    assert!(
        redrive > serve_once && drive_call < redrive,
        "US-1509: the window's re-drive must be reached from `serve_once` (before it \
         reads the OUT endpoint again), not from inside the dispatch that opened it. \
         A re-drive owned by the dispatch is the old nested loop with a new name."
    );

    // US-921's leak analysis turns on this pairing. `close_window` is the
    // single exit from a window, so `end_window` and the prompt clear cannot
    // be separated by an edit to one caller — but only while both live in
    // that one function. Split them and the pin below is what notices.
    let close = src
        .find("fn close_window")
        .expect("the window must be closed in one place");
    let close_body = &src[close..close + 600];
    for step in ["presence::end_window(ticket.tag)", "presence::touch_prompt(false)"] {
        assert!(
            close_body.contains(step),
            "`close_window` no longer contains `{step}` — every window exit must pair \
             the presence-slot release with the prompt clear. A leaked window holds \
             the single presence slot for the life of the process and no applet can \
             ever grant again."
        );
    }
}
