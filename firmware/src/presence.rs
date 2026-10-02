//! US-921: presence-latch anti-harvest discipline — the device wiring that
//! binds the BOOTSEL press latch to a **pending** grant request.
//!
//! Root cause (US-921 brief): `button.rs`'s sticky latch was consumed by
//! whichever command asked first — a hostile host looping WRITE_CONFIG/RESET
//! could harvest a user's press meant for an unrelated FIDO touch. US-906's
//! `PresenceService` carries the queue discipline (single pending-request
//! slot, tag-bound single-use timed grants, presses with nothing pending
//! discarded); this module is the *wiring*:
//!
//! * [`PRESS_LATCH`] — the raw press edge latch, set by the device button
//!   task (`main.rs`'s `button` module) and by the emulation board-test
//!   hook [`emul_inject_press`].
//! * [`LatchSource`] — the US-906 `PresenceSource` over that latch: one
//!   poll returns and consumes one press edge (no double-report).
//! * [`PresenceRuntime`] — the shared `PresenceService` plus the source and
//!   the injected monotonic clock. The device build owns **one** instance
//!   ([`init`]/[`request_grant`]/[`drain_press`]): the whole runtime's
//!   single user-presence authority (EPIC constraint).
//! * [`request_grant`] — the synchronous one-shot command path: begin the
//!   pending request under the command tag, poll the latch once (a press
//!   during the window arms the grant), consume the grant, release the
//!   slot. Fail-closed without a press.
//! * [`drain_press`] — the button task's idle tick: a press with *no*
//!   pending request is discarded without arming (anti-harvest).
//!
//! # The cross-call consent window (US-921)
//!
//! A one-shot synchronous poll can never arm a grant on hardware: the
//! serve section is non-preemptive and the button task latches + drains
//! the press edge in one 10 ms tick — no human press can ever land
//! between the two. The window machinery closes that:
//!
//! * [`TouchWindow`] — the pure policy piece (`open`/`expired`): the
//!   CTAP2 touch budget a host is granted between the UpRequired reply
//!   and its retry (keepalives stream meanwhile).
//! * [`PresenceRuntime::begin_window`]/[`end_window`] — the HID task's
//!   UpRequired loop owns the window lifecycle: `begin_window` opens the
//!   pending slot under the command tag with the platform deadline, the
//!   keepalive yields let the button task arm a grant, and the app's own
//!   injected closure ([`request_grant_in_window`], join-only) consumes
//!   it inside the loop.
//! * [`PresenceRuntime::window_grant`] — join-or-open for the CCID
//!   consumers (mgmt WRITE_CONFIG/RESET, OATH RESET/SET_CODE-clear): a
//!   cross-call window opens on the first 6985 and stays open until its
//!   deadline, so the user's press on the retry is consent for the retry.
//!   It never steals another command's slot.
//! * [`set_touch_prompt_hook`] — the device touch prompt (the shared
//!   LED_OUT) driven by the window, write-once at boot.
//!
//! The OpenPGP touch-to-sign gate (`button::pso_wait_grant` →
//! [`wait_grant`]) is unchanged: its blocking window already spans the
//! whole wait inside one command.
//!
//! # FIDO-over-CCID stays refuse-only (by design)
//!
//! The CCID dispatcher reaches the FIDO app only through a bridged APDU
//! carrying a fixed channel; a fixed BRIDGE tag would collide with HID
//! channel `0x0001`'s grants (the app derives its tag from
//! `current_channel`). The HID transport is the only FIDO consent path;
//! the CCID-side FIDO entries keep the refuse-only behavior (status-quo-
//! plus: they never granted, they never will).
//!
//! # Emulation hook status
//!
//! [`emul_inject_press`] is currently **host-test-only**: the `fapico2-emulation`
//! bin does not attach the shared runtime (its auto-ack default keeps the
//! existing e2e suites green). Wiring the emulation bin to the runtime with
//! injected presses is deferred to the US-920/US-924 scope.
//!
//! # The presence handshake, instrumented (US-1020)
//!
//! Every arm/discard/grant in this module now emits a [`PresenceEvent`]
//! carrying the runtime's monotonic clock, and accumulates into a
//! [`PresenceStats`] counter block readable with [`PresenceRuntime::stats`]
//! (host) or [`stats`] (device). That block is the **measurement US-1022 is
//! judged against** — in particular `last_arm_to_grant_ms`, the touch→consent
//! latency, which is the number a "did the touch register?" argument actually
//! turns on.
//!
//! ## Where the events are published, and where they are not
//!
//! The EPIC's wording for this story is "exposed through the existing vendor
//! counter channel". **No such channel exists.** `docs/erase-budget.md` §2.3
//! established it on this branch (US-1010) by enumerating the RS-Key `0x41`
//! vendor channel's fourteen sub-commands
//! (`apps/fido/src/vendor41.rs`): not one is a counter or telemetry read, and
//! a fifteenth would be a new transport-facing feature, which this story must
//! not add. So the events are published to the two things that *do* exist:
//!
//! * the **counters**, in-process, unconditionally (`PresenceStats`); and
//! * the **US-922 diagnostic ring** (`firmware/src/dbg.rs`, drained over
//!   CTAPHID vendor command `0x42` on a per-boot random channel) in
//!   `dbg-log` / `apdu-trace` builds only — the device bin installs
//!   [`set_presence_event_hook`], and a release build installs nothing, so
//!   the hook branch is dead code there.
//!
//! Adding a production-readable counter subcommand is recorded as a
//! follow-up, not smuggled in here.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use fapico2_platform::presence::{PresenceService, PresenceSource};

/// US-921: the CTAP2 touch window — how long the UpRequired keepalive
/// loop (tasks.rs / emul_main.rs) keeps the cross-call slot open for a
/// touch. Generous: CTAP2 spec suggests ≥ 30 s for user-action windows.
pub const CTAP_TOUCH_WINDOW_MS: u64 = 30_000;

/// US-921/US-1506: the CTAPHID progress-frame period for a live consent
/// window, in milliseconds.
///
/// **US-1506 moved this from 100 ms to 250 ms.** Both the value and the
/// reason it is a single constant are load-bearing:
///
/// * **250** is the reference's own gate —
///   `pico-keys-sdk/src/usb/hid/hid.c:610-628`, `send_keepalive()`, which
///   returns early `if (last_keepalive_time != 0 && now -
///   last_keepalive_time < 250)`. One number on the reference and one
///   number here, for the same reason: the serve loop bounds its
///   OUT-endpoint read by this period while a window is live
///   (`hid_serve::read_one`), so the period *is* the cadence rather than a
///   knob sitting next to it.
/// * One number governs both, deliberately. Splitting them would let the
///   read bound and the emitted cadence disagree — and the read bound is
///   the `+ CTAP_KEEPALIVE_PERIOD_MS` term in the published serve bound
///   (`hid_serve::SERVE_BOUND_MS`). A cadence that moved without the read
///   bound would silently make that bound a lie, which is exactly the
///   class of unsound derivation the Phase C review caught once already.
///
/// ## The trade-off, stated rather than hidden
///
/// 301 keepalives in a 30 s window becomes ~121 — one `0x01` immediately,
/// then one `0x02` per 250 ms — and the status bytes are now the two the
/// spec names instead of 301 copies of `0x02`. The risk is real in
/// principle: **a host may be less patient with 250 ms of silence than
/// with 100 ms**, and this constant is the only thing between a waiting
/// device and a host that concludes it is wedged.
///
/// What the measurements say about that risk:
///
/// * the A/B probe measured this board answering a `PING` at
///   **30047.7 ms** — the window does run its full 30 s and then answer,
///   so no host we have actually observed abandons us early. The risk is
///   hypothetical, not observed;
/// * the reference, which has shipped this cadence to the same hosts, uses
///   250 ms.
///
/// The balance of evidence is that sparser, correctly-labelled frames win,
/// and that is the call made here. What would reverse it: a host *observed*
/// abandoning a window inside 250 ms of silence. The instrumentation to
/// notice that is already here — US-1509's per-pass read count, and the
/// keepalive counters in [`PresenceStats`] — so the question can be settled
/// with data instead of re-argued. If such a host appears, the right
/// response is a **per-status** period (fast `0x01` while the command is
/// genuinely processing, slow `0x02` while a human is being waited on), not
/// a return to ten identical `0x02`s a second.
pub const CTAP_KEEPALIVE_PERIOD_MS: u64 = 250;

/// US-921: the cross-call consent window for the CCID consumers (mgmt /
/// OATH). It must stay under the host's T=1 transaction-abort ceiling
/// (observed ~14.5 s over libccid — see `button.rs`) so the eventual
/// refusal is observable as SW=6985 rather than a host-side abort.
pub const CCID_WINDOW_MS: u64 = 15_000;

/// US-921: the CTAP2 touch window as a value — the pure policy piece the
/// HID loop bounds its keepalive retries with (`open` stamps the budget
/// from the current clock; `expired` is the loop's exit condition). The
/// platform deadline governs the actual grant window; this only bounds
/// the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TouchWindow {
    /// The command tag this window serves (diagnostics only).
    pub tag: u32,
    /// The loop's exit deadline (`now + CTAP_TOUCH_WINDOW_MS`).
    pub deadline_ms: u64,
}

impl TouchWindow {
    /// Open a touch window for `tag` at `now_ms`.
    pub fn open(tag: u32, now_ms: u64) -> Self {
        Self {
            tag,
            deadline_ms: now_ms.saturating_add(CTAP_TOUCH_WINDOW_MS),
        }
    }

    /// Whether the window has run out at `now_ms`.
    pub fn expired(&self, now_ms: u64) -> bool {
        now_ms >= self.deadline_ms
    }
}

/// US-921: is this U2F (CTAP1) response the bare UP-refusal shape? The
/// two shapes the app can answer a presence-gated U2F command with:
/// SW `6985` (CONDITIONS_NOT_SATISFIED) and the US-908 enforce-mode
/// `0700` (NOT_PRESENT) payload. Used by the MSG arm to decide whether a
/// keepalive window is worth opening.
pub fn u2f_up_refusal(resp: &[u8]) -> bool {
    resp == [0x69, 0x85] || resp == [0x07, 0x00]
}

// --- US-1020: the presence handshake, instrumented -------------------------

/// US-1020: what a [`PresenceEvent`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PresenceEventKind {
    /// A press edge left the source. `tag` is 0 — no tag is bound yet.
    Press = 1,
    /// The press **armed** a grant bound to `tag` (a pending request was
    /// there to receive it).
    Armed = 2,
    /// The press was **discarded**: nothing was pending (anti-harvest). It
    /// armed nothing, anywhere — the US-921 review's invariant, now
    /// countable.
    Discarded = 3,
    /// A cross-call consent window opened under `tag`.
    Window = 4,
    /// A grant was **consumed** by `tag` — the touch became consent. This is
    /// the event a `getAssertion` that reached a signature depends on.
    Grant = 5,
}

/// US-1020: one presence event, stamped with the runtime's monotonic clock
/// (the same `now_ms` the service's deadlines use), so arm→grant latency is
/// a subtraction rather than an inference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresenceEvent {
    /// What happened.
    pub kind: PresenceEventKind,
    /// The tag the event is bound to (0 where none applies).
    pub tag: u32,
    /// The runtime's monotonic clock, in milliseconds, truncated to 32 bits.
    ///
    /// Truncation wraps at 2^32 ms ≈ 49.7 days of uptime. **Elapsed times
    /// stay correct across the wrap** because every delta in this module is
    /// a `wrapping_sub` — which is why an absolute millisecond stamp is
    /// stored here and a delta is stored there, and never the other way
    /// round. (`AtomicU64` is not an option: thumbv8m.main has no 64-bit
    /// atomic CAS, so it would compile to a libcall.)
    pub now_ms: u32,
    /// Milliseconds since the arm that armed the grant this event's grant
    /// serves — the **touch→consent latency**, the figure US-1022 is judged
    /// against. `0` for every other kind (there is no prior arm to measure
    /// from, and inventing one would be a fabricated measurement).
    pub delta_ms: u32,
}

/// US-1020: the counter block — a read-only snapshot of the runtime's
/// presence accounting. The measurement US-1022 is judged against.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PresenceStats {
    /// Press edges drained from the source.
    pub presses: u32,
    /// Presses that armed a grant for a pending tag.
    pub armed: u32,
    /// Presses that armed nothing (nothing pending).
    pub discarded: u32,
    /// Cross-call consent windows opened (`begin_window` / `window_grant`).
    pub windows: u32,
    /// Grants consumed by a command — touches that became consent.
    pub grants: u32,
    /// Clock of the most recent press, in ms.
    pub last_press_ms: u32,
    /// Clock of the most recent arm, in ms.
    pub last_arm_ms: u32,
    /// Clock of the most recent consumed grant, in ms.
    pub last_grant_ms: u32,
    /// **Touch→consent latency of the most recent grant**, in ms
    /// (`last_grant_ms - last_arm_ms`, wrapping). The number that says
    /// whether a touch registered.
    pub last_arm_to_grant_ms: u32,
    /// The tag of the most recent arm/grant/window.
    pub last_tag: u32,
}

/// The mutable side of [`PresenceStats`]. `AtomicU32` throughout (see
/// [`PresenceEvent::now_ms`] for why not 64-bit): a `fetch_add`/`store` pair
/// per event, on a path that already runs at the 10 ms button tick, and no
/// new frame anywhere — the counters live in the runtime's static slot, not
/// in a task future.
#[derive(Default)]
struct PresenceCounters {
    presses: AtomicU32,
    armed: AtomicU32,
    discarded: AtomicU32,
    windows: AtomicU32,
    grants: AtomicU32,
    last_press_ms: AtomicU32,
    last_arm_ms: AtomicU32,
    last_grant_ms: AtomicU32,
    last_arm_to_grant_ms: AtomicU32,
    last_tag: AtomicU32,
}

impl PresenceCounters {
    /// `const`-constructible zeroed counters (`PresenceRuntime::new` is a
    /// `const fn` and the device runtime is built in a `MaybeUninit` slot).
    const fn new() -> Self {
        Self {
            presses: AtomicU32::new(0),
            armed: AtomicU32::new(0),
            discarded: AtomicU32::new(0),
            windows: AtomicU32::new(0),
            grants: AtomicU32::new(0),
            last_press_ms: AtomicU32::new(0),
            last_arm_ms: AtomicU32::new(0),
            last_grant_ms: AtomicU32::new(0),
            last_arm_to_grant_ms: AtomicU32::new(0),
            last_tag: AtomicU32::new(0),
        }
    }

    fn snapshot(&self) -> PresenceStats {
        PresenceStats {
            presses: self.presses.load(Ordering::Relaxed),
            armed: self.armed.load(Ordering::Relaxed),
            discarded: self.discarded.load(Ordering::Relaxed),
            windows: self.windows.load(Ordering::Relaxed),
            grants: self.grants.load(Ordering::Relaxed),
            last_press_ms: self.last_press_ms.load(Ordering::Relaxed),
            last_arm_ms: self.last_arm_ms.load(Ordering::Relaxed),
            last_grant_ms: self.last_grant_ms.load(Ordering::Relaxed),
            last_arm_to_grant_ms: self.last_arm_to_grant_ms.load(Ordering::Relaxed),
            last_tag: self.last_tag.load(Ordering::Relaxed),
        }
    }
}

/// The raw press-edge latch (US-702 latch, moved here so the lib's presence
/// wiring owns it). Set by the device button task on a BOOTSEL press edge,
/// consumed (cleared) by [`LatchSource::poll_press`].
pub static PRESS_LATCH: AtomicBool = AtomicBool::new(false);

/// US-914 review fix (stale-edge resync): the last press LEVEL observed by
/// the blocking wait's out-of-task pad sampling ([`wait_grant`]'s sampler
/// — on device, `button.rs`'s `paced_bootsel`). `0` = no wait sample since
/// the button task's last poll; `1` = released; `2` = pressed. The button
/// task adopts the value as its edge baseline when it resumes after a
/// blocking wait, so a press the wait consumed is **not** re-detected as a
/// fresh edge — one physical press grants at most one command (without
/// this, the tail of an already-granted touch-to-sign press would be
/// re-latched for a later command).
static WAIT_ADOPT: AtomicU8 = AtomicU8::new(0);

/// Record one out-of-task press-level sample (called by the blocking
/// wait's sampler; the last call before the wait exits is the baseline
/// the button task adopts).
pub fn note_wait_level(pressed: bool) {
    WAIT_ADOPT.store(if pressed { 2 } else { 1 }, Ordering::SeqCst);
}

/// Adopt the blocking wait's last observed level as the button task's
/// edge baseline (one call per button-task poll). `None` when no wait
/// sampled the pad since the last adoption.
pub fn adopt_wait_level() -> Option<bool> {
    match WAIT_ADOPT.swap(0, Ordering::SeqCst) {
        1 => Some(false),
        2 => Some(true),
        _ => None,
    }
}

/// Board test hook: inject one press edge deterministically from the
/// emulation build / host tests (US-921 brief — device builds verify via
/// the US-924 hardware BDD run).
pub fn emul_inject_press() {
    PRESS_LATCH.store(true, Ordering::SeqCst);
}

/// US-921 `PresenceSource` over the BOOTSEL press latch: one poll returns
/// whether an un-consumed press edge is latched, and consumes it (US-906:
/// sources must not report a press for a poll that was already consumed).
pub struct LatchSource;

impl PresenceSource for LatchSource {
    fn poll_press(&mut self) -> bool {
        PRESS_LATCH.swap(false, Ordering::SeqCst)
    }
}

/// The shared presence runtime: one [`PresenceService`] (US-906), the press
/// source, and the injected monotonic clock. `core`-only — host tests
/// inject the clock and drive the latch directly.
pub struct PresenceRuntime<S: PresenceSource> {
    svc: PresenceService,
    source: S,
    now_ms: fn() -> u64,
    /// US-1020: the presence handshake's counters. 40 bytes of static RAM in
    /// the device runtime slot; no allocation, no frame.
    ctr: PresenceCounters,
}

impl<S: PresenceSource> PresenceRuntime<S> {
    /// Build the runtime over `source`, with `now_ms` as the monotonic
    /// clock (device: embassy millis; host tests: a manual tick).
    pub const fn new(source: S, now_ms: fn() -> u64) -> Self {
        Self {
            svc: PresenceService::new(),
            source,
            now_ms,
            ctr: PresenceCounters::new(),
        }
    }

    /// US-1020: the runtime's presence accounting (see [`PresenceStats`]).
    pub fn stats(&self) -> PresenceStats {
        self.ctr.snapshot()
    }

    /// US-1020: stamp one event — update the counter block and publish it to
    /// the installed event hook, if any.
    ///
    /// `#[inline(always)]` and no frame of its own on purpose: this sits on
    /// the button task's 10 ms tick and inside `request()`, which
    /// `check_boot_chain.py` charges frame-by-frame on the request-serving
    /// path. A non-inlined helper here would be a new frame in the worst
    /// call chain for the sake of a counter.
    #[inline(always)]
    fn note(&self, kind: PresenceEventKind, tag: u32, now_ms: u32) {
        let mut delta_ms = 0u32;
        match kind {
            PresenceEventKind::Press => {
                self.ctr.presses.fetch_add(1, Ordering::Relaxed);
                self.ctr.last_press_ms.store(now_ms, Ordering::Relaxed);
            }
            PresenceEventKind::Armed => {
                self.ctr.armed.fetch_add(1, Ordering::Relaxed);
                self.ctr.last_arm_ms.store(now_ms, Ordering::Relaxed);
                self.ctr.last_tag.store(tag, Ordering::Relaxed);
            }
            PresenceEventKind::Discarded => {
                self.ctr.discarded.fetch_add(1, Ordering::Relaxed);
            }
            PresenceEventKind::Window => {
                self.ctr.windows.fetch_add(1, Ordering::Relaxed);
                self.ctr.last_tag.store(tag, Ordering::Relaxed);
            }
            PresenceEventKind::Grant => {
                self.ctr.grants.fetch_add(1, Ordering::Relaxed);
                self.ctr.last_grant_ms.store(now_ms, Ordering::Relaxed);
                // Touch→consent latency, wrapping (see PresenceEvent::now_ms).
                delta_ms = now_ms.wrapping_sub(self.ctr.last_arm_ms.load(Ordering::Relaxed));
                self.ctr.last_arm_to_grant_ms
                    .store(delta_ms, Ordering::Relaxed);
                self.ctr.last_tag.store(tag, Ordering::Relaxed);
            }
        }
        if let Some(hook) = event_hook() {
            hook(PresenceEvent {
                kind,
                tag,
                now_ms,
                delta_ms,
            });
        }
    }

    /// The runtime clock, truncated to the event stamp's 32 bits.
    #[inline(always)]
    fn now32(&self) -> u32 {
        (self.now_ms)() as u32
    }

    /// Declare a command pending for presence (US-906 single slot).
    pub fn begin_request(&mut self, tag: u32) -> bool {
        self.svc.begin_request(tag)
    }

    /// The tag holding the pending-request slot, if any (US-921 window
    /// introspection: the loops assert on slot ownership).
    pub fn pending_tag(&self) -> Option<u32> {
        self.svc.pending_tag()
    }

    /// Release the pending-request slot (no-op for a non-owner).
    pub fn end_request(&mut self, tag: u32) {
        self.svc.end_request(tag)
    }

    /// One press poll (the button task's tick, and the in-window poll of
    /// [`request_grant`]): a latched press arms a grant only while a
    /// request is pending — with nothing pending the service discards it
    /// (anti-harvest). Returns `true` iff the press was **armed** (a
    /// request was pending); `false` covers both "no press" and "press
    /// discarded" — a discarded press arms nothing anywhere (US-921
    /// review: the legacy raw-latch fall-through is gone; every consumer,
    /// OATH included, takes its grants from this runtime).
    pub fn poll_press(&mut self) -> bool {
        // US-921 review (P2-3): the button task's tick drains through here
        // every 10 ms — run the lazy expiry sweep in that tick too (one
        // clock read), so a window abandoned past its deadline closes here
        // and its touch prompt clears with it. The CCID join-or-open path
        // never revisits its window once the host goes quiet, so without
        // this sweep the prompt would stay lit forever after a refused,
        // never-retried command. Harmless on the in-window callers: they
        // sweep first themselves and the second sweep finds nothing.
        if self.svc.expire_pending((self.now_ms)()) {
            self.touch_prompt(false);
        }
        // US-921 review finding 1: re-assert the touch prompt while a
        // request is still pending. The one-shot assertion at window
        // open is stomped by the heartbeat task and the trussed UI's
        // Processing→Idle bracketing within tens of ms (hardware probe:
        // the CCID prompt showed as invisible). The button task's 10 ms
        // tick is the one driver that runs across the whole window, so
        // the prompt is re-asserted here; expiry cleared the prompt in
        // the sweep above, and with nothing pending this stays silent.
        // (The FIDO UpRequired loop re-asserts its own per keepalive and
        // `pso_wait_grant` inside its blocking wait — this tick covers
        // the cross-call CCID windows those paths don't own.)
        if self.svc.pending_tag().is_some() {
            self.touch_prompt(true);
        }
        if self.source.poll_press() {
            let now = self.now32();
            self.note(PresenceEventKind::Press, 0, now);
            self.svc.observe_press((self.now_ms)());
            // Armed-vs-discarded is evaluated AFTER the lazy expiry sweep
            // (US-921 window): a press that expired its window found
            // nothing pending and armed nothing — it reports not-armed.
            match self.svc.pending_tag() {
                Some(tag) => {
                    self.note(PresenceEventKind::Armed, tag, now);
                    true
                }
                None => {
                    self.note(PresenceEventKind::Discarded, 0, now);
                    false
                }
            }
        } else {
            false
        }
    }

    /// Ask for this command's grant (US-906 semantics: single-use, timed,
    /// tag-bound — a mismatched request fails without burning the grant).
    pub fn request(&mut self, cmd_tag: u32) -> Option<fapico2_platform::presence::PresenceGrant> {
        let now = self.now32();
        let grant = self.svc.request(cmd_tag, (self.now_ms)());
        if grant.is_some() {
            self.note(PresenceEventKind::Grant, cmd_tag, now);
        }
        grant
    }

    /// US-921: open a cross-call consent window under `tag` with the
    /// runtime clock's `window_ms` budget (the slot rules are the
    /// service's `begin_request` rules — single slot, fail-closed while
    /// busy). The caller owns the lifecycle: [`Self::end_window`] closes
    /// it, the platform deadline expires it lazily.
    pub fn begin_window(&mut self, tag: u32, window_ms: u64) -> bool {
        let now = (self.now_ms)();
        let opened = self.svc.begin_request_window(tag, now.saturating_add(window_ms));
        if opened {
            self.note(PresenceEventKind::Window, tag, self.now32());
        }
        opened
    }

    /// US-921: join-only grant consumption for an open window — expire,
    /// poll one press, consume a grant bound to `tag`. NEVER begins or
    /// ends the slot: the dispatch layer owns the window lifecycle. With
    /// nothing pending (or a press that armed nothing for `tag`) this
    /// refuses without disturbing the slot.
    pub fn grant_in_window(&mut self, tag: u32) -> bool {
        self.svc.expire_pending((self.now_ms)());
        self.poll_press();
        self.request(tag).is_some()
    }

    /// US-921: the CCID consumers' join-or-open gate. With nothing
    /// pending, opens a [`CCID_WINDOW_MS`] window under `tag` and lights
    /// the touch prompt; with this tag's window already open, joins it;
    /// with another command's slot held, refuses (no theft). A press
    /// inside the window grants, consumes and closes the window (prompt
    /// cleared); without one the window stays open until its deadline.
    pub fn window_grant(&mut self, tag: u32) -> bool {
        let now = (self.now_ms)();
        self.svc.expire_pending(now);
        match self.svc.pending_tag() {
            Some(t) if t != tag => return false, // no theft: the owner keeps the slot
            None => {
                if !self.svc.begin_request_window(tag, now.saturating_add(CCID_WINDOW_MS)) {
                    return false;
                }
                self.note(PresenceEventKind::Window, tag, self.now32());
                self.touch_prompt(true);
            }
            Some(_) => {} // join the already-open window under `tag`
        }
        self.poll_press();
        if self.request(tag).is_some() {
            self.svc.end_request(tag);
            self.touch_prompt(false);
            true
        } else {
            // Window stays open until its deadline — the retry is the
            // second chance to press.
            false
        }
    }

    /// US-921: light (`true`) / clear (`false`) the touch prompt — the
    /// device build forwards to the shared LED through the write-once
    /// hook; host/emulation builds install no hook, so this is a no-op.
    pub fn touch_prompt(&mut self, on: bool) {
        if let Some(hook) = touch_hook() {
            hook(on);
        }
    }

    /// The synchronous one-shot command path (device `user_present`):
    /// begin the pending request under `tag`, poll the latch once (a press
    /// during the window arms the grant), consume it, release the slot.
    /// Fail-closed without a press.
    pub fn request_grant(&mut self, tag: u32) -> bool {
        if !self.svc.begin_request(tag) {
            return false;
        }
        self.poll_press();
        let granted = self.request(tag).is_some();
        self.svc.end_request(tag);
        granted
    }

    /// US-914: the touch-to-sign wait (the OpenPGP app's device gate).
    /// Holds the pending slot under `tag` for `timeout_ms`, sampling the
    /// raw press *level* via `sample` — on the device the button poll task
    /// is starved while the serve task blocks, so the BOOTSEL pad is
    /// sampled here directly (paced by the caller). A press **edge**
    /// observed while the request is pending arms the grant and the next
    /// `request` consumes it; a button already held when the wait begins
    /// has no edge *while pending* and never grants (anti-harvest — a
    /// press that predates the request is not consent for it).
    /// Fail-closed on timeout and when the single pending slot is busy.
    pub fn wait_grant(&mut self, tag: u32, timeout_ms: u64, sample: fn() -> bool) -> bool {
        let deadline = (self.now_ms)().saturating_add(timeout_ms);
        if !self.svc.begin_request(tag) {
            return false;
        }
        // Two-sample debounce (US-914 hardware C5 anomaly): a pressed
        // level must hold for two consecutive samples before the edge is
        // accepted — the QSPI-CS read can produce single-sample spikes,
        // and one spike must never arm a grant. Presses held at entry
        // still never grant: the baseline is the first sample, so a press
        // predating the request has no released→pressed transition.
        let mut stable_pressed = sample();
        let mut candidate = stable_pressed;
        let mut granted = false;
        while !granted {
            if (self.now_ms)() >= deadline {
                break;
            }
            let pressed = sample();
            if pressed == stable_pressed {
                candidate = pressed;
            } else if pressed == candidate {
                // Two consecutive samples disagree with the stable level:
                // the level genuinely changed.
                if pressed && !stable_pressed {
                    self.svc.observe_press((self.now_ms)());
                    // US-1020: the touch-to-sign arm is a grant arm like any
                    // other — the OpenPGP `PSO:SIGN` wait is measured on the
                    // same clock as the CTAPHID window.
                    self.note(PresenceEventKind::Armed, tag, self.now32());
                }
                stable_pressed = pressed;
                candidate = pressed;
            } else {
                // First divergent sample: hold it as the candidate (a
                // spike dies here unless the next sample confirms it).
                candidate = pressed;
            }
            granted = self.request(tag).is_some();
        }
        self.svc.end_request(tag);
        granted
    }
}

// --- US-1020: the presence-event hook (device: the US-922 diagnostic ring) --

static EVENT_HOOK_SET: AtomicBool = AtomicBool::new(false);
static mut EVENT_HOOK_FN: Option<fn(PresenceEvent)> = None;

/// US-1020: install the presence-event sink. Write-once, exactly like
/// [`set_touch_prompt_hook`] — the device bin installs it at boot (next to
/// the touch-prompt hook), and returns `false` on a second call so a
/// boot-ordering mistake is loud rather than silent.
///
/// The device bin's sink is the US-922 diagnostic ring (`firmware/src/dbg.rs`,
/// CTAPHID vendor command `0x42`): `E_PRESS`/`E_PARM`/`E_PDISCARD`/
/// `E_PWINDOW`/`E_PGRANT` records with the tag and the clock in `a`/`b`, and
/// the arm→grant latency in `b` of the grant record.
///
/// **It installs nothing in a release build.** `dbg-log` is release-forbidden
/// (US-922) and `apdu-trace` is a dedicated capture build, so in the shipping
/// configuration this hook is `None` and the `if let Some(hook)` in
/// [`PresenceRuntime::note`] is a branch to a constant-false load. The
/// counters still accumulate — they are the in-process half of the
/// measurement, and they cost no frame.
pub fn set_presence_event_hook(hook: Option<fn(PresenceEvent)>) -> bool {
    if EVENT_HOOK_SET.swap(true, Ordering::SeqCst) {
        return false;
    }
    unsafe {
        // SAFETY: write-once before any task runs (boot discipline, the
        // RUNTIME_SLOT pattern) — no aliasing exists yet.
        core::ptr::addr_of_mut!(EVENT_HOOK_FN).write(hook);
    }
    true
}

/// The installed event sink, if any.
fn event_hook() -> Option<fn(PresenceEvent)> {
    if EVENT_HOOK_SET.load(Ordering::SeqCst) {
        // SAFETY: read of the write-once slot, sequenced after the flag.
        unsafe { core::ptr::addr_of!(EVENT_HOOK_FN).read() }
    } else {
        None
    }
}

// The device runtime slot: written once by `init` at boot, then only read.
// Single-core cooperative executor (no task awaits inside a presence op),
// so the `&'static mut` aliasing is serialized; the write-once discipline
// follows the boot.rs / usb.rs `static mut` pattern (addr_of_mut! + SAFETY).
static mut RUNTIME_SLOT: core::mem::MaybeUninit<PresenceRuntime<LatchSource>> =
    core::mem::MaybeUninit::uninit();
static RUNTIME_INIT: AtomicBool = AtomicBool::new(false);

/// Device wiring entry: install the shared runtime with `now_ms` as its
/// clock. Write-once discipline: called once at boot by the device bin
/// before any task runs; returns `false` on a second call (fail-loud).
pub fn init(now_ms: fn() -> u64) -> bool {
    if RUNTIME_INIT.swap(true, Ordering::SeqCst) {
        return false;
    }
    unsafe {
        // SAFETY: write-once before any task runs (boot discipline, same
        // pattern as boot.rs's device statics) — no aliasing exists yet.
        core::ptr::addr_of_mut!(RUNTIME_SLOT)
            .write(core::mem::MaybeUninit::new(PresenceRuntime::new(LatchSource, now_ms)));
    }
    true
}

/// The shared runtime (device bins).
///
/// # Safety
/// Caller must ensure `init` ran at boot and that no other task is mid-op
/// (single-core cooperative executor: presence ops never `.await`).
unsafe fn runtime() -> &'static mut PresenceRuntime<LatchSource> {
    // Cheap guard: a boot-ordering mistake must fail loud, not read the
    // (still-uninit) slot as UB.
    assert!(
        RUNTIME_INIT.load(Ordering::SeqCst),
        "presence runtime used before init()"
    );
    &mut *core::ptr::addr_of_mut!(RUNTIME_SLOT).cast::<PresenceRuntime<LatchSource>>()
}

/// Device command path: the shared runtime's one-shot grant (injected into
/// the mgmt/FIDO apps via `with_presence_grant`).
pub fn request_grant(tag: u32) -> bool {
    // SAFETY: device bin — `init` ran at boot before any task; no .await
    // inside this op, so the cooperative executor serializes access.
    unsafe { runtime().request_grant(tag) }
}

/// US-914: the device touch-to-sign wait (injected into the OpenPGP app
/// via `with_presence_grant` in `main.rs`). The shared runtime holds the
/// pending slot under `tag` for `timeout_ms` while `sample` supplies the
/// raw press level — the paced BOOTSEL pad read on the device, a scripted
/// level queue plus manual clock ticks in the host tests.
pub fn wait_grant(tag: u32, timeout_ms: u64, sample: fn() -> bool) -> bool {
    // SAFETY: as `request_grant` — init ran at boot before any task; the
    // op never awaits (the serve task blocks through the whole window),
    // so the cooperative executor serializes access.
    unsafe { runtime().wait_grant(tag, timeout_ms, sample) }
}

/// Device button-task tick: drain one press edge through the shared
/// runtime (anti-harvest: discarded unless a request is pending — and a
/// discarded press arms nothing, anywhere; US-921 review). Returns `true`
/// iff the press **armed** a pending command's grant.
///
/// # Panics
/// If [`init`] has not run (boot-ordering mistake — fail loud, not UB).
pub fn drain_press() -> bool {
    // SAFETY: as `request_grant` — init-ran-at-boot, cooperative single op.
    unsafe { runtime().poll_press() }
}

// --- US-921: the touch-prompt hook (device: the shared LED_OUT) -----------

static TOUCH_HOOK_SET: AtomicBool = AtomicBool::new(false);
static mut TOUCH_HOOK_FN: Option<fn(bool)> = None;

/// Install the touch-prompt hook (device wiring: `main` registers
/// `button::set_touch_prompt_led` after LED_OUT init, before any task).
/// Write-once discipline — the same as [`init`]: the first install wins,
/// a second call returns `false` (fail-loud on a boot-ordering mistake).
pub fn set_touch_prompt_hook(hook: Option<fn(bool)>) -> bool {
    if TOUCH_HOOK_SET.swap(true, Ordering::SeqCst) {
        return false;
    }
    unsafe {
        // SAFETY: write-once before any task runs (boot discipline, the
        // RUNTIME_SLOT pattern) — no aliasing exists yet.
        core::ptr::addr_of_mut!(TOUCH_HOOK_FN).write(hook);
    }
    true
}

/// The installed hook, if any.
fn touch_hook() -> Option<fn(bool)> {
    if TOUCH_HOOK_SET.load(Ordering::SeqCst) {
        // SAFETY: read of the write-once slot, sequenced after the flag.
        unsafe { core::ptr::addr_of!(TOUCH_HOOK_FN).read() }
    } else {
        None
    }
}

// --- US-921: the device window paths (injected / driven by the loops) -----

/// The CCID consumers' device gate (injected into the mgmt/OATH apps via
/// `with_presence_grant`): join-or-open cross-call window — see
/// [`PresenceRuntime::window_grant`].
pub fn window_grant(tag: u32) -> bool {
    // SAFETY: as `request_grant` — init ran at boot before any task; no
    // .await inside this op, so the cooperative executor serializes access.
    unsafe { runtime().window_grant(tag) }
}

/// The FIDO app's device gate (injected via `with_presence_grant`; the
/// HID task's UpRequired loop owns the window lifecycle): join-only
/// consumption — see [`PresenceRuntime::grant_in_window`].
pub fn request_grant_in_window(tag: u32) -> bool {
    // SAFETY: as `request_grant`.
    unsafe { runtime().grant_in_window(tag) }
}

/// The HID task's window open (`begin_window(tag, window_ms)`): the
/// UpRequired loop calls this once per windowed transaction, before the
/// keepalive streaming. `window_ms` bounds the slot; the caller owns the
/// paired [`end_window`].
pub fn begin_window(tag: u32, window_ms: u64) -> bool {
    // SAFETY: as `request_grant`.
    unsafe { runtime().begin_window(tag, window_ms) }
}

/// The HID task's window close: paired with [`begin_window`] on every
/// exit path of the UpRequired loop (grant consumed, timeout, or a final
/// non-windowed response).
pub fn end_window(tag: u32) {
    // SAFETY: as `request_grant`.
    unsafe { runtime().end_request(tag) }
}

/// The HID loop's touch-prompt driver: light (`true`) on window open and
/// re-asserted each keepalive iteration (cheap mitigation for the
/// heartbeat flicker), clear (`false`) at every exit path.
pub fn touch_prompt(on: bool) {
    // SAFETY: as `request_grant`.
    unsafe { runtime().touch_prompt(on) }
}

/// US-1020: the shared runtime's presence counters (device bins) — the
/// measurement US-1022 is judged against. Cheap enough to read anywhere a
/// serve task is already scheduled; it takes a copy, it does not await.
///
/// # Panics
/// If [`init`] has not run (boot-ordering mistake — fail loud, not UB).
pub fn stats() -> PresenceStats {
    // SAFETY: as `request_grant` — init ran at boot; a pure read.
    unsafe { runtime().stats() }
}

#[cfg(test)]
mod tests;
