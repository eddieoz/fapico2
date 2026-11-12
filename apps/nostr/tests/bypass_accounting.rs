//! US-1837 — the clock seam (EPIC NOSTR-BYPASS-ACCOUNTING, Phase 1).
//!
//! The invariant the file pins: a monotonic millisecond clock reaches the
//! applet as an injected `fn` provider — the same shape as the RNG and
//! presence seams — with `0` as the honest "no clock wired" value, exactly
//! the fido audit ring's `uptime_ms` convention (`apps/fido/src/vendor41.rs`:
//! "the clock is the caller's"). The applet gains no time dependency; the
//! device and the emulator supply the real clock (US-1844), the tests supply
//! a fake.
//!
//! RED until `with_now_provider` and the host-only `now_ms` accessor exist.
//! Later stories in this file build on this seam: US-1838 the accounting
//! state, US-1839 the cap, US-1840 the expiry, US-1841 the ring, US-1842 the
//! GET_AUDIT verb — each story's scenarios land here RED-first.

use fapico2_nostr::NostrApp;

// ---------------------------------------------------------------------------
// Fixtures (the touch_bypass.rs set, mirrored — test files do not name each
// other; US-1838+ grow this block as their stories need the region identity)
// ---------------------------------------------------------------------------

/// The thread-local fake clock. `with_now_provider` takes a capture-free
/// `fn`, so the tests' variability lives here — the `PRESSES` counting
/// pattern of the presence tests.
fn fake_now() -> u64 {
    FAKE_MS.with(|c| c.get())
}

fn advance(ms: u64) {
    FAKE_MS.with(|c| c.set(c.get() + ms));
}

thread_local! {
    static FAKE_MS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

// ---------------------------------------------------------------------------
// US-1837 — the clock seam
// ---------------------------------------------------------------------------

/// A bare applet with no clock wired reads `0` — and `0` is a legal value,
/// not an error (the fido audit ring's caller-owned clock).
#[test]
fn default_clock_reads_zero() {
    let app = NostrApp::new();
    assert_eq!(app.now_ms(), 0, "no clock wired reads zero, honestly");
}

/// An injected provider is returned verbatim — the applet is a conduit for
/// the caller's clock, never a second source of truth.
#[test]
fn injected_clock_is_returned_verbatim() {
    let app = NostrApp::new().with_now_provider(|| 12_345);
    assert_eq!(app.now_ms(), 12_345, "the injected clock is the clock");
}

/// The clock advances between reads — a fake that never moves would make
/// every later expiry test vacuous.
#[test]
fn clock_advances_between_reads() {
    let app = NostrApp::new().with_now_provider(fake_now);
    let first = app.now_ms();
    advance(50);
    let second = app.now_ms();
    assert_eq!(first, 0, "the fake starts at zero");
    assert_eq!(second, 50, "the second read is strictly greater");
}
