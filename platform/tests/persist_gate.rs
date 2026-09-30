//! US-421 (SECURE-PERSIST Phase A): the platform persist gate.
//!
//! `persist_apps` / `persist_one` are the ONLY code path that sequences
//! persist-state → snapshot-partition-image → program-sink. These host tests
//! pin the contract:
//!
//! * a dirty app programs exactly one (loadable) image; a clean app programs
//!   nothing;
//! * the app's dirty flag is cleared only when its store write succeeds;
//! * a store write error leaves the app dirty and never reaches the sink;
//! * the sink is programmed only after a successful store write;
//! * a sink program failure returns false and re-marks exactly the writing
//!   apps dirty (durable-before-ack: no success reply without a durable
//!   image — the change retries on the next command).

use fapico2_platform::dispatch::{App, MAX_RESPONSE};
use fapico2_platform::persist::{persist_apps, persist_one, pull_image, ImageSink, Persist, WindowedImageSource};
use fapico2_platform::secure_store::{HostSecureStore, SecureStore};
use heapless::Vec as HeaplessVec;

/// Records every image programmed through the sink.
#[derive(Default)]
struct InMemorySink {
    images: Vec<Vec<u8>>,
}

impl InMemorySink {
    fn program_count(&self) -> usize {
        self.images.len()
    }
}

impl ImageSink for InMemorySink {
    fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
        self.images.push(pull_image(src));
        true
    }
}

/// Stub dispatcher app with an explicit dirty flag (mirrors the OATH/OTP/mgmt
/// `persist_state` convention: clear dirty only when the store write succeeds).
struct StubApp {
    aid: &'static [u8],
    dirty: bool,
    /// The value written to the store when `persist_state` runs.
    value: &'static [u8],
}

impl StubApp {
    fn new(aid: &'static [u8]) -> Self {
        Self {
            aid,
            dirty: false,
            value: b"stub-state-v1",
        }
    }

    /// Oversized value: the store rejects it (ValueTooLong).
    const fn with_oversized_value(self) -> Self {
        Self {
            value: &OVERSIZED,
            ..self
        }
    }
}

/// `MAX_VALUE_LEN` (16 KiB) + 1 byte: guaranteed to exceed the store bound.
static OVERSIZED: [u8; 16 * 1024 + 1] = [0xAB; 16 * 1024 + 1];

impl App for StubApp {
    fn aid(&self) -> &[u8] {
        self.aid
    }

    fn select(&mut self, _internal: bool) -> u16 {
        fapico2_platform::dispatch::SW_OK
    }

    fn deselect(&mut self) {}

    fn process(&mut self, _apdu: &[u8], _resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {}

    fn persist_state(&mut self, store: &mut dyn SecureStore) -> bool {
        if !self.dirty {
            return false;
        }
        let wrote = store.write(b"stub.state", self.value).is_ok();
        if wrote {
            self.dirty = false;
        }
        wrote
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn is_dirty(&self) -> bool {
        self.dirty
    }
}

/// A loadable image restored into a fresh host store carries the app's write.
fn assert_image_loadable(img: &[u8]) {
    let mut restored = HostSecureStore::new();
    restored.from_partition_image(img);
    assert!(
        restored.contains(b"stub.state"),
        "the programmed image must load back into a fresh store"
    );
}

// ---------------------------------------------------------------------------
// persist_apps — the dispatcher gate
// ---------------------------------------------------------------------------

#[test]
fn dirty_app_programs_one_loadable_image_then_clean_app_programs_nothing() {
    let mut app = StubApp::new(&[0xA0, 0x00]);
    app.dirty = true;
    let mut store = HostSecureStore::new();
    let mut sink = InMemorySink::default();

    let wrote = persist_apps(&mut [&mut app], &mut store, &mut sink);
    assert!(wrote, "a dirty app must report a persist");
    assert_eq!(sink.program_count(), 1, "exactly one image programmed");
    assert_image_loadable(&sink.images[0]);
    assert!(!app.dirty, "a successful persist must clear the app's dirty flag");

    // Second call with no mutation: nothing new, nothing programmed.
    let wrote = persist_apps(&mut [&mut app], &mut store, &mut sink);
    assert!(!wrote, "a clean app must not report a persist");
    assert_eq!(
        sink.program_count(),
        1,
        "a clean app must not program the sink (counter stays at 1)"
    );
}

#[test]
fn clean_app_does_not_program() {
    let mut app = StubApp::new(&[0xA0, 0x00]);
    let mut store = HostSecureStore::new();
    let mut sink = InMemorySink::default();

    assert!(
        !persist_apps(&mut [&mut app], &mut store, &mut sink),
        "a clean app must return false"
    );
    assert_eq!(sink.program_count(), 0, "no image may be programmed");
}

#[test]
fn app_write_error_returns_false_keeps_dirty_and_skips_sink() {
    let mut app = StubApp::new(&[0xA0, 0x00]).with_oversized_value();
    app.dirty = true;
    let mut store = HostSecureStore::new();
    let mut sink = InMemorySink::default();

    assert!(
        !persist_apps(&mut [&mut app], &mut store, &mut sink),
        "a store write error must return false"
    );
    assert!(app.dirty, "the app must stay dirty after a failed store write");
    assert_eq!(
        sink.program_count(),
        0,
        "the sink is programmed only after a successful store write"
    );

    // Recovery: the same app, now writing a valid value, persists on retry.
    app.value = b"stub-state-v1";
    assert!(persist_apps(&mut [&mut app], &mut store, &mut sink));
    assert_eq!(sink.program_count(), 1);
    assert!(!app.dirty);
}

// ---------------------------------------------------------------------------
// persist_one — the single non-dispatcher app gate (FIDO on the HID path)
// ---------------------------------------------------------------------------

/// A non-`App` object implementing the small `Persist` trait directly — the
/// shape `FidoApp` takes (keystore `persist_if_dirty`, not `App`).
struct SoloApp {
    dirty: bool,
}

impl Persist for SoloApp {
    fn persist_dirty(&mut self, store: &mut dyn SecureStore) -> bool {
        if !self.dirty {
            return false;
        }
        let wrote = store.write(b"solo.state", b"solo-value").is_ok();
        if wrote {
            self.dirty = false;
        }
        wrote
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }
}

#[test]
fn persist_one_dirty_programs_once_then_clean_programs_nothing() {
    let mut app = SoloApp { dirty: true };
    let mut store = HostSecureStore::new();
    let mut sink = InMemorySink::default();

    assert!(persist_one(&mut app, &mut store, &mut sink));
    assert_eq!(sink.program_count(), 1);
    assert!(!app.dirty);

    let mut restored = HostSecureStore::new();
    restored.from_partition_image(&sink.images[0]);
    assert!(restored.contains(b"solo.state"));

    assert!(!persist_one(&mut app, &mut store, &mut sink));
    assert_eq!(sink.program_count(), 1, "a clean single app must not re-program");
}

// ---------------------------------------------------------------------------
// Sink failure — the gate's re-dirty path (durable-before-ack)
// ---------------------------------------------------------------------------

/// A sink whose program always fails (and counts its calls).
#[derive(Default)]
struct FailingSink {
    calls: usize,
}

impl ImageSink for FailingSink {
    fn program(&mut self, _src: &mut dyn WindowedImageSource) -> bool {
        self.calls += 1;
        false
    }
}

#[test]
fn sink_failure_returns_false_and_remarks_only_writers_dirty() {
    let mut writer = StubApp::new(&[0xA0, 0x01]);
    writer.dirty = true;
    let mut bystander = StubApp::new(&[0xA0, 0x02]); // clean, never wrote
    let mut store = HostSecureStore::new();
    let mut sink = FailingSink::default();

    assert!(
        !persist_apps(&mut [&mut writer, &mut bystander], &mut store, &mut sink),
        "a sink program failure must return false (no success reply may go out)"
    );
    assert_eq!(sink.calls, 1, "the image was handed to the sink");
    assert!(
        writer.dirty,
        "the app whose write reached the store must be re-marked dirty for retry"
    );
    assert!(
        !bystander.dirty,
        "apps that did not write are not touched by the failure path"
    );

    // Retry with a working sink programs and clears the writer.
    let mut good = InMemorySink::default();
    assert!(persist_apps(&mut [&mut writer, &mut bystander], &mut store, &mut good));
    assert!(!writer.dirty);
    assert_eq!(good.program_count(), 1);
    assert_image_loadable(&good.images[0]);
}

/// Phase A triage M5: two dirty writers + a failing sink → the gate returns
/// false and re-marks BOTH writers dirty (exercises the multi-bit
/// `wrote_mask`, not just a single writer).
#[test]
fn two_dirty_writers_sink_failure_remarks_both_dirty() {
    let mut writer_a = StubApp::new(&[0xA0, 0x03]);
    writer_a.dirty = true;
    let mut writer_b = StubApp::new(&[0xA0, 0x04]);
    writer_b.dirty = true;
    let mut store = HostSecureStore::new();
    let mut sink = FailingSink::default();

    assert!(
        !persist_apps(&mut [&mut writer_a, &mut writer_b], &mut store, &mut sink),
        "a sink program failure must return false (no success reply may go out)"
    );
    assert_eq!(sink.calls, 1, "the image was handed to the sink exactly once");
    assert!(
        writer_a.dirty,
        "both writers must be re-marked dirty for retry (writer A)"
    );
    assert!(
        writer_b.dirty,
        "both writers must be re-marked dirty for retry (writer B)"
    );

    // Retry with a working sink programs once and clears both writers.
    let mut good = InMemorySink::default();
    assert!(persist_apps(&mut [&mut writer_a, &mut writer_b], &mut store, &mut good));
    assert!(!writer_a.dirty);
    assert!(!writer_b.dirty);
    assert_eq!(good.program_count(), 1);
    assert_image_loadable(&good.images[0]);
}

#[test]
fn persist_one_sink_failure_keeps_app_dirty() {
    let mut app = SoloApp { dirty: true };
    let mut store = HostSecureStore::new();
    let mut sink = FailingSink::default();

    assert!(!persist_one(&mut app, &mut store, &mut sink));
    assert!(app.dirty, "the app must stay dirty when the sink program fails");

    let mut good = InMemorySink::default();
    assert!(persist_one(&mut app, &mut store, &mut good));
    assert!(!app.dirty);
    assert_eq!(good.program_count(), 1);
}
