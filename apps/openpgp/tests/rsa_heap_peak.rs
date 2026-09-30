//! US-942: RSA peak-heap regression + measurement (host, virt path).
//!
//! Re-derived by US-956 (the device heap is now 48 KiB, not 128 KiB) — same
//! method, same binary, new bound. Extended by US-957 to cover the two RSA
//! workloads US-956 never armed the cap against (**PSO:DECIPHER** and **PUT
//! KEY private import**). Three jobs:
//!
//! 1. **Peak measurement / regression** (`rsa_keygen_peak_*`,
//!    `rsa_private_import_peak_fits_heap`, `rsa_pso_decipher_peak_fits_heap`):
//!    every RSA workload at every modulus width (2048/3072/4096) runs the
//!    full card flow with the *enforceable* device-heap capacity armed — an
//!    OOM is caught loudly, never silent — and asserts the measured
//!    high-water mark against the heap size.
//! 2. **Requirement-4 scenario** (`rsa4096_generated_key_signs_verifiably`):
//!    RSA-4096 GENERATE → READ PUBLIC KEY → parse the `81/82` RsaParts shape
//!    (dispatch.rs `rsa_pubkey_from_template`) → serialize the host-side
//!    `rsa::RsaPublicKey` → PSO:SIGN with the generated key → PKCS#1 v1.5
//!    verification against the serialized public key.
//! 3. **Sizing bound** (`rsa_sizing_worst_case_fits_heap_with_headroom`): the
//!    heap must clear the largest of *all four* RSA workloads by the
//!    documented multiplier.
//!
//! # The measured table (max of 3 runs each, byte-identical across repeats)
//!
//! | operation | RSA-2048 | RSA-3072 | RSA-4096 |
//! |---|---:|---:|---:|
//! | GENERATE | 7,018 | 13,034 | 13,162 |
//! | PSO:SIGN | — | — | **24,792** |
//! | PSO:DECIPHER | 12,520 | 24,040 | 24,168 |
//! | PUT KEY import | 5,083 | 7,961 | 9,961 |
//! | ambient control | 256 | 256 | 256 |
//!
//! # Why the bound is 48 KiB and not the 13,162 B keygen peak
//!
//! The **keygen** peak is not the worst RSA operation. PSO:SIGN on a
//! 4096-bit key peaks at **24,792 B** (measured in job 2 below, same
//! instrument) — 1.9x the largest keygen peak, because the sign path also
//! deserializes the PKCS#8 key into `BigUint`s and runs a blinded CRT modexp.
//! PSO:DECIPHER at 4096 lands within 624 B of it (24,168 B) and PUT KEY
//! import is far below both (9,961 B). The device heap is therefore sized at
//! **49,152 B = 1.98x** the worst measured case (3.73x the largest keygen
//! peak). **US-957 confirmed the sizing holds against the two workloads
//! US-956 left unmeasured — the heap stays at 48 KiB.**
//!
//! The multiplier is not decoration. The `rsa`/`num-bigint-dig` stack grows
//! with *infallible* `Vec` allocations, so an exhausted heap does **not**
//! return an error — `handle_alloc_error` aborts the process, and the device
//! build is `panic = "abort"`. A 1.0x bound would be a coin flip on a
//! structural-but-unmeasured variation. 1.98x absorbs one further `Vec`
//! doubling rung in the sign path before it costs a device.
//!
//! (Full derivation, the 128 KiB history, and the "do not grow this again"
//! arithmetic against the RP2350's 532,480 B of SRAM: `platform/src/
//! rsa_heap.rs` and `docs/size-report.md`.)
//!
//! # Why this measures the device path (allocator trace)
//!
//! Device: `trussed_rsa_alloc::SoftwareRsa` (platform/src/trusted_backend/dispatch.rs,
//! `Backend::Rsa` arm) executes `rsa::RsaPrivateKey::new` + PKCS#8
//! serialization over `alloc` — the binary's `#[global_allocator]`, which for
//! arm builds is the dedicated static heap `platform/src/rsa_heap.rs`
//! (`LockedHeap` over `RSA_HEAP`, initialized exactly once by
//! `DeviceBackend::boot`, platform/src/trusted_backend/device.rs). The device
//! build is otherwise heap-free, so *every* allocation SoftwareRsa makes lands
//! on that static.
//!
//! Host: `rsa_heap` is `#[cfg(all(feature = "rsa-backend", target_arch = "arm"))]`
//! (platform/src/lib.rs), so the virt tests run on the std allocator and do
//! NOT exercise `rsa_heap`. This binary therefore carries a *mirror* of the
//! device condition: a `#[global_allocator]` that delegates to `System` but
//! tracks live bytes with atomics and supports a *measurement window* —
//! between `window_enter` and `window_exit` it records the high-water mark of
//! `live − baseline`, and with the device-heap limit armed it refuses
//! allocations past [`DEVICE_RSA_HEAP_SIZE`], reproducing the device capacity
//! boundary. The window wraps exactly the one APDU that drives the software
//! RSA backend — GENERATE, PSO:SIGN, PSO:DECIPHER or PUT KEY — which is the
//! span in which `SoftwareRsa.request` / the `unsafe_inject_key` RSA path
//! runs.
//!
//! [`DEVICE_RSA_HEAP_SIZE`] is a hand-written mirror of a value that only
//! compiles for `target_arch = "arm"`, so it can drift. `device_heap_mirror_
//! matches_rsa_heap_rs` parses the device source and fails if it ever does.
//!
//! On overflow the rsa/num-bigint-dig stack fails an *infallible* `Vec`
//! allocation → the process aborts with `memory allocation of N bytes failed`
//! (the device `panic = "abort"` build behaves the same); a test-level panic
//! is caught and reported. Either way the OOM is loud.
//!
//! # Running
//!
//! Runs green under the default harness (the US-942 tests serialize
//! themselves through `serial_lock`, so their windows can never overlap —
//! no `--test-threads=1` needed):
//!
//! ```text
//! cargo test -p fapico2-openpgp --test rsa_heap_peak \
//!     --target x86_64-unknown-linux-gnu --offline -- --nocapture
//! ```
//!
//! Runtime ≈ 30 s (the RSA-4096 keygens dominate; the workspace
//! `profile.test` opt-level 2 overrides for `rsa`/`num-bigint-dig` keep it
//! there). Not `#[ignore]`d — the brief requires these to run.

use std::alloc::{GlobalAlloc, Layout, System};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use fapico2_openpgp::OpenPgpApp;
use fapico2_platform::dispatch::{Dispatcher, MAX_RESPONSE, SW_OK};
use heapless::Vec as HeaplessVec;

// ---------------------------------------------------------------------------
// Peak-mirror global allocator (host stand-in for the device `rsa_heap`).
// ---------------------------------------------------------------------------

/// Device RSA heap size — mirrors `platform/src/rsa_heap.rs::RSA_HEAP_SIZE`,
/// which is `#[cfg(target_arch = "arm")]`-only and therefore unreachable from
/// this host test binary. Pinned by `device_heap_mirror_matches_rsa_heap_rs`.
pub const DEVICE_RSA_HEAP_SIZE: usize = 48 * 1024;

/// US-956: the host mirror must not drift from the device constant. Reads
/// `platform/src/rsa_heap.rs` and evaluates the `RSA_HEAP_SIZE` initializer
/// (`<int> * 1024`) — deliberately not a regex over "any 128", but the exact
/// declaration, so a rename or a different expression form fails loudly
/// rather than passing a vacuous match.
#[test]
fn device_heap_mirror_matches_rsa_heap_rs() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../platform/src/rsa_heap.rs");
    let text = std::fs::read_to_string(&src)
        .unwrap_or_else(|e| panic!("US-956: cannot read {}: {e}", src.display()));
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("pub const RSA_HEAP_SIZE"))
        .unwrap_or_else(|| {
            panic!(
                "US-956: no `pub const RSA_HEAP_SIZE` declaration in {}",
                src.display()
            )
        });
    let kib: usize = line
        .split("=")
        .nth(1)
        .and_then(|r| r.split('*').next())
        .and_then(|k| k.trim().parse().ok())
        .unwrap_or_else(|| {
            panic!("US-956: cannot read a `<kib> * 1024` RHS from {line:?}")
        });
    assert_eq!(
        kib * 1024,
        DEVICE_RSA_HEAP_SIZE,
        "US-956: the host mirror ({DEVICE_RSA_HEAP_SIZE} B) drifted from the device \
         `RSA_HEAP_SIZE` ({kib} KiB) in {}",
        src.display()
    );
    println!(
        "US956 INFO device_heap={} B = {} KiB; mirror and platform/src/rsa_heap.rs agree",
        DEVICE_RSA_HEAP_SIZE, kib
    );
}

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static BASELINE: AtomicUsize = AtomicUsize::new(0);
static WINDOW_OPEN: AtomicBool = AtomicBool::new(false);
static LIMIT: AtomicUsize = AtomicUsize::new(0);

/// Serializes the US-942 tests *within this binary*: the test harness may run
/// them on parallel threads, but the measurement windows must not overlap
/// (another thread's allocations would pollute the peak). Each test holds
/// this lock for its whole body, so the windows are effectively
/// single-threaded under any harness configuration. Other test binaries are
/// separate processes — no shared allocator, no interference.
static SERIAL_LOCK: Mutex<()> = Mutex::new(());

fn serial_lock() -> MutexGuard<'static, ()> {
    // Recover from a poisoned lock: a failed earlier test must not cascade.
    SERIAL_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Open a measurement window. Panics if another window is already open
/// (defensive — `serial_lock` should make that impossible).
fn window_enter(limit: Option<usize>) {
    if WINDOW_OPEN.swap(true, Ordering::Relaxed) {
        panic!("US-942: overlapping measurement window — take serial_lock() first");
    }
    BASELINE.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    PEAK.store(0, Ordering::Relaxed);
    LIMIT.store(limit.unwrap_or(0), Ordering::Relaxed);
}

/// Close the window and return the high-water mark of `live − baseline`
/// observed inside it, in bytes.
fn window_exit() -> usize {
    WINDOW_OPEN.store(false, Ordering::Relaxed);
    LIMIT.store(0, Ordering::Relaxed);
    PEAK.load(Ordering::Relaxed)
}

struct PeakMirror;

impl PeakMirror {
    /// Account `n` live bytes; returns `false` if the device-heap limit
    /// (when armed) is exceeded — the caller then reports `AllocError`
    /// exactly as a full `LockedHeap` would.
    fn add(&self, n: usize) -> bool {
        let mut cur = LIVE.load(Ordering::Relaxed);
        loop {
            match LIVE.compare_exchange_weak(
                cur,
                cur.wrapping_add(n),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => cur = x,
            }
        }
        if WINDOW_OPEN.load(Ordering::Relaxed) {
            let used = cur.wrapping_add(n).saturating_sub(BASELINE.load(Ordering::Relaxed));
            let limit = LIMIT.load(Ordering::Relaxed);
            if limit != 0 && used > limit {
                LIVE.fetch_sub(n, Ordering::Relaxed);
                return false;
            }
            PEAK.fetch_max(used, Ordering::Relaxed);
        }
        true
    }

    fn sub(&self, n: usize) {
        LIVE.fetch_sub(n, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for PeakMirror {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !self.add(layout.size()) {
            return core::ptr::null_mut();
        }
        let p = System.alloc(layout);
        if p.is_null() {
            self.sub(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if !self.add(layout.size()) {
            return core::ptr::null_mut();
        }
        let p = System.alloc_zeroed(layout);
        if p.is_null() {
            self.sub(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        self.sub(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let old = layout.size();
        if new_size > old && !self.add(new_size - old) {
            return core::ptr::null_mut();
        }
        let p = System.realloc(ptr, layout, new_size);
        if p.is_null() {
            if new_size > old {
                self.sub(new_size - old);
            }
            return p;
        }
        if new_size < old {
            self.sub(old - new_size);
        }
        p
    }
}

#[global_allocator]
static RSA_PEAK_MIRROR: PeakMirror = PeakMirror;

// ---------------------------------------------------------------------------
// Card-flow helpers (same shapes as tests/dispatch.rs).
// ---------------------------------------------------------------------------

fn select_openpgp() -> [u8; 11] {
    let mut apdu = [0u8; 11];
    apdu[0] = 0x00;
    apdu[1] = 0xA4;
    apdu[2] = 0x04;
    apdu[3] = 0x00;
    apdu[4] = 0x06;
    apdu[5..11].copy_from_slice(fapico2_openpgp::OPENPGP_AID);
    apdu
}

fn put_data_apdu(tag_hi: u8, tag_lo: u8, data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0xDA, tag_hi, tag_lo];
    apdu.push(data.len() as u8);
    apdu.extend_from_slice(data);
    apdu
}

fn apdu(dispatcher: &mut Dispatcher<1>, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(apdu, &mut resp);
    assert!(resp.len() >= 2, "response too short for {:x?}", apdu);
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    (resp[..resp.len() - 2].to_vec(), sw)
}

fn apdu_read(dispatcher: &mut Dispatcher<1>, first: &[u8]) -> (Vec<u8>, u16) {
    let (mut body, mut sw) = apdu(dispatcher, first);
    while sw & 0xFF00 == 0x6100 {
        let le = (sw & 0xFF) as u8;
        let (chunk, next) = apdu(dispatcher, &[0x00, 0xC0, 0x00, 0x00, le]);
        body.extend_from_slice(&chunk);
        sw = next;
    }
    (body, sw)
}

/// RSA-2048/3072/4096 key-attribute bytes (opcard types.rs `RSA_*K_ATTRIBUTES`):
/// `01 | <modulus length in BITS, big-endian> | <exponent bits 0x0020> | 00
/// (standard format)`.
fn rsa_attr(bits: u32) -> Vec<u8> {
    let kb = bits as u16;
    vec![0x01, (kb >> 8) as u8, (kb & 0xFF) as u8, 0x00, 0x20, 0x00]
}

/// Fresh ram card, SELECT, PW3 verify, RSA attribute PUT (tag C1), PIN
/// personalization (US-912 gate) — everything except GENERATE. The
/// `Dispatcher<'a>` borrows the app, so the whole card flow must run inside
/// the `with_ram_client` closure. Personalized PINs: PW1 `654321`,
/// PW3 `87654321` (same as dispatch.rs `personalize_pins`).
fn personalize_rsa_card(dispatcher: &mut Dispatcher<1>, bits: u32) {
    let (_, sw) = apdu(dispatcher, &select_openpgp());
    assert_eq!(sw, SW_OK, "SELECT must answer 9000");
    let (_, sw) = apdu(
        dispatcher,
        &[0x00, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38],
    );
    assert_eq!(sw, SW_OK, "VERIFY PW3 must answer 9000");
    let (_, sw) = apdu(dispatcher, &put_data_apdu(0x00, 0xC1, &rsa_attr(bits)));
    assert_eq!(sw, SW_OK, "PUT DATA RSA-{bits} attribute must answer 9000");
    let (_, sw) = apdu(
        dispatcher,
        &[0x00, 0x24, 0x00, 0x81, 0x0C,
          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
    );
    assert_eq!(sw, SW_OK, "CHANGE PW1 must answer 9000");
    let (_, sw) = apdu(
        dispatcher,
        &[0x00, 0x24, 0x00, 0x83, 0x10,
          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
          0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
    );
    assert_eq!(sw, SW_OK, "CHANGE PW3 must answer 9000");
}

// ---------------------------------------------------------------------------
// Measurements.
// ---------------------------------------------------------------------------

/// One full card flow (fresh ram client, personalized to RSA-`bits`) with the
/// measurement window wrapped around GENERATE ASYMMETRIC KEY PAIR. Returns
/// the window peak in bytes. The window span is where `SoftwareRsa.request`
/// runs on the device — every allocation there lands on `RSA_HEAP`.
fn generate_peak_once(bits: u32, limit: Option<usize>, tag: &str) -> usize {
    let id = format!("fapico2-us942-{tag}-{bits}-{}", std::process::id());
    opcard::virt::with_ram_client(&id, |client| {
        let mut app = OpenPgpApp::new(client);
        let mut d: Dispatcher<1> = Dispatcher::new();
        assert!(d.register(&mut app), "register openpgp app");
        personalize_rsa_card(&mut d, bits);

        window_enter(limit);
        let mut gen = vec![0x00u8, 0x47, 0x80, 0x00, 0x02];
        gen.extend_from_slice(&[0xB6, 0x00]);
        gen.push(0x00);
        let (body, sw) = apdu_read(&mut d, &gen);
        let peak = window_exit();

        assert_eq!(sw, SW_OK, "GENERATE RSA-{bits} must answer 9000, got {sw:04x}");
        assert!(!body.is_empty(), "GENERATE RSA-{bits} must return a public key template");
        assert!(
            body.windows(3).any(|w| w[0] == 0x81 || w[0] == 0x82),
            "GENERATE RSA-{bits} must carry a modulus-format (81/82) public key"
        );
        assert_eq!(
            body.windows(2).position(|w| w == [0x2B, 0x06]),
            None,
            "GENERATE RSA-{bits} must not return an ECC OID-encoded key"
        );
        println!("US942 INFO bits={bits} tag={tag} template_len={}", body.len());
        peak
    })
}

/// Peak over `reps` unlimited keygen runs (fresh card each rep) — the number
/// that sizes the heap.
fn measure_peak(bits: u32, reps: usize) -> usize {
    let mut max_peak = 0usize;
    for rep in 0..reps {
        let peak = generate_peak_once(bits, None, &format!("gen-{rep}"));
        println!(
            "US942 RESULT kind=unlimited bits={bits} rep={rep} peak={peak} \
             peak_kib={:.2}",
            peak as f64 / 1024.0
        );
        max_peak = max_peak.max(peak);
    }
    max_peak
}

/// One keygen run under the exact device-heap boundary: an OOM is
/// loud (process abort with `memory allocation of N bytes failed`, or a
/// caught panic) — never silent.
fn measure_at_limit(bits: u32) -> Result<usize, String> {
    panic::set_hook(Box::new(|info| {
        eprintln!("US942 LIMIT-RUN PANIC (captured): {info}");
    }));
    let out = panic::catch_unwind(AssertUnwindSafe(|| {
        generate_peak_once(bits, Some(DEVICE_RSA_HEAP_SIZE), "lim")
    }));
    let _ = panic::take_hook();
    // If the run panicked inside a window, close it so later windows work.
    WINDOW_OPEN.store(false, Ordering::Relaxed);
    LIMIT.store(0, Ordering::Relaxed);
    match out {
        Ok(peak) => Ok(peak),
        Err(e) => Err(if let Some(s) = e.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic payload".to_string()
        }),
    }
}

/// Per-size regression: 3 unlimited runs pin the peak number, then one run
/// with the enforceable device capacity armed asserts the keygen completes
/// and peaks identically (the limit must never bind). Asserts at every level
/// that the peak fits `RSA_HEAP`.
fn assert_keygen_fits(bits: u32) {
    // The caller (each `rsa_keygen_peak_*` test) holds `serial_lock()`.
    let max_peak = measure_peak(bits, 3);
    assert!(
        max_peak > 0,
        "US-942: the measurement window must observe a nonzero peak for RSA-{bits}"
    );
    assert!(
        max_peak <= DEVICE_RSA_HEAP_SIZE,
        "US-956: RSA-{bits} keygen peak {max_peak} B exceeds the \
         {DEVICE_RSA_HEAP_SIZE} B RSA_HEAP — heap sizing is gated on the measured \
         worst case AND the RP2350 SRAM budget (docs/tasks/us956-ram-right-sizing.md)"
    );
    match measure_at_limit(bits) {
        Ok(peak) => {
            assert_eq!(
                peak, max_peak,
                "US-956: the limited run must reproduce the unlimited peak \
                 (the heap fits — the limit must never bind)"
            );
            println!(
                "US942 SUMMARY bits={bits} unlimited_peak_max={max_peak} \
                 unlimited_peak_max_kib={:.2} device_heap={} verdict_fits=FITS \
                 limit_run_peak={peak}",
                max_peak as f64 / 1024.0,
                DEVICE_RSA_HEAP_SIZE
            );
        }
        Err(msg) => panic!(
            "US-956: RSA-{bits} keygen FAILED under the armed \
             {DEVICE_RSA_HEAP_SIZE} B heap: {msg:?} (a process abort with \
             `memory allocation of N bytes failed` is the same verdict — the heap \
             does not fit)"
        ),
    }
}

/// US-956: RSA-2048 keygen fits the RSA_HEAP (measured peak 7,018 B).
#[test]
fn rsa_keygen_peak_2048() {
    let _serial = serial_lock();
    assert_keygen_fits(2048);
}

/// US-956: RSA-3072 keygen fits the RSA_HEAP (measured peak 13,034 B).
#[test]
fn rsa_keygen_peak_3072() {
    let _serial = serial_lock();
    assert_keygen_fits(3072);
}

/// US-956: RSA-4096 keygen fits the RSA_HEAP (measured peak 13,162 B —
/// the upstream "4096 may exceed 128 KiB" warning stays measured-false).
#[test]
fn rsa_keygen_peak_4096() {
    let _serial = serial_lock();
    assert_keygen_fits(4096);
}

/// Ambient control: the same window span around a non-keygen card operation
/// (GET DATA of the just-PUT attribute inside a personalized card) — the
/// host-side allocation noise the peaks include on top of keygen (~256 B).
#[test]
fn rsa_window_ambient_control() {
    let _serial = serial_lock();
    let id = format!("fapico2-us942-ambient-{}", std::process::id());
    opcard::virt::with_ram_client(&id, |client| {
        let mut app = OpenPgpApp::new(client);
        let mut d: Dispatcher<1> = Dispatcher::new();
        assert!(d.register(&mut app), "register openpgp app");
        personalize_rsa_card(&mut d, 2048);

        window_enter(None);
        let (_, sw) = apdu_read(&mut d, &[0x00, 0xCA, 0x00, 0xC1, 0x00]);
        let peak = window_exit();
        assert_eq!(sw, SW_OK);
        println!("US942 RESULT kind=ambient_control peak={peak} peak_bytes_above_baseline");
    });
}

// ---------------------------------------------------------------------------
// US-942 requirement 4: the full RSA-4096 card scenario.
// ---------------------------------------------------------------------------

/// Parse the READ PUBLIC KEY 7F49 reply for an RSA key: `7F 49 <len> 81
/// <len> <n> 82 <len> <e>` (the `81/82` RsaParts wire shape; dispatch.rs
/// `rsa_pubkey_from_template`). Returns (n, e).
fn rsa_pubkey_from_template(body: &[u8]) -> (Vec<u8>, Vec<u8>) {
    fn take_len(data: &[u8], i: usize) -> (usize, usize) {
        match data[i] {
            l @ 0x00..=0x7f => (l as usize, i + 1),
            0x81 => (data[i + 1] as usize, i + 2),
            0x82 => (((data[i + 1] as usize) << 8) | data[i + 2] as usize, i + 3),
            b => panic!("unexpected length byte {b:02x} in template"),
        }
    }
    assert_eq!(&body[..2], &[0x7f, 0x49], "reply must open with the 7F49 template");
    let (_total, mut i) = take_len(body, 2);
    assert_eq!(body[i], 0x81, "first template member must be tag 81 (modulus)");
    i += 1;
    let (n_len, next) = take_len(body, i);
    i = next;
    let n = body[i..i + n_len].to_vec();
    i += n_len;
    assert_eq!(body[i], 0x82, "second template member must be tag 82 (exponent)");
    i += 1;
    let (e_len, next) = take_len(body, i);
    i = next;
    let e = body[i..i + e_len].to_vec();
    (n, e)
}

/// PSO:SIGN (INS 2A 9E 9A) with a DigestInfo, Le = 0 (the raw signature fills
/// the max-length reply exactly).
fn pso_sign_apdu(info: &[u8; 51]) -> Vec<u8> {
    let mut apdu = vec![0x00u8, 0x2A, 0x9E, 0x9A, info.len() as u8];
    apdu.extend_from_slice(info);
    apdu.push(0x00);
    apdu
}

/// SHA-256 DigestInfo over `message` (RFC 8017 §9.2 with the SHA-256
/// prefix): `30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || h`.
fn sha256_digest_info(message: &[u8]) -> [u8; 51] {
    use sha2::Digest as _;
    let digest: [u8; 32] = sha2::Sha256::digest(message).into();
    let mut info = [0u8; 51];
    info[..19].copy_from_slice(&[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, 0x05, 0x00, 0x04, 0x20,
    ]);
    info[19..].copy_from_slice(&digest);
    info
}

/// Does `signature` verify as PKCS#1 v1.5 (SHA-256 DigestInfo prefix) over
/// `digest`? The card signs the raw DigestInfo with an *unprefixed*
/// `SigningKey` (rsa-alloc `sign`), so verification uses
/// `VerifyingKey::<Sha256>` (whose prefix is exactly that DigestInfo) over
/// the bare 32-byte digest — same reasoning as dispatch.rs `rsa_verifies`.
fn rsa_verifies(pub_key: &rsa::RsaPublicKey, digest: &[u8; 32], signature: &[u8]) -> bool {
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::hazmat::PrehashVerifier as _;

    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(signature) else {
        return false;
    };
    VerifyingKey::<sha2::Sha256>::new(pub_key.clone())
        .verify_prehash(digest, &signature)
        .is_ok()
}

/// US-942 requirement 4: the advertised `rsa4096-gen` capability is real, end
/// to end through the virt path — GENERATE ASYMMETRIC KEY PAIR (RSA-4096,
/// the device capacity armed) → READ PUBLIC KEY → parse the `81/82` RsaParts
/// shape → serialize the host-side `rsa::RsaPublicKey` from the card's own
/// modulus/exponent → PSO:SIGN → PKCS#1 v1.5 verification with the generated
/// key; a tampered digest must not verify.
#[test]
fn rsa4096_generated_key_signs_verifiably() {
    use rsa::traits::PublicKeyParts as _;

    let _serial = serial_lock();
    let id = format!("fapico2-us942-gen4096-sign-{}", std::process::id());
    opcard::virt::with_ram_client(&id, |client| {
        let mut app = OpenPgpApp::new(client);
        let mut d: Dispatcher<1> = Dispatcher::new();
        assert!(d.register(&mut app), "register openpgp app");
        personalize_rsa_card(&mut d, 4096);

        // GENERATE with the enforceable device capacity armed — the OOM
        // verdict for the heap under test is loud, the peak is asserted.
        window_enter(Some(DEVICE_RSA_HEAP_SIZE));
        let gen = vec![0x00u8, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00, 0x00];
        let (gen_body, sw) = apdu_read(&mut d, &gen);
        let gen_peak = window_exit();
        assert_eq!(sw, SW_OK, "GENERATE RSA-4096 must answer 9000, got {sw:04x}");
        assert!(
            gen_peak <= DEVICE_RSA_HEAP_SIZE,
            "US-956: RSA-4096 GENERATE peak {gen_peak} B must fit the \
             {DEVICE_RSA_HEAP_SIZE} B RSA_HEAP"
        );
        println!("US942 RESULT kind=generate4096 peak={gen_peak} template_len={}", gen_body.len());

        // READ PUBLIC KEY: the card's own serialization of the generated key,
        // in the `81/82` RsaParts wire shape.
        let read = vec![0x00u8, 0x47, 0x81, 0x00, 0x02, 0xB6, 0x00, 0x00];
        let (body, sw) = apdu_read(&mut d, &read);
        assert_eq!(sw, SW_OK, "READ PUBLIC KEY must answer 9000, got {sw:04x}");
        let (n, e) = rsa_pubkey_from_template(&body);
        assert_eq!(n.len(), 512, "RSA-4096 modulus must be 512 bytes (the 7F49 81 member)");
        assert_eq!(e, vec![0x01, 0x00, 0x01], "the exponent must be 65537 (82 member)");

        // Serialize the RsaParts into the verification key: derived from
        // exactly the (n, e) the card reports, never from a host-side twin.
        let pub_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&n),
            rsa::BigUint::from_bytes_be(&e),
        )
        .expect("the card-reported (n, e) must form a valid RSA public key");
        assert_eq!(pub_key.size(), 512, "the serialized key must be a 4096-bit key");

        // PSO:SIGN needs a PW1 sign session (the personalized PIN, P2 = 81).
        let (_, sw) = apdu(
            &mut d,
            &[0x00, 0x20, 0x00, 0x81, 0x06, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
        );
        assert_eq!(sw, SW_OK, "VERIFY PW1 (sign) must answer 9000");

        // PSO:SIGN over a host-computed SHA-256 DigestInfo — with the device
        // capacity armed (rsa-alloc's sign path also allocates: PKCS#8 key
        // load + big-integer math).
        let info = sha256_digest_info(b"fapico2-us942-rsa4096-pso");
        window_enter(Some(DEVICE_RSA_HEAP_SIZE));
        let (signature, sw) = apdu_read(&mut d, &pso_sign_apdu(&info));
        let sign_peak = window_exit();
        assert_eq!(sw, SW_OK, "PSO:SIGN RSA-4096 must answer 9000, got {sw:04x}");
        assert!(
            sign_peak <= DEVICE_RSA_HEAP_SIZE,
            "US-956: RSA-4096 PSO:SIGN peak {sign_peak} B must fit the \
             {DEVICE_RSA_HEAP_SIZE} B RSA_HEAP"
        );
        // US-956: this is the *sizing* peak — the worst RSA operation the
        // device can reach today, and the one the multiplier in
        // `platform/src/rsa_heap.rs` is applied to. Assert a floor on the
        // headroom so a future RSA path that allocates more fails on a
        // *bound* with an actionable message, rather than only on the
        // abort-on-exhaustion (which is what the limit above would produce).
        // The floor is 1.5x; the actual measured multiplier is 1.98x.
        const MIN_HEADROOM_X1000: usize = 1500;
        assert!(
            sign_peak * 1000 <= DEVICE_RSA_HEAP_SIZE * MIN_HEADROOM_X1000,
            "US-956: RSA-4096 PSO:SIGN peak {sign_peak} B leaves less than \
             {}x headroom in the {DEVICE_RSA_HEAP_SIZE} B RSA_HEAP — re-derive the \
             heap size (and the RP2350 SRAM budget) before the OOM becomes an abort",
            MIN_HEADROOM_X1000 as f64 / 1000.0
        );
        println!(
            "US956 MARGIN worst_peak={sign_peak} B device_heap={DEVICE_RSA_HEAP_SIZE} B \
             headroom={} B multiplier={:.2}x",
            DEVICE_RSA_HEAP_SIZE - sign_peak,
            DEVICE_RSA_HEAP_SIZE as f64 / sign_peak as f64
        );
        assert_eq!(
            signature.len(),
            512,
            "PSO:SIGN must return exactly the modulus length, no TLV wrapping"
        );
        println!("US942 RESULT kind=sign4096 peak={sign_peak} signature_len={}", signature.len());

        // Verify with the generated key (PKCS#1 v1.5, SHA-256 DigestInfo).
        let digest: [u8; 32] = info[19..].try_into().unwrap();
        assert!(
            rsa_verifies(&pub_key, &digest, &signature),
            "the RSA-4096 signature must verify against the card-reported public key"
        );
        // One flipped digest bit → must not verify.
        let mut tampered_digest = digest;
        tampered_digest[0] ^= 1;
        assert!(
            !rsa_verifies(&pub_key, &tampered_digest, &signature),
            "the signature must not verify over a tampered digest"
        );
    });
}

// ---------------------------------------------------------------------------
// US-957: the two workloads the US-956 justification never measured.
//
// US-956 shrank the device RSA heap from 128 KiB to 48 KiB and justified it
// against three measured peaks (GENERATE at 2048/3072/4096, PSO:SIGN at 4096,
// plus an ambient control). Two further RSA workloads exist on the card and
// were **not** armed against the cap:
//
// - **PSO:DECIPHER with an RSA key** — `vendor/opcard/src/command/pso.rs`
//   `decrypt_rsa` → the trussed `decrypt` syscall →
//   `trussed-rsa-alloc` `SoftwareRsa::decrypt`, which does PKCS#1 v1.5
//   *unpadding with blinding* (RFC 8017 §7.2.2) and deserializes the key into
//   `BigUint`s. A different allocation shape from both keygen and sign.
// - **PUT KEY (INS DB) private import** — `private_key_template.rs`
//   `parse_rsa_template` → `RsaImportFormat{p, q}` →
//   `from_components(&p·q, e, d, vec![p, q])` + `precompute()`. A third shape
//   again: it builds the modulus product and the CRT inverse, which neither
//   of the US-956 workloads does.
//
// Both are measured here at 4096 bits (the largest modulus the card serves)
// through the same `window_enter(Some(DEVICE_RSA_HEAP_SIZE))` instrument the
// keygen/sign tests use, and both are folded into the *sizing* worst case
// asserted by `rsa_sizing_worst_case_fits_heap_with_headroom` below.
// ---------------------------------------------------------------------------

/// A deterministic RSA test key in the `(e, p, q, n)` shape the card's PUT
/// KEY import takes. Same shape as the RSA-2048 fixture in `tests/dispatch.rs`.
struct RsaTestKey {
    e: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    n: Vec<u8>,
}

/// Fixed-seed keygen, memoised per modulus width: failures are reproducible
/// and the (multi-second) prime search is paid once per width per test
/// binary, never inside a measurement window.
fn rsa_test_key(bits: u32) -> &'static RsaTestKey {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Mutex<Vec<(u32, &'static RsaTestKey)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(Vec::new()));
    let mut cache = cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, k)) = cache.iter().find(|(b, _)| *b == bits) {
        return k;
    }
    use rand::SeedableRng as _;
    use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};

    let mut rng = rand::rngs::StdRng::seed_from_u64(0x4641_5049_434F_0900 | u64::from(bits));
    let private = rsa::RsaPrivateKey::new(&mut rng, bits as usize)
        .unwrap_or_else(|e| panic!("deterministic RSA-{bits} keygen must succeed: {e}"));
    let primes = private.primes();
    assert_eq!(primes.len(), 2, "RSA-{bits} private key has exactly two primes");
    let e = private.e().to_bytes_be();
    let half = (bits / 16) as usize; // bytes per CRT prime
    let pad = |mut v: Vec<u8>| -> Vec<u8> {
        while v.len() < half {
            v.insert(0, 0);
        }
        v
    };
    let (p, q) = (pad(primes[0].to_bytes_be()), pad(primes[1].to_bytes_be()));
    let n = (&primes[0] * &primes[1]).to_bytes_be();
    assert_eq!(n.len(), (bits / 8) as usize, "RSA-{bits} modulus width");
    let leaked: &'static RsaTestKey = Box::leak(Box::new(RsaTestKey { e, p, q, n }));
    cache.push((bits, leaked));
    leaked
}

/// BER definite length for a template member (`dispatch.rs` `der_len`).
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

/// PUT KEY (INS DB 3F FF) of a full RSA private key: extended header `B8 00`
/// (decryption slot, key *and* CRT — no `B6`), a `7F48` template carrying
/// `91 e` / `92 p` / `93 q`, and a `5F48` concatenation DO `e || p || q`.
/// Built on the host, *before* the measurement window opens, so the window
/// measures only what the card allocates.
fn put_key_rsa_apdu(crt: &[u8], e: &[u8], p: &[u8], q: &[u8]) -> Vec<u8> {
    // The `7F48` template carries tags and lengths only — opcard's
    // `parse_rsa_template` walks it purely to compute the (offset, len) of
    // e/p/q inside the `5F48` concatenation DO, so appending the parts here
    // would desynchronise that walk (the same shape as `tests/dispatch.rs`).
    let mut template = Vec::new();
    for (tag, part) in [(0x91u8, e), (0x92u8, p), (0x93u8, q)] {
        template.push(tag);
        template.extend_from_slice(&der_len(part.len()));
    }
    let mut key_data = Vec::from(e);
    key_data.extend_from_slice(p);
    key_data.extend_from_slice(q);

    let mut content = Vec::from(crt);
    for (tag, value) in [(&[0x7fu8, 0x48][..], template), (&[0x5fu8, 0x48][..], key_data)] {
        content.extend_from_slice(tag);
        content.extend_from_slice(&der_len(value.len()));
        content.extend_from_slice(&value);
    }

    let mut blob = vec![0x4Du8];
    blob.extend_from_slice(&der_len(content.len()));
    blob.extend_from_slice(&content);

    // Extended APDU: `00 DB 3F FF 00 <LcHi LcLo> <data>`, no Le.
    let mut apdu = vec![0x00u8, 0xDB, 0x3F, 0xFF, 0x00];
    apdu.extend_from_slice(&(blob.len() as u16).to_be_bytes());
    apdu.extend_from_slice(&blob);
    apdu
}

/// PSO:DECIPHER (INS 2A 80 86) with the raw cipher DO. The DO exceeds short
/// Lc for RSA-4096 (513 B), so the APDU uses extended length (3-byte Lc) and
/// carries no Le — the plaintext reply is shorter than the ciphertext and the
/// dispatcher sizes the response buffer itself (§7.2.11).
fn pso_decipher_apdu(data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00u8, 0x2A, 0x80, 0x86, 0x00];
    apdu.extend_from_slice(&(data.len() as u16).to_be_bytes());
    apdu.extend_from_slice(data);
    apdu
}

/// Host-side PKCS#1 v1.5 (encryption) of `plaintext` with a *fixed* padding
/// seed (RFC 8017 §7.2.1, `EM = 00 02 PS 00 || M`) — byte-for-byte
/// deterministic, so the host allocates no big-integer state inside the card
/// measurement window and no rng is involved.
fn pkcs1v15_encrypt_fixed_ps(n: &[u8], e: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let k = n.len();
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x02);
    while em.len() < k - plaintext.len() - 1 {
        em.push(((em.len() * 7) % 255 + 1) as u8);
    }
    em.push(0x00);
    em.extend_from_slice(plaintext);
    assert_eq!(em.len(), k, "EM must fill the RSA block exactly");
    let m = rsa::BigUint::from_bytes_be(&em);
    let c = m.modpow(
        &rsa::BigUint::from_bytes_be(e),
        &rsa::BigUint::from_bytes_be(n),
    );
    let mut ct = c.to_bytes_be();
    while ct.len() < k {
        ct.insert(0, 0);
    }
    ct
}

/// The 32-byte payload the PSO:DECIPHER scenario round-trips. The DO the
/// card receives is one leading `0x00` padding-indicator byte followed by the
/// ciphertext (§7.2.11); the DEC slot is addressed by the default `03 00`
/// key reference, so the DO is exactly `00 || ciphertext`.
const DEC_PLAINTEXT: &[u8; 32] = b"fapico2-us957-rsa-dec-4096!!!!!!";

/// Fresh ram card, SELECT, PW3 verify, RSA *decryption* attribute (tag C2) for
/// `bits`, PIN personalization — everything except PUT KEY / PSO:DECIPHER.
fn personalize_rsa_dec_card(dispatcher: &mut Dispatcher<1>, bits: u32) {
    let (_, sw) = apdu(dispatcher, &select_openpgp());
    assert_eq!(sw, SW_OK, "SELECT must answer 9000");
    let (_, sw) = apdu(
        dispatcher,
        &[0x00, 0x20, 0x00, 0x83, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38],
    );
    assert_eq!(sw, SW_OK, "VERIFY PW3 must answer 9000");
    let (_, sw) = apdu(dispatcher, &put_data_apdu(0x00, 0xC2, &rsa_attr(bits)));
    assert_eq!(sw, SW_OK, "PUT DATA RSA-{bits} DEC attribute must answer 9000");
    let (_, sw) = apdu(
        dispatcher,
        &[0x00, 0x24, 0x00, 0x81, 0x0C,
          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
    );
    assert_eq!(sw, SW_OK, "CHANGE PW1 must answer 9000");
    let (_, sw) = apdu(
        dispatcher,
        &[0x00, 0x24, 0x00, 0x83, 0x10,
          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
          0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
    );
    assert_eq!(sw, SW_OK, "CHANGE PW3 must answer 9000");
}

/// One PUT KEY import at `bits` with the device capacity optionally armed.
/// Returns the window peak in bytes. The peak is the third allocation shape
/// (`from_components` + `precompute`), so it is measured with the *same*
/// instrument as keygen and sign — not inferred from them.
fn import_peak_once(bits: u32, limit: Option<usize>, tag: &str) -> usize {
    let id = format!("fapico2-us957-import-{tag}-{bits}-{}", std::process::id());
    opcard::virt::with_ram_client(&id, |client| {
        let mut app = OpenPgpApp::new(client);
        let mut d: Dispatcher<1> = Dispatcher::new();
        assert!(d.register(&mut app), "register openpgp app");
        personalize_rsa_dec_card(&mut d, bits);

        let k = rsa_test_key(bits);
        // Build the APDU on the host *before* opening the window.
        let apdu_bytes = put_key_rsa_apdu(&[0xB8, 0x00], &k.e, &k.p, &k.q);
        window_enter(limit);
        let (_, sw) = apdu(&mut d, &apdu_bytes);
        let peak = window_exit();
        assert_eq!(sw, SW_OK, "PUT KEY RSA-{bits} import must answer 9000, got {sw:04x}");
        println!("US957 RESULT kind=import bits={bits} tag={tag} peak={peak} peak_kib={:.2}", peak as f64 / 1024.0);
        peak
    })
}

/// One PSO:DECIPHER roundtrip at `bits` with the device capacity optionally
/// armed: the RSA-4096 key is imported *outside* the window (that is the
/// `import_peak_once` scenario), a PW1-other session is opened, then the
/// window wraps only the decipher APDU.
fn decipher_peak_once(bits: u32, limit: Option<usize>, tag: &str) -> usize {
    let id = format!("fapico2-us957-dec-{tag}-{bits}-{}", std::process::id());
    opcard::virt::with_ram_client(&id, |client| {
        let mut app = OpenPgpApp::new(client);
        let mut d: Dispatcher<1> = Dispatcher::new();
        assert!(d.register(&mut app), "register openpgp app");
        personalize_rsa_dec_card(&mut d, bits);

        let k = rsa_test_key(bits);
        let (_, sw) = apdu(&mut d, &put_key_rsa_apdu(&[0xB8, 0x00], &k.e, &k.p, &k.q));
        assert_eq!(sw, SW_OK, "PUT KEY RSA-{bits} import must answer 9000, got {sw:04x}");
        let (_, sw) = apdu(
            &mut d,
            &[0x00, 0x20, 0x00, 0x82, 0x06, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
        );
        assert_eq!(sw, SW_OK, "VERIFY PW1 (other) must answer 9000");

        // Host-side encryption happens before the window.
        let ciphertext = pkcs1v15_encrypt_fixed_ps(&k.n, &k.e, DEC_PLAINTEXT);
        let mut data = vec![0x00u8];
        data.extend_from_slice(&ciphertext);
        let decipher = pso_decipher_apdu(&data);

        window_enter(limit);
        let (body, sw) = apdu_read(&mut d, &decipher);
        let peak = window_exit();
        assert_eq!(sw, SW_OK, "PSO:DECIPHER RSA-{bits} must answer 9000, got {sw:04x}");
        assert_eq!(
            body,
            DEC_PLAINTEXT.as_slice(),
            "PSO:DECIPHER must return the original plaintext byte-exact"
        );
        println!("US957 RESULT kind=decipher bits={bits} tag={tag} peak={peak} peak_kib={:.2}", peak as f64 / 1024.0);
        peak
    })
}

/// Shared driver: `reps` unlimited runs pin the peak number, then one run
/// with the enforceable device capacity armed asserts the operation
/// completes and peaks identically (the limit must never bind). The caller
/// (each test) holds `serial_lock()`.
#[derive(Clone, Copy)]
enum Workload {
    Import,
    Decipher,
}

fn workload_peak_once(w: Workload, bits: u32, limit: Option<usize>, tag: &str) -> usize {
    match w {
        Workload::Import => import_peak_once(bits, limit, tag),
        Workload::Decipher => decipher_peak_once(bits, limit, tag),
    }
}

fn assert_workload_fits(w: Workload, bits: u32, reps: usize) -> usize {
    let name = match w {
        Workload::Import => "PUT KEY import",
        Workload::Decipher => "PSO:DECIPHER",
    };
    let mut max_peak = 0usize;
    for rep in 0..reps {
        let peak = workload_peak_once(w, bits, None, &format!("open-{rep}"));
        max_peak = max_peak.max(peak);
    }
    assert!(max_peak > 0, "US-957: the {name} window must observe a nonzero peak");
    let limited = panic::catch_unwind(AssertUnwindSafe(|| {
        workload_peak_once(w, bits, Some(DEVICE_RSA_HEAP_SIZE), "lim")
    }));
    WINDOW_OPEN.store(false, Ordering::Relaxed);
    LIMIT.store(0, Ordering::Relaxed);
    match limited {
        Ok(peak) => {
            assert_eq!(
                peak, max_peak,
                "US-957: the limited {name} run must reproduce the unlimited peak"
            );
        }
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic payload".to_string()
            };
            panic!(
                "US-957: {name} at RSA-{bits} FAILED under the armed \
                 {DEVICE_RSA_HEAP_SIZE} B heap: {msg:?} (a process abort with \
                 `memory allocation of N bytes failed` is the same verdict — on the \
                 device that is a hard reset, a second dark boot)"
            );
        }
    }
    println!(
        "US957 SUMMARY workload={name} bits={bits} peak={max_peak} \
         peak_kib={:.2} device_heap={DEVICE_RSA_HEAP_SIZE} verdict_fits=FITS",
        max_peak as f64 / 1024.0
    );
    max_peak
}

/// US-957: PUT KEY of an RSA private key (e, p, q) fits the RSA_HEAP with the
/// enforceable device capacity armed, at every modulus width the card serves.
#[test]
fn rsa_private_import_peak_fits_heap() {
    let _serial = serial_lock();
    assert_workload_fits(Workload::Import, 2048, 3);
    assert_workload_fits(Workload::Import, 3072, 3);
    assert_workload_fits(Workload::Import, 4096, 3);
}

/// US-957: PSO:DECIPHER with an RSA key fits the RSA_HEAP with the
/// enforceable device capacity armed, at every modulus width.
#[test]
fn rsa_pso_decipher_peak_fits_heap() {
    let _serial = serial_lock();
    assert_workload_fits(Workload::Decipher, 2048, 3);
    assert_workload_fits(Workload::Decipher, 3072, 3);
    assert_workload_fits(Workload::Decipher, 4096, 3);
}

/// US-957 sizing bound: the heap must clear the **largest** of every measured
/// RSA workload by the documented multiplier. This is the assertion that ties
/// the two new measurements into the heap sizing rather than letting them sit
/// as informational prints. The peak is the max of:
/// keygen (2048/3072/4096), PSO:SIGN (4096), PUT KEY import (4096) and
/// PSO:DECIPHER (4096) — i.e. every RSA path the card can reach today.
#[test]
fn rsa_sizing_worst_case_fits_heap_with_headroom() {
    /// The measured worst case across *all four* RSA workloads, re-derived by
    /// US-957. Mirrored in `platform/src/rsa_heap.rs`.
    const SIZING_PEAK_B: usize = 24_792; // US-957: PSO:SIGN RSA-4096, re-confirmed

    let _serial = serial_lock();
    let import_peak = assert_workload_fits(Workload::Import, 4096, 1);
    let decipher_peak = assert_workload_fits(Workload::Decipher, 4096, 1);
    let worst = SIZING_PEAK_B.max(import_peak).max(decipher_peak);
    // Floor: 1.5x, the same floor the sign path asserts. On device there is no
    // recoverable OOM (`handle_alloc_error` under `panic = "abort"`), so the
    // headroom has to absorb one further `Vec` doubling rung by construction
    // rather than by luck.
    const MIN_HEADROOM_X1000: usize = 1500;
    assert!(
        worst * 1000 <= DEVICE_RSA_HEAP_SIZE * MIN_HEADROOM_X1000,
        "US-957: the worst RSA peak across keygen/sign/import/decipher ({worst} B) \
         leaves less than {}x headroom in the {DEVICE_RSA_HEAP_SIZE} B RSA_HEAP — \
         re-derive the heap size (and the RP2350 SRAM budget in \
         docs/size-report.md) before an overrun becomes a hard reset",
        MIN_HEADROOM_X1000 as f64 / 1000.0
    );
    println!(
        "US957 MARGIN import_peak={import_peak} decipher_peak={decipher_peak} \
         worst_peak={worst} device_heap={DEVICE_RSA_HEAP_SIZE} \
         headroom={} B multiplier={:.2}x",
        DEVICE_RSA_HEAP_SIZE - worst,
        DEVICE_RSA_HEAP_SIZE as f64 / worst as f64
    );
}
