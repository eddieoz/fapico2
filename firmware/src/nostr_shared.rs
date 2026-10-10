//! US-1658 — shared applet ownership: `NOSTR_APP` behind the first
//! device-code blocking mutex (design §A.8.3 #3).
//!
//! The applet instance lives in the CCID `Dispatcher` while FIDO is owned by
//! `hid_task`, and both transports must reach it. `init_static_slot`'s
//! sole-`&mut` rule admits exactly one borrower, so the instance instead
//! sits behind the [`NOSTR_APP`] mutex — the first `embassy_sync::Mutex`
//! in device code in the tree (every existing Mutex hit is host-test
//! `std`) — and both the CCID proxy and the Nostr HID serve path reach the
//! applet through [`with_nostr`].
//!
//! This module is bin-independent on purpose: it is a lib module so the
//! shared-ownership shape is host-testable (the device bin is arm-only and
//! has no host test target), and so a second serving arm can route through
//! the same mutex rather than a structurally-identical private instance.
//! Nothing here is arm-specific; the gate matches [`hid_serve`]'s because
//! the module needs `embassy-sync` and the applet crate, which only the
//! device and emulation builds enable.

use fapico2_nostr::NostrApp;
use fapico2_platform::dispatch::{App as _, MAX_RESPONSE};

// US-1642: the Nostr applet — not a write-once `MaybeUninit` slot, because
// US-1658 changes its ownership story: **both** transports must reach the
// one instance (the CCID dispatcher *and* the Nostr HID interface, D23), and
// `init_static_slot`'s sole-`&mut` rule admits exactly one borrower. This is
// the first `embassy_sync::Mutex` in device code in the tree (every existing
// Mutex hit is host-test `std`), a new ownership discipline beside
// `init_static_slot`'s rule. It is constructed bare (`NostrApp::new()` is
// const) and the boot path installs the providers through the lock — the
// lock is contended only by short, synchronous critical sections
// (`App::process` has no `.await`), and the touch wait happens OUTSIDE the
// lock: the applet's strict presence path parks and returns, so a pending
// window never blocks the other transport (design §A.8.3 #3). Snapshots and
// flash commits stay under the lock, closing the two-writer race.
/// `Mutex`'s Sync bound needs the guarded value `Send`, and `NostrRegion`'s
/// `Box<dyn KeyRegion>` is a plain trait object — none of the region
/// backends promise `Send`. The promise is made here instead, once, with the
/// scope written down: the RP2350 is single-core and its executor is
/// cooperative; the applet's interior is only ever touched by the two
/// serving tasks (CCID and the Nostr HID interface), whose accesses the
/// Mutex serializes inside `.await`-free critical sections; and no
/// reference to the applet ever crosses a thread boundary. This is the same
/// single-core-serializes argument `tasks.rs` documents for the aliased
/// store/flash handles — not a new concurrency story, the same one made
/// nameable.
pub struct DeviceNostrApp(pub NostrApp);

// SAFETY: see the struct docs — single-core cooperative executor, Mutex-
// serialized access, no cross-thread references.
unsafe impl Send for DeviceNostrApp {}

pub static NOSTR_APP: embassy_sync::blocking_mutex::Mutex<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    DeviceNostrApp,
> = embassy_sync::blocking_mutex::Mutex::new(DeviceNostrApp(NostrApp::new()));

/// Runs `f` with the shared Nostr applet (US-1658).
///
/// This is the ONE accessor both transports use — the CCID proxy below and
/// the Nostr HID serve path call it, and nothing reaches `NOSTR_APP`'s
/// interior directly. The blocking-closure shape (not the async `lock()`) is
/// the deliberate choice: `App::process` is synchronous, the guard must not
/// survive a `.await` (the touch wait happens outside the lock, §A.8.3 #3),
/// and the closure form makes holding across a wait impossible to express.
///
/// # SAFETY
///
/// `BlockingMutex::lock_mut` is unsafe iff the closure could re-enter the
/// mutex (self-deadlock). `f` never does: it receives the applet's own
/// `&mut`, and the applet's body reaches the presence runtime, the region
/// and the RNG pool — never this mutex. The single unsafe site is the point.
pub fn with_nostr<R>(f: impl FnOnce(&mut NostrApp) -> R) -> R {
    unsafe { NOSTR_APP.lock_mut(|app| f(&mut app.0)) }
}

/// The CCID arm's proxy onto [`NOSTR_APP`] (US-1658).
///
/// `CCID_DISPATCHER` holds `&'static mut dyn App` — and the Mutex admits no
/// stable `&mut` to the applet behind it, so the CCID arm reaches the applet
/// through this zero-sized proxy, which locks per call. Every lock is held
/// only inside the synchronous [`App::process`] body (no `.await` inside the
/// gate, no touch wait under the lock — the strict presence path parks and
/// returns), so the two transports' critical sections stay word-scale and
/// the cooperative executor cannot deadlock. The touch wait happens outside
/// the lock by construction; snapshots and flash commits stay under it.
pub struct NostrViaMutex;

/// Write-once slot for the proxy (the dispatcher borrows it for `'static`).
pub static mut NOSTR_CCID_PROXY: core::mem::MaybeUninit<NostrViaMutex> =
    core::mem::MaybeUninit::uninit();

impl fapico2_platform::dispatch::App for NostrViaMutex {
    fn aid(&self) -> &[u8] {
        fapico2_nostr::NOSTR_AID
    }

    fn select(&mut self, internal: bool) -> fapico2_platform::dispatch::Sw {
        with_nostr(|app| app.select(internal))
    }

    fn deselect(&mut self) {
        with_nostr(|app| app.deselect());
    }

    fn process(
        &mut self,
        apdu: &[u8],
        resp: &mut heapless::Vec<u8, MAX_RESPONSE>,
    ) {
        with_nostr(|app| app.process(apdu, resp));
    }

    fn select_apdu(
        &mut self,
        internal: bool,
        apdu: &[u8],
        resp: &mut heapless::Vec<u8, MAX_RESPONSE>,
    ) -> fapico2_platform::dispatch::Sw {
        with_nostr(|app| app.select_apdu(internal, apdu, resp))
    }
}

// US-1662: the vendor arm's scratch. Both are the HID Nostr arm's
// write-once-in-use buffers — the same single-owner discipline as
// `boot::NOSTR_RESP`, here because the impl that uses them is a lib module
// (and the device bin is arm-only). The CCID arm has its own buffers; the
// applet itself is what the shared mutex guards, and these are filled and
// drained inside one synchronous `process_vendor` body, never across an
// `.await`.
//
// Request: the CBOR request decoded and re-framed as the applet APDU
// (`[00, INS, idx, 00, Lc, arg…]`) — `nostr_wire::NOSTR_APDU_REQ_MAX` sizes
// the worst legal `NIP44_DECRYPT` argument plus the header. Response: the
// applet's `App::process` signature demands `MAX_RESPONSE` (4,096), and the
// legal vendor replies (≤ ~1.9 KB) are cut from it into `NOSTR_RESP` after.
/// The request APDU scratch.
pub static mut NOSTR_APDU_REQ: heapless::Vec<u8, { crate::nostr_wire::NOSTR_APDU_REQ_MAX }> =
    heapless::Vec::new();
/// The applet response scratch (`MAX_RESPONSE`, the `App::process` shape).
pub static mut NOSTR_APDU_RESP: heapless::Vec<u8, MAX_RESPONSE> = heapless::Vec::new();

/// SAFETY (both statics): written and read only by `hid_task`'s Nostr arm,
/// inside the synchronous `process_vendor` body below — one owner, no
/// re-entry (the applet never calls back into the vendor arm), nothing
/// aliasing across the mutex boundary. `NostrApp::process` reads `apdu` as a
/// borrowed slice from `NOSTR_APDU_REQ` while writing `NOSTR_APDU_RESP` — two
/// distinct statics, so no overlap.
impl crate::hid_serve::NostrDispatch for NostrViaMutex {
    fn process_vendor(
        &mut self,
        cmd: u8,
        payload: &[u8],
        out: &mut heapless::Vec<u8, { crate::hid_serve::NOSTR_RESP_MAX }>,
    ) -> usize {
        // SAFETY: single owner (see the statics' docs above).
        let req: &mut heapless::Vec<u8, { crate::nostr_wire::NOSTR_APDU_REQ_MAX }> =
            unsafe { &mut *core::ptr::addr_of_mut!(NOSTR_APDU_REQ) };
        // SAFETY: single owner (see the statics' docs above).
        let resp: &mut heapless::Vec<u8, MAX_RESPONSE> =
            unsafe { &mut *core::ptr::addr_of_mut!(NOSTR_APDU_RESP) };
        crate::nostr_wire::process_vendor_through(
            cmd,
            payload,
            req,
            resp,
            |apdu, resp| with_nostr(|app| app.process(apdu, resp)),
            out,
        )
    }
}

/// Installs the device providers through the lock (US-1658) — the boot path's
/// only mutation of the applet, done before any task runs.
pub fn install_nostr_providers(
    region: fn() -> Option<fapico2_platform::keyregion::nostr_store::NostrRegion>,
    rng: fn(&mut [u8]),
    grant: fn(u32) -> bool,
) {
    with_nostr(|app| app.install_providers(region, rng, grant));
}

// ---------------------------------------------------------------------------
// US-1658 — the shared-ownership shape, host-tested
//
// The touch-wait-outside-the-lock property is realized by the grant
// being a **poll-once** seam (`presence::request_grant` samples one
// press level and answers): the applet never blocks inside the closure,
// so the lock cannot be held across a wait by construction. What a
// synchronous test can still pin is the shape: two client handles, one
// lock, state written through one visible to the other, and the lock
// free again after a denied touch.
// ---------------------------------------------------------------------------
#[cfg(all(test, feature = "emulation"))]
mod us1658_shared_ownership {
    extern crate std;

    use core::sync::atomic::{AtomicUsize, Ordering};

    use fapico2_nostr::{INS_GENERATE_KEY, INS_GET_INFO, INS_SIGN};

    use fapico2_platform::dispatch::{App, SW_OK};
    use fapico2_platform::keyregion::crypto::{derive_payload_key, NOSTR_PAYLOAD_SECRET};
    use fapico2_platform::keyregion::host::FileKeyRegion;
    use fapico2_platform::keyregion::nostr_store::NostrRegion;
    use fapico2_platform::keyregion::TOTAL_SLOTS;

    use super::{with_nostr, MAX_RESPONSE, NostrViaMutex};

    /// How many times the applet asked for a touch. The first call must
    /// grant (the `GENERATE_KEY` the fixture performs), every later call
    /// must refuse — so the `SIGN` leg is what drives the call count to 2,
    /// proving it reached the touch (state precedes touch) rather than
    /// failing earlier.
    static GRANT_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn grant_refuse_after_first(_tag: u32) -> bool {
        GRANT_CALLS.fetch_add(1, Ordering::SeqCst) == 0
    }

    /// A uniform `0x01` fill is a valid secret scalar (non-zero, below the
    /// curve order), so `GENERATE_KEY` succeeds on the first draw.
    fn rng_constant(out: &mut [u8]) {
        out.fill(0x01);
    }

    /// Opens the fixture region file — the same attach-per-command shape
    /// the device uses (`nostr_region` answers per read, from flash).
    fn region_fixture() -> Option<NostrRegion> {
        let path = std::env::temp_dir().join("fapico2-us1658-region.bin");
        let region = FileKeyRegion::open(&path).expect("the fixture region file");
        let otp_row: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x11));
        let chipid: [u8; 8] = 0x0000_BADC_0FFE_EE01_0203_u64.to_be_bytes();
        let key = derive_payload_key(&otp_row, &chipid, &NOSTR_PAYLOAD_SECRET)
            .expect("a non-zero OTP row");
        Some(NostrRegion::new(Box::new(region), key))
    }

    fn apdu(ins: u8, p1: u8, data: &[u8]) -> heapless::Vec<u8, 64> {
        let mut a = heapless::Vec::new();
        a.extend_from_slice(&[0x00, ins, p1, 0x00]).unwrap();
        a.push(data.len() as u8).unwrap();
        a.extend_from_slice(data).unwrap();
        a
    }

    fn sw_of(resp: &[u8]) -> u16 {
        let n = resp.len();
        assert!(n >= 2, "the applet must always answer with a status word");
        u16::from_be_bytes([resp[n - 2], resp[n - 1]])
    }

    #[test]
    fn two_clients_one_lock_and_the_touch_wait_outside() {
        let path = std::env::temp_dir().join("fapico2-us1658-region.bin");
        std::fs::remove_file(&path).ok();
        FileKeyRegion::create(&path, TOTAL_SLOTS).expect("a fresh region file");

        GRANT_CALLS.store(0, Ordering::SeqCst);
        super::install_nostr_providers(region_fixture, rng_constant, grant_refuse_after_first);

        // --- client A: the CCID proxy. Select, then GENERATE (granted).
        let mut proxy = NostrViaMutex;
        assert_eq!(proxy.select(false), SW_OK, "the proxy selects the applet");

        let mut resp: heapless::Vec<u8, MAX_RESPONSE> = heapless::Vec::new();
        proxy.process(&apdu(INS_GENERATE_KEY, 0, &[]), &mut resp);
        assert_eq!(sw_of(&resp), SW_OK, "GENERATE_KEY is granted on the first touch");
        assert_eq!(resp.len(), 34, "npub(32) + SW");
        assert_eq!(GRANT_CALLS.load(Ordering::SeqCst), 1);

        // --- client B: the direct accessor the HID serve path will use.
        // The key client A wrote is visible through the same lock: SIGN
        // gets past the state check and reaches the touch (call 2), which
        // the fixture refuses → 6985, and the closure returns without
        // holding anything.
        let sighash: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x40));
        let mut resp_b: heapless::Vec<u8, MAX_RESPONSE> = heapless::Vec::new();
        with_nostr(|app| app.process(&apdu(INS_SIGN, 0, &sighash), &mut resp_b));
        assert_eq!(sw_of(&resp_b), 0x6985, "a refused touch is SW_TOUCH_REQUIRED");
        assert_eq!(GRANT_CALLS.load(Ordering::SeqCst), 2, "SIGN reached the touch");

        // --- client A again: the lock is free after the denied touch, and
        // the shared applet still answers.
        resp.clear();
        proxy.process(&apdu(INS_GET_INFO, 0, &[]), &mut resp);
        assert_eq!(sw_of(&resp), SW_OK, "the lock is released after the denial");
    }
}
