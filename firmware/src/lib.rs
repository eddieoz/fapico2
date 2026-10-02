//! Pure, host-testable core of the firmware crate (US-705.1).
//!
//! The device bins (`fapico2-firmware`, `bridge`) and the emulation bin link
//! this lib for their transport-layer logic; the HAL/embassy stack stays in
//! the arm-target dependency scope, so the lib — and its unit tests — build
//! on the host unchanged (platform-crate parity). Device-only code (serve
//! loops, boot, USB endpoint I/O) lives in the bins' own modules.

#![cfg_attr(not(test), no_std)]

// US-922: the `dbg-log` diagnostic feature (CTAP-HID vendor cmd 0x42 drain of
// the RAM event ring, device bin only) is **release-forbidden**: a debug
// surface on a fixed channel is exactly what must never ship. `cargo build
// --release --features dbg-log` is refused here (the `release_profile` cfg is
// published by the build script from cargo's PROFILE). Debug builds keep it
// for live diagnosis, and host/emulation builds keep it regardless of profile
// — they have no device USB surface to protect.
#[cfg(all(feature = "dbg-log", release_profile, not(feature = "emulation")))]
compile_error!(
    "US-922: dbg-log is release-forbidden — the diagnostic log channel must \
     not be enabled in a release build; use a debug profile, or the emulation \
     feature for host builds"
);

/// US-956: measured Embassy **task-arena demand** on the device build, in
/// bytes — the sum of the six `embassy_executor::raw::TaskPool<{async fn
/// body of ..}, 1>` types the firmware spawns:
///
/// | task | `TaskPool<F, 1>` |
/// |---|---:|
/// | `button_poll_task` | 56 |
/// | `ccid_task` | 8,600 |
/// | `embassy_main` | 168 |
/// | `hid_task` | 12,304 |
/// | `led_heartbeat_task` | 56 |
/// | `usb_task` | 736 |
/// | **total** | **21,920** |
///
/// The arena itself is `embassy-executor`'s `task-arena-size-32768` feature
/// (`firmware/Cargo.toml`) = 32,768 B, i.e. **1.50x** this demand (floor
/// 1.25x). The feature was `task-arena-size-65536` until US-956, at 3.7x —
/// 46 KiB of a 532,480 B part spent on a reservoir that is 84 % empty, out of
/// a boot path whose statics already claimed 527,420 B.
///
/// The demand was 17,760 B until 2026-10-01, when the re-measurement forced
/// by the `cargo-deps` revert (PR #2) found `hid_task` at 12,224 B rather
/// than the recorded 8,144 B. The 2026-09-30 size-report entry attributed an
/// unchanged arena to the OTP-HID handlers being "synchronous, inside the USB
/// control transfer" — true of the handlers, but not of the future that
/// carries their state, which is where the 4,080 B lives. The earlier stamp
/// was simply never re-run after that change landed.
///
/// The arena is bumped, not paged, and overflow panics "task arena is full"
/// at the first spawn that does not fit — a dark boot, and one nothing
/// measures. That is a *runtime* check, so the value is carried here for a
/// *build-time* one: `tests/scripts/check_boot_chain.py` reads this constant,
/// reads the `embassy_executor::_export::ARENA` symbol size out of the
/// release ELF, and fails if the demand no longer fits (or if the headroom
/// drops below 1.25x).
///
/// US-964: the number above was hand-copied out of a one-off
/// `RUSTFLAGS=-Zprint-type-sizes cargo +nightly build`, and nothing tied it to
/// the build it came from — a contributor could grow `ccid_task`'s future
/// (8,600 B of this total) and the gate would go on publishing `1.85x, floor
/// 1.25x` from a number that no longer described anything, while the device
/// panicked `task arena is full` before USB enumerated. A silently stale
/// number in the one place a floor was added for exactly that reason.
///
/// So the measurement is now a command and the constant carries a stamp:
///
/// ```text
/// python3 tests/scripts/measure_task_arena.py   # re-measure + re-stamp
/// python3 tests/scripts/measure_task_arena.py --check   # no build, no nightly
/// ```
///
/// [`TASK_ARENA_DEMAND_B_STAMP`] is a sha256 over the inputs the measurement
/// was taken from — the firmware's own sources and manifests, plus the
/// resolved version of every package in its dependency closure
/// (`tests/scripts/arena_stamp.py`). `check_boot_chain.py` recomputes it and
/// **fails, naming the command above**, whenever it no longer matches. It
/// never reports a headroom figure from a demand it cannot account for. The
/// measurement itself needs a nightly toolchain (`-Zprint-type-sizes` has no
/// stable equivalent and the futures' types are anonymous, so their sizes are
/// not readable from the ELF), which is why this is stamp-and-refuse rather
/// than a compile-time re-derivation.
pub const TASK_ARENA_DEMAND_B: usize = 21_920;

/// US-964: the fingerprint of the sources [`TASK_ARENA_DEMAND_B`] was
/// measured from — see `tests/scripts/arena_stamp.py` for exactly what it
/// covers, and what it deliberately does not. Not a build input: the gate
/// reads it, and refuses to believe the demand when it disagrees.
pub const TASK_ARENA_DEMAND_B_STAMP: &str = "79ed3ee6bb539f2bc4386c969682237e6aaa49a82eda3d6382dc7f372ced32c2";

/// US-920: pure CCID bulk-OUT message reassembly with a park timeout
/// (partial-message drop + resync, HAL-free, host-testable).
pub mod ccid_reasm;
/// US-922: the per-boot debug-drain channel derivation (pure, host-tested;
/// the device bin seeds it from the TRNG at boot).
pub mod dbg_cid;
pub mod ctap_hid;
/// US-1504: the CTAPHID reply-write park guard — the deadline-bounded reply
/// framing, with the "write one report" step behind a trait so the deadline
/// is testable on the host against a writer that never ACKs.
pub mod hid_reply;
/// US-921: the presence-latch anti-harvest wiring (shared presence runtime).
pub mod presence;

/// US-130 (PICOForge-COMPAT): the OATH applet's SELECT `TAG_NAME` device-id —
/// the per-unit PBKDF2 salt for the OATH access key.
///
/// Shared by the two `OathApp` construction sites so "which unit is this?"
/// is one decision, stated once:
///
/// * `main.rs` (device) passes the real OTP chip-id;
/// * `emul_main.rs` (emulation) passes [`EMULATION_CHIPID`], explicitly and
///   visibly, rather than inheriting a default nobody chose.
pub fn oath_device_id(chipid: u64) -> [u8; fapico2_oath::oath_core::DEVICE_ID_LEN] {
    fapico2_oath::oath_core::device_id_from_chipid(chipid)
}

/// The stand-in chip-id the emulation binary uses for the OATH device-id
/// (re-exported so the emulation call site states it rather than defaulting).
pub const EMULATION_CHIPID: u64 = fapico2_oath::oath_core::EMULATION_CHIPID;
