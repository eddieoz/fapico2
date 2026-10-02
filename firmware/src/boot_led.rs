//! The **LED half** of the boot-phase ladder: drives the board LED
//! (GPIO25, active-low) with one short pulse per boot boundary crossed, so a
//! board that flashed cleanly and then never re-enumerates can be diagnosed by
//! power-cycling it and watching one LED — no debugger, no rebuild, no special
//! image.
//!
//! The encoding, the ordering contract and the pin-handover rule live in
//! [`fapico2_firmware::bootphase`] and are host-tested there. This module is
//! only the ~30 lines that turn a [`bootphase::Mark`] into GPIO writes.
//!
//! # Why this is not `dbg::phase_blinks`
//!
//! `firmware/src/dbg.rs` has had a `phase_blinks(id)` since US-929 and it had
//! **zero call sites in any configuration**. Three reasons, all of which are
//! also why this module is a sibling and not a resurrection of it:
//!
//! * It lives behind `dbg-log` / `boot-timeline`, both **non-default**
//!   features — and `dbg-log` is additionally *release-forbidden* (US-922),
//!   with `tests/scripts/check_dbg_release_gate.py` refusing the build. An
//!   instrument that cannot exist in a shipping image cannot answer the
//!   shipping image's failure.
//! * `bphase!` — the macro every boot boundary already calls — expands to
//!   `dlog!` and nothing else, so the ring (which needs enumeration to drain)
//!   and the blinks were never wired to the same call sites.
//! * Its encoding is **quadratic in the phase id**: phase `N` emits `N`
//!   blinks, so a full ladder costs `sum(1..=19) x 80 ms ≈ 15 s` of boot.
//!   That is why it could not simply be turned on. [`bootphase`] emits **one
//!   pulse per boundary** instead, which is linear.
//!
//! # Pin contention, and how it is resolved
//!
//! GPIO25 has four owners. Three of them cannot overlap the ladder and one is
//! handled explicitly:
//!
//! | owner | when it can drive the pin |
//! |---|---|
//! | this ladder | only between [`ready`] and [`release`] |
//! | `led_heartbeat_task` (1 Hz) | only once the executor polls it — i.e. after `main` awaits, which is after [`release`] |
//! | trussed `LedUi` (`set_status`/`wink`) | only inside `DeviceBackend::boot` and inside synchronous CCID request sections — both after [`release`] |
//! | `button::set_touch_prompt_led` | only from a presence window, which only a serve task can open — after [`release`] |
//!
//! [`release`] is therefore called on the last statement of `main` before it
//! parks into the executor, which is the earliest moment at which **any** of
//! the three runtime owners can exist. Before it, [`Ladder::mark`] refuses
//! every rung. That is a mechanical guarantee rather than an argument about
//! scheduling: after [`release`] this module cannot write the pin at all, so
//! a boot-phase pulse can never leave GPIO25 latched on and mislead a user
//! into reading "touch me" for a consent window that does not exist.
//!
//! Each pulse additionally parks the pin **off** before returning, so even a
//! freeze inside the ladder leaves the pin dark rather than lit.
//!
//! # Why it is on in the default build
//!
//! Because the failure it diagnoses is undiagnosable otherwise, and the
//! failure is *reproducible* (2 for 2 on the re-flash path). The whole cost
//! is [`bootphase::full_ladder_us`] — well under a second, paid once per
//! boot. `FAPICO2_BOOT_LED=0` compiles every call site out for a deployment
//! that decides latency is worth more; the default is ON, and
//! `firmware/build.rs` is where that default is written down.

#[cfg(FAPICO2_BOOT_LED)]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(FAPICO2_BOOT_LED)]
use embassy_rp::gpio::Output;

#[cfg(FAPICO2_BOOT_LED)]
use fapico2_firmware::bootphase::{self, Ladder, Mark};

// ---------------------------------------------------------------------------
// The build parameter. Off is `FAPICO2_BOOT_LED=0`; an unrecognised value
// stops the build rather than picking a side (the same rule
// `FAPICO2_FOREIGN_IMAGE_WIPE` uses, for the same reason: the setting decides
// whether a device can be diagnosed in the field).
// ---------------------------------------------------------------------------

#[cfg(FAPICO2_BOOT_LED)]
mod on {
    use super::*;

    /// The boot-path ladder. A `static mut` under the same write-once
    /// discipline as `boot::LED_OUT`: single core, no preemption, and no
    /// task exists between [`ready`] and [`release`], so there is exactly one
    /// accessor at any time.
    static mut LADDER: Ladder = Ladder::new();

    /// Whether the `LED_OUT` slot has been filled. Before [`ready`] there is
    /// no pin to pulse, and a rung must not be *counted* without a pulse —
    /// the count is the instrument.
    static LED_READY: AtomicBool = AtomicBool::new(false);

    /// Called by `main` immediately after `boot::init_static_slot` fills the
    /// `LED_OUT` slot. The first rung is emitted after this returns.
    pub fn ready() {
        LED_READY.store(true, Ordering::Release);
    }

    /// Report that boot crossed boundary `rung`: emit that rung's pulse(s),
    /// then park the pin off.
    ///
    /// # Safety of the reordering
    ///
    /// A pulse is a GPIO write on pin 25 plus a read-only spin on TIMER0's
    /// raw counter. Neither peripheral is touched by anything else at these
    /// call sites, and the pulse *completes* before the statement it precedes
    /// begins — in particular [`mark`] for [`RUNG_OTP`] completes before the
    /// first `OTP_DATA` read of `boot::derive_boot_store_key`, so it cannot
    /// perturb the ECC decode it is there to localise.
    pub fn mark(rung: u8) {
        if !LED_READY.load(Ordering::Acquire) {
            return;
        }
        // SAFETY: `mark` is called from `main`'s boot path only, before any
        // task exists and before `release()` makes every later call a no-op;
        // single core, no preemption, no re-entry.
        let action = unsafe { (&mut *core::ptr::addr_of_mut!(LADDER)).mark(rung) };
        let Mark::Pulse { pulses, .. } = action else {
            return;
        };
        // SAFETY: `LED_READY` is published only after `init_static_slot`
        // wrote the slot exactly once, with `Release` ordering; this is the
        // same write-once `Output<'static>` the heartbeat task and the trussed
        // UI share. Nothing else is polling yet — see the module docs.
        let led: &mut Output<'static> = unsafe {
            (&mut *core::ptr::addr_of_mut!(crate::boot::LED_OUT)).assume_init_mut()
        };
        for _ in 0..pulses {
            led.set_low(); // ON (active-low)
            busy_wait_us(bootphase::PULSE_ON_US);
            led.set_high(); // OFF
            busy_wait_us(bootphase::PULSE_OFF_US);
        }
        // Park it dark: an LED left lit after a boot-phase marker would be
        // read as an open user-presence window.
        led.set_high();
    }

    /// Hand GPIO25 to the runtime drivers. Idempotent, and after it `mark` is
    /// inert for the rest of the run.
    ///
    /// `main` calls this on the last statement before it parks into the
    /// executor — the earliest point at which the heartbeat task, the trussed
    /// UI or the touch-prompt hook can run.
    pub fn release() {
        // SAFETY: as `mark` — pre-task boot path, single core, no re-entry.
        unsafe { (&mut *core::ptr::addr_of_mut!(LADDER)).release() };
        if LED_READY.load(Ordering::Acquire) {
            // SAFETY: as `mark`; the slot is initialised and this is the last
            // write before the pin belongs to the heartbeat task.
            let led: &mut Output<'static> = unsafe {
                (&mut *core::ptr::addr_of_mut!(crate::boot::LED_OUT)).assume_init_mut()
            };
            led.set_high(); // OFF — the ladder never ends holding the pin
        }
    }

    /// Synchronous µs busy-wait over the RP2350 TIMER's raw 32-bit
    /// microsecond counter (`TIMERAWL` — the same 1 MHz tick the embassy
    /// time-driver config; reading it has no side effects, unlike `TIMELR`).
    /// 32-bit µs wraps every ~71 min; the signed-difference form is
    /// wrap-correct for any wait far under that.
    ///
    /// Deliberately a copy rather than a call into `dbg::busy_wait_us`: the
    /// `dbg` module is feature-gated **out** of the default build, so
    /// sharing it would mean un-gating the 12 KiB diagnostic ring and the
    /// CTAP-HID drain surface with it — exactly the release-forbidden surface
    /// US-922 exists to keep out of a shipping image.
    ///
    /// A `Timer::after` would not work either: the early rungs run before the
    /// async executor has ever been polled, so nothing would ever wake.
    fn busy_wait_us(us: u32) {
        let target = rp_pac::TIMER0.timerawl().read().wrapping_add(us);
        while ((rp_pac::TIMER0.timerawl().read().wrapping_sub(target)) as i32) < 0 {}
    }
}

#[cfg(not(FAPICO2_BOOT_LED))]
mod off {
    /// `FAPICO2_BOOT_LED=0`: every call site compiles to nothing. See the
    /// module docs for when that trade is worth making.
    pub fn ready() {}
    /// See [`ready`].
    pub fn mark(_rung: u8) {}
    /// See [`ready`].
    pub fn release() {}
}

#[cfg(FAPICO2_BOOT_LED)]
pub use on::*;
#[cfg(not(FAPICO2_BOOT_LED))]
pub use off::*;