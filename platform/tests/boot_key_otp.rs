//! US-1081: **one-shot** secure-boot key-fingerprint provisioning and
//! anti-rollback. This is the red the story asks for.
//!
//! # The two assertions that carry the story
//!
//! * [`a_second_provisioning_write_is_refused`] — the path is reachable
//!   **exactly once per key slot**, and the refused attempt leaves the burnt
//!   row bit-for-bit unchanged. This is RS-Key's HIGH-1 counter-example
//!   refused: a second write that re-opens a locked surface.
//! * [`the_version_counter_cannot_be_lowered`] — the counter is a one-way
//!   function of the OTP bits, so "cannot decrease" is not a check this code
//!   performs but a property of the medium. The test proves the *software*
//!   also refuses, so a bug cannot talk the silicon out of it either.
//!
//! # What the recording fake proves, and what it does not
//!
//! [`RecordingOtp`] models three properties of a real one-time-programmable
//! array, and **only** those three:
//!
//! 1. **Bits only go 0 → 1.** `program_row` refuses any payload that would
//!    clear a bit that is already set (`OtpError::NotVirgin`).
//! 2. **A row is not rewriteable.** There is no `erase`, no `clear`, no
//!    `unprogram` in the [`Otp`] trait, so the fake — like the module — offers
//!    no way to take a burnt row back to virgin.
//! 3. **Every write is recorded**, so a test can assert not only that a call
//!    was refused but that the refusal wrote **nothing**.
//!
//! It does **not** model, and therefore does not prove, anything about:
//!
//! * **row-address-level silicon behaviour** — RP2350 OTP ECC, the rolling
//!   OTP CRC, the 32-bit write granularity, or whether a partially written
//!   row is readable. The [`Otp`] contract is deliberately *stricter* than the
//!   part (it refuses a non-virgin row, where the hardware would accept a
//!   partial program), which is exactly why the module's own pre-flight read
//!   — not the driver's refusal — is the load-bearing guard. That distinction
//!   is stated on `Otp` itself.
//! * **the row numbers in `Layout::rp2350()`**, which are unverified against
//!   the RP2350 datasheet. Nothing here writes silicon, and nothing in the
//!   tree calls `platform::boot_key`.
//! * **timing, glitching, or fault injection** on real OTP write hardware.
//!
//! In short: this file proves the *policy* is one-shot and monotonic. It does
//! not prove the policy survives contact with a real OTP block.

use fapico2_platform::boot_key::{
    Layout, LockState, LockWord, Otp, OtpError, ProvisionRefusal, Provisioner, SlotStatus,
    FINGERPRINT_BYTES, LockField, OTP_ROW_BYTES, PROVISION_BOOT_KEY, VERSION_STEPS,
};
use fapico2_platform::presence::{PresenceService, PresenceSource};

/// A press source the test drives by hand, so "no press" is a state and not an
/// accident of the build. The presence *service* under test is the real one —
/// `platform::presence::PresenceService` — not a stand-in.
struct HandPress {
    pressed: bool,
}

impl PresenceSource for HandPress {
    fn poll_press(&mut self) -> bool {
        let was = self.pressed;
        self.pressed = false;
        was
    }
}

/// A recording OTP: the three modelled properties, and nothing else.
struct RecordingOtp {
    rows: [[u8; OTP_ROW_BYTES]; 48],
    /// Every accepted `program_row`, in order. A refused attempt appends
    /// nothing — that is what makes "the refusal wrote nothing" checkable.
    programs: Vec<(usize, [u8; OTP_ROW_BYTES])>,
    /// Every attempted `program_row`, accepted or not.
    attempts: Vec<usize>,
    /// Every `read_row`.
    reads: Vec<usize>,
    /// US-1083: the raw `sw_lock[page]` word for each OTP page. All zero —
    /// both fields `READ_WRITE` — unless a test says otherwise.
    locks: Vec<LockWord>,
    /// Every `lock_state` call, in order, so a test can assert the
    /// precondition was consulted *and consulted before* the other steps.
    lock_reads: Vec<usize>,
}

impl RecordingOtp {
    fn virgin() -> Self {
        Self {
            rows: [[0u8; OTP_ROW_BYTES]; 48],
            programs: Vec::new(),
            attempts: Vec::new(),
            reads: Vec::new(),
            locks: vec![LockWord(0); 1],
            lock_reads: Vec::new(),
        }
    }

    /// US-1083: put a page into a non-nominal lock state. `word` is the raw
    /// register value, so a test states the hardware state it is modelling
    /// rather than an enum this crate invented.
    fn with_lock(mut self, page: usize, word: LockWord) -> Self {
        while self.locks.len() <= page {
            self.locks.push(LockWord(0));
        }
        self.locks[page] = word;
        self
    }

    /// Is every bit of `row` still clear?
    fn virgin_row(&self, row: usize) -> bool {
        self.rows[row].iter().all(|&b| b == 0)
    }

    fn row(&self, row: usize) -> [u8; OTP_ROW_BYTES] {
        self.rows[row]
    }

    fn writes_to(&self, row: usize) -> usize {
        self.programs.iter().filter(|(r, _)| *r == row).count()
    }

    fn attempts_to(&self, row: usize) -> usize {
        self.attempts.iter().filter(|r| **r == row).count()
    }
}

impl Otp for RecordingOtp {
    fn read_row(&mut self, row: usize) -> Result<[u8; OTP_ROW_BYTES], OtpError> {
        self.reads.push(row);
        if row >= self.rows.len() {
            return Err(OtpError::RowOutOfRange);
        }
        Ok(self.rows[row])
    }

    /// Property 1: bits only go 0 → 1. A payload that would clear a set bit is
    /// refused whole — nothing partial, no partial write.
    fn program_row(&mut self, row: usize, data: &[u8; OTP_ROW_BYTES]) -> Result<(), OtpError> {
        self.attempts.push(row);
        if row >= self.rows.len() {
            return Err(OtpError::RowOutOfRange);
        }
        let cur = self.rows[row];
        if cur.iter().zip(data.iter()).any(|(&old, &new)| old & !new != 0) {
            return Err(OtpError::NotVirgin);
        }
        self.rows[row] = *data;
        self.programs.push((row, *data));
        Ok(())
    }

    /// US-1083: the lock state of the page holding `row`.
    fn lock_state(&mut self, row: usize) -> LockState {
        let page = Layout::rp2350().page_of(row);
        self.lock_reads.push(page);
        let word = self.locks.get(page).copied().unwrap_or_default();
        if word.is_nominal() {
            LockState::Nominal
        } else {
            LockState::NonNominal { page, word }
        }
    }
}

/// A fingerprint that differs from every other one in this file.
fn fingerprint(byte: u8) -> [u8; FINGERPRINT_BYTES] {
    // A 32-byte SHA-256 in the low half, zero padding above — the RS-Key shape.
    // Only the low half matters here; what matters is that two calls with
    // different bytes are bytewise different.
    let mut fp = [0u8; FINGERPRINT_BYTES];
    fp[..32].fill(byte);
    fp
}

/// One full presence-gated attempt: open the slot, deliver the press (or not),
/// then call `f` with the armed service and the OTP.
fn attempt<R>(
    otp: &mut RecordingOtp,
    press_it: bool,
    f: impl FnOnce(&mut PresenceService, &mut Provisioner, &mut RecordingOtp) -> R,
) -> R {
    let mut svc = PresenceService::new();
    let mut press = HandPress { pressed: press_it };
    assert!(
        svc.begin_request(PROVISION_BOOT_KEY),
        "the pending slot must be free"
    );
    if press.poll_press() {
        svc.observe_press(1_000);
    }
    let mut p = Provisioner::new(Layout::rp2350());
    f(&mut svc, &mut p, otp)
}

fn provision(
    otp: &mut RecordingOtp,
    press_it: bool,
    slot: u8,
    fp: &[u8; FINGERPRINT_BYTES],
    version: u16,
) -> Result<(), ProvisionRefusal> {
    attempt(otp, press_it, |svc, p, otp| {
        p.provision_key(svc, otp, 1_200, slot, fp, version)
    })
}

// ---------------------------------------------------------------------------
// The story's red #1: a second provisioning write is refused.
// ---------------------------------------------------------------------------

#[test]
fn a_second_provisioning_write_is_refused() {
    let mut otp = RecordingOtp::virgin();

    assert_eq!(
        provision(&mut otp, true, 0, &fingerprint(0xA1), 1),
        Ok(()),
        "the first write is the one that is allowed"
    );

    let row = Layout::rp2350().key_row(0);
    let burnt = otp.row(row);
    assert!(!otp.virgin_row(row), "the key row must no longer be virgin");
    assert_eq!(otp.writes_to(row), 1, "the key row must have been written exactly once");

    // **The second write.** Same slot, a different fingerprint, a fresh
    // presence grant — an attacker with the button and a client.
    assert_eq!(
        provision(&mut otp, true, 0, &fingerprint(0xB2), 1),
        Err(ProvisionRefusal::AlreadyProvisioned),
        "a second write to a burnt key slot must be refused"
    );

    // ...and the refusal must have changed nothing.
    assert_eq!(
        otp.row(row),
        burnt,
        "the refused second write must leave the burnt row bit-for-bit unchanged"
    );
    assert_eq!(otp.writes_to(row), 1, "the refused write must not have been accepted");
    assert_eq!(
        otp.attempts_to(row),
        1,
        "the refusal is the caller's pre-flight read, not a rejected write: \
         programming a burnt row is never even attempted"
    );
}

/// A second *slot* is a rotation, not a re-opening of the first surface — but
/// it must not disturb slot 0, and slot 1 must close just as hard.
#[test]
fn a_second_slot_is_a_different_surface_not_a_reopen() {
    let mut otp = RecordingOtp::virgin();
    let l = Layout::rp2350();
    let mut p = Provisioner::new(l);

    provision(&mut otp, true, 0, &fingerprint(0xA1), 1).unwrap();
    provision(&mut otp, true, 1, &fingerprint(0xC3), 2).unwrap();

    assert_eq!(
        otp.row(l.key_row(0)),
        p.encoded_fingerprint_row(0, &fingerprint(0xA1)).unwrap(),
        "slot 0's fingerprint must be untouched by a slot-1 provision"
    );
    assert_eq!(
        otp.row(l.key_row(1)),
        p.encoded_fingerprint_row(1, &fingerprint(0xC3)).unwrap()
    );
    // The counter followed, because the counter is initialised with the trust
    // anchor rather than separately.
    assert_eq!(p.current_version(&mut otp), 2);

    assert_eq!(
        provision(&mut otp, true, 1, &fingerprint(0xD4), 3),
        Err(ProvisionRefusal::AlreadyProvisioned),
        "slot 1 is now equally closed"
    );
    assert_eq!(
        p.slot_status(&mut otp, 0).unwrap(),
        SlotStatus::Fingerprinted
    );
    assert_eq!(p.slot_status(&mut otp, 2).unwrap(), SlotStatus::Blank);
}

// ---------------------------------------------------------------------------
// The story's red #2: the version counter cannot be lowered.
// ---------------------------------------------------------------------------

#[test]
fn the_version_counter_cannot_be_lowered() {
    let mut otp = RecordingOtp::virgin();
    let mut p = Provisioner::new(Layout::rp2350());

    assert_eq!(p.current_version(&mut otp), 0, "a virgin device is version 0");
    p.set_version(&mut otp, 5).unwrap();
    assert_eq!(p.current_version(&mut otp), 5);
    let after_five = otp.row(Layout::rp2350().version_row);

    // Lower it.
    assert_eq!(
        p.set_version(&mut otp, 3),
        Err(ProvisionRefusal::VersionNotLowerable { current: 5, requested: 3 }),
        "the counter must refuse to go backwards"
    );
    // Repeat it — a re-assertion is not progress and must not be allowed to
    // rewrite the row.
    assert_eq!(
        p.set_version(&mut otp, 5),
        Err(ProvisionRefusal::VersionNotLowerable { current: 5, requested: 5 })
    );
    // Version 0 is not a version.
    assert_eq!(
        p.set_version(&mut otp, 0),
        Err(ProvisionRefusal::InvalidVersion { requested: 0 })
    );
    assert_eq!(
        otp.row(Layout::rp2350().version_row),
        after_five,
        "a refused counter write must leave the burnt bitmap unchanged"
    );
    assert_eq!(otp.writes_to(Layout::rp2350().version_row), 1);

    // Up is allowed, and only ever forward.
    p.set_version(&mut otp, 6).unwrap();
    p.set_version(&mut otp, 40).unwrap();
    assert_eq!(p.current_version(&mut otp), 40);
    // …and down is refused again from the new high-water mark.
    assert_eq!(
        p.set_version(&mut otp, 6),
        Err(ProvisionRefusal::VersionNotLowerable { current: 40, requested: 6 })
    );
}

/// The *medium* refuses too, not just the software. The encoding of version
/// `n` is a superset of the bits of every smaller version, so even a caller
/// that bypassed `set_version` and wrote the row directly cannot lower it.
#[test]
fn the_otp_itself_refuses_to_encode_a_lower_version() {
    let l = Layout::rp2350();
    // The encoding property, on two *separate* devices: the row a device
    // reaches at version 20 contains, bit for bit, everything a device that
    // only ever reached version 5 would hold. That is what makes "lower the
    // counter" unrepresentable on this medium rather than merely refused.
    let mut low = RecordingOtp::virgin();
    Provisioner::new(l).set_version(&mut low, 5).unwrap();
    let mut high = RecordingOtp::virgin();
    Provisioner::new(l).set_version(&mut high, 20).unwrap();
    let (low_row, high_row) = (low.row(l.version_row), high.row(l.version_row));
    for (i, (&a, &b)) in low_row.iter().zip(high_row.iter()).enumerate() {
        assert_eq!(
            a & !b,
            0,
            "byte {i}: the version-5 bitmap 0x{a:02x} is not contained in the \
             version-20 bitmap 0x{b:02x}"
        );
    }

    // And the practical consequence: a hand-crafted payload trying to rewind
    // the burnt bitmap to version 5 is refused by the driver itself.
    let mut otp = high;
    assert_eq!(
        otp.program_row(l.version_row, &low_row),
        Err(OtpError::NotVirgin),
        "clearing burnt counter bits must be refused by the medium"
    );
    assert_eq!(otp.row(l.version_row), high_row);
}

/// Exhaustion is final, and a policy rather than an error to be handled: after
/// the last step there is no further image this silicon will accept, and that
/// is decided once, at step 1, by whoever provisions.
#[test]
fn version_exhaustion_is_final_and_documented() {
    let mut otp = RecordingOtp::virgin();
    let l = Layout::rp2350();
    let mut p = Provisioner::new(l);

    assert_eq!(VERSION_STEPS, 48, "RS-Key's reference counter is 48 steps");
    assert_eq!(l.steps, 48);
    p.set_version(&mut otp, VERSION_STEPS).unwrap();
    assert_eq!(p.current_version(&mut otp), VERSION_STEPS);
    assert!(p.is_exhausted(&mut otp));

    assert_eq!(
        p.set_version(&mut otp, VERSION_STEPS + 1),
        Err(ProvisionRefusal::VersionExhausted),
        "there is no step 49; asking for one is exhaustion, not a forward move"
    );
    // Even after exhaustion the counter does not go down.
    assert_eq!(
        p.set_version(&mut otp, 1),
        Err(ProvisionRefusal::VersionNotLowerable { current: 48, requested: 1 })
    );
}

/// A fresh device re-derives the counter from the burnt bits, so the version
/// survives a reboot and a `.uf2` re-flash — which is the whole point.
#[test]
fn the_counter_is_derived_from_the_burnt_bits_not_from_ram() {
    let mut otp = RecordingOtp::virgin();
    Provisioner::new(Layout::rp2350())
        .set_version(&mut otp, 12)
        .unwrap();

    // A brand-new provisioner, as after a reboot — no RAM carried over.
    let mut fresh = Provisioner::new(Layout::rp2350());
    assert_eq!(fresh.current_version(&mut otp), 12);
    assert!(!fresh.is_exhausted(&mut otp));
    // And it refuses to rewind from that derived value.
    assert_eq!(
        fresh.set_version(&mut otp, 1),
        Err(ProvisionRefusal::VersionNotLowerable { current: 12, requested: 1 })
    );
}

// ---------------------------------------------------------------------------
// The presence gate. Reused, not re-implemented.
// ---------------------------------------------------------------------------

#[test]
fn provisioning_without_a_press_is_refused_and_touches_no_row() {
    let mut otp = RecordingOtp::virgin();
    let mut p = Provisioner::new(Layout::rp2350());

    assert_eq!(
        provision(&mut otp, false, 0, &fingerprint(0xA1), 1),
        Err(ProvisionRefusal::PresenceNotGranted)
    );
    assert!(
        otp.programs.is_empty() && otp.attempts.is_empty() && otp.reads.is_empty(),
        "a refused provisioning must not read or write a single OTP row: \
         reads {:?} writes {:?}", otp.reads, otp.programs
    );
    assert_eq!(p.current_version(&mut otp), 0);
}

/// A grant belongs to the command tag it was armed for. A press harvested by
/// some other command cannot open this one.
#[test]
fn a_press_armed_for_another_command_does_not_open_this_one() {
    let mut otp = RecordingOtp::virgin();
    let mut svc = PresenceService::new();
    let mut p = Provisioner::new(Layout::rp2350());
    const OTHER_COMMAND: u32 = 0x0042;

    let mut press = HandPress { pressed: true };
    assert!(svc.begin_request(OTHER_COMMAND));
    if press.poll_press() {
        svc.observe_press(1_000);
    }
    assert_eq!(
        p.provision_key(&mut svc, &mut otp, 1_200, 0, &fingerprint(0xA1), 1),
        Err(ProvisionRefusal::PresenceNotGranted),
        "a grant armed for another tag must not open the provisioning path"
    );
    assert!(otp.programs.is_empty());
}

/// A grant is single-use: one touch provisions once, and the *same* press
/// cannot be spent twice — so a client that loops cannot turn one physical
/// touch into an unbounded number of writes.
#[test]
fn one_press_provisions_at_most_once() {
    let mut otp = RecordingOtp::virgin();
    let l = Layout::rp2350();
    let mut p = Provisioner::new(l);

    attempt(&mut otp, true, |svc, p, otp| {
        assert_eq!(
            p.provision_key(svc, otp, 1_200, 0, &fingerprint(0xA1), 1),
            Ok(())
        );
        // Same grant, second call, no new press.
        assert_eq!(
            p.provision_key(svc, otp, 1_250, 1, &fingerprint(0xC3), 2),
            Err(ProvisionRefusal::PresenceNotGranted)
        );
    });
    assert!(otp.virgin_row(l.key_row(1)), "slot 1 must still be virgin");
    assert_eq!(p.current_version(&mut otp), 1, "the counter must not have moved either");
}

// ---------------------------------------------------------------------------
// The counter is initialised *with* the trust anchor, never separately.
// ---------------------------------------------------------------------------

#[test]
fn the_counter_is_initialised_in_the_same_write_as_the_fingerprint() {
    let mut otp = RecordingOtp::virgin();
    let l = Layout::rp2350();
    let mut p = Provisioner::new(l);

    provision(&mut otp, true, 0, &fingerprint(0xA1), 7).unwrap();
    assert_eq!(
        p.current_version(&mut otp),
        7,
        "the provisioning firmware's own version is where the counter starts"
    );

    // On a device whose counter is already advanced, provisioning a new slot
    // cannot rewind it to 1 — and the refusal happens before the key write.
    assert_eq!(
        provision(&mut otp, true, 1, &fingerprint(0xC3), 1),
        Err(ProvisionRefusal::VersionNotLowerable { current: 7, requested: 1 }),
        "a second slot must not reset the counter to the provisioning version"
    );
    assert!(
        otp.virgin_row(l.key_row(1)),
        "the refused attempt must not have burnt slot 1"
    );
    assert_eq!(p.current_version(&mut otp), 7);
}

// ---------------------------------------------------------------------------
// Layout, and the argument checks that keep a garbage value off the fuse.
// ---------------------------------------------------------------------------

#[test]
fn the_layout_keeps_the_fingerprint_and_counter_surfaces_disjoint() {
    let l = Layout::rp2350();
    let mut used: Vec<usize> = (0..l.key_slots).map(|s| l.key_row(s)).collect();
    let mut unique = used.clone();
    unique.push(l.version_row);
    let distinct: std::collections::HashSet<usize> = unique.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        unique.len(),
        "a key row and the version row must never be the same row: key rows \
         {used:?}, version row {}", l.version_row
    );
    used.push(l.version_row);
    for r in &used {
        assert!(*r < l.rows, "row {r} is outside the {}-row OTP window", l.rows);
    }
    // The whole 48-step counter is a bitmap, so it lives in one row and the
    // layout stays inside the window on any plausible part.
    assert!(
        l.step_bytes <= OTP_ROW_BYTES,
        "{} steps need {} bytes, which must fit one {OTP_ROW_BYTES}-byte row",
        VERSION_STEPS,
        l.step_bytes
    );
    assert_eq!(l.step_bytes, 6, "48 steps is 6 bytes");
}

#[test]
fn out_of_range_slots_and_empty_fingerprints_are_refused() {
    let mut otp = RecordingOtp::virgin();
    let l = Layout::rp2350();
    let mut p = Provisioner::new(l);

    assert_eq!(
        provision(&mut otp, true, l.key_slots, &fingerprint(1), 1),
        Err(ProvisionRefusal::NoSuchKeySlot { slot: l.key_slots })
    );
    assert_eq!(
        provision(&mut otp, true, 0, &[0u8; FINGERPRINT_BYTES], 1),
        Err(ProvisionRefusal::EmptyFingerprint)
    );
    // A version of 0, or past the last step, is refused before presence is
    // even asked for.
    assert_eq!(
        provision(&mut otp, true, 0, &fingerprint(1), 0),
        Err(ProvisionRefusal::InvalidVersion { requested: 0 })
    );
    assert_eq!(
        provision(&mut otp, true, 0, &fingerprint(1), VERSION_STEPS + 1),
        Err(ProvisionRefusal::VersionExhausted)
    );

    assert!(
        otp.programs.is_empty() && otp.attempts.is_empty(),
        "no refusal may burn a row: attempts {:?}", otp.attempts
    );
    assert_eq!(p.current_version(&mut otp), 0);
}

/// Property 2 of the fake, asserted as a property of the whole surface: there
/// is no API anywhere in this module or trait that can take a burnt row back
/// to virgin, and the fake enforces the same rule the trait documents.
#[test]
fn a_burnt_row_cannot_be_cleared_through_the_public_surface() {
    let mut otp = RecordingOtp::virgin();
    let l = Layout::rp2350();
    provision(&mut otp, true, 0, &fingerprint(0xA1), 1).unwrap();
    let before = otp.row(l.key_row(0));

    assert_eq!(
        otp.program_row(l.key_row(0), &[0u8; OTP_ROW_BYTES]),
        Err(OtpError::NotVirgin),
        "a zeroed payload must not clear a burnt row"
    );
    assert_eq!(
        otp.row(l.key_row(0)),
        before,
        "the refused clear must not have altered the row"
    );
    // The status reader is the only other way in, and it is read-only.
    assert_eq!(
        Provisioner::new(l).slot_status(&mut otp, 0).unwrap(),
        SlotStatus::Fingerprinted
    );
}

// ---------------------------------------------------------------------------
// US-1083 — the lock-state precondition.
//
// The one-shot pre-flight above reads the target row and requires it to be
// blank. That is necessary and it is **not** sufficient, because the RP2350
// has two distinct non-writable states and only one of them makes a read
// fail:
//
//   * `INACCESSIBLE` — reads fail, so the pre-flight's `read_row` errors
//     and nothing is written. Already handled, by accident of the driver.
//   * `READ_ONLY`     — reads SUCCEED. The row reads blank, the pre-flight
//     passes, the presence grant is consumed, and the failure lands at
//     `program_row`.
//
// The second is the whole of US-1083. It is not hypothetical on this part:
// the C reference in this repository locks a page by writing `0b1100` to
// `otp_hw->sw_lock[page]` (`pico-keys-sdk/src/otp/otp_rp2350.c:88-95`), and
// the rows this module names are all inside page 0.
// ---------------------------------------------------------------------------

/// The `SEC` field alone set to `READ_ONLY` — `0b01` in bits 1:0.
const LOCK_SEC_READ_ONLY: LockWord = LockWord(0b01);
/// The `NSEC` field alone set to `READ_ONLY` — `0b01` in bits 3:2.
const LOCK_NSEC_READ_ONLY: LockWord = LockWord(0b0100);
/// `INACCESSIBLE` on both fields, which is what the C reference's `0b1100`
/// write produces for the `NSEC` field plus a `SEC` field left alone.
const LOCK_BOTH_INACCESSIBLE: LockWord = LockWord(0b1111);
/// The unnamed `0b10` encoding. Non-nominal because an unnamed value is not
/// evidence of a writable page.
const LOCK_UNSPECIFIED: LockWord = LockWord(0b0010);

/// **The precondition.** With the target page locked, provisioning is
/// refused — and, critically, refused at the *lock check* rather than at the
/// driver, which is the only place a `READ_ONLY` page is visible at all.
#[test]
fn a_locked_page_refuses_the_burn_before_any_write_is_attempted() {
    for (label, word) in [
        ("SEC=READ_ONLY", LOCK_SEC_READ_ONLY),
        ("NSEC=READ_ONLY", LOCK_NSEC_READ_ONLY),
        ("both INACCESSIBLE", LOCK_BOTH_INACCESSIBLE),
        ("the unnamed 0b10 encoding", LOCK_UNSPECIFIED),
    ] {
        let mut otp = RecordingOtp::virgin().with_lock(0, word);
        let err = provision(&mut otp, true, 0, &fingerprint(0xA1), 1)
            .expect_err("a non-nominal lock state must refuse the burn");

        assert!(
            matches!(err, ProvisionRefusal::LockStateNotNominal { .. }),
            "{label}: the refusal must name the lock state, got {err:?} — an \
             operator seeing `Otp(..)` would go looking at the medium rather \
             than at the locks, and the medium is fine"
        );
        assert!(
            otp.attempts.is_empty(),
            "{label}: the lock check must run BEFORE the first write attempt, \
             or the grant is already spent. attempts: {:?}",
            otp.attempts
        );
    }
}

/// **The grant is not consumed.** This is the difference US-1083's placement
/// buys over a check placed after the presence arm, and it is a *second*
/// observation about the same refused call, not a re-run of the first.
///
/// `HandPress` is single-use by construction (`poll_press` clears the flag),
/// so a consumed grant shows up as a refusal on the *next* attempt, and a
/// preserved one as a success. A test that only asserted the first refusal
/// would pass with the check in the wrong place.
#[test]
fn a_lock_state_refusal_does_not_consume_the_presence_grant() {
    let l = Layout::rp2350();

    // A locked device: refused, grant preserved, nothing written.
    let mut otp = RecordingOtp::virgin().with_lock(0, LOCK_SEC_READ_ONLY);
    assert!(matches!(
        provision(&mut otp, true, 0, &fingerprint(0xA1), 1),
        Err(ProvisionRefusal::LockStateNotNominal { .. })
    ));
    assert!(
        !otp.lock_reads.is_empty(),
        "the precondition must have been consulted"
    );
    assert!(otp.virgin_row(l.key_row(0)), "the key row must be untouched");
    assert!(otp.virgin_row(l.version_row), "the version row must be untouched");

    // The same press, on an unlocked device, still works. If the first
    // refusal had consumed the grant this would fail with
    // `PresenceNotGranted` — which is a *different* error, and the test says
    // so, so a future reader cannot mistake one for the other.
    let mut otp = RecordingOtp::virgin();
    match provision(&mut otp, true, 0, &fingerprint(0xA1), 1) {
        Ok(()) => {}
        Err(ProvisionRefusal::LockStateNotNominal { .. }) => {
            panic!("an unlocked page must not be refused as locked")
        }
        Err(other) => panic!(
            "the grant was consumed by the earlier refusal, so this attempt \
             was answered on different terms (got {other:?}). US-1083 places \
             the lock check before the presence arm precisely so that an \
             operator's press survives a refusal."
        ),
    }
    assert!(!otp.virgin_row(l.key_row(0)), "the second attempt should have burnt");
}

/// The precondition reads the lock state of **every page the call will
/// write**, not just the key row's. The counter-first ordering exists to
/// make a mid-write failure leave the safe direction; that argument only
/// holds if both pages were writable.
#[test]
fn both_written_pages_are_checked_not_just_the_key_row() {
    let l = Layout::rp2350();
    // With `Layout::rp2350()`'s 48 rows everything is in page 0, so the
    // de-duplication in `check_lock_state` means one read. That is asserted
    // rather than assumed, because the de-duplication is what would silently
    // stop covering a second page if the row numbers were reconciled.
    let mut otp = RecordingOtp::virgin();
    provision(&mut otp, true, 0, &fingerprint(0xA1), 1).unwrap();
    assert_eq!(
        otp.lock_reads,
        vec![0],
        "both rows are in page 0, so the precondition must read page 0 once \
         — not once per row, and not only the key row's page"
    );

    // The rows are all in page 0 *because* the layout says 48 rows. Assert
    // the fact the de-duplication depends on, so a future reconciliation of
    // the row numbers past row 63 has to re-derive it.
    assert_eq!(l.rows_per_page(), 64);
    assert_eq!(l.page_of(l.key_row(0)), 0);
    assert_eq!(l.page_of(l.key_row(3)), 0);
    assert_eq!(l.page_of(l.version_row), 0);
}

/// A page beyond the first is checked too, which is the behaviour the
/// de-duplication exists to preserve and which `Layout::rp2350()` alone
/// cannot reach. A synthetic layout is the only way to get there, and it is
/// worth having: it is the case that a reconciled row map would land in.
#[test]
fn a_row_in_a_later_page_is_checked_independently() {
    let layout = Layout { first_key_row: 200, version_row: 140, ..Layout::rp2350() };
    let mut otp = RecordingOtp::virgin();

    let mut svc = PresenceService::new();
    let mut press = HandPress { pressed: true };
    svc.begin_request(PROVISION_BOOT_KEY);
    if press.poll_press() {
        svc.observe_press(1_000);
    }
    let mut p = Provisioner::new(layout);

    // Both pages nominal: the call proceeds far enough to be refused on the
    // *version* check, which is a different, later refusal — proving the
    // lock check passed for two distinct pages.
    let err = p
        .provision_key(&mut svc, &mut otp, 1_000, 0, &fingerprint(0xA1), 1)
        .expect_err("a virgin counter row refuses version 1 only if... ");
    assert!(
        !matches!(err, ProvisionRefusal::LockStateNotNominal { .. }),
        "two distinct pages were both nominal, so the lock check must not \
         have refused: {err:?}"
    );
    assert_eq!(
        otp.lock_reads,
        vec![layout.page_of(200), layout.page_of(140)],
        "each written page is read exactly once, in call order, and a page \
         boundary is not collapsed"
    );
}

/// The precondition's own vocabulary, pinned against the datasheet
/// transcription it is built from. If `LockWord`'s bit positions are ever
/// wrong, every test above still passes — they all drive the same wrong
/// decoder. These are the only tests in the file that would not.
#[test]
fn the_lock_word_decoder_matches_the_datasheet_field_positions() {
    // `SEC` is bits 1:0, `NSEC` is bits 3:2
    // (pico-sdk .../hardware/regs/otp.h, OTP_SW_LOCK0_SEC_LSB=0, _NSEC_LSB=2).
    assert_eq!(LOCK_SEC_READ_ONLY.sec(), LockField::ReadOnly);
    assert_eq!(LOCK_SEC_READ_ONLY.nsec(), LockField::ReadWrite);

    assert_eq!(LOCK_NSEC_READ_ONLY.nsec(), LockField::ReadOnly);
    assert_eq!(LOCK_NSEC_READ_ONLY.sec(), LockField::ReadWrite);

    // Value encodings: 0b00 READ_WRITE, 0b01 READ_ONLY, 0b11 INACCESSIBLE,
    // 0b10 unnamed.
    assert_eq!(LockWord(0b0000).sec(), LockField::ReadWrite);
    assert_eq!(LockWord(0b0011).sec(), LockField::Inaccessible);
    assert_eq!(LockField::from_bits_for_test(0b10), LockField::Unspecified);

    // Nominal is the WHOLE word reading zero, so bits above 3:2 are
    // ignored by the decoder but must not make the word non-nominal — they
    // are not lock bits.
    assert!(LockWord(0xFFFF_FFF0).is_nominal());
    assert!(!LockWord(0b0001).is_nominal());
    assert!(!LockWord(0b0100).is_nominal());
    assert!(!LockWord(0b0010).is_nominal());
}

/// The C reference locks a page by writing `0b1100` to `sw_lock[page]`
/// (`otp_rp2350.c:94`). Whatever that word means, this precondition must
/// treat it as non-nominal — otherwise the two implementations disagree and
/// a page the C firmware considers locked is one this one will happily burn.
#[test]
fn the_c_references_lock_write_is_non_nominal_here() {
    assert!(
        !LockWord(0b1100).is_nominal(),
        "the C reference's page-lock constant must be non-nominal under this \
         decoder, or the two implementations disagree about what 'locked' \
         means"
    );
    assert_eq!(LockWord(0b1100).nsec(), LockField::Inaccessible);
}
