//! **One-shot secure-boot key-fingerprint provisioning** (US-1081).
//!
//! # What this is, and what it is not
//!
//! The *enforcement* of signed boot is US-1082 and is not here: nothing in
//! this module verifies an image, and `SECURE` (Rescue `INS 0x1D`, US-163)
//! still refuses with `6A86`. What is here is the **provisioning** of the two
//! pieces of silicon state that enforcement will later read:
//!
//! * a **boot-key fingerprint** in one of the RP2350 bootrom's OTP key-hash
//!   rows, written through a one-shot, presence-gated, irreversible path; and
//! * an **anti-rollback version counter**, initialised in the *same* write.
//!
//! The signing key is **not** here and must never be: a private key in this
//! repository is the failure mode the whole story exists to prevent. The only
//! thing this module accepts is a **fingerprint** — a hash, supplied by the
//! operator at the call site from wherever the key is held.
//!
//! # The property the story is really about
//!
//! *"The path must be reachable exactly once."* RS-Key's HIGH-1 is the
//! counter-example: an unauthenticated write that re-opens a locked surface.
//! **Four** independent things have to hold, and each is checked separately
//! in `platform/tests/boot_key_otp.rs`:
//!
//! 1. **Presence.** No write without a [`PresenceGrant`] bound to
//!    [`PROVISION_BOOT_KEY`], taken from the real
//!    [`PresenceService`](crate::presence::PresenceService) — the physical
//!    BOOTSEL button path, not a parallel one. A grant is single-use and
//!    tag-bound, so one touch cannot be harvested into many writes and a
//!    press taken by another command cannot open this one.
//! 2. **A pre-flight blank read.** Before anything is written, the target key
//!    row is read and must be **virgin**. A burnt row is
//!    [`AlreadyProvisioned`](ProvisionRefusal::AlreadyProvisioned) and the
//!    refusal happens **before any write is attempted**, so there is no partial
//!    second write to reason about. This — not the driver's own refusal — is
//!    the load-bearing guard, because [`Otp::program_row`] is deliberately
//!    *stricter* than the silicon (see the trait).
//! 3. **A nominal lock state** (US-1083). Checked *before* the presence grant
//!    is consumed, so a device that is already locked costs the operator
//!    nothing and burns nothing. See [the section below](#us-1083-the-lock-state-precondition).
//! 4. **A medium that cannot be rewound.** The counter is a bitmap of burnt
//!    OTP bits, so "cannot decrease" is a property of the fuse array, not a
//!    check this code performs. The software check is the belt; the fuses are
//!    the braces.
//!
//! # US-1083: the lock-state precondition
//!
//! *"Refusing to burn while the lock state is non-nominal is the difference
//! between a recoverable mistake and a permanently mis-provisioned token."*
//!
//! ## Why the blank-row pre-flight does not already cover it
//!
//! Point 2 above reads the target row and requires it to be blank. That is
//! necessary and it is **not sufficient**, because the two failure modes
//! have different shapes on real silicon:
//!
//! * A page locked **`INACCESSIBLE`** makes the *read* fail. `read_row`
//!   returns an error, `provision_key` maps it to
//!   [`ProvisionRefusal::Otp`], and nothing is written. Already handled —
//!   but only because the driver happened to fail, and it is reported as a
//!   read failure rather than as a lock state, so the operator is told to go
//!   look at the medium rather than at the locks.
//! * A page locked **`READ_ONLY`** lets the *read* succeed. The row reads
//!   blank, the pre-flight passes, and the failure surfaces at
//!   `program_row` — **after** the presence grant has been consumed. On a
//!   real driver that is the interesting case, and it is exactly the shape
//!   the pre-flight cannot see.
//!
//! The second is the one US-1083 is about, and it is not hypothetical on
//! this part: the C reference in this repository
//! (`pico-keys-sdk/src/otp/otp_rp2350.c:88-95`) locks a page by writing
//! `0b1100` to `otp_hw->sw_lock[page]`, and calls `otp_lock_page` for the
//! OTP-MKEK rows. The rows this module names (`0x08`..`0x0C`) are all inside
//! **page 0** — 64 rows per page — so they are inside the page the C
//! firmware locks. A device provisioned by the C stack and then provisioned
//! again by this one lands in precisely the `READ_ONLY` shape.
//!
//! ## What is read, and from where
//!
//! One register: `otp_hw->sw_lock[page]`, `RP2350` §16.7.3 `OTP_SW_LOCK0`
//! ("Software lock register for page 0"; the array index applies
//! identically). Each word carries two 2-bit fields with the same encoding:
//!
//! | field | bits | `0b00` | `0b01` | `0b11` |
//! |---|---|---|---|---|
//! | `SEC`  | 1:0 | `READ_WRITE` | `READ_ONLY` | `INACCESSIBLE` |
//! | `NSEC` | 3:2 | `READ_WRITE` | `READ_ONLY` | `INACCESSIBLE` |
//!
//! Nominal is **the whole word reading `0x0000_0000`**, both fields
//! `READ_WRITE`. The encoding and the field positions are transcribed from
//! `pico-sdk/src/rp2350/hardware_regs/include/hardware/regs/otp.h`
//! (`OTP_SW_LOCK0_SEC_*` / `OTP_SW_LOCK0_NSEC_*`) and are the same constants
//! the C reference's `0b1100` write is written against, so the two agree by
//! construction rather than by recollection.
//!
//! **`0b10` is not listed because the header does not assign it a name.** It
//! is treated as non-nominal, which is the only safe default for a fuse
//! state: an unnamed value is not evidence of a writable page.
//!
//! Note the register is `io_rw_32`, not `io_ro_32`. This module **reads** it
//! and never writes it; the trait it is read through
//! ([`Otp::lock_state`]) has no write method at all, so there is no path
//! from this code to setting a lock.
//!
//! ## Which pages
//!
//! [`Layout::page_of`] — `row / 64`, matching
//! `NUM_ROWS_PER_PAGE = 64` in `embassy-rp`'s `otp` module and the C
//! reference's `row >> 6`. With [`Layout::rp2350`]'s `rows: 48`, **every row
//! this module can name is in page 0**, so the precondition and the
//! one-shot pre-flight check the same page. That is a fact about the
//! unverified row numbers, not about the policy, and it is recorded here
//! because if the rows are later reconciled and move past row 63 the
//! precondition silently starts covering a *second* page — which is the
//! behaviour it was written for, and which no current test exercises.
//!
//! # Anti-rollback, and the exhaustion policy
//!
//! [`VERSION_STEPS`] is **48**, RS-Key's reference figure, across
//! [`Layout::key_slots`] = 4 key slots. Step *n* is one bit; writing version
//! *n* burns the low *n* bits, so the encoded value is monotone in *n* and no
//! later write can encode a smaller one. [`Provisioner::current_version`]
//! reads the highest burnt bit, so a device re-derives its version from the
//! medium after any reboot or re-flash.
//!
//! **Exhaustion policy.** Burning step 48 means the 49th firmware can never be
//! signed in, on this silicon, forever — the counter has no step 49 to burn.
//! That is a deliberate choice made once, by whoever provisions, not an error
//! to be recovered from: [`ProvisionRefusal::VersionExhausted`] is a terminal
//! state, and the device remains otherwise usable (it still runs what it has).
//! The alternative — a wider counter — trades a permanent, self-inflicted
//! bricking risk for headroom nobody has asked for. 48 is what the reference
//! design uses and is deliberately not raised here.
//!
//! # The layout, and what is *unverified* about it
//!
//! [`Layout::rp2350`] names the OTP row numbers. **They have not been checked
//! against the RP2350 datasheet in this story**, and the byte encoding of a
//! fingerprint into a row ([`Provisioner::encoded_fingerprint_row`]) is this
//! tree's own convention, not the bootrom's key-hash entry format. Nothing in
//! the tree calls this module, no build path writes an OTP, and the host tests
//! run entirely against a fake. **The row numbers and the row encoding must be
//! reconciled with the datasheet before any device is provisioned.** That is
//! stated here, on [`Layout`], and in the US-1081 report, because a wrong row
//! number is an irreversible burn on a part that cannot be recovered.
//!
//! What *is* verified is the shape: the key rows and the version row are
//! disjoint, every row is inside the OTP window, and the whole step bitmap
//! fits in one row.

#![allow(clippy::needless_range_loop)]

use crate::presence::PresenceService;

/// The command tag a presence grant must be bound to before this module will
/// touch an OTP row. Chosen out of the app command-tag range so it cannot
/// collide with an FIDO/CCID tag.
pub const PROVISION_BOOT_KEY: u32 = 0x0108;

/// Bytes per OTP row on the RP2350.
pub const OTP_ROW_BYTES: usize = 64;

/// Rows per OTP **page** on the RP2350 — the unit the lock register is keyed
/// by. See [`Layout::rows_per_page`].
pub const OTP_ROWS_PER_PAGE: usize = 64;

/// The raw `otp_hw->sw_lock[page]` word.
///
/// Nominal is the whole word being zero: both 2-bit lock fields reading
/// `READ_WRITE`. The field positions and the value encodings are
/// transcribed from `pico-sdk/src/rp2350/hardware_regs/include/hardware/regs/otp.h`
/// (`OTP_SW_LOCK0_SEC_*`, `OTP_SW_LOCK0_NSEC_*`), which is the same header
/// the C reference's `0b1100` lock write is written against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct LockWord(pub u32);

impl LockWord {
    /// The `SEC` field, bits 1:0.
    pub const fn sec(self) -> LockField {
        LockField::from_bits(self.0 & 0b11)
    }

    /// The `NSEC` field, bits 3:2.
    pub const fn nsec(self) -> LockField {
        LockField::from_bits((self.0 >> 2) & 0b11)
    }

    /// Whether both fields are `READ_WRITE` — the only state in which a
    /// program to this page can be attempted at all.
    pub const fn is_nominal(self) -> bool {
        matches!(self.sec(), LockField::ReadWrite) && matches!(self.nsec(), LockField::ReadWrite)
    }
}

/// The 2-bit lock encoding shared by the `SEC` and `NSEC` fields.
///
/// `0b10` is [`Unspecified`], not a fourth state: the RP2350 header assigns
/// `READ_WRITE`, `READ_ONLY` and `INACCESSIBLE` to `0b00`, `0b01` and
/// `0b11` and does not name `0b10`. It is non-nominal because an unnamed
/// value is not evidence of a writable page, and the cost of being wrong in
/// that direction is a refusal an operator can investigate, against a
/// partially-burnt fuse row that nobody can.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockField {
    /// `0b00` — the nominal state.
    ReadWrite,
    /// `0b01` — reads succeed, programs are refused. **The dangerous one**:
    /// a read-based pre-flight cannot see it.
    ReadOnly,
    /// `0b11` — neither reads nor programs succeed.
    Inaccessible,
    /// `0b10` — not named by the datasheet; treated as non-nominal.
    Unspecified,
}

impl LockField {
    /// Decode a raw 2-bit lock field. Public so the datasheet transcription
    /// can be pinned against the datasheet itself, rather than only through
    /// `LockWord` — a wrong bit position in `LockWord` would otherwise make
    /// every behavioural test in the tree agree with itself and be wrong.
    pub const fn from_bits_for_test(bits: u32) -> Self {
        Self::from_bits(bits)
    }

    const fn from_bits(bits: u32) -> Self {
        match bits {
            0b00 => Self::ReadWrite,
            0b01 => Self::ReadOnly,
            0b11 => Self::Inaccessible,
            _ => Self::Unspecified,
        }
    }
}

/// The lock state of one OTP page, as a provisioner reads it (US-1083).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockState {
    /// Both fields `READ_WRITE`. The only state in which a burn is attempted.
    Nominal,
    /// A field is set to something other than `READ_WRITE`. The burn is
    /// refused; nothing is written.
    NonNominal {
        /// The page whose lock is not nominal.
        page: usize,
        /// The raw register word, so the refusal names what was actually
        /// read rather than a paraphrase of it.
        word: LockWord,
    },
    /// The lock register could not be read.
    ///
    /// **Not** treated as nominal, and the distinction is the point. "I
    /// could not ask" is not "I asked and the answer was fine"; on a
    /// one-time-programmable medium the only safe reading of an unknown is
    /// the refusing one.
    Unreadable {
        /// The page whose lock state could not be read.
        page: usize,
    },
}

/// Width of a boot-key fingerprint: a 32-byte SHA-256 digest, padded to 48 —
/// the RS-Key shape.
pub const FINGERPRINT_BYTES: usize = 48;

/// **48 signable versions**, the RS-Key reference figure. See the module
/// docs for the exhaustion policy; this is deliberately not raised.
pub const VERSION_STEPS: u16 = 48;

/// Which OTP rows hold what.
///
/// A plain record rather than free constants so the *invariants* — the key
/// rows and the version row are disjoint, everything is inside the window —
/// are checkable, which is what
/// `the_layout_keeps_the_fingerprint_and_counter_surfaces_disjoint` does.
/// `const`-constructible, so a hypothetical part with a different map is a
/// `const`, not a runtime value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Rows in the OTP array.
    pub rows: usize,
    /// Bytes per row.
    pub row_bytes: usize,
    /// How many boot-key slots the bootrom offers.
    pub key_slots: u8,
    /// Row holding slot 0's fingerprint; slot *n* is `first_key_row + n`.
    pub first_key_row: usize,
    /// Row holding the anti-rollback step bitmap.
    pub version_row: usize,
    /// How many signable versions this layout has.
    pub steps: u16,
    /// Bytes the step bitmap occupies.
    pub step_bytes: usize,
}

impl Layout {
    /// Rows per OTP page on the RP2350.
    ///
    /// 64, from `NUM_ROWS_PER_PAGE` in `embassy-rp`'s `otp` module and from
    /// the C reference's `row >> 6` (`pico-keys-sdk/src/otp/otp_rp2350.c:147`).
    /// Both the data and the lock register are indexed by page, so this is
    /// the conversion between them and it is the only one in the module.
    pub const fn rows_per_page(&self) -> usize {
        OTP_ROWS_PER_PAGE
    }

    /// The OTP page holding `row` — the unit [`Otp::lock_state`] is keyed by.
    pub const fn page_of(&self, row: usize) -> usize {
        row / self.rows_per_page()
    }

    /// The RP2350 map. **The two row numbers below are unverified against the
    /// datasheet** — see the module docs. They are the only two numbers in
    /// this module that would burn a fuse if they were wrong, which is why
    /// they are named here rather than sprinkled through the code.
    pub const fn rp2350() -> Self {
        Self {
            rows: 48,
            row_bytes: OTP_ROW_BYTES,
            key_slots: 4,
            first_key_row: 0x08,
            version_row: 0x0C,
            steps: VERSION_STEPS,
            step_bytes: 6, // 48 bits
        }
    }

    /// The row holding `slot`'s fingerprint.
    pub const fn key_row(&self, slot: u8) -> usize {
        self.first_key_row + slot as usize
    }

    /// Bit index of version `v` (1-based) within the step bitmap.
    const fn step_bit(v: u16) -> usize {
        (v - 1) as usize
    }

    /// Mask of the bit that records "version `v` has been signed in".
    const fn step_mask(v: u16) -> u8 {
        1u8 << (Self::step_bit(v) % 8)
    }

    /// Byte of the step bitmap holding version `v`'s bit.
    const fn step_byte(v: u16) -> usize {
        Self::step_bit(v) / 8
    }
}

impl Default for Layout {
    fn default() -> Self {
        Self::rp2350()
    }
}

/// Why an OTP row could not be read or written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpError {
    /// The row index is outside the OTP window. A driver bug, not a policy.
    RowOutOfRange,
    /// The payload would clear a bit that is already set.
    ///
    /// On a one-time-programmable array this is not a recoverable condition —
    /// it means the row has been burnt and cannot be burnt differently.
    NotVirgin,
    /// The write failed for a reason the caller cannot see (a real OTP block
    /// reports an ECC/CRC failure here).
    WriteFailed,
}

/// Why a provisioning attempt was refused.
///
/// Every arm is a refusal that **wrote nothing**. That is the contract: a
/// caller that gets an `Err` back can rely on the device being in exactly the
/// state it was in before the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionRefusal {
    /// No live presence grant bound to [`PROVISION_BOOT_KEY`]. No row was
    /// read or written.
    PresenceNotGranted,
    /// The slot index is outside `0..key_slots`.
    NoSuchKeySlot {
        /// The index that was asked for.
        slot: u8,
    },
    /// The fingerprint was all zero — an unwritten buffer, not a digest.
    EmptyFingerprint,
    /// **The one-shot refusal.** This slot already carries a fingerprint.
    AlreadyProvisioned,
    /// The requested version is zero, which is the state that means "no
    /// signed image has ever been accepted".
    InvalidVersion {
        /// The version that was asked for.
        requested: u16,
    },
    /// The counter cannot go backwards, and cannot repeat.
    VersionNotLowerable {
        /// The version burnt into the OTP.
        current: u16,
        /// The version that was asked for.
        requested: u16,
    },
    /// The counter is out of steps. Terminal — see the module docs.
    VersionExhausted,
    /// **The lock state is not nominal, so the burn is refused** (US-1083).
    ///
    /// Every arm is a refusal that wrote nothing, and this one is checked
    /// *before* the presence grant is consumed, so a device that is already
    /// locked costs the operator nothing at all — not a button press, not a
    /// grant, not a partially-applied write.
    LockStateNotNominal {
        /// Why the lock is not nominal, and which page it is.
        state: LockState,
    },
    /// The OTP itself failed.
    Otp(OtpError),
}

/// One-time-programmable row access — the seam this story is testable through.
///
/// # The contract, and where it is stricter than the silicon
///
/// `program_row` is specified as **all-or-nothing on a virgin row**, and
/// refuses a non-virgin one with [`OtpError::NotVirgin`]. Real OTP silicon
/// permits a partially-programmed row (it is written 32 bits at a time with an
/// ECC per row), so this contract is **stricter than the part**. That is
/// deliberate, and it is why it is *not* where the one-shot guarantee rests:
/// a real driver would have to be built on this contract deliberately, and
/// the guarantee that holds regardless of how the driver is written is
/// [`Provisioner`]'s own pre-flight read.
///
/// The trait also has **no** `erase`, `clear` or `unprogram` method. There is
/// no way to ask a fuse array to forget.
pub trait Otp {
    /// Read a whole row. Blank is all zero.
    fn read_row(&mut self, row: usize) -> Result<[u8; OTP_ROW_BYTES], OtpError>;

    /// Program a whole row, virgin only. See the trait docs.
    fn program_row(&mut self, row: usize, data: &[u8; OTP_ROW_BYTES]) -> Result<(), OtpError>;

    /// The lock state of the OTP **page** containing `row` (US-1083).
    ///
    /// # Why it is here and not a free function over a register block
    ///
    /// Two reasons, and the second is the load-bearing one.
    ///
    /// First, symmetry: the precondition is only meaningful against the same
    /// medium the write goes to, and a trait method cannot be satisfied by a
    /// different object than the one being written.
    ///
    /// Second — and this is why it is `&mut self` and returns a [`LockState`]
    /// rather than a `bool` — a trait method can be **wrong in a way a
    /// register read cannot**. A device implementation that returned
    /// `Nominal` unconditionally would compile, would satisfy the signature,
    /// and would make the gate in `check_otp_provisioning_precondition.py`
    /// green while the precondition did nothing. Returning a three-valued
    /// state with `Unreadable` in it, and having the gate require that every
    /// implementation in the tree is more than a pass-through, is what stops
    /// that.
    ///
    /// # There is deliberately no `set_lock`
    ///
    /// The underlying register (`otp_hw->sw_lock[page]`) is writable, and the
    /// C reference writes it (`pico-keys-sdk/src/otp/otp_rp2350.c:94`). This
    /// trait has no method that can, so there is no path from this code to
    /// locking a page — and therefore no path by which the precondition
    /// could be satisfied by first making the device non-nominal.
    fn lock_state(&mut self, row: usize) -> LockState;
}

/// Whether a key slot has been provisioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotStatus {
    /// Every bit clear: this slot has never been written.
    Blank,
    /// The slot carries a fingerprint and can never be written again.
    Fingerprinted,
}

impl SlotStatus {
    fn of(row: &[u8; OTP_ROW_BYTES]) -> Self {
        if row.iter().all(|&b| b == 0) {
            Self::Blank
        } else {
            Self::Fingerprinted
        }
    }
}

/// The one-shot provisioner.
///
/// Borrows nothing and holds no state across calls: **every** decision is read
/// back out of the OTP, so a device that reboots, or a second [`Provisioner`]
/// in the same process, sees the same answers. There is no in-RAM "already
/// done" flag, because such a flag would be exactly the re-openable surface
/// this story refuses.
#[derive(Debug, Clone, Copy)]
pub struct Provisioner {
    layout: Layout,
}

impl Provisioner {
    /// A provisioner over `layout`. `Layout::rp2350()` is the only layout
    /// that exists.
    pub const fn new(layout: Layout) -> Self {
        Self { layout }
    }

    /// The layout in use.
    pub const fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Encode `fingerprint` into the row body for `slot`.
    ///
    /// **This encoding is this tree's convention, not the RP2350 bootrom's
    /// key-hash entry format**, which has not been reproduced here. It exists
    /// so the payload is inspectable and so a host-side pre-flight tool can
    /// compute exactly what the device would burn; it must be reconciled with
    /// the datasheet before any device is provisioned.
    pub fn encoded_fingerprint_row(
        &self,
        slot: u8,
        fingerprint: &[u8; FINGERPRINT_BYTES],
    ) -> Result<[u8; OTP_ROW_BYTES], ProvisionRefusal> {
        self.check_slot(slot)?;
        if fingerprint.iter().all(|&b| b == 0) {
            return Err(ProvisionRefusal::EmptyFingerprint);
        }
        let mut row = [0u8; OTP_ROW_BYTES];
        row[..FINGERPRINT_BYTES].copy_from_slice(fingerprint);
        // The slot index, so a row is self-describing: a burned row that
        // somehow landed in another slot's position is visible on read-back
        // rather than being silently accepted as a different key.
        row[FINGERPRINT_BYTES] = slot;
        Ok(row)
    }

    fn check_slot(&self, slot: u8) -> Result<(), ProvisionRefusal> {
        if slot >= self.layout.key_slots {
            Err(ProvisionRefusal::NoSuchKeySlot { slot })
        } else {
            Ok(())
        }
    }

    /// **The US-1083 precondition.** The lock state of every OTP page this
    /// call is about to write, checked *before* anything is written and
    /// *before* the presence grant is consumed.
    ///
    /// # Why the key row and the version row are both checked
    ///
    /// `provision_key` writes two rows, in two pages in general, and the two
    /// writes are not atomic. Checking only the key row would leave the
    /// counter-first ordering exposed in exactly the case that ordering
    /// exists for: if the key row's page is writable and the version row's
    /// is not, the counter write is attempted, fails, and the caller sees an
    /// OTP error with the key row still virgin — recoverable, but only by
    /// accident of which page happened to be locked.
    ///
    /// Duplicates collapse, so the common case (both rows in page 0) is one
    /// read, not two.
    pub fn check_lock_state(
        &self,
        otp: &mut impl Otp,
        rows: &[usize],
    ) -> Result<(), ProvisionRefusal> {
        let mut checked: usize = 0;
        for row in rows {
            let page = self.layout.page_of(*row);
            if checked & (1usize << page) != 0 {
                continue;
            }
            checked |= 1usize << page;
            match otp.lock_state(*row) {
                LockState::Nominal => {}
                other => {
                    return Err(ProvisionRefusal::LockStateNotNominal { state: other });
                }
            }
        }
        Ok(())
    }

    /// The version a step-bitmap row encodes: the highest set step bit, or 0
    /// on a virgin row.
    fn version_of(&self, row: &[u8; OTP_ROW_BYTES]) -> u16 {
        for v in (1..=self.layout.steps).rev() {
            if row[Layout::step_byte(v)] & Layout::step_mask(v) != 0 {
                return v;
            }
        }
        0
    }

    /// Set every step bit from `current + 1` through `to`, in place.
    fn burn_steps(&self, row: &mut [u8; OTP_ROW_BYTES], current: u16, to: u16) {
        for v in current + 1..=to {
            let (b, m) = (Layout::step_byte(v), Layout::step_mask(v));
            row[b] |= m;
        }
    }

    /// The version burnt into the OTP: the highest set step bit, or 0 on a
    /// virgin device.
    ///
    /// Read from the medium every time, never cached — a RAM cache would be
    /// the one thing a re-flash could roll back, and this is the value that
    /// must not be.
    pub fn current_version(&mut self, otp: &mut impl Otp) -> u16 {
        match otp.read_row(self.layout.version_row) {
            Ok(row) => self.version_of(&row),
            // A read fault reads as 0, which makes every caller re-verify
            // rather than trust a value it could not fetch. The alternative —
            // propagating — would mean `is_exhausted` could panic, and a
            // provisioning refusal has to be a value, not a fault.
            Err(_) => 0,
        }
    }

    /// Whether every step is burnt — the terminal state, after which no
    /// further image can ever be signed in.
    pub fn is_exhausted(&mut self, otp: &mut impl Otp) -> bool {
        self.current_version(otp) >= self.layout.steps
    }

    /// What `slot` holds.
    pub fn slot_status(&mut self, otp: &mut impl Otp, slot: u8) -> Result<SlotStatus, ProvisionRefusal> {
        self.check_slot(slot)?;
        let row = otp.read_row(self.layout.key_row(slot)).map_err(ProvisionRefusal::Otp)?;
        Ok(SlotStatus::of(&row))
    }

    /// Advance the anti-rollback counter to `to`.
    ///
    /// Monotone by construction and by check:
    ///
    /// * the payload is `current | low_bits(to)`, so it is a **superset** of
    ///   the bits of every smaller version — an OTP cannot accept it if a
    ///   later attempt tries to encode a lower one;
    /// * `to <= current` is refused before any write.
    ///
    /// Refusals write nothing.
    pub fn set_version(&mut self, otp: &mut impl Otp, to: u16) -> Result<(), ProvisionRefusal> {
        if to == 0 {
            return Err(ProvisionRefusal::InvalidVersion { requested: to });
        }
        if to > self.layout.steps {
            return Err(ProvisionRefusal::VersionExhausted);
        }
        let mut row = otp.read_row(self.layout.version_row).map_err(ProvisionRefusal::Otp)?;
        let current = self.version_of(&row);
        if to <= current {
            return Err(ProvisionRefusal::VersionNotLowerable { current, requested: to });
        }
        self.burn_steps(&mut row, current, to);
        otp.program_row(self.layout.version_row, &row)
            .map_err(ProvisionRefusal::Otp)
    }

    /// **The one-shot write.** Provision `slot` with `fingerprint` and
    /// initialise the counter to `version`, in one presence-gated operation.
    ///
    /// Order of operations, and why:
    ///
    /// 1. argument checks — pure, no I/O, so a bad call does not consume a
    ///    grant or touch a row;
    /// 2. **presence**, consumed here and not later;
    /// 3. pre-flight read of the key row, which must be **virgin**;
    /// 4. pre-flight read of the counter, and the counter payload is
    ///    **computed** — so a version refusal is known *before* either write;
    /// 5. **counter first, fingerprint second.**
    ///
    /// Step 5 is fail-closed on purpose. If the second write fails, the
    /// device holds a burnt counter and a virgin key slot: it accepts no
    /// image and trusts no key until a new slot is provisioned, which is
    /// recoverable by re-running this function. The other order would leave a
    /// burnt fingerprint with a virgin counter — a device that trusts a key
    /// while still accepting version 0, i.e. anything. A mid-write failure is
    /// unrecoverable either way, and that is the intended reading of
    /// "irreversible"; this ordering just makes the unrecoverable direction
    /// the safe one.
    ///
    /// There is deliberately **no** un-provisioning counterpart.
    ///
    /// # US-1083: where the lock-state check sits, and why there
    ///
    /// It is step **1b** — after the pure argument checks and *before* the
    /// presence grant. Two consequences, both intended:
    ///
    /// * A locked device costs the operator **nothing**: no button press is
    ///   consumed, so an operator who presses, is refused, and presses again
    ///   has not silently burned a grant. On a surface whose failure mode is
    ///   "pressed the wrong thing at the wrong time", that matters.
    /// * It cannot be reached by a caller that has already paid for it. The
    ///   check is inside `provision_key`, not in a helper the caller might
    ///   skip — the same argument the one-shot pre-flight makes, and the
    ///   reason US-1083 could not be discharged by a documented convention.
    ///
    /// It is *not* step 0, before the argument checks: a bad `slot` or an
    /// all-zero fingerprint is a caller bug that should be reported as
    /// itself, and a caller that has both a bad argument and a locked page
    /// should hear about the argument.
    pub fn provision_key(
        &mut self,
        presence: &mut PresenceService,
        otp: &mut impl Otp,
        now_ms: u64,
        slot: u8,
        fingerprint: &[u8; FINGERPRINT_BYTES],
        version: u16,
    ) -> Result<(), ProvisionRefusal> {
        // 1. Arguments — pure, so a bad call burns neither a grant nor a row.
        let key_row = self.encoded_fingerprint_row(slot, fingerprint)?;
        if version == 0 {
            return Err(ProvisionRefusal::InvalidVersion { requested: version });
        }
        if version > self.layout.steps {
            return Err(ProvisionRefusal::VersionExhausted);
        }

        // 1b. US-1083: the lock state of every page this call will write to,
        //     before the grant is taken and before anything is read or
        //     written. A `READ_ONLY` page is the case the blank-row
        //     pre-flight below structurally cannot see: the read succeeds,
        //     the row reads virgin, and the failure would otherwise land at
        //     `program_row` with a grant already spent.
        self.check_lock_state(
            otp,
            &[self.layout.key_row(slot), self.layout.version_row],
        )?;

        // 2. Presence — single use, tag-bound, and consumed here.
        if presence.request(PROVISION_BOOT_KEY, now_ms).is_none() {
            return Err(ProvisionRefusal::PresenceNotGranted);
        }

        // 3. The one-shot pre-flight. A burnt key row is refused here, before
        //    any write is attempted, so there is no partial second write.
        let existing = otp.read_row(self.layout.key_row(slot)).map_err(ProvisionRefusal::Otp)?;
        if SlotStatus::of(&existing) != SlotStatus::Blank {
            return Err(ProvisionRefusal::AlreadyProvisioned);
        }

        // 4. The counter payload, computed before either write.
        let mut vrow = otp.read_row(self.layout.version_row).map_err(ProvisionRefusal::Otp)?;
        let current = self.version_of(&vrow);
        if version <= current {
            return Err(ProvisionRefusal::VersionNotLowerable { current, requested: version });
        }
        self.burn_steps(&mut vrow, current, version);

        // 5. Counter first, fingerprint second — see the docs.
        otp.program_row(self.layout.version_row, &vrow)
            .map_err(ProvisionRefusal::Otp)?;
        otp.program_row(self.layout.key_row(slot), &key_row)
            .map_err(ProvisionRefusal::Otp)
    }
}
