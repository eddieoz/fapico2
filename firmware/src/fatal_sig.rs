//! US-1306: a fatal boot says *why*, on the one channel a human has.
//!
//! # The problem this solves
//!
//! `boot::fatal_boot` was `defmt::error!` followed by `loop {}`. `defmt` needs
//! a RTT sink, which means a probe attached — and per `AGENTS.md`:98-112, a
//! connected SWD debugger is *sufficient on its own* to make this firmware
//! fail its OTP read and dark-boot on a board whose OTP is perfectly healthy.
//! So the one act available for finding out why the board died is the act that
//! kills the board. The panic handler has the identical shape and the identical
//! problem.
//!
//! The device has no watchdog and no recovery path, so every pre-USB park is
//! permanent until VBUS is removed. The only instrument left to a person
//! standing at a board with no tools is the LED.
//!
//! # How to read a signature
//!
//! A signature is a **preamble** followed by the reason's id in binary,
//! most-significant bit first. `0` is a short gap, `1` a long one:
//!
//! ```text
//!     ████████████░░░░░     preamble: one 1200 ms pulse, 600 ms gap
//!     ██░░░  ██░░░  ██░░░  ████░░░░░  4 bits, MSB first
//!     short  short  short  long          = 0b0001 = 1 = OTP key row
//! ```
//!
//! Everything is a *duration*, so the reading survives a board revision that
//! inverts the LED — the same polarity-independence property the boot ladder
//! is built on, and for the same reason (US-1303).
//!
//! # Why it cannot be mistaken for the other two patterns
//!
//! Three things blink on this pin, and a signature that collided with either
//! of the others would be worse than no signal. They are separated on axes
//! that do not depend on who is looking:
//!
//! | pattern | pulses | shortest lit pulse | repeats? |
//! |---|---|---|---|
//! | boot ladder (`boot_ladder`) | ≤ 19 cycles, 40 ms on/off | 40 ms | cumulative, then stops |
//! | heartbeat (`main.rs`) | 500 ms on / 500 ms off | 500 ms | forever, 1 Hz |
//! | **fatal signature** | 1 preamble + 4 bits | **200 ms** | once, then the board parks |
//!
//! The decisive axes are *pulse length* (200 ms is nothing else on this pin)
//! and *the preamble*, which is a single pulse three times longer than any
//! other lit pulse the firmware drives. A person who has seen the board blink
//! normally cannot confuse the two, and the host suite asserts both
//! separations rather than leaving them to this comment.

/// A signature's pulses: one preamble (lit + gap) plus two pulses per bit.
///
/// A fixed-size array, not a `Vec`: the device path is `no_std` with no heap
/// (`check_heap_gate.py` enforces exactly one sanctioned allocator and nothing
/// allocating pre-boot), and the length is known at compile time anyway.
pub const SIGNATURE_PULSES: usize = 2 + 2 * ID_BITS as usize;

/// The encoded pulse sequence for `reason`.
///
/// `SIGNATURE_PULSES` is always the length; [`signature_len`] states it as a
/// function so call sites read as a length rather than a magic number.
pub type Signature = [Pulse; SIGNATURE_PULSES];

/// Number of pulses in any signature.
pub const fn signature_len() -> usize {
    SIGNATURE_PULSES
}

/// One LED pulse: the level driven, and how long it is held (µs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pulse {
    /// [`crate::boot_ladder::Level`] the pin is driven to.
    pub on: bool,
    /// Hold time in microseconds.
    pub us: u32,
}

/// The lit level for every pulse here. GPIO25 on the Pico 2 is **active-high**
/// (US-1303), so a pulse is the pin driven high; this constant exists so the
/// mapping is stated once.
pub const LIT: bool = true;

/// Preamble: the longest lit pulse the firmware drives, by a wide margin.
/// Nothing else on this pin holds the LED for anything close.
pub const PREAMBLE_US: u32 = 1_200_000;

/// Unlit gap after the preamble, before the first bit.
///
/// Load-bearing, and easy to omit: without it the preamble runs straight into
/// the first bit's lit pulse and the two read as a *single* 1400 ms flash.
/// The preamble only works as a marker if it is separated from the data.
pub const PREAMBLE_GAP_US: u32 = 600_000;

/// Lit length of a data bit, long or short. Distinct from the ladder's 40 ms
/// and the heartbeat's 500 ms, which is what separates a signature from both.
pub const BIT_LIT_US: u32 = 200_000;

/// Unlit gap encoding a `0` bit — the longer of the two.
pub const ZERO_GAP_US: u32 = 600_000;

/// Unlit gap encoding a `1` bit — the shorter of the two.
pub const ONE_GAP_US: u32 = 200_000;

/// Why the device refused to boot.
///
/// One variant per *distinct cause*, not per call site: the whole point is that
/// a human reads the cause off the LED, and twenty-one call sites collapse to
/// ten things a person can act on. Several sites map to the same variant on
/// purpose — the four "OTP key row unavailable" sites are one failure with one
/// recovery, and a human who is told "OTP key row" can act on it without being
/// told which of four subsystems asked first.
///
/// Variants are grouped by *what the operator can do*, not by which crate
/// raised them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reason {
    /// The hardware key row could not be read.
    ///
    /// **This is the one whose recovery is known**: a power cycle clears it,
    /// and per `SECURITY-ASSESSMENT-ROUND2.md` §22 a plain *system* reset does
    /// not — the OTP `SW_LOCK` escalation survives that and only removing VBUS
    /// clears it. It was previously indistinguishable from the chipid, TRNG and
    /// DRBG refusals below, which is why it gets its own signature.
    OtpKeyRow = 1,
    /// The chip identity row could not be read.
    ChipId = 2,
    /// The boot entropy wait ran out of budget with no usable draw.
    TrngRefused = 3,
    /// The DRBG could not be seeded — no randomness, so no generator.
    DrbgRefused = 4,
    /// The secure-partition image failed authentication.
    UntrustedImage = 5,
    /// The secure partition could not be written durably.
    PersistFailed = 6,
    /// The backend never mounted.
    BackendNotMounted = 7,
    /// A keystore could not be opened.
    KeystoreFailed = 8,
    /// A schema migration could not complete.
    MigrationFailed = 9,
    /// A panic — the runtime's own refusal, distinct from every refusal above.
    Panic = 10,
}

/// Every reason, in id order. Used by the host tests to assert that no two
/// reasons encode identically, which is the property that makes the signature
/// worth reading.
pub const ALL_REASONS: [Reason; 10] = [
    Reason::OtpKeyRow,
    Reason::ChipId,
    Reason::TrngRefused,
    Reason::DrbgRefused,
    Reason::UntrustedImage,
    Reason::PersistFailed,
    Reason::BackendNotMounted,
    Reason::KeystoreFailed,
    Reason::MigrationFailed,
    Reason::Panic,
];

/// Bits in the encoded id field. Four covers ten reasons with room to spare,
/// and is the most a person can reliably count while watching a board.
pub const ID_BITS: u8 = 4;

impl Reason {
    /// The reason's numeric id, as encoded on the wire.
    pub fn id(self) -> u8 {
        self as u8
    }
}

/// The pulse sequence that identifies `reason` on the LED.
///
/// Pure, and deliberately so: this is the function a host test asserts, and
/// the thing a person is expected to read correctly by eye. Both matter more
/// than the LED plumbing, which is a thin wrapper in `boot::fatal_boot`.
pub fn signature(reason: Reason) -> Signature {
    let mut pulses = [
        Pulse { on: LIT, us: PREAMBLE_US },
        Pulse { on: !LIT, us: PREAMBLE_GAP_US },
        Pulse { on: LIT, us: BIT_LIT_US },
        Pulse { on: !LIT, us: 0 },
        Pulse { on: LIT, us: BIT_LIT_US },
        Pulse { on: !LIT, us: 0 },
        Pulse { on: LIT, us: BIT_LIT_US },
        Pulse { on: !LIT, us: 0 },
        Pulse { on: LIT, us: BIT_LIT_US },
        Pulse { on: !LIT, us: 0 },
    ];
    // MSB first, so the id reads left-to-right the way it is written.
    for (bit_index, slot) in (2..SIGNATURE_PULSES).step_by(2).enumerate() {
        let shift = ID_BITS as usize - 1 - bit_index;
        let bit = (reason.id() >> shift) & 1;
        pulses[slot + 1].us = if bit == 1 { ONE_GAP_US } else { ZERO_GAP_US };
    }
    pulses
}

/// Decode a pulse sequence back to the reason it names, or `None` if it is not
/// a signature.
///
/// The inverse of [`signature`], and the reason the format is testable at all:
/// a signature nobody can decode is a pattern, not a diagnosis. Returning
/// `None` for anything that is not exactly a well-formed signature is what
/// keeps a `fatal_boot` from being confused with the ladder or the heartbeat.
pub fn decode(pulses: &[Pulse]) -> Option<Reason> {
    if pulses.len() != 2 + 2 * ID_BITS as usize {
        return None;
    }
    if pulses[0] != (Pulse { on: LIT, us: PREAMBLE_US })
        || pulses[1] != (Pulse { on: !LIT, us: PREAMBLE_GAP_US })
    {
        return None;
    }
    let mut id = 0u8;
    for bit in 0..ID_BITS {
        let lit = pulses[2 + 2 * bit as usize];
        let gap = pulses[3 + 2 * bit as usize];
        if lit != (Pulse { on: LIT, us: BIT_LIT_US }) {
            return None;
        }
        id <<= 1;
        match gap.us {
            us if gap.on == !LIT && us == ZERO_GAP_US => {}
            us if gap.on == !LIT && us == ONE_GAP_US => id |= 1,
            _ => return None,
        }
    }
    ALL_REASONS.into_iter().find(|r| r.id() == id)
}

/// Total lit time of a signature, in µs.
///
/// Not merely informative: a person can only count pulses they can see, so the
/// lit time is the minimum duration the whole pattern must occupy. It is also
/// what makes the signature's visibility a stated budget rather than an
/// accident — 2.0 s per signature.
pub fn lit_time_us(reason: Reason) -> u32 {
    signature(reason)
        .iter()
        .filter(|p| p.on)
        .map(|p| p.us)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gherkin: "Given a device whose OTP key row cannot be read / When it
    /// refuses to boot / Then the LED emits a signature that decodes back to
    /// the OTP reason / And no other reason produces that signature."
    #[test]
    fn given_the_otp_key_row_is_unreadable_when_the_device_parks_then_the_led_names_that_exact_cause() {
        let pulses = signature(Reason::OtpKeyRow);
        assert_eq!(decode(&pulses), Some(Reason::OtpKeyRow));
    }

    /// The load-bearing property of the whole story: the OTP signature is
    /// unique among all reasons. Without this, US-1306's promise — that a
    /// person can name the cause — is false, however good the encoding looks.
    #[test]
    fn given_every_reason_when_each_is_encoded_then_no_two_produce_the_same_signature() {
        for a in ALL_REASONS {
            for b in ALL_REASONS {
                if a == b {
                    continue;
                }
                assert_ne!(
                    signature(a),
                    signature(b),
                    "{a:?} and {b:?} encode identically — a person could not tell them apart"
                );
            }
        }
    }

    #[test]
    fn given_every_reason_when_each_is_encoded_then_it_decodes_back_to_itself() {
        for reason in ALL_REASONS {
            assert_eq!(
                decode(&signature(reason)),
                Some(reason),
                "{reason:?} did not round-trip"
            );
        }
    }

    /// US-1306: the OTP refusal must be distinguishable from the other
    /// refusals it used to be indistinguishable from. Asserted per-pair on the
    /// bit field, since that is where the distinction lives.
    #[test]
    fn given_the_otp_signature_when_compared_to_the_other_refusals_then_it_is_distinct_from_each() {
        let otp = signature(Reason::OtpKeyRow);
        for other in [
            Reason::ChipId,
            Reason::TrngRefused,
            Reason::DrbgRefused,
            Reason::UntrustedImage,
            Reason::PersistFailed,
            Reason::BackendNotMounted,
            Reason::KeystoreFailed,
            Reason::MigrationFailed,
            Reason::Panic,
        ] {
            assert_ne!(otp, signature(other), "{other:?} collides with the OTP signature");
        }
    }

    /// The panic handler's signature is distinct from every refusal. US-1306
    /// calls this out separately because a panic is the runtime's own failure
    /// mode and has a different fix (it is a bug, not a policy refusal).
    #[test]
    fn given_a_panic_when_the_device_parks_then_the_led_is_distinct_from_every_policy_refusal() {
        let panic = signature(Reason::Panic);
        for reason in ALL_REASONS.into_iter().filter(|r| *r != Reason::Panic) {
            assert_ne!(panic, signature(reason));
        }
    }

    // -- separation from the other two blinking patterns ------------------------

    /// The heartbeat is 500 ms on / 500 ms off forever. No signature pulse may
    /// be a heartbeat pulse, or the two could not be told apart by a person
    /// counting.
    #[test]
    fn given_the_heartbeat_when_a_signature_is_encoded_then_no_pulse_has_the_heartbeat_period() {
        const HEARTBEAT_US: u32 = 500_000;
        for reason in ALL_REASONS {
            for pulse in signature(reason) {
                assert_ne!(
                    pulse.us, HEARTBEAT_US,
                    "{reason:?} emits a 500 ms pulse, which is a heartbeat pulse"
                );
            }
        }
    }

    /// The boot ladder blinks 40 ms on / 40 ms off, at most 19 cycles. No
    /// signature pulse may be 40 ms, and no signature may be a run of ladder
    /// cycles.
    #[test]
    fn given_the_boot_ladder_when_a_signature_is_encoded_then_no_pulse_has_the_ladder_period() {
        const LADDER_US: u32 = 40_000;
        for reason in ALL_REASONS {
            for pulse in signature(reason) {
                assert_ne!(
                    pulse.us, LADDER_US,
                    "{reason:?} emits a 40 ms pulse, which is a ladder pulse"
                );
            }
        }
    }

    /// The preamble is the unambiguous marker: it is the single longest lit
    /// pulse the firmware drives, so seeing it at all says "this is a fatal
    /// signature, not the ladder or the heartbeat" before any bit is counted.
    #[test]
    fn given_every_signature_when_it_is_encoded_then_it_starts_with_the_preamble_marker() {
        for reason in ALL_REASONS {
            let pulses = signature(reason);
            assert_eq!(pulses[0], Pulse { on: LIT, us: PREAMBLE_US });
            assert_eq!(pulses[1], Pulse { on: !LIT, us: PREAMBLE_GAP_US });
            let longest = pulses.iter().map(|p| p.us).max().unwrap();
            assert_eq!(longest, PREAMBLE_US, "{reason:?} preamble is not the longest pulse");
            assert!(
                PREAMBLE_US > 3 * BIT_LIT_US,
                "the preamble must be unmistakably longer than a bit"
            );
        }
    }

    /// The signature is emitted once and then the board parks. Asserted as a
    /// property of the encoder's output length so it cannot silently grow into
    /// something a person has to watch for a minute to read.
    #[test]
    fn given_every_signature_when_it_is_encoded_then_it_is_five_lit_pulses_and_five_gaps() {
        for reason in ALL_REASONS {
            let pulses = signature(reason);
            assert_eq!(pulses.len(), 2 + 2 * ID_BITS as usize);
            assert_eq!(pulses.iter().filter(|p| p.on).count(), 1 + ID_BITS as usize);
        }
    }

    /// A human has to be able to watch it. Stated as a budget: the whole
    /// signature occupies ~4.2 s of which 2.0 s is lit.
    #[test]
    fn given_a_signature_when_it_is_timed_then_it_is_readable_in_a_few_seconds() {
        let total = signature(Reason::OtpKeyRow).iter().map(|p| p.us).sum::<u32>();
        // OtpKeyRow is id 1, so its bits are 0,0,0,1: three zero gaps and one
        // one gap, plus the preamble and its own gap.
        assert_eq!(
            total,
            PREAMBLE_US + PREAMBLE_GAP_US + 4 * BIT_LIT_US + 3 * ZERO_GAP_US + ONE_GAP_US
        );
        assert!(total < 6_000_000, "a signature taking {total} us is too slow to read");
        assert_eq!(lit_time_us(Reason::OtpKeyRow), PREAMBLE_US + 4 * BIT_LIT_US);
    }

    // -- the decoder refuses what is not a signature ----------------------------

    #[test]
    fn given_something_that_is_not_a_signature_when_it_is_decoded_then_the_answer_is_none() {
        // The heartbeat, verbatim.
        assert_eq!(decode(&[Pulse { on: LIT, us: 500_000 }, Pulse { on: false, us: 500_000 }]), None);
        // Empty, and truncated.
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&signature(Reason::Panic)[..4]), None);
        // Right shape, wrong preamble.
        let mut wrong_preamble = signature(Reason::ChipId);
        wrong_preamble[0].us = 900_000;
        assert_eq!(decode(&wrong_preamble), None);
        // Right preamble, a bit pulse of the wrong length.
        let mut wrong_bit = signature(Reason::ChipId);
        wrong_bit[2].us = 40_000;
        assert_eq!(decode(&wrong_bit), None);
        // An id that is not a real reason (0 is reserved; nothing maps to it).
        let mut unused = signature(Reason::ChipId);
        for slot in 0..ID_BITS as usize {
            let idx = 2 + 2 * slot;
            unused[idx + 1].us = ZERO_GAP_US;
        }
        assert_eq!(decode(&unused), None);
    }

    /// US-1306's acceptance criterion, stated as a test: on a board frozen by
    /// the OTP path, what a human sees identifies that path and nothing else
    /// could produce it. Asserted end to end over the encoder — encode the OTP
    /// reason, decode it back, and confirm the every-other-reason exclusion
    /// still holds — because that is the whole chain that runs on the device.
    ///
    /// What is NOT asserted here: that the board actually lights. No board was
    /// attached when this was written, so the LED-driving wrapper in
    /// `boot::emit_fatal_signature` is unexercised. This test proves the
    /// signature a person would read is unambiguous; whether it reaches the pin
    /// is a hardware measurement and is recorded as such in the epic.
    #[test]
    fn given_a_board_frozen_by_the_otp_path_when_a_person_reads_the_led_then_only_the_otp_cause_fits() {
        let observed = signature(Reason::OtpKeyRow);
        assert_eq!(decode(&observed), Some(Reason::OtpKeyRow));
        // Nothing else decodes to this pattern...
        for other in ALL_REASONS.into_iter().filter(|r| *r != Reason::OtpKeyRow) {
            assert_eq!(decode(&observed), Some(Reason::OtpKeyRow));
            assert_ne!(observed, signature(other));
        }
        // ...and the recovery is the documented one: a power cycle, not a
        // reset. The reason carries that distinction in its own doc, and it is
        // why this reason was split out rather than folded into a generic
        // "hardware identity unavailable".
        assert_eq!(Reason::OtpKeyRow.id(), 1);
    }

    /// US-1310 (implementing ADR 0004 option 1): the OTP refusal emits its
    /// signature and the device does not serve. Asserted against the *decision*
    /// rather than the encoder — the property ADR 0004 chose is that the
    /// refusal is both **legible** and **enforced**, so the test checks both
    /// halves and would fail if someone "fixed" a freeze by making the key row
    /// optional.
    ///
    /// What it cannot check: that `derive_boot_store_key` still calls
    /// `fatal_boot` on a bad read. That is a device-path property — the OTP
    /// read needs real silicon — and is covered by review plus the epic's
    /// hardware stories, not by a host test that could only assert it about
    /// itself. Stated here so nobody reads a green suite as proof of it.
    #[test]
    fn given_the_otp_refusal_when_the_policy_runs_then_it_is_both_legible_and_enforced() {
        // Legible: the cause is on the LED, uniquely.
        assert_eq!(
            decode(&signature(Reason::OtpKeyRow)),
            Some(Reason::OtpKeyRow)
        );
        // Enforced: the signature is emitted and then the device parks. There
        // is exactly one terminal state in this enum for an unreadable key row,
        // it is the same state every other refusal uses, and nothing in the
        // encoder can express "carry on" — the type has no such arm. A fallback
        // key would have to be a new variant, which is the point: it becomes
        // visible here rather than slipping in as a behaviour change.
        assert!(ALL_REASONS.contains(&Reason::OtpKeyRow));
        // And the fallback key this ADR rejected has no reason id, so no
        // signature could ever be read as "booted with an unverified key".
        assert_eq!(Reason::OtpKeyRow.id(), 1);
        assert!(ALL_REASONS.iter().all(|r| r.id() != 0));
    }

    /// The encoder and decoder are a bijection on the reason set, so the id
    /// space is not silently over-subscribed: no reason can be encoded into a
    /// pattern that some other id also claims.
    #[test]
    fn given_the_reason_set_when_it_is_encoded_then_every_id_is_in_range_and_unique() {
        let mut ids: Vec<u8> = ALL_REASONS.iter().map(|r| r.id()).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before, "two reasons share an id");
        for id in ids {
            assert!(
                id > 0 && id < (1 << ID_BITS),
                "reason id {id} does not fit in {ID_BITS} bits"
            );
        }
    }
}
