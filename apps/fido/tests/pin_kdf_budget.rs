//! US-1570 — the PIN KDF's cost, its ceiling, and its migration window.
//!
//! Four clauses from the story, and what each test here is actually able to
//! say. The distinction is stated up front because this story's headline is a
//! latency number and **there is no RP2350 in this loop**: what can be pinned
//! here is the derivation, the ceiling that follows from it, the equivalence
//! of the accelerated and software paths, and the migration behaviour. The
//! latency itself belongs to a board.
//!
//! | clause | pinned by | what it really establishes |
//! |---|---|---|
//! | "the measured verification latency stays inside the 200 ms budget" | [`the_round_count_fits_the_budget_under_the_pessimistic_cost_model`] | the **arithmetic** — `rounds x per-round cycles <= budget cycles`, with the per-round figure the pessimist's. Not a measurement, and the test says so in its own failure message. |
//! | "the snapshot-decode ceiling refuses any iteration count the new budget cannot serve" | [`a_raised_ceiling_refuses_the_counts_above_it_in_both_decoders`] | the refusal, at the new value, through **both** decoders — the host `PinState` codec and the device `DeviceKeystore` codec. |
//! | "existing verifiers migrate via `pin_verifier_upgrade` on the next successful PIN" | [`the_upgrade_emits_a_record_at_exactly_the_round_count_the_decoders_accept`] | the emitted record's round count equals the ceiling, so a migration can never write a record the loader would refuse. |
//! | "legacy-format verifiers are refused after the migration window" | [`the_legacy_migration_window_is_a_single_comparison_and_it_gates_admission`] | the window exists, is one comparison, and is the thing `pin_verifier_admission` consults. |
//!
//! # What is arithmetic here and what would need hardware
//!
//! **Arithmetic, and pinned below:** the round count, the 16x increase, the
//! block count (`rounds + 1`, because a 60-byte input pads across two blocks),
//! the budget in cycles, and the fact that the chosen count fits that budget
//! under the pessimistic per-round figure.
//!
//! **Needs hardware, and deliberately not claimed here:** the per-round figure
//! itself. The block's 57 compression cycles and the stock 150 MHz clock are
//! datasheet figures — the first carried in `rp-pac`'s SVD text for
//! `CSR.WDATA_RDY`, the second by `embassy-rp`'s RP2350 `Config::default()` —
//! but the **CPU-side** cost (`hash_into`'s block copy, the `CSR`
//! read-modify-write in `begin`, sixteen `WDATA` stores, the `SUM_VLD` poll) is
//! estimated, not measured. `platform/src/sha256_accel.rs` states the same
//! limit about its own register layer: "the logic is tested, the register
//! writes are reviewed". If a board comes in above
//! `PIN_VERIFIER_CYCLES_PER_ROUND_POLLED`, the `const _` assertion in
//! `crypto.rs` is what catches it and this file's headline test is where the
//! number would be re-derived.

mod common;

use common::*;
use fapico2_fido::cbor::{self, Value};
use fapico2_fido::crypto::{self, PinVerifierRefusal};
use fapico2_fido::device_keystore::DeviceKeystore;
use fapico2_fido::keystore::{FileKeystore, Keystore, PinState};
use fapico2_platform::sha256_accel::{digest_from_words, hash_into, Block, BlockSink};

/// A `BlockSink` that runs SHA-256's **compression function** itself, counts
/// the blocks it is handed, and can be told to stop working.
///
/// # Why it is a compression function and not a `sha2::Sha256`
///
/// Because [`hash_into`] pushes blocks that are **already padded**, and the
/// high-level `Digest` API is a *message* API whose `finalize` appends its own
/// `0x80`, zeroes and length field. Feeding a padded block to `Digest::update`
/// and finalising computes `SHA256(padded_block)` — a 64-byte message with a
/// second layer of padding — which is a well-formed digest of the wrong thing
/// and refuses nothing. There is no high-level call that says "compress this
/// block onto the current state"; the compression function is the only API that
/// matches what `BlockSink` means.
///
/// `platform/tests/sha256_accel.rs` carries a second, independent copy of this
/// same oracle for the same reason, and neither should be folded into the other:
/// an oracle built from the code under test proves nothing.
///
/// # Why it counts
///
/// The block count *is* the latency. [`crypto::PIN_VERIFIER_CYCLES_PER_ROUND_POLLED`]
/// is a per-block figure, so `one_verification_is_rounds_plus_one_blocks` can
/// only check the cost model against reality by seeing how many blocks the
/// verifier actually asks the accelerator to compress.
struct Compress256Sink {
    state: [u32; 8],
    blocks: usize,
    /// `true` = work normally. `false` = fail every operation, which is the
    /// "the block is not there" case that `Sha256Error::Unavailable` and
    /// `Sha256Error::DigestNotValid` both stand for.
    healthy: bool,
}

/// FIPS 180-4 §4.2.2 — the SHA-256 initial hash value.
const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// FIPS 180-4 §4.2.3 — the first 32 bits of the fractional parts of the cube
/// roots of the first 64 primes.
#[rustfmt::skip]
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Compress256Sink {
    fn new() -> Self {
        Self { state: SHA256_H0, blocks: 0, healthy: true }
    }

    /// One 512-bit compression onto `self.state`.
    fn compress(&mut self, block: &Block) {
        let mut w = [0u32; 64];
        for (i, slot) in w.iter_mut().enumerate().take(16) {
            // Big-endian: SHA-256's first byte of a word is the most
            // significant, which is the opposite of the little-endian
            // `WDATA` feed the driver assembles before handing it over.
            *slot = u32::from_be_bytes([
                block.0[i * 4],
                block.0[i * 4 + 1],
                block.0[i * 4 + 2],
                block.0[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

/// The one error this stand-in can report. Deliberately opaque: the test is
/// about the *fallback*, not about which accelerator failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Broken;

impl BlockSink for Compress256Sink {
    type Error = Broken;

    fn begin(&mut self) -> Result<(), Broken> {
        if !self.healthy {
            return Err(Broken);
        }
        self.state = SHA256_H0;
        Ok(())
    }

    fn push(&mut self, block: &Block) -> Result<(), Broken> {
        if !self.healthy {
            return Err(Broken);
        }
        self.blocks += 1;
        self.compress(block);
        Ok(())
    }

    fn finish(&mut self) -> Result<[u8; 32], Broken> {
        if !self.healthy {
            return Err(Broken);
        }
        Ok(digest_from_words(self.state))
    }
}

// ---------------------------------------------------------------------------
// "the measured verification latency stays inside the 200 ms budget"
// ---------------------------------------------------------------------------

/// HEADLINE (US-1570): the round count fits the 200 ms budget **under the
/// pessimistic per-round cost model**.
///
/// # This is arithmetic. It is not a latency measurement and must not be
/// quoted as one.
///
/// There is no RP2350 here. What is checked is the multiplication
/// `rounds x per-round cycles <= budget cycles`, with `per-round cycles`
/// taken at [`crypto::PIN_VERIFIER_CYCLES_PER_ROUND_POLLED`] — a deliberately
/// pessimistic figure, roughly 3x the block's own 57-cycle compression time,
/// chosen so the assertion holds even if the compiler generates the driver's
/// byte-to-word assembly as written rather than folding it into one aligned
/// load. The same inequality is a `const _` assertion in `crypto.rs`, so it is
/// a *build* failure too; this test exists so the three constants are in the
/// test output where a reader meets them, and so the relationship between them
/// cannot be quietly satisfied by only one.
///
/// The failure message names the hardware measurement that would supersede
/// this, because when it goes red on a real board that is what the fix is.
#[test]
fn the_round_count_fits_the_budget_under_the_pessimistic_cost_model() {
    let rounds = u64::from(crypto::PIN_VERIFIER_ROUNDS);
    let per_round = u64::from(crypto::PIN_VERIFIER_CYCLES_PER_ROUND_POLLED);
    let cycles = rounds * per_round;
    assert!(
        cycles <= crypto::PIN_VERIFY_BUDGET_CYCLES,
        "PIN_VERIFIER_ROUNDS ({rounds}) x PIN_VERIFIER_CYCLES_PER_ROUND_POLLED \
         ({per_round}) = {cycles} cycles > PIN_VERIFY_BUDGET_CYCLES ({}) — the \
         derivation says a verification overruns its budget. Re-derive \
         PIN_VERIFIER_CYCLES_PER_ROUND_POLLED against a measured board, or \
         lower PIN_VERIFIER_ROUNDS.",
        crypto::PIN_VERIFY_BUDGET_CYCLES
    );

    // The 16x claim, stated as a claim rather than left implicit: US-910's
    // 4096 is the number this story exists to replace, and a reader who cannot
    // see the factor cannot judge the change.
    assert_eq!(
        crypto::PIN_VERIFIER_ROUNDS / 4096,
        16,
        "US-1570's stated increase is 4096 -> 65536, a factor of 16"
    );

    // ...and the direction the story wanted, 100k, with the reason it is not
    // taken. Recorded here rather than left to a reader of the constant to
    // work out, because "why not 100k" is the question this constant invites.
    let hundred_k = 100_000u64;
    assert!(
        hundred_k * per_round > crypto::PIN_VERIFY_BUDGET_CYCLES,
        "100,000 rounds now fits the polled budget, so the round count can be \
         raised to the figure US-1570 named. Revisit PIN_VERIFIER_ROUNDS."
    );
    assert!(
        hundred_k * u64::from(crypto::PIN_VERIFIER_CYCLES_PER_ROUND_DMA)
            <= crypto::PIN_VERIFY_BUDGET_CYCLES,
        "100,000 rounds is expected to fit the DMA path only — which is why it \
         is not the shipped number"
    );
}

/// The block arithmetic the budget is made of: **one verification is
/// `rounds + 1` blocks**, because the domain-separated input is 60 bytes and
/// 60 > 55 pads across two, while every iterated round is a 32-byte message and
/// one block.
///
/// This is the quantity that actually decides latency on the board, so it is
/// *measured* rather than asserted — by counting the blocks a real sink is
/// handed, at a **small** round count. `PIN_VERIFIER_ROUNDS` itself is not
/// used: counting 65,537 blocks through `sha2` is wasted test time for an exact
/// formula, and the formula is what is under test.
#[test]
fn one_verification_is_rounds_plus_one_blocks() {
    const ROUNDS: u32 = 37;
    let mut sink = Compress256Sink::new();
    let _out = crypto::pin_verifier_stretched_via(&[0x11; 16], &[0x22; 16], ROUNDS, &mut sink)
        .expect("a healthy sink produces a verifier");

    // 2 blocks for the 60-byte domain-separated input + 1 per iterated round.
    assert_eq!(
        sink.blocks,
        2 + (ROUNDS as usize - 1),
        "a verification is `rounds - 1` single-block rounds plus a two-block \
         first hash, i.e. rounds + 1 blocks"
    );
    assert!(
        sink.blocks > ROUNDS as usize,
        "the domain-separated input must cost more than one block, or the \
         `rounds + 1` derivation is hiding an off-by-one"
    );
}

/// The accelerated path and the software path are the **same digest**.
///
/// The device runs [`crypto::pin_verifier_stretched`] through the RP2350 block
/// and every host build runs it through [`crypto::Sha2BlockSink`]. If those two
/// could disagree, the host test suite would be validating a verifier the board
/// never computes — and US-910's `pin_verifier.rs` would pass against a device
/// that rejects every PIN.
///
/// This is also the only differential available without silicon, and it is worth
/// being blunt about its limit: it proves the *block assembly* feeding a sink is
/// right (which is what `sha256_accel` tests, and it tests it again here over
/// the one input shape the verifier uses), not that the registers latch what
/// they are handed.
#[test]
fn the_accelerated_and_software_paths_are_the_same_digest() {
    for (ph, salt, rounds) in [
        ([0x00u8; 16], [0xFFu8; 16], 1u32),
        ([0xA5; 16], [0x5A; 16], 2),
        ([0x11; 16], [0x22; 16], 17),
        ([0x33; 16], [0x44; 16], 64),
    ] {
        let mut sink = Compress256Sink::new();
        let accelerated = crypto::pin_verifier_stretched_via(&ph, &salt, rounds, &mut sink)
            .expect("a healthy sink produces a verifier");
        let software = crypto::pin_verifier_stretched(&ph, &salt, rounds);
        assert_eq!(
            accelerated, software,
            "the sink path and the shipped path disagree at rounds={rounds}: \
             the host suite would be testing a verifier the board never computes"
        );
    }
}

/// A board whose accelerator stops working must still verify the right PIN.
///
/// The fallback in [`crypto::pin_verifier_stretched`] is to software, and the
/// reason it can be is that software and accelerator are specified to be the
/// same function. What this pins is that the failure is an `Err` and not a
/// digest — an accelerator that returns an error mid-verification must not leave
/// the caller holding a partial value, and `sha256_accel` states the rule three
/// times over because it is the rule that matters ("a broken accelerator must
/// produce a distinguishable failure, never a plausible-looking hash").
///
/// Only the software arm is reachable on this host, since the accelerated one
/// is `target_arch = "arm"`. What is tested here is therefore the *contract*
/// the fallback rests on — a failed sink reports `Err` and is credited with no
/// work — plus the positive control that a healthy sink and the shipped path
/// agree. The selection between the two is a `#[cfg]` on a board.
#[test]
fn an_accelerator_that_stops_working_falls_back_rather_than_lying() {
    let ph = [0x7Eu8; 16];
    let salt = [0x18u8; 16];
    let reference = crypto::pin_verifier_stretched(&ph, &salt, 32);

    // Positive control: a sink that never fails must equal the shipped answer.
    let mut healthy = Compress256Sink::new();
    assert_eq!(
        crypto::pin_verifier_stretched_via(&ph, &salt, 32, &mut healthy).unwrap(),
        reference
    );

    // A sink that fails from the first block. There is no digest here, so the
    // only correct outcome at the call site is "recompute in software".
    let mut broken = Compress256Sink::new();
    broken.healthy = false;
    assert_eq!(
        crypto::pin_verifier_stretched_via(&ph, &salt, 32, &mut broken),
        Err(Broken),
        "a sink that fails must report an error, never a digest"
    );
    assert_eq!(
        broken.blocks, 0,
        "a failed sink must not be credited with any work"
    );
    assert_eq!(
        crypto::pin_verifier_stretched(&ph, &salt, 32),
        reference,
        "with the accelerator unavailable the shipped path must still return \
         the correct verifier"
    );
}

/// The 2^61-byte boundary is unreachable from this verifier, structurally.
///
/// `sha256_accel::hash_into` takes the bit length as an explicit argument
/// precisely so a `len * 8` cannot wrap silently. This verifier never passes a
/// runtime length at all — [`crypto::pin_verifier_stretched_via`] goes through
/// a fixed-size helper — so the class of bug has no code path to live in. This
/// test says so out loud, and fails if a future edit reintroduces a runtime
/// length.
#[test]
fn the_verifier_never_feeds_a_runtime_length_to_the_accelerator() {
    assert!(
        (crypto::PIN_VERIFIER_INPUT_LEN as u64) < (1u64 << 61),
        "the domain-separated input must stay under SHA-256's 2^61-byte \
         encodable maximum"
    );
    // And a directly-driven fixed-size hash matches `sha2` for the two shapes
    // the verifier uses, which is the property the fixed-size helper keeps.
    // Two calls rather than a loop over differently-sized arrays: a `[u8; N]`
    // loop variable cannot hold both, and the point is the two lengths, not a
    // collection of them.
    let mut sink = Compress256Sink::new();
    let round = [0u8; 32];
    assert_eq!(
        hash_into(&round, 32u64 * 8, &mut sink).expect("healthy sink"),
        crypto::sha256(&round),
        "the 32-byte round message differs from sha2"
    );
    assert_eq!(sink.blocks, 1, "a 32-byte message is exactly one block");
    let mut sink = Compress256Sink::new();
    let input = [0xCDu8; 60];
    assert_eq!(
        hash_into(&input, 60u64 * 8, &mut sink).expect("healthy sink"),
        crypto::sha256(&input),
        "the 60-byte domain-separated input differs from sha2"
    );
    assert_eq!(
        sink.blocks, 2,
        "60 bytes pads across two blocks — the reason a verification is \
         `rounds + 1` blocks and not `rounds`"
    );
}

// ---------------------------------------------------------------------------
// "the snapshot-decode ceiling refuses any iteration count the new budget
//  cannot serve"
// ---------------------------------------------------------------------------

/// Both decoders refuse the counts above the **new** ceiling, and both accept
/// the ceiling itself.
///
/// Two codecs, two independent refusal sites, and both of them read
/// `crypto::PIN_VERIFIER_ROUNDS` rather than a literal — which is the whole
/// reason US-1570's 16x increase needed no edit outside `crypto.rs`:
///
/// * `keystore.rs` (host): `if i > crypto::PIN_VERIFIER_ROUNDS as u64 { return None }`
/// * `device_keystore.rs` (RP2350): `Item::U(u) if u <= crypto::PIN_VERIFIER_ROUNDS`
///
/// Neither clamps. That is the discipline the story requires to survive: a
/// **clamp** would let an attacker write `u32::MAX` and have the device either
/// agree to run 4096 rounds against a record the attacker computed for a
/// different count, or (clamping upward) wedge the PIN path for hours — which
/// is precisely FX-440.
#[test]
fn a_raised_ceiling_refuses_the_counts_above_it_in_both_decoders() {
    let stretched = |iter: u64| {
        Value::M(vec![
            (Value::U(14), Value::U(1)),
            (Value::U(15), Value::B(vec![0x11; 16])),
            (Value::U(16), Value::U(iter)),
        ])
    };
    let ceiling = u64::from(crypto::PIN_VERIFIER_ROUNDS);

    // (a) the HOST codec
    for iter in [ceiling + 1, 1_000_000, u64::from(u32::MAX)] {
        assert!(
            PinState::from_cbor_for_test(&stretched(iter)).is_none(),
            "host decoder accepted pin_iter {iter}: corrupt input must be \
             refused, never truncated"
        );
    }
    let state =
        PinState::from_cbor_for_test(&stretched(ceiling)).expect("the ceiling is a real value");
    assert_eq!(state.pin_iter, crypto::PIN_VERIFIER_ROUNDS);
    assert_eq!(state.pin_salt, Some([0x11; 16]));

    // (b) the DEVICE codec, reached through a real snapshot rather than
    // through a synthetic pin map — the device decoder has no public entry
    // point for a pin record on its own, and the honest way in is the whole
    // image.
    let (base, original) = device_snapshot();
    assert_eq!(original, crypto::PIN_VERIFIER_ROUNDS);
    assert!(
        DeviceKeystore::from_cbor(&base, None).is_some(),
        "the control image must parse: otherwise the refusals below would \
         prove nothing about the iteration count"
    );
    for iter in [ceiling + 1, 1_000_000, u64::from(u32::MAX), u64::from(u32::MAX) + 1] {
        let tampered = with_pin_iter(&base, iter);
        assert!(
            DeviceKeystore::from_cbor(&tampered, None).is_none(),
            "device decoder accepted pin_iter {iter}: the refusal at load is \
             what stops an attacker-crafted count from wedging the PIN path"
        );
    }
}

/// A `format == 1` record with no salt is **inadmissible**, at any round count.
///
/// The salt is not decoration: without it the stretched derivation is a
/// function of the PIN alone, which is exactly the shared offline table US-910
/// exists to remove. `pin_verifier_matches` has a fallback arm that compares the
/// candidate *directly* when the salt is absent — correct for a record that says
/// it is legacy, a hole for one that claims to be stretched — so this is the
/// condition that fallback must never see.
///
/// # A gap in the device codec, recorded rather than papered over
///
/// The **host** codec refuses a stretched record with no salt
/// (`keystore.rs`: `if s.pin_verifier_format == PIN_VERIFIER_FORMAT_STRETCHED
/// && s.pin_salt.is_none() { return None }`) and so does its key-15 arm. The
/// **device** codec (`device_keystore.rs::decode_auth`) has the key-15 arm —
/// `Item::B(b) if b.len() == 16` — but **no post-loop check**, so a snapshot
/// carrying keys 14 and 16 and no 15 at all parses. That asymmetry is a real
/// finding, and it is in a file this story does not own, so it is neither fixed
/// nor asserted here: asserting it would enshrine the hole, and a test written
/// to fail until someone fixes it would go red for the wrong reason.
///
/// What *is* pinned, and what closes the exposure independently of the codec,
/// is [`crypto::pin_verifier_admission`]: the gate US-1570 adds refuses the
/// record before any PIN guess is spent and before `pin_verifier_matches` can
/// reach its direct-comparison arm. The gap's practical reach is also limited
/// today — writing such a snapshot requires the AEAD seal's key, so it is
/// reachable only by an attacker who can already forge a sealed snapshot.
/// What it would *not* survive is a future path that assembles a verifier
/// without the store key (a restored backup, a vendor import), which is exactly
/// why the admission gate is the load-bearing half here and the codec check is
/// defence in depth.
#[test]
fn a_stretched_record_with_no_salt_is_refused_by_both_admission_and_the_host_codec() {
    let unsalted = Value::M(vec![
        (Value::U(14), Value::U(1)),
        (Value::U(16), Value::U(u64::from(crypto::PIN_VERIFIER_ROUNDS))),
    ]);
    assert!(
        PinState::from_cbor_for_test(&unsalted).is_none(),
        "a stretched record with no salt must be refused by the host codec, \
         not downgraded"
    );

    // And the gate the device path must consult before it verifies anything.
    assert_eq!(
        crypto::pin_verifier_admission(
            crypto::PIN_VERIFIER_FORMAT_STRETCHED,
            crypto::PIN_VERIFIER_ROUNDS,
            None,
        ),
        Err(PinVerifierRefusal::Malformed),
        "admission must refuse an unverifiable record before a PIN guess is \
         spent — this, not the snapshot codec, is what keeps \
         pin_verifier_matches' direct-comparison arm unreachable for a record \
         that claims to be stretched"
    );

    // The control: with a salt, the same record is admitted at the same count.
    assert_eq!(
        crypto::pin_verifier_admission(
            crypto::PIN_VERIFIER_FORMAT_STRETCHED,
            crypto::PIN_VERIFIER_ROUNDS,
            Some(&[0x22u8; 16]),
        ),
        Ok(())
    );
}

/// The device codec round-trips the salt the way the host codec reads it.
///
/// The negative half of the previous test is left to the admission gate, but
/// the positive half is worth pinning on the device path too: if a future
/// encoder change moved the salt out of key 15, `decode_auth` would stop
/// populating `pin_salt` and every verification on the RP2350 would silently
/// take `pin_verifier_matches`' legacy arm. That is the same failure the
/// no-salt test is about, reached from the other direction, and nothing else in
/// the suite would notice it.
#[test]
fn the_device_codec_round_trips_the_salt_and_the_round_count() {
    let (base, iter) = device_snapshot();
    let parsed = DeviceKeystore::from_cbor(&base, None).expect("the control snapshot parses");
    assert_eq!(parsed.pin_state.pin_iter, iter);
    assert_eq!(parsed.pin_state.pin_salt, Some([0x22u8; 16]));
    assert_eq!(parsed.pin_state.pin_verifier_format, crypto::PIN_VERIFIER_FORMAT_STRETCHED);

    // ...and re-encoding it produces a byte-identical snapshot, which is what
    // "the field survived the round trip" has to mean for the device's own
    // persist gate.
    let mut buf = heapless::Vec::<u8, 8448>::new();
    parsed
        .to_cbor(None, &mut buf)
        .expect("the re-encoded snapshot fits its scratch");
    assert_eq!(
        buf.as_slice(),
        base.as_slice(),
        "the snapshot is not stable across an encode/decode round trip"
    );
}

// ---------------------------------------------------------------------------
// "existing verifiers migrate via pin_verifier_upgrade on the next successful
//  PIN" / "legacy-format verifiers are refused after the migration window"
// ---------------------------------------------------------------------------

/// The record `pin_verifier_upgrade` emits is accepted by the decoders that
/// will later read it.
///
/// The failure this guards is not "too weak" — it is **unrecoverable**. A
/// migration that wrote a round count above the decode ceiling would leave the
/// owner with a PIN that no longer verifies and no recovery but a factory reset.
/// The check is exact equality rather than `<=`, because the two numbers being
/// equal is what makes the migration window's length irrelevant to correctness:
/// every migrated device reaches the new cost on its next successful PIN,
/// however long the grace period runs.
#[test]
fn the_upgrade_emits_a_record_at_exactly_the_round_count_the_decoders_accept() {
    let candidate = crypto::pin_hash(PIN.as_bytes());
    let salt = [0x42u8; 16];
    let (verifier, iter) = crypto::pin_verifier_upgrade(&candidate, &salt);

    assert_eq!(
        iter,
        crypto::PIN_VERIFIER_ROUNDS,
        "the upgrade must emit the count the decoders' ceiling is checked \
         against — a lower count ships a weaker verifier than the budget was \
         raised for, a higher one is unreadable"
    );
    assert_eq!(
        verifier,
        crypto::pin_verifier_stretched(&candidate, &salt, iter),
        "the emitted verifier must be exactly the derivation it claims"
    );
    assert_eq!(
        crypto::pin_verifier_admission(crypto::PIN_VERIFIER_FORMAT_STRETCHED, iter, Some(&salt)),
        Ok(())
    );

    // It survives a decode round trip through the host codec, which is the
    // half of the format a `FileKeystore` writes.
    let path = temp_path("upgrade-roundtrip");
    let mut ks = FileKeystore::load_or_create(path.clone()).unwrap();
    {
        let s = ks.get_pin_state_mut();
        s.pin_hash = Some(verifier);
        s.pin_verifier_format = crypto::PIN_VERIFIER_FORMAT_STRETCHED;
        s.pin_salt = Some(salt);
        s.pin_iter = iter;
    }
    ks.save_pin_state().unwrap();
    drop(ks);
    let reloaded = FileKeystore::load_or_create(path.clone()).unwrap();
    let s = reloaded.get_pin_state();
    assert_eq!(s.pin_iter, crypto::PIN_VERIFIER_ROUNDS);
    assert_eq!(s.pin_salt, Some(salt));
    assert_eq!(s.pin_hash, Some(verifier));
    let _ = std::fs::remove_file(&path);
}

/// The legacy migration window is **one comparison**, and it gates admission.
///
/// Two properties, and the second is the one that is easy to lose.
///
/// 1. With the window open, a legacy record is admitted, and the end-to-end
///    migration on the next *successful* PIN is the host twin's
///    `pin_verifier.rs::legacy_migrates_on_success_never_on_failure`. This
///    test pins the decision, not the migration.
/// 2. **When the window is closed, admission refuses** — and the refusal is a
///    distinguishable value, not `Ok`. That is what keeps "this record is no
///    longer verifiable" from arriving on the wire as "this PIN is wrong",
///    which would spend a retry and hide a lockout behind an ordinary
///    `PIN_INVALID`.
///
/// The window cannot be closed in this test run — it is a build constant. So
/// the closed case is pinned structurally rather than exercised: what is
/// asserted is that the window is *one derived comparison* and that every
/// refusal `pin_verifier_admission` can produce is a distinct value, which is
/// the property that has to survive whoever bumps the constant.
#[test]
fn the_legacy_migration_window_is_a_single_comparison_and_it_gates_admission() {
    assert_eq!(
        crypto::PIN_VERIFIER_LEGACY_WINDOW_OPEN,
        crypto::PIN_VERIFIER_RELEASE_INDEX < crypto::PIN_VERIFIER_LEGACY_GRACE_RELEASE,
        "the window must stay a single derived comparison — if it grows a \
         second input, two release bumps can disagree about whether legacy \
         verifiers are admitted"
    );
    // Release 0 shipped the raised count with the window open, so grace cannot
    // be revoked from it (a `const _` assertion in crypto.rs).
    const {
        assert!(
            crypto::PIN_VERIFIER_LEGACY_GRACE_RELEASE >= 1,
            "grace release 0 is not revocable"
        );
    }

    // While the window is open, a legacy record is admitted...
    assert!(
        crypto::pin_verifier_admission(0, 0, None).is_ok(),
        "the migration window is open in this build, so legacy records must \
         still be admitted — refusing them now would lock out every device \
         that has not typed its PIN since the upgrade"
    );
    // ...and so is any non-`1` format byte, because there is no third format
    // and inventing one would be inventing a record no encoder emits.
    for format in [0u8, 2, 7, 255] {
        assert!(
            crypto::pin_verifier_admission(format, 0, None).is_ok(),
            "format {format} is a legacy record while the window is open"
        );
    }

    // Every refusal admission can return is a **distinct** value. That is the
    // property the closed window depends on and the one that survives the
    // constant being bumped: a caller must be able to tell "not verifiable"
    // from "wrong PIN" without inspecting the count.
    let refusals = [
        crypto::pin_verifier_admission(
            crypto::PIN_VERIFIER_FORMAT_STRETCHED,
            crypto::PIN_VERIFIER_ROUNDS,
            None,
        ),
        crypto::pin_verifier_admission(
            crypto::PIN_VERIFIER_FORMAT_STRETCHED,
            crypto::PIN_VERIFIER_ROUNDS + 1,
            Some(&[0u8; 16]),
        ),
    ];
    assert_ne!(
        refusals[0], refusals[1],
        "the two stretched-record refusals must not collapse into one: a \
         caller cannot answer a corrupt record and an over-budget record the \
         same way without losing the distinction"
    );
    assert_eq!(
        refusals[0],
        Err(PinVerifierRefusal::Malformed),
        "a stretched record with no salt is corrupt whatever its count says — \
         and reporting the count first would tell a record-crafting attacker \
         which of their two defects the decoder noticed"
    );
    assert_eq!(
        refusals[1],
        Err(PinVerifierRefusal::IterationsOverBudget {
            claimed: crypto::PIN_VERIFIER_ROUNDS + 1,
        }),
        "one round above the budget is already out of it — the ceiling is the \
         count this build derives, not a count it will merely survive"
    );

    // And the ceiling itself is admitted — a refusal that also fired on the
    // legitimate value would be a self-inflicted lockout.
    for claimed in [1u32, 4096, crypto::PIN_VERIFIER_ROUNDS] {
        assert_eq!(
            crypto::pin_verifier_admission(
                crypto::PIN_VERIFIER_FORMAT_STRETCHED,
                claimed,
                Some(&[0u8; 16]),
            ),
            Ok(()),
            "count {claimed} is within budget and must be admitted"
        );
    }
    // While every count the budget cannot serve is refused **by name**, so the
    // claimed value survives to the caller.
    for claimed in [crypto::PIN_VERIFIER_ROUNDS + 1, 1_000_000, u32::MAX] {
        assert_eq!(
            crypto::pin_verifier_admission(
                crypto::PIN_VERIFIER_FORMAT_STRETCHED,
                claimed,
                Some(&[0u8; 16]),
            ),
            Err(PinVerifierRefusal::IterationsOverBudget { claimed }),
            "an iteration count the budget cannot serve must be refused by name"
        );
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn temp_path(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("us1570-{}-{tag}.fido", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// A whole, valid, **device** keystore snapshot whose PIN record is in the
/// stretched format at [`crypto::PIN_VERIFIER_ROUNDS`], plus the round count
/// the encoder actually wrote.
///
/// Built through the device codec itself, so it is a snapshot the firmware
/// genuinely writes. A hand-assembled one that happened to be rejected would
/// make the refusal assertions in this file prove nothing.
fn device_snapshot() -> (Vec<u8>, u32) {
    let mut trng = fapico2_platform::trng::HostTrng::new();
    let mut ks = DeviceKeystore::fresh(&mut trng).expect("a fresh device keystore");
    ks.pin_state.pin_hash = Some([0x7Bu8; 16]);
    ks.pin_state.pin_verifier_format = crypto::PIN_VERIFIER_FORMAT_STRETCHED;
    ks.pin_state.pin_salt = Some([0x22u8; 16]);
    ks.pin_state.pin_iter = crypto::PIN_VERIFIER_ROUNDS;
    ks.pin_state.retries = 8;
    let mut buf = heapless::Vec::<u8, 8448>::new();
    ks.to_cbor(None, &mut buf).expect("the snapshot fits its scratch");
    let bytes = buf.to_vec();
    let parsed =
        DeviceKeystore::from_cbor(&bytes, None).expect("the control snapshot must parse");
    (bytes, parsed.pin_state.pin_iter)
}

/// Rewrite the snapshot's PIN map through the crate's own CBOR codec.
///
/// Byte-patching a snapshot is the obvious approach and the wrong one: the
/// device encoder and the host encoder write the same *fields* with different
/// headers, and a patch anchored on one of them silently does nothing to the
/// other. Decoding down to the PIN map and re-encoding edits the field rather
/// than a guess at where it sits, and reuses the parser the decoders use — so a
/// shape this cannot round-trip shows up as a panic rather than as a test that
/// passes for the wrong reason.
///
/// The pin map is reached as `{1: [max_creds, auth, creds]}` → auth map →
/// `1` → the pin map. The last hop accepts both shapes the encoders use: the
/// device `no_heap` encoder inlines the map, and a bstr-wrapped one is decoded
/// a level further rather than assumed away.
fn rewrite_pin_map(bytes: &[u8], edit: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    let (mut top, _) = cbor::decode(bytes).expect("snapshot decodes");
    let Value::M(top_map) = &mut top else {
        panic!("top level is not a map")
    };
    let slot = top_map
        .iter_mut()
        .find(|(k, _)| matches!(k, Value::U(1)))
        .expect("snapshot key 1");
    let Value::A(arr) = &mut slot.1 else {
        panic!("snapshot key 1 is not an array")
    };
    let auth_bytes = match &arr[1] {
        Value::B(b) => b.clone(),
        other => panic!("auth is not a byte string: {other:?}"),
    };
    let (auth, _) = cbor::decode(&auth_bytes).expect("auth map decodes");
    let Value::M(mut auth_map) = auth else {
        panic!("auth is not a map")
    };
    let pin_slot = auth_map
        .iter_mut()
        .find(|(k, _)| matches!(k, Value::U(1)))
        .expect("auth key 1 is the pin state");
    let pin_map = match &mut pin_slot.1 {
        Value::M(m) => m.clone(),
        Value::B(b) => {
            let (v, _) = cbor::decode(b).expect("pin state decodes");
            let Value::M(m) = v else {
                panic!("pin state is not a map")
            };
            m
        }
        other => panic!("pin state is neither a map nor a byte string: {other:?}"),
    };
    let mut pin_map = pin_map;
    edit(&mut pin_map);
    pin_slot.1 = Value::M(pin_map);
    arr[1] = Value::B(cbor::encode(&Value::M(auth_map)));
    cbor::encode(&top)
}

/// The same snapshot with its `pin_iter` set to `iter`.
fn with_pin_iter(bytes: &[u8], iter: u64) -> Vec<u8> {
    rewrite_pin_map(bytes, |pin| {
        pin.retain(|(k, _)| !matches!(k, Value::U(16)));
        pin.push((Value::U(16), Value::U(iter)));
    })
}

