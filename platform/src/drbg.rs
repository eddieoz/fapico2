//! US-1002 — HMAC_DRBG (NIST SP 800-90A Rev. 1, §10.1.2) over HMAC-SHA-256.
//!
//! # Why this exists
//!
//! RP2350 hardware entropy is scarce and *eventually* fails: the peripheral's
//! autocorrelation health test can wedge, and every operation that draws
//! directly from it pays that risk (see [`crate::trng::MAX_ENTROPY_POLLS`] for
//! what happens when it does). A deterministic generator fixes the shape of
//! the problem: draw entropy **once**, at a moment we choose, and derive as
//! much as we need from it afterwards. The draw is a full-entropy block; the
//! stretching is what is cheap.
//!
//! # What this is not
//!
//! A DRBG is not an entropy source. It produces bytes that are unpredictable
//! *given* its seed and worthless without it, and it stops being trustworthy
//! once its re-seed budget is spent — which is why [`DrbgError::ReseedRequired`]
//! is an error and not a warning. The house rule in [`crate::trng`] is
//! unchanged by this module: the TRNG remains the only source of entropy.
//!
//! # Shape
//!
//! `no_std`, no `alloc`, fixed-size state: two 32-byte values and a counter,
//! 80 bytes held by value. Nothing here is sized from the request, so
//! `generate` costs one HMAC per 32 output bytes and no more stack than one
//! HMAC context. That matters because `check_async_frame.py` gates the async
//! frame size and a `Drbg` in a stack frame is 80 bytes plus a 256-byte
//! block.
//!
//! # Deliberately absent
//!
//! * **No `additional_input` parameter.** SP 800-90A's `Generate` takes one
//!   and this drops it, which is the `<empty>` case the NIST vectors use: the
//!   `0x01` half of `Update` is skipped and the generator is deterministic
//!   given its state. CTAP2's channel binding would be the only reason to add
//!   it, and there is no call site for CTAP2 to bind to yet.
//! * **No software-PRNG fallback.** A DRBG that has not been seeded does not
//!   silently become something else — see [`seed_from`] and [`SeedSource`]
//!   (US-1003), where failing closed is the whole contract.
//! * **No entropy-length check.** [`MIN_ENTROPY_LEN`] is published so US-1003
//!   can enforce it where the policy belongs, rather than this module guessing
//!   a policy for its caller. [`SeedSource`] pins the seed width at
//!   [`OUTLEN`], so the length half of that rule is structural and
//!   [`crate::drbg_seed`] gates the rest at compile time. The one bound this
//!   module *does* enforce is the re-seed interval, which is a property of
//!   the mechanism rather than a policy question: [`Drbg::new`] clamps it to
//!   [`MAX_RESEED_INTERVAL`].
//!
//! # Seeding (US-1003)
//!
//! A `Drbg` cannot seed itself. [`SeedSource`] is the accessor it asks, once
//! per instantiate and once per re-seed, and the fused implementation lives
//! in [`crate::drbg_seed`]. The rule that shapes the whole design is that
//! **the seed is never stored**: not as a `Drbg` field, not inside the
//! source, not between calls. It is derived from fuses at the moment of use,
//! handed over in a `zeroize`d buffer, and dropped as soon as the generator
//! has absorbed it — so a RAM-disclosure bug finds a derived `Key`/`V` (which
//! is the state a DRBG *is*, and which `Drop` clears) and nothing that
//! regenerates it.
//!
//! # A key is not entropy (C-1)
//!
//! [`SeedMaterial`] carries **two** inputs, and the second one is the whole
//! point. The fuse-derived half is
//! `HKDF(otp_key_1, serial_hash ‖ chipid ‖ boot.entropy.v1)` — and all three
//! of its inputs are constant for the life of the device: the chipid is the
//! public flash UID, the OTP row is a software-readable fuse, and the
//! boot-entropy record is written once and never refreshed. A generator
//! instantiated from that alone is *deterministic across boots*: every warm
//! boot starts in the same state, so the first block of every session repeats
//! the first block of the previous one. Sign two different messages across two
//! boots and the card reuses an ECDSA nonce `k`, which is private-key
//! recovery. That violates the signing roadmap's S-4 (deterministic,
//! **non-repeating** nonces) and the EPIC's Phase 1 outcome (every nonce from
//! a *reseeded* generator), so it is a defect and not a tuning choice.
//!
//! SP 800-90A §10.1.2.3 already has the right shape: `seed_material =
//! entropy_input ‖ nonce`, and `Drbg::new` already concatenates both halves
//! into the same `Update`. The fuse-derived value goes in the first slot as
//! before — it is a *key*, and a key belongs in `entropy_input` — and a fresh
//! full-entropy draw from the peripheral goes in the **nonce** slot. No change
//! to the mechanism is needed for that; it is entirely a call-site change.
//!
//! The draw comes from [`crate::trng::TrngProbe::probe_bytes`], the bounded
//! seam US-1001 added: at most [`crate::trng::MAX_ENTROPY_POLLS`] polls, then
//! [`TrngError::Stalled`]. A peripheral that has wedged therefore costs a
//! **bounded error**, not the unbounded hang Phase 1 exists to prevent — and
//! that error is fatal to seeding, because the fuse seed alone is not an
//! acceptable fallback. Failing closed is the design; see [`SeedError::Trng`].
//!
//! * **Wired (US-1005/US-1006), and the wiring is gated.** The sequencing
//!   concern this note used to raise — route before the KATs are green and
//!   entropy regressions ship — is why the KATs ran first, and they are green.
//!   The device now builds exactly one generator, in
//!   `firmware/src/boot.rs::init_drbg`, and serves the FIDO boot keystore
//!   material, the FIDO and OATH boot RNG pools, and the trussed `Rng`
//!   backend from it.
//!
//!   `tests/scripts/check_rng_path.py` now carries patterns for
//!   `Drbg::new` and `Drbg::new_device` — this paragraph used to claim the
//!   gate enforced "the device path uses `seed_from_device`" when **no
//!   pattern for either name existed**, which made the claim documentary
//!   rather than true. It is true now, and it is a per-flag, count-capped
//!   allowlist: `Drbg::new` is `pub(crate)` so only this crate's own unit
//!   tests reach it, and `Drbg::new_device` is fully `pub`, which is why a
//!   firmware call site passing it a constant — a well-formed generator with
//!   no entropy in it, the one failure mode the whole epic exists to prevent
//!   — needed a pattern of its own.

use core::fmt;

use crate::trng::TrngError;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

/// Output block length `outlen` for HMAC-SHA-256: 256 bits (SP 800-90A
/// Table 2). Everything in the state is this wide.
pub const OUTLEN: usize = 32;

/// Security strength of HMAC-SHA-256 in bits: 128 (SP 800-90A Table 2).
pub const SECURITY_STRENGTH: usize = 128;

/// Minimum entropy, in bytes, for instantiating this mechanism (SP 800-90A
/// Table 2 `min_length` = 128 bits). **Not enforced here** — see the module
/// docs; US-1003 owns the fail-closed policy.
pub const MIN_ENTROPY_LEN: usize = 16;

/// Maximum re-seed interval for HMAC-SHA-256: 2^48 requests (SP 800-90A
/// Table 2). The device value US-1004 picks must be well below this, because
/// a request's worth of a stretched block ages much faster than a request's
/// worth of a hardware draw.
///
/// [`Drbg::new`] clamps to it, so the constant is load-bearing rather than
/// advisory: no `Drbg` in the tree can hold a budget larger than the
/// mechanism is specified to support.
pub const MAX_RESEED_INTERVAL: u64 = 1 << 48;

/// The device's operating re-seed interval (US-1004): 2^8 requests, or 256.
///
/// # The unit of the budget is a *request*, and saying so is the whole claim
///
/// Every re-seed is a **touch of a peripheral that can wedge permanently.**
/// `RNG_ISR.AUTOCORR_ERR` on the RP2350 means the health test failed four
/// times running and, per the peripheral's own documentation, *"RNG ceases
/// functioning until next reset"* — no amount of polling clears it, and
/// nothing in this firmware supplies that reset. The interval is therefore
/// the number of authenticator requests allowed to rest on **one** such
/// touch, and the number that matters to an attacker, a fault injection, or
/// anyone holding a snapshot of the live state is how much output one draw
/// can underwrite.
///
/// US-1004 first wrote the next line as *"at 2^8 × [`OUTLEN`] that is 8 KiB
/// per draw"*. That reads as a per-byte ceiling, and **it is not one** — the
/// code does not implement it, and this is the correction rather than a
/// defence of the old wording. SP 800-90A §10.1.2.5 increments
/// `reseed_counter` by **1 per `Generate` call**, whatever length the caller
/// asked for, and [`Drbg::generate`] takes a slice of any length. So:
///
/// * the budget is **256 requests**, and that is exactly what the counter
///   enforces;
/// * the output one peripheral touch can underwrite is
///   `256 × (bytes per request)`. The *requests* are bounded; the *bytes* are
///   not, and nothing in the tree caps a request;
/// * 8 KiB is what that product evaluates to **only if every request is
///   exactly `OUTLEN`**. No caller in this tree is. The boot path's
///   `fill_rng_pool` draws **8 requests of 64 B**
///   (`apps/fido/src/device_app.rs`, `apps/oath/src/oath_core.rs`), so one
///   pool fill costs 8 of the 256 ticks and returns 512 B, and 256 ticks of
///   that same shape would be 16 KiB.
///
/// Naming the unit is not a retreat from the argument — it is the argument.
/// 2^12 would put 4,096 requests between touches, sixteen times as many, and
/// at the request sizes this tree actually uses sixteen times the output, for
/// no security gain anything here can name. The trade has to be made in the
/// unit the code enforces, and the unit the code enforces is the request.
///
/// ## Why the budget is *not* charged by the byte
///
/// Charging `reseed_counter` in `OUTLEN` blocks rather than requests was
/// considered and rejected. The reasons are recorded so the next reader does
/// not re-propose it as a tidy simplification:
///
/// 1. **It would not close the hole it appears to.** The budget is checked
///    *before* a request is served, so a single request longer than the
///    remaining budget is still served in full and only overshoots
///    afterwards. Per-block charging turns an unbounded aggregate into
///    "`8 KiB + one request`", not into a bound — the doc would still have to
///    carry that qualification, so the change would buy a sentence, not a
///    claim.
/// 2. **It changes what [`MAX_RESEED_INTERVAL`] means.** That constant is
///    documented as SP 800-90A Table 2's 2^48 **requests**; charging blocks
///    makes the same literal a count of blocks, and the mapping back to the
///    standard's table becomes a matter of opinion on a security path.
/// 3. **It halves the reach of a touch on the one hot path there is.** The
///    boot pool fill requests 64 B, so per-block accounting spends 2 ticks
///    per call and covers half as many draws per peripheral touch — the
///    opposite of what the interval exists to do, bought at exactly the
///    availability cost the next section says this value avoids.
///
/// # Why not lower
///
/// Because a *stalled* re-seed is not a degraded token, it is a **dead one**:
/// the generator refuses to serve and stays refusing until the peripheral is
/// reset, which is exactly the fail-closed behaviour the design wants and
/// exactly the availability event an operator dreads. Every crossing is a
/// chance to walk into that, so the interval cannot be driven toward zero
/// just because the *output* window shrinks. 256 sits above the request count
/// of a realistic single session — a CTAP2 or U2F interaction is a handful of
/// operations and a long CCID/OpenPGP session is tens — so a session crosses
/// the bound zero or one times rather than dozens of times. That is the shape
/// wanted: the rare, not the routine.
///
/// The cost of a crossing is also cheap enough to be invisible at the
/// transport layer. A re-seed is one bounded probe (at most
/// [`crate::trng::MAX_ENTROPY_POLLS`] polls), one 32-byte sealed-store read,
/// and one HKDF-Extract/Expand — all small beside a single ECDSA signature on
/// a Cortex-M33, which is milliseconds. At 256 the amortized overhead is a
/// fraction of a percent of signing throughput.
///
/// # This is reasoned, not measured
///
/// **No board was attached when this number was chosen, and it is not
/// dressed up as otherwise.** The two inputs that would turn it into a bound
/// — the stall rate of a real RP2350 TRNG under repeated use, and the
/// request-count distribution of real CTAP2/CCID/OpenPGP sessions — are both
/// unmeasured, and the value is a judgement drawn from them. It is a one-line
/// change, this constant and nothing else, and the tests in
/// `platform/tests/drbg_reseed_policy.rs` are written against the constant
/// rather than the literal, so they follow it.
///
/// # What it does *not* bound (the older, subordinate argument)
///
/// The previous derivation of this number rested on forward extrapolation
/// from a single snapshot of the live `Key`/`V`. That is real but it is now
/// the second-order consideration, because the 256-request window above
/// already bounds that window sixteen times more tightly for free. It is
/// recorded here because it still holds and because a future session that
/// finds the number wrong should know it was not the primary axis.
pub const RESEED_INTERVAL: u64 = 1 << 8;

/// The policy is a choice, not the mechanism's limit. If someone sets
/// `RESEED_INTERVAL` to the ceiling, the clamp in [`Drbg::new`] becomes the
/// policy by accident — which is the failure this story exists to prevent,
/// so it fails at compile time instead of shipping.
const _: () = assert!(
    RESEED_INTERVAL < MAX_RESEED_INTERVAL,
    "the device re-seed interval must be chosen, not defaulted to the ceiling"
);

/// Reasons a [`Drbg`] declines to produce bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrbgError {
    /// `reseed_counter > reseed_interval` (SP 800-90A §10.1.2.5 step 1). The
    /// state is intact but the budget is spent; the caller must re-seed.
    ReseedRequired,
}

impl fmt::Display for DrbgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DrbgError::ReseedRequired => write!(f, "DRBG re-seed required before generating"),
        }
    }
}

/// Why a [`SeedSource`] could not produce seed material.
///
/// The two wrapped error types are kept wrapped rather than flattened into a
/// single "seeding failed", because the caller has to be able to tell the
/// cases apart: an absent record ([`CKeyError::MissingBootEntropy`]) means
/// "this device was never provisioned", a store failure
/// ([`SecureStoreError::Io`]) means "this store cannot be trusted right
/// now", and a caller that conflates them cannot tell a fresh device from a
/// failing one. This is the same shape as [`crate::migration::MigrationError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedError {
    /// The fused derivation refused. `MissingBootEntropy` here is **the**
    /// fail-closed refusal: no seed, and therefore no `Drbg`, without the
    /// record.
    CKey(crate::ckey::CKeyError),
    /// The secure store refused to hand the record over.
    Store(crate::secure_store::SecureStoreError),
    /// The boot-entropy record is present and correctly sized but carries no
    /// entropy — an erased or zeroized slot reading as all-zero. Raised by
    /// [`crate::drbg_seed::FuseSeedSource`], the only source that can see it.
    DepletedBootEntropy,
    /// The fresh draw the seed needs could not be taken: the peripheral did
    /// not produce a validated block within
    /// [`crate::trng::MAX_ENTROPY_POLLS`] polls, and per the RP2350's own
    /// documentation an `AUTOCORR_ERR` "ceases functioning until next reset".
    ///
    /// **This is not a degradation, it is the end of the attempt.** There is
    /// deliberately no path that catches this and instantiates the generator
    /// from the fuse seed alone: that seed is a fixed function of a public
    /// UID, a software-readable fuse row, and a record written once at first
    /// boot, so "falling back" to it would produce a generator that repeats
    /// its first block on every warm boot — the exact nonce-reuse defect
    /// [`SeedMaterial`] exists to close. A device whose peripheral has wedged
    /// is a device that cannot sign until it is reset. That is the correct
    /// outcome and it is the whole contract.
    Trng(TrngError),
}

impl fmt::Display for SeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeedError::CKey(e) => write!(f, "DRBG seed derivation refused: {e:?}"),
            SeedError::Store(e) => write!(f, "DRBG seed source store failure: {e}"),
            SeedError::DepletedBootEntropy => {
                write!(f, "DRBG seed source is present but carries no entropy")
            }
            SeedError::Trng(e) => write!(f, "DRBG seed source drew no fresh entropy: {e}"),
        }
    }
}

impl From<crate::ckey::CKeyError> for SeedError {
    fn from(e: crate::ckey::CKeyError) -> Self {
        SeedError::CKey(e)
    }
}

impl From<crate::migration::MigrationError> for SeedError {
    /// The fused record read reports through `MigrationError`, which wraps
    /// exactly the two types [`SeedError`] wraps. The other `MigrationError`
    /// variants (the migration-class slot overflow) cannot reach this path;
    /// they are mapped to a store failure rather than silently dropped, so a
    /// future call site cannot get a seed it did not earn.
    fn from(e: crate::migration::MigrationError) -> Self {
        match e {
            crate::migration::MigrationError::CKey(e) => SeedError::CKey(e),
            crate::migration::MigrationError::Store(e) => SeedError::Store(e),
            _other => SeedError::Store(crate::secure_store::SecureStoreError::Corrupt),
        }
    }
}

/// Length of the fresh draw a [`SeedSource`] must supply alongside the fused
/// seed, mixed in as the DRBG's `nonce` (§10.1.2.3).
///
/// One full-entropy block, matching [`OUTLEN`] and exceeding the mechanism's
/// [`MIN_ENTROPY_LEN`], because the draw is not stretched before use — it is
/// absorbed verbatim, and it is the only part of `seed_material` that
/// actually carries entropy.
pub const NONCE_LEN: usize = OUTLEN;

/// What a [`SeedSource`] hands back: the fused key material **and** a fresh
/// draw for the nonce slot. One return value, because one of the two being
/// absent is always a refusal — the generator is either correctly
/// instantiated or it does not exist.
///
/// The two halves are deliberately different in kind and the split is the
/// security argument:
///
/// * [`SeedMaterial::seed`] is a **key**. It is derived from the OTP row, the
///   chipid and the boot-entropy record, all three of which are constant for
///   the life of the device, so it is perfectly reproducible and would be a
///   catastrophic seed on its own. Its job is to bind the generator to *this
///   board*: a leaked OTP row must not reconstruct another device's keystream.
/// * [`SeedMaterial::nonce`] is the **entropy**. It is drawn from the
///   peripheral at the moment of use, never stored, and never repeated. Its
///   job is to make the generator's state unrepeatable across boots — which
///   is what stops a warm boot from replaying the previous boot's first nonce
///   (S-4).
///
/// [`Drbg::new`] concatenates the two exactly as §10.1.2.3 specifies
/// (`seed_material = entropy_input ‖ nonce`), so mixing a fresh draw in costs
/// no change to the mechanism.
pub struct SeedMaterial {
    /// The fuse-derived half, in `entropy_input`.
    pub seed: Zeroizing<[u8; OUTLEN]>,
    /// The fresh draw, in `nonce`.
    pub nonce: Zeroizing<[u8; NONCE_LEN]>,
}

impl SeedMaterial {
    /// `seed_material = entropy_input ‖ nonce` (§10.1.2.3) as the two pieces
    /// it is, with no concatenated buffer on the stack.
    ///
    /// `pub` because a caller that wants to *inspect* what a source handed
    /// back — a test, or a caller with its own instantiation to drive — must
    /// be able to see both halves, and hiding them would only move the same
    /// inspection somewhere less honest.
    pub fn halves(&self) -> (&[u8], &[u8]) {
        (&self.seed[..], &self.nonce[..])
    }
}

/// A source of DRBG seed material, consulted **at the moment of seeding**.
///
/// # Why a trait and not a stored value
///
/// The EPIC's Phase 1 header is explicit: an HMAC-DRBG concentrates the
/// device's forward randomness behind a small amount of live state, so "the
/// DRBG is seeded from fuses **on demand**, never stored, and the seed
/// buffers are `zeroize`d". RS-Key's `FusedKey = fn() -> Option<[u8; 32]>`
/// closure is the reference shape, and its reason is worth repeating
/// because it is the whole security argument: *"a bug that discloses
/// adjacent memory has nothing to disclose — the OTP window is not RAM."*
///
/// A `Drbg` therefore holds **no** source and **no** seed: a field of either
/// kind would put the generator's key schedule in RAM for the life of the
/// object, which is precisely the state a RAM-disclosure bug is after. What
/// a `Drbg` holds is the *derived* `Key`/`V`, which is what a DRBG *is*, and
/// which [`Drbg::wipe`] and `Drop` already clear.
///
/// # What an implementation owes its caller
///
/// * Read the material **now**, every time. A source that caches its seed
///   defeats the only thing this trait is for; the read is also what makes
///   the boot-entropy record's absence detectable at seed time rather than
///   silently inherited from an earlier boot.
/// * Draw a **fresh** [`NONCE_LEN`]-byte block every call, from the hardware
///   peripheral, and return it as [`SeedMaterial::nonce`]. A source that
///   returns a constant — or reuses the previous call's draw — reinstates the
///   cross-boot nonce repetition this design exists to prevent, and no test
///   downstream can tell, because a deterministic generator looks perfectly
///   healthy right up until it repeats.
/// * Take the draw through the **bounded** seam
///   ([`crate::trng::TrngProbe::probe_bytes`]) and refuse with
///   [`SeedError::Trng`] on a stall. There is no "serve from the fuse seed
///   anyway" branch; see that variant.
/// * Return both halves in [`zeroize::Zeroizing`] buffers and keep no copy.
///   The caller drops them as soon as the generator has absorbed them; the
///   source must not be the thing that keeps them alive.
/// * Never log either half, and never derive one from fewer than
///   [`MIN_ENTROPY_LEN`] bytes of real entropy.
pub trait SeedSource {
    /// Produce the seed **and** the fresh draw for the next instantiate or
    /// re-seed.
    fn seed(&mut self) -> Result<SeedMaterial, SeedError>;
}

/// `&mut S` is a [`SeedSource`] whenever `S` is, so a caller can hand a
/// borrow to [`Drbg::seed_from`] without giving up its own access — which is
/// how the tests observe how many times a generator consulted its source.
impl<S: SeedSource + ?Sized> SeedSource for &mut S {
    fn seed(&mut self) -> Result<SeedMaterial, SeedError> {
        (**self).seed()
    }
}

/// HMAC-DRBG over HMAC-SHA-256, `no_std` and allocation-free.
///
/// The working state is `Key` and `V` (§10.1.2.1) plus a re-seed counter. The
/// secret parts are zeroized by [`Drbg::wipe`] and, unconditionally, by `Drop`.
pub struct Drbg {
    /// The HMAC key. Secret.
    k: [u8; OUTLEN],
    /// The chaining value. Secret.
    v: [u8; OUTLEN],
    reseed_counter: u64,
    reseed_interval: u64,
}

impl Drbg {
    /// Instantiate (§10.1.2.3): `seed_material = entropy_input || nonce`, one
    /// `Update`, and `reseed_counter = 1`.
    ///
    /// `entropy` should carry at least [`MIN_ENTROPY_LEN`] bytes of hardware
    /// entropy; the caller owns that policy.
    ///
    /// `reseed_interval` is clamped to [`MAX_RESEED_INTERVAL`], so a caller
    /// cannot build a generator whose budget exceeds what the mechanism is
    /// specified to support. `MIN_ENTROPY_LEN` is deliberately *not* enforced
    /// here — see the module docs.
    ///
    /// # `pub(crate)`, and why that is only a start (I-3)
    ///
    /// This is the unvalidated raw constructor: `Drbg::new(&[0u8; 32], &[],
    /// n)` builds a working generator from a constant. Narrowing it to the
    /// crate keeps the *external* door shut, and it is the shape the crate's
    /// own KATs need, so the cost is zero.
    ///
    /// It does **not** close the hole on its own, and pretending otherwise
    /// would be worse than not trying. [`Drbg::new_device`] is a public
    /// pass-through to exactly this function, and an external test crate
    /// needs `new_device` too, so the invariant is not expressible as a
    /// visibility rule alone.
    ///
    /// What enforces the rule is US-1005's `check_rng_path.py` gate, which
    /// **does** now carry patterns for both constructor names — the earlier
    /// version of this comment said the gate "is not in this pass" and that
    /// the rule was documentary, and it was: the gate had landed with no
    /// pattern for `Drbg::new` or `Drbg::new_device` at all. The rule is
    /// enforced now, in both directions, by a per-flag count-capped
    /// allowlist: **the device path goes through
    /// [`Drbg::seed_from_device`], never through here or through
    /// `new_device`.**
    pub(crate) fn new(entropy: &[u8], nonce: &[u8], reseed_interval: u64) -> Self {
        let mut d = Self {
            k: [0u8; OUTLEN],
            v: [0x01u8; OUTLEN],
            reseed_counter: 0,
            reseed_interval: reseed_interval.min(MAX_RESEED_INTERVAL),
        };
        d.update_seeded(entropy, nonce);
        d.reseed_counter = 1;
        d
    }

    /// Re-seed (§10.1.2.4): one `Update` over `entropy_input || additional_input`
    /// and `reseed_counter = 1`. There is no `additional_input` — see the
    /// module docs.
    ///
    /// The raw re-seed takes no `additional_input` because SP 800-90A's
    /// §10.1.2.4 re-seed puts `seed_material` in the *first* slot. The
    /// on-demand device path needs a fresh draw mixed in, and it is therefore
    /// a different function: [`Drbg::reseed_from`], which supplies both
    /// halves. This one exists for the KATs and for a caller that already
    /// holds full-entropy material of its own.
    pub fn reseed(&mut self, entropy: &[u8]) {
        self.reseed_seeded(entropy, &[]);
    }

    /// Generate (§10.1.2.5) `out.len()` bytes, the leftmost bits of `temp`.
    ///
    /// An empty `out` is **not** a no-op: §10.1.2.5 has no early return, so
    /// the trailing `Update` and the counter increment still happen. That
    /// follows the standard rather than second-guessing it, and it is why an
    /// empty request is not free.
    pub fn generate(&mut self, out: &mut [u8]) -> Result<(), DrbgError> {
        if self.reseed_counter > self.reseed_interval {
            return Err(DrbgError::ReseedRequired);
        }

        let mut written = 0;
        while written < out.len() {
            let next = hmac(&self.k, &[&self.v]);
            self.v = next;
            let take = core::cmp::min(OUTLEN, out.len() - written);
            out[written..written + take].copy_from_slice(&self.v[..take]);
            written += take;
        }

        self.update(&[]);
        self.reseed_counter += 1;
        Ok(())
    }

    /// US-1004: instantiate on the device's re-seed policy
    /// ([`RESEED_INTERVAL`]) rather than a caller's guess.
    ///
    /// This exists so that forgetting the policy is not possible to do
    /// quietly. [`Drbg::new`] accepts any interval and clamps it to
    /// [`MAX_RESEED_INTERVAL`], so a caller who passes `u64::MAX` as a
    /// "never re-seed" sentinel gets a 2^48-request budget that no test
    /// would object to and no reviewer would necessarily read past. The
    /// argument here is a raw block rather than a [`SeedSource`] only so the
    /// construction costs one HKDF and nothing else; the fused path has its
    /// own entry point, below.
    ///
    /// **It accepts caller-supplied entropy and so does not enforce the
    /// fail-closed policy.** It is the KAT/host constructor. The device path
    /// is [`Drbg::seed_from_device`] — see the note on [`Drbg::new`].
    pub fn new_device(entropy: &[u8], nonce: &[u8]) -> Self {
        Self::new(entropy, nonce, RESEED_INTERVAL)
    }

    /// US-1004: [`Drbg::seed_from`] on the device's re-seed policy
    /// ([`RESEED_INTERVAL`]).
    ///
    /// [`Drbg::seed_from`] takes any interval and clamps it, exactly like
    /// [`Drbg::new`], so a caller that reaches for it by name is handed a
    /// default nobody chose. This is the constructor the fused path should
    /// use, and the only one that makes the policy unskippable there.
    pub fn seed_from_device<S: SeedSource>(source: &mut S) -> Result<Self, SeedError> {
        Self::seed_from(source, RESEED_INTERVAL)
    }

    /// The re-seed budget this generator is actually running with, after
    /// [`Drbg::new`]'s clamp. The policy test reads it rather than assuming
    /// `RESEED_INTERVAL` survived construction.
    pub fn reseed_interval(&self) -> u64 {
        self.reseed_interval
    }

    /// Requests made since instantiation or the last re-seed.
    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }

    /// US-1003: instantiate from `source` — the fused seed **plus a fresh
    /// draw** — and no generator at all if the source refuses.
    ///
    /// The two halves land in the two slots §10.1.2.3 defines: the
    /// fuse-derived key in `entropy_input`, the peripheral draw in `nonce`.
    /// Both are absorbed by the same `Update`, so the resulting `Key`/`V`
    /// is unrepeatable across boots — the property the whole seeding design
    /// exists to provide, and the one the fuse half alone cannot.
    ///
    /// `Ok(Err(_))` is the only honest answer to a missing or corrupt
    /// boot-entropy record **or a peripheral that will not produce a
    /// block**. There is deliberately no constructor that takes the OTP row
    /// alone: that seed is computable by anyone holding a leaked row, which
    /// is the whole reason the record exists.
    pub fn seed_from<S: SeedSource>(
        source: &mut S,
        reseed_interval: u64,
    ) -> Result<Self, SeedError> {
        let material = source.seed()?;
        let (entropy, nonce) = material.halves();
        Ok(Self::new(entropy, nonce, reseed_interval))
    }

    /// US-1003: re-seed from `source` (§10.1.2.4), the same way
    /// [`Drbg::seed_from`] instantiated — including a **fresh** draw on
    /// every call, not just at instantiate.
    ///
    /// That second draw is what makes the re-seed worth performing. Re-seeding
    /// from the fuse half alone returns the *same* seed every time, which
    /// re-anchors the counter and buys nothing an attacker does not already
    /// have; with a fresh draw in the nonce slot the generator's state
    /// genuinely moves.
    ///
    /// **Atomic on refusal.** The material is taken before any state is
    /// touched, so an `Err` leaves the generator bit-for-bit as it was —
    /// including at exhaustion, where it stays refusing to generate. A
    /// re-seed that half-applied would leave a generator that is neither the
    /// old one nor a correctly seeded one, and at exhaustion it would be one
    /// that silently reopened a spent budget.
    pub fn reseed_from<S: SeedSource>(&mut self, source: &mut S) -> Result<(), SeedError> {
        let material = source.seed()?;
        let (entropy, nonce) = material.halves();
        self.reseed_seeded(entropy, nonce);
        Ok(())
    }

    /// Zero the secret state. Called by `Drop`; exposed so a caller that is
    /// about to hand the storage to something less trusted than a function
    /// return can do it at a point it chooses.
    ///
    /// `reseed_counter` and `reseed_interval` are deliberately left alone:
    /// they are not secret, and zeroing them would make a wiped generator
    /// indistinguishable from a fresh one to a later reader of the same
    /// memory.
    pub fn wipe(&mut self) {
        self.k.zeroize();
        self.v.zeroize();
    }

    /// The `Update` function (§10.1.2.2) with `provided_data` as one slice.
    fn update(&mut self, provided_data: &[u8]) {
        self.update_seeded(provided_data, &[]);
    }

    /// Re-seed with `seed_material` held as two pieces, so the on-demand path
    /// (fuse key ‖ fresh draw) needs no concatenated buffer on the stack.
    /// Shared by [`Drbg::reseed`] — which passes an empty second half — and
    /// [`Drbg::reseed_from`], so the counter arithmetic lives in one place.
    fn reseed_seeded(&mut self, first: &[u8], second: &[u8]) {
        self.update_seeded(first, second);
        self.reseed_counter = 1;
    }

    /// `Update` where the caller holds `provided_data` as two adjacent pieces.
    ///
    /// The standard only ever builds `provided_data` as a concatenation —
    /// `entropy_input || nonce` on instantiate, `entropy_input ||
    /// additional_input` on reseed — so two slices cover every call site and
    /// no seed buffer has to live on the stack.
    fn update_seeded(&mut self, first: &[u8], second: &[u8]) {
        const TAG_0: [u8; 1] = [0x00];
        const TAG_1: [u8; 1] = [0x01];

        self.k = hmac(&self.k, &[&self.v, &TAG_0, first, second]);
        self.v = hmac(&self.k, &[&self.v]);
        // Step 3: `provided_data = Null` returns after the 0x00 half. This is
        // not an optimisation — skipping it is what the NIST vectors do for
        // the post-generate `Update`, and a generator that always runs both
        // halves diverges from them.
        if first.is_empty() && second.is_empty() {
            return;
        }
        self.k = hmac(&self.k, &[&self.v, &TAG_1, first, second]);
        self.v = hmac(&self.k, &[&self.v]);
    }
}

impl Drop for Drbg {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl fmt::Debug for Drbg {
    /// Deliberately opaque: `Key` and `V` are secret, and a `Debug` that
    /// printed them would undo `wipe()` in any log line that ever reached a
    /// host.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Drbg")
            .field("reseed_counter", &self.reseed_counter)
            .field("reseed_interval", &self.reseed_interval)
            .finish_non_exhaustive()
    }
}

/// `HMAC(key, parts[0] || parts[1] || …)` — the keyed hash the whole
/// mechanism is built from (FIPS 198).
fn hmac(key: &[u8; OUTLEN], parts: &[&[u8]]) -> [u8; OUTLEN] {
    let mut m = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts a key of any length; a 32-byte key is in range");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // KAT provenance
    // ------------------------------------------------------------------
    //
    // Every constant below is a verbatim value from NIST's published
    // HMAC_DRBG example document, titled "HMAC_DRBG", linked from SP 800-90A
    // Rev. 1 (June 2015) §10: *"Examples for determining correct
    // implementation of each DRBG are available at
    // http://csrc.nist.gov/groups/ST/toolkit/examples.html"*.
    //
    //   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_DRBG.pdf
    //   sha256 4bf9cf3b23727f33db320a5eb158807ca9b573860e0a00b733f2c3124a1b2bb2
    //
    // The document carries a full KAT trace per (security strength, hash,
    // prediction-resistance) combination. The values used here are the
    // `Requested Security Strength = 128` / `Requested Hash Algorithm =
    // SHA-256` traces, and they come from two of them:
    //
    // * `prediction_resistance_flag = "NOT ENABLED"` — PDF pages 148-153.
    //   `HMAC_DRBG_Instantiate_algorithm` (p148) gives the instantiate `Key`
    //   and `V`; the two `HMAC_DRBG_Generate` calls of 512 bits (p150-151,
    //   p152-153) give tests (1) and (2).
    // * `prediction_resistance_flag = "ENABLED"` — PDF pages 180-186. Its
    //   *first* `HMAC_DRBG_Generate` (p183) deliberately reports
    //   "Generate FAILED: Reseed is required", which leaves the state at the
    //   instantiate values; `HMAC_DRBG_Reseed_algorithm` (p183-185) then
    //   reseeds with `EntropyInput1`, and the `HMAC_DRBG_Generate` on p185
    //   gives test (3). That is why test (3) reseeds a *freshly
    //   instantiated* generator rather than the post-generate one — reseeding
    //   after the two generates in test (2) does not reproduce these values,
    //   because NIST's trace never did the generates first.
    //
    // Two details that look like mistakes and are not, and that a future
    // reader must not "fix":
    //
    // * The nonce `20 21 22 23 24 25 26 27` is a *substring* of the entropy
    //   input `00 01 … 36`. That overlap is NIST's, verbatim.
    // * `EntropyInput` and `EntropyInput1` are 55 bytes each, not 32. The
    //   security strength is 128 bits; the 55 bytes are simply the trace's
    //   chosen input, and the mechanism consumes all of them.

    /// NIST's `EntropyInput` for the SHA-256 / 128-bit traces: the 55 bytes
    /// `0x00..=0x36`.
    fn entropy() -> [u8; 55] {
        let mut out = [0u8; 55];
        for (i, b) in out.iter_mut().enumerate() {
            *b = i as u8;
        }
        out
    }

    /// NIST's `EntropyInput1` (the re-seed input): the 55 bytes `0x80..=0xB6`.
    fn reseed_entropy() -> [u8; 55] {
        let mut out = [0u8; 55];
        for (i, b) in out.iter_mut().enumerate() {
            *b = 0x80 + i as u8;
        }
        out
    }

    /// NIST's `Nonce`: the 8 bytes `0x20..=0x27`.
    fn nonce() -> [u8; 8] {
        [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27]
    }

    /// Hex string → `[u8; N]`, with the length pinned by the type.
    ///
    /// Const-generic over the output size so every KAT literal states its own
    /// length in its type: a truncated or doubled paste becomes a compile
    /// error here rather than a silently wrong comparison below. No `Vec` —
    /// the `no alloc in platform/src/` rule applies to test code too.
    fn h<const N: usize>(s: &str) -> [u8; N] {
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), N * 2, "hex literal has the wrong length");
        let mut out = [0u8; N];
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = (bytes[2 * i] as char)
                .to_digit(16)
                .expect("KAT literals are hex") as u8;
            let lo = (bytes[2 * i + 1] as char)
                .to_digit(16)
                .expect("KAT literals are hex") as u8;
            *slot = (hi << 4) | lo;
        }
        out
    }

    /// A fresh DRBG over NIST's published instantiate inputs, with the
    /// reseed interval at the standard's maximum so the KAT generates run.
    fn kat_drbg() -> Drbg {
        Drbg::new(&entropy(), &nonce(), MAX_RESEED_INTERVAL)
    }

    /// (1) **Instantiate KAT.** NIST's `HMAC_DRBG_Instantiate_algorithm` trace
    /// for SHA-256 / 128-bit strength, prediction resistance disabled
    /// (`HMAC_DRBG.pdf` p148), after the single `Update` over
    /// `seed_material = entropy_input || nonce` (personalization string empty).
    /// An exact byte match — not "looks random".
    #[test]
    fn kat_instantiate_matches_the_published_trace() {
        let d = kat_drbg();
        assert_eq!(
            d.k,
            h::<32>("3DDA543E7EEF14F936237BE65D094B4DDC969C0B2B5EAFB5D805E86CFA64D741"),
        );
        assert_eq!(
            d.v,
            h::<32>("2D02C2F822517D54B817279A59491C41A1989B3E382DEBE80D2C7F660F4476C4"),
        );
        assert_eq!(d.reseed_counter(), 1, "instantiate sets reseed_counter = 1");
    }

    /// (2) **Generate KAT.** Two consecutive 512-bit requests (`HMAC_DRBG.pdf`
    /// p150-151 and p152-153). `additional_input` is empty, so the trailing
    /// `0x01` half of `Update` is skipped — that branch is exactly where a
    /// plausible-looking implementation diverges, so the second vector is what
    /// proves it is right.
    #[test]
    fn kat_generate_matches_the_published_trace() {
        let mut d = kat_drbg();

        let mut first = [0u8; 64];
        d.generate(&mut first).unwrap();
        assert_eq!(
            first,
            h::<64>(concat!(
                "D67B8C1734F46FA3F763CF57C6F9F4F2DC1089BD8BC1F6F023950BFC56176352",
                "08C8501238AD7A4400DEFEE46C640B61AF77C2D1A3BFAA90EDE5D207406E5403"
            )),
        );

        let mut second = [0u8; 64];
        d.generate(&mut second).unwrap();
        assert_eq!(
            second,
            h::<64>(concat!(
                "8FDAEC20F8B421407059E3588920DA7EDA9DCE3CF8274DFA1C59C108C1D0AA9B",
                "0FA38DA5C792037C4D33CD070CA7CD0C5608DBA8B885654639DE2187B74CB263"
            )),
        );
        assert_eq!(d.reseed_counter(), 3, "two generates advance the counter twice");
    }

    /// (3) **Reseed KAT.** Re-seeding a *freshly instantiated* generator with
    /// NIST's `EntropyInput1` (`HMAC_DRBG.pdf` p183-185, the
    /// prediction-resistance-enabled trace whose first Generate fails and so
    /// reseeds the untouched instantiate state), plus the 512-bit request that
    /// follows it on p185.
    #[test]
    fn kat_reseed_matches_the_published_trace() {
        let mut d = kat_drbg();
        d.reseed(&reseed_entropy());

        assert_eq!(
            d.k,
            h::<32>("B84007E3E27F34F9A7820B7AB59BBEFCD0C4ACAEDE4B0B36B147B89779FD749D"),
        );
        assert_eq!(
            d.v,
            h::<32>("A72B8FEE92392F0A9D2D61BF09A4DFCC9DE69A16A5F150224C3EF6042D1521FC"),
        );

        let mut out = [0u8; 64];
        d.generate(&mut out).unwrap();
        assert_eq!(
            out,
            h::<64>(concat!(
                "FABD0AE25C69DC2EFDEFB7F20C5A31B57AC938AB771AA19BF8F5F1468F665C93",
                "8C9A1A5DF0628A5690F15A1AD8A613F31BBD65EEAD5457D5D26947F29FE91AA7"
            )),
        );
    }

    /// (4) The `leftmost(temp, requested)` rule: a shorter request is a
    /// **prefix** of a longer one from the same state, not a re-derivation.
    /// Two independent instantiations so neither has advanced.
    #[test]
    fn a_shorter_request_is_the_prefix_of_a_longer_one() {
        let mut short_drbg = kat_drbg();
        let mut short = [0u8; 32];
        short_drbg.generate(&mut short).unwrap();

        let mut long_drbg = kat_drbg();
        let mut long = [0u8; 64];
        long_drbg.generate(&mut long).unwrap();

        assert_eq!(short, long[..32]);
    }

    /// (5) The re-seed boundary is the standard's `reseed_counter >
    /// reseed_interval` — **strictly** greater, so a counter sitting exactly on
    /// the interval is still allowed to generate.
    #[test]
    fn the_reseed_boundary_is_strictly_greater_than() {
        let mut d = Drbg::new(&entropy(), &nonce(), 1);
        let mut buf = [0u8; 32];

        // reseed_counter == 1 == reseed_interval: allowed.
        assert_eq!(d.generate(&mut buf), Ok(()));
        // reseed_counter == 2 > 1: refused, and the counter does not move.
        assert_eq!(d.generate(&mut buf), Err(DrbgError::ReseedRequired));
        assert_eq!(d.reseed_counter(), 2, "a refusal must not consume budget");

        // A reseed puts the counter back to 1 and generation works again.
        d.reseed(&reseed_entropy());
        assert_eq!(d.reseed_counter(), 1);
        assert_eq!(d.generate(&mut buf), Ok(()));
    }

    /// (6) An interval of 0 refuses the very first request. The device policy
    /// for "never serve from an exhausted generator" is US-1003's; this only
    /// pins that the counter arithmetic fails closed rather than defaulting to
    /// "generate anyway".
    #[test]
    fn a_zero_interval_refuses_the_first_request() {
        let mut d = Drbg::new(&entropy(), &nonce(), 0);
        let mut buf = [0u8; 32];
        assert_eq!(d.generate(&mut buf), Err(DrbgError::ReseedRequired));
    }

    /// (7) An empty request still spends budget, because §10.1.2.5 has no early
    /// return. Documented on `generate`; pinned here so the documentation
    /// cannot quietly drift away from the code.
    #[test]
    fn an_empty_request_still_advances_the_counter() {
        let mut d = kat_drbg();
        assert_eq!(d.generate(&mut []), Ok(()));
        assert_eq!(d.reseed_counter(), 2, "the trailing Update and ++ always run");
    }

    /// (8) `new` clamps the interval to [`MAX_RESEED_INTERVAL`], so the
    /// published constant is load-bearing. Without the clamp this test is
    /// trivially false for any request above 2^48 — including `u64::MAX`,
    /// which a careless caller reaches for as a "no reseeding" sentinel.
    ///
    /// `MIN_ENTROPY_LEN` is *not* pinned here: fail-closed on a short seed is
    /// US-1003's contract, and this module publishing the constant is the
    /// whole of its share of that work.
    #[test]
    fn the_reseed_interval_is_clamped_to_the_maximum() {
        let d = Drbg::new(&entropy(), &nonce(), u64::MAX);
        assert_eq!(d.reseed_interval, MAX_RESEED_INTERVAL);

        // Exactly at the ceiling is not clamped, so the KATs' own interval is
        // preserved rather than coincidentally passing.
        let at_ceiling = Drbg::new(&entropy(), &nonce(), MAX_RESEED_INTERVAL);
        assert_eq!(at_ceiling.reseed_interval, MAX_RESEED_INTERVAL);

        // Below the ceiling is passed through untouched.
        let below = Drbg::new(&entropy(), &nonce(), 7);
        assert_eq!(below.reseed_interval, 7);
    }

    /// (9) `wipe()` leaves no key material behind.
    #[test]
    fn wipe_zeroizes_the_key_material() {
        let mut d = kat_drbg();
        assert_ne!(d.k, [0u8; OUTLEN], "precondition: K must be non-zero");

        d.wipe();

        assert_eq!(d.k, [0u8; OUTLEN], "wipe must zero Key");
        assert_eq!(d.v, [0u8; OUTLEN], "wipe must zero V");
    }

    /// (10) ...and `Drop` does it without the caller remembering. A `Drbg` that
    /// goes out of scope on a stack frame the compiler can see through would
    /// otherwise keep its key material in dead memory until the frame is
    /// reused.
    #[test]
    fn drop_zeroizes_the_key_material() {
        let mut d = core::mem::ManuallyDrop::new(kat_drbg());
        let ptr: *mut Drbg = &mut *d;

        // SAFETY: exactly one `drop_in_place` call on `ptr`, after which the
        // storage is only *read* — never used again, never freed. `Drbg` is an
        // aggregate of arrays and `u64`s, so every bit pattern is a valid
        // value and reading the fields after the drop is well defined.
        unsafe { core::ptr::drop_in_place(ptr) };

        let dead: &Drbg = unsafe { &*ptr };
        assert_eq!(dead.k, [0u8; OUTLEN], "Drop must zero Key");
        assert_eq!(dead.v, [0u8; OUTLEN], "Drop must zero V");
    }
}
