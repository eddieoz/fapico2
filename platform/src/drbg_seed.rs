//! US-1003 — the fused seed source: where a [`Drbg`]'s seed actually
//! comes from, and the only place that decides whether there is one.
//!
//! [`crate::drbg`] owns the mechanism and deliberately knows nothing about
//! storage; this module is the other half. It binds the three inputs a
//! generator's **key** needs —
//!
//! | input | where it comes from | why it is there |
//! |---|---|---|
//! | `otp_key_1` | OTP key row (fuses) | the only key material a device has before provisioning |
//! | flash UID | on-flash chip identity | so a leaked OTP row does not reconstruct another board |
//! | `boot.entropy.v1` | the AEAD-sealed secure store | so a leaked OTP row does not reconstruct *this* board |
//!
//! — through [`ckey::derive_drbg_seed`], the same HKDF shape and the same
//! fail-closed policy as the bound device root.
//!
//! # A key is not entropy: the fresh draw (C-1)
//!
//! All three of those inputs are **constant for the life of the device**. The
//! chipid is the public flash UID. The OTP row is software-readable from any
//! code on the board. The boot-entropy record is written once by
//! `firmware::boot::ensure_boot_entropy` on first boot and is never refreshed
//! — and per this project's AGENTS.md a reflash does not clear the NOR store,
//! so a warm boot re-derives the identical value.
//!
//! A generator instantiated from those three alone is therefore
//! **deterministic across boots**: every warm boot starts in the same state,
//! so the first block of every session repeats the first block of the
//! previous one. Sign two different messages across two boots and the card
//! reuses an ECDSA nonce `k` — that is private-key recovery. This is not a
//! tuning question; it violates the signing roadmap's S-4 ("deterministic,
//! **non-repeating** nonces") and the EPIC's Phase 1 outcome (every nonce
//! from a *reseeded* generator).
//!
//! So this source also holds a [`TrngProbe`] and draws a **fresh**
//! [`NONCE_LEN`]-byte block on **every** call — at instantiate and at every
//! re-seed. SP 800-90A §10.1.2.3 already has the right shape
//! (`seed_material = entropy_input ‖ nonce`) and [`Drbg::new`] already
//! concatenates both halves into the same `Update`; the fuse-derived value
//! stays in the first slot (it is a *key*, and a key belongs in
//! `entropy_input`) and the draw goes in the second. No change to the
//! mechanism was needed — this is a call-site change, and the reason the
//! defect stayed latent until US-1005 is that the routing was not wired
//! until then; it is called now (see "Wired" below).
//!
//! The draw is taken through [`TrngProbe::probe_bytes`], the bounded seam
//! US-1001 added: the wait ends on a wall-clock budget
//! ([`MAX_ENTROPY_WAIT`], 20 ms — 10x the datasheet's ~2 ms average
//! generation time for this configuration) or on the independent hard cap
//! ([`MAX_ENTROPY_POLLS`]), whichever comes first, and a partial fill is an
//! error rather than a short success. A wedged peripheral costs a **bounded
//! error** rather than the unbounded hang Phase 1 exists to prevent, and that
//! error is fatal to seeding — see "no fallback" below.
//!
//! # On demand, and never stored
//!
//! Every [`SeedSource::seed`] call re-reads the record from the store. There
//! is no cached copy anywhere: not in this struct, not in the [`Drbg`] it
//! seeds, not between calls. That is the EPIC's binding constraint — *"the
//! DRBG is seeded from fuses **on demand**, never stored, and the seed
//! buffers are `zeroize`d"* — and it is also what makes a deleted record
//! *detectable* rather than silently inherited from a previous boot. The
//! derived seed and the draw are handed back in [`Zeroizing`] buffers that
//! the caller drops as soon as the generator has absorbed them.
//!
//! # Fail-closed, with the refusals kept apart
//!
//! Four refusals, four distinct errors, and the difference is what a
//! caller does next:
//!
//! * **no record** → [`CKeyError::MissingBootEntropy`]. The device was never
//!   provisioned. There is no fallback to the OTP row alone: that seed is
//!   computable by anyone holding a leaked row, which is the entire reason
//!   the record exists (the US-918 policy, unchanged).
//! * **wrong-length record** → [`CKeyError::BadLength`]. Corrupt media. It
//!   is never padded up to [`ckey::BOOT_ENTROPY_LEN`].
//! * **present but all-zero** → [`SeedError::DepletedBootEntropy`]. An
//!   erased or zeroized slot. The length is right, so the US-918 length
//!   rules wave it through, and it is the case that would otherwise be the
//!   worst of the three: a *known-constant* key, producing a keystream any
//!   attacker can compute without touching the device. Refusing it is the
//!   difference between "absent" and "worse than absent". (The invariant is
//!   duplicated inside [`ckey::derive_drbg_seed`] as
//!   [`CKeyError::DepletedBootEntropy`], so a direct caller of the
//!   derivation cannot bypass it either.)
//! * **the peripheral wedged** → [`SeedError::Trng`]. No validated block
//!   within the wait budget ([`MAX_ENTROPY_WAIT`]) or the hard poll cap
//!   ([`MAX_ENTROPY_POLLS`]), and the RP2350 says the RNG "ceases
//!   functioning until next reset". **The fuse seed is not an acceptable
//!   fallback here.** It is not a degraded substitute, it is *the defect*:
//!   serving from it produces exactly the cross-boot nonce repetition this
//!   module's draw exists to prevent. So a wedged peripheral is a device
//!   that cannot sign until it is reset. Fail-closed, and correct.
//!
//! Store failures stay wrapped too, so "this store cannot be
//! read right now" never reads as "this device is new".
//!
//! The refusals are ordered so that the cheap, in-process ones run *before*
//! the peripheral is touched: a short UID, an absent record or a store I/O
//! failure must not spend a probe budget, let alone a wedge.
//!
//! # Wired (US-1005 / US-1006)
//!
//! This is on the device's boot path now. `firmware::boot::init_drbg` builds
//! the one [`crate::trng::DrbgTrng`] from a [`FuseSeedSource`] over the OTP
//! row, the chip id, the secure store and a `crate::trng::Rp2350Probe`, and a
//! seed refusal there is **fatal by design** — there is deliberately no
//! fallback, because the fallback (deriving the seed from the fuses alone) *is*
//! the cross-boot nonce-repetition defect this module exists to close.
//! `platform::trusted_backend::device::Rp2350Rng` serves the trussed `Rng`
//! from that generator, and the US-1004 re-seed re-reads the record and takes
//! a fresh draw on that path too.
//!
//! One correction to an earlier version of these docs, recorded rather than
//! quietly fixed: this section used to say the health-test status bits "are
//! not observable through the public driver" and leave the impression that
//! they were therefore unobservable at all. They are observable — through
//! `rp-pac`, not through `embassy-rp`. `Rp2350Probe` reads them directly.


use zeroize::Zeroizing;

use crate::ckey;
use crate::drbg::{SeedError, SeedMaterial, SeedSource, MIN_ENTROPY_LEN, NONCE_LEN, OUTLEN};
use crate::migration;
use crate::secure_store::SecureStore;
use crate::trng::{
    TrngError, TrngProbe, ENTROPY_CLOCK_TICKS_PER_MS, MAX_ENTROPY_POLLS, MAX_ENTROPY_WAIT,
};

/// Compile-time gate on the mechanism's own `min_length` rule (SP 800-90A
/// Table 2). The seed this module produces is [`OUTLEN`] bytes, so the
/// width requirement is structural; what a runtime check has to police is
/// the *entropy* behind those bytes, and the all-zero refusal below is
/// that check. What this assertion does is stop a future edit — a narrower
/// output block, a shorter record — from quietly invalidating the
/// instantiation the way US-1002's numbers assume.
const _: () = assert!(
    OUTLEN >= MIN_ENTROPY_LEN,
    "the DRBG seed must carry at least MIN_ENTROPY_LEN bytes"
);

/// The same rule on the record side, stated where the record is read.
const _: () = assert!(
    ckey::BOOT_ENTROPY_LEN >= MIN_ENTROPY_LEN,
    "the boot-entropy record must carry at least MIN_ENTROPY_LEN bytes"
);

/// And the same rule on the fresh draw: it is absorbed verbatim, so unlike
/// the stretched key half its width *is* the entropy it contributes.
const _: () = assert!(
    NONCE_LEN >= MIN_ENTROPY_LEN,
    "the fresh TRNG draw must carry at least MIN_ENTROPY_LEN bytes"
);

/// A [`SeedSource`] over the OTP key row, the flash UID, the sealed
/// store's `boot.entropy.v1` record, and the hardware entropy peripheral.
///
/// Holds **references**. The OTP key row is a fuse window, not RAM, and
/// copying it into this struct would make it RAM — the one thing RS-Key's
/// `FusedKey` closure shape exists to prevent. The struct is four pointers
/// and a lifetime; there is nothing in it for a memory-disclosure bug to
/// find, and in particular no copy of either the last seed or the last draw.
pub struct FuseSeedSource<'a, K: SecureStore, P: TrngProbe> {
    otp_key_1: &'a [u8; ckey::KEY_LEN],
    /// The flash UID: its first 8 bytes are the big-endian chipid, and the
    /// whole of it is the input to `SHA-256(uid)`. The same two uses
    /// `migration::boot_kbase` makes of it.
    uid: &'a [u8],
    store: &'a mut K,
    /// The peripheral the fresh draw is taken from. The fourth borrow is the
    /// whole of C-1: a source that cannot reach hardware entropy cannot
    /// produce a seed that differs between two boots, and the type now says
    /// so instead of leaving it to review.
    probe: &'a mut P,
}

impl<'a, K: SecureStore, P: TrngProbe> FuseSeedSource<'a, K, P> {
    /// Bind the source to one device. All four inputs are borrowed for as
    /// long as the source lives; the source is re-usable, and each
    /// [`SeedSource::seed`] re-reads the store **and re-draws**.
    pub fn new(
        otp_key_1: &'a [u8; ckey::KEY_LEN],
        uid: &'a [u8],
        store: &'a mut K,
        probe: &'a mut P,
    ) -> Self {
        Self {
            otp_key_1,
            uid,
            store,
            probe,
        }
    }
}

impl<K: SecureStore, P: TrngProbe> SeedSource for FuseSeedSource<'_, K, P> {
    fn seed(&mut self) -> Result<SeedMaterial, SeedError> {
        // Every in-process refusal runs *before* the peripheral is touched,
        // so a misprovisioned device never spends a probe budget and never
        // reports a stall in place of the fault that can be diagnosed without
        // hardware. The store read has no side effects, so it too precedes
        // the draw. The ordering is not cosmetic: with the draw first, a
        // device that was both unprovisioned and wedged reported the wedge,
        // and the operator went looking at the wrong thing.
        let chipid = migration::chipid_from_uid(self.uid)?;

        // Re-read, every time. The two-in-one below is the US-918 accessor,
        // not a second reader: one length rule for one record.
        //
        // I-2: the record is live entropy, and this local is now zeroized
        // before the function returns on *every* branch — success, refusal,
        // and the error paths inside. It costs one line and closes a 32-byte
        // window that used to survive the frame.
        let entropy = Zeroizing::new(migration::boot_entropy_from(self.store)?);
        if let Some(record) = entropy.as_ref() {
            if record.iter().all(|&b| b == 0) {
                // An erased slot is present and correctly sized, so every
                // US-918 length rule waves it through. It is also the one
                // case that would supply a *constant* key — strictly worse
                // than having no record at all, which at least refuses.
                return Err(SeedError::DepletedBootEntropy);
            }
        }

        // The key half, derived first for the ordering reason above. The
        // derived value goes straight into the zeroizing buffer — there is
        // deliberately no named intermediate that would outlive it.
        let seed = Zeroizing::new(ckey::derive_drbg_seed(
            self.otp_key_1,
            &ckey::serial_hash(self.uid),
            chipid,
            entropy.as_ref(),
        )?);

        // And the entropy, which is the only refusal left that hardware can
        // close. A stall here is fatal and there is no fallback: see the
        // module docs. `Stalled` is the only variant a device can reach in
        // the field, but both are wrapped so the caller can tell a transient
        // source failure from a dead peripheral.
        let mut draw = Zeroizing::new([0u8; NONCE_LEN]);
        self.probe
            .probe_bytes(&mut draw[..])
            .map_err(SeedError::Trng)?;

        // A peripheral that reports success and hands back a constant would
        // reproduce the defect at one layer up, so the draw is checked for
        // the same "present but carries nothing" condition as the record.
        // This is cheap and it is the difference between "fresh" and
        // "asserted to be fresh".
        if draw.iter().all(|&b| b == 0) {
            return Err(SeedError::Trng(TrngError::Entropy));
        }

        Ok(SeedMaterial { seed, nonce: draw })
    }
}

/// A short note kept next to the code it constrains, because the alternative
/// is a future edit that reads the draw is "just a formality".
///
/// **Both** bounds are checked, and the budget one is checked against the
/// datasheet figure it is derived from: a ceiling that is non-zero but orders
/// of magnitude below one healthy generation would not be a bound at all, it
/// would be a boot brick (see [`crate::trng::MAX_ENTROPY_WAIT_MS`]).
const _: () = assert!(
    MAX_ENTROPY_POLLS > 0,
    "the fresh draw must be taken through a bounded wait, not an unbounded one"
);
const _: () = assert!(
    MAX_ENTROPY_WAIT >= 2 * ENTROPY_CLOCK_TICKS_PER_MS,
    "the wait budget must clear the RP2350 datasheet's ~2 ms AVERAGE generation \
     time for embassy-rp's default Config (RP2350 §12.12.2) — a budget at or \
     below the average refuses roughly half of all healthy draws, and a seed \
     refusal is fatal at boot"
);

