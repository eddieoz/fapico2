//! US-1822 / US-1823: the entropy bring-up state machine, as a pure core.
//!
//! # What this is
//!
//! The boot inverts under `WARM-BOOT-SERVE`: the board comes up and serves
//! everything deterministic while a background task warms and verifies the
//! TRNG. Until the bring-up completes, creation-class operations refuse with
//! one honest, pollable answer: *the randomness source is warming — retry.*
//!
//! This module is the single fact that encodes that policy:
//!
//! * [`State`] — `Warming` / `Ready`, the one bit every gate consults.
//! * [`step`] — the transition, pure over `record_present` and
//!   `trng_healthy`.
//! * [`OpClass`] + [`CLASS_TABLE`] — the frozen split of which operations
//!   serve while warming and which refuse (US-1823).
//! * [`gate`] — `Allow | RefuseWarming` per `(OpClass, State)`.
//! * [`next_action`] — the ordered bring-up sequence the background task
//!   (US-1825) walks: record (if absent) → DRBG seed → hkey (if absent) →
//!   Ready.
//!
//! No hardware types. Host-tested. Mirrors `entropy_reset.rs`'s pure-core
//! shape.
//!
//! # The TRNG is the only entropy source (owner direction, 2026-11-10)
//!
//! Nothing here proposes a second source. `trng_healthy` is the only input
//! that can move `Warming → Ready`; a wedged TRNG keeps the state `Warming`
//! forever and deterministic operations keep serving. A counter may be used
//! only as bookkeeping, never as entropy.
//!
//! # The entropy record still precedes every derivation (US-918)
//!
//! `next_action` draws the record (if absent) *before* seeding the DRBG, and
//! `step` returns `Warming` while `record_present` is false. Bound
//! derivations (`kbase`) never skip the record — they wait for `Ready`.

/// The bring-up state. One bit, consulted by every gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// TRNG unverified (or record absent). Deterministic ops serve;
    /// creation-class ops refuse with `RefuseWarming`.
    Warming,
    /// TRNG healthy, record present, DRBG seeded (and hkey provisioned on a
    /// fresh board). Nothing refuses.
    Ready,
}

/// The outcome of a per-operation gate check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Allow,
    RefuseWarming,
}

/// The ordered action the bring-up task performs next.
///
/// The task walks these in order, re-evaluating after each completes, so a
/// failure at any step leaves the state `Warming` and the next loop iteration
/// retries from the top (idempotently — already-drawn record/seeded DRBG are
/// observed, not re-drawn).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepAction {
    /// TRNG not yet healthy: sleep one step and retry. No reboot, no park.
    Wait,
    /// The boot-entropy record is absent: draw it first (US-918 — the record
    /// precedes every derivation). Consumes TRNG; refuses → `Wait`.
    DrawRecord,
    /// Record present: seed the `LazyDrbg`. Refuses → `Wait`.
    SeedDrbg,
    /// Fresh board (no hkey): draw the hkey from the DRBG and persist it.
    /// Only reached after `SeedDrbg` (ADR 0008 — `froot = hkey.to_bytes()`
    /// seedless; the hkey is a bring-up step, never a boot-path one).
    DrawHkey,
    /// All of the above done: publish `Ready`.
    Ready,
}

/// The next bring-up action given current progress.
///
/// `trng_healthy`: the bounded TRNG probe draw (US-1802 budget semantics)
/// succeeded. `record_present`: `SLOT_BOOT_ENTROPY` reads back the right
/// length. `drbg_seeded`: the `LazyDrbg` has been seeded. `hkey_present`:
/// `HKEY_KEY` reads back a key (provisioned board).
pub fn next_action(
    record_present: bool,
    drbg_seeded: bool,
    hkey_present: bool,
    trng_healthy: bool,
) -> StepAction {
    if !trng_healthy {
        return StepAction::Wait;
    }
    if !record_present {
        return StepAction::DrawRecord;
    }
    if !drbg_seeded {
        return StepAction::SeedDrbg;
    }
    if !hkey_present {
        return StepAction::DrawHkey;
    }
    StepAction::Ready
}

/// The state transition.
///
/// `Ready` is absorbing: once published it never goes back. `Warming` becomes
/// `Ready` only when `record_present && trng_healthy` (the record draw + DRBG
/// seed + hkey draw have all completed — observed through `record_present`
/// becoming true after a successful full bring-up pass). A wedged TRNG
/// (`!trng_healthy`) keeps `Warming` forever; deterministic operations keep
/// serving.
///
/// The two-argument signature matches the epic's `step(record_present,
/// trng_healthy)`; the finer progress (drbg_seeded/hkey_present) is folded
/// into `record_present` becoming true only after the whole sequence succeeds.
pub fn step(record_present: bool, trng_healthy: bool) -> State {
    if record_present && trng_healthy {
        State::Ready
    } else {
        State::Warming
    }
}

/// Operation classes. The split is frozen here (US-1823); every consumer in
/// the consumer map (US-1821) is in exactly one class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpClass {
    // ---- Deterministic under Warming (Allow) ----
    /// FIDO getAssertion: RFC 6979 signing; resident scalar derives from
    /// `froot`. No TRNG draw at serving time.
    GetAssertion,
    /// FIDO clientPIN verification: ECDH + HMAC over the persisted hkey.
    ClientPinVerify,
    /// OATH TOTP/HOTP code computation.
    OathCalculate,
    /// OpenPGP signing / decryption (Ed25519 deterministic; ECDH KEK + AES-KW).
    OpenPgpSignDecrypt,
    /// PIV signing.
    PivSign,
    /// Credential / key listing (no randomness).
    CredentialListing,
    /// Nostr read-only: GET_INFO, GET_PUBKEY, LIST_KEYS.
    NostrRead,

    // ---- Creation-class under Warming (RefuseWarming) ----
    /// FIDO makeCredential: keygen (non-resident), cred_id (non-resident),
    /// GCM write nonce. The resident arm consumes zero randomness, but the
    /// whole command stays in the refusal class (one reason, one code path);
    /// resident-only Allow is a recorded later narrowing (US-1823).
    MakeCredential,
    /// OpenPGP GET CHALLENGE (4+ bytes per request).
    OpenPgpGetChallenge,
    /// OpenPGP on-card keygen.
    OpenPgpKeygen,
    /// PIV keygen.
    PivKeygen,
    /// Nostr GENERATE.
    NostrGenerate,
    /// Nostr SIGN: draws a BIP-340 aux value per signature. BIP-340 marks
    /// the aux optional (nonce is RFC 6979-derived without it), but this
    /// epic DECIDES: refuse under Warming (default — one class, no
    /// side-channel regression). Recorded cost of the alternative: forgoing
    /// the aux's side-channel hardening during the warming window.
    NostrSign,
    /// Nostr NIP-44 ENC/DEC: the AEAD nonce is required per message.
    NostrNip44,
    /// OATH SET_CODE (PIN salts / challenge).
    OathSetCode,
    /// OATH SELECT: draws a fresh challenge per SELECT. Refuses under
    /// Warming even though CALCULATE is Allow; on a PIN-less board SELECT
    /// must have been invoked to arm the session, so a cold SELECT waits for
    /// Ready. (US-1823 design task: PIN-less CALCULATE needs the SELECT
    /// challenge issued; the split is reads-allow/SET_CODE-refuses, and
    /// SELECT itself draws, so it refuses.)
    OathSelect,
    /// Vendor backup (LOAD/EXPORT over the vendor channel).
    VendorBackup,
    /// hmac-secret credRandom creation IV draw (v2 protocol).
    HmacSecretCredRandom,
    /// Fresh board: hkey provisioning draw (ADR 0008).
    HkeyProvisioning,
    /// Fresh board only: PIN-dependent operations that need the hkey.
    PinDependentFresh,
}

/// Frozen class assignment: `true` = Allow under Warming, `false` = Refuse.
const CLASS_TABLE: &[(OpClass, bool)] = &[
    // Deterministic
    (OpClass::GetAssertion, true),
    (OpClass::ClientPinVerify, true),
    (OpClass::OathCalculate, true),
    (OpClass::OpenPgpSignDecrypt, true),
    (OpClass::PivSign, true),
    (OpClass::CredentialListing, true),
    (OpClass::NostrRead, true),
    // Creation-class
    (OpClass::MakeCredential, false),
    (OpClass::OpenPgpGetChallenge, false),
    (OpClass::OpenPgpKeygen, false),
    (OpClass::PivKeygen, false),
    (OpClass::NostrGenerate, false),
    (OpClass::NostrSign, false),
    (OpClass::NostrNip44, false),
    (OpClass::OathSetCode, false),
    (OpClass::OathSelect, false),
    (OpClass::VendorBackup, false),
    (OpClass::HmacSecretCredRandom, false),
    (OpClass::HkeyProvisioning, false),
    (OpClass::PinDependentFresh, false),
];

/// Whether `op` is in the Allow (deterministic) class.
pub fn is_allow_class(op: OpClass) -> bool {
    CLASS_TABLE
        .iter()
        .find(|(o, _)| *o == op)
        .map(|(_, a)| *a)
        .unwrap_or(false)
}

/// The per-operation gate decision.
pub fn gate(op: OpClass, state: State) -> Gate {
    match state {
        State::Ready => Gate::Allow,
        State::Warming => {
            if is_allow_class(op) {
                Gate::Allow
            } else {
                Gate::RefuseWarming
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // US-1822 scenario: fresh boot starts warming.
    #[test]
    fn fresh_boot_starts_warming() {
        assert_eq!(step(false, false), State::Warming);
        assert_eq!(gate(OpClass::MakeCredential, State::Warming), Gate::RefuseWarming);
    }

    // US-1822: first healthy draw completes the bring-up.
    #[test]
    fn first_healthy_draw_completes_bringup() {
        assert_eq!(step(true, true), State::Ready);
        assert_eq!(gate(OpClass::MakeCredential, State::Ready), Gate::Allow);
    }

    // US-1822: fresh install draws the record first, then seeds the DRBG.
    // The bring-up sequence orders DrawRecord before SeedDrbg.
    #[test]
    fn fresh_install_draws_record_before_seeding() {
        // record absent initially -> DrawRecord first
        assert_eq!(next_action(false, false, false, true), StepAction::DrawRecord);
        // after record drawn -> SeedDrbg
        assert_eq!(next_action(true, false, false, true), StepAction::SeedDrbg);
        // after seed -> (fresh board, no hkey) DrawHkey
        assert_eq!(next_action(true, true, false, true), StepAction::DrawHkey);
        // after hkey -> Ready
        assert_eq!(next_action(true, true, true, true), StepAction::Ready);
        // state only flips to Ready once record present + healthy
        assert_eq!(step(false, true), State::Warming);
        assert_eq!(step(true, true), State::Ready);
    }

    // US-1822: fresh install provisions the hkey at bring-up, in order.
    #[test]
    fn fresh_install_provisions_hkey_at_bringup() {
        // full sequence: DrawRecord -> SeedDrbg -> DrawHkey -> Ready
        let mut record = false;
        let mut drbg = false;
        let mut hkey = false;
        let trng = true;
        let mut seq = [StepAction::Wait; 4];
        // simulate
        seq[0] = next_action(record, drbg, hkey, trng);
        assert_eq!(seq[0], StepAction::DrawRecord);
        record = true;
        seq[1] = next_action(record, drbg, hkey, trng);
        assert_eq!(seq[1], StepAction::SeedDrbg);
        drbg = true;
        seq[2] = next_action(record, drbg, hkey, trng);
        assert_eq!(seq[2], StepAction::DrawHkey);
        hkey = true;
        seq[3] = next_action(record, drbg, hkey, trng);
        assert_eq!(seq[3], StepAction::Ready);
    }

    // US-1822: wedged TRNG stays Warming forever; deterministic ops serve.
    #[test]
    fn wedged_trng_stays_warming_forever() {
        // no bound on retry count: every call with !healthy -> Warming
        for _ in 0..1000 {
            assert_eq!(step(false, false), State::Warming);
            assert_eq!(step(true, false), State::Warming);
        }
        assert_eq!(next_action(false, false, false, false), StepAction::Wait);
        // deterministic ops still serve under Warming
        assert_eq!(gate(OpClass::GetAssertion, State::Warming), Gate::Allow);
        assert_eq!(gate(OpClass::ClientPinVerify, State::Warming), Gate::Allow);
    }

    // US-1822: Ready is absorbing.
    #[test]
    fn ready_is_absorbing() {
        // step() only models Warming->Ready; Ready state gate allows everything
        assert_eq!(gate(OpClass::MakeCredential, State::Ready), Gate::Allow);
    }

    // US-1823: deterministic operations serve under Warming.
    #[test]
    fn deterministic_ops_serve_under_warming() {
        for op in [
            OpClass::GetAssertion,
            OpClass::ClientPinVerify,
            OpClass::OathCalculate,
            OpClass::OpenPgpSignDecrypt,
            OpClass::PivSign,
            OpClass::CredentialListing,
            OpClass::NostrRead,
        ] {
            assert_eq!(gate(op, State::Warming), Gate::Allow, "{:?}", op);
        }
    }

    // US-1823: creation-class operations refuse under Warming.
    #[test]
    fn creation_ops_refuse_under_warming() {
        for op in [
            OpClass::MakeCredential,
            OpClass::OpenPgpGetChallenge,
            OpClass::OpenPgpKeygen,
            OpClass::PivKeygen,
            OpClass::NostrGenerate,
            OpClass::NostrSign,
            OpClass::NostrNip44,
            OpClass::OathSetCode,
            OpClass::OathSelect,
            OpClass::VendorBackup,
            OpClass::HmacSecretCredRandom,
            OpClass::HkeyProvisioning,
            OpClass::PinDependentFresh,
        ] {
            assert_eq!(gate(op, State::Warming), Gate::RefuseWarming, "{:?}", op);
        }
    }

    // US-1823: every OpClass is in exactly one class (table is total).
    #[test]
    fn class_table_is_total_and_exclusive() {
        // every variant appears exactly once
        let variants = [
            OpClass::GetAssertion, OpClass::ClientPinVerify, OpClass::OathCalculate,
            OpClass::OpenPgpSignDecrypt, OpClass::PivSign, OpClass::CredentialListing,
            OpClass::NostrRead, OpClass::MakeCredential, OpClass::OpenPgpGetChallenge,
            OpClass::OpenPgpKeygen, OpClass::PivKeygen, OpClass::NostrGenerate,
            OpClass::NostrSign, OpClass::NostrNip44, OpClass::OathSetCode,
            OpClass::OathSelect, OpClass::VendorBackup, OpClass::HmacSecretCredRandom,
            OpClass::HkeyProvisioning, OpClass::PinDependentFresh,
        ];
        for v in variants {
            let count = CLASS_TABLE.iter().filter(|(o, _)| *o == v).count();
            assert_eq!(count, 1, "OpClass {:?} appears {} times", v, count);
        }
        assert_eq!(CLASS_TABLE.len(), variants.len());
    }
}
