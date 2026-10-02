//! US-106 (EPIC `PICOForge-COMPAT`) — the clean `CTAP2_ERR_NOT_ALLOWED`
//! stub set for the RS-Key `0x41` vendor channel (PicoForge framing (C)).
//!
//! # Why this file exists
//!
//! US-101..US-104 made the device advertise the **RS-Key profile** (AAGUID,
//! version, USB serial, `USB_CAP_PIV`). PicoForge keys five of its screens off
//! that profile — Offboard, Lock, Backup, Audit, Attestation — and every one
//! of them drives a `0x41` sub-command. Before this story those calls fell into
//! the CTAP2 dispatch catch-all and answered `0x01` (`CTAP2_ERR_INVALID_COMMAND`),
//! or landed on `0x3E` (`CTAP2_ERR_INVALID_SUBCOMMAND`), or never answered at
//! all. To a desktop app all three read the same way: "this token is broken."
//!
//! The honest answer is `CTAP2_ERR_NOT_ALLOWED` — the sub-command is a real
//! part of the protocol we advertise, and this firmware does not permit it
//! *yet*. That is exactly the mitigation risk R-1 asks for, and it is
//! **expected to shrink to empty** as Phase I lands the real handlers.
//!
//! # Which tests drive which `FidoApp`
//!
//! There is no `cfg` fork of the command path: `fapico2_fido::FidoApp` is
//! always `device_app::FidoApp` (the `no_std` RP2350 shell), while
//! `fapico2_fido::app::FidoApp` is the `host`-feature std stack used by the
//! emulation binary. They are separate `match` statements over the same
//! opcode space, so a stub added to only one of them is a real defect that the
//! other test binary would never see.
//!
//! Concretely, and without over-claiming: the **status** tests
//! ([`unimplemented_vendor_subcommand_returns_2b`],
//! [`vendor41_unknown_subcommand_is_invalid_subcommand`],
//! [`vendor41_malformed_body_is_invalid_cbor`],
//! [`vendor41_extract_subcommand_rejects_malformed_shapes`],
//! [`vendor41_pending_set_is_exactly_the_stub_set`],
//! [`vendor41_stub_is_ungated_and_synchronous`]) run against **both** paths,
//! because both must answer the same status for the same request. The two
//! tests that do *not* are [`vendor41_subcommand_set_matches_picoforge`],
//! which is pure data with no app involved, and
//! [`vault_framing_does_not_alias_ctap2_vendor_0x41`], which is host-only
//! because the vault's host entry point (`app::FidoApp::process_vendor_vault`)
//! is what it contrasts against and the device twin has a different
//! signature. The aliasing test still exercises the device-typed `FidoApp` for
//! the RS-Key side of the comparison.
//!
//! The US-111 MAC tests follow the same split, and it is worth being explicit
//! about which half is which. The two named ones call
//! [`fapico2_fido::vendor41::verify_mac`] directly, because that function is
//! path-independent code shared by both command paths — there is no `cfg` fork
//! of it to drive twice, and calling it from two arms would only re-assert
//! that a function equals itself. What *does* differ by path is the pinUvAuth
//! token the caller has to hand it, because the host stack and the device stack
//! mint those through two separate `clientPin` implementations;
//! [`vendor41_mac_accepts_correct_mac`] drives that difference for real. And
//! what a *stubbed* sub-command does when handed a well-formed MAC is pinned,
//! on both paths, by [`vendor41_mac_is_not_yet_wired_into_the_stubs`] — which
//! also is the test that makes "available but deliberately not wired in yet" a
//! checkable claim instead of an assertion in a comment.
//!
//! # US-114: the first real arm
//!
//! `CONFIG_READ` (`0x0D`) is implemented, so this file is no longer only about
//! the stub set. Three things changed shape, and each is a place where the
//! absence of a change would itself be a bug:
//!
//! * [`unimplemented_vendor_subcommand_returns_2b`],
//!   [`vendor41_pending_set_is_exactly_the_stub_set`],
//!   [`vendor41_stub_is_ungated_and_synchronous`] and
//!   [`vendor41_stub_never_charges_pin_auth_failure`] iterate
//!   [`fapico2_fido::vendor41::PENDING`] rather than [`Subcommand::ALL`].
//!   The protocol table is permanent and the stub set shrinks, so a test
//!   walking the former fails the day the *second* arm lands — a contract
//!   turned into a change-detector.
//! * US-115 landed `CONFIG_WRITE`, so this file is no longer only about the
//!   stub set. The two "not yet wired" gates keep their names (the EPIC's
//!   grep resolves to them) but **not** their `CONFIG_WRITE` legs, because
//!   there is no such thing any more. Both now iterate [`PENDING`] rather
//!   than naming a sub-command — which is what keeps them from becoming
//!   change-detectors, since the original `CONFIG_WRITE` version would have
//!   started failing the day US-115 landed, for a reason unrelated to what it
//!   protects. A comment that is quietly wrong is worse than no comment, and a
//!   test whose *name* is quietly wrong is the same thing.
//!
//! # US-1516: six of those tests are now **vacuous**, and that is the finding
//!
//! [`PENDING`] is empty. Six tests in this file iterate it —
//! `vendor41_pending_set_is_exactly_the_stub_set`,
//! `vendor41_stub_is_ungated_and_synchronous`,
//! `vendor41_mac_is_not_yet_wired_into_the_stubs`,
//! `vendor41_stub_never_touches_the_state`,
//! `vendor41_permission_gate_is_not_yet_wired_into_the_stubs` and
//! `vendor41_stub_never_charges_pin_auth_failure` — so **each of them asserts
//! nothing at all today.** They are green because `for sub in PENDING` runs
//! zero times, and they went on being read as proof that a stub refuses
//! politely, gates nothing, and charges no PIN failure. Three of their doc
//!   comments still said "drives all twelve", which stopped being true when
//!   the last stub drained.
//!
//! That is the same failure US-1516 was raised about, in its sharpest form: a
//! test that reads as a specification and specifies nothing. A *test* decaying
//! silently is worse than prose decaying, because prose announces itself as
//! prose and a green test does not.
//!
//! They are **kept, not deleted**, and that is a decision rather than
//! sentiment: [`PENDING`] is retained precisely so that "is this still a stub?"
//! is answerable and so an empty list is a guard rather than a void (see
//! `vendor41::PENDING`'s own docs). A test that fires the moment an entry is
//! added back is exactly the guard that the module wants, and deleting the
//! bodies would throw it away. What was fixed is the prose, which claimed
//! enforcement that had silently stopped happening.
//!
//! The live statements about behaviour are elsewhere and are not vacuous:
//! the per-module tests for the arms that exist, and — for the claim "every
//! sub-command reaches a real arm on the device" —
//! `every_subcommand_is_dispatched_on_the_device_path`, which is what this
//! file's `PENDING` walks can no longer say.
//! * `vendor41_token_auth_reports_the_latch_but_nothing_reads_it_yet` was
//!   renamed to `..._and_only_the_identity_tier_reads_it`, because
//!   `CONFIG_WRITE` now reads `TokenAuth::blocked` — and reads it *narrowly*,
//!   which is the substantive claim: the benign tier must stay reachable
//!   through a PIN lockout, or a token typo bricks the Config screen until a
//!   power cycle.
//! * [`config_read_returns_phy_tlv_blob`] and its four siblings assert
//!   **literal bytes**, because a test that encoded with this crate's encoder
//!   and compared against this crate's decoder would prove only that the
//!   implementation agrees with itself.
//!
//! # US-113: the one place a *field* is the claim
//!
//! [`vendor_prototype_set_led_gpio_persists`] and its three siblings are the
//! only tests in this file that ask *which field did the decoded `0xFF` id
//! land in*, and they are the only shape here that answers it: each writes one
//! id into a record where the other three are already populated, then drops
//! the app and asserts the whole record back out of a fresh
//! [`DeviceApp::boot`] over the same `HostSecureStore`.
//!
//! The two halves are separate failures and are named as such below. The
//! reboot is what separates *durable* from *in RAM* — an arm that set a field,
//! answered `0x00` and never persisted satisfies every assertion made before
//! the app is dropped. The other three fields are what separates *the right
//! field* from *a field*: an arm that wrote the target and also damaged or
//! duplicated a neighbour satisfies any assertion that names only the target.
//! Neither half is reachable by the id-set, range or pack/unpack tests, which
//! is why a handler that decoded all four ids correctly and then wrote three of
//! them into the wrong struct member would have passed this file before.

use fapico2_fido::cbor::no_heap as nh;
use fapico2_fido::keystore::{Keystore, MemoryKeystore};
use fapico2_platform::secure_store::{HostSecureStore, SecureStoreError};
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;

// The two independent command paths (see module docs).
use fapico2_fido::app::FidoApp as HostApp;
use fapico2_fido::FidoApp as DeviceApp;
use fapico2_fido::vendor41::Subcommand;

#[path = "common/mod.rs"]
mod common;

/// CTAP2.1 `CTAP2_ERR_NOT_ALLOWED`.
const NOT_ALLOWED: u8 = 0x30;
/// CTAP2.1 `CTAP2_ERR_INVALID_SUBCOMMAND`.
const INVALID_SUBCOMMAND: u8 = 0x3E;
/// CTAP2.1 `CTAP2_ERR_INVALID_CBOR`.
const INVALID_CBOR: u8 = 0x12;
/// CTAP2.1 `CTAP2_ERR_INVALID_PARAMETER` — a well-formed parameter with a
/// value the firmware does not accept.
const INVALID_PARAMETER: u8 = 0x02;

/// CTAP2 command byte that carries the RS-Key vendor channel (framing (C)).
///
/// Spelled as a literal on the test side on purpose: it is the byte on the
/// wire, and asserting it against `vendor41::CMD` would compare two constants
/// that both say `0x41` and could not fail. The wiring is covered instead by
/// the status tests below, which drive this byte through `process_ctap2` and
/// would fall through to the `InvalidCommand` catch-all if either dispatch arm
/// stopped matching on it.
const VENDOR_41: u8 = 0x41;

/// The RS-Key `0x41` sub-commands, checked against
/// `picoforge/src/hal/fido/constants.rs:715-775` (RSKEY_* block).
///
/// Kept as data — not inlined into each test — so the set has exactly one
/// definition and the exhaustiveness test below can assert against it.
const RSKEY_SUBCOMMANDS: &[(u8, &str)] = &[
    (0x01, "RSKEY_VENDOR_MSE"),
    (0x02, "RSKEY_VENDOR_EXPORT"),
    (0x03, "RSKEY_VENDOR_LOAD"),
    (0x04, "RSKEY_VENDOR_FINALIZE"),
    (0x05, "RSKEY_VENDOR_STATE"),
    (0x06, "RSKEY_VENDOR_UNLOCK"),
    (0x07, "RSKEY_VENDOR_AUDIT_READ"),
    (0x08, "RSKEY_VENDOR_AUDIT_CHECKPOINT"),
    (0x09, "RSKEY_VENDOR_ATT_IMPORT"),
    (0x0A, "RSKEY_VENDOR_ATT_CLEAR"),
    (0x0B, "RSKEY_VENDOR_ATT_STATE"),
    (0x0C, "RSKEY_CONFIG_WRITE"),
    (0x0D, "RSKEY_CONFIG_READ"),
    (0x0E, "RSKEY_VENDOR_AUDIT_CONFIG"),
];

/// Build the RS-Key request body for `sub` — the CBOR map PicoForge puts in a
/// `0x90` frame after the `0x41` opcode byte:
/// `{1: subCommand, 2: subCommandParams, 3: pinUvAuthProtocol, 4: pinUvAuthParam}`.
///
/// Deliberately carries an *empty* params map and **no** auth material: the
/// stub must answer `0x30` without demanding a token, and a stub that reached
/// for one would fail this build of the request. (RS-Key `CONFIG_READ` is in
/// fact sent with no MAC and no token at all —
/// `picoforge/src/hal/fido/ops.rs:1461-1479`.)
fn rskey_request(sub: u8) -> HV<u8, 64> {
    let mut buf: HV<u8, 64> = HV::new();
    nh::push_map_header(&mut buf, 2).unwrap();
    nh::push_uint(&mut buf, 1).unwrap();
    nh::push_uint(&mut buf, sub as u64).unwrap();
    nh::push_uint(&mut buf, 2).unwrap();
    nh::push_map_header(&mut buf, 0).unwrap();
    buf
}

/// A fresh host-path app with **no PIN configured** — so any answer that
/// depends on a pinUvAuth token would be observable as a non-`0x30` status.
fn host_app() -> HostApp<MemoryKeystore> {
    HostApp::with_keystore(MemoryKeystore::new())
}

// ---------------------------------------------------------------------------
// The `VendorOps` seam (US-176).
//
// `handle` grew a sixth parameter and these six call sites are the ones that
// drive it directly rather than through a `FidoApp`. They all want the same
// thing: a real implementation over a throwaway snapshot, so that "this call
// touched no state" is a claim about the real types rather than about a mock.
//
// `store: None` is the dispatcher-bridge path `grow_checked` already
// documents (apply and mark dirty, let the durable-before-ack gate flush it),
// and the filler entropy is a counter because **no arm is implemented** — a
// Phase I arm that reaches entropy in one of these six tests would be reaching
// it on a snapshot the test then discards, which is a test bug and the tests
// below say so.
// ---------------------------------------------------------------------------

/// A [`VendorOps`] over a fresh device keystore, for the tests that call
/// [`fapico2_fido::vendor41::handle`] directly.
///
/// The keystore is taken as an argument rather than created here so a test that
/// wants to observe the state afterwards can keep it; the six call sites below
/// create a local and drop it, which is exactly the intent — they assert the
/// `Outcome`, and that no sub-command has an arm yet.
fn call_handle<R>(
    ks: &mut fapico2_fido::device_keystore::DeviceKeystore,
    f: impl FnOnce(&mut dyn fapico2_fido::vendor_backup::BackupOps) -> R,
) -> R {
    use fapico2_fido::vendor_state::{with_keystore_ops, VendorSession};
    let mut session = VendorSession::default();
    let mut counter = 0u8;
    let mut random = move |b: &mut [u8]| {
        for x in b.iter_mut() {
            counter = counter.wrapping_add(1);
            *x = counter;
        }
    };
    let mut store = None;
    with_keystore_ops(ks, &mut session, &mut store, &mut random, f)
}

/// [`fapico2_fido::vendor41::handle`] with a throwaway snapshot behind it.
fn handle_isolated(
    data: &[u8],
    auth: Option<TokenAuth<'_>>,
    phy: &fapico2_fido::vendorff::PhyConfig,
    presence: fapico2_fido::vendor41::PresenceGate,
    out: &mut HV<u8, { fapico2_fido::CTAP2_MAX_MSG }>,
) -> fapico2_fido::vendor41::Outcome {
    let mut trng = HostTrng::new();
    let mut ks = fapico2_fido::device_keystore::DeviceKeystore::fresh(&mut trng).expect("host TRNG");
    call_handle(&mut ks, |ops| {
        fapico2_fido::vendor41::handle(data, auth, phy, presence, out, ops)
    })
}

/// A fresh device-path app (the exact type the RP2350 serve loop drives).
fn device_app() -> (DeviceApp, HostTrng, HostSecureStore) {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let app = DeviceApp::boot(&mut trng, &mut store).unwrap();
    (app, trng, store)
}

// ---------------------------------------------------------------------------
// The named EPIC test.
// ---------------------------------------------------------------------------

// # `unimplemented_vendor_subcommand_returns_2b`
//
// Every RS-Key `0x41` sub-command that has no implementation yet must answer
// `CTAP2_ERR_NOT_ALLOWED` — never `InvalidCommand` (`0x01`), never
// `InvalidSubcommand` (`0x3E`), and never a timeout.
//
// ## Why the name says `2b` but the assertion says `0x30`
//
// The EPIC's acceptance bullet for US-106 names the test
// `..._returns_2b`, and its prose names the constant
// `CTAP2_ERR_NOT_ALLOWED` in the same breath. Those two disagree, and the
// constant is the one that is right:
//
// | byte | CTAP2.1 name | meaning |
// |---|---|---|
// | `0x2B` | `CTAP2_ERR_INVALID_OPTION` | the request is *malformed* — a parameter had an unusable value |
// | `0x30` | `CTAP2_ERR_NOT_ALLOWED` | the request was *well-formed and recognised*, but this authenticator does not permit it |
//
// A pending sub-command is the second case, not the first: the host sent a
// valid RS-Key sub-command with valid params, and we declined. Answering
// `0x2B` would blame the caller's request for a limitation that is ours.
//
// `0x30` is also what this crate already does for the identical meaning. The
// sibling vendor-vault path returns `Ctap2Response::NotAllowed` for its
// recognised-but-unimplemented sub-commands 0x04/0x05
// (`crate::device_core`, `app::FidoApp::process_vendor_vault`), and
// [`Ctap2Response::NotAllowed`] is already defined as `0x30`. So the correct
// byte needs no new enum variant and keeps this channel consistent with the
// one next door.
//
// The test *name* is deliberately left as the EPIC spells it so the EPIC's own
// grep keeps resolving to a real test. The same mislabelling recurs in US-111,
// which pairs `0x36` with `0x31` — those are `CTAP2_ERR_PUAT_REQUIRED` and
// `CTAP2_ERR_PIN_INVALID` respectively, and the pairing there is likewise
// wrong. That is US-111's problem to fix; it is recorded here only so the
// error is not propagated from this story.

/// The enumerated set is closed and correct, so the "shrink to empty" claim is
/// about a *finite, known* list rather than an open-ended catch-all.
///
/// Two things are pinned here that are easy to get wrong:
///
/// * `0x0C` / `0x0D` are `CONFIG_WRITE` / `CONFIG_READ`, **not** the 12th and
///   13th members of the 1..=11 run. The `1..=11` block plus `0x0C`, `0x0D`
///   and `0x0E` is the whole protocol — there is no sub-command 15 or 16.
/// * `CONFIG_READ` is **unimplemented too**, so it is stubbed with the rest.
///   It is ungated on the PicoForge side (no PIN token, no MAC,
///   `ops.rs:1461-1479`), which makes it the most likely sub-command to be
///   probed and therefore the most important one not to leave on `0x01`.
#[test]
fn vendor41_subcommand_set_matches_picoforge() {
    let set: Vec<u8> = RSKEY_SUBCOMMANDS.iter().map(|(b, _)| *b).collect();
    let expected: Vec<u8> = (1u8..=11)
        .chain([0x0C, 0x0D, 0x0E])
        .collect();
    assert_eq!(set, expected, "the RS-Key 0x41 sub-command set drifted");
    assert_eq!(RSKEY_SUBCOMMANDS.len(), 14, "expected exactly 14 sub-commands");

    // Tie the crate's enum to the table above. Without this the two could
    // drift apart silently: the enum is the thing that actually dispatches,
    // the table is only a transcription of the protocol, and nothing else in
    // the suite would notice if one gained or lost a member. The compile-time
    // exhaustiveness of `Subcommand` cannot catch this on its own — it is
    // perfectly happy with a consistently-wrong byte.
    for sub in Subcommand::ALL {
        assert_eq!(
            Subcommand::from_byte(sub.byte()),
            Some(sub),
            "{sub:?} must round-trip through from_byte",
        );
        assert!(
            RSKEY_SUBCOMMANDS.iter().any(|(b, _)| *b == sub.byte()),
            "{sub:?} carries byte 0x{:02X}, which is not in the pinned RS-Key \
             set — update the table above (and the protocol) if that is real",
            sub.byte(),
        );
    }

    // ...and back the other way, so a *dropped* variant is caught too.
    for &(byte, name) in RSKEY_SUBCOMMANDS {
        assert!(
            Subcommand::from_byte(byte).is_some(),
            "{name} (0x{byte:02X}) is in the pinned set but has no `Subcommand` \
             variant — the handler could not stub it",
        );
    }
}

/// [`vendor41::PENDING`] is exactly the set of sub-commands that answer
/// `NOT_ALLOWED` — checked in **both** directions.
///
/// This is the piece the compiler cannot do. `handle_subcommand`'s exhaustive
/// `match` only fires when a variant is *added*; it says nothing about whether
/// a variant is still a stub. So a Phase I story could write a real arm, leave
/// the variant in [`Subcommand`], forget to drop it from `PENDING` — and the
/// build would be silent. Asserting only "pending ⇒ stub" would miss that.
/// Asserting only "not pending ⇒ not stub" would miss the mirror mistake,
/// where someone deletes a `PENDING` entry without implementing anything and
/// the sub-command silently starts answering `0x3E`.
///
/// One assertion carries both directions, for every variant in the protocol.
/// # US-1516: this test is **vacuous today**, and that is its finding
///
/// [`PENDING`] is empty, so the loop below runs zero times and this asserts
/// nothing at all. It is not broken and it is not a stub-era leftover to
/// delete: it is the guard that fires the moment a sub-command is added back
/// to the stub set, which is the one thing keeping [`PENDING`] honest. What was
/// wrong was the doc comment above, which claimed active enforcement.
/// See the US-1516 section of this file's module docs for all six such tests
/// and for why a green test that has quietly stopped testing is the sharper
/// version of the problem US-1516 was raised about.
#[test]
fn vendor41_pending_set_is_exactly_the_stub_set() {
    // Every PENDING entry must be a real protocol sub-command, so the stub set
    // can never invent one the device would then claim to recognise.
    for &p in fapico2_fido::vendor41::PENDING {
        assert!(
            RSKEY_SUBCOMMANDS.iter().any(|(b, _)| *b == p.byte()),
            "{p:?} (0x{:02X}) is in PENDING but is not an RS-Key sub-command",
            p.byte(),
        );
    }

    // The other direction, now that the stub set has drained: **no**
    // sub-command answers NOT_ALLOWED merely for being unimplemented.
    //
    // This used to be the two-way check — "PENDING contains exactly the
    // sub-commands that answer 0x30" — and it was the mechanism that made
    // retiring a stub a one-line move. With `PENDING` empty that invariant is
    // satisfied vacuously and says nothing, so it is replaced by the assertion
    // that actually has content left: the protocol table is still all fourteen
    // (it must never shrink), and none of them is a stub any more.
    //
    // `NOT_ALLOWED` is still a legal *answer* — `ATT_IMPORT` on a device with
    // no MSE session, a soft lock engaged on a device with no seed, and so on.
    // What must not happen is a sub-command that refuses *because it was never
    // written*, and that is no longer expressible: the dispatcher has no
    // `stub()` arm left to reach.
    assert!(
        fapico2_fido::vendor41::PENDING.is_empty(),
        "the stub set has fully drained; every sub-command is implemented, so \
         PENDING must be empty",
    );
    assert_eq!(
        Subcommand::ALL.len(),
        14,
        "the protocol table is permanent and must not shrink as stories land",
    );
    // A regression guard for the mechanism itself: if a future arm is ever
    // added without a `match` arm, the exhaustive `match` in
    // `handle_subcommand` fails the build, and if a `stub()` reappears without
    // a PENDING entry, this list is what catches the omission.
    let stubs: Vec<_> = fapico2_fido::vendor41::PENDING.to_vec();
    assert!(
        stubs.is_empty(),
        "PENDING is non-empty again: a stub has been reintroduced, and the \
         sub-commands in it are {stubs:?}",
    );
}

/// A byte that is **not** in the RS-Key set is a malformed request, not a
/// pending one, and says so with `CTAP2_ERR_INVALID_SUBCOMMAND`.
///
/// This is the one place the handler needs a fallback, and it deliberately
/// does *not* answer `NOT_ALLOWED`: `NOT_ALLOWED` would assert "you asked for
/// something real and I declined", which would be a lie about a byte that the
/// protocol does not define. `0x0F` is a plausible future extension and `0xC1`
/// is PicoForge's own `CTAP_VENDOR_CBOR_CMD` — neither is an RS-Key
/// sub-command, and both must not be silently absorbed into the `0x30` set.
#[test]
fn vendor41_unknown_subcommand_is_invalid_subcommand() {
    for sub in [0x00u8, 0x0F, 0xC1, 0xFF] {
        let req = rskey_request(sub);
        let mut host = host_app();
        let resp = host.process_ctap2(VENDOR_41, &req, [1, 2, 3, 4]);
        assert_eq!(
            resp.first().copied(),
            Some(INVALID_SUBCOMMAND),
            "host: 0x{sub:02X} is not an RS-Key sub-command, so it must be \
             INVALID_SUBCOMMAND (0x3E) — not NOT_ALLOWED, not INVALID_COMMAND",
        );

        let (mut dev, _trng, mut store) = device_app();
        let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
        let n = dev.process_ctap2_with_store(VENDOR_41, &req, [1, 2, 3, 4], &mut out, Some(&mut store));
        assert_eq!(
            out[..n].first().copied(),
            Some(INVALID_SUBCOMMAND),
            "device: 0x{sub:02X} is not an RS-Key sub-command, so it must be \
             INVALID_SUBCOMMAND (0x3E) — not NOT_ALLOWED, not INVALID_COMMAND",
        );
    }
}

/// Garbage in the `0x41` slot is a CBOR error, not a `NOT_ALLOWED` one.
///
/// A blanket `0x30` on *any* `0x41` payload would be the "permanent catch-all"
/// the EPIC forbids: it would make a genuinely broken request indistinguishable
/// from a valid pending one, and would hide real decoder bugs behind a
/// plausible-looking status.
#[test]
fn vendor41_malformed_body_is_invalid_cbor() {
    for body in [
        b"".as_slice(),      // empty body: no CBOR at all
        b"\xff".as_slice(),  // "break" outside an indefinite item
        b"\x01".as_slice(),  // a bare uint, not the {1: sub, ...} map
        b"\x9f".as_slice(),  // indefinite array, never terminated
    ] {
        let mut host = host_app();
        let resp = host.process_ctap2(VENDOR_41, body, [1, 2, 3, 4]);
        assert_eq!(
            resp.first().copied(),
            Some(INVALID_CBOR),
            "host: malformed body {body:02X?} must be INVALID_CBOR (0x12), got {resp:02X?}",
        );

        let (mut dev, _trng, mut store) = device_app();
        let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
        let n = dev.process_ctap2_with_store(VENDOR_41, body, [1, 2, 3, 4], &mut out, Some(&mut store));
        assert_eq!(
            out[..n].first().copied(),
            Some(INVALID_CBOR),
            "device: malformed body {body:02X?} must be INVALID_CBOR (0x12), got {:02X?}",
            &out[..n],
        );
    }
}

/// The three exits of `extract_subcommand` that the map-header test above
/// cannot reach, plus the two shapes a real client can plausibly send.
///
/// `vendor41_malformed_body_is_invalid_cbor` only covers "this is not a CBOR
/// map at all". Everything downstream of a *well-formed* map was unpinned, and
/// Phase I will be editing this function — so each exit is pinned here
/// individually, with a status that is deliberately *not* `0x30`:
///
/// * no key 1 at all → `0x14` MISSING_PARAMETER. Not a CBOR error: the CBOR is
///   fine, the request is just incomplete. Collapsing it into `0x12` would
///   misreport a well-formed request as undecodable.
/// * key 1 present but not an unsigned int (`{1: "x"}`) → `0x12`. The request
///   is not the shape the protocol defines, and must not be coerced.
/// * key 1 out of `u8` range (`{1: 270}`) → `0x3E`. The value is a well-formed
///   integer, it is simply not a sub-command. `0x10E` truncating to `0x0E`
///   would silently dispatch AUDIT_CONFIG for a request that never asked.
/// * key 1 twice → `0x12`; ambiguous, and canonical CBOR forbids it.
/// * keys out of order (`{2: …, 1: 5}`) → accepted, and answered as the stub.
///   The EPIC flags non-canonical key ordering as real-client behaviour, so
///   the decoder must not be order-sensitive.
#[test]
fn vendor41_extract_subcommand_rejects_malformed_shapes() {
    /// `CTAP2_ERR_MISSING_PARAMETER`.
    const MISSING_PARAMETER: u8 = 0x14;

    // `{1: "x"}` — key 1 is a text string.
    let key1_string: HV<u8, 64> = {
        let mut b: HV<u8, 64> = HV::new();
        nh::push_map_header(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        nh::push_tstr(&mut b, "x").unwrap();
        b
    };
    // `{1: 270}` — a valid CBOR uint that does not fit a u8.
    let key1_overflow: HV<u8, 64> = {
        let mut b: HV<u8, 64> = HV::new();
        nh::push_map_header(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 270).unwrap();
        b
    };
    // `{1: 1, 1: 6}` — a duplicated key.
    let key1_duplicated: HV<u8, 64> = {
        let mut b: HV<u8, 64> = HV::new();
        nh::push_map_header(&mut b, 2).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 6).unwrap();
        b
    };
    // `{2: {…}, 1: 5}` — key 1 last rather than first.
    let order_swapped: HV<u8, 64> = {
        let mut b: HV<u8, 64> = HV::new();
        nh::push_map_header(&mut b, 2).unwrap();
        nh::push_uint(&mut b, 2).unwrap();
        nh::push_map_header(&mut b, 0).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 5).unwrap();
        b
    };

    // `{}` — a well-formed map with no key 1 at all.
    let no_key1: HV<u8, 64> = {
        let mut b: HV<u8, 64> = HV::new();
        nh::push_map_header(&mut b, 0).unwrap();
        b
    };

    let cases: [(&str, &[u8], u8); 4] = [
        ("no key 1", &no_key1, MISSING_PARAMETER),
        ("key 1 is a text string", &key1_string, INVALID_CBOR),
        ("key 1 out of u8 range", &key1_overflow, INVALID_SUBCOMMAND),
        ("key 1 duplicated", &key1_duplicated, INVALID_CBOR),
    ];

    for (what, body, expect) in cases {
        let mut host = host_app();
        let resp = host.process_ctap2(VENDOR_41, body, [1, 2, 3, 4]);
        assert_eq!(
            resp.first().copied(),
            Some(expect),
            "host: {what} ({body:02X?}) must be 0x{expect:02X}, got {resp:02X?}",
        );

        let (mut dev, _trng, mut store) = device_app();
        let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
        let n = dev.process_ctap2_with_store(VENDOR_41, body, [1, 2, 3, 4], &mut out, Some(&mut store));
        assert_eq!(
            out[..n].first().copied(),
            Some(expect),
            "device: {what} ({body:02X?}) must be 0x{expect:02X}, got {:02X?}",
            &out[..n],
        );
    }

    // Order-independence: the same request with its keys swapped decodes to the
    // same `STATE` response, on both paths.
    //
    // This asserted the STATE *stub*; it now asserts the real body, which is a
    // stronger statement than "reached the same arm" — it checks the decode
    // produced the right sub-command and not merely *some* arm. The expected
    // bytes are read off the wire format rather than the encoder:
    //
    //   0x00       status Success
    //   0xA4       CBOR map, 4 pairs
    //   01 F4      key 1 (sealed)   = false
    //   02 F4      key 2 (has_seed) = false
    //   03 F4      key 3 (locked)   = false
    //   04 F4      key 4 (unlocked) = false
    //
    // `0xF4` is a CBOR **false**, not a `0x00` byte. That is load-bearing:
    // the client's `m_bool` (`picoforge/src/hal/fido/mod.rs:1558-1565`) accepts
    // a bool or a non-zero integer and reads *anything else* — a string, a byte
    // string, a missing key — as `false`. For `locked` that means silently
    // reporting an unlocked device.
    const STATE_ALL_FALSE: [u8; 10] = [0x00, 0xA4, 0x01, 0xF4, 0x02, 0xF4, 0x03, 0xF4, 0x04, 0xF4];
    let mut host = host_app();
    let resp = host.process_ctap2(VENDOR_41, &order_swapped, [1, 2, 3, 4]);
    assert_eq!(
        resp.as_slice(),
        STATE_ALL_FALSE,
        "host: {{2: …, 1: 5}} must decode order-independently to STATE's \
         all-false response, with all four values as CBOR bools",
    );
    let (mut dev, _trng, mut store) = device_app();
    let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
    let n = dev.process_ctap2_with_store(
        VENDOR_41, &order_swapped, [1, 2, 3, 4], &mut out, Some(&mut store),
    );
    assert_eq!(
        out[..n],
        STATE_ALL_FALSE,
        "device: {{2: …, 1: 5}} must decode order-independently to STATE's \
         all-false response, byte-identical to the host path's",
    );
}

/// The stub is a pure, synchronous, ungated refusal.
///
/// PicoForge allows generous timeouts on this channel — 30 s for `CONFIG_WRITE`
/// (`ops.rs:1550`) and 32 s for the touch-gated vendor calls (`ops.rs:1598`) —
/// precisely because those sub-commands can block on a physical button. A stub
/// that waited, spun, or demanded a pinUvAuth token would read to the desktop
/// app as a hang, and a token demand would be a *second* different bug: RS-Key
/// `CONFIG_READ` is explicitly sent with no MAC and no token, so a stub that
/// asked for one would reject a request the protocol sends ungated.
///
/// These apps have **no PIN set** and are called with no `pinUvAuthProtocol`
/// or `pinUvAuthParam` in the request, so a token-gated implementation could
/// not produce `0x30` here.
///
/// US-114 made `CONFIG_READ` real, and this used to be the test that pinned
/// *its* ungatedness. It is not: the test that does that now is
/// `config_read_demands_no_token`, which drives the implemented arm. What
/// remains here is the property the other thirteen still need — a stub must
/// answer `0x30` **synchronously**, with the lone status byte and no
/// keepalive, on a device with no PIN — so this now iterates
/// [`PENDING`], for the same reason `unimplemented_vendor_subcommand_returns_2b`
/// does.
/// # US-1516: this test is **vacuous today**, and that is its finding
///
/// [`PENDING`] is empty, so the loop below runs zero times and this asserts
/// nothing at all. It is not broken and it is not a stub-era leftover to
/// delete: it is the guard that fires the moment a sub-command is added back
/// to the stub set, which is the one thing keeping [`PENDING`] honest. What was
/// wrong was the doc comment above, which claimed active enforcement.
/// See the US-1516 section of this file's module docs for all six such tests
/// and for why a green test that has quietly stopped testing is the sharper
/// version of the problem US-1516 was raised about.
#[test]
fn vendor41_stub_is_ungated_and_synchronous() {
    for sub in fapico2_fido::vendor41::PENDING {
        let req = rskey_request(sub.byte());
        let mut host = host_app();
        let resp = host.process_ctap2(VENDOR_41, &req, [1, 2, 3, 4]);
        assert_eq!(
            resp.as_slice(),
            [NOT_ALLOWED],
            "{:?} is a stub, so it must answer NOT_ALLOWED synchronously with \
             the lone status byte — no keepalive, no wait, and no token demand",
            sub.byte(),
        );
    }
}

// ---------------------------------------------------------------------------
// Non-aliasing: the RS-Key `0x41` vs the vendor-vault `0x41` (EPIC US-110).
// ---------------------------------------------------------------------------

/// The two `0x41`s in this firmware are different layers and cannot collide.
///
/// There are two distinct things called `0x41` here, and US-110 asks for a
/// test asserting both work at once. The vault one predates this story; the
/// RS-Key one is what the new arm above adds.
///
/// **The vault** dispatches on the **CTAPHID frame CMD byte** — a
/// non-standard command handled in `firmware/src/tasks.rs`, whose arm requires
/// `cmd == 0x41 && payload[0] == 0x05` (vault function 0x05). Its sub-command
/// numbering is its own: `1`=STATUS, `2`/`3`=ENROLL begin/finish, `4`, `5`=UNENROLL.
///
/// **RS-Key** is the **first byte of the payload inside a standard
/// `CTAPHID_CBOR` (`0x10`, `0x90` on the wire)** frame. The CBOR arm in
/// `tasks.rs` reads that byte as `ctap_cmd` and hands `payload[1..]` to the
/// CTAP2 command path, where it now selects the new arm.
///
/// They are **disjoint fields of disjoint frames** — a frame's CMD byte and a
/// `0x90` frame's first payload byte are different bytes of different frames,
/// so at most one of the two arms can ever match. There is no `0xC1` handler
/// in the tree.
///
/// The sharpest evidence that they are separate protocols, and not one shared
/// decoder, is that **their sub-command numbering overlaps with different
/// meanings**: sub-command `1` is `RSKEY_VENDOR_MSE` (ephemeral ECDH) on the
/// RS-Key channel and `STATUS` (return the enrolled vault id) on the vault
/// channel. A single shared sub-command decoder would be wrong for at least
/// one of them by construction. Their pinUvAuth messages differ for the same
/// reason — the vault MACs `0xff*32 ‖ 0x0D ‖ sub ‖ params`
/// (`device_core.rs:3248-3261`, i.e. the `authenticatorConfig` 0x0D domain)
/// where RS-Key MACs `0xff*32 ‖ 0x41 ‖ sub ‖ params`
/// (`picoforge/src/hal/fido/ops.rs:1581-1586`, the `0x41` domain).
#[test]
fn vault_framing_does_not_alias_ctap2_vendor_0x41() {
    // (1) The RS-Key framing: a STANDARD 0x90 CBOR frame whose first payload
    //     byte is 0x41, followed by the CBOR request map. The `0x41` is
    //     `ctap_cmd`, so this routes to the CTAP2 arm.
    let mut cbor_frame: HV<u8, 80> = HV::new();
    cbor_frame.push(0x90).unwrap(); // CTAPHID_CBOR on the wire
    cbor_frame.push(0x41).unwrap(); // payload[0] == ctap_cmd
    cbor_frame.extend_from_slice(&rskey_request(0x01)).unwrap(); // MSE

    let mut host = host_app();
    let (ctap_cmd, body) = (cbor_frame[1], &cbor_frame[2..]);
    assert_eq!(ctap_cmd, VENDOR_41);
    let via_ctap2 = host.process_ctap2(ctap_cmd, body, [1, 2, 3, 4]);
    // This asserted `NOT_ALLOWED` while `MSE` was a stub. It is real now, and
    // a bare `{1: 1}` carries no host key, so the arm answers
    // `MISSING_PARAMETER` (0x14) — which is a *better* discriminator than the
    // stub was: 0x30 was the answer of a sub-command that did not exist, and
    // would equally have been the answer of one that existed and refused.
    // 0x14 can only come from an arm that read the request and found it short
    // of what the protocol requires.
    assert_eq!(
        via_ctap2.as_slice(),
        [0x14],
        "the RS-Key framing (0x90 frame, payload[0] == 0x41) must reach the \
         MSE arm, which answers MISSING_PARAMETER for a request with no \
         subCommandParams",
    );

    // (2) The vault framing, at the same byte value: a NON-STANDARD frame whose
    //     CMD byte is 0x41 and whose payload[0] is 0x05 (the vault function).
    //     The sub-command goes in CBOR key 1 exactly as above.
    let vault_cmd = VENDOR_41;
    let vault_function = 0x05u8;
    let mut vault_frame: HV<u8, 80> = HV::new();
    vault_frame.push(vault_cmd).unwrap(); // frame CMD byte
    vault_frame.push(vault_function).unwrap(); // payload[0] == function
    vault_frame.extend_from_slice(&rskey_request(0x01)).unwrap(); // sub-command

    // Here the very same CBOR body means "STATUS", not "MSE". The vault answers
    // 0x00 + a CBOR map; the RS-Key arm answers a lone 0x30. Same bytes in,
    // provably different handlers out.
    let vault_out = host.process_vendor_vault(&vault_frame[2..]);
    assert_eq!(
        vault_out.first().copied(),
        Some(0x00),
        "the vault path must still work through its own framing",
    );
    assert!(
        vault_out.len() > 1,
        "the vault answers 0x00 followed by a CBOR map; it must not have been \
         diverted into the RS-Key stub",
    );

    // (3) And the vault rejects the same bytes that the RS-Key arm accepts,
    //     with a status the RS-Key arm can never produce. A shared decoder
    //     could not yield two different answers from one byte.
    //
    //     The vault's answer is `0x36` (`CTAP2_ERR_PUAT_REQUIRED`), not the
    //     `0x3E` one might expect, and that is worth recording: the host
    //     vault checks "does this sub-command need a pinUvAuth token?" *before*
    //     it reaches its sub-command `match`, so with no token configured the
    //     gate fires first for every sub-command except STATUS. The point
    //     stands either way — RS-Key answers 0x30, the vault answers 0x36, the
    //     two handlers are provably not sharing a dispatch — but do not read
    //     the 0x36 as a regression; it is the vault's pre-existing gate order.
    let mut unknown_vault: HV<u8, 64> = HV::new();
    nh::push_map_header(&mut unknown_vault, 1).unwrap();
    nh::push_uint(&mut unknown_vault, 1).unwrap();
    nh::push_uint(&mut unknown_vault, 0x0E).unwrap(); // RS-Key AUDIT_CONFIG
    let vault_unknown = host.process_vendor_vault(&unknown_vault);
    let vault_status = vault_unknown.first().copied();
    assert_ne!(
        vault_status,
        Some(NOT_ALLOWED),
        "the vault must never answer NOT_ALLOWED for 0x0E — that is the RS-Key \
         arm's answer, and sharing it would mean the two protocols had been \
         merged",
    );
    assert_eq!(
        vault_status,
        Some(0x36), // CTAP2_ERR_PUAT_REQUIRED
        "the vault's token gate runs before its sub-command match, so 0x0E with \
         no token configured answers PUAT_REQUIRED",
    );
    // The same bytes, sent as RS-Key. `0x0E` is `AUDIT_CONFIG`, a real arm now,
    // and the request carries the vault function byte in a position this
    // protocol does not use, so the arm answers on its own terms rather than
    // the vault's. What is being pinned is that the two framings still land in
    // different handlers: the vault said 0x36, the RS-Key arm says 0x14, and
    // neither answer is reachable from the other's decoder.
    let rskey_same = host.process_ctap2(VENDOR_41, &unknown_vault, [1, 2, 3, 4]);
    assert_eq!(
        rskey_same.as_slice(),
        [0x14],
        "0x0E IS an RS-Key sub-command, so the RS-Key arm must answer on its \
         own terms for the very same bytes the vault refused — they cannot \
         share a decoder",
    );
}

// ---------------------------------------------------------------------------
// The EPIC US-110 test: opcode 0x41 reaches the vendor handler *by dispatch*.
// ---------------------------------------------------------------------------

/// # `ctap2_opcode_0x41_reaches_vendor_handler`
///
/// A CTAP2 opcode `0x41` arriving as a request must be routed to
/// [`fapico2_fido::vendor41`] by **both** dispatch sites — the host
/// `app::FidoApp::process_ctap2` and the device-typed `FidoApp` (the exact
/// type the RP2350 serve loop drives) — and must be dispatched there on the
/// request's own `subCommand`, not merely answered by *something*.
///
/// ## What this covers, and what it does not
///
/// **Read this before concluding the dispatch guarantee lives here.** It
/// mostly does not, and saying otherwise would point a maintainer at the wrong
/// test when a future story edits one of the two `match` sites. Two tests
/// above already pin both dispatch sites, each looping **host and device**:
///
/// * [`vendor41_unknown_subcommand_is_invalid_subcommand`] asserts
///   `INVALID_SUBCOMMAND` (`0x3E`) for sub-commands `[0x00, 0x0F, 0xC1,
///   0xFF]`. This test's `0x0F` leg is one of those four, with the same
///   assertion on the same two paths.
/// * [`vendor41_malformed_body_is_invalid_cbor`] asserts `INVALID_CBOR`
///   (`0x12`) for `["", b"\xff", b"\x01", b"\x9f"]`. All four of those are
///   rejected at the **head check** in `extract_subcommand` — the
///   `Parser::next()` must yield `Item::Map`, and each of them yields
///   something else or an error instead.
///
/// Those two, not this one, are where "the opcode reaches `vendor41::handle`
/// on both sites" is actually enforced; delete an arm from either dispatch and
/// they fail. This test's own contribution is narrow and should be quoted
/// honestly:
///
/// * it is the **specifically-named US-110 entry point**, so the EPIC's grep
///   for the story resolves to a real test rather than to a neighbour's
///   coverage;
/// * it adds the one input in the file that is rejected **after** the head
///   check rather than at it: `0xA1`, a `1`-pair map header with its body cut
///   off. The parser's major-5 arm is the one compound arm with no bounds
///   check, so `next()` returns `Ok(Item::Map(1))` and **passes** the head
///   check; the `0x12` then comes from the key read inside the pair loop
///   hitting `CborError::Eof`. The four inputs above all fail *at* the head,
///   so nothing else in this file exercises the truncated-after-a-valid-header
///   route;
/// * it asserts the **whole response slice** equals `[status]`, where the two
///   existing tests assert only `.first()` — so a stray trailing byte on the
///   error path would be caught here and not there.
///
/// The third of those is the only one that could fail while all the others
/// pass; do not count this test as the dispatch proof when auditing coverage.
///
/// ## The framing layer
///
/// [`vault_framing_does_not_alias_ctap2_vendor_0x41`], directly above, covers
/// something none of these do: that the two different `0x41`s (CTAPHID frame
/// CMD byte = vault, first byte of a `0x90` payload = RS-Key) stay disjoint.
/// It is host-only by construction, because its contrast arm is the host vault
/// entry point `app::FidoApp::process_vendor_vault`, which has no device twin
/// with the same signature. Where it drives `process_ctap2(0x41, …)` it only
/// ever observes a `0x30`, which is also what any other handler refusing the
/// request could produce — so it cannot stand in for the `0x3E`/`0x12`
/// evidence, and this test cannot stand in for its non-aliasing half.
///
/// ## Why `0x3E`/`0x12` and not `0x30`
///
/// `0x30` (NOT_ALLOWED) is ambiguous as evidence: it is the answer for *every*
/// pending sub-command, so a mis-wired path that reached some other stub — or
/// a `_` fallback that happened to answer — could produce it too.
///
/// `0x3E` (INVALID_SUBCOMMAND) and `0x12` (INVALID_CBOR) are not, and it is
/// worth being precise about why, because `0x3E` in particular is *not* unique
/// to this module — it is also the sub-command fallback of the credential and
/// authenticator-config handlers (`app.rs`'s and `device_core.rs`'s inner
/// `_` arms). Those are unreachable from a `0x41` request, and the reason is
/// structural rather than incidental: the **outer** dispatch routes on the
/// opcode byte first, and both of its catch-alls answer `0x01`. A request
/// arriving with opcode `0x41` is therefore *inside* `vendor41::handle`
/// before any other handler's sub-command `match` can be reached at all.
///
/// Within `extract_subcommand` the two statuses come from two different
/// places: `0x3E` when CBOR key 1 parses as an unsigned integer outside
/// `Subcommand`, `0x12` when the body is not a well-formed map. Asserting both
/// from a single opcode therefore pins two things at once — that the opcode
/// routed, and that routing continued *as far as the sub-command decode* — and
/// it pins them on each path separately, so removing the arm from one site
/// cannot be masked by the other.
#[test]
fn ctap2_opcode_0x41_reaches_vendor_handler() {
    // Sub-command 0x0F is past the end of the closed 14-member set
    // (`Subcommand::ALL`), so `from_byte` refuses it → INVALID_SUBCOMMAND.
    // The file's own request builder — the same helper, and the same sub-
    // command, `vendor41_unknown_subcommand_is_invalid_subcommand` uses.
    let unknown_sub = rskey_request(0x0F);

    // `0xA1` is a 1-pair map header with its body cut off. It is the only
    // malformed input here that is NOT rejected at the `Ok(Item::Map(n))` head
    // check: the parser's major-5 arm has no bounds check, so it yields
    // `Map(1)` and passes, and the `0x12` arrives at the key read inside the
    // pair loop instead (Eof).
    let malformed_body: HV<u8, 64> = {
        let mut buf: HV<u8, 64> = HV::new();
        buf.push(0xA1).unwrap();
        buf
    };

    // --- host path (the emulation / std stack) ---
    let mut host = host_app();
    assert_eq!(
        host.process_ctap2(VENDOR_41, &unknown_sub, [1, 2, 3, 4])
            .as_slice(),
        [INVALID_SUBCOMMAND],
        "host: opcode 0x41 with an out-of-set sub-command must be decoded by \
         vendor41 (0x3E); 0x01 would mean the opcode never left the \
         InvalidCommand catch-all",
    );
    assert_eq!(
        host.process_ctap2(VENDOR_41, &malformed_body, [1, 2, 3, 4])
            .as_slice(),
        [INVALID_CBOR],
        "host: opcode 0x41 with a non-CBOR body must be decoded by vendor41 \
         (0x12) — a status that only its parser can produce",
    );

    // --- device path (the type the RP2350 serve loop drives) ---
    // Driven with the secure store bound, exactly as `firmware/src/tasks.rs`
    // does, so the `Some(store)` arm of the dispatch is the one under test
    // and not a test-only `None` shortcut around it.
    let (mut dev, _trng, mut store) = device_app();
    let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
    let n = dev.process_ctap2_with_store(
        VENDOR_41,
        &unknown_sub,
        [1, 2, 3, 4],
        &mut out,
        Some(&mut store),
    );
    assert_eq!(
        &out[..n],
        [INVALID_SUBCOMMAND],
        "device: opcode 0x41 must reach vendor41 with the store bound (0x3E), \
         got {:02X?}",
        &out[..n],
    );

    let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
    let n = dev.process_ctap2_with_store(
        VENDOR_41,
        &malformed_body,
        [1, 2, 3, 4],
        &mut out,
        Some(&mut store),
    );
    assert_eq!(
        &out[..n],
        [INVALID_CBOR],
        "device: opcode 0x41 must reach vendor41's parser with the store bound \
         (0x12), got {:02X?}",
        &out[..n],
    );
}

// ---------------------------------------------------------------------------
// US-111: the RS-Key pinUvAuth MAC — framing (C), authenticated half.
// ---------------------------------------------------------------------------

/// CTAP2.1 `CTAP2_ERR_PIN_AUTH_INVALID` — a pinUvAuthParam that was supplied
/// and did not verify.
const PIN_AUTH_INVALID: u8 = 0x33;
/// CTAP2.1 `CTAP2_ERR_PUAT_REQUIRED` — no pinUvAuthParam supplied at all.
///
/// ## The two EPIC mislabels, in one place
///
/// The US-111 acceptance bullet says "reject with `0x36` (`PIN_REQUIRED`) when
/// absent and `0x31` (`INVALID_COMMAND`) when wrong". Both pairings are wrong
/// against CTAP2.1 *and* against this crate's own `Ctap2Response`:
///
/// | byte | this crate | CTAP2.1 | the EPIC calls it |
/// |---|---|---|---|
/// | `0x36` | `PuatRequired` | `CTAP2_ERR_PUAT_REQUIRED` | `PIN_REQUIRED` |
/// | `0x31` | `PinInvalid` | `CTAP2_ERR_PIN_INVALID` | `INVALID_COMMAND` |
///
/// `0x36` is used, with the name this crate actually gives it — the EPIC's
/// *byte* is right for "no auth material supplied", its *name* is not.
///
/// `0x31` is **not** used. This crate's `INVALID_COMMAND` is `0x01`; `0x31` is
/// `PinInvalid`, which means "the PIN you entered was wrong" and would tell a
/// desktop app to re-prompt for the PIN when in fact the host sent a stale
/// token or a MAC over the wrong bytes. For "a MAC was supplied and it did
/// not match" the correct existing code is `0x33` `PinAuthInvalid` — which is
/// what the sibling vendor-vault path already answers for a bad MAC
/// (`crate::device_core`'s `vendor_vault_inner`, reached from
/// `app::FidoApp::process_vendor_vault`). Matching the vault is what gives a
/// client one coherent auth-error model across the two `0x41`s, which is why
/// `0x31` is not used despite the EPIC naming it.
const PUAT_REQUIRED: u8 = 0x36;

/// The RS-Key pinUvAuth MAC length — protocol 1 truncates HMAC-SHA256 to 16.
const MAC_LEN: usize = 16;

/// The token the golden vectors below are computed with.
///
/// Deliberately not a real token: a fixed 32-byte pattern makes them
/// reproducible from the protocol description alone, so a reviewer can
/// recompute them without running any of this code.
const GOLDEN_TOKEN: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// `{1: target, 2: blob}` with `target = 1` and a 32-byte blob — the
/// `CONFIG_WRITE` params shape PicoForge builds at
/// `picoforge/src/hal/fido/ops.rs:1520-1523`.
const GOLDEN_PARAMS: [u8; 38] = [
    0xa2, 0x01, 0x01, 0x02, 0x58, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Offset of the blob's first content byte **within** the params encoding —
/// past the 6-byte head `A2 01 01 02 58 20`.
const PARAMS_BLOB_OFFSET: usize = 6;

/// The MAC a correct client sends for (`GOLDEN_TOKEN`, sub `0x0C`,
/// `GOLDEN_PARAMS`): `HMAC-SHA256(token, 0xFF*32 || 0x41 || 0x0C || params)[..16]`.
///
/// **Computed out of band** — Python `hmac`/`hashlib` over a hand-written CBOR
/// encoding — and transcribed here as a constant. That is what makes the
/// accept-test below non-circular: [`picoforge_mac`] rebuilds the message from
/// the protocol description, [`GOLDEN_MAC`] says what that message must hash
/// to, and [`fapico2_fido::vendor41::verify_mac`] is a third, independent
/// implementation that derives the message from the parsed request instead of
/// from a formula. If the firmware's construction drifts — a dropped `0xFF`
/// prefix, the `0x0D` domain byte, params left out of the message, the
/// truncation width — this constant stops matching and the test fails.
///
/// The two companions are the negative vectors: same inputs, one thing changed.
///
/// * [`GOLDEN_MAC_VAULT_DOMAIN`] — `0x0D` instead of `0x41` (the vault's
///   domain, `device_core.rs`'s `vendor_vault_inner`).
/// * [`GOLDEN_MAC_OTHER_SUBCOMMAND`] — sub `0x05` instead of `0x0C`.
const GOLDEN_MAC: [u8; 16] = [
    0xfa, 0x4f, 0x1a, 0x20, 0x7c, 0x8f, 0x7b, 0x78, 0x2f, 0xdd, 0xcb, 0x89, 0xf7, 0x70, 0x9e, 0x4a,
];
/// `… || 0x0D || 0x0C || …` rather than `|| 0x41 || 0x0C || …`.
const GOLDEN_MAC_VAULT_DOMAIN: [u8; 16] = [
    0x34, 0x4e, 0x25, 0x40, 0x2e, 0x27, 0xeb, 0xb1, 0x7c, 0x4d, 0xec, 0xb9, 0x26, 0x47, 0x17, 0xcb,
];
/// `… || 0x41 || 0x05 || …` rather than `|| 0x41 || 0x0C || …`.
const GOLDEN_MAC_OTHER_SUBCOMMAND: [u8; 16] = [
    0xfd, 0x43, 0x75, 0xc4, 0x6d, 0x39, 0x6a, 0x69, 0xd3, 0xd9, 0x00, 0x6a, 0xae, 0xc0, 0x49, 0xe1,
];

/// Build the RS-Key pinUvAuth MAC the way **PicoForge** builds it
/// (`picoforge/src/hal/fido/ops.rs:1526-1534` for `CONFIG_WRITE`, `:1581-1586`
/// for the generic vendor call).
///
/// `domain` is the vendor-command byte PicoForge pushes before the
/// sub-command: `0x41` here, `0x0D` in the sibling vault. It is a parameter
/// rather than a hard-coded constant so the negative vectors come out of the
/// *same* builder with one thing changed — which is what makes them a test of
/// the domain byte instead of of a second, independently-guessable formula.
///
/// This drives the `hmac` crate directly, not `fapico2_fido::crypto`, so it
/// shares no line of code with the implementation under test.
fn picoforge_mac(token: &[u8; 32], domain: u8, sub: u8, params: &[u8]) -> [u8; MAC_LEN] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut msg: Vec<u8> = vec![0xFFu8; 32];
    msg.push(domain);
    msg.push(sub);
    msg.extend_from_slice(params);

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(token).expect("HMAC key");
    mac.update(&msg);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&full[..MAC_LEN]);
    out
}

/// `{1: sub, 2: params, 3: protocol, 4: mac}` — the RS-Key request body, in
/// the key order PicoForge's canonical CBOR produces.
///
/// `protocol` and `mac` are optional because the real client omits them for an
/// unauthenticated request (notably `CONFIG_READ`,
/// `picoforge/src/hal/fido/ops.rs:1461-1479`).
fn rskey_request_with_mac(
    sub: u8,
    params: &[u8],
    protocol: Option<u8>,
    mac: Option<&[u8]>,
) -> Vec<u8> {
    let pairs = 2 + usize::from(protocol.is_some()) + usize::from(mac.is_some());
    let mut b: HV<u8, 128> = HV::new();
    nh::push_head(&mut b, 5, pairs as u64).unwrap();
    nh::push_uint(&mut b, 1).unwrap();
    nh::push_uint(&mut b, sub as u64).unwrap();
    nh::push_uint(&mut b, 2).unwrap();
    b.extend_from_slice(params).unwrap();
    if let Some(p) = protocol {
        nh::push_uint(&mut b, 3).unwrap();
        nh::push_uint(&mut b, p as u64).unwrap();
    }
    if let Some(m) = mac {
        nh::push_uint(&mut b, 4).unwrap();
        nh::push_bstr(&mut b, m).unwrap();
    }
    b.to_vec()
}

/// The status a verification produced, as the byte that goes on the wire.
///
/// Kept as a helper because almost every assertion below is about the wire
/// value — a desktop app only ever sees that — while the function under test
/// returns a `Result` whose `Ok` arm carries the authenticated params.
fn status_byte(r: Result<&[u8], fapico2_fido::ctap2::Ctap2Response>) -> u8 {
    match r {
        Ok(_) => 0x00,
        Err(c) => c as u8,
    }
}

/// # `vendor41_mac_accepts_correct_mac`
///
/// The EPIC's named happy path. A MAC built the way PicoForge builds it must
/// verify against [`fapico2_fido::vendor41::verify_mac`].
///
/// ## Why this is not "the implementation agreeing with itself"
///
/// Three separate things have to line up, and only the third is the firmware:
///
/// 1. [`picoforge_mac`] reconstructs the auth message from the protocol — a
///    literal 32-byte `0xFF` prefix, the `0x41` vendor-command byte, the
///    sub-command, then the CBOR encoding of the key-2 params.
/// 2. [`GOLDEN_MAC`] says what that message must hash to, **computed outside
///    this codebase** and transcribed as a constant. The test asserts step 1
///    against it, so the client-side half is pinned to the protocol rather than
///    to whatever [`picoforge_mac`] happens to do today.
/// 3. `verify_mac` builds the message a *third* time, out of the parsed
///    request, and recomputes the HMAC with the crate's own primitive.
///
/// Steps 1 and 3 share no code, so their agreement means both match the
/// protocol — and any single-byte drift in either one of them (prefix, domain
/// byte, sub-command, truncation width, params inclusion) breaks it.
///
/// ## Both command paths
///
/// [`verify_mac`] is path-independent code with no `cfg` fork, so calling it
/// from two arms would only re-assert that a function equals itself. What
/// genuinely differs by path is the token the caller must supply, because the
/// host stack and the device stack mint those through two different
/// `clientPin` implementations. So this test mints a real one on each —
/// [`common::PinClient`] on the host app (`getPinUvAuthToken`, protocol 2) and
/// [`DevicePinClient`] on the device app (`getPinToken`, protocol 1). A real
/// token is the point: it is what proves the HMAC key is a full 32 bytes end to
/// end, and that the verifier does not care which of the two `clientPin` paths
/// issued it.
#[test]
fn vendor41_mac_accepts_correct_mac() {
    // --- steps 1 and 2: the client half, pinned to the out-of-band constant ---
    let mac = picoforge_mac(&GOLDEN_TOKEN, VENDOR_41, 0x0C, &GOLDEN_PARAMS);
    assert_eq!(
        mac, GOLDEN_MAC,
        "the test's own PicoForge-shaped MAC builder no longer matches the \
         out-of-band vector; re-derive the constant before trusting anything \
         below it",
    );

    // --- step 3: the firmware half ---
    let req = rskey_request_with_mac(0x0C, &GOLDEN_PARAMS, Some(1), Some(&mac));
    assert_eq!(
        fapico2_fido::vendor41::verify_mac(&req, Some(&GOLDEN_TOKEN)),
        Ok(&GOLDEN_PARAMS[..]),
        "HMAC-SHA256(token, 0xFF*32 || 0x41 || 0x0C || cbor(params))[..16] must \
         verify, and the params must come back as a span borrowed from the \
         request — byte-identical to what was signed, so an arm decodes *these* \
         bytes rather than re-finding the pair in the body itself. This is the \
         only assertion that would catch a wrong domain byte, a dropped 0xFF \
         prefix, or params left out of the message",
    );

    // --- a real token, host path (protocol-2 getPinUvAuthToken) ---
    let (mut host, host_client) = common::setup();
    let host_token: [u8; 32] = host_client
        .get_token(&mut host, 0x09, Some(0x20), None)
        .expect("getPinUvAuthTokenUsingPinWithPermissions(ACFG) must succeed")
        .try_into()
        .expect("a pinUvAuth token is 32 bytes");
    let host_mac = picoforge_mac(&host_token, VENDOR_41, 0x0C, &GOLDEN_PARAMS);
    let host_req = rskey_request_with_mac(0x0C, &GOLDEN_PARAMS, Some(1), Some(&host_mac));
    assert_eq!(
        status_byte(fapico2_fido::vendor41::verify_mac(&host_req, Some(&host_token))),
        0x00,
        "a token minted by the host stack's clientPin must key the same MAC — \
         a 32-byte HMAC key is not being shortened anywhere on the way in",
    );

    // --- a real token, device path (protocol-1 getPinToken) ---
    let (mut dev, _trng) = DevicePinClient::boot();
    dev.set_pin(b"1234");
    let dev_token = dev.get_pin_token(b"1234");
    let dev_mac = picoforge_mac(&dev_token, VENDOR_41, 0x0C, &GOLDEN_PARAMS);
    let dev_req = rskey_request_with_mac(0x0C, &GOLDEN_PARAMS, Some(1), Some(&dev_mac));
    assert_eq!(
        status_byte(fapico2_fido::vendor41::verify_mac(&dev_req, Some(&dev_token))),
        0x00,
        "a token minted by the device stack's clientPin must key the same MAC — \
         the verifier must not care which of the two clientPin paths issued it",
    );

    // --- the shape three real sub-commands actually use: NO key 2 at all ---
    //
    // `rs_key_vendor` signs `params_bytes = Vec::new()` and then omits key 2
    // from the map entirely (`picoforge/src/hal/fido/ops.rs:1560-1573`);
    // `mod.rs:1573` calls it as `rs_key_vendor(RSKEY_VENDOR_AUDIT_READ, None,
    // pin)`, and `EXPORT` and `ATT_CLEAR` go the same way. Every other leg of
    // this file builds its body through `rskey_request_with_mac`, which always
    // inserts key 2 — so without this leg the one request shape where the
    // params were never on the wire would be covered by no test at all, and
    // today's correct handling would be an accident of a buffer starting
    // empty rather than a pinned decision.
    let no_params = {
        let mut b: HV<u8, 64> = HV::new();
        nh::push_map_header(&mut b, 3).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 0x07).unwrap(); // AUDIT_READ
        nh::push_uint(&mut b, 3).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 4).unwrap();
        nh::push_bstr(&mut b, &picoforge_mac(&GOLDEN_TOKEN, VENDOR_41, 0x07, &[])).unwrap();
        b.to_vec()
    };
    // Guard the guard: decode the body and confirm it really is three pairs
    // with no key 2, rather than trusting the literal above to have built
    // what the comment claims.
    {
        use fapico2_fido::cbor::no_heap::{Item, Parser};
        let mut q = Parser::new(&no_params);
        assert!(
            matches!(q.next(), Ok(Item::Map(3))),
            "this leg is only meaningful if the body is the 3-pair map the \
             comment above says it is",
        );
        let mut keys = heapless::Vec::<u64, 8>::new();
        for _ in 0..3 {
            assert!(matches!(q.next(), Ok(Item::U(k)) if keys.push(k).is_ok()));
            q.skip().unwrap();
        }
        assert!(
            !keys.contains(&2),
            "this leg is only meaningful if the body has no key 2 at all, \
             found keys {keys:?}",
        );
    }
    assert_eq!(
        fapico2_fido::vendor41::verify_mac(&no_params, Some(&GOLDEN_TOKEN)),
        Ok(&[][..]),
        "a request with no key 2 must verify against a MAC over an empty \
         params tail and hand back an empty span — this is what \
         AUDIT_READ, EXPORT and ATT_CLEAR send, and omitting the params is \
         not a malformed request",
    );
}

/// # `vendor41_mac_rejects_tampered_params`
///
/// The EPIC's actual point: the MAC **covers the parameters**, so an edit to
/// any one byte of them must invalidate it.
///
/// ## Why blob content bytes, and not "any byte of the request"
///
/// The claim has to isolate the MAC from the decoder. Flipping an arbitrary
/// byte of the encoded request usually changes the CBOR itself — a map-header
/// byte becomes a different map, a length byte a different length — and the
/// request then fails at `0x12`/`0x14` before any HMAC is computed. A verifier
/// that rejected *everything* would pass such a test, which makes it vacuous.
///
/// So this flips the **32 content bytes of the params' byte string**. Every one
/// of those flips is length- and structure-preserving: the request decodes to
/// the same shape before and after, and the only thing that differs is the
/// bytes the MAC is computed over. The assertion is on the specific status
/// `0x33`, not merely on "not `Ok`" — so a decode failure fails the test
/// instead of satisfying it, and so does a verifier that accepted everything.
///
/// Two guards keep it from being vacuous in the other direction: the
/// *unmodified* request must verify first (otherwise 32 rejections would only
/// mean "this fixture is bad"), and each mutated request is checked to have
/// actually changed the byte the test believes it changed.
#[test]
fn vendor41_mac_rejects_tampered_params() {
    let mac = picoforge_mac(&GOLDEN_TOKEN, VENDOR_41, 0x0C, &GOLDEN_PARAMS);
    let good = rskey_request_with_mac(0x0C, &GOLDEN_PARAMS, Some(1), Some(&mac));

    assert_eq!(
        status_byte(fapico2_fido::vendor41::verify_mac(&good, Some(&GOLDEN_TOKEN))),
        0x00,
        "the untampered request must verify; without this, the rejections below \
         would only show the fixture is refused, not that the params are \
         covered by the MAC",
    );

    // Locate the blob inside the encoded request rather than hard-coding an
    // absolute offset, then assert the head really is the shape assumed.
    let params_at = good
        .windows(2)
        .position(|w| w == [0x01, 0x0C])
        .expect("the sub-command pair is in the request")
        + 3;
    assert_eq!(
        &good[params_at..params_at + PARAMS_BLOB_OFFSET],
        &GOLDEN_PARAMS[..PARAMS_BLOB_OFFSET],
        "the params must sit where this test assumes; if the request encoder \
         changed shape, the loop below would be mutating the wrong bytes",
    );
    let blob_at = params_at + PARAMS_BLOB_OFFSET;

    for i in 0..32 {
        let mut params = GOLDEN_PARAMS;
        params[PARAMS_BLOB_OFFSET + i] ^= 0xFF;
        // The MAC stays the one computed over the *original* params: a
        // forger's edit, not a re-signed request.
        let tampered = rskey_request_with_mac(0x0C, &params, Some(1), Some(&mac));
        assert_ne!(
            tampered[blob_at + i], good[blob_at + i],
            "byte {i} of the params was not actually changed, so its rejection \
             would prove nothing",
        );
        assert_eq!(
            tampered.len(),
            good.len(),
            "a params edit must not change the request's encoded length, or the \
             rejection below could be a decode failure rather than the MAC",
        );
        assert_eq!(
            status_byte(fapico2_fido::vendor41::verify_mac(&tampered, Some(&GOLDEN_TOKEN))),
            PIN_AUTH_INVALID,
            "flipping byte {i} of the params blob must invalidate the MAC. The \
             MAC covers cbor(params); an edit to the params is exactly what it \
             exists to catch. Any status other than 0x33 here means the request \
             stopped decoding instead of the MAC rejecting it.",
        );
    }
}

/// No auth material at all is `0x36` `PUAT_REQUIRED`, on both of its routes:
/// a request with no `pinUvAuthParam` (key 4), and a request that carries a
/// param the caller has no token to check it against.
///
/// The second is the case that keeps the failure honest. Answering `0x33`
/// there would tell the desktop app "your MAC was wrong", sending the user
/// round the PIN prompt for a token the app failed to obtain — when the real
/// fault is upstream, in token acquisition. "You sent no auth" and "you sent
/// the wrong auth" are different problems with different fixes, and they get
/// different codes.
#[test]
fn vendor41_mac_absent_is_puat_required() {
    // (a) a well-formed request with no key 4 — the shape PicoForge sends for
    //     `CONFIG_READ` (`picoforge/src/hal/fido/ops.rs:1461-1479`).
    let no_mac = rskey_request_with_mac(0x0C, &GOLDEN_PARAMS, None, None);
    assert_eq!(
        status_byte(fapico2_fido::vendor41::verify_mac(&no_mac, Some(&GOLDEN_TOKEN))),
        PUAT_REQUIRED,
        "a request with no pinUvAuthParam is unauthenticated, and demanding one \
         is the whole answer — 0x36 is what the sibling vault returns for the \
         same omission",
    );

    // (b) a request that does carry a MAC, but the caller holds no token.
    let mac = picoforge_mac(&GOLDEN_TOKEN, VENDOR_41, 0x0C, &GOLDEN_PARAMS);
    let with_mac = rskey_request_with_mac(0x0C, &GOLDEN_PARAMS, Some(1), Some(&mac));
    assert_eq!(
        status_byte(fapico2_fido::vendor41::verify_mac(&with_mac, None)),
        PUAT_REQUIRED,
        "with no token to check the param against, the answer is 'auth is \
         required', not 'auth is invalid' — 0x33 would send the user back to the \
         PIN prompt for a token the app never obtained",
    );
}

/// A pinUvAuthParam that is present and wrong is `0x33` `PinAuthInvalid`, in
/// all four ways a client can get it wrong.
///
/// The last two are the load-bearing ones for the domain byte and the
/// sub-command: both are *self-consistent* MACs, correctly HMAC'd with the
/// right token, over a message this channel did not authorise. A verifier that
/// merely checked "did 16 bytes arrive" would accept both; a verifier that
/// computed the MAC over `subcommand || params` without the domain byte would
/// accept the first. They are why the message layout is specified rather than
/// assumed.
#[test]
fn vendor41_mac_wrong_is_pin_auth_invalid() {
    let params = &GOLDEN_PARAMS[..];

    // (a) sixteen bytes of noise — a plausible-looking param that verifies
    //     nothing.
    let garbage = rskey_request_with_mac(0x0C, params, Some(1), Some(&[0xA5u8; MAC_LEN]));
    assert_eq!(
        status_byte(fapico2_fido::vendor41::verify_mac(&garbage, Some(&GOLDEN_TOKEN))),
        PIN_AUTH_INVALID,
        "a MAC that verifies nothing must be 0x33",
    );

    // (b) the right MAC sent under the wrong sub-command. `verify_mac` builds
    //     its message from the sub-command the *request* carries, so the two
    //     disagree.
    let good_mac = picoforge_mac(&GOLDEN_TOKEN, VENDOR_41, 0x0C, params);
    let wrong_sub = rskey_request_with_mac(0x05, params, Some(1), Some(&good_mac));
    assert_eq!(
        status_byte(fapico2_fido::vendor41::verify_mac(&wrong_sub, Some(&GOLDEN_TOKEN))),
        PIN_AUTH_INVALID,
        "a MAC computed for CONFIG_WRITE must not authorise AUDIT_READ: the \
         sub-command is inside the signed message, which is what stops one \
         sub-command's authorisation being replayed onto another",
    );

    // (c) the same MAC the sibling vendor vault would have produced for this
    //     request — right token, right sub-command, right params, wrong
    //     `0x0D` domain byte.
    let vault_mac = picoforge_mac(&GOLDEN_TOKEN, 0x0D, 0x0C, params);
    assert_eq!(
        vault_mac, GOLDEN_MAC_VAULT_DOMAIN,
        "the out-of-band vault-domain vector no longer matches; re-derive it",
    );
    let vault_domain = rskey_request_with_mac(0x0C, params, Some(1), Some(&vault_mac));
    assert_eq!(
        status_byte(fapico2_fido::vendor41::verify_mac(&vault_domain, Some(&GOLDEN_TOKEN))),
        PIN_AUTH_INVALID,
        "a MAC built with the vault's 0x0D domain byte must not authorise this \
         channel: the two 0x41s must not be able to borrow each other's \
         authorisations",
    );

    // (d) the MAC for a *different* sub-command, arriving as such — the
    //     negative constant, so the case is covered by an out-of-band value
    //     rather than only by the builder's own arithmetic.
    let other_sub_mac = picoforge_mac(&GOLDEN_TOKEN, VENDOR_41, 0x05, params);
    assert_eq!(
        other_sub_mac, GOLDEN_MAC_OTHER_SUBCOMMAND,
        "the out-of-band wrong-sub-command vector no longer matches",
    );
    let other_sub = rskey_request_with_mac(0x0C, params, Some(1), Some(&other_sub_mac));
    assert_eq!(
        status_byte(fapico2_fido::vendor41::verify_mac(&other_sub, Some(&GOLDEN_TOKEN))),
        PIN_AUTH_INVALID,
        "a MAC minted for sub-command 0x05 must not authorise 0x0C",
    );

    // (e) the right 32 bytes, declared as protocol 2. The RS-Key profile only
    //     defines protocol 1, so this is refused as an undefined parameter
    //     *before* the MAC is even computed — which is what stops "compare
    //     whatever the client sent against the first N bytes of the HMAC" from
    //     being a usable rule. The status is `0x02`, not `0x33`: the request
    //     names something this channel does not implement, which is a
    //     different fault from a MAC that does not match, and the sibling
    //     vault's leniency here (it honours the declared protocol) is
    //     deliberately not copied.
    let full_hmac = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut msg: Vec<u8> = vec![0xFFu8; 32];
        msg.push(VENDOR_41);
        msg.push(0x0C);
        msg.extend_from_slice(params);
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&GOLDEN_TOKEN).expect("HMAC key");
        m.update(&msg);
        m.finalize().into_bytes().to_vec()
    };
    let protocol2 = rskey_request_with_mac(0x0C, params, Some(2), Some(&full_hmac));
    assert_eq!(
        status_byte(fapico2_fido::vendor41::verify_mac(&protocol2, Some(&GOLDEN_TOKEN))),
        INVALID_PARAMETER,
        "a full 32-byte HMAC presented as protocol 2 must not verify on a \
         protocol-1 channel, and must be refused on the declared protocol \
         rather than after a 32-byte comparison — PicoForge always sends 3:1",
    );
}

/// A repeated key is an ambiguity this parser refuses rather than resolves.
///
/// [`verify_mac`] rejects a repeated key 1, 2 and 4 the same way, and the
/// reason is specific rather than stylistic: all three are inside or alongside
/// the signed message, so a duplicate makes "what was authorised" undecidable.
/// Key 2 is the sharpest case — the params *are* the signed bytes, so
/// last-wins would pick one pair and verify against the other.
///
/// Key 3 is the deliberate exception, and it is checked separately below: it
/// is outside the signed message, so repeating it changes nothing that was
/// authorised.
///
/// This is **not** an auth bypass either way, and the test is careful to say
/// so rather than implying the looser behaviour would be exploitable: an
/// attacker still needs a valid MAC over whichever pair survived. What last-
/// wins would cost is determinism — a later arm re-parsing the params with its
/// own helper could land on the other pair from the same bytes, and nothing
/// would report the disagreement. A parser that errors cannot diverge that way.
///
/// The duplicate is also built so that the request is *not* something the
/// decoder could reject for an unrelated reason: the second key 2 carries the
/// params a valid MAC was computed over, so a last-wins implementation would
/// accept this request outright and only a rejecting one answers `0x12`.
#[test]
fn vendor41_mac_rejects_repeated_map_keys() {
    let mac = picoforge_mac(&GOLDEN_TOKEN, VENDOR_41, 0x0C, &GOLDEN_PARAMS);
    let singly = rskey_request_with_mac(0x0C, &GOLDEN_PARAMS, Some(1), Some(&mac));
    assert_eq!(
        status_byte(fapico2_fido::vendor41::verify_mac(&singly, Some(&GOLDEN_TOKEN))),
        0x00,
        "the single-key request must verify; otherwise the rejections below \
         would only show the fixture is broken",
    );

    // Splice a second copy of the duplicated pair in immediately after the
    // first, so the request stays well-formed CBOR throughout and the only
    // thing wrong with it is the repetition. Five pairs either way: the key
    // under test appears twice among {1, 2, 2, 3, 4}.
    let duplicate = |key: u64, value: &[u8]| -> Vec<u8> {
        let mut b: HV<u8, 192> = HV::new();
        nh::push_map_header(&mut b, 5).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 0x0C).unwrap();
        nh::push_uint(&mut b, key).unwrap();
        b.extend_from_slice(value).unwrap();
        nh::push_uint(&mut b, key).unwrap();
        b.extend_from_slice(value).unwrap();
        nh::push_uint(&mut b, 3).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 4).unwrap();
        nh::push_bstr(&mut b, &mac).unwrap();
        b.to_vec()
    };

    for (what, body) in [
        ("key 1 (subCommand)", duplicate(1, &[0x0C])),
        ("key 2 (params)", duplicate(2, &GOLDEN_PARAMS)),
        ("key 4 (pinUvAuthParam)", duplicate(4, &mac)),
    ] {
        assert_eq!(
            status_byte(fapico2_fido::vendor41::verify_mac(&body, Some(&GOLDEN_TOKEN))),
            INVALID_CBOR,
            "{what} appears twice, so which value was signed is undecidable and \
             the request must be refused rather than resolved by key order",
        );
    }

    // Key 3 is the deliberate exception: it sits *outside* the signed message,
    // so repeating it cannot change what was authorised — the MAC is the same
    // either way and the surviving value still has to be 1. Last-wins is the
    // stated policy, so it is pinned here rather than left to be discovered:
    // a repeat that *ends* on 1 verifies, and a repeat that ends on 2 is
    // refused as the undefined protocol it is, not as a bad MAC.
    let repeated_protocol = |last: u8| -> Vec<u8> {
        let mut b: HV<u8, 192> = HV::new();
        nh::push_map_header(&mut b, 5).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 0x0C).unwrap();
        nh::push_uint(&mut b, 2).unwrap();
        b.extend_from_slice(&GOLDEN_PARAMS).unwrap();
        nh::push_uint(&mut b, 3).unwrap();
        nh::push_uint(&mut b, 2).unwrap();
        nh::push_uint(&mut b, 3).unwrap();
        nh::push_uint(&mut b, last as u64).unwrap();
        nh::push_uint(&mut b, 4).unwrap();
        nh::push_bstr(&mut b, &mac).unwrap();
        b.to_vec()
    };
    assert_eq!(
        fapico2_fido::vendor41::verify_mac(&repeated_protocol(1), Some(&GOLDEN_TOKEN)),
        Ok(&GOLDEN_PARAMS[..]),
        "a repeated key 3 whose last value is 1 is last-wins by policy: it is \
         outside the signed message, so the MAC is unaffected and the request \
         is authorised exactly as a single key-3 request would be",
    );
    assert_eq!(
        status_byte(fapico2_fido::vendor41::verify_mac(
            &repeated_protocol(2),
            Some(&GOLDEN_TOKEN)
        )),
        INVALID_PARAMETER,
        "a repeated key 3 whose last value is 2 must be refused as an \
         undefined protocol (0x02) — last-wins still has to clear the \
         protocol check, or the policy would be a way to smuggle one in",
    );
}

/// The two status bytes US-111 settles, pinned against the crate's own enum
/// so the mapping cannot be re-labelled by an edit to a comment.
#[test]
fn vendor41_mac_statuses_match_the_crate_enum() {
    use fapico2_fido::ctap2::Ctap2Response;
    assert_eq!(
        Ctap2Response::PuatRequired as u8,
        PUAT_REQUIRED,
        "0x36 is this crate's PUAT_REQUIRED, not the EPIC's PIN_REQUIRED",
    );
    assert_eq!(
        Ctap2Response::PinAuthInvalid as u8,
        PIN_AUTH_INVALID,
        "0x33 is this crate's PinAuthInvalid; the EPIC's 0x31 is PinInvalid \
         (wrong PIN), and its INVALID_COMMAND is 0x01",
    );
    assert_eq!(
        Ctap2Response::PinInvalid as u8, 0x31,
        "confirms 0x31 is PinInvalid in this crate, so it cannot be the \
         'wrong MAC' code the EPIC names",
    );
}

/// The MAC is available but is deliberately **not** wired into the stub arms.
///
/// Every sub-command still in [`fapico2_fido::vendor41::PENDING`] must answer
/// `CTAP2_ERR_NOT_ALLOWED`, and this story does not change that. So a request
/// carrying a *valid* MAC must still answer `0x30`, and one carrying a *bogus*
/// MAC must answer the same `0x30` rather than `0x33` — a `0x33` here would
/// mean verification had been switched on somewhere in the dispatch, changing
/// what a stub refuses for and, worse, letting a caller probe which MACs we
/// accept without any sub-command being implemented.
///
/// Iterates [`PENDING`] rather than naming one sub-command. US-106..US-114
/// used `CONFIG_WRITE` for this, on the reasoning that it is the one row a
/// permission gate gets right today, so a wired gate would be observable
/// there. US-115 implemented it, which made that choice a change-detector: the
/// named version of this test would have started failing for a reason that has
/// nothing to do with the property it exists to protect. Iterating `PENDING`
/// keeps the property and loses the coupling to *which* sub-command is a stub.
///
/// The last leg is the one that is specific to `CONFIG_WRITE`, and it is the
/// reason the name survives at all: for the *benign* tier of that sub-command
/// a `pinUvAuthParam` is not verified either, because the gate is a physical
/// touch and there is no MAC to check. Charging one would let three reads of a
/// config screen latch the three-strike lockout against a user who failed
/// nothing.
/// # US-1516: this test is **vacuous today**, and that is its finding
///
/// [`PENDING`] is empty, so the loop below runs zero times and this asserts
/// nothing at all. It is not broken and it is not a stub-era leftover to
/// delete: it is the guard that fires the moment a sub-command is added back
/// to the stub set, which is the one thing keeping [`PENDING`] honest. What was
/// wrong was the doc comment above, which claimed active enforcement.
/// See the US-1516 section of this file's module docs for all six such tests
/// and for why a green test that has quietly stopped testing is the sharper
/// version of the problem US-1516 was raised about.
#[test]
fn vendor41_mac_is_not_yet_wired_into_the_stubs() {
    // Arm the presence answer before anything can read it, not after. The
    // benign-tier leg below asserts `0x3B`, which is only the answer when the
    // gate says "no press", and the poll it consults is a `thread_local!` —
    // so the value in force during `handle_isolated` is what decides the
    // assertion, and it used to be whatever the thread already held. The
    // `set_presence(false)` that sat *after* the call was dead code: it
    // described the answer the test wanted without establishing it.
    //
    // Today that is harmless in practice — the `Cell` starts at `false`, and
    // libtest gives each test a fresh thread rather than handing out pooled
    // workers, so nothing is inherited (verified on rustc 1.98.1: six tests,
    // six distinct `ThreadId`s, every `thread_local!` at its initialiser).
    // But the order is what makes the test correct, and reading the answer off
    // a default is exactly the arrangement that breaks the first time either
    // half of that stops being true. Arming is one line; arguing about which
    // schedule produced a 0x00 is not.
    set_presence(false);
    let auth = Some(TokenAuth {
        token: &GOLDEN_TOKEN,
        permissions: PERM_ACFG_LITERAL,
        blocked: false,
    });

    for &sub in fapico2_fido::vendor41::PENDING {
        let good_mac = picoforge_mac(&GOLDEN_TOKEN, VENDOR_41, sub.byte(), &GOLDEN_PARAMS);
        let signed = rskey_request_with_mac(sub.byte(), &GOLDEN_PARAMS, Some(1), Some(&good_mac));
        let bad = rskey_request_with_mac(
            sub.byte(),
            &GOLDEN_PARAMS,
            Some(1),
            Some(&[0xA5u8; MAC_LEN]),
        );

        for (what, req) in [("correctly signed", &signed), ("bogus MAC", &bad)] {
            let mut app = host_app();
            assert_eq!(
                app.process_ctap2(VENDOR_41, req, [1, 2, 3, 4]).as_slice(),
                [NOT_ALLOWED],
                "host: {sub:?} is still a stub, so a {what} request must answer                  NOT_ALLOWED. A 0x33 would mean the verifier is reachable from                  dispatch for a sub-command with no implementation",
            );

            let (mut app, _trng, mut st) = device_app();
            let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
            let n =
                app.process_ctap2_with_store(VENDOR_41, req, [1, 2, 3, 4], &mut out, Some(&mut st));
            assert_eq!(
                &out[..n],
                [NOT_ALLOWED],
                "device: same for {sub:?} with a {what} request — the two \
                 command paths are independent `match`es over the same opcode \
                 space, so passing on one says nothing about the other",
            );
        }
        let _ = auth;
    }

    // The benign tier of `CONFIG_WRITE` is the one implemented arm that does
    // not authenticate, so a `pinUvAuthParam` riding along on it is neither
    // verified nor charged. A blob that reaches the benign tier at all: a
    // well-formed LED GPIO record.
    let benign = phy_blob(&[(TAG_LED_GPIO, &[0x04])]);
    let params = config_write_params(TARGET_PHY_LITERAL, &benign);
    // The MAC is deliberately *wrong*, over the right message. That is the
    // point: the benign tier never looks at it, so the wrongness is the
    // evidence rather than a fixture bug.
    let outcome = handle_isolated(
        &rskey_request_with_mac(0x0C, &params, Some(1), Some(&[0xA5u8; MAC_LEN])),
        auth,
        &fapico2_fido::vendorff::PhyConfig::default(),
        fapico2_fido::vendor41::PresenceGate {
            window_grant: None,
            poll: Some(presence_poll),
            tag: 0,
        },
        &mut HV::new(),
    );
    assert_eq!(
        outcome.status.code(),
        UP_REQUIRED,
        "a bogus MAC on a *benign* CONFIG_WRITE is not an authentication \
         failure at all: the benign tier is gated on a touch, so the param is \
         never verified"
    );
    assert!(
        !outcome.pin_auth_failure,
        "and it must not be charged against the three-strike counter. Charging a \
         param the arm declined to verify would let three config-screen reads \
         latch a PIN lockout against a user who failed nothing"
    );
}

/// # US-176: no arm may reach the state until its story implements it
///
/// `handle` gained a sixth parameter, and the twelve stubs are the only
/// sub-commands that could reach it. This is the check that they do not: on
/// **both** command paths, every `PENDING` sub-command is driven with a
/// correct `0x20` token, a correct MAC and a body that would be parseable by a
/// real arm — and the state must come back byte-identical.
///
/// It is the mirror image of
/// [`vendor41_pending_set_is_exactly_the_stub_set`], and it is deliberately a
/// *different* check. That one asks "is this still a stub?" from the protocol
/// table; this one asks "did a stub touch the state?" from the state itself,
/// which is the question a Phase I implementer can answer wrongly by adding an
/// arm that reads state before removing the `PENDING` entry — a change the
/// compiler is silent about and the other test is silent about too, because
/// from its side the sub-command still answers `NOT_ALLOWED`.
/// # US-1516: this test is **vacuous today**, and that is its finding
///
/// [`PENDING`] is empty, so the loop below runs zero times and this asserts
/// nothing at all. It is not broken and it is not a stub-era leftover to
/// delete: it is the guard that fires the moment a sub-command is added back
/// to the stub set, which is the one thing keeping [`PENDING`] honest. What was
/// wrong was the doc comment above, which claimed active enforcement.
/// See the US-1516 section of this file's module docs for all six such tests
/// and for why a green test that has quietly stopped testing is the sharper
/// version of the problem US-1516 was raised about.
#[test]
fn vendor41_stub_never_touches_the_state() {
    for sub in fapico2_fido::vendor41::PENDING {
        // --- host path -------------------------------------------------
        let mut host = host_app();
        // Seed the state so "untouched" means something: a snapshot whose
        // vendor half is fully populated, then a request through the same
        // dispatch the client uses.
        {
            use fapico2_fido::keystore::Keystore;
            let auth_state = host.keystore().get_auth_state_mut();
            auth_state.vendor.public.audit_enabled = true;
            auth_state.vendor.secret.master_seed = Some([0xA5; 32]);
        }
        let before = {
            use fapico2_fido::keystore::Keystore;
            host.keystore().get_auth_state().vendor.clone()
        };
        let req = rskey_request_with_mac(
            sub.byte(),
            &GOLDEN_PARAMS,
            Some(1),
            Some(&GOLDEN_MAC),
        );
        let _ = host.process_ctap2(VENDOR_41, &req, [1, 2, 3, 4]);
        let after = {
            use fapico2_fido::keystore::Keystore;
            host.keystore().get_auth_state().vendor.clone()
        };
        assert_eq!(
            after, before,
            "host: {sub:?} is a stub; it must not read or write the Phase I \
             state, and it must not clear it either"
        );

        // --- device path ------------------------------------------------
        let (mut dev, _trng, mut store) = device_app();
        dev.keystore().vendor.public.audit_enabled = true;
        dev.keystore().vendor.secret.master_seed = Some([0xA5; 32]);
        let before = dev.keystore().vendor.clone();
        let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
        let n =
            dev.process_ctap2_with_store(VENDOR_41, &req, [1, 2, 3, 4], &mut out, Some(&mut store));
        assert_eq!(
            dev.keystore().vendor, before,
            "device: same for {sub:?} — the two command paths are independent \
             implementations of the same trait, so passing on one says \
             nothing about the other"
        );
        assert_eq!(out[..n][0], NOT_ALLOWED, "and it must still answer NOT_ALLOWED");
    }
}

// ---------------------------------------------------------------------------
// A minimal protocol-1 CTAP2 PIN client for the *device* stack.
//
// The host stack has one in `tests/common`; the device stack's `clientPin` is a
// separate implementation (`device_core.rs`, reached through `device_app::FidoApp`)
// and has no shared helper. This is the same shape as the device client in
// `tests/pin_lockout.rs`, trimmed to what US-111 needs: derive the v1 shared
// secret, set a PIN, mint a token.
// ---------------------------------------------------------------------------

struct DevicePinClient {
    app: DeviceApp,
    hmac_key: [u8; 32],
    enc_key: [u8; 32],
    /// US-113: the client now carries the secure store, because a `0xFF`
    /// physical-config write is *only* meaningful if it survives one, and
    /// [`Self::call`] has to hand the store to `process_ctap2_with_store` the
    /// way the RP2350 HID task does — otherwise the transaction that
    /// `grow_checked` runs would take the `store = None` legacy branch and
    /// never prove durability.
    store: HostSecureStore,
}

impl DevicePinClient {
    /// Returns the client and the TRNG. The store stays *inside* the client
    /// (US-113) rather than being handed back separately, because a test that
    /// holds the store by value and a test that reaches in through
    /// `self.store` are two different durability claims, and only the second
    /// one is the one the RP2350 makes.
    fn boot() -> (Self, HostTrng) {
        let (app, trng, store) = device_app();
        (
            Self { app, hmac_key: [0; 32], enc_key: [0; 32], store },
            trng,
        )
    }

    fn call(&mut self, cmd: u8, payload: &[u8]) -> (u8, Vec<u8>) {
        // Split, not `self.call_with_store(.., &mut self.store)`: the latter
        // borrows `self` mutably for the method call and again for the
        // argument.
        let mut store = core::mem::replace(&mut self.store, HostSecureStore::new());
        let out = self.call_with_store(cmd, payload, &mut store);
        self.store = store;
        out
    }

    /// [`Self::call`] against a store the test chooses, so a command that has
    /// to *fail* to persist can be driven without also failing the ones that
    /// had to succeed first (booting, `setPin`, minting a token all write).
    ///
    /// US-115: this exists for
    /// `config_write_answers_a_commit_failure_rather_than_a_0x00`, which needs
    /// an app that is already in the right state and a store that is not
    /// writable. Reusing the client's own store would mean the state had been
    /// built on the same medium that is about to fail.
    fn call_with_store(
        &mut self,
        cmd: u8,
        payload: &[u8],
        store: &mut dyn fapico2_platform::secure_store::SecureStore,
    ) -> (u8, Vec<u8>) {
        let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
        let n = self
            .app
            .process_ctap2_with_store(cmd, payload, [1, 2, 3, 4], &mut out, Some(store));
        (out[..n][0], out[..n][1..].to_vec())
    }

    /// The US-425/US-427 durable-before-ack gate, driven the way
    /// `firmware/src/tasks.rs`'s `persist_hid` drives it: flush whatever the
    /// command dirtied. Returns `true` when the store now holds the app's
    /// snapshot, which is the precondition the HID task requires before it
    /// will let a success reply go out.
    fn persist(&mut self) -> bool {
        self.app.keystore().persist_if_dirty(&mut self.store)
    }

    /// A fixed client key so every run derives the same shared secret; the
    /// token it mints is still whatever the device TRNG produces, so this
    /// buys reproducibility of the *client* side only.
    fn client_key() -> p256::SecretKey {
        p256::SecretKey::from_slice(&[0x99u8; 32]).expect("valid scalar")
    }

    /// `getKeyAgreement` → the v1 shared HMAC/enc keys.
    fn derive_keys(&mut self) {
        use fapico2_fido::cbor::no_heap::{Item, Parser};
        use fapico2_fido::crypto;
        let mut req: HV<u8, 64> = HV::new();
        nh::push_map_header(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        let (status, cbor) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00, "device getKeyAgreement failed");
        let mut p = Parser::new(&cbor);
        assert!(matches!(p.next(), Ok(Item::Map(1))));
        assert_eq!(p.next().unwrap(), Item::U(1));
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        let Item::Map(n) = p.next().unwrap() else { panic!("COSE key map") };
        for _ in 0..n {
            let key = match p.next().unwrap() {
                Item::U(u) => u as i64,
                Item::N(n) => n,
                _ => panic!("COSE key"),
            };
            match key {
                -2 => match p.next().unwrap() {
                    Item::B(b) => x.copy_from_slice(b),
                    _ => panic!("bstr x"),
                },
                -3 => match p.next().unwrap() {
                    Item::B(b) => y.copy_from_slice(b),
                    _ => panic!("bstr y"),
                },
                _ => p.skip().unwrap(),
            }
        }
        let device_pub = crypto::parse_cose_ec2_p256_bytes(&x, &y).expect("device pubkey");
        let raw = crypto::ecdh_shared_secret(&Self::client_key(), &device_pub);
        let k = crypto::derive_shared_secret_v1(&raw);
        self.hmac_key = k;
        self.enc_key = k;
    }

    fn push_client_key_agreement(&self, out: &mut HV<u8, 256>) {
        use fapico2_fido::crypto;
        let bytes = crypto::public_key_bytes(&Self::client_key().public_key());
        nh::push_map_header(out, 5).unwrap();
        nh::push_uint(out, 1).unwrap();
        nh::push_uint(out, 2).unwrap();
        nh::push_uint(out, 3).unwrap();
        nh::push_neg(out, -25).unwrap();
        nh::push_neg(out, -1).unwrap();
        nh::push_uint(out, 1).unwrap(); // crv = P-256
        nh::push_neg(out, -2).unwrap();
        nh::push_bstr(out, &bytes[1..33]).unwrap();
        nh::push_neg(out, -3).unwrap();
        nh::push_bstr(out, &bytes[33..65]).unwrap();
    }

    /// Protocol-1 shared-secret encryption: AES-256-CBC, zero IV, zero padding
    /// to a 16-byte multiple.
    fn v1_encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        use fapico2_fido::crypto;
        let mut padded = plaintext.to_vec();
        while !padded.len().is_multiple_of(16) {
            padded.push(0);
        }
        let mut buf = [0u8; 96];
        buf[..padded.len()].copy_from_slice(&padded);
        crypto::aes256_cbc_encrypt_into(&self.enc_key, &[0u8; 16], &mut buf[..padded.len()])
            .expect("CBC encrypt");
        buf[..padded.len()].to_vec()
    }

    fn set_pin(&mut self, pin: &[u8]) {
        use fapico2_fido::crypto;
        self.derive_keys();
        let pin_enc = self.v1_encrypt(pin);
        let tag = crypto::hmac_sha256(&self.hmac_key, &pin_enc)[..16].to_vec();
        // {1: pinUvAuthProtocol, 2: subCommand, 3: keyAgreement,
        //  4: pinHashAuth, 5: newPinEnc} — five pairs, keys in order.
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap(); // pinUvAuthProtocol 1
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 3).unwrap(); // setPIN (CTAP2 clientPin numbering)
        nh::push_uint(&mut req, 3).unwrap();
        self.push_client_key_agreement(&mut req);
        nh::push_uint(&mut req, 4).unwrap();
        nh::push_bstr(&mut req, &tag).unwrap();
        nh::push_uint(&mut req, 5).unwrap();
        nh::push_bstr(&mut req, &pin_enc).unwrap();
        let (status, _) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00, "device setPIN failed");
    }

    /// `getPinUvAuthTokenUsingPinWithPermissions` (0x09) with a permissions
    /// byte (key 9) → the raw 32-byte token.
    ///
    /// The US-112 twin of [`Self::get_pin_token`]: the device stack's
    /// `clientPin` accepts sub-command `0x09` and CBOR key `9` as a single
    /// unsigned integer (`device_core.rs`'s `client_pin`), so this is the same
    /// request with one more key pair and a different sub-command. Needed
    /// because a token with permission byte `0` is exactly the case a gate
    /// would refuse, and testing "the gate is not wired" against a
    /// zero-permission token would prove nothing.
    fn get_pin_token_with_permissions(&mut self, pin: &[u8], permissions: u8) -> [u8; 32] {
        use fapico2_fido::cbor::no_heap::{Item, Parser};
        use fapico2_fido::crypto;
        let pin_hash = crypto::pin_hash(pin);
        let pin_hash_enc = self.v1_encrypt(&pin_hash);
        // Keys 1, 2, 3, 6, 9 in ascending order — CTAP2 canonical CBOR.
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        self.push_client_key_agreement(&mut req);
        nh::push_uint(&mut req, 6).unwrap();
        nh::push_bstr(&mut req, &pin_hash_enc).unwrap();
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, permissions as u64).unwrap();
        let (status, cbor) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00, "device getPinUvAuthTokenUsingPinWithPermissions failed");
        let mut p = Parser::new(&cbor);
        assert!(matches!(p.next(), Ok(Item::Map(1))));
        assert_eq!(p.next().unwrap(), Item::U(2));
        let Item::B(ct) = p.next().unwrap() else { panic!("bstr token") };
        let mut buf = [0u8; 96];
        buf[..ct.len()].copy_from_slice(ct);
        crypto::aes256_cbc_decrypt_into(&self.enc_key, &[0u8; 16], &mut buf[..ct.len()])
            .expect("CBC decrypt");
        let mut token = [0u8; 32];
        token.copy_from_slice(&buf[..32]);
        token
    }

    /// `getPinToken` → the raw 32-byte token.
    fn get_pin_token(&mut self, pin: &[u8]) -> [u8; 32] {
        use fapico2_fido::cbor::no_heap::{Item, Parser};
        use fapico2_fido::crypto;
        let pin_hash = crypto::pin_hash(pin);
        let pin_hash_enc = self.v1_encrypt(&pin_hash);
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 4).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        self.push_client_key_agreement(&mut req);
        nh::push_uint(&mut req, 6).unwrap();
        nh::push_bstr(&mut req, &pin_hash_enc).unwrap();
        let (status, cbor) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00, "device getPinToken failed");
        let mut p = Parser::new(&cbor);
        assert!(matches!(p.next(), Ok(Item::Map(1))));
        assert_eq!(p.next().unwrap(), Item::U(2));
        let Item::B(ct) = p.next().unwrap() else { panic!("bstr token") };
        let mut buf = [0u8; 96];
        buf[..ct.len()].copy_from_slice(ct);
        crypto::aes256_cbc_decrypt_into(&self.enc_key, &[0u8; 16], &mut buf[..ct.len()])
            .expect("CBC decrypt");
        let mut token = [0u8; 32];
        token.copy_from_slice(&buf[..32]);
        token
    }
}

// ---------------------------------------------------------------------------
// US-112: the per-sub-command permission table.
// ---------------------------------------------------------------------------

use fapico2_fido::vendor41::{authorize, required_permission, Requirement, TokenAuth};

/// CTAP2.1 `CTAP2_ERR_UNAUTHORIZED_PERMISSION`.
const UNAUTHORIZED_PERMISSION: u8 = 0x40;

/// The status [`authorize`] produced, as the byte that goes on the wire — the
/// `status_byte` twin for the permission gate, whose `Ok` arm carries no
/// payload to pattern on.
fn gate_status(r: Result<(), fapico2_fido::ctap2::Ctap2Response>) -> u8 {
    match r {
        Ok(()) => 0x00,
        Err(c) => c as u8,
    }
}

/// `AUTHENTICATOR_CONFIG` — `picoforge/src/hal/fido/constants.rs:309`.
const PERM_ACFG_LITERAL: u8 = 0x20;
/// `CREDENTIAL_MANAGEMENT` — `picoforge/src/hal/fido/constants.rs:310`.
const PERM_CM_LITERAL: u8 = 0x04;

/// What the real client actually sends for each sub-command, as test-side
/// literal data: the `pin` argument its `rs_key_vendor` call site passes, the
/// `picoforge` line number, and therefore whether a token reaches the wire.
///
/// This is the durable half of US-112's fix. `rs_key_vendor`
/// (`picoforge/src/hal/fido/ops.rs:1556-1586`) mints and attaches a `0x20`
/// token **only when `pin` is `Some`**; with `None` it sends no key 3 and no
/// key 4, and says why in its own comment — *"Without one, the firmware gates
/// on a physical touch instead, so no auth fields are sent."* So the call
/// site's `pin` argument *is* the protocol's answer to "is this gated", and
/// reading it once per row is the only way to know.
///
/// An earlier revision of this story inferred the whole table from "the client
/// mints `0x20`" and got twelve of these rows wrong — six tokenless and six
/// PIN-or-touch, all of them `TokenOptional` rather than `Permission` — in a
/// direction that would
/// have answered `0x40` to `backup_status`, `att_status`, `lock_unlock` and
/// `audit_status` — four calls whose own doc comments say "ungated" — the
/// moment a Phase I story wired the gate. Nothing would have failed until
/// then, which is why the call sites are pinned here as literals.
///
/// `Call` is spelled as data rather than re-derived from `mod.rs` at test
/// time: a test that read the client would agree with the client by
/// construction and would catch nothing when the client changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    /// `rs_key_vendor(…, None)` — no token is ever attached.
    Tokenless,
    /// `rs_key_vendor(…, pin.as_deref())` — a token only if the caller has one.
    TokenOptional,
    /// Reached only via a helper that takes the token as an argument, so a
    /// `0x20` token is always in hand.
    TokenRequired,
    /// Not a `0x41` call at all: built and sent with no auth fields because
    /// the protocol defines no authenticated form of it.
    NoAuthForm,
}

const PIN_PERMISSIONS_REQUIRED: u8 = 0x20;

/// Every sub-command, the family it belongs to, the call site, and the
/// requirement that call site implies.
const EXPECTED: &[(Subcommand, Requirement, &str, Call, &str)] = &[
    // --- Config family. `rs_key_config_read` / `rs_key_config_write`. ---
    (
        Subcommand::ConfigRead,
        Requirement::Ungated,
        "Config",
        Call::NoAuthForm,
        "ops.rs:1461-1479 via mod.rs:1163-1166 (0x41 feature probe, pre-token)",
    ),
    (
        Subcommand::ConfigWrite,
        Requirement::Permission(PIN_PERMISSIONS_REQUIRED),
        "Config",
        Call::TokenRequired,
        "ops.rs:1514-1534 via mod.rs:1168, :1310, :2057, :2093 (token is a parameter)",
    ),
    // --- Backup family. ---
    (
        Subcommand::Mse,
        Requirement::TokenOptional(PIN_PERMISSIONS_REQUIRED),
        "Backup",
        Call::Tokenless,
        "mod.rs:1709",
    ),
    (
        Subcommand::Export,
        Requirement::TokenOptional(PIN_PERMISSIONS_REQUIRED),
        "Backup",
        Call::TokenOptional,
        "mod.rs:1771 (backup_export, \"PIN or touch gated\")",
    ),
    (
        Subcommand::Load,
        Requirement::TokenOptional(PIN_PERMISSIONS_REQUIRED),
        "Backup",
        Call::TokenOptional,
        "mod.rs:1797 (backup_restore, \"PIN or touch gated\")",
    ),
    (
        Subcommand::Finalize,
        Requirement::TokenOptional(PIN_PERMISSIONS_REQUIRED),
        "Backup",
        Call::Tokenless,
        "mod.rs:1757 (backup_finalize, \"touch-gated\")",
    ),
    // --- Lock family. `lock_enable` / `lock_disable`'s authenticatorConfig
    // vendor-prototype calls (mod.rs:1847/:1874) are NOT this channel. ---
    (
        Subcommand::State,
        Requirement::TokenOptional(PIN_PERMISSIONS_REQUIRED),
        "Lock",
        Call::Tokenless,
        "mod.rs:1741 (backup_status, \"(ungated)\")",
    ),
    (
        Subcommand::Unlock,
        Requirement::TokenOptional(PIN_PERMISSIONS_REQUIRED),
        "Lock",
        Call::Tokenless,
        "mod.rs:1826, :1867 (lock_unlock, \"Ungated over the 0x41 channel\")",
    ),
    // --- Audit family. ---
    (
        Subcommand::AuditRead,
        Requirement::TokenOptional(PIN_PERMISSIONS_REQUIRED),
        "Audit",
        Call::TokenOptional,
        "mod.rs:1573 (audit_log / audit_verify, \"PIN or touch gated\")",
    ),
    (
        Subcommand::AuditCheckpoint,
        Requirement::TokenOptional(PIN_PERMISSIONS_REQUIRED),
        "Audit",
        Call::TokenOptional,
        "mod.rs:1611 (audit_verify, \"PIN or touch gated\")",
    ),
    (
        Subcommand::AuditConfig,
        Requirement::TokenOptional(PIN_PERMISSIONS_REQUIRED),
        "Audit",
        Call::Tokenless,
        "mod.rs:1653 (audit_status, \"ungated status query, no touch\")",
    ),
    // --- Attestation family. ---
    (
        Subcommand::AttImport,
        Requirement::TokenOptional(PIN_PERMISSIONS_REQUIRED),
        "Attestation",
        Call::TokenOptional,
        "mod.rs:1987 (att_import, PIN/touch)",
    ),
    (
        Subcommand::AttClear,
        Requirement::TokenOptional(PIN_PERMISSIONS_REQUIRED),
        "Attestation",
        Call::TokenOptional,
        "mod.rs:1916 (att_clear, \"needs an MSE channel, then PIN/touch\")",
    ),
    (
        Subcommand::AttState,
        Requirement::TokenOptional(PIN_PERMISSIONS_REQUIRED),
        "Attestation",
        Call::Tokenless,
        "mod.rs:1895 (att_status, \"(ungated)\")",
    ),
];

/// Every sub-command has a row, and the row's *shape* is the one the client's
/// call site implies.
///
/// This is the table test proper; the client-parity assertion that carries the
/// same evidence is
/// [`vendor41_permission_table_matches_the_picoforge_call_sites`], which is
/// where a wrong row actually gets caught. Kept as two tests because they fail
/// for different reasons: this one fails when a row was never added, the other
/// when a row is present and wrong.
#[test]
fn vendor41_required_permission_covers_every_subcommand() {
    assert_eq!(
        EXPECTED.len(),
        Subcommand::ALL.len(),
        "the expectation table and the protocol enumeration have drifted \
         apart; every sub-command needs a row, and the table is what the \
         compile-time exhaustiveness of required_permission cannot check",
    );
    for (sub, expected, family, _call, site) in EXPECTED {
        assert_eq!(
            required_permission(*sub),
            *expected,
            "{:?} (family {family}, {site}) has the wrong requirement. \
             Only AUTHENTICATOR_CONFIG is ever minted for a 0x41 \
             sub-command, and most of them are sent with no token at all",
            sub.byte(),
        );
    }
    let ungated: Vec<u8> = Subcommand::ALL
        .iter()
        .filter(|s| required_permission(**s) == Requirement::Ungated)
        .map(|s| s.byte())
        .collect();
    assert_eq!(
        ungated,
        vec![0x0Du8],
        "exactly one sub-command is ungated, and it is CONFIG_READ (0x0D) — \
         PicoForge sends it with no MAC and no token and uses it as the \
         feature probe for 0x41 support, so gating it would report a \
         working token as one without FIDO configuration",
    );
}

/// # The client-parity test
///
/// For each sub-command, the requirement in the table must be the one the real
/// client actually implies at its `picoforge` call site — and the two are
/// checked against each other directly, not merely both written down.
///
/// The mapping asserted is:
///
/// | the client does | the row must be |
/// |---|---|
/// | never sends a token (`pin: None`) | `TokenOptional(0x20)` |
/// | sends one only if it has one (`pin.as_deref()`) | `TokenOptional(0x20)` |
/// | always holds a `0x20` token (token is a helper parameter) | `Permission(0x20)` |
/// | has no authenticated form at all | `Ungated` |
///
/// The first two collapse to the same row deliberately — a tokenless request
/// and a token-optional request are the same thing to the gate — but they are
/// kept as two literals in [`Call`] so the test can also count them, because
/// "how much of this channel is unauthenticated" is worth knowing and would
/// otherwise be lost the moment the table stops caring.
#[test]
fn vendor41_permission_table_matches_the_picoforge_call_sites() {
    for (sub, expected, family, call, site) in EXPECTED {
        let required = match call {
            // No token ever reaches the wire. Refusing it would be refusing
            // the client's normal call, not an unauthenticated one.
            Call::Tokenless | Call::TokenOptional => Requirement::TokenOptional(
                PIN_PERMISSIONS_REQUIRED,
            ),
            Call::TokenRequired => Requirement::Permission(PIN_PERMISSIONS_REQUIRED),
            Call::NoAuthForm => Requirement::Ungated,
        };
        // Against the *implementation*, not against the `expected` column.
        // Asserting `expected == required` would only prove the two test-side
        // tables agree with each other: a wrong row in `required_permission`
        // would sail through as long as the literals were written to match it.
        // A mutation check (`State` flipped from `TokenOptional` to
        // `Permission`) is what caught that, and this is the assertion it
        // should have been failing.
        assert_eq!(
            required_permission(*sub), required,
            "{:?} (family {family}, {site}): the table says {:?} but the \
             client sends {:?}. These must not drift — a tokenless request \
             answered 0x40 breaks a screen the client documents as ungated, \
             and a token-required row loosened to optional drops the \
             device-config write's only authorisation",
            sub.byte(),
            *expected,
            call,
        );
    }
    let tokenless = EXPECTED
        .iter()
        .filter(|(_, _, _, call, _)| *call == Call::Tokenless)
        .count();
    let optional = EXPECTED
        .iter()
        .filter(|(_, _, _, call, _)| *call == Call::TokenOptional)
        .count();
    assert_eq!(
        (tokenless, optional),
        (6, 6),
        "the client's 0x41 call sites changed: recount which sub-commands are \
         sent bare (mod.rs:1709, :1757, :1741, :1826/:1867, :1653, :1895) and \
         which are PIN-or-touch (:1771, :1797, :1573, :1611, :1987, :1916), \
         then update both the literals and this count",
    );
}

/// A `CREDENTIAL_MANAGEMENT`-only token is refused on every row that consults
/// a permission at all, including the token-optional ones.
///
/// The optional rows must not become a loophole: the client attaches a token
/// when it has one, and the only token it ever attaches carries `0x20`. So
/// "optional" is about the *absence* of a token, never about a token that
/// lacks the bit. An implementation that returned `Ok(())` for any token on a
/// `TokenOptional` row would pass the ungated tests and fail this one, and it
/// would be a real escalation: a `credentialManagement` session could read
/// the seed export and rewrite device configuration.
#[test]
fn vendor41_token_optional_rows_still_require_the_bit() {
    for (sub, _expected, family, _call, site) in EXPECTED {
        // Read the *implementation*, not the `expected` column: filtering on
        // the literal would skip exactly the row whose variant had just been
        // changed, which is the one this test exists to catch.
        if required_permission(*sub) == Requirement::Ungated {
            continue;
        }
        assert_eq!(
            gate_status(authorize(*sub, Some(PERM_CM_LITERAL))),
            UNAUTHORIZED_PERMISSION,
            "{:?} (family {family}, {site}) is {:?}, but a \
             CREDENTIAL_MANAGEMENT-only token must still be refused with 0x40: \
             optional means the token may be absent, not that any token \
             suffices",
            sub.byte(),
            required_permission(*sub),
        );
    }
}

/// The gate is built and **not yet consulted from dispatch**.
///
/// US-111's twin of this test proves the MAC verifier is not reachable from
/// dispatch, using a request that no app could satisfy (there is no token in
/// hand, so a wired verifier would answer `0x36`). That direction is
/// necessary but not sufficient: a gate could be switched on for *refusals*
/// only and that test would still pass. So this one takes the permissive
/// direction — a real `0x20` token minted by each stack's own `clientPin`, a
/// MAC computed with it, `CONFIG_WRITE` as the sub-command — and requires
/// `0x30` on both command paths.
///
/// `0x40` or `0x33` here would mean the permission gate (or the verifier) had
/// started answering before any sub-command is implemented, which is not this
/// story's decision to make: no sub-command exists to enforce anything for.
///
/// # Why `CONFIG_WRITE` specifically
///
/// Because it is the one sub-command a gate gets *right* today, so a wired
/// gate is observable here. The tokenless direction — the case the twelve
/// `TokenOptional` rows exist for — is covered elsewhere and does not need
/// repeating: `unimplemented_vendor_subcommand_returns_2b` drives all fourteen
/// sub-commands with no token and no MAC through **both** dispatch paths, and
/// `vendor41_stub_never_charges_pin_auth_failure` drives all fourteen through
/// `handle` with a `0x20` token in hand. Between them, no sub-command and no
/// token state is left untested at the stub boundary.
/// # US-1516: this test is **vacuous today**, and that is its finding
///
/// [`PENDING`] is empty, so the loop below runs zero times and this asserts
/// nothing at all. It is not broken and it is not a stub-era leftover to
/// delete: it is the guard that fires the moment a sub-command is added back
/// to the stub set, which is the one thing keeping [`PENDING`] honest. What was
/// wrong was the doc comment above, which claimed active enforcement.
/// See the US-1516 section of this file's module docs for all six such tests
/// and for why a green test that has quietly stopped testing is the sharper
/// version of the problem US-1516 was raised about.
#[test]
fn vendor41_permission_gate_is_not_yet_wired_into_the_stubs() {
    // The EPIC's acceptance bullet for US-112 was that a `CONFIG_WRITE` with
    // a real `0x20` token is admitted by `authorize` while the sub-command
    // still answers `0x30` — i.e. the gate is built, tested, and deliberately
    // not reached. US-115 implemented that sub-command, so the leg is gone and
    // the test keeps its name for the remaining twelve.
    //
    // What replaces the missing leg is worth stating, because the old
    // premise ("a wired gate would answer 0x40 here") no longer holds for any
    // row that is left: the twelve stubs are all `TokenOptional` or `Ungated`,
    // so `authorize` *admits* every one of them. The property that is still
    // worth protecting is therefore the one stated above — reaching the
    // permission table or the MAC verifier at all, for a sub-command with no
    // implementation, is a change that must show up as a failing assertion.
    // The *permissive* direction is kept (a genuine `0x20` token is presented
    // and the answer is still `0x30`) precisely so that a gate switched on for
    // the right tokens and off for the rest cannot pass this either.
    let (mut host, host_client) = common::setup();
    let host_token: [u8; 32] = host_client
        .get_token(&mut host, 0x09, Some(PERM_ACFG_LITERAL), None)
        .expect("getPinUvAuthTokenUsingPinWithPermissions(ACFG) must succeed")
        .try_into()
        .expect("a pinUvAuth token is 32 bytes");

    for &sub in fapico2_fido::vendor41::PENDING {
        let params = config_write_params(TARGET_PHY_LITERAL, &phy_blob(&[(TAG_LED_GPIO, &[0x04])]));
        let mac = picoforge_mac(&host_token, VENDOR_41, sub.byte(), &params);
        let req = rskey_request_with_mac(sub.byte(), &params, Some(1), Some(&mac));
        // The precondition, so the assertion below cannot pass for the wrong
        // reason: with this exact token the MAC does verify, and the
        // permission table admits the sub-command. Only "not consulted yet"
        // can explain a 0x30.
        assert_eq!(
            status_byte(fapico2_fido::vendor41::verify_mac(&req, Some(&host_token))),
            0x00,
            "precondition for {sub:?}: the MAC over the real token verifies"
        );
        assert_eq!(
            authorize(sub, Some(PERM_ACFG_LITERAL)),
            Ok(()),
            "precondition for {sub:?}: 0x20 is accepted by the table"
        );
        assert_eq!(
            host.process_ctap2(VENDOR_41, &req, [1, 2, 3, 4]).as_slice(),
            [NOT_ALLOWED],
            "a correctly authenticated request for {sub:?} must still answer \
             NOT_ALLOWED — it is a stub. 0x40 or 0x33 here would mean the \
             permission table or the verifier started answering for a \
             sub-command with no implementation"
        );
    }

    // The device twin, driven with a token minted by *its* `clientPin` — the
    // two stacks mint those through two separate implementations, and a host
    // token is not a device token.
    let (mut dev, _trng) = DevicePinClient::boot();
    dev.set_pin(b"1234");
    let dev_token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);
    for &sub in fapico2_fido::vendor41::PENDING {
        let params = config_write_params(TARGET_PHY_LITERAL, &phy_blob(&[(TAG_LED_GPIO, &[0x04])]));
        let mac = picoforge_mac(&dev_token, VENDOR_41, sub.byte(), &params);
        let (status, _) = dev.call(VENDOR_41, &rskey_request_with_mac(sub.byte(), &params, Some(1), Some(&mac)));
        assert_eq!(
            status, NOT_ALLOWED,
            "device: {sub:?} is still a stub, so a correctly authenticated \
             request must answer NOT_ALLOWED here too"
        );
    }

    // The one row the table is *strict* about is now a real arm, and it is
    // wired. Asserting that is what keeps this test from outliving its own
    // premise: if a later story re-stubbed `CONFIG_WRITE`, this leg would say
    // so rather than leaving the name to imply it.
    assert_eq!(
        required_permission(Subcommand::ConfigWrite),
        Requirement::Permission(PERM_ACFG_LITERAL),
        "`CONFIG_WRITE` is still the protocol's only strictly-required-token \
         row, and it is the row the implemented identity tier enforces"
    );
    assert!(
        !fapico2_fido::vendor41::PENDING.contains(&Subcommand::ConfigWrite),
        "and it is no longer a stub — if this fails, a real arm exists for it \
         and the rest of this test's premise needs revisiting"
    );
}

/// The stub path never asks the app to charge a PIN-auth failure.
///
/// [`Outcome::pin_auth_failure`] is the whole of the US-112 lockout seam, and
/// it is the one piece of this story that could be wired up wrongly in a way
/// no status test would see: a stub that set it would increment the app's
/// three-strike counter on **every** `0x41` request, and three reads of a
/// config screen would latch `needs_power_cycle` against a user who never
/// failed anything. Nothing about the returned status would change — it would
/// still be `0x30` — so the status tests above cannot see it.
///
/// The stub is exercised with a token in hand, because that is the case where
/// a future edit has every opportunity to charge.
///
/// Iterates [`PENDING`] rather than [`Subcommand::ALL`], for the same reason
/// `unimplemented_vendor_subcommand_returns_2b` does: the protocol table is
/// permanent and the stub set shrinks, so walking the former would make this
/// test fail the day the second real arm lands — turning a contract into a
/// change-detector. `CONFIG_READ` is real as of US-114, and the second leg
/// below is what says it still does not charge.
/// # US-1516: this test is **vacuous today**, and that is its finding
///
/// [`PENDING`] is empty, so the loop below runs zero times and this asserts
/// nothing at all. It is not broken and it is not a stub-era leftover to
/// delete: it is the guard that fires the moment a sub-command is added back
/// to the stub set, which is the one thing keeping [`PENDING`] honest. What was
/// wrong was the doc comment above, which claimed active enforcement.
/// See the US-1516 section of this file's module docs for all six such tests
/// and for why a green test that has quietly stopped testing is the sharper
/// version of the problem US-1516 was raised about.
#[test]
fn vendor41_stub_never_charges_pin_auth_failure() {
    let auth = Some(TokenAuth {
        token: &GOLDEN_TOKEN,
        permissions: PERM_ACFG_LITERAL,
        blocked: false,
    });
    for sub in fapico2_fido::vendor41::PENDING {
        let outcome = handle_isolated(
            &rskey_request_with_mac(sub.byte(), &GOLDEN_PARAMS, Some(1), Some(&GOLDEN_MAC)),
            auth,
            &fapico2_fido::vendorff::PhyConfig::default(),
            fapico2_fido::vendor41::PresenceGate::default(),
            &mut HV::new(),
        );
        assert_eq!(
            outcome.status,
            fapico2_fido::ctap2::Ctap2Response::NotAllowed,
            "{:?} is still a stub and must answer NOT_ALLOWED",
            sub.byte(),
        );
        assert!(
            !outcome.pin_auth_failure,
            "{:?} answered without ever looking at the pinUvAuthParam, so it \
             must not ask the app to charge a PIN-auth failure — three config \
             reads would otherwise latch the three-strike lockout",
            sub.byte(),
        );
    }

    // `CONFIG_READ` is the one implemented arm, and it is ungated by
    // protocol, so it looks at neither the token nor the MAC. That is exactly
    // why the flag must stay clear: an arm that *did* look at a
    // `pinUvAuthParam` it is entitled to ignore would charge a three-strike
    // lockout against a caller who failed nothing.
    let outcome = handle_isolated(
        &rskey_request_with_mac(0x0D, &GOLDEN_PARAMS, Some(1), Some(&GOLDEN_MAC)),
        auth,
        &fapico2_fido::vendorff::PhyConfig::default(),
        fapico2_fido::vendor41::PresenceGate::default(),
        &mut HV::new(),
    );
    assert!(
        !outcome.pin_auth_failure,
        "CONFIG_READ never consults the MAC — PicoForge sends it with no token \
         and no key 3/4 — so a `pinUvAuthParam` riding along must not be \
         charged as a failed authentication",
    );
}

// ---------------------------------------------------------------------------
// US-112 review follow-ups: the presence obligation, the latch on `TokenAuth`,
// and the escalation seam observed end to end.
// ---------------------------------------------------------------------------

/// # The presence obligation is a named function, not a paragraph
///
/// [`requires_presence_when_tokenless`] returns `true` for exactly the twelve
/// `TokenOptional` rows — the sub-commands the client sends bare, and which
/// the client expects the firmware to gate on a physical touch instead
/// (`picoforge/src/hal/fido/ops.rs:1573-1575`).
///
/// The reason this is a function and not ten lines of module doc is that the
/// opposite of a doc line is already a **passing test**:
/// `pin_perms::token_optional_rows_admit_a_tokenless_request` asserts that a
/// tokenless request clears `authorize` for all twelve, and two of them are
/// `Export` ("read the encrypted master seed") and `State` (`has_seed` /
/// `locked`). An implementer who reads that as a green light, implements
/// `Export`, and wires the gate has shipped an unguarded seed read with no
/// touch requirement either — and the suite is still green. A named function
/// that returns `true` for those rows is greppable, and a Phase I arm can
/// call it rather than infer the obligation.
///
/// It **reports** the obligation; it does not discharge it. Nothing calls it
/// yet, and `pin_perms::TODO_us1xx_presence_gate_covers_every_tokenless_row`
/// is `#[ignore]`d with the twelve sub-commands listed, so the debt is also
/// visible as a test that fails the moment anyone runs it.
#[test]
fn vendor41_presence_obligation_covers_every_tokenless_row() {
    use fapico2_fido::vendor41::requires_presence_when_tokenless;
    let obligated: Vec<u8> = Subcommand::ALL
        .iter()
        .filter(|s| requires_presence_when_tokenless(**s))
        .map(|s| s.byte())
        .collect();
    assert_eq!(
        obligated,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0E,
        ],
        "the presence obligation must cover every TokenOptional row and \\
         nothing else. A row added here without a presence gate ships an \\
         unauthenticated operation; a row removed here is one the client \\
         sends bare with no gate at all. 1,2,3,4 (backup), 5,6 (lock), \\
         7,8,0x0E (audit), 9,0x0A,0x0B (attestation) — CONFIG_READ 0x0D is \\
         excluded (no authenticated form) and CONFIG_WRITE 0x0C is excluded \\
         (a tokenless request is refused 0x40, so there is nothing to gate)",
    );
    // The two exclusions are the interesting half, and each is a claim that
    // could quietly become false.
    assert!(
        !requires_presence_when_tokenless(Subcommand::ConfigWrite),
        "CONFIG_WRITE refuses a tokenless request outright, so it has no \\
         tokenless path to gate. Answering true here would assert a touch \\
         fallback for the one sub-command that must never have one",
    );
    assert!(
        !requires_presence_when_tokenless(Subcommand::ConfigRead),
        "CONFIG_READ has no authenticated form at all by protocol, so the \\
         predicate has nothing to say about it; whether that exposure is \\
         acceptable is the module docs' question, not this function's",
    );
}

/// # Finding 3: the latch travels with the token, and is not consulted yet
///
/// `TokenAuth::blocked` exists because the `0x41` seam bypasses `verify_token`
/// — the place where CTAP2.1 §6.5.7's three-strike check lives on both paths.
/// A Phase I arm composing `verify_mac` + `authorize` and ignoring the latch
/// would keep serving requests during a lockout.
///
/// This pins the current state precisely, in both directions:
///
/// * **plumbed** — the app does fill `blocked` from its own
///   `needs_power_cycle`, so an arm has the value available;
/// * **consulted, narrowly** — since US-115 exactly one place on this channel
///   reads it: [`Subcommand::ConfigWrite`]'s *identity* tier, which answers
///   `0x34` (`PIN_AUTH_BLOCKED`) however well the request is signed. The
///   *benign* tier is deliberately unaffected, and that asymmetry is the
///   substantive claim: the latch is a **pinUvAuth** latch (CTAP2.1 §6.5.7),
///   and a benign write presents no pinUvAuth, so letting the latch refuse it
///   would turn a PIN typo into a config screen that needs a power cycle.
///
/// The name changed with the behaviour. While every sub-command was a stub the
/// test was `..._but_nothing_reads_it_yet`, and the "nothing reads it" half was
/// a real observation about a real state. Keeping that name would have left a
/// test whose name says the opposite of what it asserts.
#[test]
fn vendor41_token_auth_reports_the_latch_and_only_the_identity_tier_reads_it() {
    use fapico2_fido::vendor41::set_escalation_test_sub;

    // --- host twin ---
    let (mut host, host_client) = common::setup();
    assert!(
        !host.keystore().get_pin_state().needs_power_cycle,
        "precondition: a fresh host app is not latched",
    );
    // The token is minted **before** the strikes, not after, and that ordering
    // is load-bearing: a successful `clientPin` clears `needs_power_cycle`
    // (`apps/fido/src/pin.rs`), so minting afterwards would un-latch the app
    // and the assertion below would be testing a device that is no longer in
    // the state it claims to be in.
    let host_token: [u8; 32] = host_client
        .get_token(&mut host, 0x09, Some(PERM_ACFG_LITERAL), None)
        .expect("getPinUvAuthTokenUsingPinWithPermissions(ACFG)")
        .try_into()
        .expect("a pinUvAuth token is 32 bytes");
    {
        let _guard = set_escalation_test_sub(Some(Subcommand::ConfigWrite));
        for _ in 0..3 {
            host.process_ctap2(VENDOR_41, &rskey_request(0x0C), [1, 2, 3, 4]);
        }
    }
    assert!(
        host.keystore().get_pin_state().needs_power_cycle,
        "the host app must latch, so that TokenAuth::blocked has a true value \
         to carry for the assertion below",
    );
    // An *identity* blob, because that is the only tier that authenticates.
    // The benign tier is below, and it must be untouched by the latch.
    let blob = phy_blob(&[(TAG_VIDPID, &VIDPID_BYTES)]);
    let mac = picoforge_mac(&host_token, VENDOR_41, 0x0C, &config_write_params(TARGET_PHY_LITERAL, &blob));
    assert_eq!(
        host.process_ctap2(
            VENDOR_41,
            &rskey_request_with_mac(0x0C, &config_write_params(TARGET_PHY_LITERAL, &blob), Some(1), Some(&mac)),
            [1, 2, 3, 4],
        )
        .as_slice(),
        [PIN_AUTH_BLOCKED],
        "a latched app must answer 0x34 for an identity-field CONFIG_WRITE \
         however well it is signed. Since US-115 this is the only place on the \
         channel that reads TokenAuth::blocked, and it reads it in the right \
         direction: refusing all pinUvAuth, rather than answering 0x36 or 0x33 \
         and sending the client back to the PIN prompt for a token that is \
         perfectly good",
    );

    // --- device twin ---
    //
    // This leg needs an app that is *both* holding a token and latched, and
    // `device_app()` gives neither — a fresh device app has no PIN, so
    // `self.pin_token` is `None` and the arm answers `0x36` before it ever
    // looks at the latch. `DevicePinClient` is what mints one.
    let mut dev = DevicePinClient::boot().0;
    dev.set_pin(b"1234");
    // Minted before the strikes, because a successful `clientPin` clears
    // `needs_power_cycle`.
    let dev_token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);
    assert!(
        !dev.app.keystore().pin_state.needs_power_cycle,
        "precondition: a device with a fresh PIN is not latched",
    );
    {
        let _guard = fapico2_fido::vendor41::set_escalation_test_sub(Some(Subcommand::ConfigWrite));
        for _ in 0..3 {
            dev.call(VENDOR_41, &rskey_request(0x0C));
        }
    }
    assert!(
        dev.app.keystore().pin_state.needs_power_cycle,
        "the device app must latch, and it also sets `blocked` and `dirty` \
         alongside `needs_power_cycle` (device_core.rs's \
         note_pin_auth_failure)",
    );

    // An *identity* blob, because that is the only tier that authenticates.
    // The benign tier is below, and it must be untouched by the latch.
    let blob = phy_blob(&[(TAG_VIDPID, &VIDPID_BYTES)]);
    let params = config_write_params(TARGET_PHY_LITERAL, &blob);
    let mac = picoforge_mac(&dev_token, VENDOR_41, 0x0C, &params);
    let (status, _) = dev.call(
        VENDOR_41,
        &rskey_request_with_mac(0x0C, &params, Some(1), Some(&mac)),
    );
    assert_eq!(
        status, PIN_AUTH_BLOCKED,
        "device: a latched app must answer 0x34 for an identity-field \
         CONFIG_WRITE however well it is signed, and must do so with the token \
         it already holds rather than with none — the two command paths are \
         separate matches, so passing on the host twin says nothing about this \
         one"
    );

    // The other half, and the reason the test is not simply "the latch works":
    // the benign tier must be **unaffected** by a pinUvAuth latch. The latch
    // is a pinUvAuth latch — it exists because CTAP2.1 §6.5.7 says so — and
    // the benign tier uses no pinUvAuth, so a latch that refused it would be
    // refusing a physical touch for a PIN failure it has nothing to do with.
    // That would make a token typo into a bricked config screen until a power
    // cycle, which is a worse outcome than the one the latch prevents.
    //
    // The device app has no presence probe attached (`presence_grant` is
    // `None` here), so `PresenceGate::default()` resolves through
    // `default_user_present()`, which auto-acks on a host build. That is the
    // same default `user_present` uses, so this leg is testing the latch's
    // *scope* and not the presence tier.
    let benign = phy_blob(&[(TAG_LED_GPIO, &[0x04])]);
    let benign_params = config_write_params(TARGET_PHY_LITERAL, &benign);
    let benign_mac = picoforge_mac(&dev_token, VENDOR_41, 0x0C, &benign_params);
    let (status, _) = dev.call(
        VENDOR_41,
        &rskey_request_with_mac(0x0C, &benign_params, Some(1), Some(&benign_mac)),
    );
    assert_eq!(
        status, 0x00,
        "a latched app must still accept a benign-tier CONFIG_WRITE given a \
         presence grant. The latch gates pinUvAuth; the benign tier has none, \
         and its authority is the touch",
    );
}

/// # Finding 2: the escalation seam, observed
///
/// The commit's central claim is that a Phase I arm gets the three-strike
/// latch and the `0x34` status for free, by returning
/// [`Outcome::pin_auth_failure`]. Before this test, **no test on either path
/// ever set that flag** — the only test that touched it asserted it was
/// `false` — so the claim was true by reading and unobserved.
///
/// `set_escalation_test_sub` (host builds only, and verified absent from the
/// RP2350 firmware) makes one sub-command answer exactly as an arm does when
/// [`verify_mac`] refuses a `pinUvAuthParam`]. Everything after that is the
/// real thing: the real dispatch arm, the real private
/// `note_pin_auth_failure`, the real latch.
///
/// The expected sequence is `0x33`, `0x33`, `0x34`: CTAP2.1 §6.5.7 latches on
/// the third *consecutive* failure, and the counter is the volatile streak —
/// not the durable latch, which is what survives.
#[test]
fn vendor41_escalation_reaches_pin_auth_blocked_on_the_third_failure() {
    use fapico2_fido::vendor41::set_escalation_test_sub;
    const PIN_AUTH_BLOCKED: u8 = 0x34;

    // --- host path ---
    let (mut host, _client) = common::setup();
    {
        let _guard = set_escalation_test_sub(Some(Subcommand::ConfigWrite));
        let statuses: Vec<u8> = (0..3)
            .map(|_| {
                host.process_ctap2(VENDOR_41, &rskey_request(0x0C), [1, 2, 3, 4])[0]
            })
            .collect();
        assert_eq!(
            statuses,
            vec![PIN_AUTH_INVALID, PIN_AUTH_INVALID, PIN_AUTH_BLOCKED],
            "host: the first two rejected MACs answer 0x33 and the third \
             answers 0x34. This is the whole point of the Outcome seam — the \
             arm reports the failure and the app owns the counter, so a \
             Phase I arm inherits the strike count and the latch with no \
             second edit to this dispatch site",
        );
        // The knob is narrow: arming one sub-command must not change another.
        // The knob is still one sub-command wide. `AUDIT_READ` was the probe
        // for as long as it was a stub, and it stays the probe now that it is
        // real: it is ungated, so it answers 0x00 and — more to the point —
        // stays 0x00 while `ConfigWrite` is armed, which is what "the seam is
        // one sub-command wide" means once there is no stub left to compare.
        assert_eq!(
            host.process_ctap2(VENDOR_41, &rskey_request(0x07), [1, 2, 3, 4])[0],
            0x00,
            "arming ConfigWrite must not make AUDIT_READ answer 0x33; the \
             seam is one sub-command wide",
        );
    }
    assert!(
        host.keystore().get_pin_state().needs_power_cycle,
        "host: the latch must be set after the third strike — this is the \
         durable half, and the app is what persists it",
    );

    // --- device path ---
    let (mut dev, _trng, mut st) = device_app();
    {
        let _guard = set_escalation_test_sub(Some(Subcommand::ConfigWrite));
        let mut statuses = Vec::new();
        for _ in 0..3 {
            let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
            let n = dev.process_ctap2_with_store(
                VENDOR_41,
                &rskey_request(0x0C),
                [1, 2, 3, 4],
                &mut out,
                Some(&mut st),
            );
            statuses.push(out[..n][0]);
        }
        assert_eq!(
            statuses,
            vec![PIN_AUTH_INVALID, PIN_AUTH_INVALID, PIN_AUTH_BLOCKED],
            "device: same 0x33/0x33/0x34 sequence on the RP2350 command path. \
             Its note_pin_auth_failure also sets `blocked` and `dirty`; the \
             latch asserted below is the gate the twin actually enforces",
        );
    }
    assert!(
        dev.keystore().pin_state.needs_power_cycle,
        "device: the latch must be set after the third strike, and must \
         survive in the keystore rather than in a volatile field",
    );
}

// ---------------------------------------------------------------------------
// US-113: `vendorPrototype` (`0xFF`) — the pico-fido legacy physical-config
// framing (PicoForge framing (B)).
// ---------------------------------------------------------------------------

/// CTAP2 `authenticatorConfig` — the opcode `0xFF` is a sub-command of.
const CTAP2_CONFIG: u8 = 0x0D;
/// The sub-command byte on the wire, spelled as a test-side literal for the
/// same reason [`VENDOR_41`] is: an assertion against `vendorff::SUB_COMMAND`
/// would compare two spellings of `0xFF` and could not fail.
const VENDOR_FF: u8 = 0xFF;
/// CTAP2.1 `CTAP2_ERR_MISSING_PARAMETER`.
const MISSING_PARAMETER: u8 = 0x14;
/// CTAP2.1 `CTAP2_ERR_PIN_NOT_SET`.
const PIN_NOT_SET: u8 = 0x35;
/// CTAP2.1 `CTAP2_ERR_INVALID_PARAMETER`.
const INVALID_PARAM: u8 = 0x02;

/// The four 64-bit physical-config ids PicoForge actually sends, checked
/// against `picoforge/src/hal/fido/constants.rs` (`VendorConfigCommand`) and
/// the call sites in `write_legacy_hardware_config`
/// (`picoforge/src/hal/fido/mod.rs:1305-1375`).
///
/// The list is data, not inlined, so the id-table test can assert the firmware
/// module against it and a wrong id fails as a *set* mismatch rather than as
/// four unrelated happy paths.
const VENDOR_FF_IDS: &[(&str, u64)] = &[
    ("PhysicalVidPid", 0x6fcb19b0cbe3acfa),
    ("PhysicalLedGpio", 0x7b392a394de9f948),
    ("PhysicalLedBrightness", 0x76a85945985d02fd),
    ("PhysicalOptions", 0x269f3b09eceb805f),
];

/// The `subCommandParams` map PicoForge builds: `{1: <64-bit id>, 3: <int>}`.
///
/// The parameter key is chosen **by CBOR type**, not by this framing's own
/// choice — `HidTransport::send_vendor_config`
/// (`picoforge/src/hal/fido/ops.rs:154-181`) files `Value::Integer` under
/// `0x03`, `Value::Bytes` under `0x02` and `Value::Text` under `0x04`. Every
/// one of the four physical-config writes is an integer, so `0x03` is the key
/// this framing must read, and reading anything else is the bug this test's
/// negative legs are for.
fn vendor_0xff_params(id: u64, value: u64) -> Vec<u8> {
    let mut b: HV<u8, 64> = HV::new();
    nh::push_map_header(&mut b, 2).unwrap();
    nh::push_uint(&mut b, 1).unwrap();
    nh::push_uint(&mut b, id).unwrap();
    nh::push_uint(&mut b, 3).unwrap();
    nh::push_uint(&mut b, value).unwrap();
    b.to_vec()
}

/// The full `authenticatorConfig` request for a `0xFF` sub-command:
/// `{1: 0xFF, 2: params, 3: 1, 4: pinUvAuthParam}`.
///
/// The MAC is built over `0xFF*32 || 0x0D || 0xFF || cbor(params)` — the CTAP2
/// config domain (`0x0D`), not the `0x41` vendor domain the rest of this file
/// uses, so [`picoforge_mac`] is reused with an explicit domain argument
/// rather than a new builder.
fn vendor_0xff_request_no_params(token: &[u8; 32]) -> Vec<u8> {
    let mut b: HV<u8, 128> = HV::new();
    nh::push_map_header(&mut b, 3).unwrap();
    nh::push_uint(&mut b, 1).unwrap();
    nh::push_uint(&mut b, VENDOR_FF as u64).unwrap();
    nh::push_uint(&mut b, 3).unwrap();
    nh::push_uint(&mut b, 1).unwrap();
    nh::push_uint(&mut b, 4).unwrap();
    nh::push_bstr(&mut b, &picoforge_mac(token, CTAP2_CONFIG, VENDOR_FF, &[])).unwrap();
    b.to_vec()
}

fn vendor_0xff_request(token: &[u8; 32], params: &[u8]) -> Vec<u8> {
    let mac = picoforge_mac(token, CTAP2_CONFIG, VENDOR_FF, params);
    let mut b: HV<u8, 128> = HV::new();
    nh::push_map_header(&mut b, 4).unwrap();
    nh::push_uint(&mut b, 1).unwrap();
    nh::push_uint(&mut b, VENDOR_FF as u64).unwrap();
    nh::push_uint(&mut b, 2).unwrap();
    b.extend_from_slice(params).unwrap();
    nh::push_uint(&mut b, 3).unwrap();
    nh::push_uint(&mut b, 1).unwrap();
    nh::push_uint(&mut b, 4).unwrap();
    nh::push_bstr(&mut b, &mac).unwrap();
    b.to_vec()
}

/// # `vendor_prototype_set_led_gpio_persists`
///
/// The EPIC's named test. `authenticatorConfig` sub-command `0xFF`
/// (`vendorPrototype`) with the `PhysicalLedGpio` id must set the LED GPIO
/// **and that value must survive a store round-trip**.
///
/// ## Why the "persists" half is the test
///
/// The other four legs below could all be satisfied by a handler that sets an
/// in-memory field and answers `0x00` — and that is exactly the shape a
/// reviewer would have to take on trust, because nothing about the CTAP2
/// transaction says the write was durable. So the load-bearing step is the
/// one at the bottom: the app is **dropped** and a *fresh* one is booted from
/// the same `HostSecureStore`, which is the only way to reach the same bytes
/// the RP2350's secure partition would hold across a power cycle. Asserting on
/// `app.keystore().phy` before the reboot would pass even if `persist` were
/// never called.
#[test]
fn vendor_prototype_set_led_gpio_persists() {
    let (mut dev, _trng) = DevicePinClient::boot();
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);

    let params = vendor_0xff_params(VENDOR_FF_IDS[1].1, 15);
    let (status, _) = dev.call(CTAP2_CONFIG, &vendor_0xff_request(&token, &params));
    assert_eq!(
        status, 0x00,
        "a PIN-authenticated `0xFF` write of PhysicalLedGpio must be accepted \
         on the device path. `0xFF` reached the sub-command match here; the \
         EPIC's claim that the host twin already had this handler is wrong — \
         `cfg_vendor_prototype` dispatches only to the two credential ids"
    );
    assert_eq!(
        dev.app.keystore().phy.led_gpio,
        Some(15),
        "the handler must decode the value PicoForge packs under CBOR key \
         `0x03` and store exactly that, not an off-by-one or a truncated byte"
    );

    // The CTAPHID task's durable-before-ack gate. With a store bound — which
    // it is, because this test drives `process_ctap2_with_store` — the
    // handler's `grow_checked` has *already* written the snapshot, so what
    // this call reports is the partition-image program, not the snapshot
    // write. A handler that dirtied nothing would answer `false` here and the
    // HID task would refuse the ack, so the leg is still worth having; it is
    // the reboot below, not this assertion, that proves the bytes landed.
    assert!(
        dev.persist(),
        "a `0x00` answer is only honest if there was a durable change to \
         program — the HID task (firmware/src/tasks.rs, durable-before-ack) \
         refuses to ack a command that left nothing to persist"
    );

    // --- the persistence claim: drop the app, boot a new one from the store ---
    let mut store = dev.store;
    let mut trng = HostTrng::new();
    let mut rebooted = DeviceApp::boot(&mut trng, &mut store).unwrap();
    assert_eq!(
        rebooted.keystore().phy.led_gpio,
        Some(15),
        "the LED GPIO must come back from a store round-trip. This is the only \
         step that proves durability: reading the same struct in memory would \
         also pass with a handler that never persisted"
    );
}

/// # `vendor_prototype_set_vid_pid_persists`
///
/// [`vendor_prototype_set_led_gpio_persists`] is the EPIC's named test, and it
/// is one id out of four. Everything else in this section is blind to the
/// question it leaves open — *which field did the decoded value land in?* —
/// because [`vendor_0xff_id_table_matches_picoforge`] is a *set* assertion,
/// [`vendor_0xff_range_checks_refuse_out_of_range_values`] only ever observes
/// refusals and so never reaches an `apply`, and
/// [`vendor_0xff_vidpid_packing_round_trips`] is a pure helper round-trip
/// that runs no handler at all. An arm that decoded `PhysicalVidPid` and then
/// stored it in `led_gpio` — the truncation the field's own type invites,
/// since `0x1209_0001` narrows to `0x01` and `0x01` is a real pin — would
/// pass every one of them.
///
/// ## What the reboot is for
///
/// The same assertion made against `dev.app.keystore().phy` immediately after
/// the write would be satisfied by a handler that set a struct field, answered
/// `0x00` and never called `persist`: nothing in the CTAP2 transaction says
/// the write was durable. Dropping the app and booting a *fresh* [`DeviceApp`]
/// over the same `HostSecureStore` is the only way to reach the bytes the
/// RP2350's secure partition holds across a power cycle — and, on this id
/// specifically, the only way to see auth-map key 6's per-field numbers as
/// distinct, because a `vid_pid` that reappeared in *two* fields after the
/// round trip would be a snapshot-codec bug that no command-path assertion
/// can reach.
///
/// ## What the cross-id assertions are for
///
/// The `vid_pid` assertion alone catches a *swap*, because a swapped-in field
/// stops being `Some(value)`. It does **not** catch a handler that writes the
/// right field **and also** touches a neighbour — one that rebuilds the record
/// from the decoded command and blanks the three it did not decode would
/// satisfy it. The three siblings are therefore written *first*, each with its
/// own value, and re-read *after* the reboot: a neighbour that lost its value
/// is the one failure no assertion naming only `vid_pid` would see.
#[test]
fn vendor_prototype_set_vid_pid_persists() {
    let (mut dev, _trng) = DevicePinClient::boot();
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);

    // The three siblings, written first and out of the way, so the field under
    // test has populated neighbours to fail to disturb. `15`, `73` and `0x0e`
    // are the values this section uses throughout: each is legal for its own
    // id, and each is a different number from the other three both in its own
    // type and narrowed to a `u8`.
    for (id, value, who) in [
        (VENDOR_FF_IDS[1].1, 15u64, "PhysicalLedGpio"),
        (VENDOR_FF_IDS[2].1, 73u64, "PhysicalLedBrightness"),
        (VENDOR_FF_IDS[3].1, 0x0eu64, "PhysicalOptions"),
    ] {
        let (status, _) = dev.call(
            CTAP2_CONFIG,
            &vendor_0xff_request(&token, &vendor_0xff_params(id, value)),
        );
        assert_eq!(
            status, 0x00,
            "the {who} sibling write must be accepted before the one under \
             test. It is the precondition that makes the non-disturbance \
             assertions after the reboot mean anything: with empty siblings a \
             'wrote a field' bug and a 'wrote the right field' bug are the \
             same bytes"
        );
    }

    // `(0x1209 << 16) | 0x0001` — the client's own expression, with a vendor
    // id rather than `0x0000` so that a value landing in *any* 8-bit field
    // would truncate to `0x01` instead of to a plausible-looking `0x00`.
    let (status, _) = dev.call(
        CTAP2_CONFIG,
        &vendor_0xff_request(&token, &vendor_0xff_params(VENDOR_FF_IDS[0].1, 0x1209_0001)),
    );
    assert_eq!(
        status, 0x00,
        "a PIN-authenticated `0xFF` write of PhysicalVidPid must be accepted \
         on the device path exactly as PhysicalLedGpio is. A refusal here \
         would be a `vendorff::validate` that accepts one id and not the \
         other, which is the other half of the question this test asks"
    );

    // The durable-before-ack gate, driven the way `firmware/src/tasks.rs`
    // drives it. `vendor_prototype_set_led_gpio_persists` says why the leg is
    // worth having even though the reboot below is the real proof.
    assert!(
        dev.persist(),
        "a `0x00` answer is only honest if there was a durable change to \
         program — the HID task refuses to ack a command that left nothing to \
         persist"
    );

    // --- the persistence claim: drop the app, boot a new one from the store ---
    let mut store = dev.store;
    let mut trng = HostTrng::new();
    let mut rebooted = DeviceApp::boot(&mut trng, &mut store).unwrap();
    let phy = rebooted.keystore().phy;

    assert_eq!(
        phy.vid_pid,
        Some(0x1209_0001),
        "PhysicalVidPid must be stored in `vid_pid` and must come back from a \
         store round-trip. Reading the same struct in memory before the drop \
         would also pass with a handler that never persisted"
    );
    assert_eq!(
        fapico2_fido::vendorff::unpack_vidpid(phy.vid_pid.unwrap()),
        (0x1209u16, 0x0001u16),
        "and the stored `u32` must unpack to the pair the client packed. \
         `write_legacy_hardware_config` builds `((vid as u32) << 16) | pid` \
         and reads it back the same way, so a value that survived the round \
         trip shifted by sixteen would enumerate the device under the wrong \
         identity — an assertion against the literal alone would not see it"
    );
    assert_eq!(
        phy.led_gpio,
        Some(15),
        "the PhysicalLedGpio sibling must be exactly where it was put. A \
         handler that wrote the VID/PID into `led_gpio` as well, or that \
         rebuilt the record from the decoded command, is invisible to the \
         `vid_pid` assertion above and to every other `0xFF` test in this file"
    );
    assert_eq!(
        phy.led_brightness,
        Some(73),
        "and the same for PhysicalLedBrightness — the neighbour a `u32` most \
         easily overwrites, because the narrowing that would do it is a cast \
         rather than a checked conversion"
    );
    assert_eq!(
        phy.options,
        Some(0x0e),
        "and the same for PhysicalOptions: the one field whose accepted value \
         set is narrow enough that a shared write would have stored a word \
         `vendorff::validate` refuses for it"
    );
}

/// # `vendor_prototype_set_led_brightness_persists`
///
/// The second `0xFF` id to get a positive device-path test, and the one whose
/// swap is hardest to see by inspection: `led_brightness` and `led_gpio` are
/// both `Option<u8>`, so to a handler that dispatched on anything but the id
/// they are interchangeable, and [`fapico2_fido::vendorff::validate`]'s only
/// objection is a *range* one — 73 is a legal `u8` and a legal brightness, so
/// the check is silent either way. Nothing else in this file would catch it:
/// the id-set test is a set assertion, the range test only ever reaches
/// refusals, and neither ever looks at a field that was written.
///
/// ## What the reboot is for
///
/// Both assertions below could be made against `dev.app.keystore().phy`
/// immediately after the write, and both would pass for a handler that set a
/// struct field, answered `0x00` and never called `persist`. Dropping the app
/// and booting a fresh [`DeviceApp`] from the same `HostSecureStore` is the
/// only way to reach the bytes that would survive a power cycle, and so the
/// only way to tell "the handler wrote the field" from "the device stored
/// it" — for brightness in particular, the one value the RP2350 would have to
/// read back to actually dim an LED.
///
/// ## What the cross-id assertions are for
///
/// A `led_brightness` assertion on its own is satisfied by a handler that set
/// the right field *and also* damaged a neighbour — one that rebuilt the
/// record from the decoded command, or one that assigned the value twice. The
/// three siblings are written first, each with a different value, and re-read
/// after the reboot, so a neighbour that lost its value or gained a second
/// one is a failure here rather than a surprise in a Phase H soak test.
#[test]
fn vendor_prototype_set_led_brightness_persists() {
    let (mut dev, _trng) = DevicePinClient::boot();
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);

    for (id, value, who) in [
        (VENDOR_FF_IDS[0].1, 0x1209_0001u64, "PhysicalVidPid"),
        (VENDOR_FF_IDS[1].1, 15u64, "PhysicalLedGpio"),
        (VENDOR_FF_IDS[3].1, 0x0eu64, "PhysicalOptions"),
    ] {
        let (status, _) = dev.call(
            CTAP2_CONFIG,
            &vendor_0xff_request(&token, &vendor_0xff_params(id, value)),
        );
        assert_eq!(
            status, 0x00,
            "the {who} sibling write must be accepted before the one under \
             test. With empty siblings there is nothing for a cross-wired \
             write to disturb, and the test would only be asserting that the \
             target field changed"
        );
    }

    // 73, chosen because it is a legal brightness *and* a legal `u8`: the
    // check the handler runs cannot separate the two ids for us, so the
    // record's other contents have to.
    let (status, _) = dev.call(
        CTAP2_CONFIG,
        &vendor_0xff_request(&token, &vendor_0xff_params(VENDOR_FF_IDS[2].1, 73)),
    );
    assert_eq!(
        status, 0x00,
        "a PIN-authenticated `0xFF` write of PhysicalLedBrightness must be \
         accepted on the device path. 73 is inside the 0..=100 the hardware \
         honours, so a refusal here is a range check applied to the wrong id"
    );

    assert!(
        dev.persist(),
        "a `0x00` answer is only honest if there was a durable change to \
         program — the HID task refuses to ack a command that left nothing to \
         persist"
    );

    // --- the persistence claim: drop the app, boot a new one from the store ---
    let mut store = dev.store;
    let mut trng = HostTrng::new();
    let mut rebooted = DeviceApp::boot(&mut trng, &mut store).unwrap();
    let phy = rebooted.keystore().phy;

    assert_eq!(
        phy.led_brightness,
        Some(73),
        "PhysicalLedBrightness must be stored in `led_brightness` and must \
         come back from a store round-trip. Reading the same struct in memory \
         before the drop would also pass with a handler that never persisted"
    );
    assert_eq!(
        phy.led_gpio,
        Some(15),
        "the PhysicalLedGpio sibling must survive the brightness write \
         unchanged. Both fields are `Option<u8>` and both accept 73, so this \
         assertion — not the one above — is what distinguishes the two ids"
    );
    assert_eq!(
        phy.vid_pid,
        Some(0x1209_0001),
        "and so must PhysicalVidPid: a handler that shared its `Option<u32>` \
         with the brightness case would have overwritten the USB identity, \
         which is the one field on this record a wrong write would turn into \
         an identity-spoofing primitive the moment descriptors become \
         runtime-configurable"
    );
    assert_eq!(
        phy.options,
        Some(0x0e),
        "and PhysicalOptions, whose value 0x0e is a legal brightness in its \
         own right — so without this leg the swap would have been invisible \
         in both directions"
    );
}

/// # `vendor_prototype_set_physical_options_persists`
///
/// The fourth `0xFF` id, and the one where the **value alone cannot catch a
/// cross-wire**: `0x0e`, the three bits [`fapico2_fido::vendorff`] accepts, is
/// equally a legal `u8` for `led_gpio` and a legal percentage for
/// `led_brightness`, and `0x0000_000e` is a legal `vid_pid`. An arm that got
/// this id's dispatch right and its *field* wrong would produce a record that
/// looks correct under any assertion naming only `options` — which is why
/// this test leans hardest on the record's other contents, and why the
/// siblings are written before the id under test rather than after.
///
/// `options` is also the narrowest field the framing accepts — any bit outside
/// `0x02 | 0x04 | 0x08` is refused — so a neighbour that picked up a
/// brightness or a GPIO by accident would in most cases be holding a word
/// this firmware's own validator rejects for it.
///
/// ## What the reboot is for
///
/// Asserting on `dev.app.keystore().phy` before the drop would be satisfied by
/// a handler that set a struct field, answered `0x00` and never called
/// `persist`, and the field is the one a client would read back as device
/// behaviour: `power_cycle_on_reset` and `led_steady` are both computed from
/// these bits in the client, so a brightness that survived a reboot in the
/// wrong field is a token whose Reset button does the wrong thing. Only a
/// fresh [`DeviceApp::boot`] over the same `HostSecureStore` distinguishes
/// that from an in-RAM struct the nobody will ever see again.
///
/// ## What the cross-id assertions are for
///
/// Asserting `options == Some(0x0e)` is satisfied by a handler that set the
/// right field and also overwrote, duplicated or cleared a neighbour — a
/// record rebuilt from the decoded command, for instance, blanks the three it
/// did not decode and this assertion would not notice. Each sibling is
/// asserted after the reboot against the value it was written with, so the
/// only way to pass is a handler that touched exactly one field.
#[test]
fn vendor_prototype_set_physical_options_persists() {
    let (mut dev, _trng) = DevicePinClient::boot();
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);

    for (id, value, who) in [
        (VENDOR_FF_IDS[0].1, 0x1209_0001u64, "PhysicalVidPid"),
        (VENDOR_FF_IDS[1].1, 15u64, "PhysicalLedGpio"),
        (VENDOR_FF_IDS[2].1, 73u64, "PhysicalLedBrightness"),
    ] {
        let (status, _) = dev.call(
            CTAP2_CONFIG,
            &vendor_0xff_request(&token, &vendor_0xff_params(id, value)),
        );
        assert_eq!(
            status, 0x00,
            "the {who} sibling write must be accepted before the one under \
             test. Its value is one this id could not legally hold — the \
             siblings are what give the non-disturbance assertions below \
             something to assert against"
        );
    }

    // All three accepted option bits, which is also 14: the one value in the
    // whole set that is a legal brightness, a legal GPIO and a legal packed
    // id at the same time. Distinctness has to come from the siblings here,
    // not from this number.
    let (status, _) = dev.call(
        CTAP2_CONFIG,
        &vendor_0xff_request(&token, &vendor_0xff_params(VENDOR_FF_IDS[3].1, 0x0e)),
    );
    assert_eq!(
        status, 0x00,
        "a PIN-authenticated `0xFF` write of PhysicalOptions must be accepted \
         on the device path. 0x0e is `DIMMABLE | DISABLE_POWER_RESET | \
         LED_STEADY`, every bit this firmware defines, so a refusal here is a \
         mask applied to the wrong id"
    );

    assert!(
        dev.persist(),
        "a `0x00` answer is only honest if there was a durable change to \
         program — the HID task refuses to ack a command that left nothing to \
         persist"
    );

    // --- the persistence claim: drop the app, boot a new one from the store ---
    let mut store = dev.store;
    let mut trng = HostTrng::new();
    let mut rebooted = DeviceApp::boot(&mut trng, &mut store).unwrap();
    let phy = rebooted.keystore().phy;

    assert_eq!(
        phy.options,
        Some(0x0e),
        "PhysicalOptions must be stored in `options` and must come back from \
         a store round-trip. Reading the same struct in memory before the \
         drop would also pass with a handler that never persisted"
    );
    assert_eq!(
        phy.led_brightness,
        Some(73),
        "the PhysicalLedBrightness sibling must be untouched. 0x0e is a legal \
         brightness, so an arm that reached the wrong field would store 14 \
         here and this is the only assertion that sees it"
    );
    assert_eq!(
        phy.led_gpio,
        Some(15),
        "and so must PhysicalLedGpio — 0x0e is GPIO 14, a real pin on this \
         part, which is why a value-only assertion could never have been \
         enough for this id"
    );
    assert_eq!(
        phy.vid_pid,
        Some(0x1209_0001),
        "and PhysicalVidPid, whose packed form is a `u32` and the one field \
         whose corruption is an identity change rather than a cosmetic one"
    );
}

/// The four ids the firmware accepts are exactly the four the client sends,
/// and nothing else. This is a *set* assertion on purpose: an id table that
/// had drifted — a typo, a dropped id, a plausible-looking extra — has to fail
/// here rather than quietly 404 at runtime against a desktop app.
#[test]
fn vendor_0xff_id_table_matches_picoforge() {
    use fapico2_fido::vendorff;
    let firmware: Vec<(&'static str, u64)> = vendorff::SUPPORTED_IDS.to_vec();
    assert_eq!(
        firmware, VENDOR_FF_IDS,
        "the ids the client sends (picoforge VendorConfigCommand, the four \
         used by write_legacy_hardware_config) and the ids this firmware \
         accepts must be the same list, in the same order — a mismatch here \
         means one side silently answers 0x02 to a write the other believes \
         it made"
    );
}

/// The VID/PID packing is `(vid << 16) | pid`, and it round-trips.
///
/// Taken from `write_legacy_hardware_config`
/// (`picoforge/src/hal/fido/mod.rs:1324-1326`), which computes
/// `((vid as u32) << 16) | (pid as u32)` and sends it as an integer. The
/// round-trip assertion is the part that would catch a transposition: a
/// "pack" that is merely self-consistent still produces a device that
/// enumerates under the wrong ids.
#[test]
fn vendor_0xff_vidpid_packing_round_trips() {
    use fapico2_fido::vendorff;
    for (vid, pid) in [(0x1209u16, 0x0001u16), (0x2e8au16, 0x000cu16), (0xffffu16, 0xffffu16)] {
        let packed = vendorff::pack_vidpid(vid, pid);
        assert_eq!(
            vendorff::unpack_vidpid(packed),
            (vid, pid),
            "VID {vid:#06x}/PID {pid:#06x} must survive pack→unpack; the client \
             builds the same u32 and reads it back the same way"
        );
        assert_eq!(
            packed, ((vid as u32) << 16) | pid as u32,
            "the packed form is `(vid << 16) | pid` — the client's own \
             expression, asserted rather than restated in the helper"
        );
    }
}

/// A `0xFF` write is refused — not silently applied — when the wire shape is
/// not the one the client produces.
///
/// Three distinct ways to get it wrong, three distinct answers, because a
/// handler that accepted any of these would be writing a value the client
/// never meant to send.
#[test]
fn vendor_0xff_rejects_misshapen_requests() {
    let (mut dev, _trng) = DevicePinClient::boot();
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);
    let id = VENDOR_FF_IDS[1].1;

    // (a) no `subCommandParams` key at all — key 2 is simply absent, which is
    // a *different* failure from an empty one: an empty map would parse and
    // then carry no id, whereas this never carries any parameter.
    let (status, _) = dev.call(CTAP2_CONFIG, &vendor_0xff_request_no_params(&token));
    assert_eq!(
        status, MISSING_PARAMETER,
        "`0xFF` with no subCommandParams key has no vendor id to dispatch on. \
         The MAC is correct for this request, so the answer is about the \
         request's shape and not about authorisation"
    );

    // (b) the value under the byte-string key instead of the integer key.
    // PicoForge files `Value::Integer` under `0x03`; reading `0x02` here
    // would mean reading a field the client never populates for this framing.
    let mut wrong_key: HV<u8, 64> = HV::new();
    nh::push_map_header(&mut wrong_key, 2).unwrap();
    nh::push_uint(&mut wrong_key, 1).unwrap();
    nh::push_uint(&mut wrong_key, id).unwrap();
    nh::push_uint(&mut wrong_key, 2).unwrap();
    nh::push_bstr(&mut wrong_key, &[15]).unwrap();
    let (status, _) = dev.call(
        CTAP2_CONFIG,
        &vendor_0xff_request(&token, wrong_key.as_slice()),
    );
    assert_eq!(
        status, INVALID_PARAM,
        "a byte-string value under key `0x02` is a different framing's shape; \
         this one must refuse it rather than apply a value the client never \
         sent as an integer"
    );

    // (c) an id this firmware does not implement.
    let (status, _) = dev.call(
        CTAP2_CONFIG,
        &vendor_0xff_request(&token, &vendor_0xff_params(0xdead_beef_dead_beef, 15)),
    );
    assert_eq!(
        status, INVALID_PARAM,
        "an unknown 64-bit id must be refused with INVALID_PARAMETER — the \
         same answer an unsupported RS-Key sub-command gets, so the client \
         sees one consistent 'this device does not do that'"
    );
}

/// A `0xFF` physical-config write needs a PIN and an `AUTHENTICATOR_CONFIG`
/// token, like every other `authenticatorConfig` sub-command.
///
/// Not decoration: `PhysicalVidPid` rewrites the USB identity, so "only the
/// PIN holder can do it" is the property that makes the surface safe to
/// expose at all. Without this leg the handler could be reached bare, and the
/// other four tests would still pass.
#[test]
fn vendor_0xff_requires_pin_and_acfg_permission() {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut fresh = DeviceApp::boot(&mut trng, &mut store).unwrap();
    let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();

    // A syntactically perfect request, signed with a token the device has
    // never issued, on a device that has no PIN at all.
    let params = vendor_0xff_params(VENDOR_FF_IDS[0].1, 0x1209_0001);
    let n = fresh.process_ctap2_with_store(
        CTAP2_CONFIG,
        &vendor_0xff_request(&[0xabu8; 32], &params),
        [1, 2, 3, 4],
        &mut out,
        Some(&mut store),
    );
    assert_eq!(
        out[..n],
        [PIN_NOT_SET],
        "without a PIN there is no key to gate the write on, so a physical- \
         config command must be unreachable rather than open"
    );
    assert_eq!(
        fresh.keystore().phy.vid_pid,
        None,
        "a refused write must leave the stored configuration untouched — the \
         VID/PID in particular, since that is the one that would change how \
         the device enumerates on the bus"
    );

    // Same request on a device that *has* a PIN, still without a token: the
    // gate moves from PIN_NOT_SET to PIN_AUTH_INVALID, which is the leg that
    // actually says "the MAC is checked", not merely "there is a PIN".
    let (mut dev, _trng) = DevicePinClient::boot();
    dev.set_pin(b"1234");
    let (status, _) = dev.call(
        CTAP2_CONFIG,
        &vendor_0xff_request(&[0xabu8; 32], &params),
    );
    assert_eq!(
        status, 0x33,
        "CTAP2_ERR_PIN_AUTH_INVALID: a PIN is set but no pinUvAuthToken is \
         held, so the `0xFF` arm must be behind the same \
         AUTHENTICATOR_CONFIG gate as every other config sub-command"
    );
}

/// The host twin answers the same `0xFF` and applies the same write.
///
/// The two command paths are separate `match` statements, so a `0xFF` arm
/// added to one and not the other is a real defect the other test binary
/// would never see — the reason this file drives both wherever the *status*
/// is the claim. Here the claim is the write itself: the host stack is what
/// the emulation binary runs (`firmware/src/emul_main.rs` builds
/// `fapico2_fido::app::FidoApp`), so a `0xFF` that worked on the RP2350 and
/// answered `INVALID_SUBCOMMAND` on the host would make one desktop app
/// succeed against hardware and fail against the emulator.
///
/// The read-back is through the host keystore's `AuthState`, a different
/// snapshot format from the device's. The two share `PhyConfig` but not an
/// encoder, and this leg is what would notice if the host one stopped
/// persisting it.
#[test]
fn vendor_0xff_physical_config_works_on_the_host_twin() {
    let (mut host, client) = common::setup();
    let token: [u8; 32] = client
        .get_token(&mut host, 0x09, Some(PERM_ACFG_LITERAL), None)
        .expect("getPinUvAuthTokenUsingPinWithPermissions(ACFG) must succeed")
        .try_into()
        .expect("a pinUvAuth token is 32 bytes");

    let params = vendor_0xff_params(VENDOR_FF_IDS[1].1, 15);
    let reply = host.process_ctap2(
        CTAP2_CONFIG,
        &vendor_0xff_request(&token, &params),
        [0, 0, 0, 1],
    );
    assert_eq!(
        reply.first().copied(),
        Some(0x00),
        "the host twin must answer the same `0x00` the device path does, for \
         the same correctly-authorised request. The two dispatch `match`es \
         are independent, so nothing above implies this"
    );
    assert_eq!(
        host.keystore().get_auth_state().phy.led_gpio,
        Some(15),
        "and it must apply the write to the host keystore's persisted \
         `AuthState` — a `0x00` from a handler that dropped the value would \
         satisfy the status assertion above on its own"
    );
}

/// Every range check on the `0xFF` path, one leg each.
///
/// These are the checks the persistence test cannot reach: it drives
/// `PhysicalLedGpio` with a legal value, so a handler that dropped a
/// `try_from` or a bound would still pass it. The one id that originally had
/// **no** check at all — `PhysicalVidPid` narrowed a `u64` straight into a
/// `u32` — is why this test exists in the shape it does: a value that a
/// narrowing cast would silently accept, asserted on both paths.
#[test]
fn vendor_0xff_range_checks_refuse_out_of_range_values() {
    let (mut dev, _trng) = DevicePinClient::boot();
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);

    // (id index into VENDOR_FF_IDS, value, which range it breaks)
    let cases: &[(usize, u64, &str)] = &[
        (0, 0x1_0000_0000, "vid_pid wider than u32 — a narrowing cast would store 0x0000_0000"),
        (1, 256, "led_gpio 256 — a narrowing cast would store GPIO 0, which is a real pin"),
        (2, 101, "led_brightness 101 — one past the 0..=100 the hardware honours"),
        (3, 0x0100, "an undefined PHYSICAL_OPTIONS bit above the three the client sets"),
    ];
    for &(idx, value, why) in cases {
        let (name, id) = VENDOR_FF_IDS[idx];
        let (status, _) = dev.call(
            CTAP2_CONFIG,
            &vendor_0xff_request(&token, &vendor_0xff_params(id, value)),
        );
        assert_eq!(
            status, INVALID_PARAM,
            "{name} must refuse {value:#x}: {why}. A truncation here is a \
             silently wrong hardware setting, which is the failure mode the \
             Phase H soak tests exist to catch"
        );
    }

    // The refusals must not have half-applied anything: a transactional
    // commit that validated one field and wrote another is exactly the shape
    // these checks exist to prevent.
    assert_eq!(
        dev.app.keystore().phy,
        fapico2_fido::vendorff::PhyConfig::default(),
        "a refused write must leave the stored configuration untouched — \
         every leg above is an error, and an error that still mutated the \
         record would be invisible to the status byte"
    );

    // The host twin applies the same table with the same answers, because it
    // runs the same `validate` — and because a divergence here is the one the
    // module doc says cannot happen.
    let (mut host, client) = common::setup();
    let host_token: [u8; 32] = client
        .get_token(&mut host, 0x09, Some(PERM_ACFG_LITERAL), None)
        .expect("ACFG token")
        .try_into()
        .expect("a pinUvAuth token is 32 bytes");
    for &(idx, value, why) in cases {
        let (name, id) = VENDOR_FF_IDS[idx];
        let reply = host.process_ctap2(
            CTAP2_CONFIG,
            &vendor_0xff_request(&host_token, &vendor_0xff_params(id, value)),
            [0, 0, 0, 1],
        );
        assert_eq!(
            reply.first().copied(),
            Some(INVALID_PARAM),
            "host twin: {name} must refuse {value:#x} for the same reason \
             ({why}). The two paths are separate `match`es over the same \
             opcode space, so agreement has to be asserted, not assumed"
        );
    }
}

/// A repeated id key is refused, on both paths, with the same answer.
///
/// A legitimate PicoForge never sends one, so this is not an attack — it is a
/// divergence. The host's `cfg_vendor_prototype` scans for the *first* key
/// `1` to pick the sub-handler, while a last-wins decode would take the
/// second; before the shared refusal those two produced a spurious
/// `INVALID_PARAMETER` on the host and a silent apply on the device, for
/// identical bytes. The fix is one shared refusal in `PhyCommand::decode`,
/// and this is the leg that keeps it shared.
#[test]
fn vendor_0xff_rejects_a_repeated_id_key() {
    let mut dup: HV<u8, 64> = HV::new();
    nh::push_map_header(&mut dup, 3).unwrap();
    nh::push_uint(&mut dup, 1).unwrap();
    nh::push_uint(&mut dup, VENDOR_FF_IDS[1].1).unwrap(); // PhysicalLedGpio
    nh::push_uint(&mut dup, 1).unwrap();
    nh::push_uint(&mut dup, VENDOR_FF_IDS[0].1).unwrap(); // PhysicalVidPid
    nh::push_uint(&mut dup, 3).unwrap();
    nh::push_uint(&mut dup, 15).unwrap();

    let (mut dev, _trng) = DevicePinClient::boot();
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);
    let (status, _) = dev.call(
        CTAP2_CONFIG,
        &vendor_0xff_request(&token, dup.as_slice()),
    );
    assert_eq!(
        status, INVALID_PARAM,
        "device: a map with two key-1 entries has no single vendor id, so it \
         must be refused rather than resolved by first-wins or last-wins"
    );
    assert_eq!(
        dev.app.keystore().phy,
        fapico2_fido::vendorff::PhyConfig::default(),
        "and nothing may be written — whichever id the duplicate resolved to, \
         the operator did not unambiguously ask for it"
    );

    let (mut host, client) = common::setup();
    let host_token: [u8; 32] = client
        .get_token(&mut host, 0x09, Some(PERM_ACFG_LITERAL), None)
        .expect("ACFG token")
        .try_into()
        .expect("a pinUvAuth token is 32 bytes");
    let reply = host.process_ctap2(
        CTAP2_CONFIG,
        &vendor_0xff_request(&host_token, dup.as_slice()),
        [0, 0, 0, 1],
    );
    assert_eq!(
        reply.first().copied(),
        Some(INVALID_PARAM),
        "host: the same bytes must get the same answer. The host scans for \
         the FIRST key 1 and the shared decoder refuses the repeat, so this \
         leg is what proves the two resolve duplicates the same way"
    );
    assert_eq!(
        host.keystore().get_auth_state().phy,
        fapico2_fido::vendorff::PhyConfig::default(),
        "and the host record is untouched too"
    );
}

/// Trailing bytes after a well-formed `subCommandParams` map are refused.
///
/// The pinUvAuthParam MAC already covered exactly those bytes, so accepting
/// them is not a hole — but `DeviceKeystore::decode_auth` makes the same
/// check twenty lines from where this framing decodes, and a decoder that is
/// strict in one snapshot format and lax in another is the asymmetry that
/// gets tightened on one side and missed on the other.
///
/// Driven against [`PhyCommand::decode`] rather than through the command
/// path, because the device path cannot deliver trailing bytes to it: the
/// `authenticatorConfig` parser takes the `0x02` value's extent with
/// `Parser::skip`, which ends at the map's own close brace. The check is
/// therefore defence-in-depth for the direct callers (`decode` is public, and
/// the host twin re-encodes before calling) — and a check nothing can reach
/// is a comment pretending to be a guard, so it is pinned here at the level
/// it actually operates on rather than left implied.
#[test]
fn vendor_0xff_decode_refuses_trailing_bytes() {
    let mut body = vendor_0xff_params(VENDOR_FF_IDS[1].1, 15);
    body.extend_from_slice(&[0x01, 0x02, 0x03]);
    assert_eq!(
        fapico2_fido::vendorff::PhyCommand::decode(&body).err(),
        Some(fapico2_fido::ctap2::Ctap2Response::InvalidCbor),
        "a well-formed map followed by junk is not a well-formed map, and the \
         MAC having covered the junk is not a reason for this decoder to \
         disagree with the snapshot decoder"
    );
    // Guard the guard: the same helper's output without the tail must decode,
    // so the assertion above is about the trailing bytes and not the map.
    assert_eq!(
        fapico2_fido::vendorff::PhyCommand::decode(&vendor_0xff_params(VENDOR_FF_IDS[1].1, 15))
            .map(|c| (c.id, c.value)),
        Ok((VENDOR_FF_IDS[1].1, fapico2_fido::vendorff::ValueSource::Integer(15))),
        "without the trailing bytes the identical map decodes"
    );
}

// ---------------------------------------------------------------------------
// US-114: `0x41` CONFIG_READ (sub-command `0x0D`).
// ---------------------------------------------------------------------------

/// `RSKEY_CFG_TARGET_PHY` — the `target` byte inside `CONFIG_READ`'s
/// `subCommandParams` (`picoforge/src/hal/fido/constants.rs:773`). The only
/// target this story serves; the other two are refused.
const TARGET_PHY: u8 = 0x01;

/// The RS-Key `0x41` `CONFIG_READ` request PicoForge actually builds:
/// `{1: 0x0D, 2: {1: target}}`.
///
/// Transcribed from `HidTransport::rs_key_config_read`
/// (`picoforge/src/hal/fido/ops.rs:1461-1479`), which inserts key 1 =
/// `RSKEY_CONFIG_READ` and a params map holding a single key 1 = `target`.
/// Written as literal CBOR head bytes here rather than pushed through
/// `no_heap::push_uint` so that a change in the encoder cannot silently make
/// the request this test sends agree with a change in the device — the two
/// have to be pinned to the same protocol independently.
fn config_read_request(target: u8) -> HV<u8, 16> {
    let mut b: HV<u8, 16> = HV::new();
    // A2           map(2)
    // 01 0D        key 1 = 0x0D (RSKEY_CONFIG_READ)
    // 02 A1        key 2 = map(1)
    // 01 01        key 1 = target
    b.extend_from_slice(&[0xA2, 0x01, 0x0D, 0x02, 0xA1, 0x01, target])
        .unwrap();
    b
}

/// A PHY record covering **all six** fields [`PhyConfig`] can hold, chosen so
/// that every one of them lands on a distinct byte value. A blob encoder that
/// reordered its records, transposed two values, or dropped one would have to
/// produce these exact bytes to pass.
///
/// The two US-117 fields are set here too, so "all six" stays literally true
/// after US-117 extended the record. That has a consequence worth stating:
/// `config_read_returns_phy_tlv_blob` compares the whole reply against a
/// literal, so the PHY read genuinely must not emit either of them — which is
/// the property that a `CONFIG_READ` of target `0x01` did not widen when
/// `0x02` became readable.
fn full_phy_config() -> fapico2_fido::vendorff::PhyConfig {
    fapico2_fido::vendorff::PhyConfig {
        // 0x1209/0x0001, packed `(vid << 16) | pid` as `pack_vidpid` does and
        // the client writes big-endian, vid first
        // (`build_rskey_phy_tlv`, `picoforge/src/hal/fido/mod.rs:1024-1027`).
        vid_pid: Some(0x1209_0001),
        led_gpio: Some(4),
        led_brightness: Some(80),
        options: Some(0x0002),
        enabled_usb_itf: Some(0x003B),
        led_conf: Some(full_led_block()),
        // Unset on purpose. This fixture is the "every field a `CONFIG_READ`
        // can emit" record, and the two names are not among them — they are
        // variable-length and the emitted blob is a fixed-width table. Seeding
        // them here would change every byte-count assertion downstream for no
        // coverage gain; they have their own tests on the Rescue read path.
        product: None,
        manufacturer: None,
    }
}

/// A 17-byte LED block whose five fields-per-record all differ from each other
/// and from `steady`.
///
/// # The bytes are the client's own, transcribed
///
/// This is `parses_current_17_byte_block`'s block from
/// `picoforge/src/hal/common/led.rs:49-60` — the example the client's test
/// uses to pin `parse_led_block`, and the one place in this file where a 17-byte
/// block is a fact about the *client* rather than about this firmware's encoder.
///
/// It is transcribed rather than generated for the reason the rest of this file
/// keeps hand-written literals: an expectation produced by the code under test
/// proves only that the code agrees with itself. This suite has twice caught an
/// encoder that agreed with itself and disagreed with the protocol.
///
/// Its value here is that the same bytes can be run through both directions:
/// the client decodes them to `(steady, [(2,0x40),(3,0x20),(4,0x10),(1,0x08)])`,
/// and this firmware must hand back all 17 unchanged. If either side had the
/// offsets wrong, the two would disagree about which byte is the effect and
/// which the colour.
fn full_led_block() -> fapico2_fido::vendorff::LedConf {
    // 0x01,                                     // steady
    // 0x00, 0x02, 0x40, 0x00,                   // idle:  green,  br 0x40
    // 0x01, 0x03, 0x20, 0x05,                   // proc:  blue,   br 0x20
    // 0x02, 0x04, 0x10, 0x0F,                   // touch: yellow, br 0x10
    // 0x00, 0x01, 0x08, 0x00,                   // boot:  red,    br 0x08
    fapico2_fido::vendorff::LedConf([
        0x01, 0x00, 0x02, 0x40, 0x00, 0x01, 0x03, 0x20, 0x05, 0x02, 0x04, 0x10, 0x0F, 0x00, 0x01,
        0x08, 0x00,
    ])
}

/// # `config_read_returns_phy_tlv_blob`
///
/// The EPIC's US-114 test. `CONFIG_READ` (`0x0D`) with `target` `0x01`
/// (PHY) answers `0x00` and a CBOR map `{1: <blob>}`, where `blob` is the
/// `EF_PHY` record: a bare `TAG LEN VALUE` stream with a **one-byte** tag and a
/// **one-byte** length — not BER/TLV, which is what makes a value over 255
/// bytes unrepresentable rather than merely unusual.
///
/// ## Why the expected bytes are a literal, not a round-trip
///
/// The EPIC's acceptance bullet says "serialise the same PHY TLV blob US-116
/// defines, from the same source of truth". A test that encoded with the
/// crate's encoder and compared against the crate's decoder would satisfy that
/// sentence while proving nothing at all about the wire format — which is the
/// exact failure this suite has already caught twice. So the expectation below
/// is written out byte by byte, derived from the client's own reader
/// (`read_rskey_physical_config`, `picoforge/src/hal/fido/mod.rs:934-939`,
/// which reads `tag = data[i]`, `len = data[i + 1] as usize` and the value at
/// `data[i + 2 .. i + 2 + len]`) and from its writer
/// (`build_rskey_phy_tlv`, `:1015-1066`).
///
/// A BER length would put a `0x81` continuation byte in front of every length
/// above 15, a big-endian `u16` length would put two bytes where the client's
/// reader expects one, and either reordering or dropping a record changes the
/// literal. All three fail this assertion.
#[test]
fn config_read_returns_phy_tlv_blob() {
    const EXPECTED_TLV: &[u8] = &[
        0x00, 0x04, 0x12, 0x09, 0x00, 0x01, // VID/PID, len 4, big-endian, vid first
        0x04, 0x01, 0x04, // LED GPIO, len 1
        0x05, 0x01, 0x50, // LED brightness, len 1
        0x06, 0x02, 0x00, 0x02, // options, len 2, big-endian
    ];
    // The full wire reply is `status || CBOR`, and `DevicePinClient::call`
    // splits those, so the shared expectation is the *body*: `{1: bstr(16)}`
    // == 0xA1, key 0x01, byte-string head 0x50, then the 16 record bytes. The
    // host leg below prefixes the status byte itself, because its entry point
    // returns the whole reply.
    let mut expected_body: Vec<u8> = vec![0xA1, 0x01, 0x50];
    expected_body.extend_from_slice(EXPECTED_TLV);
    let mut expected: Vec<u8> = vec![0x00];
    expected.extend_from_slice(&expected_body);

    {
        let (mut dev, _trng) = DevicePinClient::boot();
        dev.app.keystore().phy = full_phy_config();
        let (status, body) = dev.call(VENDOR_41, config_read_request(TARGET_PHY).as_slice());
        assert_eq!(status, 0x00, "device: CONFIG_READ must answer CTAP2_OK");
        assert_eq!(
            body, expected_body,
            "device: the CBOR body must be the literal TLV record the client \
             parses, in ascending tag order with a one-byte length each"
        );
    }
    {
        let (mut host, _client) = common::setup();
        host.keystore().get_auth_state_mut().phy = full_phy_config();
        let resp = host.process_ctap2(
            VENDOR_41,
            config_read_request(TARGET_PHY).as_slice(),
            [1, 2, 3, 4],
        );
        assert_eq!(
            resp, expected,
            "host: the whole `status || CBOR` reply must match, status byte \
             included — the two dispatch paths are independent `match`es, so \
             passing on the device says nothing about this one"
        );
    }
}

/// An empty PHY record is an **empty byte string**, not a missing key, and the
/// client treats it as support rather than failure.
///
/// `write_rskey_physical_config` (`picoforge/src/hal/fido/mod.rs:1158-1166`)
/// calls `CONFIG_READ` purely as a *feature probe* before it has any
/// configuration to write, and its own comment says so: "A supported device
/// may legitimately return an empty PHY blob, so success alone is the signal —
/// never the blob length." A device that answered `0x00` with a map missing
/// key 1, or with a `0x14`, would be reported as "this RS-Key firmware does not
/// support FIDO configuration" — a device that does.
#[test]
fn config_read_of_an_unset_phy_record_is_an_empty_byte_string() {
    let (mut dev, _trng) = DevicePinClient::boot();
    // No `phy` written at all, so every field is `None`.
    let (status, body) = dev.call(VENDOR_41, config_read_request(TARGET_PHY).as_slice());
    assert_eq!(status, 0x00);
    assert_eq!(
        body, [0xA1, 0x01, 0x40],
        "an all-absent record is {{1: h''}}: key 1 present, byte string of \
         length 0. Omitting key 1 would make the client's `m.get(&Integer(1))` \
         return `None` and report 'missing blob (key 1)'"
    );
}

/// The `2` map is genuinely optional, and this firmware omits it.
///
/// PicoForge reads it defensively — `if let Some(Value::Map(e)) =
/// m.get(&Value::Integer(2))` (`picoforge/src/hal/fido/ops.rs:1490`) — and
/// documents it as "the boot-resolved effective LED pin (tag 4) / driver
/// (tag 12) / touch timeout (tag 8). Key 2 is optional." The client's UI then
/// renders those as `format!("Firmware default (GPIO {g})")`
/// (`picoforge/src/ui/screens/config/view_model.rs:364-370`), i.e. as the
/// **compile-time default**, shown as a placeholder for an unset field.
///
/// So the answer here is a deliberate omission rather than a shrug: nothing in
/// this firmware reads [`fapico2_fido::vendorff::PhyConfig`] to drive
/// hardware — the USB descriptors are a compile-time `CONFIG_DESC` and the
/// LED pin is the build-time default — so there is no boot-resolved value to
/// report. Emitting the *stored* `led_gpio` under key 4 would make the desktop
/// app print "Firmware default (GPIO 4)" for a firmware whose LED is not on
/// GPIO 4 at all. See [`vendor41::effective_config`] for the seam that will
/// fill it in when something actually reads the record.
#[test]
fn config_read_omits_the_effective_config_map() {
    let (mut dev, _trng) = DevicePinClient::boot();
    dev.app.keystore().phy = full_phy_config();
    let (status, body) = dev.call(VENDOR_41, config_read_request(TARGET_PHY).as_slice());
    assert_eq!(status, 0x00);
    // A one-pair map (`0xA1`), so key 2 is provably absent rather than present
    // and empty — a two-pair map with an empty sub-map would be a different
    // claim about what this firmware knows.
    assert_eq!(
        body[0], 0xA1,
        "the response map must have exactly one pair. The second pair (key 2, \
         the effective/firmware-default config) is omitted on this firmware"
    );
    // A byte-scan for `0x02` would be the wrong check — the options record's
    // own length byte *is* `0x02` — so decode the map instead and assert the
    // second pair is not there. Trailing bytes past the map would be a
    // separate defect the same parse catches.
    let mut p = nh::Parser::new(&body);
    assert_eq!(
        p.next().unwrap(),
        nh::Item::Map(1),
        "the response is a one-pair map: key 1 and nothing else"
    );
    assert_eq!(p.next().unwrap(), nh::Item::U(1));
    assert!(matches!(p.next().unwrap(), nh::Item::B(_)));
    assert_eq!(
        p.next().err(),
        Some(nh::CborError::Eof),
        "and the map ends there — a second pair, or trailing bytes, would both \
         mean the effective map was emitted"
    );
}

/// `DEV_CONF` (`0x00`) is refused, and `LED` (`0x02`) is served as of US-117.
///
/// The security boundary the ungated read is bounded by is `DEV_CONF`, and it
/// is PicoForge's own statement about the protocol, not a policy this story
/// invented: *"Enabled-apps info is NOT readable over the `0x41` CONFIG_READ
/// path — the firmware exposes only PHY/LED there and rejects DEV_CONF"*
/// (`picoforge/src/hal/fido/mod.rs:615-618`). `DEV_CONF` is the USB
/// application enabled-interface mask — the one record that changes what the
/// token can *do* over the bus — and it remains reachable only through a
/// `CONFIG_WRITE` carrying a `0x20` token. The client agrees and routes around
/// the absence: it reads enabled-apps over the `0xC2` Management path
/// (`picoforge/src/hal/fido/mod.rs:615-623`).
///
/// **`LED` moved from refused to served, and the reason is not cosmetic.**
/// US-114 refused it for a true but insufficient reason: a fixed 17-byte
/// `[steady, (effect, colour, brightness, speed) × 4]` block is not a TLV
/// record, so answering it with a PHY TLV would be a `0x00` the client parses
/// as garbage. US-117 answers it with an actual block instead — but the reason
/// it *has* to is on the client's write path.
/// `write_rskey_led_config` is read-modify-write
/// (`picoforge/src/hal/fido/mod.rs:2043-2057`): it reads the current block,
/// copies it, and overwrites only `block[0]`, `block[2 + 4i]` and
/// `block[3 + 4i]`, deliberately leaving effect (`1 + 4i`) and speed (`4 + 4i`)
/// alone. A device that stored the block but refused to read it back would take
/// that function's `if let Ok(..) && current.len() >= RSKEY_LED_CONF_LEN`
/// fall-through to an all-zero block — **which is exactly the silent
/// zeroing of every effect and speed that the EPIC predicted**, arriving by the
/// read rather than the write. See `led_read_modify_write_preserves_effect_and_speed`.
#[test]
fn config_read_refuses_targets_it_does_not_serve() {
    for (target, name) in [
        (
            0x00u8,
            "DEV_CONF — write-only over this channel by the client's own account",
        ),
        (
            0x03u8,
            "an unassigned target byte the protocol does not define",
        ),
    ] {
        let (mut dev, _trng) = DevicePinClient::boot();
        let (status, body) = dev.call(VENDOR_41, config_read_request(target).as_slice());
        assert_eq!(
            status, INVALID_PARAMETER,
            "{name} (target 0x{target:02X}) is not served by this firmware, and \
             a `0x00` here would be a body the client misparses. DEV_CONF is the \
             write-only record this ungated read must not reach: it is the USB \
             enabled-interface mask, the one config blob that changes what the \
             token can do on the bus, and the client says it is not readable \
             here (`picoforge/src/hal/fido/mod.rs:615-618`)"
        );
        assert!(
            body.is_empty(),
            "{name}: a non-zero status carries no body at all; PicoForge parses \
             the CBOR half only when `status == 0` \
             (`HidTransport::read_cbor_response`), so trailing bytes here would \
             be a second, quieter bug"
        );
    }
}

/// `CONFIG_READ` is ungated, and stays ungated once it is real.
///
/// This is the arm the client uses as its *feature probe* — before any token
/// is minted, and with no key 3 or key 4 on the wire
/// (`picoforge/src/hal/fido/ops.rs:1461-1479`). A `CONFIG_READ` that reached
/// [`fapico2_fido::vendor41::verify_mac`] or demanded a token would answer
/// `0x36`/`0x40` to the request the protocol deliberately sends bare, and the
/// desktop app would report the device as not supporting FIDO configuration.
///
/// Three legs, because "a valid token does not change the answer" is a much
/// weaker claim than it looks — a gate that *admits* valid tokens passes it
/// while still being a gate:
///
/// 1. no token in hand at all — rules out [`verify_mac`] being reachable,
///    which answers `0x36` (`PuatRequired`) for want of one;
/// 2. a `CREDENTIAL_MANAGEMENT` token (`0x04`) — the wrong permission, so an
///    arm that asked the table for a *specific* one would answer `0x40`;
/// 3. an `AUTHENTICATOR_CONFIG` token (`0x20`) — the right one, so an arm
///    that demanded the `0x20` it would demand for `CONFIG_WRITE` is caught
///    too.
///
/// One thing these legs deliberately do **not** claim: a gate that ran
/// `authorize(ConfigRead, ..)` unconditionally would pass all three, because
/// [`Requirement::Ungated`] admits any token *and* `None`. That is not a hole
/// in the test — it is what `Ungated` means — and it is why this test is about
/// the observable answer rather than about which function the arm called.
#[test]
fn config_read_demands_no_token() {
    // (1) No PIN, no token, nothing held.
    let (mut dev, _trng) = DevicePinClient::boot();
    dev.app.keystore().phy = full_phy_config();
    let (status, body) = dev.call(VENDOR_41, config_read_request(TARGET_PHY).as_slice());
    assert_eq!(
        status, 0x00,
        "with no token in hand CONFIG_READ must still answer CTAP2_OK — this \
         is the call PicoForge makes as its feature probe, before any token \
         exists"
    );
    assert!(
        !body.is_empty(),
        "and it must return the record rather than a bare `0x00`"
    );

    // (2) and (3) — the same answer whichever token is held.
    for (perm, name) in [(PERM_CM_LITERAL, "CREDENTIAL_MANAGEMENT"), (PERM_ACFG_LITERAL, "AUTHENTICATOR_CONFIG")] {
        let (mut dev, _trng) = DevicePinClient::boot();
        dev.app.keystore().phy = full_phy_config();
        dev.set_pin(b"1234");
        let _token = dev.get_pin_token_with_permissions(b"1234", perm);
        let (status, _) = dev.call(VENDOR_41, config_read_request(TARGET_PHY).as_slice());
        assert_eq!(
            status, 0x00,
            "a held {name} token ({perm:#04X}) must not change the answer: \
             CONFIG_READ is `Requirement::Ungated`, so consulting the \
             permission table for it could only ever admit the request"
        );
    }
}

/// The PHY record is bounded, and the bound is far below the reply buffer.
///
/// The `0x41` response is a CBOR map carrying a byte string, written into a
/// `heapless::Vec<u8, CTAP2_MAX_MSG>` on the device path. "It fits" is only
/// worth asserting if the size is derived rather than assumed, because the
/// failure mode is not a clean error — it is a truncated record that the
/// client parses as a *different* configuration.
#[test]
fn config_read_blob_fits_the_reply_buffer() {
    let full = full_phy_config();
    let len = fapico2_fido::vendor41::phy_record_len(&full);
    assert_eq!(
        len, 16,
        "four records: 2+4 (VID/PID) + 2+1 (GPIO) + 2+1 (brightness) + 2+2 (options)"
    );
    // The format's own ceiling, for the case where a future record carries
    // 255-byte strings rather than 1-byte values.
    let ceiling = fapico2_platform::phy_tlv::MAX_BLOB_LEN;
    assert!(
        ceiling < fapico2_fido::CTAP2_MAX_MSG,
        "even a blob of every tag at its maximal value ({ceiling} bytes) has to \
         fit the {}-byte reply buffer, or `CONFIG_READ` needs a size refusal it \
         does not have today",
        fapico2_fido::CTAP2_MAX_MSG
    );
    // The encoder refuses rather than truncating: a value over 255 bytes has
    // no one-byte length, and a wrapped length would be read as a different
    // record.
    assert_eq!(
        fapico2_platform::phy_tlv::TlvError::ValueTooLong { got: 256 },
        match fapico2_platform::phy_tlv::encode_record(
            fapico2_platform::phy_tlv::PhyTag::UsbProduct,
            &[0u8; 256],
            &mut HV::<u8, 512>::new(),
        ) {
            Err(e) => e,
            Ok(()) => panic!("256 bytes must not encode into a one-byte length"),
        },
        "the refusal has to be a refusal: truncating or wrapping the length \
         produces a blob the client reads as a different field"
    );
}

/// The status byte is never missing, even when there is no room for one.
///
/// # The failure this pins
///
/// `finish_reply` prepends the CTAP2 status byte to a body an arm already
/// wrote, which costs a slot. A body that exactly filled the reply buffer
/// would leave nowhere to put it, and the old `.ok()` on that insert
/// **discarded** the failure: the reply went out with body content in byte 0.
/// The client then reads that byte as the status
/// (`HidTransport::read_cbor_response`,
/// `picoforge/src/hal/transport/fido.rs:461`) — so a perfectly good
/// `CONFIG_READ` response would have been reported as a CTAP2 error whose
/// code is the first character of its own CBOR.
///
/// Unreachable today: the largest body this channel produces is a 16-byte PHY
/// record in a `CTAP2_MAX_MSG` (7609) buffer. It is reachable in principle as
/// soon as US-115 adds a `CONFIG_WRITE` body, and it is tested here on a
/// deliberately tiny buffer so that "unreachable" does not have to be taken on
/// trust.
#[test]
fn finish_reply_refuses_rather_than_emitting_a_body_without_a_status() {
    // (a) the ordinary case: status in front, body behind, byte order intact.
    let mut roomy: HV<u8, 8> = HV::new();
    roomy.extend_from_slice(&[0xA1, 0x01, 0x40]).unwrap();
    fapico2_fido::vendor41::finish_reply(&mut roomy, 0x00);
    assert_eq!(
        roomy.as_slice(),
        &[0x00, 0xA1, 0x01, 0x40],
        "`status || CBOR`, with the status byte first — the client reads \\
         `response_data[0]` as the status, so this order is the contract"
    );

    // (b) the failure: a buffer with no free slot at all.
    let mut full: HV<u8, 4> = HV::new();
    full.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
    fapico2_fido::vendor41::finish_reply(&mut full, 0x00);
    assert_eq!(
        full.as_slice(),
        &[0x15],
        "a body that fills the buffer gets a clean, correctly framed refusal \\
         (CTAP2_ERR_LIMIT_EXCEEDED, 0x15) — one non-zero status byte and \\
         nothing else. Leaving the body in place would make the client read \\
         0xAA as the status"
    );
    assert_ne!(
        full.first().copied().unwrap_or(0xFF),
        0x00,
        "and in particular the reply must not claim success, which is what the \\
         discarded `.ok()` would have produced"
    );

    // (c) the same for a non-zero status that somehow left a body behind: the
    // body still goes, and the status is not overwritten by a second one.
    let mut stale: HV<u8, 16> = HV::new();
    stale.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
    fapico2_fido::vendor41::finish_reply(&mut stale, 0x30);
    assert_eq!(
        stale.as_slice(),
        &[0x30],
        "NOT_ALLOWED with a body behind it is still the lone status byte: the \\
         client parses the CBOR half only when the status is zero"
    );
}

/// A reused output buffer must not leak the previous command's reply.
///
/// # Why this test exists
///
/// On the real device, `out` is `HID_RESP` — a `&'static mut` the firmware
/// hands to every CTAPHID command in turn and **never clears**
/// (`firmware/src/tasks.rs`: it is aliased out of the static once at
/// `:486-487` and then passed down; there is no `ctap_out.clear()` anywhere).
///
/// `vendor41::finish_reply` *prepends* the status byte to whatever the buffer
/// holds, so on the success path it assumes the buffer was emptied first. For
/// a while that assumption was carried by `config_read` clearing on entry —
/// which made the invariant load-bearing on the one function that happens to
/// clear today, rather than on the dispatch arm that owns the buffer. Deleting
/// `config_read`'s own `clear()` shows exactly what that was worth:
///
/// ```text
/// status=0x00 reply=[00, DE AD BE EF CA FE, A1 01 46 00 04 12 09 00 01]
/// ```
///
/// Six bytes of the *previous* command's reply, sitting between the status
/// byte and this one's body. No existing test caught it, because every one of
/// them hands `finish_reply` a buffer it just created.
///
/// The same stale bytes are planted here directly, so the property is pinned
/// on the dispatch arm rather than on an accident of one handler. It runs on
/// both paths, because the two `match`es are independent and only the device
/// one reads a reused buffer today — the host leg is there to keep the host
/// arm from acquiring the same dependence without a test noticing.
#[test]
fn vendor41_reused_output_buffer_carries_no_stale_bytes() {
    /// A recognisable prior reply: a status byte that is not `0x00`, followed
    /// by bytes no `CONFIG_READ` response could contain.
    const STALE: [u8; 7] = [0x33, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

    // --- device: `out` is the firmware's reused HID_RESP ---
    let (mut dev, _trng, mut store) = device_app();
    dev.keystore().phy = full_phy_config();
    let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
    out.extend_from_slice(&STALE).unwrap();
    let n = dev.process_ctap2_with_store(
        VENDOR_41,
        config_read_request(TARGET_PHY).as_slice(),
        [1, 2, 3, 4],
        &mut out,
        Some(&mut store),
    );
    let reply = &out[..n];
    // The whole reply, against a literal. An exact comparison is what catches
    // *interleaved* staleness: a length check would pass if the stale bytes
    // somehow balanced out, and a per-byte "is this byte the old one" scan
    // misses any position where the old value happens to coincide with the
    // new one. The literal is the same one
    // `config_read_returns_phy_tlv_blob` pins, plus the status byte.
    const EXPECTED: [u8; 20] = [
        0x00, // CTAP2_OK
        0xA1, 0x01, 0x50, // {1: bstr(16)}
        0x00, 0x04, 0x12, 0x09, 0x00, 0x01, // VID/PID
        0x04, 0x01, 0x04, // LED GPIO
        0x05, 0x01, 0x50, // LED brightness
        0x06, 0x02, 0x00, 0x02, // options
    ];
    assert_eq!(
        reply,
        &EXPECTED[..],
        "`HID_RESP` is reused across every CTAPHID command and is never \
         cleared by the firmware, so the dispatch arm has to empty it before \
         the handler runs. With the stale reply still in the buffer, the old \
         body bytes would appear between the status byte and this one's body"
    );

    // --- host: the local buffer starts empty, so nothing can survive ---
    let (mut host, _client) = common::setup();
    host.keystore().get_auth_state_mut().phy = full_phy_config();
    let host_reply = host.process_ctap2(
        VENDOR_41,
        config_read_request(TARGET_PHY).as_slice(),
        [1, 2, 3, 4],
    );
    assert_eq!(
        host_reply.first().copied(),
        Some(0x00),
        "host: same reply shape, from a fresh buffer — the device arm above is \
         the one reading a reused buffer, and this leg is what says the two \
         arms produce the same bytes"
    );
    assert_eq!(host_reply.len(), 20, "host: and the same length");
}

/// The `2` map is emitted when there is something to report, and only then.
///
/// The **populated** half of the rule [`EffectiveConfig`] exists for. On this
/// firmware nothing populates it — no boot-time resolver reads `PhyConfig` to
/// drive hardware — so `config_read_omits_the_effective_config_map` covers
/// only the empty case, and the emission branch would otherwise be ~20 lines
/// shipped on the strength of a comment. `write_config_read_response` takes
/// the value by reference precisely so this leg can exist before a resolver
/// does.
///
/// The keys are the ones PicoForge reads at
/// `picoforge/src/hal/fido/ops.rs:1490-1496` — `4` for the effective LED GPIO,
/// `8` for the touch timeout, `0x0C` for the LED driver — and the map is
/// emitted in ascending key order, which is the canonical order used
/// throughout this channel.
///
/// The expected bytes are literal: a two-pair map (`0xA2`), the record under
/// key 1, then key 2 as a three-pair map with the three values. A fourth
/// field added to [`EffectiveConfig::is_empty`] but not to the emission would
/// make the header count disagree with the pairs, and this assertion — being
/// an exact byte comparison rather than a decoded one — is what catches it.
#[test]
fn write_config_read_response_emits_the_effective_map_when_populated() {
    use fapico2_fido::vendor41::{write_config_read_response, EffectiveConfig};

    let eff = EffectiveConfig {
        led_gpio: Some(25),
        touch_timeout: Some(30),
        led_driver: Some(2),
    };
    let mut out: HV<u8, 64> = HV::new();
    write_config_read_response(&mut out, &full_phy_config(), &eff).unwrap();

    assert_eq!(
        out.as_slice(),
        &[
            0xA2, // map(2)
            0x01, 0x50, // key 1, bstr(16)
            0x00, 0x04, 0x12, 0x09, 0x00, 0x01, // VID/PID
            0x04, 0x01, 0x04, // LED GPIO
            0x05, 0x01, 0x50, // LED brightness
            0x06, 0x02, 0x00, 0x02, // options
            0x02, 0xA3, // key 2, map(3)
            0x04, 0x18, 0x19, // LED GPIO 25 — >=24, so a one-byte argument
            0x08, 0x18, 0x1E, // touch timeout 30 — likewise
            0x0C, 0x02, // LED driver 2 — fits in the head byte
        ],
        "a populated EffectiveConfig is a second pair holding exactly the \\
         three keys PicoForge reads, in ascending order. This is the leg that \\
         makes the emission branch reachable at all. The two-byte value
         encodings are the point of writing it out by hand: 25 and 30 do not
         fit in a CBOR head, so a writer that assumed they did would emit
         0x18 0x18 / 0x18 0x1D and the client would read back 24 and 29"
    );

    // Partial population is the interesting middle: one key set, two absent.
    // This is what a first boot-resolver would actually produce.
    let mut partial: HV<u8, 64> = HV::new();
    write_config_read_response(
        &mut partial,
        &full_phy_config(),
        &EffectiveConfig {
            led_gpio: Some(25),
            ..Default::default()
        },
    )
    .unwrap();
    let mut p = nh::Parser::new(&partial);
    assert_eq!(p.next().unwrap(), nh::Item::Map(2), "still two pairs");
    assert_eq!(p.next().unwrap(), nh::Item::U(1), "key 1");
    assert!(matches!(p.next().unwrap(), nh::Item::B(_)), "the record");
    assert_eq!(p.next().unwrap(), nh::Item::U(2), "key 2");
    assert_eq!(
        p.next().unwrap(),
        nh::Item::Map(1),
        "and a **one**-pair sub-map, not a three-pair one with nulls: the \\
         header count has to match the pairs the client will iterate, or its \\
         `if let Some(n) = e.get(&Integer(k))` lookup lands on the wrong value"
    );

    // And the empty case still emits nothing, through the same code path.
    let mut empty: HV<u8, 64> = HV::new();
    write_config_read_response(&mut empty, &full_phy_config(), &EffectiveConfig::default())
        .unwrap();
    assert_eq!(
        empty[0], 0xA1,
        "an empty EffectiveConfig is a one-pair map — the device-side \\
         behaviour `config_read_omits_the_effective_config_map` pins through \\
         the command path, here pinned through the writer directly"
    );
}

// ---------------------------------------------------------------------------
// US-115: `CONFIG_WRITE` (`0x0C`) and its field-tiered gate.
//
// # Three tests, one per row of the EPIC's table — and why three
//
// The EPIC is explicit about the reason, and the reason is the point of the
// story: *"A single presence test would pass under RS-Key's weaker gate and so
// does not test the decision."* RS-Key's `rsk-phy` accepts a `CONFIG_WRITE`
// with no PIN and no token at all. A test that only checked "benign fields
// need a touch" would therefore be green against RS-Key's firmware *and*
// against ours, and would prove nothing about the decision that distinguishes
// them. So the three tests are:
//
// | test | row | fails if |
// |---|---|---|
// | [`config_write_rejected_without_presence`] | benign overlay → presence | the benign tier stops needing a grant |
// | [`config_write_identity_field_requires_pin_token`] | identity → `0x20` token | the identity tier is dropped, or weakened to presence |
// | [`config_write_rejects_zero_interface_mask_unconditionally`] | zero mask → no gate at all | the refusal is moved behind a gate, so a token can reach it |
//
// The third is the one that cannot be reached by "be stricter": it is the only
// rule whose safety property is that **no** authority discharges it, so it is
// the only one a plausible-looking tightening can break.
// ---------------------------------------------------------------------------

/// The PHY tags as **wire bytes**, with the names PicoForge gives them
/// (`picoforge/src/hal/fido/constants.rs`, the `RSKEY_PHY_TAG_*` block;
/// enumerated in `platform/src/phy_tlv.rs` as `PhyTag`).
///
/// Spelled as literals on the test side, like [`VENDOR_41`]: the point of
/// `tier_of` is that it maps *these* bytes to a gate, so the test must name the
/// bytes rather than import the mapping and assert it agrees with itself.
const TAG_VIDPID: u8 = 0x00;
const TAG_LED_GPIO: u8 = 0x04;
const TAG_LED_BRIGHTNESS: u8 = 0x05;
const TAG_OPTIONS: u8 = 0x06;
const TAG_PRESENCE_TIMEOUT: u8 = 0x08;
const TAG_USB_PRODUCT: u8 = 0x09;
const TAG_CURVES: u8 = 0x0A;
const TAG_ENABLED_USB_ITF: u8 = 0x0B;
const TAG_LED_DRIVER: u8 = 0x0C;
const TAG_LED_ORDER: u8 = 0x0D;
const TAG_LED_NUM: u8 = 0x0E;
const TAG_USB_MANUFACTURER: u8 = 0x0F;

/// `0x7A` — outside the protocol's twelve tags, so a record carrying it is a
/// record this firmware cannot classify. The same byte
/// `platform/src/phy_tlv.rs`'s `decoder_yields_unknown_tags_rather_than_refusing_them`
/// uses, deliberately: one byte, two opposite policies, and the difference
/// between them is the whole of the "unknown tag" question.
const TAG_UNKNOWN: u8 = 0x7A;

/// `RSKEY_CFG_TARGET_PHY` — the `target` byte in `CONFIG_WRITE`'s params
/// (`picoforge/src/hal/fido/constants.rs:773`).
const TARGET_PHY_LITERAL: u8 = 0x01;
/// `RSKEY_CFG_TARGET_DEV_CONF` — the USB enabled-interface record
/// (`picoforge/src/hal/fido/constants.rs:771`). Carries a *management* TLV, not
/// a PHY one; US-117 serves it (`picoforge/src/hal/fido/mod.rs:2086-2091`).
const TARGET_DEV_CONF_LITERAL: u8 = 0x00;
/// `RSKEY_CFG_TARGET_LED` — the LED status block
/// (`picoforge/src/hal/fido/constants.rs:775`). US-117 serves it on both
/// `CONFIG_WRITE` and `CONFIG_READ`.
const TARGET_LED_LITERAL: u8 = 0x02;
/// `FIDO_MGMT_TAG_USB_ENABLED` — the `DEV_CONF` record's only tag
/// (`picoforge/src/hal/fido/mod.rs:2071`). A *management* tag, deliberately not
/// one of the twelve `PhyTag` values above.
const DEV_CONF_TAG_USB_ENABLED_LITERAL: u8 = 0x03;

/// CTAP2.1 `CTAP2_ERR_UNSUPPORTED_OPTION` — a well-formed request naming
/// something this authenticator does not do.
const UNSUPPORTED_OPTION: u8 = 0x2A;
/// CTAP2.1 `CTAP2_ERR_INVALID_OPTION` — a well-formed option carrying a value
/// that is never acceptable. Used for exactly one thing: the zero
/// enabled-USB-interface mask.
const INVALID_OPTION: u8 = 0x2B;
/// CTAP2.1 `CTAP2_ERR_UP_REQUIRED` — a touch is needed before this proceeds.
const UP_REQUIRED: u8 = 0x3B;
/// CTAP2.1 `CTAP2_ERR_PIN_AUTH_BLOCKED` — pinUvAuth is refused outright
/// because the three-strike latch is set.
const PIN_AUTH_BLOCKED: u8 = 0x34;

/// A PHY TLV blob, assembled from `tag, value` pairs by hand.
///
/// **Not** `fapico2_platform::phy_tlv::encode_record`. The format is
/// `tag, len, value` with a one-byte length and nothing else
/// (`platform/src/phy_tlv.rs`'s module docs, read off
/// `build_rskey_phy_tlv`, `picoforge/src/hal/fido/mod.rs:1015-1100`). Using the
/// codec under test to build the codec's input would make every assertion below
/// a statement about the encoder agreeing with itself; this writes the three
/// header/content bytes out longhand so a wrong tag or a wrong endianness in
/// the *decoder* is visible as a failing test rather than as two consistent
/// mistakes.
///
/// Panics rather than refusing on a value over 255 bytes, because no record in
/// these tests is and a silently-dropped record would be exactly the failure
/// mode the story is about.
fn phy_blob(records: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (tag, value) in records {
        assert!(
            value.len() <= 255,
            "a PHY record length is one byte; a test that wanted a longer value \
             would be testing a format this protocol does not have"
        );
        out.push(*tag);
        out.push(value.len() as u8);
        out.extend_from_slice(value);
    }
    out
}

/// `subCommandParams` for `CONFIG_WRITE`: `{1: target, 2: h'blob'}`.
///
/// Hand-rolled for the same reason as [`phy_blob`], and pinned against a
/// literal below so the two helpers cannot drift from the CBOR head PicoForge
///'s serialiser produces. Two head forms only, because no blob in this story
/// is longer than 23 bytes — `A2 01 tt 02 58 LL` — or between 24 and 255, which
/// is `A2 01 tt 02 59 LL LL`. (`0x58`/`0x59` are CBOR major type 2 with a
/// 1- and 2-byte length; this format has no long form, so a blob over 255
/// bytes cannot be expressed at all — see `phy_tlv::MAX_VALUE_LEN`.)
fn config_write_params(target: u8, blob: &[u8]) -> Vec<u8> {
    let mut out = vec![0xA2, 0x01, target, 0x02];
    if blob.len() <= 23 {
        out.push(0x58);
        out.push(blob.len() as u8);
    } else {
        assert!(blob.len() <= 255, "see the doc comment: no long form exists");
        out.push(0x59);
        out.extend_from_slice(&(blob.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(blob);
    out
}

/// The whole `0x41` request for a `CONFIG_WRITE` of `blob`.
///
/// `mac` is `None` for the bare form. When it is `Some`, the MAC is computed
/// over the exact params bytes this function just built, with
/// [`picoforge_mac`] — the same construction the client uses
/// (`picoforge/src/hal/fido/ops.rs:1526-1534`), so a `0x33` in a test means
/// the firmware's message layout moved and not that the fixture is wrong.
fn config_write_request(blob: &[u8], token: Option<&[u8; 32]>) -> Vec<u8> {
    let params = config_write_params(TARGET_PHY_LITERAL, blob);
    match token {
        Some(t) => {
            let mac = picoforge_mac(t, VENDOR_41, 0x0C, &params);
            rskey_request_with_mac(0x0C, &params, Some(1), Some(&mac))
        }
        None => rskey_request_with_mac(0x0C, &params, None, None),
    }
}

// A per-test presence answer, so the benign tier can be driven both ways.
//
// A plain comment rather than a doc one because `thread_local!` is a macro
// invocation, and rustc reports a doc comment on one as `unused doc comment`.
//
// `thread_local!` rather than a `static` because the gate is an
// `fn() -> bool` and so cannot capture, and because libtest gives each test
// its own thread: a global would let `config_write_rejected_without_presence`
// (which wants "no press") and the tests that want a press (which want one)
// overwrite each other and flake. Under `--test-threads=1` they share a
// thread and each test sets the value before use, so both schedules are
// correct.
thread_local! {
    static PRESENCE_PRESSED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Arm or disarm the test's presence answer for the current thread.
fn set_presence(pressed: bool) {
    PRESENCE_PRESSED.with(|p| p.set(pressed));
}

/// The presence poll [`PresenceGate`] is handed in these tests.
fn presence_poll() -> bool {
    PRESENCE_PRESSED.with(|p| p.get())
}

/// `vendor41::handle` for a `CONFIG_WRITE`, with every input stated.
///
/// The arm is driven **directly** rather than through a `FidoApp` for the gate
/// tests, for a reason worth stating: the gate is per-*field*, and the field
/// lives in the blob, so a test that has to arrange a `clientPin` handshake to
/// reach it is testing the handshake. [`config_write_persists_before_the_ack`]
/// and [`config_write_identity_field_is_written_by_a_0x20_token`] drive the
/// same rules through the device command path with a real minted token, so
/// both levels are covered and neither is taken on trust.
///
/// `phy` is the record as it stands; the returned [`Outcome::phy`] is what the
/// dispatch arm would commit.
fn run_config_write(
    blob: &[u8],
    auth: Option<TokenAuth<'_>>,
    present: bool,
    phy: &fapico2_fido::vendorff::PhyConfig,
) -> fapico2_fido::vendor41::Outcome {
    set_presence(present);
    let req = config_write_request(
        blob,
        auth.map(|a| a.token),
    );
    handle_isolated(
        &req,
        auth,
        phy,
        fapico2_fido::vendor41::PresenceGate {
            window_grant: None,
            poll: Some(presence_poll),
            tag: 0,
        },
        &mut HV::new(),
    )
}

/// A `TokenAuth` over the golden token with the golden permissions.
fn golden_auth() -> TokenAuth<'static> {
    TokenAuth {
        token: &GOLDEN_TOKEN,
        permissions: PERM_ACFG_LITERAL,
        blocked: false,
    }
}

/// The VID/PID this file uses throughout: Raspberry Pi's vendor id `0x2E8A`
/// and a product id of `0x0005`.
///
/// Chosen so the two halves are *distinguishable as bytes*: `0x2E`/`0x8A` and
/// `0x00`/`0x05` are not a repeated digit, so a big-endian/little-endian
/// mistake in either the encoder or the decoder produces a different number
/// rather than the same one. A `(0x1212, 0x1212)` pair would not.
const TEST_VID: u16 = 0x2E8A;
const TEST_PID: u16 = 0x0005;

/// The four bytes a VID/PID record holds, big-endian, written out longhand.
const VIDPID_BYTES: [u8; 4] = [0x2E, 0x8A, 0x00, 0x05];

/// The packed form those four bytes must decode to: `0x2E8A << 16 | 0x0005`,
/// which is `0x2E8A_0005`.
///
/// Written out rather than computed with
/// `fapico2_fido::vendorff::pack_vidpid`, because that function is one of the
/// two things under test here — a computed expectation would make this the
/// encoder agreeing with itself, which this file has been caught by twice.
const VIDPID_PACKED: u32 = 0x2E8A_0005;

/// [`VIDPID_PACKED`] and [`VIDPID_BYTES`] are two transcriptions of the same
/// fact — the packed `u32` and the four big-endian bytes — and neither is
/// computed with the code under test. This is the one place they are tied back
/// to the VID/PID they name, so neither is a free-floating literal that could
/// be edited without anything noticing.
#[test]
fn config_write_vidpid_literals_agree_with_each_other() {
    assert_eq!(
        VIDPID_PACKED,
        ((TEST_VID as u32) << 16) | TEST_PID as u32,
        "0x2E8A_0005 is (vid << 16) | pid for vid 0x2E8A and pid 0x0005 — the \
         packing `vendorff::pack_vidpid` and the client's \
         `write_legacy_hardware_config` both use"
    );
    assert_eq!(
        VIDPID_BYTES,
        [
            (TEST_VID >> 8) as u8,
            TEST_VID as u8,
            (TEST_PID >> 8) as u8,
            TEST_PID as u8,
        ],
        "and the record form is the same pair big-endian, which is what the \
         client writes (`tlv.extend_from_slice(&vid.to_be_bytes())`, \
         `picoforge/src/hal/fido/mod.rs:1026-1027`) and reads back (`:952`)"
    );
    assert_eq!(
        crate_packed_from_bytes(),
        VIDPID_PACKED,
        "and the two representations must decode to each other: a little-endian \
         record would be a *valid* record that is a different VID/PID, which \
         is the identity-spoofing primitive rather than a parse bug"
    );
}

/// The packed form the record's four bytes decode to, computed here by hand
/// from the byte order rather than through `vendorff`.
fn crate_packed_from_bytes() -> u32 {
    ((VIDPID_BYTES[0] as u32) << 24)
        | ((VIDPID_BYTES[1] as u32) << 16)
        | ((VIDPID_BYTES[2] as u32) << 8)
        | (VIDPID_BYTES[3] as u32)
}

/// # `config_write_rejected_without_presence` — row 1, benign overlay
///
/// A benign PHY field (the LED GPIO, tag `0x04`) is gated on a **presence
/// grant** and nothing else. The grant is the authority, so the test drives it
/// both ways: no press must be refused, a press must be accepted, and the
/// second half is what stops the test from passing for the wrong reason — a
/// blanket "always refuse" would satisfy the first assertion too.
///
/// The identity tier is deliberately *not* touched here. That is
/// [`config_write_identity_field_requires_pin_token`]'s job, and a test that
/// did both would pass under RS-Key's weaker gate, which is the failure the
/// EPIC warns about.
#[test]
fn config_write_rejected_without_presence() {
    let blob = phy_blob(&[(TAG_LED_GPIO, &[0x04])]);
    let auth = golden_auth();
    let phy = fapico2_fido::vendorff::PhyConfig::default();

    let refused = run_config_write(&blob, Some(auth), false, &phy);
    assert_eq!(
        refused.status.code(),
        UP_REQUIRED,
        "an LED GPIO write with no presence grant is the benign tier's whole \
         gate, and it must be refused. RS-Key accepts this with neither a PIN \
         nor a touch, which is the HIGH-1 finding in the RS-Key adoption review",
    );
    assert_eq!(
        refused.phy, None,
        "nothing may be proposed for commit on a refused write — otherwise the \
         dispatch arm would persist a configuration the user never authorised"
    );
    assert!(
        !refused.pin_auth_failure,
        "the benign tier authenticates nothing, so a `0x3B` must not be \
         charged against the app's three-strike PIN counter"
    );

    let granted = run_config_write(&blob, Some(auth), true, &phy);
    assert_eq!(
        granted.status.code(),
        0x00,
        "the same write with a presence grant must succeed: a test that only \
         asserted the refusal would also pass a gate that refuses everything, \
         and would not tell a present user from an absent one",
    );
    assert_eq!(
        granted.phy.map(|p| p.led_gpio),
        Some(Some(0x04)),
        "and it must propose the GPIO the blob asked for — a 0x00 with an empty \
         record is an ack for a write that did nothing"
    );
}

/// # `config_write_identity_field_requires_pin_token` — row 2, identity
///
/// The VID/PID record changes how the device identifies itself on the USB bus,
/// so it is gated on a `pinUvAuthToken` carrying `AUTHENTICATOR_CONFIG`
/// (`0x20`) — and on **nothing weaker**.
///
/// The four assertions below are the load-bearing part, and the middle two are
/// what make this test the EPIC asks for rather than the one it warns against:
///
/// 1. **No token at all** → `0x36`. A presence grant alone must not open an
///    identity write, or the gate would be presence-only and would pass under
///    RS-Key's rule.
/// 2. **A presence grant, still no token** → still `0x36`. This is the
///    assertion that fails if the identity tier is dropped: with the tier
///    weakened to presence, this request would answer `0x00`.
/// 3. **A token with the wrong permission** → `0x40`. A `CREDENTIAL_MANAGEMENT`
///    (`0x04`) token must not rewrite the token's own configuration.
/// 4. **A `0x20` token** → `0x00`, and the record is proposed.
#[test]
fn config_write_identity_field_requires_pin_token() {
    let blob = phy_blob(&[(TAG_VIDPID, &VIDPID_BYTES)]);
    let phy = fapico2_fido::vendorff::PhyConfig::default();

    // (1) no token, no press.
    let anon = run_config_write(&blob, None, false, &phy);
    assert_eq!(
        anon.status.code(),
        PUAT_REQUIRED,
        "an unauthenticated VID/PID write must demand a token. This is the \
         identity-spoofing primitive: a local process that rewrites the USB \
         identity of a token somebody else is about to authenticate against"
    );
    assert_eq!(
        anon.phy, None,
        "and nothing is proposed: a request that never authenticated cannot \
         have earned a configuration change"
    );

    // (2) a presence grant, still no token. The step that a
    //    presence-only (i.e. RS-Key's) gate would get wrong.
    let touched = run_config_write(&blob, None, true, &phy);
    assert_eq!(
        touched.status.code(),
        PUAT_REQUIRED,
        "a physical touch must NOT authorise an identity field. A press is a \
         statement that the person in front of the device wants the benign \
         thing it is offering; it is not consent to re-enumerate the token \
         under someone else's VID. Dropping the identity tier makes this \
         answer 0x00, which is exactly the regression this test exists for"
    );

    // (3) the right token, the wrong permission.
    let credmgmt = TokenAuth {
        token: &GOLDEN_TOKEN,
        permissions: 0x04,
        blocked: false,
    };
    let wrong_bit = run_config_write(&blob, Some(credmgmt), true, &phy);
    assert_eq!(
        wrong_bit.status.code(),
        0x40,
        "a CREDENTIAL_MANAGEMENT token must not rewrite device configuration. \
         That boundary is the reason `required_permission` is a table with one \
         row per sub-command rather than a single channel-wide bit",
    );

    // (4) the right token.
    let ok = run_config_write(&blob, Some(golden_auth()), true, &phy);
    assert_eq!(
        ok.status.code(),
        0x00,
        "a token carrying AUTHENTICATOR_CONFIG must be accepted — the \
         compatibility check found that PicoForge does supply exactly this \
         (`picoforge/src/hal/fido/mod.rs:1163-1177` mints it before every \
         `rs_key_config_write`), so the gate does not degrade the Config \
         screen to read-only"
    );
    assert_eq!(
        ok.phy.map(|p| p.vid_pid),
        Some(Some(VIDPID_PACKED)),
        "and the record it proposes must be the VID/PID the blob carried, \
         decoded big-endian"
    );
}

/// A mixed blob is gated by its **strongest** field, and the token is enough
/// on its own — a touch is not additionally required.
///
/// The second half is the compatibility claim, and it is the one that would
/// silently hang the desktop app: PicoForge's `rs_key_config_write` allows
/// 30 s (`picoforge/src/hal/fido/ops.rs:1550`) and sends no touch. If an
/// authenticated write also demanded a button press, the Config screen would
/// sit until that timeout and the user would see nothing but a failure.
#[test]
fn config_write_mixed_blob_needs_the_token_but_not_a_touch() {
    let blob = phy_blob(&[
        (TAG_LED_GPIO, &[0x0C]),
        (TAG_VIDPID, &VIDPID_BYTES),
    ]);
    let phy = fapico2_fido::vendorff::PhyConfig::default();

    let no_press = run_config_write(&blob, Some(golden_auth()), false, &phy);
    assert_eq!(
        no_press.status.code(),
        0x00,
        "a 0x20 token is a strictly stronger authorisation than a touch, so \
         requiring both would be a requirement with no security content behind \
         it — and PicoForge sends no touch for CONFIG_WRITE"
    );
    let proposed = no_press.phy.expect("a 0x00 proposes a record");
    assert_eq!(
        (proposed.led_gpio, proposed.vid_pid),
        (Some(0x0C), Some(VIDPID_PACKED)),
        "both fields apply, whichever order the blob listed them in"
    );

    let no_token = run_config_write(&blob, None, true, &phy);
    assert_eq!(
        no_token.status.code(),
        PUAT_REQUIRED,
        "the benign field in the same blob must not launder the identity field \
         past the token gate: the aggregate tier is the strongest one present"
    );
}

/// # `config_write_rejects_zero_interface_mask_unconditionally` — row 3
///
/// `TAG_ENABLED_USB_ITF` (`0x0B`) with the value `0` is refused in **every**
/// authentication state: no token, a `0x20` token, a wrong-permission token
/// and a legacy zero-permission token all get the same answer, and the answer
/// is the same one with and without a presence grant.
///
/// That is the property the EPIC asks for and the property a plausible-looking
/// tightening breaks. RS-Key's `rsk-phy` accepts `(0x0B, 1)` with no non-zero
/// floor, so one unauthenticated packet makes the device re-enumerate with no
/// USB interfaces — gone from every attached host until BOOTSEL recovery. A
/// denial of service against the whole bus, with no legitimate use in any
/// configuration.
///
/// The three *different* statuses in the companion assertions are what make
/// this one specific. `0x0B` with the value `1` is `0x2A`
/// (no field for it in the persisted record) and a VID/PID write with no token
/// is `0x36`, so `0x2B` can only be the zero-mask rule and not one of those
/// two rules leaking into the answer.
#[test]
fn config_write_rejects_zero_interface_mask_unconditionally() {
    let zero = phy_blob(&[(TAG_ENABLED_USB_ITF, &[0x00])]);
    let phy = fapico2_fido::vendorff::PhyConfig::default();

    for (what, auth, present) in [
        ("no token, no press", None, false),
        ("no token, with a press", None, true),
        ("a 0x20 token", Some(golden_auth()), false),
        ("a 0x20 token and a press", Some(golden_auth()), true),
    ] {
        let outcome = run_config_write(&zero, auth, present, &phy);
        assert_eq!(
            outcome.status.code(),
            INVALID_OPTION,
            "{what}: a zero enabled-USB-interface mask must be refused whatever \
             the caller holds. A gate in front of this rule would make it \
             reachable by anyone who can obtain a token, and the EPIC's point \
             is that it has no legitimate use in *any* configuration"
        );
        assert_eq!(
            outcome.phy, None,
            "{what}: nothing may be proposed for commit"
        );
    }

    // It is refused *before* the gate, not inside the identity branch. This
    // control is what says so: the same tag with a **non-zero** value gets
    // past the zero-mask rule and is then stopped by the *gate* instead, so
    // the two rules are distinguishable and the loop above cannot be passing
    // because 0x0B is simply refused.
    //
    // US-117 changed what the non-zero value answers. It used to be
    // `0x2A` (`UnsupportedOption`) because the mask had no field in the
    // persisted record on the PHY path; `DEV_CONF` (`0x00`) now gives it one,
    // so `0x0B` is writable and reaches the identity gate — and a request with
    // no token is `0x36` (`PuatRequired`). The status is still *not* `0x2B`,
    // which is the property the control exists to protect.
    let nonzero = phy_blob(&[(TAG_ENABLED_USB_ITF, &[0x01])]);
    let unsupported = run_config_write(&nonzero, None, false, &phy);
    assert_eq!(
        unsupported.status.code(),
        PUAT_REQUIRED,
        "0x0B with a non-zero value is a different fault — the mask is now \
         writable, so what stops it is the identity tier's gate, not the \
         record. It must answer 0x36 (no token) and not 0x2B. If it answered \
         0x2B the loop above would be passing for the wrong reason"
    );
    assert_eq!(
        unsupported.phy, None,
        "and a gated 0x0B write must propose nothing to commit"
    );
    // ...and with the token it is written, which is the other half of the
    // control: the rule above is about the value, not about the tag.
    let with_token = run_config_write(&nonzero, Some(golden_auth()), false, &phy);
    assert_eq!(
        with_token.status.code(),
        0x00,
        "the same non-zero 0x0B write with a 0x20 token is accepted — 0x0B and \
         DEV_CONF's 0x03 write one field and are held to one zero-mask rule"
    );
    assert_eq!(
        with_token.phy.expect("accepted").enabled_usb_itf,
        Some(0x0001),
        "and the mask is stored as the number it is, from the one-byte \
         carrier's width"
    );

    let vidpid_no_token =
        run_config_write(&phy_blob(&[(TAG_VIDPID, &VIDPID_BYTES)]), None, true, &phy);
    assert_eq!(
        vidpid_no_token.status.code(),
        PUAT_REQUIRED,
        "and a VID/PID write with a press but no token is the *identity* rule \
         at 0x36 — so 0x2B above can only be the zero-mask rule"
    );

    // The width is checked before the value, so a multi-byte `0x0B` record that
    // merely *starts* with zero gets the width status, not `0x2B`. The
    // client's reader would skip such a record (`picoforge/src/hal/fido/
    // mod.rs:1001-1003`) rather than misread it, and `0x2B` — "an invalid value
    // for a real option" — is not what a wrong-width record is.
    //
    // US-117 changed the status here from `0x2A` to `0x02`, and the change is
    // the rule working rather than drifting. `0x2A` was right for the wrong
    // reason: `0x0B` had no field in the persisted record, so *every* `0x0B`
    // record was unsupported and the width never had to be looked at. Now that
    // the tag is writable the width *is* checked, and a three-byte record is a
    // wrong-width record — `InvalidParameter` (`0x02`), the same status a
    // wrong-width VID/PID earns. The status is still not `0x2B`, which is the
    // property this leg exists to protect.
    let wrong_width = phy_blob(&[(TAG_ENABLED_USB_ITF, &[0x00, 0x01, 0x00])]);
    let bad_width = run_config_write(&wrong_width, None, false, &phy);
    assert_eq!(
        bad_width.status.code(),
        INVALID_PARAMETER,
        "a three-byte 0x0B record whose leading byte is zero is a wrong-width \
         record, not a zero mask: it must answer 0x02, or 0x2B would be \
         reachable by a shape the rule was never about"
    );
    assert_eq!(
        bad_width.phy, None,
        "and a wrong-width record must propose nothing to commit"
    );
}

/// The classifier is exhaustive over the protocol's twelve tags, and a tag
/// outside them is refused rather than admitted as benign.
///
/// The first half is a compile-time claim restated as a test: `tier_of`'s
/// `match` has no `_` arm, so a tag added to `PhyTag` cannot be added without
/// being tiered. The test pins the *result* — that exactly two of the twelve
/// are identity-tier — so that adding a fourteenth tag and tiering it
/// `Presence` "because it looked cosmetic" is a visible, reviewed change
/// rather than an invisible one.
///
/// The second half is the security property, and it is the reason the blob is
/// not classified by a `match` with a catch-all: the blob is attacker-chosen,
/// so an unrecognised tag is a tag nobody has decided anything about. RS-Key's
/// reader skips it (`picoforge/src/hal/fido/mod.rs:1001-1003`); a *writer*
/// cannot, because a writer has to know what it is authorising.
#[test]
fn config_write_unknown_tag_is_refused_not_treated_as_benign() {
    use fapico2_platform::phy_tlv::PhyTag;
    use fapico2_fido::vendor41::{tier_of, tier_of_wire, FieldTier};

    // The protocol's twelve tags, as literals. `PhyTag::byte` is the thing
    // under test here as much as `tier_of` is — a tag whose wire byte moved
    // would silently re-classify — so the table is written out rather than
    // read back from the enum it is supposed to agree with.
    let twelve: [(PhyTag, u8); 12] = [
        (PhyTag::VidPid, TAG_VIDPID),
        (PhyTag::LedGpio, TAG_LED_GPIO),
        (PhyTag::LedBrightness, TAG_LED_BRIGHTNESS),
        (PhyTag::Options, TAG_OPTIONS),
        (PhyTag::PresenceTimeout, TAG_PRESENCE_TIMEOUT),
        (PhyTag::UsbProduct, TAG_USB_PRODUCT),
        (PhyTag::Curves, TAG_CURVES),
        (PhyTag::EnabledUsbItf, TAG_ENABLED_USB_ITF),
        (PhyTag::LedDriver, TAG_LED_DRIVER),
        (PhyTag::LedOrder, TAG_LED_ORDER),
        (PhyTag::LedNum, TAG_LED_NUM),
        (PhyTag::UsbManufacturer, TAG_USB_MANUFACTURER),
    ];
    assert_eq!(
        PhyTag::ALL.len(),
        twelve.len(),
        "the table is a literal transcription of the protocol's twelve tags; if \
         the enum has grown a variant, this is where the transcription has to \
         grow with it — and where the new tag's *gate* has to be decided"
    );
    for (tag, byte) in twelve {
        assert_eq!(
            tag.byte(),
            byte,
            "{tag:?} must sit at its protocol byte"
        );
        assert_eq!(
            PhyTag::from_byte(byte),
            Some(tag),
            "and `from_byte` must invert `byte`, or `tier_of_wire` would tier a \
             tag by a byte that does not name it"
        );
    }

    let mut identity: Vec<u8> = twelve
        .iter()
        .filter(|(tag, _)| tier_of(*tag) == FieldTier::Identity)
        .map(|(_, byte)| *byte)
        .collect();
    identity.sort_unstable();
    assert_eq!(
        identity,
        vec![TAG_VIDPID, TAG_ENABLED_USB_ITF],
        "exactly two of the protocol's twelve tags change what the device *is* \
         on the bus. Adding a third is a security decision, and this assertion \
         is where it has to be made deliberately"
    );
    // The wire-byte classifier and the tag classifier must not disagree, and
    // an unrecognised byte must be `None` rather than a default tier.
    for (tag, byte) in twelve {
        assert_eq!(
            tier_of_wire(byte),
            Some(tier_of(tag)),
            "the wire-byte and tag classifiers are one function; a divergence \
             would mean `tier_of_wire` had grown its own copy of the table"
        );
    }
    assert_eq!(
        tier_of_wire(TAG_UNKNOWN),
        None,
        "a tag outside the twelve is `None` — an *unclassified* record, not a \
         benign one. The client's reader skips unknown tags and that is correct \
         for a reader; a writer that skipped one would be authorising a field \
         nobody decided anything about"
    );

    // A benign field alongside an unknown tag: the whole blob is refused. A
    // partial write would ack a record the caller believes it set.
    let mixed = phy_blob(&[(TAG_LED_GPIO, &[0x04]), (TAG_UNKNOWN, &[0xAB])]);
    let outcome = run_config_write(
        &mixed,
        Some(golden_auth()),
        true,
        &fapico2_fido::vendorff::PhyConfig::default(),
    );
    assert_eq!(
        outcome.status.code(),
        UNSUPPORTED_OPTION,
        "an unknown tag anywhere in the blob refuses the whole write, even \
         alongside a well-formed benign field and a valid token: the client \
         would skip the tag and then render a 0x00 as 'Configuration updated \
         successfully' (`picoforge/src/hal/fido/mod.rs:1180-1184`)"
    );
    assert_eq!(outcome.phy, None, "and nothing is proposed for commit");
}

/// A record this firmware has nowhere to store is refused, with the status
/// that says "unsupported" rather than "malformed".
///
/// Eight of the twelve tags have no field in
/// [`fapico2_fido::vendorff::PhyConfig`]. Refusing them is the honest answer
/// and a partial apply is not available — see `vendor41::config_write`. The
/// named boundary is worth a test of its own, because the day someone extends
/// `PhyConfig` this test is the thing that says which fields became writable.
///
/// Every case below carries a **correctly sized** value for its tag, so the
/// only thing each answer can be about is whether the record has a
/// destination. A tag with the wrong width would answer `0x02` and prove
/// nothing, which is why the widths are spelled out here rather than left to a
/// default.
#[test]
fn config_write_refuses_records_with_no_destination_in_the_persisted_record() {
    use fapico2_fido::vendorff::PhyConfig;
    use fapico2_platform::phy_tlv::PhyTag;

    // (tag, a value of that tag's own width, whether it is writable today).
    // The widths come from `platform/src/phy_tlv.rs`'s `PhyTag` docs: VID/PID
    // is 4 bytes, options 2, everything else 1.
    let cases: &[(PhyTag, &[u8], bool)] = &[
        (PhyTag::VidPid, &[0x2E, 0x8A, 0x00, 0x05], true),
        (PhyTag::LedGpio, &[0x0C], true),
        (PhyTag::LedBrightness, &[0x64], true),
        (PhyTag::Options, &[0x00, 0x02], true),
        (PhyTag::PresenceTimeout, &[0x0A], false),
        (PhyTag::Curves, &[0x01], false),
        // Deliberately non-zero: the zero case is row 3 of the EPIC's table
        // and is `config_write_rejects_zero_interface_mask_unconditionally`'s
        // job, with a different status. Using 0x01 here is what keeps the two
        // tests from being the same test.
        //
        // US-117 flipped this row to writable, and that is the one row here
        // whose answer changed. `DEV_CONF` (`0x00`) carries the *same*
        // operator intent — the USB enabled-interface mask — in the management
        // dialect, and needed a field to land in; one field, two carriers. It
        // was `false` from US-115, where the mask genuinely had nowhere to go
        // on the PHY path. The zero case did **not** change with it, and
        // `config_write_rejects_zero_interface_mask_unconditionally` is what
        // says so.
        (PhyTag::EnabledUsbItf, &[0x01], true),
        (PhyTag::LedDriver, &[0x01], false),
        (PhyTag::LedOrder, &[0x01], false),
        (PhyTag::LedNum, &[0x01], false),
        // The two USB identity names, writable for the same reason `0x0B` is:
        // they had no field in the persisted record, so a write was refused and
        // the client silently showed a blank product name. Note their values
        // carry a trailing NUL, because that is what the client sends
        // (`ops.rs:543-560`) and a value without one is refused — a detail the
        // `0x41` arm's own test pins, and one this table must not paper over
        // by sending something the client never would.
        (PhyTag::UsbProduct, b"fapico2\0", true),
        (PhyTag::UsbManufacturer, b"The BLOCO Community\0", true),
    ];
    assert_eq!(
        cases.len(),
        PhyTag::ALL.len(),
        "every one of the protocol's twelve tags must appear: a tag missing from \
         this table is a tag nothing in this story is checking"
    );

    let auth = golden_auth();
    for (tag, value, writable) in cases {
        let blob = phy_blob(&[(tag.byte(), value)]);
        let outcome = run_config_write(&blob, Some(auth), true, &PhyConfig::default());
        let expected = if *writable { 0x00 } else { UNSUPPORTED_OPTION };
        assert_eq!(
            outcome.status.code(),
            expected,
            "tag 0x{:02X} with a correctly sized value must answer 0x{:02X}: {}",
            tag.byte(),
            expected,
            if *writable {
                "it has a field in PhyConfig and is writable today"
            } else {
                "it has no field in PhyConfig, and a partial apply is not \
                 available — see vendor41::config_write. Note the status is \
                 0x2A (unsupported), not 0x2B (invalid): the record is one this \
                 firmware does not do, not one it does badly"
            },
        );
    }
}

/// The params hand-off is pinned against a literal, so the two test helpers
/// above cannot drift from the CBOR the client's serialiser produces.
///
/// The EPIC transcribes the request as `{1: 0x0C, 2: {1: target, 2: blob},
/// 3: 1, 4: mac}`. The client builds it at
/// `picoforge/src/hal/fido/ops.rs:1519-1546`, and the transcription is right —
/// but it is right for a *reason* worth pinning rather than assuming, because
/// the two things that could be wrong (the `0x02` byte-string key for the
/// blob, and the `0x58` one-byte length head) are both ones this file's other
/// helpers also encode.
#[test]
fn config_write_request_shape_matches_the_client() {
    assert_eq!(
        config_write_params(TARGET_PHY_LITERAL, &[0x00, 0x04, 0x2E, 0x8A, 0x00, 0x05]),
        vec![0xA2, 0x01, 0x01, 0x02, 0x58, 0x06, 0x00, 0x04, 0x2E, 0x8A, 0x00, 0x05],
        "`{{1: 1, 2: h'0004 2E8A 0005'}}` is `A2 01 01 02 58 06` followed by the \
         six blob bytes: a two-pair map, the target under key 1, and the blob \
         as a CBOR byte string (major type 2) under key 2 with a one-byte \
         length"
    );
    // A blob over 23 bytes takes the two-byte length head. Only the head
    // differs; the format has no BER continuation, which is why 0x59 is the
    // longest form and 255 the ceiling.
    let long = vec![0xAB; 24];
    let head = config_write_params(TARGET_PHY_LITERAL, &long);
    assert_eq!(
        &head[..7],
        &[0xA2, 0x01, 0x01, 0x02, 0x59, 0x00, 0x18],
        "a 24-byte value takes a SEVEN-byte head: `0x59` (major type 2, \
         two-byte length) followed by the length big-endian as `0x00 0x18`. \
         There is no third form — 255 is the ceiling"
    );
    assert_eq!(
        head.len(),
        7 + 24,
        "and nothing is inserted between the head and the value"
    );
}

/// The arm is reached through the **device command path** with a real minted
/// `0x20` token, and the record is still on the device afterwards.
///
/// The other gate tests call `vendor41::handle` directly, which is the right
/// level for a per-field decision but says nothing about the two things only
/// the command path has: that the dispatch arm's `presence`/`presence_grant`
/// wiring compiles into a gate the arm can actually use, and that the record
/// this arm proposes is the one the dispatch arm commits. A `0x00` from
/// [`run_config_write`] and a `0x00` on the wire are only the same observation
/// if something connects them.
#[test]
fn config_write_identity_field_is_written_by_a_0x20_token() {
    use fapico2_fido::vendorff::PhyConfig;

    let mut dev = DevicePinClient::boot().0;
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);
    let blob = phy_blob(&[(TAG_VIDPID, &VIDPID_BYTES)]);

    let (status, _) = dev.call(VENDOR_41, &config_write_request(&blob, Some(&token)));
    assert_eq!(
        status, 0x00,
        "a CONFIG_WRITE with a real AUTHENTICATOR_CONFIG token must be \
         accepted on the device path. This is the compatibility check's \
         consequence: PicoForge mints exactly this token immediately before \
         every `rs_key_config_write` (`picoforge/src/hal/fido/mod.rs:1163-1177`)"
    );
    assert_eq!(
        dev.app.keystore().phy,
        PhyConfig {
            vid_pid: Some(VIDPID_PACKED),
            ..PhyConfig::default()
        },
        "and the VID/PID must be in the keystore the app will persist — the \
         commit is the dispatch arm's, so a 0x00 with an unchanged record would \
         be an ack for a write that did nothing"
    );

    // The same request with no token at all, on the same live app, must not
    // change anything. Asserted on the record rather than only on the status,
    // because a gate that refuses *and writes* is a worse bug than one that
    // refuses.
    let (status, _) = dev.call(VENDOR_41, &config_write_request(&blob, None));
    assert_eq!(
        status, PUAT_REQUIRED,
        "the same write with no token must be refused on the device path too — \
         the two command paths are independent `match`es over the same opcode \
         space, so passing on one says nothing about the other"
    );
    assert_eq!(
        dev.app.keystore().phy.vid_pid,
        Some(VIDPID_PACKED),
        "and the refused request must leave the record exactly as the accepted \
         one left it"
    );
}

/// # Durability of an acked write — and what this test does **not** show
///
/// The claim has two halves, and an earlier revision of this comment claimed
/// both while the test only pinned one. The halves are:
///
/// 1. **Durability** — a `CONFIG_WRITE` the device acked with `0x00` is on
///    flash, so a crash afterwards cannot lose it.
/// 2. **Ordering** — it is on flash *before* that `0x00` went out, not after.
///
/// **This test pins (1) and not (2)**, and it cannot pin (2): the reply is
/// built inside the same `process_ctap2_with_store` call that commits, so from
/// the test's side there is no seam between the two to observe — a `0x00` is
/// consistent with either ordering, and so is the reboot below. It calls
/// `dev.persist()` first, and that call is the one that would make an
/// "after-the-reply" implementation pass; it is here to drive the HID task's
/// gate the way `firmware/src/tasks.rs` drives it, not to establish ordering.
///
/// (2) is pinned by
/// [`config_write_answers_a_commit_failure_rather_than_a_0x00`], which gives
/// the device path a store that refuses every write and asserts the reply is
/// `0x28` rather than `0x00` — a property only the "commit first" ordering can
/// produce. That test was verified to fail (with `0x00`) when the commit is
/// moved to after `finish_reply`.
///
/// For (1) the test reboots, which is the only check that distinguishes "on
/// flash" from "in RAM": it writes over the device path, throws the running
/// app away, boots a **fresh** `FidoApp` from the same `HostSecureStore` — the
/// store being the only thing that survives a reset — and reads the PHY record
/// back over `CONFIG_READ` (`0x0D`), a separate arm reached by a separate
/// dispatch. The bytes are compared against literals rather than against this
/// crate's encoder.
#[test]
fn config_write_persists_before_the_ack() {
    let mut dev = DevicePinClient::boot().0;
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);
    let blob = phy_blob(&[(TAG_VIDPID, &VIDPID_BYTES)]);

    let (status, _) = dev.call(VENDOR_41, &config_write_request(&blob, Some(&token)));
    assert_eq!(status, 0x00, "precondition: the write is accepted");

    // The HID task's own gate, driven the way `firmware/src/tasks.rs`'s
    // `persist_hid` drives it. It returns `true` both when it programmed
    // something and when the app had nothing dirty to program, so it does not
    // distinguish the two — and, as the doc comment says, it is not what makes
    // the reboot below pass. What it does show is that a *post-command* gate
    // is not what makes this write survive: by the time the gate runs the
    // record is already on flash.
    assert!(
        dev.persist(),
        "the HID task's persist gate must succeed after a CONFIG_WRITE; if it \
         failed, the ack went out against a snapshot that could not be \
         programmed"
    );

    // Reboot from the store alone.
    let mut trng = HostTrng::new();
    let mut fresh = DeviceApp::boot(&mut trng, &mut dev.store).expect("boot from the store");
    let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
    let read = {
        let mut params: HV<u8, 16> = HV::new();
        nh::push_map_header(&mut params, 1).unwrap();
        nh::push_uint(&mut params, 1).unwrap();
        nh::push_uint(&mut params, TARGET_PHY_LITERAL as u64).unwrap();
        let req = rskey_request_with_mac(0x0D, &params, None, None);
        let n = fresh.process_ctap2_with_store(VENDOR_41, &req, [1, 2, 3, 4], &mut out, None);
        out[..n].to_vec()
    };
    assert_eq!(
        read,
        vec![
            0x00, // CTAP2 OK
            0xA1, // a one-pair map
            0x01, // key 1: the PHY record
            0x46, // a 6-byte string
            0x00, 0x04, // tag 0x00 (VID/PID), length 4
            0x2E, 0x8A, 0x00, 0x05, // the VID/PID, big-endian
        ],
        "after a reboot that discarded the app, the record a CONFIG_WRITE was \
         acked for is still on flash — read back through CONFIG_READ, a \
         different sub-command and a different dispatch arm, and compared \
         against literals rather than against this crate's own encoder"
    );
}

/// A refused write commits nothing, including on the device path.
///
/// The mirror of [`config_write_persists_before_the_ack`], and the half that
/// keeps that one honest: if a refusal could still leave a record behind, then
/// "the acked write is durable" would be true for the wrong reason.
#[test]
fn config_write_refusal_leaves_the_persisted_record_untouched() {
    use fapico2_fido::vendorff::PhyConfig;

    let mut dev = DevicePinClient::boot().0;
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);
    // A well-formed benign write first, so the record is non-default and a
    // later refusal that *did* write something would be visible.
    let (status, _) = dev.call(
        VENDOR_41,
        &config_write_request(&phy_blob(&[(TAG_LED_GPIO, &[0x0C])]), Some(&token)),
    );
    assert_eq!(status, 0x00, "precondition: the benign write is accepted");
    let before = dev.app.keystore().phy;
    assert_eq!(before.led_gpio, Some(0x0C), "and it is the record that stands");

    for (what, blob, t) in [
        (
            "a zero interface mask",
            phy_blob(&[(TAG_ENABLED_USB_ITF, &[0x00])]),
            Some(&token),
        ),
        (
            "an unauthenticated VID/PID write",
            phy_blob(&[(TAG_VIDPID, &VIDPID_BYTES)]),
            None,
        ),
        (
            "a record with no destination",
            phy_blob(&[(TAG_LED_DRIVER, &[0x01])]),
            Some(&token),
        ),
    ] {
        let (status, _) = dev.call(VENDOR_41, &config_write_request(&blob, t));
        assert_ne!(status, 0x00, "{what} must be refused");
        assert_eq!(
            dev.app.keystore().phy,
            before,
            "{what} was refused, so the persisted record must be byte-identical \
             to what it was. A gate that refuses after applying would leave a \
             configuration the caller was told it did not set"
        );
    }
    // And the device path is genuinely still the one that persisted it.
    let mut trng = HostTrng::new();
    let mut fresh = DeviceApp::boot(&mut trng, &mut dev.store).expect("boot from the store");
    assert_eq!(
        fresh.keystore().phy,
        PhyConfig { led_gpio: Some(0x0C), ..PhyConfig::default() },
        "exactly one record is on flash: the accepted benign write, and neither \
         of the three refusals"
    );
}

/// The identity tier escalates a bad MAC through the app's three-strike
/// counter, and refuses outright once the latch is set.
///
/// This is the US-112 lockout seam observed end to end rather than through
/// the test instrument: [`fapico2_fido::vendor41::set_escalation_test_sub`]
/// exists because no arm reached `verify_mac` when it was written, and now
/// [`Subcommand::ConfigWrite`] does. So the seam has a real producer, and the
/// test that used to *substitute* for it becomes a check that the real thing
/// still behaves.
#[test]
fn config_write_identity_tier_escalates_a_bad_mac() {
    use fapico2_fido::ctap2::Ctap2Response;
    let mut dev = DevicePinClient::boot().0;
    dev.set_pin(b"1234");
    // Minted before the strikes, for the same reason as the host twin's leg: a
    // successful `clientPin` clears `needs_power_cycle`
    // (`device_core.rs`'s `handle_client_pin`), so minting a fresh token after
    // latching would un-latch the device and the final leg would be asserting
    // against a device that is no longer blocked.
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);

    let blob = phy_blob(&[(TAG_VIDPID, &VIDPID_BYTES)]);
    let params = config_write_params(TARGET_PHY_LITERAL, &blob);
    // A self-consistent 16-byte MAC over the right message with a token the
    // device never issued: the case that must be charged, because the caller
    // *tried* to authenticate.
    let forged = {
        let mut wrong = GOLDEN_TOKEN;
        wrong[0] ^= 0xFF;
        picoforge_mac(&wrong, VENDOR_41, 0x0C, &params)
    };
    let req = rskey_request_with_mac(0x0C, &params, Some(1), Some(&forged));

    for strike in 1..=3 {
        let (status, _) = dev.call(VENDOR_41, &req);
        let expected = if strike < 3 {
            PIN_AUTH_INVALID
        } else {
            // The third strike's own status comes from the app's latch, not
            // from the arm — that is the whole point of the seam.
            0x34
        };
        assert_eq!(
            status, expected,
            "strike {strike}: a bad MAC over a well-formed request must charge \
             the app's three-strike counter, and the third one must answer the \
             latch's 0x34 rather than the arm's 0x33"
        );
    }
    assert!(
        dev.app.keystore().pin_state.needs_power_cycle,
        "precondition: the latch is set, which is what the next leg is about"
    );

    // Now with the *correct* token, minted before the latch was set: the latch
    // must be refused before the MAC is even looked at, so a genuine token
    // holder is told the device is refusing pinUvAuth rather than being sent
    // back to the PIN prompt for a token that is perfectly good.
    let (status, _) = dev.call(VENDOR_41, &config_write_request(&blob, Some(&token)));
    assert_eq!(
        status, PIN_AUTH_BLOCKED,
        "once `needs_power_cycle` is set, CTAP2.1 §6.5.7 requires pinUvAuth to \
         be refused outright. A correct token answering 0x36 or 0x33 would tell \
         the client its token was missing or wrong when in fact the device is \
         refusing all pinUvAuth"
    );
    assert_eq!(
        Ctap2Response::PinAuthBlocked as u8,
        PIN_AUTH_BLOCKED,
        "0x34 is this crate's PinAuthBlocked, confirmed against the enum so the \
         constant above is not asserting a label"
    );
}

/// A legacy `getPinToken` (`0x05`) token — permission byte `0` — is refused on
/// the identity tier.
///
/// `get_pin_token` is the sub-command the client falls back to when
/// `getPinUvAuthTokenUsingPinWithPermissions` fails
/// (`picoforge/src/hal/fido/mod.rs:1163-1170`, and the same fallback in
/// `write_legacy_hardware_config`). So this is not a hypothetical: on a
/// firmware where the permission sub-command is unavailable, PicoForge
/// degrades to a zero-permission token, and this arm answers `0x40`.
///
/// That is the correct degradation, and it is worth being explicit that it is
/// one: the Config screen's VID/PID field stops working and says so, rather
/// than the gate being quietly weakened so the field keeps working. The
/// alternative — treating `Some(0)` as "unrestricted" — is the exact legacy
/// special case CTAP2.1 reserves for `makeCredential`/`getAssertion`.
#[test]
fn config_write_legacy_zero_permission_token_is_refused() {
    let blob = phy_blob(&[(TAG_VIDPID, &VIDPID_BYTES)]);
    let legacy = TokenAuth {
        token: &GOLDEN_TOKEN,
        permissions: 0,
        blocked: false,
    };
    let outcome = run_config_write(
        &blob,
        Some(legacy),
        true,
        &fapico2_fido::vendorff::PhyConfig::default(),
    );
    assert_eq!(
        outcome.status.code(),
        0x40,
        "a legacy getPinToken token carries permission byte 0 and must be \
         refused on the one row that requires AUTHENTICATOR_CONFIG"
    );
    assert_eq!(outcome.phy, None, "and nothing is proposed for commit");
}

/// `target` values this arm cannot serve are refused, before any gate.
///
/// US-117 made this three targets wide — `0x00` (DEV_CONF), `0x01` (PHY) and
/// `0x02` (LED) — so what remains to refuse is a target byte the protocol does
/// not define at all. Each of the three served targets is covered by its own
/// test below; this one is about the byte that names none of them.
///
/// The two bytes here are both below `0x18`, and that is not incidental. CBOR
/// encodes an unsigned integer `0x00..=0x17` in a single byte, but `0x18` and
/// above need a following length byte, and `0x7F` is worse than "needs a
/// length" — it is the **one-byte indefinite-length break**. A test that
/// wanted a large target and encoded it as a raw byte would be sending a CBOR
/// break rather than a target, and would be asserting a decoder error while
/// believing it was asserting a target refusal. Which is exactly what this
/// test did before US-117, and it is worth writing down because the next
/// person to add a case here will reach for `0xFF`.
#[test]
fn config_write_refuses_a_target_it_cannot_serve() {
    for (target, what) in [
        (0x03u8, "an unassigned target byte, one past the three served ones"),
        (0x10u8, "a target byte well above the RSKEY_CFG_TARGET_* range"),
    ] {
        let params = config_write_params(target, &phy_blob(&[(TAG_LED_GPIO, &[0x04])]));
        let mac = picoforge_mac(&GOLDEN_TOKEN, VENDOR_41, 0x0C, &params);
        let req = rskey_request_with_mac(0x0C, &params, Some(1), Some(&mac));
        let outcome = handle_isolated(
            &req,
            Some(golden_auth()),
            &fapico2_fido::vendorff::PhyConfig::default(),
            fapico2_fido::vendor41::PresenceGate {
                window_grant: None,
                poll: Some(presence_poll),
                tag: 0,
            },
            &mut HV::new(),
        );
        assert_eq!(
            outcome.status.code(),
            INVALID_PARAMETER,
            "target {target:#04x} is {what}, and answering 0x00 would be a 0x00 \
             the client's reader misparses — there is no record it could name"
        );
        assert_eq!(outcome.phy, None, "{what}: nothing is proposed for commit");
    }
}

/// A store that reads normally and refuses every write.
///
/// Reads are forwarded to a real [`HostSecureStore`] rather than stubbed, so
/// `chunked::write_chunked` runs its **normal** path: it reads to locate the
/// current generation set, then writes the new one into the other buffer. A
/// store that returned nothing on read would instead take the "no generations
/// at all" branch, and the failure this test needs to provoke is specifically
/// "the read half worked and the write half could not land" — the case a
/// device with a failing flash driver is actually in.
///
/// The forwarded store is a *fresh* [`HostSecureStore::new`], so there is no
/// previous generation set in it; the reason for forwarding is the code path,
/// not the protection of anything this instance holds.
struct UnwritableStore {
    inner: HostSecureStore,
}

impl UnwritableStore {
    fn new() -> Self {
        Self { inner: HostSecureStore::new() }
    }
}

impl fapico2_platform::secure_store::SecureStore for UnwritableStore {
    fn write(&mut self, _key: &[u8], _value: &[u8]) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::Flash)
    }
    fn read(&mut self, key: &[u8], out: &mut [u8]) -> Result<usize, SecureStoreError> {
        self.inner.read(key, out)
    }
    fn delete(&mut self, _key: &[u8]) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::Flash)
    }
    fn contains(&self, key: &[u8]) -> bool {
        self.inner.contains(key)
    }
    fn snapshot_partition(&self, buf: &mut [u8]) -> Result<usize, SecureStoreError> {
        self.inner.snapshot_partition(buf)
    }
    fn snapshot_len(&self) -> usize {
        self.inner.snapshot_len()
    }
    fn snapshot_window(&self, off: usize, buf: &mut [u8]) -> usize {
        self.inner.snapshot_window(off, buf)
    }
    fn is_empty(&self) -> Result<bool, SecureStoreError> {
        self.inner.is_empty()
    }
    fn is_empty_except(&self, slot: &[u8]) -> Result<bool, SecureStoreError> {
        self.inner.is_empty_except(slot)
    }
    fn wipe_all(&mut self) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::Flash)
    }
}

/// # Durable-before-ack: the **ordering**, demonstrated
///
/// [`config_write_persists_before_the_ack`] pins *durability* — after a reboot
/// the record is still there. It does not pin *ordering*, and it cannot: the
/// client is handed a `&mut dyn SecureStore` and the reply is built inside the
/// same call, so from the test's side there is no seam between "committed" and
/// "replied" to observe. A `0x00` is consistent with both ordersings.
///
/// This test is the one that separates them. It gives the device path a store
/// that **refuses every write**, so `DeviceKeystore::persist` fails inside
/// `grow_checked`, and then asserts two things:
///
/// 1. The status on the wire is `KeyStoreFull` (`0x28`), **not** `0x00`.
/// 2. The record was rolled back — the app's `phy` is what it was.
///
/// Both are consequences of the commit having run *before* the status the
/// reply carries was chosen. If someone moved the `grow_checked` call to after
/// `finish_reply`, the `0x00` would already be on the wire when the commit
/// failed, and this test would see `0x00` and a mutated record. That is the
/// property the EPIC asks for — "persist **before** acking" — stated as
/// something that can fail, rather than as a claim about where a block sits.
///
/// The rollback half is SOAK-FINDING-1 parity with the `0xFF` framing's arm
/// and is worth its own assertion here: a failed commit that left the record
/// mutated in RAM would be re-persisted by the *next* successful command, which
/// is a write the user never asked for.
#[test]
fn config_write_answers_a_commit_failure_rather_than_a_0x00() {
    use fapico2_fido::vendorff::PhyConfig;

    let mut dev = DevicePinClient::boot().0;
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);

    // A benign write first, so there is a non-default record for the rollback
    // to be observable against. It goes through the real store.
    let (status, _) = dev.call(
        VENDOR_41,
        &config_write_request(&phy_blob(&[(TAG_LED_GPIO, &[0x0C])]), Some(&token)),
    );
    assert_eq!(status, 0x00, "precondition: the benign write is accepted");
    let before = dev.app.keystore().phy;
    assert_eq!(
        before.led_gpio,
        Some(0x0C),
        "and it is the record that stands"
    );

    // Now an identity write into a store that cannot be programmed.
    let mut unwritable = UnwritableStore::new();
    let blob = phy_blob(&[(TAG_VIDPID, &VIDPID_BYTES)]);
    let (status, _) = dev.call_with_store(
        VENDOR_41,
        &config_write_request(&blob, Some(&token)),
        &mut unwritable,
    );

    assert_eq!(
        status, 0x28,
        "a record that could not be made durable must be reported as 0x28 \
         (KeyStoreFull), not as 0x00. This is the whole of the ordering claim: \
         the status the reply carries is computed from a commit that has \
         ALREADY run, so a commit that failed cannot be reported as success. \
         A 0x00 here would mean the commit happens after the reply is built"
    );
    assert_eq!(
        dev.app.keystore().phy,
        before,
        "and the record must be rolled back, not left mutated in RAM: a failed \
         commit that kept the change would be re-persisted by the next \
         successful command, which is a write nobody asked for. This is \
         SOAK-FINDING-1 parity with the 0xFF arm in device_core.rs"
    );

    // And nothing reached the real store either: rebooting from it shows the
    // LED GPIO from the accepted write and not the VID/PID from this one.
    let mut trng = HostTrng::new();
    let mut fresh = DeviceApp::boot(&mut trng, &mut dev.store).expect("boot from the store");
    assert_eq!(
        fresh.keystore().phy,
        PhyConfig {
            led_gpio: Some(0x0C),
            ..PhyConfig::default()
        },
        "the refused commit left nothing on flash, in the store or in the app"
    );
}

// ===========================================================================
// US-117: `DEV_CONF` (target 0x00) and `LED` (target 0x02) over `CONFIG_WRITE`.
// ===========================================================================

/// Build a `CONFIG_WRITE` for a target other than PHY.
///
/// [`config_write_request`] hard-codes [`TARGET_PHY_LITERAL`] because every
/// pre-US-117 test wanted PHY. US-117 needs the same construction against two
/// more targets, and the alternative — three near-copies of a function that
/// builds CBOR by hand — is three places for the client's serialiser to drift
/// away from. So this takes the target and the shared helper delegates to it.
fn config_write_request_for(target: u8, blob: &[u8], token: Option<&[u8; 32]>) -> Vec<u8> {
    let params = config_write_params(target, blob);
    match token {
        Some(t) => {
            let mac = picoforge_mac(t, VENDOR_41, 0x0C, &params);
            rskey_request_with_mac(0x0C, &params, Some(1), Some(&mac))
        }
        None => rskey_request_with_mac(0x0C, &params, None, None),
    }
}

/// A `DEV_CONF` blob for a USB enabled-interface mask: `03 02 <mask BE u16>`.
///
/// Hand-rolled from the client's own array literal in `write_rskey_dev_config`
/// (`picoforge/src/hal/fido/mod.rs:2086-2091`), which is
///
/// ```text
/// [FIDO_MGMT_TAG_USB_ENABLED, 0x02, (enabled_mask >> 8) as u8, (enabled_mask & 0xFF) as u8]
/// ```
///
/// so the width is fixed at two and the order is **big-endian**, high byte
/// first. Not a `phy_blob` call with a different tag: this is a management TLV,
/// and reusing the PHY helper would assert the two dialects share a codec, which
/// is exactly what `vendor41` keeps them apart to avoid.
fn dev_conf_blob(mask: u16) -> Vec<u8> {
    vec![
        DEV_CONF_TAG_USB_ENABLED_LITERAL,
        0x02,
        (mask >> 8) as u8,
        (mask & 0xFF) as u8,
    ]
}

/// `run_config_write` for a non-PHY target.
fn run_config_write_for(
    target: u8,
    blob: &[u8],
    auth: Option<TokenAuth<'_>>,
    present: bool,
    phy: &fapico2_fido::vendorff::PhyConfig,
) -> fapico2_fido::vendor41::Outcome {
    set_presence(present);
    let req = config_write_request_for(target, blob, auth.map(|a| a.token));
    handle_isolated(
        &req,
        auth,
        phy,
        fapico2_fido::vendor41::PresenceGate {
            window_grant: None,
            poll: Some(presence_poll),
            tag: 0,
        },
        &mut HV::new(),
    )
}

/// The two `DEV_CONF` bytes on the wire, checked against the client's encoding
/// rather than against this firmware's decoder.
///
/// [`config_write_decodes_dev_conf_big_endian`] already drives the request
/// through the firmware's own parser, which would agree with a byte-swapped
/// encoder. This one is the independent transcription: the client builds
/// `(enabled_mask >> 8) as u8` first and `enabled_mask & 0xFF` second, so
/// `0x1234` must arrive as `0x12 0x34`. Written as literals rather than
/// computed, because a computed expectation is the encoder agreeing with
/// itself.
#[test]
fn dev_conf_blob_bytes_match_the_clients_array_literal() {
    assert_eq!(
        dev_conf_blob(0x1234),
        vec![0x03, 0x02, 0x12, 0x34],
        "the client's TLV is [tag 0x03, len 2, high byte, low byte] — \
         `write_rskey_dev_config` pushes `(enabled_mask >> 8) as u8` before \
         `enabled_mask & 0xFF` (picoforge/src/hal/fido/mod.rs:2086-2091)"
    );
    // And the two ends of the range, so a mask of all-ones is not a special
    // case anywhere: 0xFFFF is 65 535 interfaces' worth of bits, and 0x0001 is
    // the smallest mask the client would ever send.
    assert_eq!(dev_conf_blob(0xFFFF), vec![0x03, 0x02, 0xFF, 0xFF]);
    assert_eq!(dev_conf_blob(0x0001), vec![0x03, 0x02, 0x00, 0x01]);
}

/// A `DEV_CONF` write stores the mask, and the mask survives the round trip
/// big-endian both ways.
///
/// Two legs, because one of them is the interesting one and it is not the
/// obvious one. The obvious leg is "a mask gets written". The interesting leg
/// is `0x1234` specifically: it is the one value where a big-endian bug is
/// visible in the stored number rather than hidden by symmetry (`0x1111` is
/// its own byte-swap). So the expectation is the packed `u16`, written as a
/// literal, and the value is chosen to be asymmetric.
#[test]
fn config_write_decodes_dev_conf_big_endian() {
    let mask = 0x1234u16;
    let outcome = run_config_write_for(
        TARGET_DEV_CONF_LITERAL,
        &dev_conf_blob(mask),
        Some(golden_auth()),
        true,
        &fapico2_fido::vendorff::PhyConfig::default(),
    );
    assert_eq!(
        outcome.status.code(),
        0x00,
        "a DEV_CONF write carrying a 0x20 token is authorised: DEV_CONF is the \
         identity tier, and a token is the authority for it"
    );
    let proposed = outcome.phy.expect("a 0x00 proposes a record to commit");
    assert_eq!(
        proposed.enabled_usb_itf,
        Some(0x1234),
        "0x03 02 12 34 is mask 0x1234, high byte first. A little-endian read \
         would store 0x3412 — the same four bytes, a different set of enabled \
         USB interfaces, and no way to tell from the wire which one was meant"
    );
    // And the mask is the *only* thing that changed: DEV_CONF is one record,
    // and it must not disturb the PHY fields it shares a struct with.
    assert_eq!(
        (
            proposed.vid_pid,
            proposed.led_gpio,
            proposed.led_brightness,
            proposed.options
        ),
        (None, None, None, None),
        "a DEV_CONF write touches one field of the shared record; if it also \
         cleared the PHY fields, an operator toggling USB applications would \
         silently lose the hardware configuration"
    );
}

/// # `DEV_CONF` is the identity tier — the requirement-4 answer, as a test
///
/// The EPIC asks whether a `DEV_CONF` write may be gated on a touch. It may
/// not, and the reason is that `DEV_CONF`'s only record **is** the USB
/// enabled-interface mask: the same operator intent the PHY record carries in
/// tag `0x0B`, which [`fapico2_fido::vendor41::tier_of`] already classifies as
/// [`fapico2_fido::vendor41::FieldTier::Identity`].
///
/// So a `DEV_CONF` write routed to the presence tier would not be a new policy
/// for `DEV_CONF` — it would be the one path to a value US-115 had classified,
/// left unguarded. That is the property this test exists to make false-able.
///
/// Three legs, all driven as whole requests:
///
/// 1. **no token** → `PuatRequired` (`0x36`). Not `UpRequired`: a token is
///    required, so there is no touch to wait for.
/// 2. **a token, no touch** → `0x00`. The tier is not *cumulative*: a token is
///    strictly stronger than a press, and making its holder also press a button
///    would be a requirement with no security content — the client sends no
///    touch for `CONFIG_WRITE`
///    (`picoforge/src/hal/fido/ops.rs:1514-1554`) and would time out.
/// 3. **no token, but a touch** → still `0x36`. This is the leg that fails if
///    someone routes `DEV_CONF` to the presence tier, and the reason it is
///    listed separately from leg 1: a gate implemented as "presence *or* token"
///    passes legs 1 and 2 and is exactly the bug.
#[test]
fn dev_conf_write_is_the_identity_tier_not_presence() {
    let blob = dev_conf_blob(0x0003);
    let empty = fapico2_fido::vendorff::PhyConfig::default();

    // (1) No token, no touch.
    let no_auth = run_config_write_for(TARGET_DEV_CONF_LITERAL, &blob, None, false, &empty);
    assert_eq!(
        no_auth.status.code(),
        PUAT_REQUIRED,
        "DEV_CONF changes what the token presents on the bus, so it is the \
         identity tier and demands a 0x20 token. A token is *required*, so the \
         answer is 0x36 and not the 0x3B a presence gate would give"
    );
    assert_eq!(
        no_auth.phy, None,
        "a refused DEV_CONF write commits nothing"
    );

    // (2) A token, and deliberately NO press.
    let tokened = run_config_write_for(
        TARGET_DEV_CONF_LITERAL,
        &blob,
        Some(golden_auth()),
        false,
        &empty,
    );
    assert_eq!(
        tokened.status.code(),
        0x00,
        "a token is strictly stronger than a touch, so the tiers are not \
         cumulative: demanding a press here would be a requirement with no \
         security content behind it, and PicoForge sends no touch for \
         CONFIG_WRITE (ops.rs:1514-1554) — it would simply time out"
    );

    // (3) A press but no token — the leg a "presence OR token" gate fails.
    let touched = run_config_write_for(TARGET_DEV_CONF_LITERAL, &blob, None, true, &empty);
    assert_eq!(
        touched.status.code(),
        PUAT_REQUIRED,
        "a physical touch must NOT authorise a DEV_CONF write. The threat this \
         tier exists against is not a bystander pressing the button: it is an \
         unprivileged local process rewriting the USB identity of a token \
         somebody else is about to use, and anyone who can press the button can \
         also ask for it. Only the 0x20 token separates those two"
    );
    assert_eq!(
        touched.phy, None,
        "and a touch-authorised DEV_CONF must propose nothing to commit"
    );
}

/// The zero-mask rule reaches `DEV_CONF`, and it is unconditional there too.
///
/// This is the second half of the requirement-4 question, and the half that
/// only exists because of US-117. Until this story `DEV_CONF` was refused
/// outright, so the interface mask had exactly one carrier. It now has two, at
/// different widths (PHY `0x0B` is one byte, `DEV_CONF` `0x03` is two), and a
/// rule written for one carrier would leave `03 02 00 00` — the same denial of
/// service, spelled in the other dialect — accepted behind a token.
///
/// Unconditional means it is refused *before* the gate, in every authentication
/// state, including a fully valid `0x20` token. The legitimate leg is the one
/// that shows the rule is about the value and not about the request shape:
/// mask `0x0001` is accepted by the same token that is refused mask `0x0000`.
#[test]
fn dev_conf_rejects_the_zero_mask_unconditionally() {
    let empty = fapico2_fido::vendorff::PhyConfig::default();
    for (auth, present, label) in [
        (None, true, "no token, with a press"),
        (
            Some(golden_auth()),
            true,
            "a valid 0x20 token, with a press",
        ),
        (Some(golden_auth()), false, "a valid 0x20 token, no press"),
    ] {
        let outcome = run_config_write_for(
            TARGET_DEV_CONF_LITERAL,
            &dev_conf_blob(0x0000),
            auth,
            present,
            &empty,
        );
        assert_eq!(
            outcome.status.code(),
            INVALID_OPTION,
            "a USB enabled-interface mask of 0 must be refused in every \
             authentication state — {label}. A zero mask makes the device \
             re-enumerate with no USB interfaces: gone from every attached \
             host until BOOTSEL recovery. That is a denial of service against \
             the whole bus, it has no legitimate use, and it is checked before \
             the gate precisely so that no authentication state reaches it"
        );
        assert_eq!(
            outcome.phy, None,
            "{label}: the refused zero mask must propose nothing to commit"
        );
    }

    // The legitimate neighbour, through the same token, so the test cannot pass
    // by refusing every DEV_CONF write.
    let ok = run_config_write_for(
        TARGET_DEV_CONF_LITERAL,
        &dev_conf_blob(0x0001),
        Some(golden_auth()),
        false,
        &empty,
    );
    assert_eq!(
        ok.status.code(),
        0x00,
        "mask 0x0001 is accepted by the same token that is refused mask 0x0000, \
         so the rule is about the value and not about the request shape"
    );
    assert_eq!(
        ok.phy.expect("accepted").enabled_usb_itf,
        Some(0x0001),
        "and the accepted mask is stored as the number it is"
    );
}

/// A `DEV_CONF` write that is not the shape the client sends is refused.
///
/// Four shapes, all of which a `0x00` would have to be lying about. The
/// unknown-tag and repeated-record legs matter most: they are the DEV_CONF
/// equivalents of the PHY record's "no partial apply" rule, and a partial
/// apply on this target would leave an operator believing they had changed the
/// USB application mask when they had changed something else or nothing.
#[test]
fn dev_conf_refuses_shapes_the_client_never_sends() {
    let empty = fapico2_fido::vendorff::PhyConfig::default();
    let mut both = dev_conf_blob(0x0003);
    both.extend_from_slice(&dev_conf_blob(0x0007));

    for (blob, expected, what) in [
        (
            vec![0x04, 0x02, 0x00, 0x03],
            UNSUPPORTED_OPTION,
            "a tag that is not the enabled-interface one",
        ),
        (
            // A record that *claims* one byte and stops: the decoder refuses it
            // as truncated, so this is a malformed record rather than a
            // wrong-width one — and the two are different faults.
            dev_conf_blob(0x0003)[..3].to_vec(),
            INVALID_CBOR,
            "a record whose length byte promises two value bytes and supplies one",
        ),
        (
            // The width the *other* dialect uses, spelled honestly: length 1.
            vec![DEV_CONF_TAG_USB_ENABLED_LITERAL, 0x01, 0x03],
            INVALID_PARAMETER,
            "a one-byte mask (the PHY record's width, in the wrong dialect)",
        ),
        (
            vec![DEV_CONF_TAG_USB_ENABLED_LITERAL, 0x03, 0x00, 0x03, 0x00],
            INVALID_PARAMETER,
            "a three-byte mask",
        ),
        (both, INVALID_CBOR, "the same record twice"),
        (
            Vec::new(),
            MISSING_PARAMETER,
            "an empty blob, which names no record",
        ),
    ] {
        let outcome = run_config_write_for(
            TARGET_DEV_CONF_LITERAL,
            &blob,
            Some(golden_auth()),
            true,
            &empty,
        );
        assert_eq!(
            outcome.status.code(),
            expected,
            "{what} is not a DEV_CONF record the client can have meant, and a \
             0x00 here would be a 0x00 over bytes nobody has claimed mean \
             anything. `write_rskey_dev_config` builds exactly one record"
        );
        assert_eq!(outcome.phy, None, "{what}: nothing is proposed for commit");
    }
}

/// # `LED`: the block is stored verbatim, and a wrong length is refused
///
/// The length is the whole of what this arm validates, and saying why is the
/// point: the block is `[steady(1), (effect, colour, brightness, speed) × 4]`
/// (`RSKEY_LED_CONF_LEN`, `picoforge/src/hal/fido/mod.rs:2001`), and every byte
/// of it is a cosmetic property of a light whose meaning belongs to the client.
/// A range check here would refuse configurations the reference implementation
/// accepts — `LedStatusConfig::statuses` is a plain `[(u8, u8); 4]`
/// (`picoforge/src/hal/types.rs:187`), so a brightness of `0xFF` is a value the
/// client will write and read back.
///
/// A short block is refused rather than zero-extended, because on this wire a
/// 4-byte blob and a 17-byte blob of zeros are not the same request: the first
/// is a block the caller got wrong, the second is "turn every status dark".
#[test]
fn led_write_stores_the_block_and_refuses_a_wrong_length() {
    let empty = fapico2_fido::vendorff::PhyConfig::default();
    let block = full_led_block();

    // The accepted case first, through the presence tier with a press and no
    // token — the LED block is cosmetic, so a touch is the authority for it.
    let ok = run_config_write_for(TARGET_LED_LITERAL, &block.0, None, true, &empty);
    assert_eq!(
        ok.status.code(),
        0x00,
        "an LED block is a cosmetic overlay: a physical touch authorises it, \
         and no token is demanded. This is the same answer tier_of gives the \
         PHY record's LedGpio and LedBrightness"
    );
    assert_eq!(
        ok.phy.expect("a 0x00 proposes a record").led_conf,
        Some(block),
        "and the block is stored byte for byte. Every byte is compared against \
         the client's own example block, so a transposed colour/brightness or a \
         dropped record fails here rather than at the client"
    );

    // Now the shapes that are not a 17-byte block.
    for (blob, what) in [
        (Vec::new(), "an empty blob"),
        (block.0[..16].to_vec(), "a 16-byte block, one short"),
        (
            [block.0.as_slice(), &[0x00]].concat(),
            "an 18-byte block, one long",
        ),
    ] {
        let outcome = run_config_write_for(TARGET_LED_LITERAL, &blob, None, true, &empty);
        assert_eq!(
            outcome.status.code(),
            INVALID_PARAMETER,
            "{what} is not the 17-byte block `RSKEY_LED_CONF_LEN` names, and \
             zero-extending it would make a malformed request indistinguishable \
             on the wire from a valid one that turns every status dark"
        );
        assert_eq!(outcome.phy, None, "{what}: nothing is proposed for commit");
    }

    // And the presence tier really is the gate, so the accepted case above is
    // not passing because nothing was checked.
    let no_press = run_config_write_for(TARGET_LED_LITERAL, &block.0, None, false, &empty);
    assert_eq!(
        no_press.status.code(),
        UP_REQUIRED,
        "with no press the benign tier answers 0x3B, so the accepted write above \
         went through a gate rather than around one"
    );
}

/// # The read-modify-write, performed the way the client performs it
///
/// This is the test the EPIC's warning is really about, and it is worth being
/// exact about where the read-modify-write lives, because the EPIC places it in
/// the device and it is not there.
///
/// `write_rskey_led_config` (`picoforge/src/hal/fido/mod.rs:2036-2063`) does
/// the whole thing client-side:
///
/// 1. `rs_key_config_read(RSKEY_CFG_TARGET_LED)`;
/// 2. copy the returned block if it is at least 17 bytes;
/// 3. overwrite `block[0]` (steady), `block[2 + 4i]` (colour) and `block[3 + 4i]`
///    (brightness), leaving effect (`1 + 4i`) and speed (`4 + 4i`) untouched;
/// 4. `CONFIG_WRITE` the complete 17 bytes.
///
/// So the device receives a whole block and stores it. **The consequence for
/// this firmware is about step 1, not step 4:** a device that stored the block
/// but refused to read it would take the `if let Ok(..) && current.len() >=
/// RSKEY_LED_CONF_LEN` fall-through, leave `block` all-zero, and wipe every
/// effect and speed — the exact failure the EPIC predicted, reached by refusing
/// the read.
///
/// This test therefore drives the client's algorithm rather than asserting the
/// device did a read. It would fail if `CONFIG_READ` at `0x02` were refused, if
/// it answered a short blob, or if either direction mangled the block — and
/// `led_read_of_an_unconfigured_device_is_seventeen_zero_bytes` covers the
/// fall-through case the client cannot otherwise avoid on a fresh device.
#[test]
fn led_read_modify_write_preserves_effect_and_speed() {
    let mut dev = DevicePinClient::boot().0;
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);

    // Step 0: a starting block whose effect and speed are non-zero and whose
    // colours and brightnesses are all different, so "preserved" and "zeroed"
    // are distinguishable at every one of the sixteen bytes.
    let start = fapico2_fido::vendorff::LedConf([
        0x01, // steady
        0x07, 0x01, 0x0A, 0x11, // idle:  effect 7, colour 1, br 0x0A, speed 0x11
        0x06, 0x02, 0x0B, 0x12, // proc:  effect 6, colour 2, br 0x0B, speed 0x12
        0x05, 0x03, 0x0C, 0x13, // touch: effect 5, colour 3, br 0x0C, speed 0x13
        0x04, 0x04, 0x0D, 0x14, // boot:  effect 4, colour 4, br 0x0D, speed 0x14
    ]);
    let (status, _) = dev.call(
        VENDOR_41,
        &config_write_request_for(TARGET_LED_LITERAL, &start.0, Some(&token)),
    );
    assert_eq!(status, 0x00, "precondition: the starting block is accepted");

    // Step 1: the client's read.
    let read_back = led_read_block(&mut dev);

    // Step 2 + 3: the client's copy-and-overwrite, byte for byte.
    let mut next = read_back;
    next[0] = 0x00; // steady off
    for i in 0..4usize {
        next[2 + 4 * i] = 5 & 0x07; // colour, masked exactly as the client does
        next[3 + 4 * i] = 0x40; // brightness
    }

    // Step 4: the write of the complete block.
    let (status, _) = dev.call(
        VENDOR_41,
        &config_write_request_for(TARGET_LED_LITERAL, &next, Some(&token)),
    );
    assert_eq!(status, 0x00, "the read-modify-write is accepted");

    // The point of the whole test.
    let final_block = led_read_block(&mut dev);
    assert_eq!(
        &final_block[..4],
        &[0x00, 0x07, 0x05, 0x40],
        "steady (0) and the idle record's first three bytes changed as asked: \
         effect 0x07 survived at 1+4i, colour became 5 at 2+4i, brightness \
         0x40 at 3+4i"
    );
    assert_eq!(
        &final_block[4..8],
        &[0x11, 0x06, 0x05, 0x40],
        "the idle record's speed (0x11 at 4+4i) survived, and the next record's \
         effect (0x06 at 1+4i) survived — the two fields the client never writes"
    );
    for i in 0..4usize {
        assert_eq!(
            final_block[1 + 4 * i],
            start.0[1 + 4 * i],
            "effect at 1+4i must be preserved through the read-modify-write"
        );
        assert_eq!(
            final_block[4 + 4 * i],
            start.0[4 + 4 * i],
            "speed at 4+4i must be preserved through the read-modify-write"
        );
        assert_eq!(
            final_block[2 + 4 * i],
            5 & 0x07,
            "colour at 2+4i is the field the client does write"
        );
        assert_eq!(
            final_block[3 + 4 * i],
            0x40,
            "brightness at 3+4i is the other field the client does write"
        );
    }
    assert_eq!(
        final_block[0], 0x00,
        "steady at index 0 is the client's third and last written field"
    );
}

/// A device that has never been told an LED configuration must still answer a
/// 17-byte read.
///
/// The reason is the **explicit** read, not the read-modify-write.
/// `read_rskey_led_config` (`picoforge/src/hal/fido/mod.rs:2010-2019`) reads
/// the block in order to display it and hands it to `parse_led_block`, which
/// returns `None` on an empty input (`picoforge/src/hal/common/led.rs:21-22`).
/// An empty blob therefore surfaces as
/// `PFError::Device("LED config response too short: 0 bytes")` at
/// `hal::io::read_led_config` (`picoforge/src/hal/io.rs:179`) — the call the
/// Rescue LED UI makes. Seventeen zeros returns a well-defined answer instead:
/// `steady = false`, and four `(colour 0, brightness 0)` statuses.
///
/// The read-modify-write would *not* distinguish the two, which is worth
/// saying because it is the argument this rationale is most easily confused
/// with. `write_rskey_led_config`'s guard
/// (`current.len() >= RSKEY_LED_CONF_LEN`,
/// `picoforge/src/hal/fido/mod.rs:2045-2047`) sends an empty blob down the
/// same all-zero fall-through as an error, so the write that follows is
/// byte-identical either way.
/// `led_read_modify_write_preserves_effect_and_speed` is the test for that
/// half, and what it needs is that `0x02` is *readable at all* — not that the
/// unread block has any particular shape.
#[test]
fn led_read_of_an_unconfigured_device_is_seventeen_zero_bytes() {
    let (mut dev, _trng) = DevicePinClient::boot();
    let block = led_read_block(&mut dev);
    assert_eq!(
        block,
        vec![0u8; 17],
        "an unconfigured device serves 17 zero bytes, not an empty blob. The \
         client's guard is `current.len() >= RSKEY_LED_CONF_LEN` \
         (picoforge/src/hal/fido/mod.rs:2045-2047), so an empty answer takes \
         the same all-zero fall-through as an error and the first LED write \
         becomes a wipe instead of a no-op-over-zeros"
    );
}

/// `CONFIG_READ` at `0x02` answers `{1: <17 bytes>}` and nothing else.
///
/// The literal expectation is the reason this is not a round-trip. The
/// response is written by hand into the reply buffer
/// (`write_led_read_response`) and compared against bytes typed here, so an
/// encoder that emitted the block under the wrong key, with the wrong length
/// head, or alongside the effective map would have to reproduce these exact
/// bytes to pass.
#[test]
fn led_read_answers_a_seventeen_byte_string_under_key_one() {
    let mut dev = DevicePinClient::boot().0;
    let block = full_led_block();
    dev.app.keystore().phy.led_conf = Some(block);

    let (status, body) = dev.call(
        VENDOR_41,
        config_read_request(TARGET_LED_LITERAL).as_slice(),
    );
    // `dev.call` returns the status separately, so `body` is the CBOR half and
    // the expectation starts at the map header.
    let mut expected = Vec::new();
    expected.push(0xA1); // a one-pair map
    expected.push(0x01); // key 1
    expected.push(0x51); // a 17-byte string: major type 2, length 17 (0x50|0x11)
    expected.extend_from_slice(&block.0);
    assert_eq!(
        body, expected,
        "the LED read is {{1: <block>}} — key 1 is the block as a CBOR byte \
         string, and the 2 map is absent. The effective map is PHY-shaped \
         (led_gpio/touch_timeout/led_driver) and the client reads its keys \
         off whatever record came back (picoforge/src/hal/fido/ops.rs:1480-1487), \
         so emitting it here would put a LED GPIO on a record that has none"
    );
    assert_eq!(status, 0x00);
}

/// A `DEV_CONF` or `LED` write that reaches flash is still durable before the
/// ack, and a commit that fails is still not a `0x00`.
///
/// The same two properties [`config_write_persists_before_the_ack`] and
/// [`config_write_answers_a_commit_failure_rather_than_a_0x00`] pin for PHY,
/// driven for the two new targets. They are worth re-proving per target rather
/// than assuming, because the targets differ in the tier they are gated on —
/// `DEV_CONF` is identity, `LED` is presence — and the *rollback* half in
/// particular would catch an implementation that committed a benign-tier write
/// outside the `if let Some(next) = outcome.phy` the dispatch arm shares.
///
/// The reboot is the load-bearing leg: it is the only check that separates
/// "on flash" from "in RAM", and it goes through a fresh `FidoApp` reading the
/// same store.
#[test]
fn dev_conf_and_led_are_durable_before_the_ack() {
    let mut dev = DevicePinClient::boot().0;
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);

    let (status, _) = dev.call(
        VENDOR_41,
        &config_write_request_for(
            TARGET_DEV_CONF_LITERAL,
            &dev_conf_blob(0x000B),
            Some(&token),
        ),
    );
    assert_eq!(status, 0x00, "precondition: the DEV_CONF write is accepted");
    let (status, _) = dev.call(
        VENDOR_41,
        &config_write_request_for(TARGET_LED_LITERAL, &full_led_block().0, Some(&token)),
    );
    assert_eq!(status, 0x00, "precondition: the LED write is accepted");

    assert!(
        dev.persist(),
        "the HID task's persist gate must succeed after these writes"
    );

    // Reboot from the store alone, and read each record back through a
    // different sub-command than wrote it.
    let mut trng = HostTrng::new();
    let mut fresh = DeviceApp::boot(&mut trng, &mut dev.store).expect("boot from the store");
    let stored = fresh.keystore().phy;
    assert_eq!(
        stored.enabled_usb_itf,
        Some(0x000B),
        "the acked DEV_CONF write is on flash after a reboot that discarded the \
         app — so it was durable, and not merely in RAM"
    );
    assert_eq!(
        stored.led_conf,
        Some(full_led_block()),
        "and so is the acked LED block, byte for byte"
    );
}

/// A commit that cannot land is reported as a failure on the new targets too.
///
/// This is the **ordering** half of durable-before-ack, and it is the half that
/// can actually fail: the device is handed a store that refuses every write, so
/// `DeviceKeystore::persist` fails inside `grow_checked` before the status the
/// reply carries is chosen. If someone moved the commit to after
/// `finish_reply`, the `0x00` would already be on the wire when the commit
/// failed and this would see `0x00` and a mutated record.
///
/// Driven on the **presence**-tier `LED` target on purpose. `DEV_CONF` is the
/// identity tier and reaches the same code, so one target is enough to pin the
/// ordering; `LED` is the one whose gate is not the token, so a regression that
/// committed benign writes on a different path would show up here and not in
/// the `DEV_CONF` test.
#[test]
fn led_write_answers_a_commit_failure_rather_than_a_0x00() {
    let mut dev = DevicePinClient::boot().0;
    dev.set_pin(b"1234");
    let token = dev.get_pin_token_with_permissions(b"1234", PERM_ACFG_LITERAL);

    // A first, accepted write, so the rollback is observable against a
    // non-default record.
    let start = fapico2_fido::vendorff::LedConf([0xAB; 17]);
    let (status, _) = dev.call(
        VENDOR_41,
        &config_write_request_for(TARGET_LED_LITERAL, &start.0, Some(&token)),
    );
    assert_eq!(
        status, 0x00,
        "precondition: the first LED write is accepted"
    );
    let before = dev.app.keystore().phy;
    assert_eq!(
        before.led_conf,
        Some(start),
        "and it is the record that stands"
    );

    // Now a second write into a store that cannot be programmed.
    let mut unwritable = UnwritableStore::new();
    let next = fapico2_fido::vendorff::LedConf([0xCD; 17]);
    let (status, _) = dev.call_with_store(
        VENDOR_41,
        &config_write_request_for(TARGET_LED_LITERAL, &next.0, Some(&token)),
        &mut unwritable,
    );
    assert_eq!(
        status, 0x28,
        "an LED block that could not be made durable must be reported as 0x28 \
         (KeyStoreFull), not 0x00. The status the reply carries is computed \
         from a commit that has ALREADY run, so a commit that failed cannot be \
         reported as success"
    );
    assert_eq!(
        dev.app.keystore().phy,
        before,
        "and the record must be rolled back, not left mutated in RAM: a failed \
         commit that kept the change would be re-persisted by the next \
         successful command, which is a write nobody asked for"
    );

    // Nothing reached the real store either.
    let mut trng = HostTrng::new();
    let mut fresh = DeviceApp::boot(&mut trng, &mut dev.store).expect("boot from the store");
    assert_eq!(
        fresh.keystore().phy.led_conf,
        Some(start),
        "the refused commit left nothing on flash, in the store or in the app"
    );
}

/// Read the LED block over the device command path, as the client does.
///
/// Goes through `CONFIG_READ` (`0x0D`) on a `DeviceApp` rather than calling
/// [`fapico2_fido::vendor41::config_read`] directly, because the reply's exact
/// bytes — status, map header, key, string head — are part of what is being
/// tested, and only the command path produces them.
fn led_read_block(dev: &mut DevicePinClient) -> Vec<u8> {
    let (status, body) = dev.call(
        VENDOR_41,
        config_read_request(TARGET_LED_LITERAL).as_slice(),
    );
    assert_eq!(
        status, 0x00,
        "CONFIG_READ at target 0x02 must answer 0x00. If this fails, the client's \
         read-modify-write takes its all-zero fall-through and a colour write \
         wipes every effect and speed"
    );
    // `dev.call` splits the status byte off for us, so `body` is the CBOR
    // half on its own — skipping a byte here would parse the map header as
    // a key.
    let mut p = nh::Parser::new(&body[..]);
    assert_eq!(
        p.next().unwrap(),
        nh::Item::Map(1),
        "a one-pair map: key 1 and nothing else. A second pair would mean the \
         PHY-shaped effective map was emitted for a record that has no such \
         fields"
    );
    assert_eq!(p.next().unwrap(), nh::Item::U(1), "key 1 carries the block");
    match p.next().unwrap() {
        nh::Item::B(b) => b.to_vec(),
        other => panic!("key 1 must be a byte string, got {other:?}"),
    }
}

/// The PHY read's widths come from the codec's own table, in both halves.
///
/// US-116 built `PhyTag::declared_width` and left the production write path
/// spelling its widths out as literals, on the grounds that the migration
/// belonged to whichever story owned the write path. US-117 added a fifth
/// hard-coded width (`PhyTag::EnabledUsbItf`'s `exact::<1>`), so the count of
/// places a width is written down went up rather than down — which is why the
/// migration was done here rather than left.
///
/// What this asserts is the **correspondence**, not the numbers:
///
/// 1. the set `CONFIG_READ` at `0x01` emits is exactly the four fixed-width
///    tags — no string tag, which is the case where `declared_width` is `None`
///    and the conservative fallback would silently under-count a header;
/// 2. every emitted width is what the codec table says, so `phy_record_len` and
///    `write_phy_record` cannot disagree about it;
/// 3. the total is still the 16 the reply-buffer bound was written against.
///
/// (1) is checked against `PhyTag::ALL` rather than against a hand-written
/// list, so a tag added to the codec has to be *deliberately* routed here.
#[test]
fn phy_read_widths_come_from_the_codec_table() {
    use fapico2_fido::vendor41::EMITTED_PHY_TAGS;

    let emitted: Vec<u8> = EMITTED_PHY_TAGS.iter().map(|t| t.byte()).collect();
    assert_eq!(
        emitted,
        vec![TAG_VIDPID, TAG_LED_GPIO, TAG_LED_BRIGHTNESS, TAG_OPTIONS],
        "CONFIG_READ at target 0x01 emits these four records, in ascending tag \
         order. **If you are here because you want to add a fifth tag, read \
         `vendor41::EMITTED_PHY_TAGS` first** — that array is a security \
         boundary, not just a list: it is the only thing keeping the USB \
         enabled-interface mask out of an unauthenticated read, because \
         CONFIG_READ is the one sub-command the client sends with no token and \
         no MAC. Adding PhyTag::EnabledUsbItf (0x0B) here would publish the \
         bus mask to any local process, even though it is a perfectly valid \
         fixed-width tag that apply_phy_record already writes."
    );
    assert_eq!(
        EMITTED_PHY_TAGS.len(),
        4,
        "the emitted set is exactly the four fields the PHY read writes. \
         PhyTag::ALL has {} tags; the {} absent here break down as two USB \
         string tags (declared_width -> None, and no PhyConfig field), one \
         routed to the DEV_CONF record instead (EnabledUsbItf — the security \
         exclusion above), and {} with no PhyConfig field at all \
         (LedDriver, LedOrder, LedNum, Curves, PresenceTimeout)",
        fapico2_platform::phy_tlv::PhyTag::ALL.len(),
        8,
        5
    );

    // (2) Every emitted width is the table's, and every one is exact.
    let mut total = 0usize;
    for tag in EMITTED_PHY_TAGS {
        let declared = tag
            .declared_width()
            .unwrap_or_else(|| panic!("{} is emitted, so it must declare a width", tag.byte()));
        total += fapico2_platform::phy_tlv::record_len(declared);
        // And the record this test's own encoder would produce has exactly that
        // many value bytes — checked through the public read path rather than
        // through a private helper, so this is the real reply.
        let (status, body) = {
            let (mut dev, _trng) = DevicePinClient::boot();
            let mut phy = fapico2_fido::vendorff::PhyConfig::default();
            match tag {
                t if t.byte() == TAG_VIDPID => phy.vid_pid = Some(VIDPID_PACKED),
                t if t.byte() == TAG_LED_GPIO => phy.led_gpio = Some(0x0C),
                t if t.byte() == TAG_LED_BRIGHTNESS => phy.led_brightness = Some(80),
                _ => phy.options = Some(0x0002),
            }
            dev.app.keystore().phy = phy;
            dev.call(
                VENDOR_41,
                config_read_request(TARGET_PHY_LITERAL).as_slice(),
            )
        };
        assert_eq!(
            status,
            0x00,
            "tag 0x{:02X} alone is a readable record",
            tag.byte()
        );
        // `A1 01 <head> <content...>`: the blob is the only byte string, and
        // its content is everything after the 3-byte head for these widths.
        let blob_len = body.len() - 3;
        assert_eq!(
            blob_len,
            fapico2_platform::phy_tlv::record_len(declared),
            "tag 0x{:02X} emitted a {}-byte record; the codec table declares a \
             {} byte value, so the CBOR byte-string header and its content \
             disagree",
            tag.byte(),
            blob_len,
            declared
        );
    }

    // (3) The bound the reply buffer was sized against is unchanged.
    assert_eq!(
        total, 16,
        "all four records together are still 16 bytes: (2+4)+(2+1)+(2+1)+(2+2). \
         `config_read_blob_fits_the_reply_buffer` sizes the reply against this"
    );
    assert_eq!(
        fapico2_fido::vendor41::phy_record_len(&full_phy_config()),
        16,
        "and phy_record_len agrees, which is the half that sizes the CBOR \
         byte-string header in front of the content"
    );
}

/// # The two key-6 codecs must agree, in both directions
///
/// `phy` is the one record stored **twice**: once by the host keystore
/// (`keystore.rs`, which the emulation binary drives) and once by the device
/// keystore (`device_keystore.rs`, which the RP2350 runs), in the same
/// snapshot envelope. A snapshot written by one is expected to load into the
/// other, and a configuration that survives a real reboot and not a host one
/// would be a divergence rather than a quiet difference.
///
/// US-113 review found the two decoders disagreeing about a `vid_pid` wider
/// than `u32`: one refused it, the other truncated it, so the *same bytes*
/// loaded into two different hardware configurations. That was caught by a
/// pair of unit tests living inside each module — which is the shape of test
/// that cannot see a disagreement about a field *number*, because each one
/// only ever exercises its own codec against hand-built input.
///
/// US-117 widened the record and made exactly that class of bug more likely, in
/// two new ways neither existing test could catch:
///
/// * a new **field number** (5, the `DEV_CONF` mask) that one codec could write
///   and the other refuse outright — the decoder's catch-all is `return None`,
///   so a mismatch is a snapshot that will not load at all;
/// * a new **value shape** (field 6, a 17-byte CBOR *byte string*, where every
///   other field is an integer), which is the one place the decoders dispatch
///   on the field before the value's type.
///
/// So this test does the one thing the twins cannot: it puts a fully-populated
/// record through **both** encoders and compares the key-6 maps byte for byte,
/// then pushes each one's output through the other's decoder. Every field
/// carries a value nothing else could be confused with, so a transposition or
/// a shared arm cannot pass.
#[test]
fn key6_round_trips_through_both_keystores() {
    use fapico2_fido::keystore::AuthState as HostAuth;
    use fapico2_fido::vendorff::LedConf;

    // **All eight** fields, each a value nothing else could be confused with.
    //
    // The two names are here rather than omitted because this test exists to
    // keep the two keystores in step, and a field one of them encodes
    // differently is exactly what that is for. They are also the record's
    // first variable-length members, so they exercise the CBOR byte-string
    // head the integer fields cannot reach: an off-by-one in the length would
    // show up here as a decode that stops one byte early rather than as a
    // value that came back wrong.
    let populated = fapico2_fido::vendorff::PhyConfig {
        vid_pid: Some(0x1209_0001),
        led_gpio: Some(0x0C),
        led_brightness: Some(80),
        options: Some(0x0002),
        enabled_usb_itf: Some(0x03AB),
        led_conf: Some(LedConf([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11,
        ])),
        // Deliberately *unequal* lengths, and neither a multiple of the CBOR
        // short-form thresholds, so a head encoded with the wrong major type
        // cannot agree with the other codec by accident.
        product: Some(
            fapico2_fido::vendorff::IdentityName::new("Acme Token").expect("9 bytes"),
        ),
        manufacturer: Some(
            fapico2_fido::vendorff::IdentityName::new("The BLOCO Community")
                .expect("19 bytes"),
        ),
    };

    // --- the host codec's key-6 map ---
    // Struct-update rather than `default()` then assign, which clippy flags
    // (`field_reassign_with_default`) for good reason: it reads as two steps
    // when it is one value.
    let host = HostAuth { phy: populated, ..HostAuth::default() };
    let host_key6 = key6_of(&fapico2_fido::cbor::encode(&host.to_cbor_for_test(None)));

    // --- the device codec's key-6 map, lifted out of its snapshot envelope ---
    let (mut dev, _trng) = DevicePinClient::boot();
    dev.app.keystore().phy = populated;
    let mut out: HV<u8, 4096> = HV::new();
    dev.app
        .keystore()
        .to_cbor(None, &mut out)
        .expect("the device codec must serialize a fully-populated key-6 record");
    let mut q = nh::Parser::new(&out[..]);
    assert_eq!(q.next().unwrap(), nh::Item::Map(1), "one envelope entry");
    assert_eq!(q.next().unwrap(), nh::Item::U(1), "key 1");
    assert!(matches!(q.next().unwrap(), nh::Item::Array(3)), "[max, auth, creds]");
    assert!(matches!(q.next().unwrap(), nh::Item::B(_)), "max_creds");
    let auth_bytes = match q.next().unwrap() {
        nh::Item::B(b) => b.to_vec(),
        other => panic!("the auth map must be a byte string, got {other:?}"),
    };
    let device_key6 = key6_of(&auth_bytes);

    // The load-bearing assertion: same record, same bytes.
    assert_eq!(
        fapico2_fido::cbor::encode(&device_key6),
        fapico2_fido::cbor::encode(&host_key6),
        "the two codecs must serialize a fully-populated key-6 record \
         identically. Two codecs that agree after decoding but not before can \
         still number a field differently — which is exactly the US-113 \
         finding, and which no test living inside either module can see"
    );

    // --- and each codec must read its own key-6 map back ---
    //
    // Not the *other's*, and the reason is worth stating because it looks like
    // a weaker test than it is. The byte-identity assertion above is the
    // transitive argument: if both codecs emit the same key-6 bytes, then any
    // decoder that reads one reads the other. A cross-decode would re-derive
    // that at the cost of re-implementing two snapshot envelopes — and
    // `device_keystore.rs`'s own `us113_tests` already records why that is not
    // worth it ("the snapshot envelope around it is a different format on each
    // side, so a shared test would have to re-implement two envelopes to reach
    // one function"). Those twins are where the cross-stack *decode* is
    // exercised, on forged bytes, from inside each module.
    //
    // What these two legs add is the other half: that the record survives each
    // codec's own encode/decode at all, including the two new field shapes
    // US-117 introduced — a `u16` mask and a 17-byte value that is a CBOR
    // **byte string** where every other field is an integer.
    let device_back = fapico2_fido::device_keystore::DeviceKeystore::from_cbor(&out, None)
        .expect("the device codec must read back the snapshot it just wrote");
    assert_eq!(
        device_back.phy,
        populated,
        "every field must survive the device codec's own round trip, including \
         the u16 mask (field 5) and the 17-byte block (field 6, a byte string \
         where every other field is an integer)"
    );

    let host_back = HostAuth { phy: populated, ..HostAuth::default() };
    let host_auth_bytes = fapico2_fido::cbor::encode(&host_back.to_cbor_for_test(None));
    let host_read = HostAuth::from_cbor_for_test(&host_auth_bytes, None, false)
        .expect("the host codec must read back the auth map it just wrote");
    assert_eq!(
        host_read.phy,
        populated,
        "and the host codec's own round trip must preserve them too, or the two \
         codecs would agree on the bytes while disagreeing on what they mean"
    );
}

/// Pull the key-6 value out of a CBOR-encoded **auth map**.
///
/// Hand-rolled so the failure says which layer broke. The two codecs' decoders
/// both treat an unrecognised key as fatal (`return None`), so a field-number
/// disagreement is not a silently-dropped field — it is a snapshot that will not
/// load at all, which is what makes the byte comparison above the sharper test.
fn key6_of(auth_bytes: &[u8]) -> fapico2_fido::cbor::Value {
    use fapico2_fido::cbor::Value as V;
    let (decoded, _rest) =
        fapico2_fido::cbor::decode(auth_bytes).expect("the auth map must decode");
    let V::M(entries) = decoded else {
        panic!("the auth map must be a CBOR map, got {decoded:?}")
    };
    entries
        .iter()
        .find(|(k, _)| matches!(k, V::U(6)))
        .map(|(_, v)| v.clone())
        .expect("the auth map must carry key 6 (the phy record) when phy is set")
}


// ---------------------------------------------------------------------------
// US-1516: the written decision, per sub-command
// ---------------------------------------------------------------------------

/// [`vendor41::decision`] is a row per sub-command, and the row has to agree
/// with the tables the code actually enforces.
///
/// Three checks, and each catches a different way the record goes stale:
///
/// * **`requirement` is not a field of the row** — deliberately. The enforced
///   answer lives in [`vendor41::required_permission`], so a second copy here
///   would be a second source that agrees until one of them moves. The
///   consistency that *is* checkable is checked instead: a row may only claim
///   [`Tokenless::Touch`] when the enforced table would actually admit a
///   tokenless request, i.e. when the row is `TokenOptional`. Claiming a touch
///   for `CONFIG_WRITE` would assert a fallback for the one sub-command that is
///   refused `0x40` before any gate runs.
/// * **`reason` is never empty** — a row with no reason is the thing this table
///   exists to prevent, so it is a failure rather than a style.
/// * **`arm` names a function that exists** — see the next test.
#[test]
fn decision_agrees_with_the_permission_table() {
    use fapico2_fido::vendor41::{
        decision, required_permission, Requirement, Subcommand, SubcommandDecision, Tokenless,
    };

    for sub in Subcommand::ALL {
        let d: SubcommandDecision = decision(sub);

        assert_eq!(
            d.sub, sub,
            "the row filed under {sub:?} must say it is about {sub:?} — a row \
             copied to the wrong variant is a record of the wrong sub-command"
        );
        assert!(
            !d.reason.trim().is_empty(),
            "{sub:?} has no recorded reason; an unexplained row is exactly the \
             thing US-1516 was raised about"
        );
        assert!(
            !d.arm.is_empty() && d.story.starts_with("US-"),
            "{sub:?} must name the arm that serves it and the story that wrote it \
             (got arm={:?}, story={:?})",
            d.arm,
            d.story
        );

        // The internal consistency: only a token-optional row has a tokenless
        // path at all.
        if d.tokenless == Tokenless::Touch {
            assert!(
                matches!(required_permission(sub), Requirement::TokenOptional(_)),
                "{sub:?} claims a touch fallback, so its enforced row must be \
                 TokenOptional — otherwise a tokenless request is refused \
                 before any gate runs and there is nothing for the touch to \
                 authorise (it is {})",
                match required_permission(sub) {
                    Requirement::Ungated => "Ungated",
                    Requirement::Permission(_) => "Permission",
                    Requirement::TokenOptional(_) => "TokenOptional",
                }
            );
        }
    }
}

/// The token-optional rows that admit a request with no token are split into
/// two groups, and the split is the decision US-1516 exists to write down.
///
/// Eight are stopped by a physical touch. **Four are not**, and this pins that
/// set by name: adding a fifth is then a deliberate edit to this list rather
/// than an omission nobody notices, which is the failure mode of the epoch this
/// story found — a `NOT_ALLOWED` stub that reads as a refusal while implying a
/// capability, and prose claiming a gate that no arm consults.
#[test]
fn the_token_optional_rows_without_a_touch_are_the_four_named_ones() {
    use fapico2_fido::vendor41::{decision, requires_presence_when_tokenless, Subcommand, Tokenless};

    // Recorded with the reason each one gives instead. The names must match
    // `decision`'s rows; the reasons are what a reader is owed, and they are
    // asserted to be *different from one another* by construction — two rows
    // sharing a `Tokenless` variant because they share a mechanism is fine,
    // two sharing it for different reasons is not.
    let no_touch = [
        (Subcommand::Mse, Tokenless::Ungated),
        (Subcommand::State, Tokenless::StatusOnly),
        (Subcommand::Unlock, Tokenless::Possession),
        (Subcommand::AttState, Tokenless::StatusOnly),
    ];

    for sub in Subcommand::ALL {
        // Only the token-optional rows are in the split at all: `CONFIG_READ`
        // and `CONFIG_WRITE` never reach an arm without a token, so "does it
        // take a touch" is not a question about them.
        if !requires_presence_when_tokenless(sub) {
            continue;
        }
        let touches = decision(sub).tokenless == Tokenless::Touch;
        let named = no_touch.iter().any(|(s, _)| *s == sub);
        assert_eq!(
            touches,
            !named,
            "{sub:?} ({:?}) — if this row changed which side of the split it is \
             on, this list must change with it. A fifth token-optional row \
             without a touch fallback is a decision to make, not a default.",
            decision(sub).tokenless
        );
    }

    // Every one of the four really does owe a presence check under the enforced
    // table, and the eight that do take a touch are the remaining token-optional
    // rows — twelve in total, so the two sets partition the set exactly.
    for (sub, _) in no_touch {
        assert!(
            requires_presence_when_tokenless(sub),
            "{sub:?} is in the no-touch list, so it must still be a row the \
             enforced table admits without a token — otherwise the list is \
             describing a sub-command that never reaches its arm"
        );
    }
    let tokenless_total = Subcommand::ALL
        .iter()
        .filter(|s| requires_presence_when_tokenless(**s))
        .count();
    assert_eq!(
        tokenless_total,
        no_touch.len() + 8,
        "eight token-optional rows take a touch and four do not; the enforced \
         table must therefore name twelve"
    );
}

/// Every `arm` in [`vendor41::decision`] names a function that exists.
///
/// A decision table is only better than a comment if it cannot quietly become
/// fiction. This reads the sources the arms live in and requires the function
/// name to be there — so renaming `vendor_audit::audit_read` turns this red
/// instead of leaving a table that points at a function nobody can find.
///
/// The check is textual rather than a link, because the arms are private
/// (`pub(crate)`-ish module functions that no public API reaches) and Rust has
/// no way to name a function as a value. What it catches is the realistic
/// drift: a rename, or a row written from memory.
#[test]
fn every_decision_row_names_an_arm_that_exists() {
    use fapico2_fido::vendor41::{decision, Subcommand};

    // The modules a row may name, mapped to the file that must contain the
    // function. Deliberately an allowlist: a row naming some *other* module is
    // a typo or a lie, and both should fail here rather than fall through to a
    // source file this test does not read.
    let sources: [(&str, &str); 5] = [
        ("vendor_backup", include_str!("../src/vendor_backup.rs")),
        ("vendor_lock", include_str!("../src/vendor_lock.rs")),
        ("vendor_audit", include_str!("../src/vendor_audit.rs")),
        ("vendor_att", include_str!("../src/vendor_att.rs")),
        ("vendor41", include_str!("../src/vendor41.rs")),
    ];

    for sub in Subcommand::ALL {
        let arm = decision(sub).arm;
        let (module, fn_name) = arm
            .rsplit_once("::")
            .unwrap_or_else(|| panic!("{sub:?}: arm {arm:?} is not module::function"));
        let source = sources
            .iter()
            .find(|(m, _)| *m == module)
            .unwrap_or_else(|| panic!("{sub:?}: arm {arm:?} names module {module:?}, which this test does not read"))
            .1;

        // `fn name(` or `fn name<T>(` — the generic form is real
        // (`vendor_lock::state` is `fn state<const N: usize>`), and matching
        // only the parenthesised spelling would have made this test fail on a
        // correct row.
        let needle = format!("fn {fn_name}");
        let found = source.match_indices(&needle).any(|(at, _)| {
            matches!(
                source[at + needle.len()..].trim_start().chars().next(),
                // the parameter list, or a generic list in front of it
                Some('(') | Some('<')
            )
        });
        assert!(
            found,
            "{sub:?}: the decision row names {arm}, but no `fn {fn_name}` exists in \
             {module}.rs — either the arm was renamed and the row was not, or the \
             row was written from memory"
        );
    }
}

/// "Every sub-command has a real arm", proved on the **device** path.
///
/// # Why this is not a restatement of [`vendor41::PENDING`]
///
/// The whole file so far can pass while the board is broken: `PENDING` is a
/// list in a module both twins import, so an empty one says the *list* is
/// empty and nothing about what the RP2350 actually does with a `0x41` frame.
/// Fixing only `app.rs` — or only a `PENDING` entry — would leave a green suite
/// and a dead device path, which is exactly the twin trap AGENTS.md §1 names.
///
/// So this drives the type the serve loop actually constructs,
/// [`DeviceApp`] = `device_app::FidoApp`, through `process_ctap2_with_store`,
/// and requires that every sub-command is *dispatched*: the answer is never
/// `0x01`, the catch-all's "I do not recognise this command".
///
/// # Why the assertion is `!= 0x01` and not `!= NOT_ALLOWED`
///
/// Measured, not assumed. Driving every sub-command bare (empty params, no
/// token, no touch) on this device app gives:
///
/// | sub-command | status | meaning |
/// |---|---|---|
/// | 11 of 14 | `0x14` `MissingParameter`, `0x02` or `0x00` | the arm decoded the request and had nothing to work with |
/// | `Export` | **`0x30` `NotAllowed`** | the export window is sealed on a fresh device, and a sealed window is a real refusal, not a stub |
///
/// The tempting assertion here — "no sub-command answers `NOT_ALLOWED` any
/// more" — is **false**, and would have been a broken test written with total
/// confidence. `Export` reaches `if ops.backup_sealed() { return NotAllowed }`
/// (`vendor_backup::export`), and a fresh keystore is sealed by design. The
/// distinction this test actually needs is *dispatched* vs *unrecognised*, so
/// `0x01` is the discriminator and `0x30` is allowed to mean what it means.
#[test]
fn every_subcommand_is_dispatched_on_the_device_path() {
    const INVALID_COMMAND: u8 = 0x01;
    use fapico2_fido::vendor41::PENDING;

    assert!(
        PENDING.is_empty(),
        "this test's reasoning assumes the stub set has drained; PENDING names {:?}",
        PENDING
    );

    for sub in Subcommand::ALL {
        let req = rskey_request(sub.byte());
        let (mut dev, _trng, mut store) = device_app();
        let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
        let n =
            dev.process_ctap2_with_store(VENDOR_41, &req, [1, 2, 3, 4], &mut out, Some(&mut store));

        assert_ne!(
            out[..n].first().copied(),
            Some(INVALID_COMMAND),
            "{sub:?} (0x{:02X}) answered INVALID_COMMAND on the device path, so the \
             RP2350 dispatch does not recognise it. PENDING is empty, so this is not \
             a stub refusing politely — it is a sub-command the device twin never \
             routes. Fix the device path, not the list.",
            sub.byte()
        );
    }
}

