//! US-1528: the CTAP2 **status** table, pinned against the reference.
//!
//! # Why this file exists
//!
//! `Ctap2Response` was off by one across `0x2B`..`0x2D` and wrong again at
//! `0x07`/`0x08`. The consequence was not cosmetic: **every** `InvalidOption`
//! this firmware produced (ten producer sites) was decoded by every client as
//! `UNSUPPORTED_OPTION`, which is a different sentence — "you named an option
//! we do not support" rather than "you named a value this option does not
//! accept". From `0x2E` upward the table already agreed with the reference,
//! which is exactly why nothing had visibly broken.
//!
//! # Why it drifted, and why the shape below
//!
//! The values were almost certainly transcribed by reading down a column and
//! stopping at the first row that "looked right", rather than by copying each
//! `#define`. So this file does not derive anything from the enum. The
//! expected bytes are **literals**, transcribed by hand from two independent
//! sources that agree with each other:
//!
//!   * `fido2` 2.2.1, `fido2/ctap.py`, `CtapError.ERR` — what `ykman`,
//!     Yubico Authenticator and every first-party tool actually decode. Read by
//!     *executing* the enum (`for n, v in CtapError.ERR.__members__.items()`),
//!     not by grepping a string literal — an earlier review in this epic
//!     caught exactly that failure mode.
//!   * the C reference, `pico-fido2/src/fido/ctap.h`, `CTAP2_ERR_*`.
//!
//! A test that computed its expectations from the table it is testing would
//! pass no matter how wrong the table got, so nothing here calls
//! `.code()` on the left-hand side of a comparison.
//!
//! # Where the two sources differ
//!
//! `PIN_TOKEN_EXPIRED` is the one. `fido2` defines it at `0x38`; `ctap.h` does
//! not define it at all (it runs `0x37` → `0x39`). The **library wins**, since
//! it is the decoder: a client reading our `0x38` gets `PIN_TOKEN_EXPIRED` and
//! a client reading the C firmware's silence gets nothing. So `0x38` stays and
//! the divergence is recorded rather than closed. `CtapError.ERR` also carries
//! the two withdrawals as comments — `# NOT_BUSY = 0x29  # No longer in
//! spec` and `# NO_OPERATION_PENDING = 0x2A  # No longer in spec` — which is
//! where the old `NoOperationPending = 0x29` came from and why `0x29` and
//! `0x2A` are not merely unused but *forbidden* (asserted below).

use fapico2_fido::ctap2::{Ctap2Command, Ctap2Response};
use fapico2_fido::hid::CtapHidError;
use fapico2_fido::{FidoError, FidoApp as DeviceApp};
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;

// ---------------------------------------------------------------------------
// The reference
// ---------------------------------------------------------------------------

/// `CtapError.ERR` (fido2 2.2.1, executed) ∩ `CTAP2_ERR_*`
/// (`pico-fido2/src/fido/ctap.h`), as `(variant, reference byte)`.
///
/// Transcribed, never derived. If a row here disagrees with
/// `crate::ctap2::Ctap2Response`, the enum is wrong — the reference is not
/// something this repository gets to redefine.
const REFERENCE: &[(&str, u8)] = &[
    ("Ok", 0x00),
    ("InvalidCommand", 0x01),
    ("InvalidParameter", 0x02),
    ("InvalidLength", 0x03),
    ("InvalidSeq", 0x04),
    ("Timeout", 0x05),
    ("ChannelBusy", 0x06),
    // 0x07/0x08 were LockRequired/InvalidChannel. Both wrong: the reference
    // skips 0x07..0x09 entirely. CTAP1_ERR_LOCK_REQUIRED 0x0a and
    // CTAP1_ERR_INVALID_CHANNEL 0x0b (pico-keys-sdk .../ctap_hid.h:157-158)
    // agree with the library.
    ("LockRequired", 0x0A),
    ("InvalidChannel", 0x0B),
    ("CborUnexpectedType", 0x11),
    ("InvalidCbor", 0x12),
    ("MissingParameter", 0x14),
    ("LimitExceeded", 0x15),
    // 0x16 was UNSUPPORTED_EXTENSION and 0x17/0x18 are FP_DATABASE_FULL /
    // LARGE_BLOB_STORAGE_FULL. This firmware has no code for them; KEY_STORE_FULL
    // (0x28) is what it returns. Not represented here, deliberately — an absent
    // row is not a claim that the code is wrong.
    ("CredentialExcluded", 0x19),
    ("Processing", 0x21),
    ("InvalidCredential", 0x22),
    ("UserActionPending", 0x23),
    ("OperationPending", 0x24),
    ("NoOperations", 0x25),
    ("UnsupportedAlgorithm", 0x26),
    ("OperationDenied", 0x27),
    ("KeyStoreFull", 0x28),
    // 0x29 (NOT_BUSY) and 0x2A (NO_OPERATION_PENDING) are *withdrawn* — see
    // the module docs. They were the two rows this table used to get wrong.
    ("UnsupportedOption", 0x2B),
    ("InvalidOption", 0x2C),
    ("KeepAliveCancel", 0x2D),
    ("NoCredentials", 0x2E),
    ("UserActionTimeout", 0x2F),
    ("NotAllowed", 0x30),
    ("PinInvalid", 0x31),
    ("PinBlocked", 0x32),
    ("PinAuthInvalid", 0x33),
    ("PinAuthBlocked", 0x34),
    ("PinNotSet", 0x35),
    ("PuatRequired", 0x36),
    ("PinPolicyViolation", 0x37),
    // In the library, absent from ctap.h. Library wins — see module docs.
    ("PinTokenExpired", 0x38),
    ("RequestTooLarge", 0x39),
    ("ActionTimeout", 0x3A),
    ("UpRequired", 0x3B),
    ("UvBlocked", 0x3C),
    ("IntegrityFailure", 0x3D),
    ("InvalidSubcommand", 0x3E),
    ("UvInvalid", 0x3F),
    ("UnauthorizedPermission", 0x40),
    ("Other", 0x7F),
];

/// Every variant of `Ctap2Response`, listed exhaustively.
///
/// The point of the separate list: adding a variant to the enum without adding
/// a row to [`REFERENCE`] must fail a test, not sail through. `REFERENCE.len()`
/// is compared against this in
/// [`every_variant_is_pinned_in_the_reference_table`].
///
/// Listed by `code()` so the two are cross-checked rather than trusted; the
/// per-row value assertion in [`each_variant_matches_the_reference_byte`] is
/// what actually pins the bytes.
const ALL_VARIANTS: &[Ctap2Response] = &[
    Ctap2Response::Ok,
    Ctap2Response::InvalidCommand,
    Ctap2Response::InvalidParameter,
    Ctap2Response::InvalidLength,
    Ctap2Response::InvalidSeq,
    Ctap2Response::Timeout,
    Ctap2Response::ChannelBusy,
    Ctap2Response::LockRequired,
    Ctap2Response::InvalidChannel,
    Ctap2Response::CborUnexpectedType,
    Ctap2Response::InvalidCbor,
    Ctap2Response::MissingParameter,
    Ctap2Response::LimitExceeded,
    Ctap2Response::CredentialExcluded,
    Ctap2Response::Processing,
    Ctap2Response::InvalidCredential,
    Ctap2Response::UserActionPending,
    Ctap2Response::OperationPending,
    Ctap2Response::NoOperations,
    Ctap2Response::UnsupportedAlgorithm,
    Ctap2Response::OperationDenied,
    Ctap2Response::KeyStoreFull,
    Ctap2Response::UnsupportedOption,
    Ctap2Response::InvalidOption,
    Ctap2Response::KeepAliveCancel,
    Ctap2Response::NoCredentials,
    Ctap2Response::UserActionTimeout,
    Ctap2Response::NotAllowed,
    Ctap2Response::PinInvalid,
    Ctap2Response::PinBlocked,
    Ctap2Response::PinAuthInvalid,
    Ctap2Response::PinAuthBlocked,
    Ctap2Response::PinNotSet,
    Ctap2Response::PuatRequired,
    Ctap2Response::PinPolicyViolation,
    Ctap2Response::PinTokenExpired,
    Ctap2Response::RequestTooLarge,
    Ctap2Response::ActionTimeout,
    Ctap2Response::UpRequired,
    Ctap2Response::UvBlocked,
    Ctap2Response::IntegrityFailure,
    Ctap2Response::InvalidSubcommand,
    Ctap2Response::UvInvalid,
    Ctap2Response::UnauthorizedPermission,
    Ctap2Response::Other,
];

// ---------------------------------------------------------------------------
// 1. The table
// ---------------------------------------------------------------------------

/// The core pin: every row of [`REFERENCE`] against the enum, by name.
///
/// Table-driven on purpose — a failure names the variant and both numbers, so
/// the diff reads as "InvalidOption is 0x2B, the reference says 0x2C" rather
/// than as a pile of near-identical assertion failures.
#[test]
fn each_variant_matches_the_reference_byte() {
    // Resolved by name, never by position: the enum is not required to be
    // declared in ascending order for this test to be meaningful.
    let actual: Vec<(&str, u8)> = ALL_VARIANTS
        .iter()
        .map(|r| (variant_name(*r), r.code()))
        .collect();

    for (name, expected) in REFERENCE {
        let found = actual
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("`{name}` is not in ALL_VARIANTS — add it there too"));
        assert_eq!(
            found.1, *expected,
            "Ctap2Response::{name} is 0x{:02X}, the reference says 0x{expected:02X}",
            found.1
        );
    }
}

/// A new variant with no row in [`REFERENCE`] is a hole in the pin, not a
/// silent addition.
#[test]
fn every_variant_is_pinned_in_the_reference_table() {
    assert_eq!(
        ALL_VARIANTS.len(),
        REFERENCE.len(),
        "Ctap2Response has {} variants but the reference table has {} rows. \
         A new status needs a reference byte before it can go on the wire.",
        ALL_VARIANTS.len(),
        REFERENCE.len()
    );
}

/// Two variants sharing a byte is the same class of defect as a wrong byte:
/// the client cannot tell which one it was sent.
#[test]
fn no_two_variants_share_a_byte() {
    let mut seen: Vec<(u8, &'static str)> = Vec::new();
    for v in ALL_VARIANTS {
        let name = variant_name(*v);
        if let Some((_, other)) = seen.iter().find(|(c, _)| *c == v.code()) {
            panic!(
                "0x{:02X} is both Ctap2Response::{other} and Ctap2Response::{name}",
                v.code()
            );
        }
        seen.push((v.code(), name));
    }
}

/// The withdrawn codes, asserted as forbidden rather than merely unused.
///
/// This is the one invariant that is cheap, non-self-referential, and would
/// have caught the original bug on its own: `0x2A` was
/// `Ctap2Response::UnsupportedOption` and `0x29` was
/// `Ctap2Response::NoOperationPending`, and `fido2` carries both only as
/// `# ... No longer in spec` comments. A client that received either has no
/// name for it and falls through to `<ERR.UNKNOWN>`.
#[test]
fn withdrawn_and_undefined_codes_are_not_emitted() {
    // 0x29 NOT_BUSY and 0x2A NO_OPERATION_PENDING — withdrawn from the spec.
    // 0x00..0x06 are fine; 0x07..0x09 are an unassigned gap; 0x0C..0x0F likewise.
    const FORBIDDEN: &[u8] = &[0x07, 0x08, 0x09, 0x0C, 0x0D, 0x0E, 0x0F, 0x29, 0x2A];
    for v in ALL_VARIANTS {
        assert!(
            !FORBIDDEN.contains(&v.code()),
            "Ctap2Response::{} is 0x{:02X}, which the reference does not \
             define (withdrawn or unassigned)",
            variant_name(*v),
            v.code()
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Cross-table agreement
// ---------------------------------------------------------------------------

/// Three private spellings of the same CTAP error codes used to live in this
/// crate — `Ctap2Response`, `CtapHidError` and `FidoError::to_ctap_error` —
/// and `CtapHidError`/`FidoError` were wrong in the same way `Ctap2Response`
/// was, which is a large part of why the error stayed invisible: the tables
/// agreed with *each other* and only disagreed with the reference.
///
/// `firmware/src/ctap_hid.rs:37` (the firmware worktree) already emits
/// `HID_ERR_INVALID_CHANNEL = 0x0B`, so the two halves now agree by value.
#[test]
fn the_error_tables_agree_with_each_other() {
    assert_eq!(
        CtapHidError::LockRequired.code(),
        Ctap2Response::LockRequired.code(),
        "CtapHidError and Ctap2Response both spell LOCK_REQUIRED; they must \
         not be able to drift apart again"
    );
    assert_eq!(
        CtapHidError::InvalidChannel.code(),
        Ctap2Response::InvalidChannel.code(),
        "CtapHidError and Ctap2Response both spell INVALID_CHANNEL"
    );
    assert_eq!(
        FidoError::InvalidChannel.to_ctap_error(),
        Ctap2Response::InvalidChannel.code(),
        "FidoError::InvalidChannel must reach the wire as INVALID_CHANNEL"
    );
    assert_eq!(
        FidoError::UnsupportedOption.to_ctap_error(),
        Ctap2Response::UnsupportedOption.code(),
        "FidoError::UnsupportedOption must reach the wire as UNSUPPORTED_OPTION"
    );
    // The CTAP HID decoder has to be able to read back what it writes.
    assert_eq!(
        CtapHidError::from(0x0A_u8),
        CtapHidError::LockRequired,
        "From<u8> for CtapHidError must decode 0x0A, or the HID layer reads \
         back its own LockRequired as Unknown"
    );
    assert_eq!(CtapHidError::from(0x0B_u8), CtapHidError::InvalidChannel);
    // ...and the bytes it no longer means. 0x07/0x08 are unassigned, so they
    // must fall through to Unknown rather than to a lock/channel answer.
    assert_eq!(CtapHidError::from(0x07_u8), CtapHidError::Unknown);
    assert_eq!(CtapHidError::from(0x08_u8), CtapHidError::Unknown);
}

/// The old `LockRequired = 0x07` collided with `Ctap2Command::Reset = 0x07`.
///
/// A blanket "no status equals any command" rule would be **wrong** and is not
/// asserted here: the reference itself overlaps heavily at the low end
/// (`CTAP2_ERR_INVALID_COMMAND` is `0x01` and so is `MAKE_CREDENTIAL`; both
/// live on different layers and no client confuses them). The value `0x07` was
/// wrong because it was *undefined in the status table*, not because a command
/// happened to share it. What is asserted is the specific pair that the
/// original report called out, so the collision cannot come back unnoticed.
#[test]
fn lock_required_is_not_the_reset_opcode() {
    assert_eq!(Ctap2Response::LockRequired.code(), 0x0A);
    assert_eq!(Ctap2Command::Reset as u8, 0x07);
    assert_ne!(
        Ctap2Response::LockRequired.code(),
        Ctap2Command::Reset as u8,
        "LOCK_REQUIRED is 0x0A. A reader that has lost track of which table it \
         holds cannot recover if the two tables share a value."
    );
    // The command table is the fido2 dialect and is NOT the spec's — AGENTS.md
    // §2 is explicit that this is deliberate. These are the only command
    // values US-1528 is allowed to have touched, and it did not touch them.
    assert_eq!(Ctap2Command::GetInfo as u8, 0x04);
    assert_eq!(Ctap2Command::ClientPin as u8, 0x06);
    assert_eq!(Ctap2Command::Reset as u8, 0x07);
    assert_eq!(Ctap2Command::GetNextAssertion as u8, 0x08);
    assert_eq!(Ctap2Command::CredMgmt as u8, 0x0A);
    assert_eq!(Ctap2Command::Selection as u8, 0x0B);
}

// ---------------------------------------------------------------------------
// 3. On the wire, both twins
// ---------------------------------------------------------------------------

const MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;

const MC: u8 = 0x01;
const GA: u8 = 0x02;

/// Reference bytes, restated here so the wire assertions below are readable
/// without scrolling to the top. Literals again, for the same reason.
const REF_INVALID_OPTION: u8 = 0x2C;
const REF_UNSUPPORTED_OPTION: u8 = 0x2B;
const REF_KEEPALIVE_CANCEL: u8 = 0x2D;
const REF_PUAT_REQUIRED: u8 = 0x36;
const REF_NO_CREDENTIALS: u8 = 0x2E;

fn device() -> DeviceApp {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    DeviceApp::boot(&mut trng, &mut store).expect("host TRNG + store boot the device app")
}

/// The status byte `device_app::FidoApp` — the twin that runs on the RP2350 —
/// puts on the wire for one request.
fn device_status(cmd: u8, request: &[u8]) -> u8 {
    let mut app = device();
    let mut out = HV::<u8, MAX_MSG>::new();
    let n = app.process_ctap2(cmd, request, [1, 2, 3, 4], &mut out);
    assert!(n >= 1, "device twin produced no status byte");
    out[0]
}

/// The status byte the host twin (`app.rs`) puts on the wire for the same
/// request.
///
/// Both twins are driven because the whole point of US-1528's predecessor,
/// US-1514, was that fixing one of them passes every test and changes nothing
/// on hardware. A table test that only reads the enum would have caught
/// neither.
fn both_twins(cmd: u8, request: &[u8]) -> (u8, u8) {
    let mut host = fapico2_fido::app::FidoApp::with_keystore(fapico2_fido::keystore::MemoryKeystore::new());
    let host_resp = host.process_ctap2(cmd, request, [1, 2, 3, 4]);
    assert!(!host_resp.is_empty(), "host twin produced no status byte");
    (host_resp[0], device_status(cmd, request))
}

/// makeCredential with `options.up = false` — US-1526's deliberate rejection,
/// and the one whose *byte* was wrong for the whole of US-1526's existence.
///
/// The `up: false` policy itself is unchanged and is pinned by
/// `tests/up_policy.rs`; what this asserts is only that the decision travels
/// on `INVALID_OPTION` and not on the two statuses that sit next to it in the
/// table. The `ne!`s are the point: under the old table this request answered
/// `0x2B`, and a single `assert_eq!(…, 0x2B)` would have passed.
#[test]
fn mc_up_false_puts_invalid_option_on_the_wire_on_both_twins() {
    let (host, dev) = both_twins(MC, &mc_up_false());

    for (twin, got) in [("host", host), ("device", dev)] {
        assert_eq!(
            got, REF_INVALID_OPTION,
            "{twin} twin answered 0x{got:02X} for MC up:false; the reference \
             says INVALID_OPTION is 0x2C"
        );
        assert_ne!(got, REF_UNSUPPORTED_OPTION, "{twin} twin: this is the bug US-1528 was filed for");
        assert_ne!(got, REF_KEEPALIVE_CANCEL, "{twin} twin");
    }
    assert_eq!(host, dev, "the twins must agree byte for byte");
}

/// The second `InvalidOption` site in makeCredential: `largeBlobKey` on a
/// non-resident credential. A different request, a different line of
/// `device_core.rs`/`app.rs`, the same byte.
#[test]
fn mc_large_blob_key_without_rk_puts_invalid_option_on_the_wire() {
    let (host, dev) = both_twins(MC, &mc_large_blob_key_no_rk());
    assert_eq!(host, REF_INVALID_OPTION, "host twin, largeBlobKey without rk");
    assert_eq!(dev, REF_INVALID_OPTION, "device twin, largeBlobKey without rk");
    assert_eq!(host, dev, "the twins must agree byte for byte");
}

/// The third: getAssertion with `up: false` **and** `hmac-secret`, the
/// reference's one rejected combination (`cbor_get_assertion.c:324`).
#[test]
fn ga_up_false_with_hmac_secret_puts_invalid_option_on_the_wire() {
    let (host, dev) = both_twins(GA, &ga_up_false_hmac_secret());
    assert_eq!(host, REF_INVALID_OPTION, "host twin, up:false + hmac-secret");
    assert_eq!(dev, REF_INVALID_OPTION, "device twin, up:false + hmac-secret");
    assert_ne!(host, REF_UNSUPPORTED_OPTION, "the whole point of the story");
    assert_eq!(host, dev, "the twins must agree byte for byte");
}

/// A control, and it earns its place.
///
/// `up: false` + `uv: true` with no PIN is `PUAT_REQUIRED` (`0x36`) — a status
/// whose value never moved. If the harness were reading the wrong byte, or the
/// response were not the status at all, this fails while the three tests above
/// might still pass. It also proves the `assert_eq!(…, 0x2C)` assertions are
/// discriminating rather than reflexive: two adjacent requests, two different
/// statuses, both read off `out[0]`.
#[test]
fn a_neighbouring_request_still_answers_its_own_status() {
    for (twin, got) in [
        ("host", both_twins(GA, &ga_up_false_uv_true()).0),
        ("device", both_twins(GA, &ga_up_false_uv_true()).1),
    ] {
        assert_eq!(got, REF_PUAT_REQUIRED, "{twin} twin control");
        assert_ne!(got, REF_INVALID_OPTION, "{twin} twin control must not collide");
    }
}

/// The status immediately *after* `NO_CREDENTIALS` in the corrected table.
/// Proves the values are neighbours and not transposed, from the wire.
#[test]
fn an_empty_store_still_answers_no_credentials_on_both_twins() {
    let req = ga_plain();
    let (host, dev) = both_twins(GA, &req);
    assert_eq!(host, REF_NO_CREDENTIALS, "host twin, GA against an empty store");
    assert_eq!(dev, REF_NO_CREDENTIALS, "device twin, GA against an empty store");
    assert_ne!(host, REF_KEEPALIVE_CANCEL, "0x2D is keepalive-cancel, one below NO_CREDENTIALS");
    assert_eq!(host, dev, "the twins must agree byte for byte");
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

use fapico2_fido::cbor::Value;

fn mc_with_options(options: Vec<(Value, Value)>) -> Vec<u8> {
    let mut map = vec![
        (Value::U(0x01), Value::B(vec![0xCC; 32])),
        (
            Value::U(0x02),
            Value::M(vec![
                (Value::T("id".into()), Value::T("example.com".into())),
                (Value::T("name".into()), Value::T("RP".into())),
            ]),
        ),
        (
            Value::U(0x03),
            Value::M(vec![
                (Value::T("id".into()), Value::B(b"user-1".to_vec())),
                (Value::T("name".into()), Value::T("U".into())),
            ]),
        ),
        (
            Value::U(0x04),
            Value::A(vec![Value::M(vec![
                (Value::T("type".into()), Value::T("public-key".into())),
                (Value::T("alg".into()), Value::N(-7)),
            ])]),
        ),
    ];
    if !options.is_empty() {
        map.push((Value::U(0x07), Value::M(options)));
    }
    fapico2_fido::cbor::encode(&Value::M(map))
}

fn mc_up_false() -> Vec<u8> {
    mc_with_options(vec![(Value::T("up".into()), Value::Bool(false))])
}

fn mc_large_blob_key_no_rk() -> Vec<u8> {
    // `largeBlobKey` lives in *extensions* (CBOR key 0x06) and is only
    // meaningful for a resident credential, so this is the non-resident
    // pairing the second InvalidOption site rejects.
    let mut map = vec![
        (Value::U(0x01), Value::B(vec![0xCC; 32])),
        (
            Value::U(0x02),
            Value::M(vec![
                (Value::T("id".into()), Value::T("example.com".into())),
                (Value::T("name".into()), Value::T("RP".into())),
            ]),
        ),
        (
            Value::U(0x03),
            Value::M(vec![
                (Value::T("id".into()), Value::B(b"user-1".to_vec())),
                (Value::T("name".into()), Value::T("U".into())),
            ]),
        ),
        (
            Value::U(0x04),
            Value::A(vec![Value::M(vec![
                (Value::T("type".into()), Value::T("public-key".into())),
                (Value::T("alg".into()), Value::N(-7)),
            ])]),
        ),
    ];
    map.push((
        Value::U(0x06),
        Value::M(vec![(Value::T("largeBlobKey".into()), Value::Bool(true))]),
    ));
    fapico2_fido::cbor::encode(&Value::M(map))
}

fn ga_with(options: Vec<(Value, Value)>, extensions: Vec<(Value, Value)>) -> Vec<u8> {
    let mut map = vec![
        (Value::U(0x01), Value::T("example.com".into())),
        (Value::U(0x02), Value::B(vec![0xCC; 32])),
    ];
    if !options.is_empty() {
        map.push((Value::U(0x05), Value::M(options)));
    }
    if !extensions.is_empty() {
        // getAssertion extensions are CBOR key 0x04 — *not* makeCredential's
        // 0x06. Using 0x06 here answers CBOR_UNEXPECTED_TYPE and the
        // `up:false` + hmac-secret check is never reached.
        map.push((Value::U(0x04), Value::M(extensions)));
    }
    fapico2_fido::cbor::encode(&Value::M(map))
}

fn ga_plain() -> Vec<u8> {
    ga_with(vec![], vec![])
}

fn ga_up_false_uv_true() -> Vec<u8> {
    ga_with(
        vec![
            (Value::T("up".into()), Value::Bool(false)),
            (Value::T("uv".into()), Value::Bool(true)),
        ],
        vec![],
    )
}

fn ga_up_false_hmac_secret() -> Vec<u8> {
    // hmac-secret with a silent assertion. The input map is in the shape both
    // parsers accept (v1 lengths: saltEnc 32, saltAuth 16; a well-formed COSE
    // key). The salt contents are never checked on this path — the
    // `up:false` + hmac-secret check runs before any crypto, on both twins —
    // but a malformed map would be rejected earlier, with a status that has
    // nothing to do with this story.
    ga_with(
        vec![(Value::T("up".into()), Value::Bool(false))],
        vec![(
            Value::T("hmac-secret".into()),
            Value::M(vec![
                (
                    Value::U(0x01),
                    Value::M(vec![
                        (Value::U(0x01), Value::U(2)),    // kty: EC2
                        (Value::U(0x03), Value::N(-25)),  // alg: ECDH-ES+HKDF-256
                        (Value::N(-1), Value::U(1)),      // crv: P-256
                        (Value::N(-2), Value::B(vec![0x11; 32])),
                        (Value::N(-3), Value::B(vec![0x22; 32])),
                    ]),
                ),
                (Value::U(0x02), Value::B(vec![0x33; 32])), // saltEnc, v1 length
                (Value::U(0x03), Value::B(vec![0x44; 16])), // saltAuth, v1 length
                (Value::U(0x04), Value::U(1)),             // pinUvAuthProtocol 1
            ]),
        )],
    )
}

// ---------------------------------------------------------------------------
// Name lookup
// ---------------------------------------------------------------------------

/// The variant's own name, so a failure can say *which* row is wrong without
/// the test file having to trust the ordering of `ALL_VARIANTS`.
fn variant_name(v: Ctap2Response) -> &'static str {
    match v {
        Ctap2Response::Ok => "Ok",
        Ctap2Response::InvalidCommand => "InvalidCommand",
        Ctap2Response::InvalidParameter => "InvalidParameter",
        Ctap2Response::InvalidLength => "InvalidLength",
        Ctap2Response::InvalidSeq => "InvalidSeq",
        Ctap2Response::Timeout => "Timeout",
        Ctap2Response::ChannelBusy => "ChannelBusy",
        Ctap2Response::LockRequired => "LockRequired",
        Ctap2Response::InvalidChannel => "InvalidChannel",
        Ctap2Response::CborUnexpectedType => "CborUnexpectedType",
        Ctap2Response::InvalidCbor => "InvalidCbor",
        Ctap2Response::MissingParameter => "MissingParameter",
        Ctap2Response::LimitExceeded => "LimitExceeded",
        Ctap2Response::CredentialExcluded => "CredentialExcluded",
        Ctap2Response::Processing => "Processing",
        Ctap2Response::InvalidCredential => "InvalidCredential",
        Ctap2Response::UserActionPending => "UserActionPending",
        Ctap2Response::OperationPending => "OperationPending",
        Ctap2Response::NoOperations => "NoOperations",
        Ctap2Response::UnsupportedAlgorithm => "UnsupportedAlgorithm",
        Ctap2Response::OperationDenied => "OperationDenied",
        Ctap2Response::KeyStoreFull => "KeyStoreFull",
        Ctap2Response::UnsupportedOption => "UnsupportedOption",
        Ctap2Response::InvalidOption => "InvalidOption",
        Ctap2Response::KeepAliveCancel => "KeepAliveCancel",
        Ctap2Response::NoCredentials => "NoCredentials",
        Ctap2Response::UserActionTimeout => "UserActionTimeout",
        Ctap2Response::NotAllowed => "NotAllowed",
        Ctap2Response::PinInvalid => "PinInvalid",
        Ctap2Response::PinBlocked => "PinBlocked",
        Ctap2Response::PinAuthInvalid => "PinAuthInvalid",
        Ctap2Response::PinAuthBlocked => "PinAuthBlocked",
        Ctap2Response::PinNotSet => "PinNotSet",
        Ctap2Response::PuatRequired => "PuatRequired",
        Ctap2Response::PinPolicyViolation => "PinPolicyViolation",
        Ctap2Response::PinTokenExpired => "PinTokenExpired",
        Ctap2Response::RequestTooLarge => "RequestTooLarge",
        Ctap2Response::ActionTimeout => "ActionTimeout",
        Ctap2Response::UpRequired => "UpRequired",
        Ctap2Response::UvBlocked => "UvBlocked",
        Ctap2Response::IntegrityFailure => "IntegrityFailure",
        Ctap2Response::InvalidSubcommand => "InvalidSubcommand",
        Ctap2Response::UvInvalid => "UvInvalid",
        Ctap2Response::UnauthorizedPermission => "UnauthorizedPermission",
        Ctap2Response::Other => "Other",
    }
}
