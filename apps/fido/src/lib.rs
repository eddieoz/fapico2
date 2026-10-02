//! fapico2-fido — CTAP2.1 authenticator app.
//!
//! EPIC `RUST-MIGRATION` — Phase 1 (FIDO2 over CTAP2.1).
//!
//! Feature model (US-386):
//! * `host` (default) — the full CTAP2.1 + U2F + attestation + PIN stack
//!   (std; drives the emulation binary and the pytest suites).
//! * `device` — a minimal no_std [`FidoApp`] shell (TRNG-derived P-256 hkey +
//!   real `getInfo`) for the RP2350 serve loop. The heavy std stack is
//!   excluded so the device build stays no_std and heapless.
//!
//! Build-time configuration (US-101, EPIC `PICOForge-COMPAT`):
//! * `FAPICO2_AAGUID_HEX` — 32 hex characters (16 bytes, no separators, no
//!   `0x` prefix) overriding the authenticator AAGUID, together with
//!   `FAPICO2_IDENTITY_OVERRIDE_ACK=1` (US-1517): an identity override now
//!   needs two deliberate variables, and setting it alone is a build failure.
//!   **Unset** ⇒ [`DEFAULT_AAGUID`] (fapico2's own identity — *not* the RS-Key
//!   value this paragraph used to name; the borrow is over, `identity.rs` has
//!   the history). Anything else — a malformed value, the variable set but
//!   *empty*, or a missing acknowledgement — is a hard build error, never a
//!   silent fallback. See [`AAGUID`], [`AAGUID_OVERRIDE_ACTIVE`] and
//!   `fapico2_platform::identity` — the override is resolved by *that*
//!   crate's build script; there is no `apps/fido/build.rs`.

#![cfg_attr(not(feature = "host"), no_std)]

#[cfg(feature = "host")]
pub mod app;
// US-916: the per-device attestation identity is provisioned (TRNG key +
// on-device self-signed cert) into the secure store at `FidoApp::boot` and
// served to both the host and device registration paths — no repo-committed
// key/cert pair ships in the image any more.
pub mod attestation;
// US-916: the minimal on-device X.509 builder the provisioning uses
// (no_std, fixed buffers — compiles for the thumbv8m build too).
mod attestation_cert;
// S-701-1: the CBOR codec, crypto wrappers and CTAP2 types are shared —
// the same no-heap modules compile on host and device.
pub mod cbor;
pub mod crypto;
pub mod ctap2;
// US-911: AEAD sealing of sensitive keystore-snapshot fields (no_std,
// shared by the host `keystore` codec and the no-heap `device_keystore`).
pub mod snapshot_crypt;
// US-714 (POLISH-PUB): stateless U2F key handles (C parity) — no_std, shared
// by the host twin (`u2f.rs`) and the device command path (`device_core.rs`).
pub mod stateless;
// S-701-3: the no-heap device credential keystore (always compiled — the
// host interchange tests drive it directly).
pub mod device_keystore;
// S-701-4: the no-heap core CTAP2 command path (MC/GA/clientPin/Reset).
pub mod device_core;
#[cfg(feature = "host")]
pub mod hid;
#[cfg(feature = "host")]
pub mod keystore;
#[cfg(feature = "host")]
pub mod pin;
#[cfg(feature = "host")]
pub mod u2f;
// S-701-5: the vendor vault protocol core (no_std-capable).
pub mod vault;
// US-106: the RS-Key `0x41` vendor channel (PicoForge framing C) and its clean
// NOT_ALLOWED stub set. no_std and shared by the host and device command paths
// — the two `FidoApp` types have separate dispatch `match`es, so this module
// (not either arm) is the single place the sub-command set is defined.
pub mod vendor41;
// US-176: the durable state the twelve `vendor41::PENDING` arms need, and the
// two `vendor41::VendorOps` implementations over the host and device
// keystores. A sibling rather than a part of `vendor41` because `vendor41` is
// the protocol and must stay keystore-free — see the module docs on why the
// commit lives with the dispatch arm that owns the snapshot.
pub mod vendor_state;

// US-170: `STATE` (0x05) and the soft lock, plus the two `authenticatorConfig`
// vendor-prototype arms (engage / release) that are not `0x41` sub-commands.
// A sibling module rather than part of `vendor41` for the reason the channel is
// its own module: `vendor41` is the protocol, and an arm that wanted durable
// state would be reaching across that boundary.
pub mod vendor_lock;
// US-171 (MSE 0x01) and US-172 (`EXPORT` 0x02 / `LOAD` 0x03 / `FINALIZE` 0x04):
// the ephemeral-ECDH backup channel and the seed it carries.
pub mod vendor_backup;
// US-173 (`AUDIT_READ` 0x07) and US-174 (`AUDIT_CHECKPOINT` 0x08 /
// `AUDIT_CONFIG` 0x0E): the tamper-evident journal.
pub mod vendor_audit;
// US-175: `ATT_STATE` (0x0B) / `ATT_CLEAR` (0x0A) / `ATT_IMPORT` (0x09) --
// the organisation attestation credential, layered on the per-device one.
pub mod vendor_att;
// US-113: the pico-fido legacy `vendorPrototype` (`0xFF`) physical-config
// framing (PicoForge framing B). no_std and shared by the host and device
// command paths, for the same reason as `vendor41`: the id set and the
// value-decoding rules are defined once, and each path's own `match` only
// decides which of them it answers.
pub mod vendorff;

// Re-export U2F processing for use by the app.
#[cfg(feature = "host")]
pub use u2f::process_u2f_apdu;

// Device shell (no_std, TRNG-backed). Gated on the `device` feature only so
// it is host-testable (the serve loop's command contract is verified without
// hardware); on the RP2350 build the same code runs against `Rp2350Trng`.
// device_app compiles on host too (default features) so the device command
// path is host-testable (S-701-4: no cfg forks in the command path).
pub mod device_app;
pub use device_app::FidoApp;

/// US-921 review (P0-1): the domain-separated HID presence tag derivation —
/// re-exported so the app and the firmware bin (tasks.rs/emul_main.rs) share
/// ONE helper (the firmware bin already depends on this crate: no dependency
/// cycle).
pub use device_app::presence_tag_from_channel;

/// CTAPHID_MAX_MSG: the largest CTAP message the device serves (S-701-1).
/// The response ABI (`FidoApp::process_ctap2` and friends) and the firmware's
/// HID serve-loop buffers are sized to this.
pub const CTAP2_MAX_MSG: usize = 7609;

/// The AAGUID fapico2 claims when the build sets no override (US-101,
/// EPIC `PICOForge-COMPAT`).
///
// The device identity block — AAGUID, USB manufacturer, USB product, USB
// VID:PID — lives in `fapico2-platform`, because `platform` is the only crate
// every participant depends on: the USB descriptor is built there, and the
// CTAP2 layer is here. A device whose descriptor and whose getInfo disagreed
// on a name would be a worse bug than either being hardcoded.
//
// These re-exports keep the US-101 public surface — every name below resolved
// through *this* crate's build script — so nothing downstream has to move. The
// resolution itself, the build-time overrides, and the "unset means default,
// set-but-empty is an error" rule are documented once, on
// `fapico2_platform::identity`.
pub use fapico2_platform::identity::{
    aaguid_from_hex, select_aaguid, AAGUID, AAGUID_OVERRIDE_HEX, DEFAULT_AAGUID, HOST_BUILD_TARGET,
};

/// Whether this build was configured with an explicit AAGUID override (US-101).
///
/// The counterpart to [`AAGUID_OVERRIDE_HEX`], in the form tests actually
/// branch on. An override build is the *expected* way to develop against a
/// client whose profile table still carries the borrowed RS-Key identity — and
/// the published default is now fapico2's own — so tests that pin the default
/// must consult this rather than failing with a misleading "wrong AAGUID".
pub const AAGUID_OVERRIDE_ACTIVE: bool = !AAGUID_OVERRIDE_HEX.is_empty();

/// Pack a `major.minor.patch` semver string into the CTAP2
/// `firmwareVersion` (getInfo key `0x0E`) integer the desktop client reads.
///
/// # Encoding
///
/// The value is `(major << 8) | minor`; the patch component is **dropped**.
/// CTAP2.1 §5.1.2 leaves the field's interpretation up to the consumer, and
/// ours (PicoForge, `picoforge/src/hal/fido/mod.rs:133-144`) formats the raw
/// integer as `major.minor.patch` when `raw > 0xFFFF` and as `major.minor`
/// otherwise — i.e. it reads the *same* integer differently depending on its
/// magnitude. So the packing must stay at or below `0xFFFF`; anything larger
/// would silently become a three-component version. Concretely,
/// `"1.1.0"` → `0x000101` → rendered `"1.1"`.
///
/// # Shape of the input
///
/// Exactly **three** dot-separated decimal components are required, because
/// that is the only form Cargo can produce for `CARGO_PKG_VERSION` (a manifest
/// version is always `MAJOR.MINOR.PATCH`). Anything else — a two-component
/// `"1.1"`, a pre-release/build suffix, an empty or non-numeric component —
/// is a **const-eval panic**, i.e. a hard compile error, rather than a silent
/// fallback to `0`. `0` is precisely the defect US-102 fixes: it renders
/// `"0.0"` and drives every version-gated branch in the client onto the wrong
/// answer, so quietly degrading here would reintroduce the bug at build time.
///
/// Runs in const context (no allocator, no `std`), like
/// [`aaguid_from_hex`], so the `no_std` device build and the `host` build
/// resolve the identical constant. `pub` and parameterized on a `&str` so an
/// integration test can pin the encoding on literal inputs.
pub const fn pack_firmware_version(ver: &str) -> u32 {
    let b = ver.as_bytes();
    let mut i = 0;

    // major: one or more digits.
    let major = const_decimal(&mut i, b);
    if i >= b.len() || b[i] != b'.' {
        panic!("firmware version must be MAJOR.MINOR.PATCH");
    }
    i += 1;

    // minor: one or more digits.
    let minor = const_decimal(&mut i, b);
    if i >= b.len() || b[i] != b'.' {
        panic!("firmware version must be MAJOR.MINOR.PATCH");
    }
    i += 1;

    // patch: parsed (so a non-numeric component is rejected loudly) but
    // deliberately discarded — see the encoding note above.
    let _patch = const_decimal(&mut i, b);
    if i != b.len() {
        panic!("firmware version must have exactly three components");
    }

    // Each component is capped at 8 bits; a wider one would silently alias
    // into its neighbour under the shift, so reject it instead.
    if major > 0xFF || minor > 0xFF {
        panic!("firmware version major/minor must each be <= 255");
    }
    (major << 8) | minor
}

/// Consume one or more ASCII decimal digits starting at `*i`, returning their
/// value (saturating at `u32::MAX` would hide overflow, so out-of-range input
/// is caught by the caller's `> 0xFF` check). Const-eval panics on a
/// non-digit or on an empty component.
const fn const_decimal(i: &mut usize, b: &[u8]) -> u32 {
    if *i >= b.len() || !b[*i].is_ascii_digit() {
        panic!("firmware version component is missing or not a decimal number");
    }
    let mut v: u32 = 0;
    while *i < b.len() && b[*i].is_ascii_digit() {
        v = v * 10 + (b[*i] - b'0') as u32;
        *i += 1;
    }
    v
}

/// The firmware version this build reports in getInfo key `0x0E`: the
/// workspace's own `CARGO_PKG_VERSION`, packed per [`pack_firmware_version`].
///
/// Sourced from the crate version rather than hand-written so a release
/// cannot ship a stale number, and resolved at compile time so it costs
/// nothing at runtime on the device. The workspace version is currently
/// `0.1.0`, which packs to `0x000001` and renders as `"0.1"` — a real,
/// non-zero version; bumping `[workspace.package] version` is a separate,
/// workspace-wide decision and will change this constant with no code edit.
pub const FIRMWARE_VERSION: u32 = pack_firmware_version(env!("CARGO_PKG_VERSION"));

/// CTAP2 versions advertised in getInfo.
pub const CTAP2_VERSIONS: &[&str] = &["FIDO_2_0", "FIDO_2_1", "FIDO_2_3"];
pub const CTAP1_VERSION: &str = "U2F_V2";

/// Default max credential blob length (bytes).
pub const DEFAULT_MAX_CRED_BLOB_LENGTH: usize = 32;

/// Default max large blob size (bytes).
pub const DEFAULT_MAX_LARGE_BLOB: usize = 1024 - 64;

/// Default max number of credentials in list.
pub const DEFAULT_MAX_CREDS_IN_LIST: usize = 19;

/// Default max RP IDs for setMinPINLength.
pub const DEFAULT_MAX_RPIDS_MINPIN_LENGTH: usize = 120;

// --------------------------------------------------------------------------
// COSE algorithm identifiers (US-120, EPIC `PICOForge-COMPAT`).
//
// THE rationale for this story, stated once. The COSE `alg` label (3) of an
// EC2 key-agreement map is **deliberately not validated** by either FidoApp
// twin, because the two COSE keys PicoForge sends disagree with each other on
// both axes and the authenticator must take both:
//
//   * `alg`: CTAP 2.1 mandates ECDH-ES+HKDF-256 (-25). PicoForge's clientPin
//     key-agreement map carries ES256 (-7) — `encode_cose_key` in
//     `picoforge/src/hal/fido/ops.rs` — while its RS-Key MSE key correctly
//     carries -25.
//   * label order: the RS-Key MSE key in `picoforge/src/hal/fido/mod.rs` is
//     built in a `BTreeMap` keyed by the integer label, so it serialises as
//     -3, -2, -1, 1, 3 rather than ascending. `encode_cose_key` above
//     hand-writes the ascending order.
//
// Only -2/-3 (the coordinates) are load-bearing, and only the parsers
// `pin::parse_cose_key_map` and `device_core::parse_key_agreement` read them.
// Adding an `alg` check would break interop with PicoForge — the exact
// opposite of this story's intent. These constants exist to stop the values
// being bare magic numbers at their use sites; they are documentation, not a
// validation gate.
// --------------------------------------------------------------------------

/// COSE `alg` -25 — ECDH-ES+HKDF-256. The CTAP 2.1 key-agreement value, and
/// what PicoForge's RS-Key MSE key sends.
pub const COSE_ALG_ECDH_ES_HKDF_256: i32 = -25;

/// COSE `alg` -7 — ES256. What PicoForge's clientPin key-agreement map sends;
/// accepted alongside [`COSE_ALG_ECDH_ES_HKDF_256`].
pub const COSE_ALG_ES256: i32 = -7;

/// Error type for FIDO operations.
#[derive(Debug, Clone, PartialEq)]
pub enum FidoError {
    /// Cbor encoding/decoding error.
    Cbor,
    /// Invalid CBOR (bad key ordering, unknown key type).
    InvalidCbor,
    /// CBOR field had an unexpected type.
    CborUnexpectedType,
    /// Invalid length.
    InvalidLength,
    /// Invalid parameter.
    InvalidParameter,
    /// Missing parameter.
    MissingParameter,
    /// PIN not set.
    PinNotSet,
    /// PIN invalid.
    PinInvalid,
    /// PIN auth invalid.
    PinAuthInvalid,
    /// PIN blocked.
    PinBlocked,
    /// PIN auth blocked.
    PinAuthBlocked,
    /// PIN policy violation.
    PinPolicyViolation,
    /// No credentials.
    NoCredentials,
    /// Credential excluded.
    CredentialExcluded,
    /// Unsupported algorithm.
    UnsupportedAlgorithm,
    /// Unsupported option.
    UnsupportedOption,
    /// Operation denied.
    OperationDenied,
    /// Not allowed.
    NotAllowed,
    /// Key store full.
    KeyStoreFull,
    /// Limit exceeded.
    LimitExceeded,
    /// Integrity failure.
    IntegrityFailure,
    /// Invalid command.
    InvalidCommand,
    /// Invalid channel.
    InvalidChannel,
    /// Channel busy.
    ChannelBusy,
    /// Timeout.
    Timeout,
    /// Invalid sequence.
    InvalidSeq,
    /// User presence required.
    UserPresenceRequired,
    /// User verification required.
    UserVerificationRequired,
    /// Internal error.
    Internal,
}

/// Result type for FIDO operations.
pub type Result<T> = core::result::Result<T, FidoError>;

impl FidoError {
    /// Convert to CTAP2 error code.
    pub fn to_ctap_error(&self) -> u8 {
        match self {
            FidoError::Cbor => 0x12,                   // INVALID_CBOR
            FidoError::InvalidCbor => 0x12,            // INVALID_CBOR
            FidoError::CborUnexpectedType => 0x11,     // CBOR_UNEXPECTED_TYPE
            FidoError::InvalidLength => 0x03,
            FidoError::InvalidParameter => 0x02,
            FidoError::MissingParameter => 0x14,       // MISSING_PARAMETER
            FidoError::PinNotSet => 0x35,              // PIN_NOT_SET
            FidoError::PinInvalid => 0x31,             // PIN_INVALID
            FidoError::PinAuthInvalid => 0x33,         // PIN_AUTH_INVALID
            FidoError::PinBlocked => 0x32,             // PIN_BLOCKED
            FidoError::PinAuthBlocked => 0x34,         // PIN_AUTH_BLOCKED
            FidoError::PinPolicyViolation => 0x37,     // PIN_POLICY_VIOLATION
            FidoError::NoCredentials => 0x2E,          // NO_CREDENTIALS
            FidoError::CredentialExcluded => 0x19,     // CREDENTIAL_EXCLUDED
            FidoError::UnsupportedAlgorithm => 0x26,
            FidoError::UnsupportedOption => 0x2B,
            FidoError::OperationDenied => 0x27,
            FidoError::NotAllowed => 0x30,             // NOT_ALLOWED
            FidoError::KeyStoreFull => 0x28,
            FidoError::LimitExceeded => 0x15,          // LIMIT_EXCEEDED
            FidoError::IntegrityFailure => 0x3D,       // INTEGRITY_FAILURE
            FidoError::InvalidCommand => 0x01,
            FidoError::InvalidChannel => 0x08,
            FidoError::ChannelBusy => 0x06,
            FidoError::Timeout => 0x05,
            FidoError::InvalidSeq => 0x04,
            FidoError::UserPresenceRequired => 0x3B,   // UP_REQUIRED
            FidoError::UserVerificationRequired => 0x3C, // UV_BLOCKED
            FidoError::Internal => 0x01,
        }
    }
}
