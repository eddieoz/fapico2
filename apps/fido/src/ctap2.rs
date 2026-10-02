//! CTAP2 protocol types (S-701-1: no-heap, compiled for host **and** device).
//!
//! `Ctap2Info` is serialized straight into a caller-owned fixed buffer via
//! [`crate::cbor::no_heap`] — no `alloc` in the device path. The host stack
//! additionally gets a `to_cbor()` (alloc `Value`) wrapper so `app.rs` keeps
//! its existing `cbor::encode` flow.

use crate::cbor::no_heap::{self, CborError};
use heapless::Vec as HeaplessVec;

/// `authenticatorConfig` sub-command `0xFF` (`vendorPrototype`) — credential
/// expiration. Params: `{0x02: <4-byte timestamp>}`.
///
/// Lives in this module so the id has exactly one spelling in the crate: the
/// handler (`crate::app::FidoApp::cfg_vendor_prototype`) and the key-`0x15`
/// list in [`Ctap2Info::default`] that tells the host it exists cannot drift
/// apart.
pub const CONFIG_CREDENTIAL_EXPIRE: u64 = 0x0004E532E1FEB2FD;
/// `vendorPrototype` sub-command `0xFF` — credential revocation. Params for
/// slot-based: `{0x03: <slot_index>}`; id-based: `{0x02: <credential_id>}`.
/// See [`CONFIG_CREDENTIAL_EXPIRE`] for why this lives in `ctap2`.
pub const CONFIG_CREDENTIAL_REVOKE: u64 = 0x0005961ECBA040F9;

/// CTAP2 command codes.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Ctap2Command {
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    GetNextAssertion = 0x08,
    GetInfo = 0x04,
    ClientPin = 0x06,
    Reset = 0x07,
    CredMgmt = 0x0A,
    Selection = 0x0B,
    LargeBlobs = 0x0C,
    Config = 0x0D,
}

/// CTAP2 status codes (the *response* table — see [`Ctap2Command`] for the
/// separate, deliberately-non-spec command table).
///
/// US-1528. Every byte below is a **wire value** a client decodes, so this enum
/// is transcribed, not designed. The two authorities, which agree with each
/// other, are:
///
///   * `fido2` 2.2.1, `fido2/ctap.py` `CtapError.ERR` — what `ykman`, Yubico
///     Authenticator and every first-party tool actually decode. Executed, not
///     grepped: the enum is read at runtime in the test that pins this table.
///   * the C reference, `pico-fido2/src/fido/ctap.h` `CTAP2_ERR_*`.
///
/// Where they differ the **library wins**, because it is the decoder. That is
/// the whole reason `PinTokenExpired` is `0x38` here and absent from
/// `ctap.h`: `CtapError.ERR` defines it, so a client reading our `0x38` gets
/// `PIN_TOKEN_EXPIRED` and a client reading the C firmware's silence gets
/// nothing to read.
///
/// The previous table was off by one across `0x2B`..`0x2D` and wrong again at
/// `0x07`/`0x08`, which meant **every** `InvalidOption` this firmware returned
/// was read by every client as `UNSUPPORTED_OPTION` — a different sentence
/// ("you named a value we do not support" vs "you named a value that is
/// malformed for a parameter we do support"). `tests/status_table.rs` pins
/// every value below against the executed library so this cannot drift again;
/// do not "tidy" a value here without running that test.
///
/// ## `NoOperationPending` was removed, deliberately
///
/// US-1528 listed it as one of the four non-reference codes to resolve. It is
/// gone rather than aligned or re-valued, for three reasons that all point the
/// same way:
///
///   1. The spec **withdrew** the code. `fido2` keeps it as a comment —
///      `# NO_OPERATION_PENDING = 0x2A  # No longer in spec` — so no client
///      can decode it whatever byte it carries.
///   2. Even the withdrawn code was `0x2A`, not the `0x29` we had. `0x29` was
///      `NOT_BUSY`, a *different* withdrawn code. The variant was wrong at
///      both the semantic and the numeric level, which is the signature of a
///      name copied down a column without the value ever being checked.
///   3. It had **zero producers and zero assertions** anywhere in the tree
///      (`grep -rn NoOperationPending` returns this paragraph and nothing
///      else), so removing it breaks no caller.
///
/// Keeping a wrong-valued, unreachable variant in the one table whose entire
/// job is to be transcribed correctly is a drift vector, not documentation.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Ctap2Response {
    Ok = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    /// `CTAP2_ERR_LOCK_REQUIRED`.
    ///
    /// Was `0x07`, which is wrong twice over: the reference value is `0x0A`
    /// (`CtapError.ERR.LOCK_REQUIRED`; the C SDK agrees at
    /// `pico-fido2/pico-keys-sdk/src/usb/hid/ctap_hid.h:157`,
    /// `CTAP1_ERR_LOCK_REQUIRED 0x0a`), and `0x07` collided with
    /// [`Ctap2Command::Reset`] — a status byte and a command opcode that are
    /// never on the same layer but must never share a value, because a reader
    /// that has lost track of which table it is in then has no way to tell.
    LockRequired = 0x0A,
    /// `CTAP2_ERR_INVALID_CHANNEL`. Was `0x08`; the reference value is `0x0B`
    /// (`CtapError.ERR.INVALID_CHANNEL`; `ctap_hid.h:158`,
    /// `CTAP1_ERR_INVALID_CHANNEL 0x0b`).
    InvalidChannel = 0x0B,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    CredentialExcluded = 0x19,
    Processing = 0x21,
    InvalidCredential = 0x22,
    UserActionPending = 0x23,
    OperationPending = 0x24,
    NoOperations = 0x25,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    KeyStoreFull = 0x28,
    /// `CTAP2_ERR_UNSUPPORTED_OPTION` — the request named an option this
    /// authenticator does not advertise.
    ///
    /// Was `0x2A`, which is not a live code at all. The reference skips
    /// straight from `KEY_STORE_FULL` (`0x28`) to `UNSUPPORTED_OPTION`
    /// (`0x2B`); `fido2` keeps the commented-out
    /// `# NOT_BUSY = 0x29  # No longer in spec` and
    /// `# NO_OPERATION_PENDING = 0x2A  # No longer in spec` as the reason the
    /// gap exists, so `0x2A` is a **withdrawn** code. Emitting it put a value
    /// on the wire that no client can name.
    UnsupportedOption = 0x2B,
    /// `CTAP2_ERR_INVALID_OPTION` — the option is advertised, but the value
    /// carried is not one it accepts.
    ///
    /// Was `0x2B`, which every client decodes as `UNSUPPORTED_OPTION`. This is
    /// the bug US-1528 was filed for: a conformance-visible difference in what
    /// the firmware says, at roughly ten producer sites, and the `up: false`
    /// rejection US-1526 deliberately decided and pinned is one of them.
    InvalidOption = 0x2C,
    /// `CTAP2_ERR_KEEPALIVE_CANCEL` — user cancelled a keepalive.
    ///
    /// Was `0x2C`. `firmware/src/ctap_hid.rs` (a separate worktree) is the
    /// first thing in this project to *produce* a keepalive-cancel answer and
    /// emits `0x2D` on the strength of the same two sources. Aligning here is
    /// what makes the two halves agree by value; do not "fix" one from the
    /// other, re-derive both from the table above.
    KeepAliveCancel = 0x2D,
    NoCredentials = 0x2E,
    UserActionTimeout = 0x2F,
    NotAllowed = 0x30,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinAuthBlocked = 0x34,
    PinNotSet = 0x35,
    PuatRequired = 0x36,
    PinPolicyViolation = 0x37,
    /// `CTAP2_ERR_PIN_TOKEN_EXPIRED`.
    ///
    /// **Not in the C reference** — `ctap.h` runs `PIN_POLICY_VIOLATION`
    /// (`0x37`) straight to `REQUEST_TOO_LARGE` (`0x39`) — but **in the client
    /// library**, which is the authority that matters: `CtapError.ERR` defines
    /// `PIN_TOKEN_EXPIRED = 0x38`. So this value is *correct* and the C
    /// firmware's silence is the omission, not this. Verified by executing the
    /// enum rather than grepping the literal, and re-verified on every run of
    /// `tests/status_table.rs`.
    ///
    /// Fate, per US-1528's "align or write down": **kept as-is.** Aligning it
    /// to a C-header-only reading would mean emitting a byte every client
    /// decodes as `REQUEST_TOO_LARGE`.
    PinTokenExpired = 0x38,
    RequestTooLarge = 0x39,
    ActionTimeout = 0x3A,
    UpRequired = 0x3B,
    UvBlocked = 0x3C,
    IntegrityFailure = 0x3D,
    InvalidSubcommand = 0x3E,
    UvInvalid = 0x3F,
    UnauthorizedPermission = 0x40,
    /// CTAP 2.1's catch-all: a failure the enumerator does not name.
    /// Added by the US-1007 defect fix so a request that could not obtain
    /// fresh entropy has an honest status. It refused to be folded into
    /// `OperationDenied`, which reads as a *policy* refusal ("not allowed")
    /// rather than a resource failure, or `IntegrityFailure`, which claims
    /// something was tampered with. Neither is true, and a client that
    /// retries on `Other` but gives up on `OperationDenied` is the
    /// behaviour we actually want from a starved keygen.
    Other = 0x7F,
}

impl Ctap2Response {
    pub fn code(self) -> u8 {
        self as u8
    }
}

/// CTAP2 info response (S-701-1: every field is a fixed-size heapless
/// structure — the same struct compiles on host and device).
#[derive(Debug, Clone, PartialEq)]
pub struct Ctap2Info {
    pub versions: HeaplessVec<&'static str, 8>,
    pub extensions: HeaplessVec<&'static str, 16>,
    pub aaguid: [u8; 16],
    pub options: HeaplessVec<(&'static str, bool), 16>,
    pub max_msg_size: usize,
    pub pin_protocols: HeaplessVec<u8, 4>,
    pub max_creds_in_list: Option<usize>,
    pub max_cred_id_len: Option<usize>,
    pub transports: HeaplessVec<&'static str, 4>,
    /// Supported COSE algorithm identifiers (serialized as
    /// `{ "type": "public-key", "alg": <id> }` map entries).
    pub algorithms: HeaplessVec<i32, 4>,
    pub max_large_blob: Option<usize>,
    /// getInfo key `0x0E` (CTAP2.1 §5.1.2 firmwareVersion), packed as
    /// `(major << 8) | minor` from the crate version — see
    /// [`crate::pack_firmware_version`].
    ///
    /// CTAP2.1 specifies the field as an integer with **no** interpretation
    /// of its own; the consumer supplies one. Ours (PicoForge,
    /// `picoforge/src/hal/fido/mod.rs:133-144`) formats the raw value as
    /// `major.minor.patch` when `raw > 0xFFFF` and as `major.minor`
    /// otherwise. That is why the field is `u32` rather than the `u8` it used
    /// to be, and why the patch component is dropped: a value above `0xFFFF`
    /// would be re-read as a three-component version (`0x000101` renders as
    /// `"1.0.1"`, not `"1.1"`), and a value of `0` renders as `"0.0"` and
    /// mis-gates every version-dependent path in the client. The default is
    /// [`crate::FIRMWARE_VERSION`], never `0`.
    pub firmware_version: u32,
    pub max_cred_blob_length: u16,
    pub max_rpids_min_pin: u16,
    pub min_pin_length: u8,
    pub max_pin_length: u8,
    pub force_pin_change: bool,
    pub pin_complexity_policy: Option<bool>,
    pub authenticator_config_commands: HeaplessVec<u8, 8>,
    /// Vendor prototype config commands (key 0x15): the 64-bit ids this
    /// firmware answers for `authenticatorConfig` sub-command `0xFF`
    /// (`vendorPrototype`) — the four [`crate::vendorff::SUPPORTED_IDS`]
    /// physical-config ids plus the two credential-metadata ids declared
    /// above.
    ///
    /// It is *not* a list of `authenticatorConfig` sub-command bytes (that
    /// is key `0x1F`) and it is *not* the RS-Key `0x41` id space (those are
    /// one byte, disjoint by construction — see `crate::vendorff`).
    pub vendor_prototype_config_commands: HeaplessVec<u64, 8>,
    /// Encrypted credential store state (key 0x1E): 16-byte random IV
    /// prepended to a 16-byte ciphertext block.
    pub enc_cred_store_state: HeaplessVec<u8, 64>,
    /// Encrypted device identifier (key 0x19): same layout as enc_cred_store_state.
    pub enc_identifier: HeaplessVec<u8, 64>,
}

impl Ctap2Info {
    /// Set (or replace) one advertised option.
    pub fn set_option(&mut self, key: &'static str, value: bool) {
        if let Some(slot) = self.options.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.options.push((key, value)).ok();
        }
    }

    /// Look up one advertised option.
    pub fn option(&self, key: &str) -> Option<bool> {
        self.options
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| *v)
    }

    /// Write the CTAP2 getInfo CBOR map into a caller-owned fixed buffer
    /// (S-701-1: the device path — no `alloc`).
    ///
    /// Key assignments follow the FIDO2 spec and python-fido2 `Info` field
    /// indices (CBOR key = field_index + 1):
    /// 0x01 versions, 0x02 extensions, 0x03 aaguid, 0x04 options,
    /// 0x05 maxMsgSize, 0x06 pinUvAuthProtocols, 0x07 maxCredsInList,
    /// 0x08 maxCredIdLen, 0x09 transports, 0x0A algorithms, 0x0B maxLargeBlob,
    /// 0x0D minPINLength, 0x0E firmwareVersion, 0x0F maxCredBlobLength,
    /// 0x10 maxRPIDs, 0x15 vendorPrototypeConfigCommands, 0x19 encIdentifier,
    /// 0x1D maxPINLength, 0x1E encCredStoreState, 0x1F authenticatorConfigCommands.
    ///
    /// Note the map is written in ascending-key order, which is also the
    /// canonical CBOR order for these single-byte keys.
    pub fn write_cbor_into<const N: usize>(
        &self,
        out: &mut HeaplessVec<u8, N>,
    ) -> Result<(), CborError> {
        let mut pairs = 20usize;
        if self.max_large_blob.is_some() {
            pairs += 1;
        }
        if self.pin_complexity_policy.is_some() {
            pairs += 1;
        }
        no_heap::push_map_header(out, pairs)?;
        no_heap::push_uint(out, 0x01)?;
        no_heap::push_array_header(out, self.versions.len())?;
        for v in &self.versions {
            no_heap::push_tstr(out, v)?;
        }
        no_heap::push_uint(out, 0x02)?;
        no_heap::push_array_header(out, self.extensions.len())?;
        for e in &self.extensions {
            no_heap::push_tstr(out, e)?;
        }
        no_heap::push_uint(out, 0x03)?;
        no_heap::push_bstr(out, &self.aaguid)?;
        no_heap::push_uint(out, 0x04)?;
        no_heap::push_map_header(out, self.options.len())?;
        let mut opts: HeaplessVec<(&'static str, bool), 16> = self.options.clone();
        // Canonical order = encoded key bytes: the tstr header byte carries
        // the length (0x60|len), so shorter keys sort before longer ones.
        opts.sort_unstable_by(|a, b| {
            let ka = 0x60u16 + a.0.len() as u16;
            let kb = 0x60u16 + b.0.len() as u16;
            ka.cmp(&kb).then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
        });
        for (k, v) in &opts {
            no_heap::push_tstr(out, k)?;
            no_heap::push_bool(out, *v)?;
        }
        no_heap::push_uint(out, 0x05)?;
        no_heap::push_uint(out, self.max_msg_size as u64)?;
        no_heap::push_uint(out, 0x06)?;
        no_heap::push_array_header(out, self.pin_protocols.len())?;
        for p in &self.pin_protocols {
            no_heap::push_uint(out, *p as u64)?;
        }
        no_heap::push_uint(out, 0x07)?;
        no_heap::push_uint(out, self.max_creds_in_list.unwrap_or(0) as u64)?;
        no_heap::push_uint(out, 0x08)?;
        no_heap::push_uint(out, self.max_cred_id_len.unwrap_or(0) as u64)?;
        no_heap::push_uint(out, 0x09)?;
        no_heap::push_array_header(out, self.transports.len())?;
        for t in &self.transports {
            no_heap::push_tstr(out, t)?;
        }
        no_heap::push_uint(out, 0x0A)?;
        no_heap::push_array_header(out, self.algorithms.len())?;
        for alg in &self.algorithms {
            no_heap::push_map_header(out, 2)?;
            no_heap::push_tstr(out, "alg")?;
            no_heap::push_neg(out, *alg as i64)?;
            no_heap::push_tstr(out, "type")?;
            no_heap::push_tstr(out, "public-key")?;
        }
        if let Some(mlb) = self.max_large_blob {
            no_heap::push_uint(out, 0x0B)?;
            no_heap::push_uint(out, mlb as u64)?;
        }
        // forcePinChange (key 0x0C)
        no_heap::push_uint(out, 0x0C)?;
        no_heap::push_bool(out, self.force_pin_change)?;
        no_heap::push_uint(out, 0x0D)?;
        no_heap::push_uint(out, self.min_pin_length as u64)?;
        no_heap::push_uint(out, 0x0E)?;
        no_heap::push_uint(out, self.firmware_version as u64)?;
        no_heap::push_uint(out, 0x0F)?;
        no_heap::push_uint(out, self.max_cred_blob_length as u64)?;
        no_heap::push_uint(out, 0x10)?;
        no_heap::push_uint(out, self.max_rpids_min_pin as u64)?;
        no_heap::push_uint(out, 0x15)?;
        no_heap::push_array_header(out, self.vendor_prototype_config_commands.len())?;
        for c in &self.vendor_prototype_config_commands {
            no_heap::push_uint(out, *c)?;
        }
        // Encrypted device identifier (key 0x19) — ascending canonical order
        no_heap::push_uint(out, 0x19)?;
        no_heap::push_bstr(out, &self.enc_identifier)?;
        // pinComplexityPolicy (key 0x1B)
        if let Some(pcp) = self.pin_complexity_policy {
            no_heap::push_uint(out, 0x1B)?;
            no_heap::push_bool(out, pcp)?;
        }
        no_heap::push_uint(out, 0x1D)?;
        no_heap::push_uint(out, self.max_pin_length as u64)?;
        // Encrypted credential store state (key 0x1E)
        no_heap::push_uint(out, 0x1E)?;
        no_heap::push_bstr(out, &self.enc_cred_store_state)?;
        // authenticatorConfigCommands (key 0x1F)
        no_heap::push_uint(out, 0x1F)?;
        no_heap::push_array_header(out, self.authenticator_config_commands.len())?;
        for c in &self.authenticator_config_commands {
            no_heap::push_uint(out, *c as u64)?;
        }
        Ok(())
    }
}

#[cfg(feature = "host")]
impl Ctap2Info {
    /// Encode to a CBOR map suitable for getInfo (host alloc path; the
    /// canonical key set matches [`Ctap2Info::write_cbor_into`], including
    /// its ascending-key order).
    pub fn to_cbor(&self) -> crate::cbor::Value {
        use crate::cbor::Value;
        let tstr = |s: &str| Value::T(s.to_string());
        let mut m: Vec<(Value, Value)> = vec![
            (
                Value::U(0x01),
                Value::A(self.versions.iter().map(|s| tstr(s)).collect()),
            ),
            (
                Value::U(0x02),
                Value::A(self.extensions.iter().map(|s| tstr(s)).collect()),
            ),
            (Value::U(0x03), Value::B(self.aaguid.to_vec())),
            (
                Value::U(0x04),
                Value::M(
                    self.options
                        .iter()
                        .map(|(k, v)| (tstr(k), Value::Bool(*v)))
                        .collect(),
                ),
            ),
            (Value::U(0x05), Value::U(self.max_msg_size as u64)),
            (
                Value::U(0x06),
                Value::A(self.pin_protocols.iter().map(|p| Value::U(*p as u64)).collect()),
            ),
            (
                Value::U(0x07),
                Value::U(self.max_creds_in_list.unwrap_or(0) as u64),
            ),
            (
                Value::U(0x08),
                Value::U(self.max_cred_id_len.unwrap_or(0) as u64),
            ),
            (
                Value::U(0x09),
                Value::A(self.transports.iter().map(|s| tstr(s)).collect()),
            ),
            (
                Value::U(0x0A),
                Value::A(
                    self.algorithms
                        .iter()
                        .map(|alg| {
                            Value::M(vec![
                                (tstr("type"), tstr("public-key")),
                                (tstr("alg"), Value::N(*alg as i64)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ];

        if let Some(mlb) = self.max_large_blob {
            m.push((Value::U(0x0B), Value::U(mlb as u64)));
        }
        m.push((Value::U(0x0C), Value::Bool(self.force_pin_change)));
        m.push((Value::U(0x0D), Value::U(self.min_pin_length as u64)));
        m.push((Value::U(0x0E), Value::U(self.firmware_version as u64)));
        m.push((Value::U(0x0F), Value::U(self.max_cred_blob_length as u64)));
        m.push((Value::U(0x10), Value::U(self.max_rpids_min_pin as u64)));
        m.push((
            Value::U(0x15),
            Value::A(
                self.vendor_prototype_config_commands
                    .iter()
                    .map(|c| Value::U(*c))
                    .collect(),
            ),
        ));
        if let Some(pcp) = self.pin_complexity_policy {
            m.push((Value::U(0x1B), Value::Bool(pcp)));
        }
        m.push((Value::U(0x19), Value::B(self.enc_identifier.as_slice().to_vec())));
        m.push((Value::U(0x1D), Value::U(self.max_pin_length as u64)));
        m.push((
            Value::U(0x1E),
            Value::B(self.enc_cred_store_state.as_slice().to_vec()),
        ));
        m.push((
            Value::U(0x1F),
            Value::A(
                self.authenticator_config_commands
                    .iter()
                    .map(|c| Value::U(*c as u64))
                    .collect(),
            ),
        ));
        Value::M(m)
    }
}

/// US-1512: the rule behind GetInfo's `pinUvAuthToken` option.
///
/// The option is a **capability**, not a configuration flag. CTAP 2.1
/// §5.4.6 asks "can this authenticator return a pinUvAuthToken?", and
/// `clientPin` already answers the separate question "is a PIN configured
/// right now" (`handle_get_info` sets that from `pin_hash.is_some()`).
///
/// The tempting rule — `pin_hash.is_some()`, mirroring `clientPin` — is
/// wrong. Sub-command `0x06` (getPinUvAuthTokenUsingUvWithPermissions)
/// needs no PIN: it asserts a user-presence grant and nothing else,
/// because this build has no user-verification secret to check, and
/// credentialManagement honours the token it returns even with
/// `pin_hash == None` (`device_core.rs:2564`, and `app.rs:2029` in the
/// host twin). A factory-fresh key therefore *does* have the capability,
/// so reporting `false` would withdraw a route that answers.
///
/// The option is also load-bearing off the uv-gated branch. In fido2
/// 2.2.1 `ClientPin.is_token_supported()` (`ctap2/pin.py:262-264`) has
/// three call sites, and only the third is gated on `uv`:
///
///   - `get_uv_token` (`pin.py:347-348`) raises
///     `ValueError("Authenticator does not support get_uv_token")` in the
///     client when the bit is false, so a PIN-less key loses sub-command
///     `0x06` entirely — the resident-credential case this story exists
///     to avoid.
///   - `get_pin_token` (`pin.py:307`) selects
///     `GET_TOKEN_USING_PIN` (permissions honoured) over
///     `GET_TOKEN_USING_PIN_LEGACY` (permissions dropped). Not uv-gated.
///   - `Client._get_token` (`client/__init__.py:683`), the only
///     uv-gated one, inside `if allow_uv and info.options.get("uv")`.
///
/// What the value *must* track is lockout. While a durable lockout flag is
/// latched, every PIN leg refuses: `verify_token` answers `PIN_AUTH_BLOCKED`
/// on `needs_power_cycle` (`device_core.rs:801`), and the token sub-command
/// `0x06` refuses on the same pair (`device_core.rs:1990`, US-1512).
/// Advertising a token route the device will not honour is exactly the
/// incoherence this story is about — a client reads `true`, mints a token,
/// and is then refused at the first command that uses it. So the
/// advertisement tracks the latch, and it is true whenever the route is made
/// rather than merely fail-closed.
///
/// **The latch is a lockout, not a wall: a correct PIN is the key.**
/// Sub-commands `0x05`/`0x09` carry NO up-front `needs_power_cycle` gate —
/// deliberately, and stated at `device_core.rs:1742` for changePIN — and their
/// success path clears `blocked`, `needs_power_cycle` and `new_pin_mismatches`
/// AND mints the token in the same breath (`device_core.rs:1917-1925`).
/// So `false` means "not until you present the correct PIN", never "not
/// ever": one correct PIN both restores the advertisement and returns `0x00`
/// with a usable token. Measured on **both** twins —
/// `tests/pin_uv_advert.rs::a_correct_pin_restores_the_route_it_withdrew`.
///
/// The paragraph this replaces claimed the latch was terminal ("every PIN leg
/// refuses ... a client reads `true`, mints a token, and is then refused at
/// the first command"), which is the inverse of what the code thirteen lines
/// below it does, and which contradicted itself four sentences later. It is
/// the fourth claim in this epic that came out the inverse way because it was
/// read rather than executed; the ledger already carried the correction
/// ("M2's premise was wrong: that is only true for a wrong PIN") and it reached
/// the ledger and not the code. The invariant worth keeping is the narrower
/// one, and it is the one that is actually checkable: **the advertisement and
/// the token route agree, in both directions.** Neither has to be permanent.
///
/// Withdrawing the bit also downgrades `get_pin_token` to the legacy opcode,
/// but both share one match arm (`device_core.rs:1764`) whose outcome the PIN
/// decides, not the opcode, so that costs no behaviour.
///
/// It takes the two durable lockout flags rather than a state struct: the
/// twins keep different ones (`keystore::PinState` and
/// `device_keystore::DevicePinState`), and this signature is what keeps one
/// rule behind both.
pub fn pin_uv_auth_token_available(blocked: bool, needs_power_cycle: bool) -> bool {
    !(blocked || needs_power_cycle)
}

/// US-1513: the budget `getUVRetries` (clientPIN sub-command `0x07`) reports.
///
/// The constant 3 was never arbitrary — it is the `auth_failures` latch
/// threshold that `note_pin_auth_failure` uses in both twins
/// (`device_core.rs:781`, `app.rs:515`). Reporting the *remaining* budget
/// against the same counter makes the value mean something: it falls as a
/// bad-`pinUvAuthParam` streak grows, and recovers when a good one resets
/// the counter.
///
/// It does not, however, fall to 0 in step with the lockout, and a reader
/// must not assume it does. `auth_failures` is volatile — zeroed at boot
/// (`device_app.rs:417`) and on session teardown (`device_app.rs:558`) —
/// while `powerCycleState` derives from the **durable** `needs_power_cycle`.
/// So after a power cycle during a lockout GetInfo reports
/// `uvRetries: 3, powerCycleState: true`: a full budget on a counter that
/// every leg refuses anyway. `powerCycleState` is the authoritative
/// "locked out" signal; `uvRetries` is only the remaining streak budget.
///
/// The semantic mismatch, stated rather than hidden: `auth_failures` counts
/// **pinUvAuthParam MAC** verification failures, not UV-gesture failures.
/// The UV leg (sub-command `0x06`) proves user presence, not a secret, so a
/// refused presence check answers `UpRequired` and deliberately does not
/// charge this counter — charging it would let anyone who declines to touch
/// the key drive the authenticator into a lockout.
///
/// So `uvRetries` reads as "PIN/UV authorization attempts remaining before
/// the latch", which is the budget this build actually enforces.
pub fn uv_retries(auth_failures: u8) -> u8 {
    UV_RETRY_BUDGET.saturating_sub(auth_failures)
}

/// The latch threshold both twins use for `auth_failures`, and therefore the
/// ceiling on the value [`uv_retries`] can report.
pub const UV_RETRY_BUDGET: u8 = 3;

impl Default for Ctap2Info {
    fn default() -> Self {
        // NOTE: "up" is deliberately NOT advertised, matching the reference
        // C firmware: the suite's test_option_up can only run when the option
        // is absent (its conftest Device.doGA has no options kwarg).
        // The same goes for "uv": there is no built-in user-verification
        // secret in this build to check (US-1525), so advertising it would
        // promise a mechanism that does not exist.
        // clientPin key is always present (it advertises PIN capability);
        // get_info sets the value from the actual PIN state. pinUvAuthToken
        // is seeded here so the key is on the wire, but get_info overrides it
        // with `pin_uv_auth_token_available` in every reachable state.
        let mut options: HeaplessVec<(&'static str, bool), 16> = HeaplessVec::new();
        options.push(("rk", true)).ok();
        options.push(("clientPin", false)).ok();
        options.push(("pinUvAuthToken", true)).ok();
        options.push(("largeBlobs", true)).ok();
        options.push(("credMgmt", true)).ok();
        options.push(("setMinPINLength", true)).ok();
        // makeCredUvNotRqd: makeCredential does not require UV when no PIN is set.
        options.push(("makeCredUvNotRqd", true)).ok();

        let mut versions: HeaplessVec<&'static str, 8> = HeaplessVec::new();
        for v in ["U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_2", "FIDO_2_3"] {
            versions.push(v).ok();
        }
        let mut extensions: HeaplessVec<&'static str, 16> = HeaplessVec::new();
        for e in ["credBlob", "credProtect", "hmac-secret", "largeBlobKey", "minPinLength"] {
            extensions.push(e).ok();
        }
        let mut pin_protocols: HeaplessVec<u8, 4> = HeaplessVec::new();
        pin_protocols.push(1).ok();
        pin_protocols.push(2).ok();
        let mut transports: HeaplessVec<&'static str, 4> = HeaplessVec::new();
        transports.push("usb").ok();
        // Advertised set matches the C firmware: ES256, EdDSA, ES384, ES512
        // (ES256K deliberately unsupported).
        let mut algorithms: HeaplessVec<i32, 4> = HeaplessVec::new();
        for a in [-7, -8, -35, -36] {
            algorithms.push(a).ok();
        }
        let mut authenticator_config_commands: HeaplessVec<u8, 8> = HeaplessVec::new();
        for c in [0x01u8, 0x02, 0x03, 0xFF] {
            authenticator_config_commands.push(c).ok();
        }
        // Compile-time: the advertised set can never overflow the 8-slot
        // vector, so the `push(..).ok()` calls below can never truncate.
        const _: () = assert!(crate::vendorff::SUPPORTED_IDS.len() + 2 <= 8);

        let mut vendor_prototype_config_commands: HeaplessVec<u64, 8> = HeaplessVec::new();
        // Every 64-bit id this firmware answers for the `0xFF` framing, and
        // nothing else. The four physical-config ids are taken from
        // `vendorff::SUPPORTED_IDS` rather than re-typed so the advertised
        // set cannot drift from the set the handler dispatches on
        // (`app.rs::cfg_vendor_prototype`).
        //
        // `0xFF` itself is deliberately absent: it is the *framing's*
        // sub-command byte (advertised under key `0x1F`), not a vendor id.
        // The `0x41` one-byte ids are absent for the same reason —
        // `vendorff` documents the two id spaces as disjoint.
        //
        // `push(..).ok()` would be the silent-truncation hazard here, so the
        // capacity is checked at compile time instead of at boot: on `no_std`
        // there is no unwinder, so a `default()` panic is a hard reset. A
        // fifth `SUPPORTED_IDS` entry is a build break, not a bricked token.
        for (_, id) in crate::vendorff::SUPPORTED_IDS {
            vendor_prototype_config_commands.push(*id).ok();
        }
        vendor_prototype_config_commands
            .push(CONFIG_CREDENTIAL_EXPIRE)
            .ok();
        vendor_prototype_config_commands
            .push(CONFIG_CREDENTIAL_REVOKE)
            .ok();
        let mut enc_cred_store_state: HeaplessVec<u8, 64> = HeaplessVec::new();
        enc_cred_store_state.extend_from_slice(&[0u8; 32]).ok();
        let mut enc_identifier: HeaplessVec<u8, 64> = HeaplessVec::new();
        enc_identifier.extend_from_slice(&[0u8; 32]).ok();

        Self {
            versions,
            extensions,
            aaguid: super::AAGUID,
            options,
            // S-701-1: the HID seam now really serves CTAPHID_MAX_MSG.
            max_msg_size: 7609,
            pin_protocols,
            max_creds_in_list: Some(19),
            max_cred_id_len: Some(128),
            transports,
            algorithms,
            max_large_blob: Some(1024),
            // US-102: a real, packed version — the old hard-coded 0 rendered
            // as "0.0" and mis-gated every version-dependent path.
            firmware_version: super::FIRMWARE_VERSION,
            max_cred_blob_length: 32,
            max_rpids_min_pin: 120,
            min_pin_length: 4,
            max_pin_length: 63,
            force_pin_change: false,
            pin_complexity_policy: None,
            authenticator_config_commands,
            vendor_prototype_config_commands,
            enc_cred_store_state,
            enc_identifier,
        }
    }
}
