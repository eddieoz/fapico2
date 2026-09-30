//! US-113: the pico-fido **legacy physical-config** framing (PicoForge
//! framing (B)) — CTAP2 `authenticatorConfig` sub-command `0xFF`
//! (`vendorPrototype`) carrying a 64-bit config id.
//!
//! # Which PicoForge framing this is, and which it is not
//!
//! Three PicoForge framings exist and they are easy to confuse, because two
//! of them use the word "physical config" and neither of them uses this
//! opcode:
//!
//! | framing | opcode | shape | module |
//! |---|---|---|---|
//! | (A) legacy vendor commands | `0xC1` frame, first payload byte `0x05`/`0x06` | CBOR `{1: sub}` | not implemented |
//! | (B) **this one** | CTAP2 `0x0D` config, sub-command `0xFF` | CBOR `{1: <u64 id>, 3: <int>}` (see the key table below) | this module |
//! | (C) RS-Key vendor channel | CTAP2 `0x41` | CBOR `{1: sub, 2: params}` | [`crate::vendor41`] |
//!
//! Framings (B) and (C) are both reached by an `authenticatorConfig`-shaped
//! request but are *separate* `match` statements over *different* opcode
//! bytes, so nothing here can alias [`crate::vendor41`]. The two id spaces are
//! also disjoint by construction: (C)'s ids are one byte, (B)'s are 64.
//!
//! # The wire format, read off the client
//!
//! `HidTransport::send_vendor_config` (`picoforge/src/hal/fido/ops.rs:154`)
//! builds `subCommandParams` as:
//!
//! ```text
//! { 1: vendorCommandId (u64), <k>: value }
//! ```
//!
//! where the value's key `k` is selected **by CBOR type**, not by this
//! framing's own choice:
//!
//! | value type | key |
//! |---|---|
//! | byte string | `0x02` |
//! | unsigned/negative integer | `0x03` |
//! | text string | `0x04` |
//!
//! Which key a given id arrives under is therefore a property of the
//! **caller**, not of the id. All four physical-config writes PicoForge
//! currently makes happen to be integers —
//! `write_legacy_hardware_config` (`picoforge/src/hal/fido/mod.rs:1305`)
//! passes `Value::Integer` for all four ids — so `0x03` is the key they
//! arrive under, and [`ValueSource::Integer`] is the only source accepted
//! for them here. That is a statement about the client that exists, not a
//! statement about the protocol: a future caller sending `Value::Bytes`
//! would be mis-served by an implementation that read the mapping as
//! fixed, which is why [`ValueSource`] keeps all three variants and
//! [`PhyCommand::integer`] refuses the other two by name rather than
//! coercing them.
//!
//! ## Why there is no TLV codec here, and what that means for US-116
//!
//! The EPIC text for this story says the four ids "are PHY TLV records" and
//! that this story needs US-116's `platform/tests/phy_tlv.rs` codec to
//! bootstrap it. That is **wrong**, and the client is where the correction
//! comes from: the TLV form appears only on the RS-Key `0x41` `CONFIG_WRITE`
//! path ([`crate::vendor41`], US-112), where `build_rskey_phy_tlv`
//! (`picoforge/src/hal/fido/mod.rs:1015`) packs a `TAG LEN VALUE` record
//! stream. Framing (B) sends four bare integers and never a tag, so building a
//! TLV codec for it would be a codec with no caller.
//!
//! Consequently this story does **not** pre-empt US-116: it covers **none** of
//! its 12 tags, because it needs no tags. US-116's scope is unchanged — the
//! `0x41` PHY TLV tags plus the full round-trip — and the two stories share
//! only [`PhyConfig`], the persisted record, not a codec.
//!
//! # Security: what this surface is and is not
//!
//! Three of the four ids change hardware configuration and one of those
//! (`PhysicalVidPid`) changes how the device identifies itself on the USB
//! bus, which is an identity-spoofing primitive in the sense the EPIC's R-5
//! threat model means. Two facts bound that here, and both are load-bearing:
//!
//! 1. **The framing is PIN-gated.** `0xFF` is a sub-command of
//!    `authenticatorConfig`, and both command paths require a set PIN, a live
//!    `pinUvAuthToken` carrying the `AUTHENTICATOR_CONFIG` bit, and a valid
//!    `pinUvAuthParam` MAC over the exact sub-command bytes before the arm is
//!    reached (`device_core.rs`'s `authenticator_config_inner`, and the host
//!    twin's `authenticator_config`). An unauthenticated local process gets
//!    `CTAP2_ERR_PIN_NOT_SET` or `CTAP2_ERR_PIN_AUTH_INVALID` and changes
//!    nothing. This is materially stronger than framing (A), which the client
//!    drives with **no token at all**
//!    (`probe_legacy_vendor_support` / `read_legacy_physical_config`,
//!    `picoforge/src/hal/fido/mod.rs:863` and `:887`) — that is where an
//!    unauthenticated process *can* read hardware state, and it is out of
//!    scope for this story.
//! 2. **`PhysicalVidPid` is currently stored, not applied.** The RP2350 USB
//!    descriptors are a compile-time `CONFIG_DESC`
//!    (`firmware/src/main.rs`, built by `Usb::new`), so writing `phy.vid_pid`
//!    records the operator's intent and nothing reads it. The spoofing
//!    primitive does not exist on this firmware today.
//!
//! There is a third fact, and it is about the **persisted record** rather
//! than the command path, so it does not interact with either of the two
//! above:
//!
//! 3. **`phy` is stored unsealed, and the deviation is on confidentiality
//!    grounds alone.** Keys 1-5 of the auth map are each individually
//!    sealed — every one through `seal_push` with its own
//!    [`crate::snapshot_crypt::FieldScope`] bound into the AEAD AAD — and
//!    there is no outer map-level MAC, so per-field AEAD *is* the integrity
//!    mechanism for this map. `phy` (key 6) is the one field that does not
//!    get it: `DeviceKeystore::decode_auth` rejects a *structurally* corrupt
//!    key-6 map, but a well-formed re-encoded one is accepted silently, so
//!    key 6 is the only unauthenticated field in the map.
//!
//!    The reason it is unsealed is that none of these values is secret — as of
//!    US-117 that is a VID/PID pair, two small integers, a `u16` bus mask and
//!    a 17-byte block of light settings, none of which is a credential or a
//!    key — so sealing buys no
//!    confidentiality. It does not buy the integrity either, deliberately,
//!    and that is the deviation from the seal-every-auth-field convention.
//!    The convention-following alternative is a `FieldScope::AuthPhy` seal
//!    exactly parallel to `AuthLargeBlobArray` / `AuthVaultState` /
//!    `AuthDeviceRandom`; it was not taken because it is a larger change
//!    than a 1-point story warrants, and because a snapshot field that must
//!    decrypt before it can be loaded is a field that can fail to load —
//!    a real availability cost for a record nothing reads yet. The option
//!    is named here so a later reader knows plaintext was a choice with a
//!    named alternative, not the only design that was available.
//!
//! ## The two decay surfaces, which are not the same surface
//!
//! (2) above decays on the **command path**, and this is the surface the
//! EPIC's R-5 threat model is about. The day the descriptors become
//! runtime-configurable, a `0xFF` write stops being a record and becomes
//! the primitive, so it will need a second gate (a presence prompt, or a
//! narrower token) at that point rather than inheriting the PIN gate
//! silently. `tests/vendor41.rs::vendor_0xff_requires_pin_and_acfg_permission`
//! pins the gate that exists now; nothing pins the future one, because it
//! does not exist and a comment claiming it would be a check that was never
//! made.
//!
//! (3) above decays on the **snapshot**, and it arrives there *first*. A
//! flash-level attacker does not need the PIN at all: they rewrite
//! `vid_pid` directly in the stored snapshot and the device boots into the
//! attacker-chosen identity, having never touched the PIN-gated command
//! path that a second gate on that path would have covered. So the
//! snapshot surface is the one that becomes dangerous first, and it is not
//! fixed by hardening the command handler at all. Today this is inert
//! (nothing applies `vid_pid`), which is exactly why it is a documented
//! gap rather than a tracked defect: when descriptors become
//! runtime-configurable, both surfaces need attention, and the unsealed
//! key 6 is the cheaper-looking one to forget.

use crate::ctap2::Ctap2Response;

/// The `authenticatorConfig` sub-command byte this framing dispatches on.
pub const SUB_COMMAND: u8 = 0xFF;

/// `VendorConfigCommand::PhysicalVidPid` — `picoforge`'s
/// `src/hal/fido/constants.rs`, used by `write_legacy_hardware_config` to
/// carry `((vid as u32) << 16) | (pid as u32)`.
pub const VIDPID: u64 = 0x6fcb19b0cbe3acfa;
/// `VendorConfigCommand::PhysicalLedGpio` — the RP2350 GPIO index that drives
/// the activity LED.
pub const LED_GPIO: u64 = 0x7b392a394de9f948;
/// `VendorConfigCommand::PhysicalLedBrightness` — a 0..=100 percentage.
pub const LED_BRIGHTNESS: u64 = 0x76a85945985d02fd;
/// `VendorConfigCommand::PhysicalOptions` — the bitmask below.
pub const PHYSICAL_OPTIONS: u64 = 0x269f3b09eceb805f;

/// The ids this firmware accepts, with the names the client gives them.
///
/// A `&'static [(&str, u64)]` rather than an enum, for one reason: the client
/// enumerates a *set* of ids and the useful test is that the firmware's set
/// equals it. An enum would let a fifth variant be added without any test
/// noticing. `tests/vendor41.rs::vendor_0xff_id_table_matches_picoforge`
/// asserts this against the client's own list.
pub const SUPPORTED_IDS: &[(&str, u64)] = &[
    ("PhysicalVidPid", VIDPID),
    ("PhysicalLedGpio", LED_GPIO),
    ("PhysicalLedBrightness", LED_BRIGHTNESS),
    ("PhysicalOptions", PHYSICAL_OPTIONS),
];

/// `LEGACY_PHY_OPT_DIMMABLE` — `picoforge/src/hal/fido/mod.rs:81`.
pub const OPT_DIMMABLE: u16 = 0x02;
/// `LEGACY_PHY_OPT_DISABLE_POWER_RESET` — `picoforge/src/hal/fido/mod.rs:82`.
/// Named for what it *disables*: the client reads it back as
/// `power_cycle_on_reset = (opts & DISABLE_POWER_RESET) == 0`, so the bit and
/// the config field have opposite polarity and that inversion lives in the
/// client, not here.
pub const OPT_DISABLE_POWER_RESET: u16 = 0x04;
/// `LEGACY_PHY_OPT_LED_STEADY` — `picoforge/src/hal/fido/mod.rs:83`.
pub const OPT_LED_STEADY: u16 = 0x08;

/// Pack a USB VID/PID pair the way the client does.
///
/// `write_legacy_hardware_config` (`picoforge/src/hal/fido/mod.rs:1324`)
/// computes `((vid as u32) << 16) | (pid as u32)` and sends it as a CBOR
/// integer under key `0x03`. The result is returned as a `u32` rather than
/// widened, because the client widens to `i128` only at the CBOR layer.
pub fn pack_vidpid(vid: u16, pid: u16) -> u32 {
    ((vid as u32) << 16) | pid as u32
}

/// The inverse of [`pack_vidpid`].
///
/// Total by construction: every `u32` splits into a `(vid, pid)` pair, so
/// there is no fallible case to report.
pub fn unpack_vidpid(v: u32) -> (u16, u16) {
    ((v >> 16) as u16, v as u16)
}

/// The persisted physical configuration.
///
/// Stored, not applied — see the module docs. Every field is an `Option`
/// because framing (B) is *write*-only: nothing in that framing, or in the
/// client's legacy path, reads a value back (the client reads physical options
/// over framing (A) instead, `picoforge/src/hal/fido/mod.rs:887`), and an
/// absent field is meaningfully different from a zero-valued one — GPIO 0 is a
/// real pin.
///
/// The qualifier is on *framing (B)*, not on the record: US-117 gave the `0x41`
/// `CONFIG_READ` path a reason to serve [`Self::led_conf`] at target `0x02` (see
/// `vendor41::config_read`), so the struct is not read-only any more. The other
/// five still are.
///
/// ## There is no way to clear a field
///
/// No id in [`SUPPORTED_IDS`] resets a field to `None`, and none can: the
/// four are all *set* commands, and a `0` value is a real setting (GPIO 0,
/// brightness 0, "do not power-cycle on reset"), not an absence. So once a
/// field is written it stays written for the life of the partition, and a
/// device that has accepted a `0xFF` never returns to the "no key 6 in the
/// snapshot at all" shape the encoders special-case for byte-identical
/// pre-story images.
///
/// That is inherent to the framing as the client implements it, not an
/// oversight here — the maintainer-facing consequence is that changing the
/// default LED or VID/PID on a provisioned device means a factory reset (or
/// the rescue/flash path), not another `0xFF` write. Adding a clear would be
/// a new id the client does not send.
///
/// # US-117 added two fields, and they do not come from framing (B)
///
/// [`Self::enabled_usb_itf`] and [`Self::led_conf`] arrived with US-117 and are
/// written by the RS-Key `0x41` `CONFIG_WRITE` ([`crate::vendor41`]), **not** by
/// this framing's four ids. They live on the same struct because they are the
/// same thing — the device's operator-settable physical configuration — and the
/// same durable-before-ack commit already covers them; a second record would
/// mean a second commit in the dispatch arm and a second codec to keep in step,
/// for no gain.
///
/// What they do *not* share is a write path. No [`SUPPORTED_IDS`] member
/// reaches either field, and [`PhyCommand`]'s decode still covers exactly the
/// four ids it always did. `CONFIG_WRITE` owns writing them, and
/// `CONFIG_READ` at target `0x02` owns reading [`Self::led_conf`] back.
// `Copy` is kept deliberately: the two identity fields are a fixed-size
// newtype (see `IdentityName`) rather than a `heapless::String`, precisely so
// this struct stays `Copy`. It is passed by value in seven places, and a
// record whose identity fields quietly turned every one of them into a
// move would be a poor trade for two short strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PhyConfig {
    /// `(vid << 16) | pid`, as [`pack_vidpid`] produces it.
    pub vid_pid: Option<u32>,
    /// RP2350 GPIO index for the activity LED.
    pub led_gpio: Option<u8>,
    /// LED brightness, 0..=100.
    pub led_brightness: Option<u8>,
    /// The [`PHYSICAL_OPTIONS`] bitmask.
    pub options: Option<u16>,
    /// US-117: the USB enabled-interface mask — the `DEV_CONF` record.
    ///
    /// The same operator intent as the PHY record's `EnabledUsbItf` tag
    /// (`0x0B`), reached through a *different* `CONFIG_WRITE` target:
    /// `DEV_CONF` (`0x00`) carries it as management TLV
    /// `0x03, len 2, <enabled BE u16>`, from `write_rskey_dev_config`
    /// (`picoforge/src/hal/fido/mod.rs:2086-2091`; the tag constant
    /// `FIDO_MGMT_TAG_USB_ENABLED` is at `:2071`).
    ///
    /// Both carriers write this one field, and both go through the identity
    /// tier and the unconditional zero-mask refusal in
    /// [`crate::vendor41`]. Stored, not applied, on the same grounds as the
    /// rest of this struct.
    pub enabled_usb_itf: Option<u16>,
    /// US-117: the 17-byte RS-Key LED status block — the `LED` record.
    ///
    /// The layout is `[steady(1), (effect, color, brightness, speed) × 4]`
    /// (`RSKEY_LED_CONF_LEN`, `picoforge/src/hal/fido/mod.rs:2001`), so index
    /// `1 + 4i` is effect, `2 + 4i` colour, `3 + 4i` brightness and `4 + 4i`
    /// speed, for `i` in `0..4`.
    pub led_conf: Option<LedConf>,
    /// The USB product name — PHY TLV tag `0x09`.
    ///
    /// A **NUL-terminated** UTF-8 string on the wire, at most
    /// [`MAX_IDENTITY_STRING`] bytes *including* that NUL
    /// (`platform::phy_tlv::encode_nul_string`). Stored **without** the
    /// terminator; the encoder re-adds it, so a round trip through the
    /// keystore cannot accumulate terminators.
    ///
    /// This is the field the client calls `product_name`
    /// (`picoforge/src/hal/rescue/ops.rs:350`), so storing it is what makes
    /// PicoForge's device-details screen show a name instead of a blank.
    ///
    /// Deliberately **not** seeded from
    /// [`fapico2_platform::identity::PRODUCT`] — see the field-name note on
    /// [`PhyConfig::has_identity_strings`] for why a record that silently tracked
    /// a build-time constant would be worse than an empty one.
    pub product: Option<IdentityName>,
    /// The USB manufacturer name — PHY TLV tag `0x0F`, same framing and the
    /// same length bound as [`PhyConfig::product`].
    pub manufacturer: Option<IdentityName>,
}

/// The ceiling on a stored product/manufacturer name, **including** the NUL
/// the wire format carries.
///
/// **Derived** from [`phy_tlv::MAX_NUL_STRING_LEN`] rather than restated, so a
/// change to the wire limit cannot leave the store quietly accepting a longer
/// name than the encoder will frame — the same class of defect as the two
/// keystore decoders disagreeing about a field's bounds.
pub const MAX_IDENTITY_STRING: usize = fapico2_platform::identity::MAX_IDENTITY_STRING;

/// A stored identity string — UTF-8 bytes, a length, and neither a NUL nor a
/// heap.
///
/// A newtype over `[u8; N]` plus a length for the same reason
/// [`LedConf`] is one over `[u8; 17]`: the value has a hard bound already, so
/// the interesting failures are an over-long name and a name carrying a NUL —
/// and both belong at construction, where they can be refused, rather than at
/// every read. A `heapless::String` would have been the obvious choice and
/// would have cost `PhyConfig` its `Copy`.
///
/// The stored bytes never include the trailing NUL. That terminator belongs to
/// the wire format (PHY tag `0x09`/`0x0F`), so the encoder adds it and no round
/// trip through the keystore can accumulate terminators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityName {
    bytes: [u8; MAX_IDENTITY_STRING - 1],
    len: u8,
}

impl IdentityName {
    /// The longest name that fits, **excluding** the NUL the wire carries.
    ///
    /// The `- 1` is the NUL. Storing it inside the bound would let a name that
    /// the encoder cannot frame be accepted here, which is the field-bounds
    /// disagreement this file has been bitten by before.
    pub const MAX: usize = MAX_IDENTITY_STRING - 1;

    /// Builds a name from ASCII/UTF-8 text, or `None` if it will not fit.
    ///
    /// Refuses — rather than truncating — because a silently shortened product
    /// name is one an operator cannot notice and a user reads as a typo.
    pub const fn new(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() > Self::MAX {
            return None;
        }
        let mut bytes = [0u8; MAX_IDENTITY_STRING - 1];
        let mut i = 0;
        while i < b.len() {
            // An interior NUL would split the name in half in every log line
            // that renders it; the wire form has its terminator appended, so a
            // NUL in the stored value is always a mistake.
            if b[i] == 0 {
                return None;
            }
            bytes[i] = b[i];
            i += 1;
        }
        Some(Self {
            bytes,
            len: b.len() as u8,
        })
    }

    /// The name as stored: no terminator, no padding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The name as `str`, or `""` if the stored bytes are not UTF-8.
    ///
    /// The `""` is not a silent success the caller cannot see: the only way to
    /// build one is [`Self::new`], which takes a `&str`, so the bytes are UTF-8
    /// by construction and this branch is unreachable in practice. It exists
    /// because the fallback has to be *some* value, and inventing a lossy
    /// conversion to fill it would be worse.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }
}

/// The 17-byte RS-Key LED status block, and nothing more.
///
/// # Why a newtype over `[u8; 17]`
///
/// So that a *block* cannot be confused with any other 17-byte value, and so
/// the two values this firmware needs have names: the block a configured
/// device has stored, and the block a never-configured one serves
/// ([`Self::UNCONFIGURED`]).
///
/// The second is load-bearing because of the **explicit** read, not the
/// read-modify-write. `read_rskey_led_config`
/// (`picoforge/src/hal/fido/mod.rs:2010-2019`) reads the block in order to
/// display it and hands it to `parse_led_block`, which returns `None` on an
/// empty input (`picoforge/src/hal/common/led.rs:21-22`) — so an empty blob
/// becomes `PFError::Device("LED config response too short: 0 bytes")` at
/// `hal::io::read_led_config` (`picoforge/src/hal/io.rs:179`), which is what
/// the Rescue LED UI calls. Seventeen zeros instead yields a well-defined
/// "not steady, dark in all four statuses".
///
/// Worth separating from the argument it is easily confused with:
/// `write_rskey_led_config`'s guard
/// (`current.len() >= RSKEY_LED_CONF_LEN`,
/// `picoforge/src/hal/fido/mod.rs:2045-2047`) would send an empty blob down
/// the same all-zero fall-through, so *that* consumer cannot tell the two
/// apart. It is a true property and it is not why the shape is 17 bytes. See
/// `vendor41::config_read`, which keeps the two arguments apart.
///
/// # Why nothing validates the contents
///
/// The client writes `block[2 + 4i] = color & 0x07` and
/// `block[3 + 4i] = brightness` with no further bounds
/// (`picoforge/src/hal/fido/mod.rs:2053-2054`), and `LedStatusConfig::statuses`
/// is a plain `[(u8, u8); 4]` with no range attached
/// (`picoforge/src/hal/types.rs:187`) — a brightness of `0xFF` is a value the
/// client will write and read back. A range check here would be a policy this
/// firmware invented, and it would refuse a configuration the reference
/// implementation accepts, which is exactly the drift `vendorff`'s
/// shared-validator discipline exists to prevent. The block is stored
/// verbatim; the meaning of each byte belongs to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedConf(pub [u8; LedConf::LEN]);

/// The auth-map key-6 field number for [`PhyConfig::enabled_usb_itf`].
///
/// Key 5. Named rather than written inline because **two** codecs encode and
/// decode this map — `keystore.rs` for the host twin and `device_keystore.rs`
/// for the RP2350 — and US-113 review already found them disagreeing about one
/// field's bounds, which turned one stored record into two different hardware
/// configurations depending on which stack read it. A literal in each codec is
/// how that happened.
pub const PHY_FIELD_ENABLED_USB_ITF: u64 = 5;

/// The auth-map key-6 field number for [`PhyConfig::led_conf`].
///
/// Key 6 — the one field of the record whose value is a CBOR **byte string**
/// rather than an integer, and the reason both decoders dispatch on the field
/// before the value's type. See [`PHY_FIELD_ENABLED_USB_ITF`] on why the number
/// lives here.
pub const PHY_FIELD_LED_CONF: u64 = 6;

/// The auth-map key-6 field number for [`PhyConfig::product`] — PHY tag `0x09`.
///
/// Keys 7 and 8 are the two identity strings, the record's first
/// **non-integer** fields after [`PHY_FIELD_LED_CONF`]: both keystores
/// dispatch on the field number before the value's type, so a byte-string
/// value arriving under an integer field is refused rather than truncated.
pub const PHY_FIELD_PRODUCT: u64 = 7;

/// The auth-map key-6 field number for [`PhyConfig::manufacturer`] — PHY tag
/// `0x0F`. See [`PHY_FIELD_PRODUCT`].
pub const PHY_FIELD_MANUFACTURER: u64 = 8;

impl LedConf {
    /// The block length, from the client's own constant
    /// `RSKEY_LED_CONF_LEN` (`picoforge/src/hal/fido/mod.rs:2001`).
    pub const LEN: usize = 17;

    /// The block a device that has never been told otherwise serves.
    ///
    /// All zeros, which the client decodes as `steady = false` with four
    /// `(colour 0, brightness 0)` statuses (`parse_led_block`,
    /// `picoforge/src/hal/common/led.rs:34-39`) — an LED that is not steady
    /// and dark in every status.
    pub const UNCONFIGURED: LedConf = LedConf([0; LedConf::LEN]);
}

impl PhyConfig {
    /// How many of the eight fields are set — the CBOR map header for the
    /// persisted record.
    ///
    /// The map keys are the field numbers below, in ascending order, which is
    /// what both keystores' encoders emit and what their decoders accept; the
    /// count and the pairs must agree or the map header will mis-parse.
    pub fn field_count(&self) -> usize {
        usize::from(self.vid_pid.is_some())
            + usize::from(self.led_gpio.is_some())
            + usize::from(self.led_brightness.is_some())
            + usize::from(self.options.is_some())
            + usize::from(self.enabled_usb_itf.is_some())
            + usize::from(self.led_conf.is_some())
            + usize::from(self.product.is_some())
            + usize::from(self.manufacturer.is_some())
    }

    /// Whether either identity string is set — i.e. whether this record holds
    /// a name that *someone chose*, as opposed to leaving the client to fall
    /// back to nothing.
    ///
    /// Named for what it reports, and paired with the note below because the
    /// question it exists to ask — "why isn't this seeded?" — is asked every
    /// time someone reads the struct.
    ///
    /// # Why these two are not seeded from the build-time identity block
    ///
    /// Every other field here is operator state: it starts empty and is set by
    /// a deliberate `CONFIG_WRITE`. A product name is different — the build
    /// already knows what it is.
    ///
    /// Seeding it would look helpful and be wrong twice over. First, the
    /// record would no longer be a record of *operator intent*: it would carry
    /// a value no one chose, and the client's write-then-read-back would be
    /// indistinguishable from one that had been configured. Second — and this
    /// is the one that bites — the seed is evaluated when the record is
    /// created, so a firmware upgrade that changes
    /// [`fapico2_platform::identity::PRODUCT`] would leave every existing
    /// device advertising the *old* name with no way to tell that from a
    /// deliberate setting. An empty field, by contrast, means "nobody set
    /// this", and the client already filters on it
    /// (`picoforge/src/hal/rescue/ops.rs:543,557`).
    ///
    /// So a default build serves its built-in name through the USB descriptor
    /// and the CTAP2 getInfo, and the PHY record carries a name only once
    /// somebody writes one.
    pub fn has_identity_strings(&self) -> bool {
        self.product.is_some() || self.manufacturer.is_some()
    }
}

/// Where in the `subCommandParams` map a value was found.
///
/// The client picks the key by CBOR type (see the module docs), so "which key
/// was it under" and "what type was it" are the same question. Modelling it as
/// an enum rather than as a bare `u64` means [`PhyCommand::decode`] can refuse
/// a byte-string value for an id whose value is an integer, which is the
/// distinction `tests/vendor41.rs::vendor_0xff_rejects_misshapen_requests`
/// exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueSource {
    /// Key `0x02` — a CBOR byte string. The **payload is dropped**:
    /// [`PhyCommand`] keeps the refusal that the type is wrong for these ids
    /// and nothing of the bytes. That is deliberate — no supported id takes a
    /// byte string, so keeping the payload would be dead weight on the
    /// RP2350's stack — and it is the reason a future id that *does* want
    /// bytes has to widen this enum and re-plumb the decode rather than just
    /// switching on a variant.
    Bytes,
    /// Key `0x03` — a CBOR integer. The only source the four physical-config
    /// ids use today; see the module section on value keys for why "today"
    /// is load-bearing.
    Integer(u64),
    /// Key `0x04` — a CBOR text string. Payload dropped, for the same reason
    /// as [`ValueSource::Bytes`].
    Text,
}

impl ValueSource {
    /// Classify a decoded `{key, value}` pair from a `subCommandParams` map.
    ///
    /// `key` is the CBOR map key as the client encodes it (`0x02`, `0x03`,
    /// `0x04`); `value` is the already-decoded item. Returns `None` for a key
    /// that is none of the three — an unknown key is not silently ignored,
    /// because a client that filed the value under a fourth key has said
    /// something this framing does not understand.
    pub fn classify(key: u64, value: &crate::cbor::no_heap::Item<'_>) -> Option<Self> {
        use crate::cbor::no_heap::Item;
        Some(match (key, value) {
            (2, Item::B(_)) => Self::Bytes,
            (3, Item::U(u)) => Self::Integer(*u),
            // A negative integer is representable on the wire and the client's
            // `Value::Integer` type would carry it, but no physical-config
            // value is negative; treating it as the integer it encodes would
            // let `-1` reach `led_gpio` as 255.
            (3, Item::N(_)) => return None,
            (4, Item::T(_)) => Self::Text,
            _ => return None,
        })
    }
}

/// A decoded `vendorPrototype` sub-command: a 64-bit id and its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhyCommand {
    /// The 64-bit `vendorCommandId`.
    pub id: u64,
    /// Where the value came from.
    pub value: ValueSource,
}

impl PhyCommand {
    /// Decode a `subCommandParams` byte range into an id and a value.
    ///
    /// The byte range is the *raw* CBOR of the map, borrowed from the request
    /// — the same bytes the pinUvAuthParam MAC covered, so a decoder that
    /// silently looked elsewhere in the request could not be substituted for
    /// this one without failing the MAC first.
    ///
    /// The error distinguishes the two failures an operator needs told apart:
    /// [`Ctap2Response::MissingParameter`] when the request names no vendor
    /// command or carries no value, and [`Ctap2Response::InvalidParameter`]
    /// when it names one whose id, key or value type this framing does not
    /// accept. A malformed map is [`Ctap2Response::InvalidCbor`], which is a
    /// third thing again and not this function's to fold into either.
    pub fn decode(params: &[u8]) -> Result<Self, Ctap2Response> {
        use crate::cbor::no_heap::{Item, Parser};
        let mut p = Parser::new(params);
        let Item::Map(n) = p.next().map_err(|_| Ctap2Response::InvalidCbor)? else {
            return Err(Ctap2Response::InvalidCbor);
        };
        let mut id: Option<u64> = None;
        let mut value: Option<ValueSource> = None;
        for _ in 0..n {
            let key = match p.next().map_err(|_| Ctap2Response::InvalidCbor)? {
                Item::U(k) => k,
                _ => return Err(Ctap2Response::InvalidCbor),
            };
            let item = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
            match key {
                1 => {
                    let Item::U(id_val) = item else {
                        return Err(Ctap2Response::InvalidParameter);
                    };
                    if id.replace(id_val).is_some() {
                        // A repeated id key is a map no client sends, and the
                        // two command paths would resolve it differently: the
                        // host's `cfg_vendor_prototype` scans for the *first*
                        // key 1 while a last-wins `decode` would take the
                        // second, and the host's own `id` re-check would then
                        // turn the disagreement into a spurious refusal on
                        // one path and a silent apply on the other. Refusing
                        // here makes it one shared answer on both.
                        return Err(Ctap2Response::InvalidParameter);
                    }
                }
                k => {
                    if value.is_some() {
                        // Two value keys: the client writes exactly one, and
                        // which one it is determines the type. Picking the
                        // first would let a byte string be read as an integer.
                        return Err(Ctap2Response::InvalidParameter);
                    }
                    value = Some(
                        ValueSource::classify(k, &item)
                            .ok_or(Ctap2Response::InvalidParameter)?,
                    );
                }
            }
        }
        if p.remaining() != 0 {
            // Trailing bytes after a well-formed map. Defence-in-depth rather
            // than a live hole: the CTAP2 config parser ends the `0x02`
            // value's extent at the map's own close brace, so the device
            // command path cannot hand this function a tail, and any caller
            // that could already has a MAC covering the same bytes. It is
            // here because `DeviceKeystore::decode_auth` checks the same
            // thing, and a decoder strict in one snapshot format and lax in
            // another is the asymmetry that gets tightened on one side and
            // missed on the other.
            // `tests/vendor41.rs::vendor_0xff_decode_refuses_trailing_bytes`
            // pins it at the level it operates on.
            return Err(Ctap2Response::InvalidCbor);
        }
        match (id, value) {
            (Some(id), Some(value)) => Ok(PhyCommand { id, value }),
            (None, _) | (Some(_), None) => Err(Ctap2Response::MissingParameter),
        }
    }

    /// Narrow the value to an unsigned integer, or refuse.
    ///
    /// Every one of the four supported ids takes an integer, and the client
    /// always sends one, so a non-integer is a different framing's request
    /// rather than a malformed one to be coerced.
    pub fn integer(&self) -> Result<u64, Ctap2Response> {
        match self.value {
            ValueSource::Integer(u) => Ok(u),
            _ => Err(Ctap2Response::InvalidParameter),
        }
    }
}

/// Check that `cmd` names a supported id and carries a value in range,
/// without touching any configuration.
///
/// Split out from [`apply`] for one reason: a caller that commits
/// transactionally has to know the command is acceptable *before* it opens
/// the transaction, otherwise a rejected command either dirties the snapshot
/// on its way to being undone or is applied inside a closure whose error
/// channel has nowhere to go. Keeping the two apart makes the ordering
/// explicit rather than a property of [`apply`]'s internal field-by-field
/// checks — which is the actual reason [`apply`] is safe to call inside a
/// closure, and worth a test of its own.
pub fn validate(cmd: &PhyCommand) -> Result<(), Ctap2Response> {
    let value = cmd.integer()?;
    match cmd.id {
        VIDPID => {
            // The packed pair is a `u32` and the wire value is a `u64`, so
            // this is the only thing standing between a 33-bit write and a
            // stored `vid_pid` that is not the VID/PID the client asked for.
            // `pack_vidpid` cannot produce one and no client sends one, so
            // the check costs nothing and removes a silent truncation.
            u32::try_from(value).map_err(|_| Ctap2Response::InvalidParameter)?;
        }
        LED_GPIO => {
            u8::try_from(value).map_err(|_| Ctap2Response::InvalidParameter)?;
        }
        LED_BRIGHTNESS => {
            let b = u8::try_from(value).map_err(|_| Ctap2Response::InvalidParameter)?;
            if b > 100 {
                return Err(Ctap2Response::InvalidParameter);
            }
        }
        PHYSICAL_OPTIONS => {
            let bits = u16::try_from(value).map_err(|_| Ctap2Response::InvalidParameter)?;
            if bits & !(OPT_DIMMABLE | OPT_DISABLE_POWER_RESET | OPT_LED_STEADY) != 0 {
                return Err(Ctap2Response::InvalidParameter);
            }
        }
        _ => return Err(Ctap2Response::InvalidParameter),
    }
    Ok(())
}

/// Apply a command that [`validate`] has already accepted.
///
/// The range checks are repeated rather than assumed, so this function is
/// still correct when called on its own — the cost is a comparison, and the
/// alternative is an `apply` that is only safe under a precondition the
/// compiler cannot see.
pub fn apply(cfg: &mut PhyConfig, cmd: &PhyCommand) -> Result<(), Ctap2Response> {
    validate(cmd)?;
    let value = cmd.integer()?;
    match cmd.id {
        VIDPID => cfg.vid_pid = Some(u32::try_from(value).expect("validated above")),
        LED_GPIO => cfg.led_gpio = Some(u8::try_from(value).expect("validated above")),
        LED_BRIGHTNESS => {
            cfg.led_brightness = Some(u8::try_from(value).expect("validated above"));
        }
        PHYSICAL_OPTIONS => {
            cfg.options = Some(u16::try_from(value).expect("validated above"));
        }
        _ => unreachable!("validate rejected every other id"),
    }
    Ok(())
}
