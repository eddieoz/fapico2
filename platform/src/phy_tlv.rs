//! The RS-Key / pico-fido **PHY record** TLV codec (US-116, built by US-114).
//!
//! # The wire format, and where it comes from
//!
//! A bare `TAG LEN VALUE` stream, concatenated with no header, no terminator
//! and no record count:
//!
//! ```text
//! +--------+--------+------------------+
//! | 1 byte | 1 byte | `LEN` bytes      |
//! | tag    | length | value            |
//! +--------+--------+------------------+
//! ```
//!
//! That is read directly off the client rather than inferred. The writer is
//! `build_rskey_phy_tlv` (`picoforge/src/hal/fido/mod.rs:1015`), which emits
//! `tlv.push(TAG); tlv.push(0x04); tlv.extend_from_slice(...)` — a literal
//! one-byte length, written as a constant at every call site. The reader is
//! `read_rskey_physical_config` (`picoforge/src/hal/fido/mod.rs:940-941`),
//! which does `let tag_byte = data[i]; let len = data[i + 1] as usize;` and
//! then bounds-checks `i + len > data.len()` (`:943`).
//!
//! ## **Not** BER/DER TLV
//!
//! The length is *one byte*, unconditionally. It is not a BER length
//! indicator, so there is no `0x81` continuation byte for a length over 127
//! and no long form at all: **a value of 256 bytes cannot be encoded**, and
//! [`crate::phy_tlv::encode_record`] says so with [`crate::phy_tlv::TlvError::ValueTooLong`] rather than
//! wrapping the length or silently truncating the value. Callers that need a
//! length-aware format have the wrong protocol; the client cannot read one.
//!
//! ## Unknown tags are skipped, not refused
//!
//! The client's reader is a `match` with a `_ => {}` arm
//! (`picoforge/src/hal/fido/mod.rs:1001-1003`), so a tag it does not know is
//! stepped over and parsing continues. [`crate::phy_tlv::Decoder`] therefore hands unknown
//! tags back to the caller as a raw `u8` rather than as a [`crate::phy_tlv::PhyTag`] and
//! errors on nothing: refusing them would make this decoder *stricter* than
//! the one it exists to interoperate with, and a future firmware tag would
//! then break reading the eight records that follow it.
//!
//! ## Why this lives in `platform` and not in `vendor41`
//!
//! Three stories need this format and none of them is `vendor41`: US-114
//! *emits* the PHY record over `0x41` `CONFIG_READ`, US-115 parses the
//! `CONFIG_WRITE` record on the same channel, and US-116 names
//! `platform/tests/phy_tlv.rs` as its home. A second copy in `vendor41` would
//! be a second home for the same wire format, which is the same anti-pattern
//! the [`vendorff`]/`vendor41` split was built to avoid — those two modules
//! are separate *framings*, whereas these are one format with three callers.
//!
//! [`vendorff`]: ../../apps/fido/src/vendorff.rs
//!
//! # Per-tag coverage
//!
//! The unit tests below pin the framing itself (one-byte tag, one-byte length,
//! the 255-byte ceiling, and that a refused record writes no stub) but
//! deliberately do **not** walk all twelve tags: the widths and byte orders
//! belong to the client, and a table restated from the codec's own encoder
//! would only check that the encoder agrees with itself.
//! `tests/phy_tlv.rs::phy_tlv_roundtrip_all_tags` is that walk — one case per
//! tag, each carrying the exact record bytes read off the client's writer plus
//! that tag's declared width, so a wrong width, a wrong byte order or a tag
//! missing from [`crate::phy_tlv::PhyTag::ALL`] fails the case.
//!
//! Pinned by `tests/phy_tlv.rs::bitflags_match_the_clients_bitflag_tables`.

use heapless::Vec as HeaplessVec;

/// The largest value a single record can hold — one length byte, so 255.
pub const MAX_VALUE_LEN: usize = 255;

// --- `0x06` options bitmask ---
//
// `RescueOptions` in `picoforge/src/hal/rescue/constants.rs` (the canonical
// table; the FIDO writer's `RSKEY_OPT_*`,
// `picoforge/src/hal/fido/mod.rs:110-112`, is the same table minus WCID, which
// that writer never sets). A `u16` on the wire, big-endian, 2 bytes.
//
// [`RESCUE_OPTIONS_MASK`] is what the *client's* table contains, and it is
// **not** the firmware's acceptance rule: `vendor41::apply_phy_record`
// validates an inbound `0x06` against the narrower `vendorff::OPT_*` set — the
// three bits minus `WCID` — and rejects anything else with
// `InvalidParameter` (`apps/fido/src/vendor41.rs`, the `PhyTag::Options` arm).
// So a firmware that wrote `RESCUE_OPT_WCID` today would produce a record its
// own reader refuses. The mask is stated here as the protocol's bit list, not
// as a claim about what this firmware accepts.
pub const RESCUE_OPT_WCID: u16 = 0x01;
pub const RESCUE_OPT_LED_DIMMABLE: u16 = 0x02;
pub const RESCUE_OPT_DISABLE_POWER_RESET: u16 = 0x04;
pub const RESCUE_OPT_LED_STEADY: u16 = 0x08;
/// Every bit `RescueOptions` defines — nothing wider, so a value carrying an
/// undefined bit is detectable rather than silently accepted.
pub const RESCUE_OPTIONS_MASK: u16 = RESCUE_OPT_WCID
    | RESCUE_OPT_LED_DIMMABLE
    | RESCUE_OPT_DISABLE_POWER_RESET
    | RESCUE_OPT_LED_STEADY;

// --- `0x0B` enabled USB interfaces ---
//
// `UsbInterfaces` in `picoforge/src/hal/rescue/constants.rs`. A `u8` on the
// wire, 1 byte. Bit `0x02` here and bit `0x02` in the options mask are
// different flags — the two records are different tags, and reading one as
// the other would enable the WCID interface while claiming "LED dimmable".
pub const USB_ITF_CCID: u8 = 0x01;
pub const USB_ITF_WCID: u8 = 0x02;
pub const USB_ITF_HID: u8 = 0x04;
pub const USB_ITF_KB: u8 = 0x08;
pub const USB_ITF_LWIP: u8 = 0x10;
/// Every interface bit `UsbInterfaces` defines. Bits 5..7 are undefined in the
/// client's table and stay undefined here.
pub const USB_ITF_MASK: u8 = USB_ITF_CCID | USB_ITF_WCID | USB_ITF_HID | USB_ITF_KB | USB_ITF_LWIP;

/// The longest USB product / manufacturer name, in **text bytes** — the NUL
/// is additional, so the widest such record's value is 33 bytes.
///
/// The client's own limit is `bytes.len() + 1 > 33` refused
/// (`build_rskey_phy_tlv`, `picoforge/src/hal/fido/mod.rs:1073-1077` and
/// `:1089-1093`) — a 32-byte name. A 33-byte value sits comfortably inside
/// the 255-byte length ceiling, so the binding constraint is the client's,
/// not the format's; that is why it is named here rather than left to be
/// discovered as a [`TlvError::StringTooLong`].
pub const MAX_NUL_STRING_LEN: usize = 32;

// The identity block validates its USB string overrides against its own bound
// (`identity::MAX_IDENTITY_STRING`), and the two carriers of a name must not be
// able to disagree about how long a name may be: a name the descriptor accepts
// and this codec refuses is an identity that exists on one path and not the
// other. Checked rather than restated so a change to either is a build break
// naming the other.
const _: () = assert!(MAX_NUL_STRING_LEN == crate::identity::MAX_IDENTITY_STRING);

/// The largest blob [`crate::phy_tlv::PhyTag::ALL`] can produce, used as the worst-case bound
/// for a response buffer sized against this format.
///
/// `12 * (2 + 255)`: twelve records, each a tag byte plus a length byte plus a
/// maximal value. No real record is close to this — the largest the client
/// writes is a 33-byte product string — but a *bound* is what a buffer is
/// sized against, and this one is derivable from the format rather than
/// guessed.
pub const MAX_BLOB_LEN: usize = 12 * (2 + MAX_VALUE_LEN);

/// The `12` in [`MAX_BLOB_LEN`] is [`PhyTag::ALL`]'s length, and this asserts
/// that at compile time so a thirteenth tag cannot leave the bound stale.
///
/// `MAX_BLOB_LEN` sizes a *response buffer*, so a bound that is too small is a
/// refused `CONFIG_READ`; too large is merely wasted stack. That asymmetry is
/// why the failure is worth a compile error rather than a comment.
const _: () = assert!(MAX_BLOB_LEN == PhyTag::ALL.len() * (2 + MAX_VALUE_LEN));

/// One of the twelve PHY record tags, as PicoForge names them
/// (`picoforge/src/hal/fido/mod.rs:86-97`).
///
/// The enum is the "all 12 tags" statement made a type, so a tag cannot be
/// spelled as a bare literal at an encode site and drift. It is deliberately
/// *not* a `#[repr(u8)]` fieldless enum with an `as u8` cast at the use
/// site: [`PhyTag::from_byte`] exists so the wire byte and the variant cannot
/// disagree, which is the same one-directional check `vendor41::Subcommand`
/// uses for its own byte table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhyTag {
    /// `0x00` — `u16` VID then `u16` PID, big-endian, 4 bytes.
    VidPid,
    /// `0x04` — activity-LED GPIO index, 1 byte.
    LedGpio,
    /// `0x05` — LED brightness, `0..=100`, 1 byte.
    LedBrightness,
    /// `0x06` — `u16` options bitmask ([`RESCUE_OPTIONS_MASK`]), big-endian,
    /// 2 bytes.
    Options,
    /// `0x08` — presence/timeout in seconds, 1 byte.
    PresenceTimeout,
    /// `0x09` — USB product string, NUL-terminated, at most
    /// [`MAX_NUL_STRING_LEN`] text bytes plus the NUL.
    UsbProduct,
    /// `0x0A` — curve mask, `u32` big-endian, 4 bytes.
    Curves,
    /// `0x0B` — enabled USB interface mask ([`USB_ITF_MASK`]), 1 byte.
    EnabledUsbItf,
    /// `0x0C` — LED driver type, 1 byte.
    LedDriver,
    /// `0x0D` — LED order, 1 byte.
    LedOrder,
    /// `0x0E` — number of LEDs, 1 byte.
    LedNum,
    /// `0x0F` — USB manufacturer string, NUL-terminated, at most
    /// [`MAX_NUL_STRING_LEN`] text bytes plus the NUL.
    UsbManufacturer,
}

impl PhyTag {
    /// The whole tag set, in ascending byte order.
    ///
    /// Ascending is a canonical choice, not a claim about the client. The
    /// client's own writer is *not* strictly ascending — `build_rskey_phy_tlv`
    /// (`picoforge/src/hal/fido/mod.rs:1015`) emits `0x0F` manufacturer
    /// before `0x0A` curves, and `0x0E` LED num after `0x0B` interfaces — but
    /// its reader (`read_rskey_physical_config`,
    /// `picoforge/src/hal/fido/mod.rs:923`) is a flat `while offset <
    /// data.len()` walk with no ordering rule, so any order reads back the
    /// same. Ascending is chosen because a canonical order is what makes an
    /// encoded blob byte-comparable against a literal in a test, which is the
    /// only way to check a wire format without checking it against itself.
    pub const ALL: [PhyTag; 12] = [
        PhyTag::VidPid,
        PhyTag::LedGpio,
        PhyTag::LedBrightness,
        PhyTag::Options,
        PhyTag::PresenceTimeout,
        PhyTag::UsbProduct,
        PhyTag::Curves,
        PhyTag::EnabledUsbItf,
        PhyTag::LedDriver,
        PhyTag::LedOrder,
        PhyTag::LedNum,
        PhyTag::UsbManufacturer,
    ];

    /// The tag's wire byte.
    pub const fn byte(self) -> u8 {
        match self {
            PhyTag::VidPid => 0x00,
            PhyTag::LedGpio => 0x04,
            PhyTag::LedBrightness => 0x05,
            PhyTag::Options => 0x06,
            PhyTag::PresenceTimeout => 0x08,
            PhyTag::UsbProduct => 0x09,
            PhyTag::Curves => 0x0A,
            PhyTag::EnabledUsbItf => 0x0B,
            PhyTag::LedDriver => 0x0C,
            PhyTag::LedOrder => 0x0D,
            PhyTag::LedNum => 0x0E,
            PhyTag::UsbManufacturer => 0x0F,
        }
    }

    /// Map a wire byte to a tag, or `None` if the protocol does not define it.
    ///
    /// `None` is not an error condition for *decoding* — see the module docs;
    /// it exists so a caller that wants to enumerate the known tags can, and
    /// so a new tag cannot be added to the enum without a matching byte here.
    pub const fn from_byte(byte: u8) -> Option<PhyTag> {
        Some(match byte {
            0x00 => PhyTag::VidPid,
            0x04 => PhyTag::LedGpio,
            0x05 => PhyTag::LedBrightness,
            0x06 => PhyTag::Options,
            0x08 => PhyTag::PresenceTimeout,
            0x09 => PhyTag::UsbProduct,
            0x0A => PhyTag::Curves,
            0x0B => PhyTag::EnabledUsbItf,
            0x0C => PhyTag::LedDriver,
            0x0D => PhyTag::LedOrder,
            0x0E => PhyTag::LedNum,
            0x0F => PhyTag::UsbManufacturer,
            _ => return None,
        })
    }

    /// The fixed width of this tag's value, or `None` for the two
    /// NUL-terminated strings, whose width follows the text.
    ///
    /// The widths are the length bytes the client's own writer pushes
    /// (`build_rskey_phy_tlv`, `picoforge/src/hal/fido/mod.rs:1015`) — a
    /// literal `tlv.push(0x04)` for VID/PID and curves, `0x02` for options,
    /// `0x01` for every one-byte tag — read back with `u16::from_be_bytes` /
    /// `u32::from_be_bytes` by `read_rskey_physical_config`
    /// (`picoforge/src/hal/fido/mod.rs:940-943`). So this is the client's
    /// table stated as data rather than as prose in a doc comment, which is
    /// what lets the US-116 walk check a width instead of trusting the
    /// encoder that produced the value.
    ///
    /// Stated, not enforced **by the codec itself**: [`encode_record`] takes
    /// any value for any tag, because it is the framing primitive and a future
    /// client tag may widen an existing one. A caller can still hand it
    /// `Options` with a one-byte value and it will encode it.
    ///
    /// ## What reads this table, and what checks against it
    ///
    /// * `tests/phy_tlv.rs::fixed_width_tags_declare_the_width_the_client_writes`
    ///   — the client's widths, checked against this table.
    /// * `vendor41::EMITTED_PHY_TAGS` / `EMITTED_WIDTHS` — the production
    ///   `CONFIG_READ` path derives **both** its CBOR byte-string header
    ///   (`vendor41::phy_record_len`) and its per-record length bytes
    ///   (`vendor41::encode_at`) from this table, through
    ///   [`PhyTag::declared_width`]. US-117 performed that migration; before
    ///   it the two spelled their widths out independently — `record_len(4)` /
    ///   `(1)` / `(1)` / `(2)` on one side, `[0u8; 4]`, `&[v]` and
    ///   `to_be_bytes()` on the other — which is a header free to disagree
    ///   with its own content.
    ///
    /// ## The enforcement that exists, and its limit
    ///
    /// `vendor41::encode_at` carries a `debug_assert_eq!` between a value's
    /// length and `declared_width`. **That is a debug-build check only** — it
    /// compiles out of a release build, and the RP2350 firmware is a release
    /// build. So the honest statement is:
    ///
    /// * in **debug** (host, emulation, `cargo test`), a value whose width
    ///   disagrees with this table aborts the run rather than shipping;
    /// * in **release** (the device), no width is checked at write time. The
    ///   correspondence between header and content rests on both sides
    ///   indexing the *same* `EMITTED_WIDTHS`, not on a comparison.
    ///
    /// What makes that defensible rather than a hole is that the two are
    /// structurally welded rather than merely documented: `EMITTED_WIDTHS` is
    /// indexed by the same `EMITTED_PHY_TAGS` positions the encoder walks, so
    /// they cannot be edited apart without a compile error. On top of that,
    /// `tests/vendor41.rs::phy_read_widths_come_from_the_codec_table` checks
    /// the aggregate — every emitted tag's real reply length against this table
    /// — so a width changed on one side only is caught there. A *per-tag swap*
    /// inside `phy_record_len` that preserved the total would not be, and that
    /// limit is named here rather than left for the next reader to discover.
    pub const fn declared_width(self) -> Option<usize> {
        Some(match self {
            PhyTag::VidPid => 4,
            PhyTag::LedGpio => 1,
            PhyTag::LedBrightness => 1,
            PhyTag::Options => 2,
            PhyTag::PresenceTimeout => 1,
            PhyTag::Curves => 4,
            PhyTag::EnabledUsbItf => 1,
            PhyTag::LedDriver => 1,
            PhyTag::LedOrder => 1,
            PhyTag::LedNum => 1,
            PhyTag::UsbProduct | PhyTag::UsbManufacturer => return None,
        })
    }
}

/// Why a PHY record could not be encoded or decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvError {
    /// A value longer than [`MAX_VALUE_LEN`], which the one-byte length
    /// cannot express.
    ValueTooLong {
        /// The length that was refused.
        got: usize,
    },
    /// A NUL-terminated string longer than [`MAX_NUL_STRING_LEN`].
    ///
    /// A separate variant from [`TlvError::ValueTooLong`] because the two
    /// mean different things to a caller: this one is a *policy* limit the
    /// client imposes on a name that the 255-byte format would have carried
    /// happily, so the fix is to shorten the name, not to grow a buffer. The
    /// name is refused rather than truncated — a truncated name is a
    /// different product string than the one that was asked for.
    StringTooLong {
        /// The name length in text bytes, excluding the NUL.
        got: usize,
    },
    /// The output buffer did not have room for the whole record. Never
    /// reachable for a buffer sized at [`MAX_BLOB_LEN`]; it is here so an
    /// encoder writing straight into a CTAP reply buffer reports overflow
    /// rather than panicking or truncating.
    ///
    /// Nothing is written when this is returned — see [`encode_record`].
    BufferFull,
    /// The input ended between a tag byte and its value, or declared a length
    /// that runs past the end of the input.
    Truncated,
    /// A NUL-terminated string carried a NUL of its own.
    ///
    /// The client's reader takes the whole record value and trims leading and
    /// trailing NULs (`trim_matches(char::from(0))`,
    /// `picoforge/src/hal/fido/mod.rs:963-966`), so an interior NUL is not
    /// removed by that trim — it is carried into the name the host displays.
    /// Refused rather than stripped, because stripping silently changes the
    /// name.
    EmbeddedNul {
        /// Byte offset of the first interior NUL, which is what a caller needs
        /// to say *which* part of the name was wrong.
        at: usize,
    },
}

impl core::fmt::Display for TlvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TlvError::ValueTooLong { got } => {
                write!(f, "PHY record value is {got} bytes; the length is one byte")
            }
            TlvError::StringTooLong { got } => {
                write!(
                    f,
                    "PHY string is {got} bytes; the client's limit is {MAX_NUL_STRING_LEN} \
                     text bytes plus a NUL"
                )
            }
            TlvError::BufferFull => write!(f, "PHY record output buffer is full"),
            TlvError::Truncated => write!(f, "PHY record ended mid-value"),
            TlvError::EmbeddedNul { at } => {
                write!(f, "PHY string contains a NUL at byte {at}")
            }
        }
    }
}

/// How many bytes [`crate::phy_tlv::encode_record`] will append for a value of `len` bytes.
///
/// Exists so a caller can write a CBOR byte-string header (which needs the
/// total length *before* the content) and then stream the records straight
/// into the reply buffer, with no intermediate blob. That two-pass shape is
/// what keeps a 3 KB worst-case record off the RP2350's stack.
pub const fn record_len(len: usize) -> usize {
    2 + len
}

/// Append one `TAG LEN VALUE` record to `out`.
///
/// `out` is a caller-owned buffer rather than a returned [`HeaplessVec`] so
/// the caller decides the capacity — a record destined for a CTAP reply is
/// written straight into the reply.
///
/// # Atomic: the whole record, or none of it
///
/// Capacity is checked **before** anything is written, so a
/// [`TlvError::BufferFull`] leaves `out` byte-for-byte as it was. Pushing the
/// tag and the length and only then discovering the value does not fit would
/// leave a two-byte stub: the caller sees a refusal *and* a corrupted buffer,
/// and in a reply buffer the stub shifts everything after it, so the client's
/// record reader would take the next record at the wrong offset. A partially
/// written record is a worse failure than a clean refusal, and US-115 builds
/// its reply in place through here, so the check is up front.
///
/// Pinned by `tests::a_full_buffer_is_refused_without_writing_a_stub`.
pub fn encode_record<const N: usize>(
    tag: PhyTag,
    value: &[u8],
    out: &mut HeaplessVec<u8, N>,
) -> Result<(), TlvError> {
    if value.len() > MAX_VALUE_LEN {
        return Err(TlvError::ValueTooLong { got: value.len() });
    }
    if out.len() + record_len(value.len()) > N {
        return Err(TlvError::BufferFull);
    }
    out.push(tag.byte()).map_err(|_| TlvError::BufferFull)?;
    out.push(value.len() as u8)
        .map_err(|_| TlvError::BufferFull)?;
    out.extend_from_slice(value)
        .map_err(|_| TlvError::BufferFull)?;
    Ok(())
}

/// Append one NUL-terminated string record — `0x09` product or `0x0F`
/// manufacturer — as the client's writer emits it: the length is
/// `name.len() + 1` and the NUL is **inside** the record, not after it.
///
/// # Why this is a codec function and not a call-site check
///
/// The length byte and the NUL are one fact, and only this function can
/// compute both from one input. In the client's own schema the value is a
/// NUL-terminated field — `build_rskey_phy_tlv` always pushes the terminating
/// `0x00` and counts it in the length
/// (`tlv.push((bytes.len() + 1) as u8); …; tlv.push(0x00);`,
/// `picoforge/src/hal/fido/mod.rs:1076-1079` and `:1093-1096`) — so anything
/// that stores these records has to be able to rely on the terminator being
/// there, not merely on this one client happening to tolerate its absence.
/// That is the invariant: the two must agree, and they are the client's rule
/// as much as the format's.
///
/// Worth being precise about what is *not* the justification, because it is
/// the obvious guess and it is false. The PicoForge FIDO reader would survive
/// a value with no NUL at all: it takes the whole field and trims leading and
/// trailing NULs (`std::str::from_utf8(field_data).trim_matches(char::from(0))`,
/// `picoforge/src/hal/fido/mod.rs:963-966`), so a NUL-free value reads back as
/// exactly the name that was written, with nothing visible on the host. A
/// caller that dropped the NUL would therefore break nothing *in this client*
/// — and would still have produced a field the schema says is terminated.
///
/// Refuses rather than truncates: a shortened product name is a different
/// product name, and the value is 33 bytes at most so the one-byte length has
/// no trouble with it.
///
/// An **empty** name is written as a one-byte value holding just the NUL.
/// The client filters empty names out before writing
/// (`config.product_name.as_deref().filter(|n| !n.is_empty())`,
/// `picoforge/src/hal/fido/mod.rs:1068`), so it never produces this record and
/// a round trip is asymmetric: this function will emit `0x09 0x01 0x00` where
/// the client would have emitted nothing. The asymmetry is harmless on read
/// (the record decodes to the empty string) and is documented rather than
/// refused so that a caller clearing a product name can go through the same
/// path as setting one.
///
/// # The tag is not checked
///
/// `tag` must be [`PhyTag::UsbProduct`] or [`PhyTag::UsbManufacturer`]; the
/// type does not enforce that and neither does a release build, so a
/// `debug_assert` is the whole of the check. Writing a string onto a
/// fixed-width tag is a silent misparse rather than a refusal — for example
/// `0x06` with the two bytes `0x78 0x00` is read back as
/// `u16::from_be_bytes` = `0x7800`, option bits outside
/// [`RESCUE_OPTIONS_MASK`] that this firmware's own `apply_phy_record` would
/// then reject. [`PhyTag::declared_width`] returns `None` for exactly the two
/// string tags, so a caller that wants the check in a release build can ask.
/// US-117, which owns the write path, is where the callers arrive.
pub fn encode_nul_string<const N: usize>(
    tag: PhyTag,
    name: &str,
    out: &mut HeaplessVec<u8, N>,
) -> Result<(), TlvError> {
    debug_assert!(
        matches!(tag, PhyTag::UsbProduct | PhyTag::UsbManufacturer),
        "{tag:?} is not a NUL-terminated string tag; the value would be read \
         back as that tag's fixed-width field"
    );
    if name.len() > MAX_NUL_STRING_LEN {
        return Err(TlvError::StringTooLong { got: name.len() });
    }
    // A NUL inside the name is not removed by the client's trim, which takes
    // leading and trailing NULs only — it would be carried into the host's
    // product name. Refused, not stripped.
    if let Some(at) = name.as_bytes().iter().position(|b| *b == 0) {
        return Err(TlvError::EmbeddedNul { at });
    }
    // A fixed array rather than a `HeaplessVec`: the length guard above has
    // already bounded the name, so there is no capacity error left to handle
    // and no second failure mode to describe. The slice is trimmed to
    // `name.len() + 1` — the array is 33 bytes whatever the name is, and
    // handing the whole array to `encode_record` would pad a short name out
    // to the maximum and write 32 NULs the client cannot tell from content.
    let mut value = [0u8; MAX_NUL_STRING_LEN + 1];
    value[..name.len()].copy_from_slice(name.as_bytes());
    value[name.len()] = 0;
    encode_record(tag, &value[..=name.len()], out)
}

/// A borrowed, zero-allocation reader over a PHY record blob.
///
/// Yields `(tag, value)` pairs. The tag is a raw `u8` and not a [`crate::phy_tlv::PhyTag`]
/// precisely so an unknown tag is passed through rather than refused — the
/// client skips those, and so does this.
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for Decoder<'a> {
    /// `(tag, value)` for each record, or a single [`TlvError::Truncated`].
    type Item = Result<(u8, &'a [u8]), TlvError>;

    /// Decode the next record, or `None` once the blob is consumed.
    ///
    /// There is deliberately no inherent `next` beside this one: an inherent
    /// `next` that shadows [`Iterator::next`] is a wart
    /// `clippy::should_implement_trait` is right about and that a reader
    /// cannot tell apart from the trait method.
    ///
    /// # Errors
    ///
    /// One [`TlvError::Truncated`] — when the blob ends inside a record,
    /// after a tag byte or after a length byte that runs past the end — and
    /// then `None` for ever after, so a `collect::<Result<_, _>>()` over a
    /// truncated blob stops rather than looping. That is the same check the
    /// client's reader makes
    /// (`if i + len > data.len() { break; }`,
    /// `picoforge/src/hal/fido/mod.rs:943`); the difference is that this one
    /// reports it instead of silently returning a short configuration, which
    /// is what a caller writing a *device configuration* must not be allowed
    /// to do.
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        // One tag byte is required; a lone trailing byte is truncation, not an
        // empty record.
        let tag = self.buf[self.pos];
        let len_at = self.pos + 1;
        if len_at >= self.buf.len() {
            self.pos = self.buf.len();
            return Some(Err(TlvError::Truncated));
        }
        let len = self.buf[len_at] as usize;
        let start = len_at + 1;
        let end = match start.checked_add(len) {
            Some(end) if end <= self.buf.len() => end,
            _ => {
                self.pos = self.buf.len();
                return Some(Err(TlvError::Truncated));
            }
        };
        self.pos = end;
        Some(Ok((tag, &self.buf[start..end])))
    }
}

impl<'a> Decoder<'a> {
    /// Start decoding `buf`.
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The framing itself, not the twelve tags: one-byte tag, one-byte
    /// length, no header. US-116's `phy_tlv_roundtrip_all_tags` is the
    /// per-tag walk; this is the shape check it sits on top of.
    #[test]
    fn record_framing_is_one_byte_tag_and_one_byte_length() {
        let mut out: HeaplessVec<u8, 32> = HeaplessVec::new();
        encode_record(PhyTag::LedGpio, &[0x04], &mut out).unwrap();
        assert_eq!(
            out.as_slice(),
            &[0x04, 0x01, 0x04],
            "a PHY record is `tag, len, value` with no header, no terminator \
             and no BER long-form length byte"
        );
        assert_eq!(
            record_len(1),
            3,
            "record_len must agree with what was written"
        );
    }

    /// 255 is representable and 256 is not, because the length is one byte.
    ///
    /// The boundary is the whole reason the format is not BER. An encoder
    /// that wrapped or truncated at 256 would produce a blob the client reads
    /// as a different record.
    #[test]
    fn value_length_ceiling_is_255() {
        // A length in the 16..127 range is where a BER long form would first
        // appear (a `0x81` continuation byte), so that is the case worth
        // pinning and not just the 255 boundary.
        let mid = [0x5Au8; 100];
        let mut mid_out: HeaplessVec<u8, 256> = HeaplessVec::new();
        encode_record(PhyTag::UsbProduct, &mid, &mut mid_out).unwrap();
        assert_eq!(
            &mid_out[..2],
            &[PhyTag::UsbProduct.byte(), 100],
            "a 100-byte value is `0x09, 0x64` — two header bytes, not the \
             three a BER `0x81` continuation would need"
        );
        assert_eq!(mid_out.len(), record_len(100), "and nothing is inserted");

        let max = [0x5Au8; MAX_VALUE_LEN];
        let mut out: HeaplessVec<u8, 512> = HeaplessVec::new();
        encode_record(PhyTag::UsbProduct, &max, &mut out).unwrap();
        assert_eq!(out[1], 0xFF, "255 must encode as a literal 0xFF length");

        let mut out2: HeaplessVec<u8, 512> = HeaplessVec::new();
        assert_eq!(
            encode_record(PhyTag::UsbProduct, &[0x5A; 256], &mut out2),
            Err(TlvError::ValueTooLong { got: 256 }),
            "256 bytes cannot be expressed by a one-byte length, so it must be \
             refused rather than wrapped or truncated"
        );
        assert!(
            out2.is_empty(),
            "a refused record must write nothing at all"
        );
    }

    /// A record that does not fit is refused whole, leaving no stub behind.
    ///
    /// The buffer has room for the two header bytes and not the value, which
    /// is the case a naive "push tag, push length, then extend" encoder gets
    /// wrong: it would leave `tag, len` in the buffer *and* return an error.
    #[test]
    fn a_full_buffer_is_refused_without_writing_a_stub() {
        let mut out: HeaplessVec<u8, 4> = HeaplessVec::new();
        out.push(0xAA).unwrap();
        assert_eq!(
            encode_record(PhyTag::UsbProduct, &[0x41; 3], &mut out),
            Err(TlvError::BufferFull),
            "4 free bytes are fewer than the 5 a 3-byte value needs"
        );
        assert_eq!(
            out.as_slice(),
            &[0xAA],
            "and the pre-existing byte is the only thing left: no tag, no \
             length, nothing for a reader to trip over"
        );
        // The same call with room to spare still works, so the refusal above
        // is about capacity and not about the tag or the value.
        let mut roomy: HeaplessVec<u8, 8> = HeaplessVec::new();
        encode_record(PhyTag::UsbProduct, &[0x41; 3], &mut roomy).unwrap();
        assert_eq!(roomy.as_slice(), &[0x09, 0x03, 0x41, 0x41, 0x41]);
    }

    /// A record stream decodes back to the records that produced it, in order.
    #[test]
    fn decoder_round_trips_what_the_encoder_wrote() {
        let mut out: HeaplessVec<u8, 64> = HeaplessVec::new();
        encode_record(PhyTag::VidPid, &[0x12, 0x09, 0x00, 0x01], &mut out).unwrap();
        encode_record(PhyTag::Options, &[0x00, 0x02], &mut out).unwrap();

        let got: Result<HeaplessVec<(u8, HeaplessVec<u8, 8>), 4>, TlvError> = Decoder::new(&out)
            .map(|r| r.map(|(t, v)| (t, HeaplessVec::from_slice(v).unwrap())))
            .collect();
        assert_eq!(
            got,
            Ok(HeaplessVec::from_slice(&[
                (
                    0x00,
                    HeaplessVec::from_slice(&[0x12, 0x09, 0x00, 0x01]).unwrap()
                ),
                (0x06, HeaplessVec::from_slice(&[0x00, 0x02]).unwrap()),
            ])
            .unwrap()),
            "tag, value, order — the three things a record stream is"
        );
    }

    /// An unknown tag is passed through, because the client steps over it.
    #[test]
    fn decoder_yields_unknown_tags_rather_than_refusing_them() {
        let mut out: HeaplessVec<u8, 16> = HeaplessVec::new();
        // 0x7A is not one of the twelve; the client's reader has a `_ => {}`
        // arm for exactly this.
        out.extend_from_slice(&[0x7A, 0x01, 0xAB]).unwrap();
        encode_record(PhyTag::LedGpio, &[0x04], &mut out).unwrap();
        let got: Result<HeaplessVec<(u8, u8), 4>, TlvError> = Decoder::new(&out)
            .map(|r| r.map(|(t, v)| (t, v[0])))
            .collect();
        assert_eq!(
            got,
            Ok(HeaplessVec::from_slice(&[(0x7A, 0xAB), (0x04, 0x04)]).unwrap()),
            "an unknown tag must be yielded so the records after it still parse"
        );
        assert_eq!(
            PhyTag::from_byte(0x7A),
            None,
            "and it must be outside the enumerated set, or the two assertions \
             above are describing the same tag"
        );
    }

    /// A length that runs past the end is reported, not silently short-read.
    #[test]
    fn decoder_reports_truncation() {
        assert_eq!(
            Decoder::new(&[0x04, 0x04, 0x01]).collect::<Result<HeaplessVec<_, 4>, TlvError>>(),
            Err(TlvError::Truncated),
            "declared 4 bytes, supplied 1 — the client's reader `break`s here \
             and returns a short configuration, which a config *writer* must \
             not be handed"
        );
        assert_eq!(
            Decoder::new(&[0x04]).collect::<Result<HeaplessVec<_, 4>, TlvError>>(),
            Err(TlvError::Truncated),
            "a lone tag byte with no length byte is truncated too"
        );
        assert_eq!(
            Decoder::new(&[]).collect::<Result<HeaplessVec<_, 4>, TlvError>>(),
            Ok(HeaplessVec::new()),
            "an empty blob is an empty record stream, not an error — it is \
             what an all-absent PHY configuration encodes to"
        );
    }
}
