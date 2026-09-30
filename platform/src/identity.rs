//! **The device identity block** — everything that decides which product this
//! firmware claims to be, resolved once at compile time.
//!
//! Four values, all overridable at build time by a fork, all with a published
//! default:
//!
//! | constant | wire | default | override variable |
//! |---|---|---|---|
//! | [`AAGUID`] | CTAP2.1 getInfo key `0x03` | [`DEFAULT_AAGUID`] | `FAPICO2_AAGUID_HEX` |
//! | [`MANUFACTURER`] | USB iManufacturer | the board file's `usb.manufacturer` | `FAPICO2_MANUFACTURER` |
//! | [`PRODUCT`] | USB iProduct | the board file's `usb.product` | `FAPICO2_PRODUCT` |
//! | [`VID`] / [`PID`] | USB `idVendor` / `idProduct` | the board file's `usb.vidpid` | `FAPICO2_VID_PID` |
//!
//! The three USB defaults moved from literals here to
//! `firmware/boards/<board>.toml` in **US-1080**; the AAGUID did not, for the
//! reason documented on [`DEFAULT_AAGUID`]. "Default" therefore means *the
//! selected board's declaration*, and the override variables are a per-build
//! experiment on top of it — see `platform/build.rs` for the precedence.
//!
//! They live in `platform` rather than in an app crate because `platform` is
//! the only crate every participant depends on: the USB descriptor is built
//! here, and `fapico2-fido` re-exports [`AAGUID`] for the CTAP2 layer. A
//! device whose descriptor and whose getInfo disagreed on a name would be a
//! worse bug than either being hardcoded.
//!
//! # Why an AAGUID default that is ours, and why it used not to be
//!
//! fapico2 borrowed RS-Key's AAGUID, `2479C7BF6B3056839EC80E8171A918B7`.
//! PicoForge exact-matches getInfo key `0x03` against a three-entry profile
//! table, so without a match fapico2 falls through to the pico-fido profile —
//! the one profile under which the app does **not** offer OpenPGP, hiding a
//! fully working applet. The borrow made the device usable and was always
//! meant to be temporary (EPIC `PICOForge-COMPAT` §3.2, risk R-3).
//!
//! [`DEFAULT_AAGUID`] is now fapico2's own: the ASCII bytes `fapico2` followed
//! by a version word, in the style the project used before the borrow. It
//! reads recognisably in a hex dump and in `lsusb`/`pcsc_scan` output, which
//! matters when you are trying to tell two tokens in a bag apart.
//!
//! **Consequence, stated plainly:** until PicoForge adds this AAGUID to
//! `firmwares/mod.rs`, a default build is *unclassifiable* by the app and
//! lands back on the pico-fido profile — the exact problem the borrow solved.
//! The intended sequence is: build with `FAPICO2_AAGUID_HEX=2479C7BF…` to
//! develop against the current app, publish the default, and have upstream
//! add it. A development override and a published default are different jobs,
//! which is why both exist; do not confuse them.
//!
//! # Changing the default later is not free
//!
//! The AAGUID is the leading 16 bytes of every attested credential blob, so
//! flipping it invalidates every existing passkey RP→AAGUID binding on every
//! deployed device. It is a one-line change here, but it is a *one-way* one
//! once devices exist. That is the reason the value is a named constant with
//! a stated derivation rather than a literal buried in a table.

/// The published default AAGUID: the ASCII bytes of `fapico2`.
///
/// ```text
/// 66 61 70 69 63 6F 32 00  00 00 00 00 00 00 00 02
///  f  a  p  i  c  o  2  NUL                      v2
/// ```
///
/// The trailing `0x02` is a **version word**, not padding: bump it if the
/// project's identity is ever redefined, so two distinct identities are never
/// confusable. The `0x00` after the ASCII is the CTAP convention for a
/// non-printable trailing byte and keeps the first eight readable as a word.
///
/// **Not a board key, and deliberately so.** The AAGUID is the leading 16 bytes
/// of every attested credential blob, so it is a *product* constant with a
/// one-way history (see "Changing the default later is not free" above), not a
/// property of a bag of components. Letting a board file restate it would let
/// a second board silently re-identify every passkey already enrolled on the
/// first. A board that genuinely needs a different AAGUID builds with
/// `FAPICO2_AAGUID_HEX`.
pub const DEFAULT_AAGUID: [u8; 16] = [
    0x66, 0x61, 0x70, 0x69, 0x63, 0x6F, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];

/// The ceiling on a USB identity string, **including** the NUL both carriers
/// append: the USB string descriptor, and the PHY `0x09`/`0x0F` TLV tags.
///
/// One number for all three, deliberately. The build script validates an
/// override against it, `phy_tlv` sizes its records with it, and the FIDO crate
/// bounds its stored copy with it — three consumers of a *wire* limit that
/// would each restate it if not told. A name that the descriptor accepted and
/// the config path could not frame is a record that cannot be written back.
///
/// The value is the client's own (`picoforge/src/hal/rescue/ops.rs:456`), so
/// anything longer is refused by the app before it reaches the wire.
pub const MAX_IDENTITY_STRING: usize = 32;

/// The USB manufacturer (`iManufacturer`) an **unoverridden** build advertises.
///
/// US-1080: this is `usb.manufacturer` in the selected
/// `firmware/boards/<board>.toml` (`pico2` = `The BLOCO Community`), published
/// by `platform/build.rs`. It was a literal here before, which meant a second
/// board could not have its own name without a source edit.
///
/// The value is 19 ASCII bytes, so the carrier's NUL puts it at 20 — inside
/// [`MAX_IDENTITY_STRING`], which is the constraint that would otherwise have
/// bitten: a name that the descriptor accepts but the rescue `0x0F` TLV cannot
/// frame is a name the operator can set and never read back.
pub const DEFAULT_MANUFACTURER: &str = env!("PK_BOARD_MANUFACTURER");

/// The USB product (`iProduct`) an **unoverridden** build advertises —
/// `usb.product` in the selected board file (`pico2` = `fapico2`).
pub const DEFAULT_PRODUCT: &str = env!("PK_BOARD_PRODUCT");

/// The USB vendor ID an **unoverridden** build advertises — `usb.vidpid` in
/// the selected board file.
///
/// **Provisional.** `0xFA20` is not a USB-IF-registered vendor ID. It is the
/// default because it is what every unit in the field already enumerates as,
/// and because changing it is an operator-visible identity change. A release
/// intended for sale needs a registered VID, which is now a **data change** in
/// the board file (or a `FAPICO2_VID_PID` override for a single build) rather
/// than a source edit — see [`VID`].
pub const DEFAULT_VID: u16 = select_vid_pid(env!("PK_BOARD_VID_PID"), (0, 0)).0;

/// The USB product ID an **unoverridden** build advertises — see [`DEFAULT_VID`].
pub const DEFAULT_PID: u16 = select_vid_pid(env!("PK_BOARD_VID_PID"), (0, 0)).1;

// ---------------------------------------------------------------------------
// Compile-time resolution
//
// Everything below runs in const context — no allocator, no `std` — so the
// `no_std` device build and the host build resolve to the identical constants.
// The build script has already rejected malformed values; reaching a panic
// here means a value bypassed that validation.
// ---------------------------------------------------------------------------

/// Parse a 32-hex-character string into its 16 bytes. Case-insensitive;
/// panics (a compile-time const-eval error) on a wrong length or a non-hex
/// character.
pub const fn aaguid_from_hex(s: &str) -> [u8; 16] {
    let b = s.as_bytes();
    assert!(
        b.len() == 32,
        "AAGUID must be 32 hex characters (16 bytes); build.rs validates this first",
    );
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = (hex_nibble(b[i * 2]) << 4) | hex_nibble(b[i * 2 + 1]);
        i += 1;
    }
    out
}

/// One ASCII hex digit as its value; panics on anything else.
const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("AAGUID contains a non-hex character; build.rs validates this first"),
    }
}

/// The 16-bit value of the four hex digits at `start`, case-insensitive.
const fn u16_from_hex_at(b: &[u8], start: usize) -> u16 {
    assert!(
        b.len() >= start + 4,
        "each VID/PID half must be 4 hex digits; build.rs validates this first",
    );
    ((hex_nibble(b[start]) as u16) << 12)
        | ((hex_nibble(b[start + 1]) as u16) << 8)
        | ((hex_nibble(b[start + 2]) as u16) << 4)
        | (hex_nibble(b[start + 3]) as u16)
}

/// The index just past a leading `0x`/`0x` at `i`, or `i` itself.
///
/// Taking and returning indices rather than `&str` slices is not a style
/// choice: range-indexing a `&str` is not const-callable on this toolchain
/// (`Index` is not a const trait), so the whole parser is written over the
/// byte slice. Slicing a `&[u8]` *is* const, but keeping one mechanism is
/// worth more than saving a bracket.
const fn skip_0x(b: &[u8], i: usize) -> usize {
    if i + 1 < b.len() && b[i] == b'0' && (b[i + 1] == b'x' || b[i + 1] == b'X') {
        i + 2
    } else {
        i
    }
}

/// Split a `VVVV:PPPP` (or `0xVVVV:0xPPPP`) override at its colon, dropping an
/// optional `0x` from each half, and return `(vid, pid)`.
const fn parse_vid_pid(s: &str) -> (u16, u16) {
    let b = s.as_bytes();
    let mut colon = b.len();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b':' {
            colon = i;
            break;
        }
        i += 1;
    }
    assert!(colon < b.len(), "VID:PID needs exactly one colon");
    let vid = u16_from_hex_at(b, skip_0x(b, 0));
    let pid = u16_from_hex_at(b, skip_0x(b, colon + 1));
    (vid, pid)
}

// Precedence, for every value in the block: a non-empty override wins, an
// empty one falls back to the published default.
//
// The empty branch exists **only** to serve `build.rs`'s "unset ⇒ publish the
// empty string" convention, so `env!` never needs a cfg fork. It is not a
// supported way to ask for the default: build.rs rejects a *set but empty*
// value as malformed, because `FAPICO2_PRODUCT=` is almost always a mistake —
// a shell template that rendered nothing, a CI variable that resolved empty —
// and quietly reading that as "use the default" would ship a product claiming
// an identity the operator believed they had replaced. **Unset is the default;
// set-but-empty is an error.**

/// Resolve the AAGUID from its build-time override string.
pub const fn select_aaguid(override_hex: &str) -> [u8; 16] {
    if override_hex.is_empty() {
        DEFAULT_AAGUID
    } else {
        aaguid_from_hex(override_hex)
    }
}

/// Resolve a USB identity string from its build-time override.
///
/// One lifetime for both parameters, which is what lets the return be elided
/// without ambiguity — and is also the truth about the call sites, where both
/// come from `env!` and are therefore `'static`.
pub const fn select_string<'a>(override_str: &'a str, default: &'a str) -> &'a str {
    if override_str.is_empty() {
        default
    } else {
        override_str
    }
}

/// Resolve the USB VID:PID from its build-time override.
pub const fn select_vid_pid(override_str: &str, default: (u16, u16)) -> (u16, u16) {
    if override_str.is_empty() {
        default
    } else {
        parse_vid_pid(override_str)
    }
}

// ---------------------------------------------------------------------------
// The resolved values
// ---------------------------------------------------------------------------

/// The AAGUID this build serves: the raw bytes of CTAP2.1 getInfo key `0x03`
/// and the leading 16 bytes of every attested credential data blob.
///
/// # Build-time override
///
/// Defaults to [`DEFAULT_AAGUID`]. To build against a client whose table still
/// carries the borrowed identity, set `FAPICO2_AAGUID_HEX` to 32 hex characters
/// (case-insensitive, no separators, no `0x` prefix):
///
/// ```text
/// FAPICO2_AAGUID_HEX=2479C7BF6B3056839EC80E8171A918B7 cargo build --release -p fapico2-firmware
/// ```
///
/// A malformed or wrong-length override is a **hard build failure**, never a
/// silent fallback. Setting the variable to the empty string counts as
/// malformed: only *unset* means "use the default".
pub const AAGUID: [u8; 16] = select_aaguid(env!("FAPICO2_AAGUID_HEX"));

/// The USB manufacturer string this build advertises.
pub const MANUFACTURER: &str =
    select_string(env!("FAPICO2_MANUFACTURER"), DEFAULT_MANUFACTURER);

/// The USB product string this build advertises.
pub const PRODUCT: &str = select_string(env!("FAPICO2_PRODUCT"), DEFAULT_PRODUCT);

/// The USB vendor ID this build advertises.
pub const VID: u16 = select_vid_pid(env!("FAPICO2_VID_PID"), (DEFAULT_VID, DEFAULT_PID)).0;

/// The USB product ID this build advertises.
pub const PID: u16 = select_vid_pid(env!("FAPICO2_VID_PID"), (DEFAULT_VID, DEFAULT_PID)).1;

// Test-visible echoes of what the build script saw. Each is the empty string
// when the variable was unset, which is how a test tells a default build from
// an overridden one.
/// The AAGUID override exactly as the build script saw it; empty when unset.
pub const AAGUID_OVERRIDE_HEX: &str = env!("FAPICO2_AAGUID_HEX");
/// The manufacturer override as the build script saw it; empty when unset.
pub const MANUFACTURER_OVERRIDE: &str = env!("FAPICO2_MANUFACTURER");
/// The product override as the build script saw it; empty when unset.
pub const PRODUCT_OVERRIDE: &str = env!("FAPICO2_PRODUCT");
/// The VID:PID override as the build script saw it; empty when unset.
pub const VID_PID_OVERRIDE: &str = env!("FAPICO2_VID_PID");

/// The whole identity this build advertises on the USB bus, in one value.
///
/// Exists because the descriptor is the only consumer and it needs all four
/// together, and because a *single* accessor is the honest shape for "what
/// does this firmware claim to be" — four independent constants invite a
/// future caller to read three of them and invent the fourth.
///
/// It is also ungated and host-buildable, which `usb` is not, so the value is
/// observable from a host test. That is a side benefit, not the reason: a
/// reader who wants the VID should not have to compile for `arm` to find out
/// what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbIdent {
    /// `idVendor`.
    pub vid: u16,
    /// `idProduct`.
    pub pid: u16,
    /// `iManufacturer`.
    pub manufacturer: &'static str,
    /// `iProduct`.
    pub product: &'static str,
}

/// The identity this build advertises.
pub const fn usb_ident() -> UsbIdent {
    UsbIdent { vid: VID, pid: PID, manufacturer: MANUFACTURER, product: PRODUCT }
}

/// Whether this build is a **default** one — no identity override in effect.
///
/// The counterpart to the echoes above, in the form tests actually branch on.
/// A test that pins a *default* must consult this rather than failing with a
/// misleading "wrong name" message when the build was configured.
pub const DEFAULT_BUILD: bool = AAGUID_OVERRIDE_HEX.is_empty()
    && MANUFACTURER_OVERRIDE.is_empty()
    && PRODUCT_OVERRIDE.is_empty()
    && VID_PID_OVERRIDE.is_empty();

/// Cargo's `HOST` triple — the platform the build-script executable runs on,
/// as opposed to `TARGET`, the platform this crate is being compiled for.
///
/// Published so the end-to-end override test can name a *host* triple when it
/// shells out to a real `cargo build`; hardcoding one would be wrong the day
/// the test is run under a different toolchain.
pub const HOST_BUILD_TARGET: &str = env!("FAPICO2_PLATFORM_HOST_TARGET");

/// The build script rejected a set-but-malformed override and published the
/// reason. Fail the build loudly here rather than shipping a
/// silently-defaulted identity — rustc cannot attribute a const-eval panic
/// back to the build script, so this is what carries the reason through.
#[cfg(fapico2_identity_invalid)]
const _: () = {
    // Each arm names its own variable; at most one is ever true.
    if !AAGUID_OVERRIDE_HEX.is_empty() {
        panic!(concat!(
            "FAPICO2_AAGUID_HEX is set but malformed: ",
            env!("FAPICO2_AAGUID_HEX_ERROR"),
            " — unset it to use fapico2's published default AAGUID"
        ));
    }
    if !MANUFACTURER_OVERRIDE.is_empty() {
        panic!(concat!(
            "FAPICO2_MANUFACTURER is set but malformed: ",
            env!("FAPICO2_MANUFACTURER_ERROR"),
            " — unset it to use the published default"
        ));
    }
    if !PRODUCT_OVERRIDE.is_empty() {
        panic!(concat!(
            "FAPICO2_PRODUCT is set but malformed: ",
            env!("FAPICO2_PRODUCT_ERROR"),
            " — unset it to use the published default"
        ));
    }
    if !VID_PID_OVERRIDE.is_empty() {
        panic!(concat!(
            "FAPICO2_VID_PID is set but malformed: ",
            env!("FAPICO2_VID_PID_ERROR"),
            " — unset it to use the published default"
        ));
    }
};
