// US-1080: the **board definition file** — its parser, its validation, and
// the `memory.x` it generates.
//
// # Why this is a single non-`mod` file, included three times
//
// There are three consumers and no shared crate they can all depend on:
//
//   * `platform/build.rs`  — resolves the selected board into `PK_*` values
//     (the pin constants `platform::board` compiles from, and the USB identity
//     defaults `platform::identity` resolves against).
//   * `firmware/build.rs`  — generates `memory.x` from the same board.
//   * `platform/tests/board_def.rs` — the host test that proves a *second*
//     board file changes the pin and the partition with no `.rs` edit.
//
// A build script cannot depend on a workspace crate (it runs before the crate
// graph is built for it), and a normal `pub mod` in `platform` would pull
// `std::string::String` and the whole parser into the `no_std` device image for
// a function the device never calls. So the file is deliberately **not** a
// module: it is `include!`d by the two build scripts and by the test, and it is
// never compiled into the device library. Consequences, both load-bearing:
//
//   * it must not refer to `crate::`, `super::`, or any item outside itself;
//   * it must be free of `#[cfg]`-gated halves — every item is compiled
//     everywhere it is included, so there is no such thing as an arm-only arm.
//
// # The TOML subset
//
// A real TOML parser is a dependency, and a *build* dependency has to be
// vendored, audited and re-resolved on every toolchain bump. The board file
// has seven keys in two sections, all authored in this repository. A strict
// hand parser is the smaller risk, and it is strict in the direction that
// matters: **every deviation is a hard build failure naming the file and
// line**, never a silent default. A board file that parses to a
// partly-defaulted board is exactly the failure this story exists to remove —
// a device whose LED is on GPIO25 because a key was misspelled.
//
// What the parser accepts, exactly:
//
//   * `# comment` lines and blank lines;
//   * `[board]` and `[usb]` section headers, in any order, each at most once;
//   * `key = value` where `value` is a `"…"` string or a decimal integer;
//   * a trailing `# comment` after a value.
//
// What it rejects: unknown sections, unknown keys, duplicate sections or
// keys, a key before any section, a value with trailing junk, a negative or
// non-decimal integer, a string containing a `"` or a non-ASCII byte, and
// every value that fails the range checks in [`Board::validate`]. Integers
// are **decimal only** — a TOML `0x` literal in a KiB count is a size
// somebody computed wrong, and a base-prefixed count is not a shape worth
// supporting. `vidpid` is a *string* (`"FA20:0002"`), which is the shape
// `platform::identity`'s existing override already takes.
//
// # `memory.x`
//
// [`render_memory_x`] emits the whole linker script, comments included, so the
// generated file is readable on its own in a build directory. The partition
// arithmetic, and why the secure reservation is subtracted from the *top*
// rather than the bottom, is documented on the function.

/// QSPI XIP base. Every RP2350 board in this family maps its flash here, so
/// this is a silicon constant rather than a board choice.
pub const FLASH_ORIGIN: u32 = 0x1000_0000;

/// The data partition: everything below this offset belongs to persistent
/// storage and **must not** be reachable by linking firmware (US-1539).
///
/// On the shipping 4 MiB `pico2` board the layout below it is
///
/// ```text
/// 0x200_000 .. 0x300_000   trussed internal FS (OpenPGP/PIV) 1,024 KiB
/// 0x300_000 .. 0x3F0_000   per-record key store                 960 KiB
/// 0x3F0_000 .. 0x400_000   secure partition                       64 KiB
/// ```
///
/// and above it `0x000_000 .. 0x180_000` is the firmware image, with
/// `0x180_000 .. 0x200_000` of unreferenced growth headroom.
///
/// **Why the linker's reach stops here rather than at the secure partition.**
/// Before US-1539, `FLASH LENGTH` was `app_flash_kb` — everything below the
/// secure reservation — so the linker would have accepted a 3.5 MiB image, and
/// only `check_size_report.py`'s 3.5 MiB ceiling and the CI ratchet's 1,536
/// KiB stood between a link and someone's keystore. Those are gates, and gates
/// are read by the people who read them. Truncating `FLASH` at the data
/// partition makes the overlap a **link error**, which nobody can ship past.
///
/// The secure region is unaffected and must stay exactly where it is: its
/// offset is a provisioned unit's keystore address (see [`SECURE_RESERVE_KB`]).
pub const DATA_PARTITION_OFFSET: u32 = 0x20_0000;

/// The **minimum** per-record key store, in KiB — the shipping `pico2` board's
/// actual size, and the floor a board must not fall below (US-1539; the stride
/// inside the region is derived by US-1540).
///
/// A larger part gets a larger store: [`Board::key_region_kb`] is the
/// remainder after firmware, the trussed window and the secure reservation, so
/// the four regions tile the part exactly on any board. This constant is what
/// that remainder must be **at least**.
pub const KEY_REGION_KB: u32 = 960;

/// The trussed internal-filesystem window, in KiB, at the head of the data
/// partition (US-1536).
pub const TRUSSED_FS_KB: u32 = 1024;

/// The CI flash-budget ratchet in KiB (`FIRMWARE_FLASH_BUDGET_KIB` in
/// `.github/workflows/ci.yml`), mirrored so the generated linker script can
/// print the headroom it leaves.
///
/// **This is a mirror, not the source of truth** — `platform::flashmap` owns
/// `FIRMWARE_FLASH_BUDGET_BYTES`, and `tests/scripts/check_flash_budget.py`
/// compares all three copies (this one included, since 2026-10-07). It is here
/// because this file is compiled into both build scripts without the `platform`
/// crate, so it cannot import the constant.
///
/// That gate is not decoration, and this comment used to claim a check existed
/// while it did not: the constant is read by `Board::validate` and printed into
/// the generated linker script, **nothing compared it to the other two
/// copies**, and it had drifted — 1,536 KiB here against 1,621 KiB in `ci.yml`
/// and `flashmap.rs`. A budget nobody enforced, and a headroom figure that was
/// not the ratchet's. Raise it with
/// `python3 tests/scripts/raise_flash_budget.py <KiB> --reason "..."`, which
/// moves every copy in one step instead of leaving the next reader to find
/// them one red at a time.
pub const FIRMWARE_FLASH_BUDGET_KIB: u32 = 1664;

/// The reserved secure-partition region, in KiB, at the **top** of flash.
///
/// US-388 reserved 64 KiB at `0x103F0000` on a 4 MiB part so the keystore
/// partition can never be reached by growing app text, and the two secure
/// image slots (`firmware/src/boot.rs` `SECURE_PRIMARY_OFFSET` /
/// `SECURE_SHADOW_OFFSET`) are sized to fill it exactly. Two things depend on
/// the region being exactly 64 KiB and pinned to the top: the slot pair is
/// `2 * SECURE_SLOT_BYTES` and a compile-time assertion already holds it under
/// the region; and the secure store's on-flash offsets are computed from the
/// region's offset, so a board with more flash must move the region, never
/// resize it. `[Board::validate]` refuses a board that would leave less than
/// [`MIN_FLASH_SIZE_KB`] of app region.
pub const SECURE_RESERVE_KB: u32 = 64;

/// The smallest `flash_size_kb` this tree will link.
///
/// **US-1539 raised this from 2,048 to 4,096.** The layout now tiles the space
/// between the linker's reach and the secure reservation with two persistent
/// regions — the 1,024 KiB trussed window and the 960 KiB key store — so a
/// smaller part has nowhere to put them. `2,048 + 1,024 + 960 + 64 = 4,096`,
/// and [`validate`] refuses any board whose regions do not exactly fill the
/// space, so this constant states the floor rather than deriving it.
///
/// A future smaller part shrinks the key region or the trussed window
/// deliberately, with a capacity measurement, rather than discovering the
/// problem at BOOTSEL.
pub const MIN_FLASH_SIZE_KB: u32 = 4096;

/// The largest `flash_size_kb` this tree will link. 16 MiB is the largest
/// QSPI part the RP2350 address space and the UF2 window both cover
/// (`firmware/uf2gen.py` `FLASH_END`).
pub const MAX_FLASH_SIZE_KB: u32 = 16 * 1024;

/// SRAM bytes. **Not a board key**, and deliberately so: the RP2350 map is
/// contiguous `0x20000000..0x20082000` (512 K of SRAM banks plus the two
/// 4 KiB scratch banks) on every part in the family, and the value mirrors
/// the C build's `memmap_default.ld`. Making it a board field would invite a
/// board file to claim a part size the silicon does not have.
pub const RAM_ORIGIN: u32 = 0x2000_0000;
/// See [`RAM_ORIGIN`].
pub const RAM_SIZE_BYTES: u32 = 520 * 1024;

/// The ceiling on a USB identity string **including** the NUL both carriers
/// append (the USB string descriptor and the PHY `0x09`/`0x0F` TLV tags).
/// Duplicated from `platform::identity::MAX_IDENTITY_STRING` on purpose: this
/// file is compiled without the `platform` crate, so it cannot import the
/// constant, and a board file that a build script accepts but the descriptor
/// cannot carry is a board file that produces an un-flashable identity. The
/// test in `platform/tests/board_def.rs` asserts the two agree.
pub const MAX_IDENTITY_STRING: usize = 32;

/// The highest GPIO number an RP2350 pad can be. GPIO30/31 are the debug pins
/// and are not brought out.
pub const MAX_GPIO: u8 = 29;

/// One fully-resolved board definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Board {
    /// The board's name, as written in the file (`[board] name`).
    pub name: String,
    /// Activity LED GPIO.
    pub led_pin: u8,
    /// Boot/confirm button GPIO.
    pub button_pin: u8,
    /// Total QSPI flash in KiB, **including** the secure reservation.
    pub flash_size_kb: u32,
    /// USB vendor id.
    pub vid: u16,
    /// USB product id.
    pub pid: u16,
    /// USB `iProduct`.
    pub product: String,
    /// USB `iManufacturer`.
    pub manufacturer: String,
}

impl Board {
    /// The app-flash region: total flash minus the top-anchored secure
    /// reservation. This is the `FLASH` `LENGTH` in the generated linker
    /// script and the flash window the UF2 generator's page loop must stay
    /// inside.
    pub fn app_flash_kb(&self) -> u32 {
        self.flash_size_kb - SECURE_RESERVE_KB
    }

    /// Byte offset of the secure-partition region from [`FLASH_ORIGIN`].
    ///
    /// **This is the value that must never be mis-derived.** For the shipping
    /// 4 MiB `pico2` board it is `0x3F0000`, i.e. `0x103F0000` absolute — the
    /// same address the hand-written `memory.x` carried before US-1080, and
    /// the same address `firmware/src/boot.rs` bakes into
    /// `SECURE_PRIMARY_OFFSET`. A provisioned unit's whole keystore lives in
    /// the two slots there; a board file that moved the region would leave
    /// that store unreadable rather than merely misplaced.
    pub fn secure_offset(&self) -> u32 {
        self.app_flash_kb() * 1024
    }

    /// The per-record key store for **this** board, in KiB.
    ///
    /// Derived as the remainder so the four regions *exactly tile* the part —
    /// firmware, trussed window, key region, secure reservation. A larger part
    /// therefore gets a larger key store rather than a gap, which is the right
    /// answer for both reasons: the spare flash is capacity (more resident
    /// credentials, which is what US-1540 derives from the region), and an
    /// exact tiling is what makes "no two regions overlap" a checkable
    /// statement rather than a hope.
    ///
    /// The trussed window does **not** scale: it is a fixed 1 MiB because it
    /// carries OpenPGP and PIV material, which is bounded by key size rather
    /// than by part size.
    pub fn key_region_kb(&self) -> u32 {
        self.flash_size_kb
            - (DATA_PARTITION_OFFSET / 1024)
            - TRUSSED_FS_KB
            - SECURE_RESERVE_KB
    }

    /// Absolute origin of the secure-partition region.
    pub fn secure_origin(&self) -> u32 {
        FLASH_ORIGIN + self.secure_offset()
    }

    /// Total flash in bytes.
    pub fn flash_size_bytes(&self) -> u32 {
        self.flash_size_kb * 1024
    }
}

/// Why a board file was refused. `String`, because every case is a message the
/// operator has to read, and a build script's only output is text.
pub type BoardError = String;

/// Parse a board file.
///
/// `label` is the file's identity as the caller knows it (a path, or
/// `<string>` for a literal fixture) and appears in every error, so a refusal
/// names the file rather than a bare line number.
pub fn parse(label: &str, src: &str) -> Result<Board, BoardError> {
    let mut board_name: Option<String> = None;
    let mut led_pin: Option<u8> = None;
    let mut button_pin: Option<u8> = None;
    let mut flash_size_kb: Option<u32> = None;
    let mut vidpid: Option<String> = None;
    let mut product: Option<String> = None;
    let mut manufacturer: Option<String> = None;
    let mut seen_sections: Vec<&str> = Vec::new();
    let mut section = "";

    for (idx, raw) in src.lines().enumerate() {
        let lineno = idx + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let name = rest
                .strip_suffix(']')
                .ok_or_else(|| err(label, lineno, format!("section header is not closed: {line:?}")))?;
            let name = name.trim();
            if name != "board" && name != "usb" {
                return Err(err(
                    label,
                    lineno,
                    format!(
                        "unknown section [{name}]; this build reads [board] and [usb] only — \
                         an unrecognised section is a typo, not something to ignore"
                    ),
                ));
            }
            if seen_sections.contains(&name) {
                return Err(err(
                    label,
                    lineno,
                    format!("section [{name}] appears twice; every value is single-valued"),
                ));
            }
            seen_sections.push(name);
            section = name;
            continue;
        }
        if section.is_empty() {
            return Err(err(
                label,
                lineno,
                format!("key {line:?} appears before any [section] header"),
            ));
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| err(label, lineno, format!("expected `key = value`, got {line:?}")))?;
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() {
            return Err(err(label, lineno, format!("key `{key}` has no value")));
        }
        match (section, key) {
            ("board", "name") => set_once(&mut board_name, unquote(label, lineno, value)?, label, lineno, key)?,
            ("board", "led_pin") => {
                set_once(&mut led_pin, parse_int(label, lineno, key, value)? as u8, label, lineno, key)?
            }
            ("board", "button_pin") => {
                set_once(&mut button_pin, parse_int(label, lineno, key, value)? as u8, label, lineno, key)?
            }
            ("board", "flash_size_kb") => {
                set_once(&mut flash_size_kb, parse_int(label, lineno, key, value)?, label, lineno, key)?
            }
            ("usb", "vidpid") => set_once(&mut vidpid, unquote(label, lineno, value)?, label, lineno, key)?,
            ("usb", "product") => set_once(&mut product, unquote(label, lineno, value)?, label, lineno, key)?,
            ("usb", "manufacturer") => {
                set_once(&mut manufacturer, unquote(label, lineno, value)?, label, lineno, key)?
            }
            (sec, k) => {
                return Err(err(
                    label,
                    lineno,
                    format!(
                        "unknown key `{k}` in section [{sec}]; every key this build reads is \
                         spelled out in the error for its section, and an unknown key would \
                         otherwise be silently dropped"
                    ),
                ))
            }
        }
    }

    let board = Board {
        name: require(label, "board.name", board_name)?,
        led_pin: require(label, "board.led_pin", led_pin)?,
        button_pin: require(label, "board.button_pin", button_pin)?,
        flash_size_kb: require(label, "board.flash_size_kb", flash_size_kb)?,
        vid: 0,
        pid: 0,
        product: require(label, "usb.product", product)?,
        manufacturer: require(label, "usb.manufacturer", manufacturer)?,
    };
    let vidpid = require(label, "usb.vidpid", vidpid)?;
    let (vid, pid) = parse_vid_pid(label, &vidpid)?;
    let board = Board { vid, pid, ..board };
    validate(label, &board)?;
    Ok(board)
}

fn set_once<T>(slot: &mut Option<T>, value: T, label: &str, lineno: usize, key: &str) -> Result<(), BoardError> {
    if slot.is_some() {
        return Err(err(label, lineno, format!("key `{key}` appears twice")));
    }
    *slot = Some(value);
    Ok(())
}

fn require<T>(label: &str, key: &str, slot: Option<T>) -> Result<T, BoardError> {
    slot.ok_or_else(|| {
        err(
            label,
            0,
            format!(
                "required key `{key}` is missing; a board file that omits a value would link \
                 a board nobody declared"
            ),
        )
    })
}

/// Drop a `#` comment, honouring `"` so a `#` inside a string survives.
///
/// The strings in a board file are USB descriptor names, and `#` is a legal
/// character in one. Stripping naively would turn `product = "a#b"` into
/// `"a`, which then fails as an unterminated string — a confusing message for
/// a valid file.
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
    }
    line
}

fn unquote(label: &str, lineno: usize, value: &str) -> Result<String, BoardError> {
    let inner = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or_else(|| {
            err(
                label,
                lineno,
                format!("string values must be double-quoted, got {value:?}"),
            )
        })?;
    if inner.contains('"') {
        return Err(err(
            label,
            lineno,
            format!("string {value:?} contains a nested `\"`; escapes are not supported"),
        ));
    }
    Ok(inner.to_string())
}

fn parse_int(label: &str, lineno: usize, key: &str, value: &str) -> Result<u32, BoardError> {
    if !value.bytes().all(|b| b.is_ascii_digit()) || value.is_empty() {
        return Err(err(
            label,
            lineno,
            format!(
                "`{key}` must be a plain decimal integer with no sign, separator or base \
                 prefix, got {value:?}"
            ),
        ));
    }
    value.parse::<u32>().map_err(|_| {
        err(
            label,
            lineno,
            format!("`{key}` value {value:?} does not fit in 32 bits"),
        )
    })
}

/// Split a `VVVV:PPPP` (or `0xVVVV:0xPPPP`) pair.
///
/// The same shape `platform::identity`'s `FAPICO2_VID_PID` override takes, and
/// deliberately the same parser semantics, so a value copied from one place
/// works in the other.
pub fn parse_vid_pid(label: &str, s: &str) -> Result<(u16, u16), BoardError> {
    let mut halves = s.split(':');
    let vid_s = halves.next().unwrap_or_default();
    let pid_s = halves.next().unwrap_or_default();
    if halves.next().is_some() {
        return Err(err(label, 0, format!("vidpid must be `VVVV:PPPP`, got {s:?}")));
    }
    let vid = hex16(label, "vid", vid_s)?;
    let pid = hex16(label, "pid", pid_s)?;
    Ok((vid, pid))
}

fn hex16(label: &str, what: &str, s: &str) -> Result<u16, BoardError> {
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err(
            label,
            0,
            format!("vidpid {what} half must be exactly 4 hex digits, got {s:?}"),
        ));
    }
    u16::from_str_radix(digits, 16)
        .map_err(|_| err(label, 0, format!("vidpid {what} half {s:?} does not parse")))
}

/// The range and shape checks a board must pass before it is linked.
///
/// Every rule here has a failure that would otherwise be silent: an
/// out-of-range pin drives a pad that does not exist, a flash size below the
/// floor links an image that cannot be flashed, and an over-long identity
/// string is accepted by the build script and then cannot be framed by the
/// USB descriptor or the PHY TLV.
fn validate(label: &str, b: &Board) -> Result<(), BoardError> {
    if b.name.is_empty()
        || !b
            .name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
    {
        return Err(err(
            label,
            0,
            format!(
                "board name {:?} must be non-empty [a-z0-9_-]; the name becomes the `cfg` and \
                 the build-directory name, so it has to be a filename",
                b.name
            ),
        ));
    }
    if b.led_pin > MAX_GPIO {
        return Err(err(
            label,
            0,
            format!("led_pin {} is above the highest pad GPIO{MAX_GPIO}", b.led_pin),
        ));
    }
    if b.button_pin > MAX_GPIO {
        return Err(err(
            label,
            0,
            format!("button_pin {} is above the highest pad GPIO{MAX_GPIO}", b.button_pin),
        ));
    }
    if b.flash_size_kb < MIN_FLASH_SIZE_KB {
        return Err(err(
            label,
            0,
            format!(
                "flash_size_kb {} is below the {MIN_FLASH_SIZE_KB} KiB floor; after the \
                 {SECURE_RESERVE_KB} KiB secure reservation this board would have less flash \
                 than the shipping image occupies",
                b.flash_size_kb
            ),
        ));
    }
    if b.flash_size_kb > MAX_FLASH_SIZE_KB {
        return Err(err(
            label,
            0,
            format!(
                "flash_size_kb {} is above the {MAX_FLASH_SIZE_KB} KiB ceiling (the RP2350 \
                 address space / UF2 window)",
                b.flash_size_kb
            ),
        ));
    }
    // US-1539: the data partition's three regions must tile the space between
    // the linker's reach and the secure reservation exactly. An overlap is a
    // key store the firmware can be linked over; a gap is flash nothing can
    // use. Both are refused at parse time, on the board file that caused them,
    // rather than discovered on a board.
    let data_kb = DATA_PARTITION_OFFSET / 1024;
    let key_kb = b.key_region_kb();
    if key_kb < KEY_REGION_KB {
        return Err(err(
            label,
            0,
            format!(
                "a {}-KiB part leaves a {key_kb} KiB key region, below the {KEY_REGION_KB} \
                 KiB the shipping layout needs (firmware {data_kb} + trussed {TRUSSED_FS_KB} \
                 + key region {KEY_REGION_KB} + secure {SECURE_RESERVE_KB} = {min}). A \
                 smaller part has to shrink a region deliberately, with a capacity \
                 measurement — not silently",
                b.flash_size_kb,
                min = data_kb + TRUSSED_FS_KB + KEY_REGION_KB + SECURE_RESERVE_KB
            ),
        ));
    }
    if data_kb <= FIRMWARE_FLASH_BUDGET_KIB {
        return Err(err(
            label,
            0,
            format!(
                "the data partition starts at {data_kb} KiB, which is not above the \
                 {FIRMWARE_FLASH_BUDGET_KIB} KiB CI flash budget. A firmware image the \
                 ratchet accepts could reach the trussed filesystem and the key region; \
                 move DATA_PARTITION_OFFSET up, or lower the budget deliberately"
            ),
        ));
    }
    for (what, s) in [("product", &b.product), ("manufacturer", &b.manufacturer)] {
        if s.is_empty() {
            return Err(err(label, 0, format!("usb.{what} must not be empty")));
        }
        if let Some(bad) = s.chars().find(|c| !c.is_ascii()) {
            return Err(err(
                label,
                0,
                format!(
                    "usb.{what} contains the non-ASCII character {bad:?}; a USB string \
                     descriptor is UTF-16 on the wire and a non-ASCII name does not survive \
                     every host's parser"
                ),
            ));
        }
        // +1 for the NUL, matching `MAX_IDENTITY_STRING` and `phy_tlv`.
        if s.len() + 1 > MAX_IDENTITY_STRING {
            return Err(err(
                label,
                0,
                format!(
                    "usb.{what} is {} bytes including the trailing NUL; the limit is \
                     {MAX_IDENTITY_STRING} on both the descriptor and the PHY TLV path",
                    s.len() + 1
                ),
            ));
        }
    }
    Ok(())
}

fn err(label: &str, lineno: usize, msg: String) -> BoardError {
    if lineno == 0 {
        format!("{label}: {msg}")
    } else {
        format!("{label}:{lineno}: {msg}")
    }
}

/// Render the whole linker script for `b`.
///
/// # The partition arithmetic
///
/// The secure reservation is taken off the **top** of flash, so for a board of
/// `F` KiB:
///
/// ```text
/// FLASH  ORIGIN = 0x10000000         LENGTH = (F - 64)K
/// SECURE ORIGIN = 0x10000000 + (F-64)K  LENGTH = 64K
/// ```
///
/// For the shipping `pico2` board (`F` = 4096) that is `LENGTH = 4032K` at
/// `0x10000000` and `ORIGIN = 0x103F0000` — byte-identical to the hand-written
/// `memory.x` this replaced, which is the property that keeps every already
/// provisioned unit's secure store readable.
///
/// Two constraints ride on this and neither is negotiable:
///
/// * The region stays **exactly** 64 KiB. `firmware/src/boot.rs` lays out two
///   image slots that fill it, and `platform::secure_store`'s compile-time
///   assertion holds that pair under the region. A board file cannot resize it;
///   it can only move it, and moving it is what a larger part does.
/// * `FLASH` `LENGTH` **excludes** the region, so linker overflow is an error
///   rather than a silent overlap of app text with the keystore.
///
/// The `.text` anchor and the `.start_block` placement below are the US-391
/// workarounds, carried over verbatim: the RP2350 bootrom only scans the first
/// 4 KiB for the IMAGE_DEF, and 256-byte UF2 blocks must not straddle it.
pub fn render_memory_x(b: &Board) -> String {
    let secure_origin = b.secure_origin();
    // US-1539: the linker's reach stops at the data partition, so firmware
    // cannot be linked into the trussed window or the key region even in
    // principle. `app_kb` is still what places SECURE at the top, and that
    // value must not move.
    let link_kb = DATA_PARTITION_OFFSET / 1024;
    let trussed_origin = FLASH_ORIGIN + DATA_PARTITION_OFFSET;
    let key_region_kb = b.key_region_kb();
    let key_region_origin = trussed_origin + TRUSSED_FS_KB * 1024;
    format!(
        "\
/* GENERATED by firmware/build.rs from the board file — do not edit, and do not
 * check it in. Source of truth: {board} (led GPIO{led}, button GPIO{button},
 * {flash} KiB flash). US-1080 replaced a hand-written memory.x with this; the
 * partition arithmetic and the two US-391 anchor comments below are the same
 * ones it carried. */
MEMORY {{
    /* Firmware: the first {link} KiB of a {flash} KiB part. US-1539 truncated
     * this at the data partition rather than at the secure reservation, so a
     * firmware image that grows into a persistent region is a **link error**
     * rather than something only a CI gate stands between. The shipping image
     * measures ~818 KiB and the CI ratchet admits {budget} KiB, leaving
     * {headroom} KiB of headroom above the ratchet.
     * On this board the data partition starts at {data:#010x}. */
    FLASH : ORIGIN = {flash_origin:#010x}, LENGTH = {link}K
    /* The data partition, in three regions. All three are read-only in the
     * linker and none of them is written by the shipping UF2: erased flash is
     * 0xFF, and these windows hold whatever the device programmed into them.
     *
     * TRUSSED is littlefs2 for OpenPGP and PIV, formatted by the trussed
     * backend rather than linked. KEYREGION is the per-record key store
     * (US-1539/US-1540), written by the flash driver at applet time and never
     * linked. SECURE is the two image slots the keystore lives in
     * (`firmware/src/boot.rs`); `main.rs` links the secure-partition image into
     * `.secure_partition` and the driver programs the runtime snapshot back. */
    TRUSSED (r) : ORIGIN = {trussed:#010x}, LENGTH = {trussed_kb}K
    KEYREGION (r) : ORIGIN = {key_region:#010x}, LENGTH = {key_kb}K
    SECURE (r) : ORIGIN = {secure:#010x}, LENGTH = {reserve}K
    /* SRAM per the RP2350 SDK address map — all of it is contiguous and mapped
     * on every part in the family:
     *   SRAM0-3  0x20000000..0x20040000 (256 K)
     *   SRAM4-7  0x20040000..0x20080000 (256 K)
     *   SRAM8/9  0x20080000..0x20082000 (scratch X/Y, 4 K each)
     * {ram} K mirrors the C build's memmap_default.ld, whose initial SP is
     * 0x20082000. */
    RAM   : ORIGIN = {ram_origin:#010x}, LENGTH = {ram}K
}}

SECTIONS {{
    /* The per-record key store: the address space the region occupies, reserved
     * so nothing can be linked into it. (NOLOAD) because erased flash is 0xFF,
     * the shipping UF2 must not pre-bake the region, and crt0's zero/copy
     * ranges must stay untouched. */
    .key_region (NOLOAD) : {{
        KEEP(*(.key_region))
    }} > KEYREGION

    /* The secure-partition image: erased flash is 0xFF (an empty store); boot
     * reads the keystore directly from here. (NOLOAD) for the same reasons. */
    .secure_partition (NOLOAD) : {{
        KEEP(*(.secure_partition))
    }} > SECURE
}}

/* The RP2350 bootrom only scans the first 4 KiB of flash for the PICOBIN block
 * loop (BLOCK_LIST_SEARCH_MAX); the default orphan placement leaves
 * .start_block (the IMAGE_DEF) past the end of .text, so the bootrom never
 * finds a bootable image and falls back to BOOTSEL. Anchor the IMAGE_DEF
 * immediately after the vector table (word-aligned, inside the scan window),
 * and move .text past it: cortex-m-rt computes .text's address from _stext,
 * and our PROVIDE wins over link.x's. .text starts 256-byte aligned so the UF2
 * generator's blocks never straddle the IMAGE_DEF. */
PROVIDE(_stext = ORIGIN(FLASH) + 0x200);
SECTIONS {{
    .start_block : {{
        KEEP(*(.start_block))
    }} > FLASH
}} INSERT AFTER .vector_table;
",
        board = b.name,
        led = b.led_pin,
        button = b.button_pin,
        flash = b.flash_size_kb,
        flash_origin = FLASH_ORIGIN,
        reserve = SECURE_RESERVE_KB,
        link = link_kb,
        data = DATA_PARTITION_OFFSET,
        trussed = trussed_origin,
        trussed_kb = TRUSSED_FS_KB,
        key_region = key_region_origin,
        key_kb = key_region_kb,
        budget = FIRMWARE_FLASH_BUDGET_KIB,
        headroom = link_kb - FIRMWARE_FLASH_BUDGET_KIB,
        secure = secure_origin,
        ram_origin = RAM_ORIGIN,
        ram = RAM_SIZE_BYTES / 1024,
    )
}
