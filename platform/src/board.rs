//! **The selected board**, resolved at build time from
//! `firmware/boards/<board>.toml` (US-1080).
//!
//! # What this module is for
//!
//! Before US-1080, the board was three `pub const` literals in
//! `platform/src/lib.rs` (`LED_PIN = 25`, `BUTTON_PIN = 1`) and four more in
//! `platform/src/identity.rs`, with a host test asserting the literals. That
//! test could not fail: the only way to change the value was to edit the very
//! constant the test asserted. Every number here instead comes from a **data
//! file**, resolved by `platform/build.rs` (which `include!`s
//! `platform/board_def.rs`, the dependency-free parser) and published as
//! `cargo:rustc-env` pairs.
//!
//! The consequence is the whole point of the story: adding a second board is a
//! new `.toml` and a different `FAPICO2_BOARD`, with **no `.rs` edit at all**.
//! `platform/tests/board_def.rs` is the test that holds that promise — it
//! re-parses the selected file and requires the compiled constants to match, so
//! a board file and the binary built from it can no longer disagree.
//!
//! # Why these are `const` and not a runtime lookup
//!
//! `LED_PIN` and `BUTTON_PIN` are `u8` in interrupt handlers and in
//! `embassy_rp::io::Pin::new(pin, ...)`, and `FLASH_SIZE_BYTES` is a
//! `Flash<'static, FLASH, Blocking, N>` const generic parameter. A runtime
//! board struct would cost a lookup in the boot path and a `usize` that is not
//! a const generic. Compiling them away keeps the device image identical in
//! size to the hand-written versions, which matters because the shipping image
//! is three UF2 blocks under a ratcheted flash budget.
//!
//! # The environment contract
//!
//! | variable | set by | meaning |
//! |---|---|---|
//! | `FAPICO2_BOARD` | the operator | a file name under `firmware/boards/`, no extension |
//! | `FAPICO2_BOARD_PATH` | the operator | a path to a board file; **wins** over `FAPICO2_BOARD` |
//! | `PK_BOARD_NAME` | `platform/build.rs` | the resolved `[board] name` |
//! | `PK_LED_PIN` / `PK_BUTTON_PIN` | `platform/build.rs` | the two pins, decimal |
//! | `PK_FLASH_SIZE_KB` | `platform/build.rs` | total flash, decimal KiB |
//!
//! `FAPICO2_BOARD_PATH` exists so a second board can be built **without being
//! added to the repository** — a fork's board, a bring-up part, or a reviewer's
//! reproduction. It is also what makes US-1080's red checkable: the same tree,
//! the same `.rs` files, two boards.

/// Parse a decimal `u8` in const context.
///
/// The values arrive from `env!` as strings, and the two pin constants are
/// `const`, so the conversion has to be a const fn. Panics on a non-digit,
/// because `platform/build.rs` has already rejected that case and a const-eval
/// panic here would be a build failure with a worse message than the good one
/// it replaces.
pub const fn u8_from_env(s: &str) -> u8 {
    let b = s.as_bytes();
    assert!(!b.is_empty(), "board pin value is empty; build.rs validates this first");
    let mut out: u8 = 0;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        assert!(c >= b'0' && c <= b'9', "board pin value is not a decimal integer");
        out = out * 10 + (c - b'0');
        i += 1;
    }
    out
}

/// The `u32` sibling of [`u8_from_env`], for the flash size.
pub const fn u32_from_env(s: &str) -> u32 {
    let b = s.as_bytes();
    assert!(!b.is_empty(), "board flash size is empty; build.rs validates this first");
    let mut out: u32 = 0;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        assert!(c >= b'0' && c <= b'9', "board flash size is not a decimal integer");
        out = out * 10 + (c - b'0') as u32;
        i += 1;
    }
    out
}

/// The board this build was resolved from — the `[board] name` in the selected
/// file, e.g. `pico2`.
///
/// Named in build logs, in the generated `memory.x` header, and by
/// `platform/tests/board_def.rs`.
///
/// The per-board `cfg` is `BOARD_CFG`, not `board_<BOARD_NAME>`: a cfg is an
/// identifier, so the `-` in a board name like `pico2-8m` becomes `_`. See
/// `platform/build.rs` for the mapping, which is a total function of the name,
/// and for why getting it wrong is a build failure rather than a silent
/// mis-branch.
pub const BOARD_NAME: &str = env!("PK_BOARD_NAME");

/// Activity LED GPIO, from the board file.
pub const LED_PIN: u8 = u8_from_env(env!("PK_LED_PIN"));

/// Boot/confirm button GPIO, from the board file.
pub const BUTTON_PIN: u8 = u8_from_env(env!("PK_BUTTON_PIN"));

/// The board file this build actually read, as the build script saw it.
///
/// The *absolute* path, published so `platform/tests/board_def.rs` can re-read
/// the very file rather than guessing which one a name resolved to. A test
/// that guessed would be a test that could pass while the build resolved
/// something else.
pub const BOARD_FILE: &str = env!("PK_BOARD_FILE");

/// Total QSPI flash in KiB, **including** the top-anchored secure reservation.
pub const FLASH_SIZE_KB: u32 = u32_from_env(env!("PK_FLASH_SIZE_KB"));

/// QSPI XIP base — the `FLASH` `ORIGIN` in the generated `memory.x`, and the
/// absolute base every flash address in this tree is measured from.
///
/// US-1010: this is a **silicon** constant, not a board key — every RP2350 in
/// this family maps QSPI at `0x1000_0000` — so it is published from
/// `platform/board_def.rs::FLASH_ORIGIN` (which also renders `memory.x`) rather
/// than written down a third time. It exists here because `firmware/src/boot.rs`
/// used to hold `FLASH_ORIGIN` and `SECURE_ORIGIN` as two literals beside a
/// board-derived `SECURE_PRIMARY_OFFSET`, with nothing linking them: correct
/// for a 4 MiB board, silently wrong for a smaller one. Now
/// `SECURE_ORIGIN = FLASH_ORIGIN + SECURE_PARTITION_OFFSET` and the three
/// cannot disagree.
pub const FLASH_ORIGIN: u32 = u32_from_env(env!("PK_FLASH_ORIGIN"));

/// The reserved secure-partition region in KiB (64 on every board in this
/// family; see `platform/board_def.rs::SECURE_RESERVE_KB` for why it is not a
/// board key).
pub const SECURE_RESERVE_KB: u32 = 64;

/// The app-flash region: total flash minus the secure reservation. This is the
/// `FLASH` `LENGTH` in the `memory.x` that `firmware/build.rs` generates from
/// the same board file.
pub const APP_FLASH_KB: u32 = FLASH_SIZE_KB - SECURE_RESERVE_KB;

/// Total QSPI flash in bytes — the const-generic size parameter of
/// `embassy_rp::flash::Flash`.
pub const FLASH_SIZE_BYTES: usize = (FLASH_SIZE_KB * 1024) as usize;

/// Byte offset of the secure-partition region from the flash base, i.e. the
/// `.secure_partition` section's address in `firmware/src/boot.rs`.
///
/// `0x3F0000` on the 4 MiB `pico2` board, i.e. `0x103F0000` absolute. **This
/// is a provisioned unit's keystore address**: two image slots sized to fill the
/// 64 KiB region live here, and a `.uf2` reflash does not clear them (the store
/// is NOR flash, not RAM). `firmware/src/boot.rs` computes
/// `SECURE_PRIMARY_OFFSET` from this constant, so the board file and the store
/// layout cannot drift apart.
pub const SECURE_PARTITION_OFFSET: u32 = APP_FLASH_KB * 1024;

/// Compile-time cross-checks tying the reservation to the store it exists for.
///
/// `firmware/src/boot.rs` lays out two image slots in the region —
/// `SECURE_SLOT_BYTES` is [`secure_store::rp2350::Rp2350SecureStore::SEALED_
// PARTITION_IMAGE_MAX`] rounded **up** to the 4 KiB NOR erase granularity, and
/// the pair is `2 * SECURE_SLOT_BYTES`. The region has to hold the pair, and
/// `SECURE_RESERVE_KB` has to hold the region's bytes.
///
/// Asserting that here is what links the two numbers that were previously
/// unrelated literals — `64` in this file and `32_768` in `secure_store.rs` —
/// so raising the store's entry ceiling can no longer silently outgrow the
/// reservation. The failure is a compile error naming the region, not a link
/// error nobody reads and not a corrupt store discovered at BOOTSEL.
///
/// The rounding is repeated rather than imported because `FLASH_ERASE_SIZE`
/// is declared in the *firmware* crate, which this crate cannot depend on;
/// `2 * SECURE_SLOT_BYTES <= 64 KiB` is a strictly weaker statement than
/// `SECURE_SLOT_BYTES <= 32 KiB`, so the two agree wherever the store fits at
/// all, and this version cannot rot by disagreeing about the erase size.
///
/// Kept as a `_` item, so it costs nothing in the image.
const _: () = {
    /// The 4 KiB NOR erase granularity the firmware rounds a slot up to.
    const ERASE: usize = 4096;
    const SEALED: usize =
        crate::secure_store::rp2350::Rp2350SecureStore::SEALED_PARTITION_IMAGE_MAX;
    const SLOT: usize = SEALED.div_ceil(ERASE) * ERASE;
    assert!(
        2 * SLOT <= SECURE_RESERVE_KB as usize * 1024,
        "two sealed secure-partition slots no longer fit the reserved region; raise \
         SECURE_RESERVE_KB deliberately and re-derive every already-provisioned unit's \
         keystore address, or shrink the store's entry ceiling"
    );
    assert!(
        SECURE_RESERVE_KB >= 64,
        "the secure-partition region is sized by the two store image slots; shrinking it \
         would truncate a provisioned keystore",
    );
    assert!(
        APP_FLASH_KB > 0,
        "flash_size_kb leaves no app region after the secure reservation; build.rs rejects \
         this, and a board file that got here did not",
    );
    // The reservation is taken off the *top*, so the region's first byte is the
    // byte immediately after the app region and the two can never overlap. If
    // the arithmetic were ever re-derived from the bottom instead, this is the
    // assertion that notices — an overlap here is a keystore that app text can
    // be linked over.
    assert!(
        SECURE_PARTITION_OFFSET == APP_FLASH_KB * 1024
            && SECURE_PARTITION_OFFSET + SECURE_RESERVE_KB * 1024 == FLASH_SIZE_KB * 1024,
        "the secure reservation must be top-anchored: it starts where the app region ends and \
         ends at the top of flash, so no two regions overlap"
    );
};
