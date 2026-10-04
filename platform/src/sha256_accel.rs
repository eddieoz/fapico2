//! US-1569 — the RP2350 **hardware SHA-256 engine**, driven from Rust.
//!
//! # Why this exists
//!
//! The RP2350 has a SHA-256 block in hardware at `0x400f_8000`
//! (`rp-pac` `rp235x/mod.rs:163`, from the SVD's `<name>SHA256</name>` +
//! `<baseAddress>0x400f8000</baseAddress>`). **All five reference
//! implementations ignore it** — `pico-sdk/src/rp2_common/pico_sha256/` exists
//! and is not called by any of them, and there is **no `embassy-rp` module for
//! it at all** (`embassy-rp` 0.10.0's `src/` tree has no `sha256.rs`; the only
//! `SHA256` mentions are in `trng.rs` and `block.rs`, neither a driver). So the
//! register block is reached here by hand, through `rp-pac`.
//!
//! **This is a performance control, not a security control.** It exists to make
//! US-1570 (raising `PIN_VERIFIER_ROUNDS` by an order of magnitude) affordable
//! in wall-clock terms. The digest it produces is byte-for-byte SHA-256 or
//! nothing: the compression is the block's, and everything this module does is
//! padding, block assembly and byte ordering — all of which is differentially
//! tested against `sha2` in `platform/tests/sha256_accel.rs`.
//!
//! # What the block is, and is not
//!
//! The RP2350 block is a **compression-function accelerator with no message
//! schedule and no FIFO of its own**. It takes 512-bit blocks and maintains
//! the chaining state internally. It does **not** pad a message, does **not**
//! track the message length, and does **not** know what a SHA-256 message is.
//! That is stated three ways in the datasheet text that `rp-pac` carries on
//! the registers themselves:
//!
//! * `WDATA` — *"Software is responsible for ensuring the data is correctly
//!   padded and terminated to a whole number of 512-bit blocks."*
//!   (`rp-pac` `src/rp235x/sha256/regs.rs`, the `WDATA` field description,
//!   verbatim from `svd/rp235x.svd`)
//! * `CSR.SUM_VLD` — *"Contents are undefined when CSR_SUM_VLD is 0."*
//!   (the `SUM0..SUM7` descriptions)
//! * `START` — *"internal counters are cleared"*, i.e. the block keeps no
//!   length of its own to clear.
//!
//! # Layering: the logic is separate from the registers, and that is the whole
//! testability argument
//!
//! This module is two layers with one interface between them:
//!
//! ```text
//!   hash_into(msg, bit_len, sink)          <- pure: block assembly + padding
//!        |  (BlockSink: begin / push / finish)
//!        v
//!   Sha256Accel (target_arch = "arm")      <- registers: START, WDATA, SUM0..7
//! ```
//!
//! [`hash_into`] is target-agnostic, `no_std`, allocation-free and has no
//! `rp_pac` in it. It is the whole of the part that can be *wrong in
//! interesting ways* — the padding boundary, the length encoding, the block
//! split — and it is what the differential test drives. [`BlockSink`] is the
//! seam: it is exactly the three operations the hardware performs (`CSR.START`,
//! sixteen `WDATA` writes, `SUM0..SUM7`), so a sink that implements the trait
//! faithfully gets the digest right and a sink that does not gets an error.
//!
//! **The register layer itself is unexercised without hardware.** There is no
//! RP2350 in this loop and none of the three interfaces below can be simulated:
//! `CSR`/`WDATA`/`SUM0..SUM7` are volatile memory-mapped registers, and there is
//! no host model of the compression. So the strongest claim this module makes
//! is: *the logic is tested, the register writes are reviewed*. That is stated
//! again in "What is measured and what is not" at the bottom.
//!
//! # The register names in the story brief are RP2040's, not RP2350's
//!
//! Worth writing down, because getting it wrong is how a driver ends up
//! addressing registers that do not exist. The brief lists `CS`, `DCTRL`,
//! `DCNT`, `DIGEST0..7`, `DIGEST_LEN`, `SUFO` and `ERFO`. **None of those are
//! in the RP2350 block.** What is there (`svd/rp235x.svd`, `<name>SHA256</name>`,
//! address block size 40 = `0x28`) is:
//!
//! | offset | register | role |
//! |---|---|---|
//! | `0x00` | `CSR` | `START`, `WDATA_RDY`, `SUM_VLD`, `ERR_WDATA_NOT_RDY`, `DMA_SIZE`, `BSWAP` |
//! | `0x04` | `WDATA` | the message-schedule feed, write-only |
//! | `0x08`–`0x24` | `SUM0` … `SUM7` | the 256-bit chaining state |
//!
//! and the error condition is a **single bit**, `CSR.ERR_WDATA_NOT_RDY`, not
//! the `SUFO`/`ERFO` pair of newer Cortex-M SHA peripherals. That is the whole
//! "fall back cleanly" surface, and it is smaller than the brief assumed.
//! `rp-pac` exposes them as `rp_pac::SHA256.csr()`, `.wdata()`, `.sum0()` …
//! `.sum7()` (`src/rp235x/sha256.rs`), all `const`, all at `0x400f_8000`.
//!
//! `CSR` resets to `0x0000_1206` (`svd/rp235x.svd`, `CSR`/`resetValue`): bit 1
//! `WDATA_RDY`, bit 2 `SUM_VLD`, bit 9 `DMA_SIZE = 0b10` (**32-bit**) and bit 12
//! `BSWAP = 1`. So both of the settings this driver needs are the reset values —
//! which is worth knowing, because a driver that read `BSWAP` back and only set
//! it when clear would be relying on a reset state it never asked for.
//!
//! # DMA: `TREQ_SEL`, and not `DREQ`
//!
//! The second surprise, and the one most likely to produce a channel that
//! silently never transfers. The RP2350 DMA channel **has no `DREQ` field**.
//! `CHx_CTRL` (the PAC's `ctrl_trig`) carries `TREQ_SEL` at bits 22:17 instead
//! (`svd/rp235x.svd`, `CTRL`/`TREQ_SEL`: *"Select a Transfer Request signal …
//! 0x0 to 0x3a -> select DREQ n as TREQ"*), and the SHA-256 block is
//! `TreqSel::SHA256 = 0x36` (`rp-pac` `src/rp235x/dma/vals.rs`). So the
//! handshake is `CTRL.TREQ_SEL = SHA256` plus `CTRL.EN`, not the RP2040's
//! `channel_config_set_dreq(DREQ_SHA256)`.
//!
//! The **polled path is the default**, and deliberately so. A DMA channel is a
//! shared, implicitly-owned resource: the RP2350 arbitrates channels through
//! `PERIORS`, which **`rp-pac` 7.0.0 does not publish at all** (`grep -c
//! PERIORS src/rp235x/mod.rs` → 0), so this driver cannot take an ownership
//! token for a channel the way `drbg_seed` takes one for the TRNG. Rather than
//! invent an allocator this crate cannot test, [`Sha256Accel::polled`] takes
//! nothing and the DMA constructor takes an explicit channel index from the
//! caller, who owns the contention.
//!
//! # Failure is an error, never a digest
//!
//! The one rule this module states twice, because it is the rule that matters:
//! **a broken accelerator must produce a distinguishable failure, never a
//! plausible-looking hash.** A `SUM0..SUM7` read taken when `SUM_VLD` is low is
//! undefined — the datasheet says so on the register itself — so reading it and
//! handing it back is not "degraded hashing", it is a *fabricated* digest that
//! will be compared against an HMAC and accepted. Every wait here is bounded
//! and every one of them ends in [`Sha256Error`], not in a value:
//!
//! | what went wrong | error | why it is not a digest |
//! |---|---|---|
//! | block never left reset | [`Sha256Error::Unavailable`] | `CSR` reads as reset, so nothing written to it was ever hashed |
//! | `WDATA` written while `WDATA_RDY` was low | [`Sha256Error::WroteWhileNotReady`] | the block dropped the words; `pico-sdk` `assert`s on this (`pico_sha256/sha256.c:81`) |
//! | `SUM_VLD` never rose within the poll budget | [`Sha256Error::DigestNotValid`] | `SUM0..SUM7` are undefined; see above |
//! | channel reported `READ_ERROR`/`WRITE_ERROR`/`AHB_ERROR` | [`Sha256Error::DmaError`] | the source was not delivered to the block |
//! | message longer than 2^61 − 1 bytes | [`Sha256Error::TooLong`] | a truncated 64-bit length field is a *different hash*, not a shorter message |
//!
//! # The 2^61-byte boundary
//!
//! SHA-256's length field is **64 bits** of *bits*, so the largest encodable
//! message is 2^61 − 1 bytes. A `(msg.len() as u64) * 8` silently wraps at 2^64
//! bits — 2^61 bytes — and produces a well-formed digest of a *different*
//! message. [`Sha256Accel::hash`] refuses rather than wraps, and [`hash_into`]
//! takes `bit_len` as an explicit argument so that the conversion is the
//! caller's to check rather than an implicit multiply buried in a loop. The
//! boundary itself is not reachable from a test (a 2^61-byte `&[u8]` does not
//! exist on this host), which is the same reason `sha512.rs` reaches its own
//! counter directly.
//!
//! # What is measured and what is not
//!
//! **Measured here:** block assembly and padding, differentially against stock
//! `sha2` over empty / 1-byte / 63 / 64 / 65 / multi-block inputs and over
//! every tail residue 0..64, with the errors surfaced rather than absorbed.
//!
//! **Not measured here:** anything about the register layer — that `START` is a
//! strobe, that `WDATA` needs 16 words and then 57 cycles, that `BSWAP` is on
//! at reset, that the DMA `TREQ_SEL` handshake works. None of it was executed.
//! What it has instead is a citation per register into the PAC and into
//! `pico-sdk/src/rp2_common/hardware_sha256/`, and the reference C driver's
//! ordering copied rather than reinvented. US-1571's hardware BDD is where this
//! belongs; nothing here should be read as claiming the engine has been seen
//! work.

/// SHA-256 block size in bytes (FIPS 180-4 §6.2.1). Also the DMA transfer
/// width in the word path, and the reason [`Block`] is 4-byte aligned.
pub const SHA256_BLOCK_LEN: usize = 64;

/// SHA-256 digest size in bytes.
pub const SHA256_DIGEST_LEN: usize = 32;

/// The size of the message-length field SHA-256 appends: 64 bits.
pub const SHA256_LENGTH_FIELD_LEN: usize = 8;

/// Largest number of 512-bit blocks a SHA-256 *tail* can occupy: one when the
/// remainder leaves room for the `0x80` byte and the length field, two when it
/// does not. `64 − 1 − 8 = 55`, so a remainder of 0..=55 fits in one block and
/// 56..=63 forces a second.
pub const SHA256_MAX_TAIL_BLOCKS: usize = 2;

/// One 512-bit SHA-256 block.
///
/// `#[repr(align(4))]` is **load-bearing**, not decoration: the DMA path hands
/// this buffer's address to a channel configured `CTRL_DATA_SIZE = WORD`, and
/// an unaligned source address is an `AHB_ERROR`/`READ_ERROR` on the RP2350 DMA
/// rather than a slower transfer. A bare `[u8; 64]` has alignment 1, so the
/// wrapper is what makes the address safe to DMA from.
#[repr(align(4))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block(pub [u8; SHA256_BLOCK_LEN]);

impl Block {
    /// A zeroed block.
    pub const ZERO: Block = Block([0u8; SHA256_BLOCK_LEN]);

    /// The block's bytes as a fixed-size slice, for callers that want the
    /// contents rather than the address.
    pub const fn as_bytes(&self) -> &[u8; SHA256_BLOCK_LEN] {
        &self.0
    }

    /// The block's bus address, guaranteed 4-byte aligned by `repr(align(4))`,
    /// for a word-wide DMA source register.
    ///
    /// Not `const`: a pointer-to-integer cast is not permitted in a constant
    /// expression, and a `const` here would buy nothing — this is only ever
    /// called on the DMA path, with a block already in memory.
    pub fn dma_addr(&self) -> usize {
        self.0.as_ptr() as usize
    }
}

/// Serialise eight chaining words into a 32-byte **big-endian** digest.
///
/// This is the only step between what the block computes and what a SHA-256
/// digest is, and it is a byte-order decision rather than arithmetic, which is
/// why it gets its own tested function. `pico-sdk` makes the identical one:
/// `hardware_sha256/sha256.c:11` byte-swaps `sha256_hw->sum[i]` when the caller
/// asked for `SHA256_BIG_ENDIAN`, which is the only mode that is a SHA-256
/// digest.
///
/// # Panics
///
/// None. This is a total function over all `[u32; 8]`, so the caller cannot be
/// handed a wrong answer for an in-range input — the only way to get the wrong
/// digest is to call it with the wrong words, which is the block's fault and
/// is what [`BlockSink::finish`] reports as an error.
pub const fn digest_from_words(words: [u32; SHA256_DIGEST_LEN / 4]) -> [u8; SHA256_DIGEST_LEN] {
    let mut out = [0u8; SHA256_DIGEST_LEN];
    let mut i = 0;
    while i < SHA256_DIGEST_LEN {
        out[i] = (words[i / 4] >> (24 - 8 * (i % 4))) as u8;
        i += 1;
    }
    out
}

/// Build the 1-or-2 block padded tail for a SHA-256 message.
///
/// `tail` is the message's bytes after the last **whole** block — so
/// `tail.len() < 64` — and `bit_len` is the *whole* message's length in bits,
/// not this tail's. `out` receives one block (`len == 64`) or two
/// (`len == 128`); the padding is FIPS 180-4 §5.1.1:
///
/// ```text
///   msg  |  0x80  |  zero * k  |  bit_len as 8 big-endian bytes
/// ```
///
/// with the length field at the end of the **last** block, which is why a
/// 56..=63 remainder costs two blocks and not one. `pico-sdk` derives the same
/// number independently, as
/// `(total + 9 + 63) & !63` (`pico_sha256/sha256.c:161`), and the differential
/// test asserts both agree.
///
/// `out` is fully written, including the zeros, so a caller may hand every one
/// of the `len` bytes to a block sink without tracking which were padding.
pub fn padding_blocks(
    tail: &[u8],
    bit_len: u64,
    out: &mut [u8; SHA256_MAX_TAIL_BLOCKS * SHA256_BLOCK_LEN],
) -> usize {
    out.fill(0);
    // A caller that passed a whole block here would have had it hashed twice
    // (once by `hash_into`'s whole-block loop, once as padding). Not reachable
    // from `hash_into`; the assertion is for direct callers.
    debug_assert!(tail.len() < SHA256_BLOCK_LEN);

    out[..tail.len()].copy_from_slice(tail);
    out[tail.len()] = 0x80;

    let first = SHA256_BLOCK_LEN - SHA256_LENGTH_FIELD_LEN;
    if tail.len() + 1 + SHA256_LENGTH_FIELD_LEN <= SHA256_BLOCK_LEN {
        out[first..SHA256_BLOCK_LEN].copy_from_slice(&bit_len.to_be_bytes());
        SHA256_BLOCK_LEN
    } else {
        let second = 2 * SHA256_BLOCK_LEN - SHA256_LENGTH_FIELD_LEN;
        out[second..].copy_from_slice(&bit_len.to_be_bytes());
        2 * SHA256_BLOCK_LEN
    }
}

/// The three things the RP2350 SHA-256 block actually does.
///
/// Implemented by [`Sha256Accel`] on device. It is a public trait so that the
/// block-assembly logic in [`hash_into`] can be driven — and *checked* — by a
/// sink that is not the silicon; see
/// `platform/tests/sha256_accel.rs`.
///
/// The methods map one-for-one onto the hardware:
///
/// | method | hardware |
/// |---|---|
/// | [`begin`](BlockSink::begin) | write `CSR.START`, clear `CSR.ERR_WDATA_NOT_RDY` |
/// | [`push`](BlockSink::push) | wait `CSR.WDATA_RDY`, then sixteen `WDATA` word writes |
/// | [`finish`](BlockSink::finish) | wait `CSR.SUM_VLD`, then read `SUM0..SUM7` |
///
/// A conforming implementation must return `Err` — never a digest — if any of
/// those three steps did not happen.
pub trait BlockSink {
    /// What this sink reports when the hardware did not do what was asked.
    type Error;

    /// Prepare the accelerator for a new checksum.
    fn begin(&mut self) -> Result<(), Self::Error>;

    /// Feed one 512-bit block. Called with `msg`/`tail` blocks in order.
    fn push(&mut self, block: &Block) -> Result<(), Self::Error>;

    /// Wait for and return the digest. Called exactly once, after the last
    /// [`push`](BlockSink::push).
    fn finish(&mut self) -> Result<[u8; SHA256_DIGEST_LEN], Self::Error>;
}

/// Hash `msg`, declaring its length to be `bit_len` **bits** (SHA-256's own
/// unit), by driving `sink`.
///
/// This is the whole of the driver's logic: the SHA-256 compression belongs to
/// the accelerator, and everything else — where the block boundary falls, the
/// `0x80`, the zeroes, the big-endian length field, whether a second tail
/// block is needed — happens here, in a target-agnostic and allocation-free
/// function that the differential test can reach without an RP2350.
///
/// `bit_len` is a **separate argument** from `msg` because it is the one
/// quantity that can overflow: a caller whose message arrived in chunks has no
/// `&[u8]` as long as the message to hand in. [`Sha256Accel::hash`] computes
/// it from `msg.len()` and refuses rather than wraps (see [`Sha256Error::TooLong`]).
///
/// Cost: one 64-byte working block and one 128-byte tail on the stack, both
/// reused across the loop. Nothing is allocated and nothing is `'static`.
pub fn hash_into<S: BlockSink>(
    msg: &[u8],
    bit_len: u64,
    sink: &mut S,
) -> Result<[u8; SHA256_DIGEST_LEN], S::Error> {
    sink.begin()?;

    // SHA256_BLOCK_LEN is a power of two (64), so this truncates rather than
    // divides — and it is the same expression the RP2040 SDK's SHA-256 uses to
    // find the last whole block (`pico_sha256/sha256.c:122`).
    let whole = msg.len() & !(SHA256_BLOCK_LEN - 1);

    let mut block = Block::ZERO;
    for chunk in msg[..whole].chunks(SHA256_BLOCK_LEN) {
        block.0.copy_from_slice(chunk);
        sink.push(&block)?;
    }

    let mut tail = [0u8; SHA256_MAX_TAIL_BLOCKS * SHA256_BLOCK_LEN];
    let tail_len = padding_blocks(&msg[whole..], bit_len, &mut tail);
    for padded in tail[..tail_len].chunks(SHA256_BLOCK_LEN) {
        block.0.copy_from_slice(padded);
        sink.push(&block)?;
    }

    sink.finish()
}

/// The device driver: the RP2350 SHA-256 register block at `0x400f_8000`.
///
/// Only built on `thumbv8m.main-none-eabi` with the `device` feature — the
/// arm-gated `rp-pac` dependency (`platform/Cargo.toml`, the `[target.'cfg(target_arch
/// = "arm")'.dependencies]` block) is what the register layer needs, and no
/// host build resolves it. Everything in this `mod` is `core` only.
#[cfg(all(feature = "device", target_arch = "arm"))]
mod device {
    use core::hint::spin_loop;

    use super::{
        Block, BlockSink, SHA256_BLOCK_LEN, SHA256_DIGEST_LEN, digest_from_words, hash_into,
    };
    use rp_pac::dma::vals::{DataSize, TransCountMode, TreqSel};
    use rp_pac::sha256::vals::DmaSize;

    /// Poll budget for `CSR.WDATA_RDY`.
    ///
    /// The datasheet puts the gap at 57 cycles (`CSR.WDATA_RDY` description:
    /// *"After writing 16 words, this flag will go low for 57 cycles whilst the
    /// core completes its digest."*), i.e. ~0.38 µs on a 150 MHz RP2350. Each
    /// iteration of the loop below is a volatile read plus the comparison, so
    /// this is a ceiling on *iterations*, not on time — 1024 is a ~18x margin
    /// over the documented figure even in the worst case where the loop body is
    /// two cycles. It exists because `pico-sdk`'s wait is unbounded
    /// (`hardware_sha256/include/hardware/sha256.h:152-157`, a bare
    /// `while (!sha256_is_ready())`), and an unbounded wait on a peripheral
    /// that failed to come out of reset is a device that never answers.
    pub const WDATA_RDY_MAX_POLLS: u32 = 1024;

    /// Poll budget for `CSR.SUM_VLD` and for `RESETS.RESET_DONE.SHA256`. Same
    /// reasoning as [`WDATA_RDY_MAX_POLLS`] — the same 57-cycle gap, and a
    /// reset that never completes is the "accelerator is absent" case this
    /// whole module is required to be able to report.
    pub const SUM_VLD_MAX_POLLS: u32 = 1024;

    /// The reset bit for the SHA-256 block: `RESETS.RESET.SHA256`, bit 18
    /// (`svd/rp235x.svd`, the `<name>SHA256</name>` field of the `RESETS`
    /// peripheral). **`RESETS.RESET` resets to `0x1fff_ffff`, so bit 18 is set
    /// and the block is held in reset out of power-on.** Anything that does not
    /// clear it first is writing to a register that does not latch.
    pub const SHA256_RESET_BIT: u32 = 1 << 18;

    /// Everything this driver can refuse.
    ///
    /// Every variant is a *detectable* failure. None of them is a degraded
    /// digest, and there is no variant that means "here is the hash anyway" —
    /// see the module docs, "Failure is an error, never a digest".
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Sha256Error {
        /// The block never left reset: `RESETS.RESET_DONE.SHA256` was still
        /// low after [`SUM_VLD_MAX_POLLS`] polls of a request to clear
        /// `RESETS.RESET.SHA256`.
        ///
        /// This is the "accelerator is absent" case — a part where the block is
        /// not clocked or not present — and it is reported rather than worked
        /// around, because every subsequent read would return `CSR`'s reset
        /// value and every subsequent write would be discarded.
        Unavailable,
        /// A 64-byte block was written to `WDATA` while `CSR.WDATA_RDY` was
        /// low, so the block did not take it. `CSR.ERR_WDATA_NOT_RDY` is set in
        /// that case, and `pico-sdk` `assert`s on it (`pico_sha256/sha256.c:81`).
        ///
        /// The digest of whatever the block *did* absorb is not this driver's
        /// answer; a partial write is not a short message.
        WroteWhileNotReady,
        /// `CSR.SUM_VLD` never rose within [`SUM_VLD_MAX_POLLS`] polls.
        ///
        /// `SUM0..SUM7` are documented "undefined when CSR_SUM_VLD is 0"
        /// (the register descriptions in `svd/rp235x.svd`), so there is nothing
        /// to read and this must not become a digest.
        DigestNotValid,
        /// The DMA channel reported `READ_ERROR`, `WRITE_ERROR` or `AHB_ERROR`.
        /// The source was not delivered to `WDATA`, so the block hashed
        /// something else.
        DmaError,
        /// The message does not fit SHA-256's 64-bit bit-length field, i.e. it
        /// is 2^61 bytes or longer. Refused rather than wrapped: a truncated
        /// length field is a valid-looking digest of a *different* message.
        TooLong,
    }

    /// The RP2350 hardware SHA-256 accelerator.
    ///
    /// Construct with [`polled`](Sha256Accel::polled) (the default, and what
    /// most callers want) or [`with_dma`](Sha256Accel::with_dma).
    ///
    /// The struct is two bytes of state. It holds no buffer, no message, and no
    /// partial hash, which is what lets it be created per operation on the
    /// stack — the same discipline as [`crate::drbg_seed::TrngProbe`], which
    /// takes a per-operation hardware resource and returns it.
    #[derive(Clone, Copy, Debug)]
    pub struct Sha256Accel {
        /// DMA channel index, or `None` for the polled path.
        dma_chan: Option<u8>,
    }

    impl Sha256Accel {
        /// A driver that feeds `WDATA` from the CPU, polling `CSR.WDATA_RDY`
        /// before each 64-byte block.
        ///
        /// **This is the default for a reason.** A DMA channel is an implicitly
        /// owned shared resource, and the RP2350's `PERIORS` arbitration — which
        /// is what would let this driver *prove* it owns one, the way
        /// `embassy_rp::Peri` proves it for the TRNG — is **not published by
        /// `rp-pac` 7.0.0** (no `PERIORS` in `src/rp235x/mod.rs`). Taking a
        /// channel index from the caller is the honest form: the caller owns
        /// the contention, and this driver cannot silently take a channel that
        /// something else is using. If the polled path is fast enough on the
        /// board, it is also the one that cannot be wrong that way.
        pub const fn polled() -> Self {
            Self { dma_chan: None }
        }

        /// A driver that feeds `WDATA` through DMA channel `chan`
        /// (`0..=15`, the count `rp_pac::DMA`'s `ch(n)` asserts).
        ///
        /// The caller is responsible for `chan` not being in use by anything
        /// else — see [`polled`](Sha256Accel::polled) for why this driver
        /// cannot take that responsibility itself. The channel is configured
        /// here, once, and reprogrammed per block exactly as
        /// `dma_channel_configure` does in `pico_sha256/sha256.c:83-91`.
        ///
        /// `CTRL.TREQ_SEL` is set to `TreqSel::SHA256` — the RP2350 has no
        /// `CTRL.DREQ` field, so the RP2040's
        /// `channel_config_set_dreq(cfg, DREQ_SHA256)` has no counterpart here;
        /// `TreqSel::SHA256 = 0x36` is the same selection in the register that
        /// exists (`rp-pac` `src/rp235x/dma/vals.rs`).
        pub const fn with_dma(chan: u8) -> Self {
            Self {
                dma_chan: Some(chan),
            }
        }

        /// Hash `msg` with the hardware accelerator, one shot.
        ///
        /// Returns `Err` for every way the engine can fail to produce a digest;
        /// see [`Sha256Error`] and the module docs. It never returns a digest it
        /// is not confident in.
        ///
        /// # Errors
        ///
        /// [`Sha256Error::TooLong`] if `msg` is 2^61 bytes or longer — the
        /// point at which `(len as u64) * 8` would wrap the 64-bit length field
        /// and produce the digest of a different message. The check is `checked`
        /// on both halves rather than a cast, so it cannot be optimised into
        /// the wrap it exists to prevent.
        ///
        /// Plus whatever the block or the channel reports; see [`Sha256Error`].
        pub fn hash(&mut self, msg: &[u8]) -> Result<[u8; SHA256_DIGEST_LEN], Sha256Error> {
            let bit_len = u64::try_from(msg.len())
                .ok()
                .and_then(|n| n.checked_mul(8))
                .ok_or(Sha256Error::TooLong)?;
            hash_into(msg, bit_len, self)
        }
    }

    impl BlockSink for Sha256Accel {
        type Error = Sha256Error;

        /// `pico_sha256/sha256.c:39-66` (`pico_sha256_try_start`), in its order:
        /// bring the block out of reset, clear any stale
        /// `ERR_WDATA_NOT_RDY`, set `BSWAP` and `DMA_SIZE`, then pulse `START`.
        ///
        /// `START` is a write strobe — *"Write 1 to prepare the SHA-256 core for
        /// a new checksum … internal counters are cleared"* — so it is written
        /// last and alone in its own write. Writing it also "immediately forces
        /// `WDATA_RDY` and `SUM_VLD` high", which is what makes a failed hash
        /// leave nothing behind for the next one: `begin` re-asserts both, so a
        /// caller that takes [`Sha256Error`] on block *n* and retries still
        /// starts from the SHA-256 IV.
        fn begin(&mut self) -> Result<(), Sha256Error> {
            self.ensure_unreset()?;

            if let Some(chan) = self.dma_chan {
                let ch = rp_pac::DMA.ch(chan as usize);
                // Trans count first, with the channel disabled: 16 word
                // transfers is one 512-bit block, and the CSR_DMA_SIZE=32bit
                // setting makes the block request exactly 16 of them per block
                // (`CSR.START`: "the core will always request 16 transfers at a
                // time (1 512-bit block). Additionally, the DMA channel should
                // be configured for a multiple of 16 32-bit transfers").
                ch.trans_count()
                    .modify(|w| {
                        w.set_mode(TransCountMode::NORMAL);
                        w.set_count(16);
                    });
                // CTRL with EN=0, so the address writes below are not a
                // trigger. `write` starts from the register's reset value; every
                // bit this driver means to set is named, and the rest stay 0.
                ch.ctrl_trig().write(|w| {
                    w.set_en(false);
                    // Must match CSR_DMA_SIZE, below.
                    w.set_data_size(DataSize::SIZE_WORD);
                    w.set_bswap(false);
                    w.set_incr_read(true);
                    w.set_incr_write(false);
                    w.set_irq_quiet(true);
                    w.set_treq_sel(TreqSel::SHA256);
                });
            }

            rp_pac::SHA256.csr().modify(|w| {
                // OneToClear, and *set* means "a write happened too early" —
                // so it is cleared before the sequence starts, not after
                // (`CSR.ERR_WDATA_NOT_RDY`; `sha256_err_not_ready_clear()` in
                // `pico_sha256/sha256.c:58`).
                w.set_err_wdata_not_rdy(false);
                // On at reset (CSR reset value 0x1206, bit 12), and set
                // explicitly anyway so the register's state after a hash is
                // defined rather than "whatever was there": the bus interface
                // assembles little-endian and SHA wants the first byte of a
                // word to be the most significant.
                w.set_bswap(true);
                w.set_dma_size(DmaSize::_32BIT);
                w.set_start(true);
            });
            Ok(())
        }

        /// Wait for `CSR.WDATA_RDY`, then deliver one 64-byte block.
        ///
        /// `pico_sha256/sha256.c:78-119` (`write_to_hardware`): wait ready, write,
        /// then *check* `ERR_WDATA_NOT_RDY` — the SDK's check is an `assert`,
        /// i.e. a panic, and this is the error version of it. A dropped block
        /// would otherwise be a silently short hash.
        fn push(&mut self, block: &Block) -> Result<(), Sha256Error> {
            match self.dma_chan {
                Some(chan) => self.push_dma(rp_pac::DMA.ch(chan as usize), block),
                None => self.push_polled(block),
            }
        }

        /// Wait for `CSR.SUM_VLD`, then read `SUM0..SUM7`.
        ///
        /// The wait is not optional and the read is not guarded by an `if` that
        /// returns the registers anyway: `SUM0..SUM7` are undefined when
        /// `SUM_VLD` is 0, so a timeout must be an error rather than a short
        /// read path.
        ///
        /// There is no stale-digest window to guard against here, which is worth
        /// stating because the alternative — caching the previous hash and
        /// returning it if a wait times out — is exactly the failure this module
        /// exists to prevent. `SUM_VLD` "goes low when `WDATA` is first written"
        /// (`CSR.SUM_VLD`), and every `hash_into` pushes at least one block, so
        /// by the time `finish` runs the flag describes *this* sequence and not
        /// the previous one.
        fn finish(&mut self) -> Result<[u8; SHA256_DIGEST_LEN], Sha256Error> {
            let mut polls = SUM_VLD_MAX_POLLS;
            while !rp_pac::SHA256.csr().read().sum_vld() {
                if polls == 0 {
                    return Err(Sha256Error::DigestNotValid);
                }
                polls -= 1;
                spin_loop();
            }
            Ok(digest_from_words([
                rp_pac::SHA256.sum0().read(),
                rp_pac::SHA256.sum1().read(),
                rp_pac::SHA256.sum2().read(),
                rp_pac::SHA256.sum3().read(),
                rp_pac::SHA256.sum4().read(),
                rp_pac::SHA256.sum5().read(),
                rp_pac::SHA256.sum6().read(),
                rp_pac::SHA256.sum7().read(),
            ]))
        }
    }

    impl Sha256Accel {
        /// Clear `RESETS.RESET.SHA256` and wait for `RESET_DONE`.
        ///
        /// `RESETS.RESET` resets to `0x1fff_ffff`, so the block **is** in reset
        /// at power-on and this is not optional. `embassy-rp` cannot do it for
        /// us either: it has no `SHA256` `Peri` token (there is no `sha256.rs`
        /// in `embassy-rp` 0.10.0's `src/`), so its peripheral reset does not
        /// name this bit.
        ///
        /// A reset that does not complete is reported as
        /// [`Sha256Error::Unavailable`] — the "accelerator is absent" case. The
        /// alternative, returning `CSR`'s reset value `0x0000_1206` as though it
        /// were a chaining state, would yield eight "digest" words that are
        /// literally the reset constant.
        fn ensure_unreset(&self) -> Result<(), Sha256Error> {
            if rp_pac::RESETS.reset_done().read().sha256() {
                return Ok(());
            }
            // Read-modify-write rather than `write`: RESET holds a bit per
            // peripheral and this driver must not disturb the other fifteen.
            rp_pac::RESETS
                .reset()
                .modify(|w| w.set_sha256(false));
            let mut polls = SUM_VLD_MAX_POLLS;
            while !rp_pac::RESETS.reset_done().read().sha256() {
                if polls == 0 {
                    return Err(Sha256Error::Unavailable);
                }
                polls -= 1;
                spin_loop();
            }
            Ok(())
        }

        /// Sixteen 32-bit writes to `WDATA`, bounded by `CSR.WDATA_RDY`.
        ///
        /// The words are `from_le_bytes` of the block's big-endian quarters.
        /// With `CSR.BSWAP = 1` the block's bus interface byte-swaps each word
        /// as it commits it to the message schedule, so byte `b[0]` lands as the
        /// most significant — which is what SHA-256 means
        /// (`CSR.BSWAP`: "the first byte is the *most significant* in each
        /// message word"). On the little-endian RP2350 that is exactly
        /// `u32::from_le_bytes`, and `pico-sdk`'s aligned fast path writes the
        /// words straight out of the buffer
        /// (`pico_sha256/sha256.c:94-101`), which is the same thing.
        fn push_polled(&self, block: &Block) -> Result<(), Sha256Error> {
            self.wait_ready()?;
            for i in 0..SHA256_BLOCK_LEN / 4 {
                let w = u32::from_le_bytes([
                    block.0[i * 4],
                    block.0[i * 4 + 1],
                    block.0[i * 4 + 2],
                    block.0[i * 4 + 3],
                ]);
                rp_pac::SHA256.wdata().write_value(w);
            }
            self.check_not_ready_error()
        }

        /// One 16-word DMA transfer into `WDATA`.
        ///
        /// `dma_channel_configure` in three parts, as the SDK does it
        /// (`pico_sha256/sha256.c:79-91`): wait for the previous transfer, wait
        /// for the block to be ready, then disable the channel, write the
        /// addresses, and set `EN` — which is the trigger, because `CHx_CTRL` is
        /// a trigger register and a write with `EN = 1` starts the sequence.
        fn push_dma(
            &self,
            ch: rp_pac::dma::Channel,
            block: &Block,
        ) -> Result<(), Sha256Error> {
            self.wait_dma_idle(ch)?;
            self.wait_ready()?;

            ch.ctrl_trig().modify(|w| w.set_en(false));
            ch.read_addr().write_value(block.dma_addr() as u32);
            ch.write_addr()
                .write_value(rp_pac::SHA256.wdata().as_ptr() as u32);
            ch.ctrl_trig().modify(|w| w.set_en(true));

            self.wait_dma_idle(ch)?;
            self.check_not_ready_error()
        }

        /// Bounded wait for the channel to stop being busy, then its error bits.
        ///
        /// `CTRL.BUSY` is the completion signal (`pico-sdk` waits on it in
        /// `dma_channel_wait_for_finish_blocking`), and the three error bits are
        /// checked on the way out because a channel that faulted has delivered
        /// *something* and would otherwise look merely slow.
        fn wait_dma_idle(&self, ch: rp_pac::dma::Channel) -> Result<(), Sha256Error> {
            let mut polls = WDATA_RDY_MAX_POLLS;
            while ch.ctrl_trig().read().busy() {
                if polls == 0 {
                    // Stop a half-finished sequence rather than leave it
                    // enabled: the next `begin` will reconfigure it, but a
                    // channel still pulling words out of a stack frame that has
                    // been popped is a bus fault waiting to happen.
                    ch.ctrl_trig().modify(|w| w.set_en(false));
                    return Err(Sha256Error::DmaError);
                }
                polls -= 1;
                spin_loop();
            }
            let ctrl = ch.ctrl_trig().read();
            if ctrl.read_error() || ctrl.write_error() || ctrl.ahb_error() {
                ch.ctrl_trig().modify(|w| w.set_en(false));
                return Err(Sha256Error::DmaError);
            }
            Ok(())
        }

        /// Bounded wait for `CSR.WDATA_RDY`.
        fn wait_ready(&self) -> Result<(), Sha256Error> {
            let mut polls = WDATA_RDY_MAX_POLLS;
            while !rp_pac::SHA256.csr().read().wdata_rdy() {
                if polls == 0 {
                    return Err(Sha256Error::WroteWhileNotReady);
                }
                polls -= 1;
                spin_loop();
            }
            Ok(())
        }

        /// Has the block dropped a word we wrote? (`CSR.ERR_WDATA_NOT_RDY`.)
        ///
        /// Checked *after* every block, exactly where `pico_sdk`'s
        /// `assert(!sha256_err_not_ready())` sits
        /// (`pico_sha256/sha256.c:81`) — and turned into an error, because a
        /// panic is not a recovery strategy and this caller may well have a
        /// software SHA-256 to fall back to.
        fn check_not_ready_error(&self) -> Result<(), Sha256Error> {
            if rp_pac::SHA256.csr().read().err_wdata_not_rdy() {
                rp_pac::SHA256
                    .csr()
                    .modify(|w| w.set_err_wdata_not_rdy(false));
                return Err(Sha256Error::WroteWhileNotReady);
            }
            Ok(())
        }
    }
}

#[cfg(all(feature = "device", target_arch = "arm"))]
pub use device::{
    Sha256Accel, Sha256Error, SHA256_RESET_BIT, SUM_VLD_MAX_POLLS, WDATA_RDY_MAX_POLLS,
};

#[cfg(test)]
mod tests {
    use super::*;
    use digest::Digest;

    /// The `0x80` sits at the first free byte of the tail, and the length field
    /// at the end of the **first** block, for every remainder 0..=55. This is
    /// the condition `padding_blocks` branches on, asserted directly rather
    /// than only through a digest.
    #[test]
    fn the_one_block_boundary_is_55_not_56() {
        for tail_len in 0..=SHA256_BLOCK_LEN - 1 {
            let tail = [0xa5u8; SHA256_BLOCK_LEN];
            let mut out = [0u8; SHA256_MAX_TAIL_BLOCKS * SHA256_BLOCK_LEN];
            let n = padding_blocks(&tail[..tail_len], 0x1234_5678, &mut out);

            assert_eq!(out[tail_len], 0x80, "0x80 misplaced at tail_len={tail_len}");
            let one_block = tail_len + 1 + SHA256_LENGTH_FIELD_LEN <= SHA256_BLOCK_LEN;
            assert_eq!(
                n,
                if one_block {
                    SHA256_BLOCK_LEN
                } else {
                    2 * SHA256_BLOCK_LEN
                },
                "block count at tail_len={tail_len}"
            );
            // The length field is the last eight bytes of the block the padding
            // ends in — which is the *second* one once tail_len reaches 56.
            assert_eq!(
                &out[n - 8..n],
                &0x1234_5678u64.to_be_bytes(),
                "length field at tail_len={tail_len}"
            );
        }
    }

    /// The two-block case puts the length field in the *second* block and leaves
    /// the first one's last seven bytes zero — the `0x80` occupies byte 56,
    /// which is where a fixed-offset length field would have gone. A driver
    /// that wrote the length there would produce a valid-looking digest of a
    /// message that is not the one hashed.
    #[test]
    fn the_two_block_case_moves_the_length_field() {
        let tail = [0xa5u8; SHA256_BLOCK_LEN];
        let mut out = [0u8; SHA256_MAX_TAIL_BLOCKS * SHA256_BLOCK_LEN];
        let n = padding_blocks(&tail[..56], 0xdead_beef_cafe_babe, &mut out);

        assert_eq!(n, 2 * SHA256_BLOCK_LEN);
        assert_eq!(out[56], 0x80, "the 0x80 lands where the length field would");
        assert_eq!(&out[57..64], &[0u8; 7], "first block must end in zeroes");
        assert_eq!(&out[120..128], &0xdead_beef_cafe_babeu64.to_be_bytes());
    }

    /// `digest_from_words` is the only byte-order step between the block and a
    /// digest. Checked against the SHA-256 of `b"abc"`, read back out of the
    /// words — the one SHA-256 digest this repository can name without
    /// running anything.
    #[test]
    fn digest_serialisation_is_big_endian() {
        let bytes = sha2::Sha256::digest(b"abc");
        let mut words = [0u32; 8];
        for (i, w) in words.iter_mut().enumerate() {
            *w = u32::from_be_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
        }
        assert_eq!(digest_from_words(words).as_slice(), bytes.as_slice());
    }

    /// `Block` must hand the DMA a word-aligned address; a bare `[u8; 64]` has
    /// alignment 1 and the RP2350 DMA faults rather than coping.
    #[test]
    fn a_block_is_word_aligned_for_dma() {
        assert_eq!(core::mem::align_of::<Block>(), 4);
        assert_eq!(core::mem::align_of::<Block>(), core::mem::align_of::<u32>());
        assert_eq!(core::mem::size_of::<Block>(), SHA256_BLOCK_LEN);
        // And the address handed to the channel is that of the bytes, not of
        // some inner offset.
        let b = Block::ZERO;
        assert_eq!(b.dma_addr(), b.0.as_ptr() as usize);
        assert_eq!(b.dma_addr() % 4, 0);
    }
}