//! US-1569 — the differential test for the RP2350 SHA-256 accelerator driver.
//!
//! # What this file can and cannot prove
//!
//! **Can.** `fapico2_platform::sha256_accel::hash_into` is the driver's whole
//! logic — where the block boundary falls, the `0x80`, the zeroes, the
//! big-endian 64-bit length field, and whether the tail needs a second block.
//! It is target-agnostic and takes its output sink as a parameter, so this file
//! can drive it on the host with a [`BlockSink`] that runs the FIPS 180-4
//! compression itself and compare every case against stock `sha2`. That is the
//! padding-boundary argument, and it is the one that has real content: a
//! driver that got the boundary wrong produces a *valid-looking* digest of the
//! wrong message, which is exactly the kind of failure nobody notices.
//!
//! **Cannot.** The register layer — `rp_pac::SHA256.csr()`, the sixteen
//! `WDATA` writes, `SUM0..SUM7`, the DMA `TREQ_SEL` handshake — is behind
//! `#[cfg(target_arch = "arm")]` and is **not compiled, let alone executed** by
//! any test in this repository. There is no RP2350 in this loop and the
//! registers are volatile memory, so no host model can stand in for them. What
//! this file establishes about the register layer is one arithmetic identity
//! (`the_word_assembly_pairs_le_bytes_with_the_hardware_byte_swap`) and the
//! citations in the module's own documentation; nothing else. A reviewer should
//! read a green run of this file as *the logic is right*, never as *the engine
//! works*.
//!
//! # Two independent implementations, on purpose
//!
//! The oracle is `sha2`. The subject is [`SoftwareBlockSink`] below, which
//! implements the compression from FIPS 180-4 §6.2.2 directly — full 64-word
//! schedule, no rolling, written so that it is *obvious* rather than fast. Two
//! independent implementations agreeing is evidence; the harness agreeing with
//! itself is not. Everything is anchored to ground truth first, by
//! [`the_published_vectors`], before either implementation is consulted.
//!
//! **No randomness escapes the process.** The "arbitrary" inputs are a
//! fixed-seed xorshift stream, so a failure reproduces byte for byte.

use fapico2_platform::sha256_accel::{
    Block, BlockSink, SHA256_BLOCK_LEN, SHA256_DIGEST_LEN, digest_from_words, hash_into,
    padding_blocks,
};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// The subject: a software SHA-256 written straight off the standard.
// ---------------------------------------------------------------------------

/// Round constants `K`, FIPS 180-4 §4.2.2 — the first 32 bits of the fractional
/// parts of the cube roots of the first 64 primes.
#[rustfmt::skip]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Initial hash value `H(0)`, FIPS 180-4 §5.3.3.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// The subject driver: [`hash_into`] driving a textbook SHA-256 compression.
///
/// Each block is read as **sixteen big-endian 32-bit words**, which is what the
/// RP2350 block's message scheduler wants once its `CSR.BSWAP` byte-swap has
/// been applied (see `platform::sha256_accel`'s module docs, and
/// `the_word_assembly_pairs_le_bytes_with_the_hardware_byte_swap` below for
/// the pairing this assumes).
struct SoftwareBlockSink {
    state: [u32; 8],
    pushes: usize,
}

impl SoftwareBlockSink {
    fn new() -> Self {
        Self {
            state: H0,
            pushes: 0,
        }
    }
}

impl BlockSink for SoftwareBlockSink {
    // The compression cannot fail. The error surface under test is the one
    // `FailingSink` below forces, not this one.
    type Error = core::convert::Infallible;

    fn begin(&mut self) -> Result<(), Self::Error> {
        self.state = H0;
        self.pushes = 0;
        Ok(())
    }

    fn push(&mut self, block: &Block) -> Result<(), Self::Error> {
        self.pushes += 1;

        let mut w = [0u32; 64];
        for (i, slot) in w.iter_mut().enumerate().take(16) {
            *slot = u32::from_be_bytes([
                block.0[i * 4],
                block.0[i * 4 + 1],
                block.0[i * 4 + 2],
                block.0[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<[u8; SHA256_DIGEST_LEN], Self::Error> {
        // Through the driver's own serialiser, so a byte-order error there is
        // caught by the same differential run as a padding error.
        Ok(digest_from_words(self.state))
    }
}

/// Run `hash_into` over the software sink and return what the driver produced.
fn driver(msg: &[u8]) -> [u8; SHA256_DIGEST_LEN] {
    let mut sink = SoftwareBlockSink::new();
    hash_into(msg, (msg.len() as u64) * 8, &mut sink).expect("software sink cannot fail")
}

/// Deterministic filler, so a failure reproduces byte for byte.
fn filler(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x = 0x243f_6a88_85a3_08d3u64;
    for _ in 0..len {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        v.push((x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 24) as u8);
    }
    v
}

// ---------------------------------------------------------------------------
// Ground truth, before either implementation is consulted.
// ---------------------------------------------------------------------------

/// The published FIPS 180-4 SHA-256 vectors, as literals. Checked against the
/// *subject* (`hash_into` over `SoftwareBlockSink`) rather than against `sha2`,
/// so that if the harness were secretly wrong the failure would land here
/// rather than in the differential comparisons that follow.
#[test]
fn the_published_vectors() {
    const KATS: &[(&str, &[u8], &str)] = &[
        (
            "empty message",
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "abc",
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "two-block message",
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            "896-bit message (length forces a second pad block)",
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
              ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        ),
        (
            "one million 'a'",
            &[b'a'; 1_000_000],
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        ),
    ];

    for (name, msg, want) in KATS {
        let got = driver(msg);
        assert_eq!(hex(got), *want, "{name}");
    }
}

// ---------------------------------------------------------------------------
// The differential set the story names.
// ---------------------------------------------------------------------------

/// The required set: empty, 1 byte, 63/64/65 bytes, and multi-block.
///
/// 63 is the last length whose padding fits in the same block as the message's
/// remainder; 64 is the first length that is *exactly* whole blocks and so has
/// an entirely empty tail (the `0x80` lands in a block of its own); 65 is the
/// first length with a 1-byte tail. Those three plus empty and 1 byte are the
/// five points at which a block-assembly bug is invisible everywhere else.
#[test]
fn the_required_padding_boundary_set() {
    let cases: &[(&str, Vec<u8>)] = &[
        ("empty", Vec::new()),
        ("1 byte", filler(1)),
        ("63 bytes", filler(63)),
        ("64 bytes (exactly one whole block)", filler(64)),
        ("65 bytes", filler(65)),
        ("128 bytes (two whole blocks)", filler(128)),
        ("1024 bytes (16 whole blocks)", filler(1024)),
        ("4096 bytes (64 whole blocks)", filler(4096)),
    ];
    for (name, msg) in cases {
        assert_eq!(
            hex(driver(msg)),
            hex(Sha256::digest(msg.as_slice())),
            "{name}"
        );
    }
}

/// Every remainder 0..=63, at four whole-block depths. This is the exhaustive
/// version of the boundary set: it walks the entire tail-length axis, which is
/// where the one-block/two-block decision at remainder 55/56 lives.
#[test]
fn every_tail_residue_at_four_depths() {
    for whole_blocks in [0usize, 1, 2, 17] {
        for tail in 0..SHA256_BLOCK_LEN {
            let mut msg = filler(whole_blocks * SHA256_BLOCK_LEN + tail);
            msg.shrink_to_fit();
            assert_eq!(
                hex(driver(&msg)),
                hex(Sha256::digest(msg.as_slice())),
                "whole_blocks={whole_blocks} tail={tail} (len={})",
                msg.len()
            );
        }
    }
}

/// Pseudo-random lengths across two orders of magnitude, to catch anything the
/// structured walk above misses about block splitting.
#[test]
fn pseudo_random_lengths() {
    let mut x = 0x1319_8a2e_0370_7344u64;
    for i in 0..400 {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        // 0..16 KiB. Enough depth (up to 256 blocks) to exercise the block
        // loop, small enough that the debug-build compression runs this a few
        // hundred times in a second or two.
        let len = (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 50) as usize;
        let msg = filler(len);
        assert_eq!(
            hex(driver(&msg)),
            hex(Sha256::digest(msg.as_slice())),
            "case {i}, len={len}"
        );
    }
}

/// `bit_len` is an explicit argument of `hash_into`, so the length field is
/// testable independently of the buffer. This pins the encoding SHA-256
/// requires — the message length in **bits**, big-endian, in the last eight
/// bytes of the final block — by declaring a `bit_len` that is *not* derived
/// from `msg.len()` and showing the digest move accordingly. A driver that
/// recomputed the length from the buffer would fail this.
#[test]
fn the_length_field_is_big_endian_bits_and_is_not_recomputed() {
    let msg: &[u8] = b"abc";
    let mut sink = SoftwareBlockSink::new();
    // 24 == 3 * 8: the encoding `hash_into` would have derived for this buffer.
    let honest = hash_into(msg, 24, &mut sink).expect("software sink cannot fail");
    assert_eq!(hex(honest), hex(driver(msg)));

    // One bit different, same bytes: a different hash, and not `sha2`'s.
    let mut sink2 = SoftwareBlockSink::new();
    let off = hash_into(msg, 32, &mut sink2).expect("software sink cannot fail");
    assert_ne!(hex(off), hex(honest));
    assert_ne!(hex(off), hex(Sha256::digest(msg)));

    // And the declared length is what lands in the padding, big-endian in the
    // last eight bytes of the final block: 24 = 0x0000_0000_0000_0018.
    let mut out = [0u8; 2 * SHA256_BLOCK_LEN];
    let n = padding_blocks(msg, 24, &mut out);
    assert_eq!(n, SHA256_BLOCK_LEN);
    assert_eq!(hex(out[56..64].iter().copied()), "0000000000000018");
}

// ---------------------------------------------------------------------------
// Padding, tested on its own, without any compression at all.
// ---------------------------------------------------------------------------

/// `padding_blocks` in isolation: the `0x80` position, the zero run, the length
/// field's position, and the block count, for every remainder. Independent of
/// the compression, so a failure here localises rather than showing up as an
/// unexplained digest mismatch.
#[test]
fn padding_blocks_alone() {
    for tail_len in 0..SHA256_BLOCK_LEN {
        let tail: Vec<u8> = (0..tail_len).map(|i| i as u8).collect();
        let bit_len = 0x0102_0304_0506_0708u64;
        let mut out = [0xabu8; 2 * SHA256_BLOCK_LEN];
        let n = padding_blocks(&tail, bit_len, &mut out);

        // 0x80 immediately after the remainder.
        assert_eq!(out[tail_len], 0x80, "tail_len={tail_len}");
        // The remainder itself survives untouched.
        assert_eq!(&out[..tail_len], &tail[..], "tail_len={tail_len}");

        let one = tail_len + 9 <= SHA256_BLOCK_LEN;
        assert_eq!(
            n,
            if one {
                SHA256_BLOCK_LEN
            } else {
                2 * SHA256_BLOCK_LEN
            },
            "tail_len={tail_len}"
        );

        // The length field is the last 8 bytes of the last emitted block.
        let want = bit_len.to_be_bytes();
        assert_eq!(&out[n - 8..n], &want, "tail_len={tail_len}");
        // ...and nothing outside the padding and the length is non-zero.
        assert!(
            out[tail_len + 1..n - 8].iter().all(|b| *b == 0),
            "tail_len={tail_len}: non-zero inside the zero run"
        );
        // The bytes past `n` are written (the doc says `out` is fully written)
        // but are not part of the digest.
        if n == SHA256_BLOCK_LEN {
            assert!(out[n..].iter().all(|b| *b == 0));
        }
    }
}

/// The block boundary is a mask, not a division, so it must be checked at the
/// lengths where those two would differ if the constant were not a power of
/// two — and, more usefully, `hash_into` must push the number of blocks the
/// padding arithmetic says it should.
#[test]
fn the_block_count_is_what_the_arithmetic_says() {
    for len in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 191, 192] {
        let msg = filler(len);
        let whole = len - len % SHA256_BLOCK_LEN;
        let mut out = [0u8; 2 * SHA256_BLOCK_LEN];
        let n = padding_blocks(&msg[whole..], (len as u64) * 8, &mut out);
        let expected = whole / SHA256_BLOCK_LEN + n / SHA256_BLOCK_LEN;

        let mut sink = SoftwareBlockSink::new();
        hash_into(&msg, (len as u64) * 8, &mut sink).expect("software sink cannot fail");
        assert_eq!(sink.pushes, expected, "len={len}");
    }
}

// ---------------------------------------------------------------------------
// Errors surface as errors, never as digests.
// ---------------------------------------------------------------------------

/// A sink that fails on demand, at each of the three stages the hardware has.
/// The point of the test is the *shape* of the result, not the enum.
#[derive(Debug, PartialEq, Eq)]
enum FakeError {
    Begin,
    Push(usize),
    Finish,
}

#[derive(Default)]
struct FailingSink {
    /// 0 = never fail, 1 = fail `begin`, 2 = fail `push`, 3 = fail `finish`.
    fail_at: u8,
    pushes: usize,
    finished: bool,
}

impl FailingSink {
    fn failing_at(stage: u8) -> Self {
        Self {
            fail_at: stage,
            pushes: 0,
            finished: false,
        }
    }
}

impl BlockSink for FailingSink {
    type Error = FakeError;

    fn begin(&mut self) -> Result<(), Self::Error> {
        if self.fail_at == 1 {
            return Err(FakeError::Begin);
        }
        Ok(())
    }

    fn push(&mut self, _block: &Block) -> Result<(), Self::Error> {
        if self.fail_at == 2 && self.pushes == 1 {
            return Err(FakeError::Push(1));
        }
        self.pushes += 1;
        Ok(())
    }

    fn finish(&mut self) -> Result<[u8; SHA256_DIGEST_LEN], Self::Error> {
        if self.fail_at == 3 {
            return Err(FakeError::Finish);
        }
        self.finished = true;
        Ok([0x5a; SHA256_DIGEST_LEN])
    }
}

/// A hardware refusal is an `Err`, and the sink is not asked for the digest
/// afterwards.
///
/// A digest produced after a dropped block would be a *valid-looking* hash of
/// whatever the accelerator did absorb — the failure mode this module exists to
/// avoid. So each stage is asserted twice: the result is `Err`, and the step
/// that would have handed back a digest never ran.
#[test]
fn a_hardware_refusal_is_an_error_and_never_a_digest() {
    // The message spans two blocks plus a tail, so there is a middle `push` to
    // fail and the failure is not the first thing that happens.
    let msg = filler(200);

    let mut begin_fail = FailingSink::failing_at(1);
    let r = hash_into(&msg, (msg.len() as u64) * 8, &mut begin_fail);
    assert_eq!(r, Err(FakeError::Begin));
    assert_eq!(begin_fail.pushes, 0, "pushed after begin refused");
    assert!(!begin_fail.finished, "digest requested after begin refused");

    let mut push_fail = FailingSink::failing_at(2);
    let r = hash_into(&msg, (msg.len() as u64) * 8, &mut push_fail);
    assert_eq!(r, Err(FakeError::Push(1)));
    assert!(!push_fail.finished, "digest requested after a dropped block");

    let mut finish_fail = FailingSink::failing_at(3);
    let r = hash_into(&msg, (msg.len() as u64) * 8, &mut finish_fail);
    assert_eq!(r, Err(FakeError::Finish));
    assert!(!finish_fail.finished, "a failing finish must not set the flag");

    // And the control: with nothing failing, the digest is what it is. This is
    // the assertion that makes the three above meaningful — `finish` *does*
    // return a value when it is reached, so its absence is the refusal.
    let mut ok = FailingSink::failing_at(0);
    let r = hash_into(&msg, (msg.len() as u64) * 8, &mut ok);
    assert_eq!(r, Ok([0x5a; SHA256_DIGEST_LEN]));
    assert!(ok.finished);
}

/// A sink that fails on the **last** block must not be followed by a digest,
/// either. The tempting bug is a `finish` outside the error branch, which the
/// mid-message case above would not catch.
#[test]
fn a_refusal_on_the_final_push_still_refuses() {
    let msg = filler(SHA256_BLOCK_LEN * 2);
    let total = 3; // two whole blocks + one tail block
    let mut sink = FailingSink::failing_at(2);
    sink.fail_at = 4; // fail on push #total instead of #1
    struct LastPush {
        inner: FailingSink,
        total: usize,
    }
    impl BlockSink for LastPush {
        type Error = FakeError;
        fn begin(&mut self) -> Result<(), Self::Error> {
            self.inner.begin()
        }
        fn push(&mut self, b: &Block) -> Result<(), Self::Error> {
            if self.inner.pushes + 1 == self.total {
                return Err(FakeError::Push(self.inner.pushes + 1));
            }
            self.inner.pushes += 1;
            let _ = b;
            Ok(())
        }
        fn finish(&mut self) -> Result<[u8; SHA256_DIGEST_LEN], Self::Error> {
            self.inner.finish()
        }
    }
    let mut last = LastPush {
        inner: sink,
        total,
    };
    let r = hash_into(&msg, (msg.len() as u64) * 8, &mut last);
    assert_eq!(r, Err(FakeError::Push(total)));
    assert!(!last.inner.finished, "digest requested after the final block");
}

// ---------------------------------------------------------------------------
// The one device-side transformation that can be checked without silicon.
// ---------------------------------------------------------------------------

/// The polled driver writes `u32::from_le_bytes(block.0[i*4..i*4+4])` to
/// `WDATA` and relies on `CSR.BSWAP = 1` to turn that into SHA-256's
/// most-significant-byte-first word. This asserts the pairing: byte-swapping
/// what the driver writes is identical to reading the block big-endian, for
/// every byte position.
///
/// It is the only assertion in this file about the register layer, and it is an
/// arithmetic identity, not an observation — it cannot tell you that `BSWAP` is
/// set or that `WDATA` accepts the write.
#[test]
fn the_word_assembly_pairs_le_bytes_with_the_hardware_byte_swap() {
    // A whole block of bytes whose every position is distinct enough to catch
    // an off-by-one in the word index.
    let mut bytes = [0u8; SHA256_BLOCK_LEN];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    let block = Block(bytes);

    for i in 0..SHA256_BLOCK_LEN / 4 {
        let b = &block.0[i * 4..i * 4 + 4];
        let what_the_driver_writes = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let what_sha_wants = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        assert_eq!(
            what_the_driver_writes.swap_bytes(),
            what_sha_wants,
            "word {i}"
        );
        // And the converse, so the identity cannot pass by accident: with the
        // hardware swap disabled the driver would have to hand over the
        // big-endian word directly, and this is *not* what it does.
        assert_ne!(what_the_driver_writes, what_sha_wants);
    }
}

// ---------------------------------------------------------------------------
// The no_std gate.
// ---------------------------------------------------------------------------

/// The driver is on the device path and must not have grown a dependency on
/// `std` or `alloc` — `bss` must not increase and the RP2350 build has no heap
/// on this path.
///
/// This is a source-level check rather than a compile-fail test because a
/// `compile_error!` gate can only say yes or no, while the reason it is here is
/// that someone might be *about* to add one of these tokens and would then find
/// the device build fails some distance away. Naming them here puts the
/// prohibition next to the code it is about.
///
/// `cargo check -p fapico2-platform --target thumbv8m.main-none-eabi` is the
/// complementary check — it proves the whole crate still builds `no_std` with
/// the driver in — and it is the one that would actually catch a transitive
/// addition.
#[test]
fn the_driver_uses_core_only() {
    let src = include_str!("../src/sha256_accel.rs");
    for forbidden in [
        "extern crate std",
        "extern crate alloc",
        "alloc::",
        "std::",
        "Vec<",
        "String",
        "format!",
        "println!",
    ] {
        assert!(
            !src.contains(forbidden),
            "sha256_accel.rs must stay core-only, but mentions `{forbidden}`"
        );
    }
    // And the arm-only gate is present: without it, the register layer would be
    // compiled for the host, where `rp_pac` does not even resolve.
    assert!(
        src.contains(r#"#[cfg(all(feature = "device", target_arch = "arm"))]"#),
        "the register layer must stay gated to the arm device build"
    );
}

// ---------------------------------------------------------------------------

/// Lowercase hex, so a failure reads as a digest rather than as bytes.
fn hex<I: IntoIterator<Item = u8>>(bytes: I) -> String {
    bytes.into_iter().map(|b| format!("{b:02x}")).collect()
}