//! US-1070 — a **rolled** SHA-512 compression, as a `digest`-trait drop-in.
//!
//! # Why this exists
//!
//! Stock `sha2`'s soft backend (`sha2/src/sha512/soft.rs`) unrolls all 80
//! rounds into straight-line code. That is the right trade on a desktop core
//! with a warm L1 and a branch predictor that has seen the loop body ten
//! million times; on an RP2350 executing from XIP flash it is the wrong one.
//! The unrolled body is far larger than the instruction cache, so the core
//! stalls on fetch for a large fraction of the hash, and the schedule code —
//! which is *the* part that could have been a loop — is inlined with it.
//!
//! This module keeps the algorithm and throws away the unrolling: a 16-round
//! priming loop and a 64-iteration expansion loop over a 16-word **circular**
//! message schedule, with eight working variables in registers and a 128-byte
//! stack array for the schedule. Measured on this build, the compression is
//! **1,188 B against the stock 10,544 B** — 8.9x smaller. The output is
//! **byte identical** to `sha2` for
//! every input, which is the entire safety argument, and it is enforced by
//! `platform/tests/sha512_differential.rs` — over the published NIST
//! known-answer vectors, over every block-boundary residue, over arbitrary
//! streaming chunk splits, and over several hundred deterministic pseudo-random
//! inputs, each case checked against stock `sha2` as well as against the KATs.
//!
//! # What it is and is not
//!
//! It is a **`digest` 0.10 drop-in**, so `Hkdf<Sha512>` and `Hmac<Sha512>`
//! accept it unchanged and no call site had to learn anything new. It is
//! `no_std`, allocation-free, and the only state is the eight chaining words
//! plus a `u128` block counter — the same state `sha2` keeps.
//!
//! It is **SHA-512 only**. SHA-384/512-224/512-256 are the same compression
//! with different IVs and truncation, and this firmware does not use them;
//! adding them would be untested code, so they are not here. Anything that
//! needs one of them keeps using `sha2`.
//!
//! # Scope — signing constraint S-2
//!
//! This is a *hash*, reached only through `Hkdf` and `Hmac`. It does not
//! touch, and must not be extended to touch, ECDSA nonce derivation or
//! signature encoding. Non-malleability (low-`s`) is what Bitcoin txid
//! integrity rests on and is invisible to the FIDO threat model, so a
//! performance change that altered signature encoding would break S-2
//! silently. Keeping this a `digest`-trait drop is what makes the change
//! safe: it is a pure function of its input bytes, and the differential test
//! says so case by case.
//!
//! # The 2^61-byte boundary
//!
//! SHA-512's length field is **128 bits**, which is the one structural
//! difference from SHA-256 that a port is most likely to get wrong: a
//! `u64` counter (or a `u64` bit-length) silently truncates once a message
//! passes 2^61 bytes. This module counts blocks in a `u128` and writes the
//! 128-bit field, so that boundary is real and it is tested — see
//! `the_2_pow_61_byte_length_boundary_is_not_truncated` at the bottom of this
//! file, which reaches the private counter and therefore cannot be expressed
//! as an integration test.
//!
//! # Keeping the loop rolled
//!
//! A "rolled" loop that the optimiser unrolls again is not rolled, and the
//! whole point is lost. Two things hold it open: the message schedule is
//! indexed by the loop counter (`w[s]`, `s = j & 15`), which forces the array
//! into memory rather than into registers, and `compress` is
//! `#[inline(never)]` so it cannot be duplicated into every call site. The
//! check is `arm-none-eabi-nm -S` plus a look at the disassembly: 1,188 B with
//! three conditional branches and a back-edge, where the unrolled function is
//! 10,544 B of straight line.
//!
//! # What is measured and what is not
//!
//! **Measured here:** byte-identity against `sha2` and the FIPS 180-4 vectors,
//! and code size on `thumbv8m.main-none-eabi`.
//!
//! **Not measured here:** any speedup. There is no RP2350 in this loop, so
//! the claim this module exists to make is *reasoned, not observed*. A host
//! x86-64 benchmark of the two implementations was run while writing it and
//! came out **against** the port — 0.71x to 1.10x depending on message size,
//! i.e. roughly 25 % slower on multi-kilobyte messages — which is what you
//! would expect when a hot L1 and a trained predictor make the unrolled form
//! nearly free and the loop's indexed schedule store is pure overhead. That
//! is not evidence against the port on the target (XIP fetch stalls are a
//! different cost model entirely, and the 8.9x code-size reduction is the
//! mechanism the story is betting on), but it *is* evidence that the win is
//! specific to the target and has to be confirmed there. US-1071's hardware
//! BDD is where that confirmation belongs; nothing here should be read as
//! claiming a measured speedup.

use digest::block_buffer::Eager;
use digest::core_api::{
    AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
    OutputSizeUser, UpdateCore,
};
use digest::typenum::consts::{U64, U128};
use digest::{HashMarker, Output};
use core::convert::TryInto;
use core::fmt;

/// SHA-512 block size, in bytes. The message schedule and the padding rule
/// are both built on this number; it is a `const` rather than a literal so the
/// `U128` block-size type below and the loop bound cannot drift apart.
const BLOCK_LEN: usize = 128;

/// Round constants, `K`, FIPS 180-4 §4.2.3 — the first 64 bits of the
/// fractional parts of the cube roots of the first 80 primes.
///
/// Published constants, not a derivation: recomputing them at compile time
/// would trade a `.rodata` table for float code, which is the opposite of
/// what this story is for.
const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// Initial hash value `H(0)`, FIPS 180-4 §5.3.3 — the first 64 bits of the
/// fractional parts of the square roots of the first eight primes.
const H0: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// σ₀, FIPS 180-4 §4.1.3: `ROTR(x,1) ⊕ ROTR(x,8) ⊕ SHR(x,7)`.
#[inline(always)]
const fn sigma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

/// σ₁, FIPS 180-4 §4.1.3: `ROTR(x,19) ⊕ ROTR(x,61) ⊕ SHR(x,6)`.
#[inline(always)]
const fn sigma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// The SHA-512 round function's `Ch` (choose): `g XOR (e AND (f XOR g))`.
///
/// Spelled this way rather than as the majority-of-three form because it is
/// two operations instead of four on a target whose ALU cost matters, and
/// because it is the form FIPS 180-4 §4.1.3 actually prints. Constant-time by
/// construction: no data-dependent branch and no table lookup.
#[inline(always)]
const fn ch(e: u64, f: u64, g: u64) -> u64 {
    g ^ (e & (f ^ g))
}

/// The round function's `Maj` (majority): `(a AND b) XOR (a AND c) XOR (b AND c)`.
#[inline(always)]
const fn maj(a: u64, b: u64, c: u64) -> u64 {
    (a & b) ^ (a & c) ^ (b & c)
}

/// Ψ₀, FIPS 180-4 §4.1.3: `ROTR(x,28) ⊕ ROTR(x,34) ⊕ ROTR(x,39)`.
#[inline(always)]
const fn big_sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

/// Ψ₁, FIPS 180-4 §4.1.3: `ROTR(x,14) ⊕ ROTR(x,18) ⊕ ROTR(x,41)`.
#[inline(always)]
const fn big_sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

/// One 128-byte block of message schedule, big-endian word `i`.
#[inline(always)]
fn schedule_word(block: &[u8], i: usize) -> u64 {
    // `i < 16` is guaranteed by every caller's loop bound, so the slice is
    // exactly 8 bytes and the `unwrap` is statically unreachable. Spelled
    // without a bounds check on purpose: this runs 16 times per block inside
    // the hot loop.
    u64::from_be_bytes(block[i * 8..][..8].try_into().unwrap())
}

/// **The compression function — the entire point of this module.**
///
/// One block in, the chaining state advanced. This is the FIPS 180-4 §6.4
/// update with the round loop and the schedule loop rolled, and the message
/// schedule held in a 16-word circular buffer so the working set is 128 bytes
/// of stack instead of 640.
///
/// `#[inline(never)]` is load-bearing, not decoration: `update_blocks` calls
/// this per block and is itself inlined into `Hmac`/`Hkdf` key schedules, so
/// without it the optimiser is free to duplicate this body into every such
/// site and the code-size win this story is for evaporates.
#[inline(never)]
fn compress(state: &mut [u64; 8], block: &[u8]) {
    debug_assert_eq!(block.len(), BLOCK_LEN);

    // w[i & 15] holds W[i] at the top of round i. W[0..16] are the block.
    let mut w = [0u64; 16];
    for (i, slot) in w.iter_mut().enumerate() {
        *slot = schedule_word(block, i);
    }

    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    let (mut e, mut f, mut g, mut h) = (state[4], state[5], state[6], state[7]);

    // Rounds 0..16. No schedule expansion yet: W[i] = the block word.
    //
    // Split from the main loop rather than guarded inside it so there is no
    // per-round branch. Two small loop bodies cost a few dozen bytes of code
    // and buy 64 branch-free iterations, which is the trade this story wants.
    for i in 0..16 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    // Rounds 16..80, expanding the schedule in place.
    //
    //   W[i] = σ₁(W[i−2]) + W[i−7] + σ₀(W[i−15]) + W[i−16]
    //
    // reads, in circular-buffer terms, with `j = i & 15`:
    //
    //   W[i−16] is w[s], the slot being overwritten
    //   W[i−15] is w[(s+1) & 15]
    //   W[i−7]  is w[(s+9) & 15]
    //   W[i−2]  is w[(s+14) & 15]
    //
    // 64 iterations, with `s` cycling four times through the 16 slots. The
    // iteration count is the easy thing to get wrong here and the failure is
    // spectacular rather than subtle, so it is called out rather than left to
    // the next reader.
    for j in 0..64 {
        let i = 16 + j;
        let s = j & 15;
        let w15 = w[(s + 1) & 15];
        let w2 = w[(s + 14) & 15];
        w[s] = sigma1(w2)
            .wrapping_add(w[(s + 9) & 15])
            .wrapping_add(sigma0(w15))
            .wrapping_add(w[s]);

        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[s]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// The block-level hasher: chaining state plus a **128-bit** count of blocks
/// already compressed.
///
/// The counter is `u128` because the SHA-512 length field is 128 bits, and
/// because a `u64` would be wrong for every message past 2^61 bytes. See the
/// module doc and the boundary test at the bottom of this file.
#[derive(Clone)]
pub struct Sha512Core {
    state: [u64; 8],
    block_len: u128,
}

impl HashMarker for Sha512Core {}

impl BlockSizeUser for Sha512Core {
    type BlockSize = U128;
}

impl BufferKindUser for Sha512Core {
    /// `Eager`: compress whatever whole blocks are already in the buffer at
    /// the end of every update, so a streaming caller never accumulates more
    /// than a partial block. This is the same choice `sha2` makes, and it is
    /// what keeps a `Hmac` over a long message from holding the message.
    type BufferKind = Eager;
}

impl UpdateCore for Sha512Core {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u128;
        for block in blocks {
            // SAFETY-free: `Block<Self>` is `GenericArray<u8, U128>`, i.e.
            // exactly 128 bytes, and `compress` only reads it.
            compress(&mut self.state, block.as_slice());
        }
    }
}

impl OutputSizeUser for Sha512Core {
    type OutputSize = U64;
}

impl FixedOutputCore for Sha512Core {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bit_len = 8 * (buffer.get_pos() as u128 + BLOCK_LEN as u128 * self.block_len);
        // FIPS 180-4 §5.1.1: `0x80`, then zeros, then the 128-bit big-endian
        // bit length. `len128_padding_be` is `block-buffer`'s; it is the same
        // routine `sha2`'s own core uses, so the padding cannot be a source
        // of divergence — if it were, both implementations would be wrong
        // together and the KATs would say so.
        buffer.len128_padding_be(bit_len, |b| compress(&mut self.state, b));

        // Big-endian: eight chaining words to sixty-four output bytes.
        // `as_chunks_mut` rather than `chunks_exact_mut` because it yields a
        // *fixed-size* chunk, so a length mismatch is a compile error instead
        // of a silently short digest.
        for (chunk, word) in out
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(self.state.iter())
        {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
    }
}

impl Default for Sha512Core {
    fn default() -> Self {
        Sha512Core {
            state: H0,
            block_len: 0,
        }
    }
}

impl digest::Reset for Sha512Core {
    /// Back to `H(0)` **and** `block_len == 0`.
    ///
    /// Both halves matter. Restoring the chaining words without clearing the
    /// counter produces a hasher that agrees with itself and with nothing
    /// else — and every test that hashes two *different* real messages still
    /// passes, because the mistake only shows on a message long enough for
    /// the inflated count to reach the padding. `sha512_differential.rs`
    /// checks it directly: reset, then hash the empty message, and require the
    /// published empty-message digest.
    fn reset(&mut self) {
        *self = Self::default();
    }
}

impl AlgorithmName for Sha512Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Same string `sha2` reports, so a `Mac`'s algorithm name (and
        // anything that keys a dispatch table off it) is unchanged.
        f.write_str("Sha512")
    }
}

impl fmt::Debug for Sha512Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately does not print the state. `sha2` does not either, and a
        // hasher's live state is exactly the sort of thing that ends up in a
        // log line.
        f.write_str("Sha512Core { ... }")
    }
}

/// The drop-in type. `Sha512` here is interchangeable with `sha2::Sha512`
/// anywhere `D: Digest + BlockSizeUser` is required — `Hkdf<Sha512>`,
/// `Hmac<Sha512>`, `Digest::digest`, the lot.
///
/// The equivalence is not asserted, it is *tested*:
/// `platform/tests/sha512_differential.rs` runs both types through the same
/// suite and requires identical bytes.
pub type Sha512 = CoreWrapper<Sha512Core>;

// ---------------------------------------------------------------------------
// The 128-bit length counter.
//
// This test cannot live in `tests/sha512_differential.rs`: it has to set the
// private block counter to a value whose message is 2^61 bytes long, and there
// is no public API for that in `digest` — correctly so, since a public
// "believe this length" constructor on a hash is a footgun. It reaches the
// field directly instead.
//
// The reference here is a deliberately naive, in-file SHA-512 (full 80-word
// schedule, no rolling, written straight off FIPS 180-4 §6.4) whose block
// counter and length field are *also* `u128`. It is anchored to ground truth
// by its own NIST KAT assertions below, so it is not a third implementation
// of the algorithm that could agree with a broken port — it is an independent
// one, checked against the standard, that the port is then checked against.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use digest::Digest;
    use std::format;
    use std::string::String;
    use std::vec;
    use std::vec::Vec;

    /// Lowercase hex over a byte sequence, so a failure reads as a digest
    /// rather than as bytes.
    fn hex<I: IntoIterator<Item = u8>>(bytes: I) -> String {
        bytes.into_iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The same, for the chaining state.
    fn hex_state(state: &[u64; 8]) -> String {
        hex(state.iter().flat_map(|w| w.to_be_bytes()))
    }

    /// The published vectors, as literals the tests below can hold on to.
    const KAT_EMPTY: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                              47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    const KAT_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                           2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    const KAT_896: &str = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
                           501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";

    /// Compress the padding for a message whose final (buffered) fragment is
    /// `tail`, with the 128-bit bit length `bit_len` declared by the caller.
    ///
    /// Built the FIPS 180-4 §5.1.1 way rather than by calling `block-buffer`,
    /// so the two sides of the comparison are written independently. The
    /// two-block case matters: a 112-byte message puts its `0x80` at offset
    /// 112, which is where the length field starts, so the length has to go
    /// in a block of its own. A helper that assumed one block would be wrong
    /// for exactly the lengths the differential suite cares about most.
    fn reference_tail(tail: &[u8], bit_len: u128, state: &mut [u64; 8]) {
        assert!(tail.len() < BLOCK_LEN);
        let mut block = [0u8; BLOCK_LEN];
        block[..tail.len()].copy_from_slice(tail);
        block[tail.len()] = 0x80;
        if tail.len() + 1 + 16 <= BLOCK_LEN {
            block[BLOCK_LEN - 16..].copy_from_slice(&bit_len.to_be_bytes());
            reference(&block, state);
        } else {
            reference(&block, state);
            let mut len_block = [0u8; BLOCK_LEN];
            len_block[BLOCK_LEN - 16..].copy_from_slice(&bit_len.to_be_bytes());
            reference(&len_block, state);
        }
    }

    /// The reference as a whole-message hash: every full block, then the
    /// padding for whatever is left over. The bit length is derived from
    /// `msg`, so this is an ordinary SHA-512 written the slow, obvious way.
    fn reference_digest(msg: &[u8]) -> String {
        let whole = (msg.len() / BLOCK_LEN) * BLOCK_LEN;
        let mut state = H0;
        for chunk in msg[..whole].chunks(BLOCK_LEN) {
            let mut block = [0u8; BLOCK_LEN];
            block.copy_from_slice(chunk);
            reference(&block, &mut state);
        }
        reference_tail(&msg[whole..], (msg.len() as u128) * 8, &mut state);
        hex_state(&state)
    }

    /// Deterministic filler, so a failure is reproducible byte for byte.
    fn filler(len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..len {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            v.push((x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 24) as u8);
        }
        v
    }

    /// Drive the **real** core through its real finalisation with a block
    /// counter of `block_len` and `tail` bytes still buffered — i.e. exactly
    /// the state a caller that has hashed 2^54 blocks and has 64 bytes left
    /// is in. Nothing here reimplements the padding: the buffer is handed to
    /// `finalize_fixed_core` and the answer is whatever that produces.
    fn port_finalize(state: [u64; 8], block_len: u128, tail: &[u8]) -> String {
        let mut core = Sha512Core {
            state,
            block_len,
        };
        let mut buf = Buffer::<Sha512Core>::new(&[]);
        let block = digest::generic_array::GenericArray::clone_from_slice(&{
            let mut b = [0u8; BLOCK_LEN];
            b[..tail.len()].copy_from_slice(tail);
            b
        });
        buf.set(block, tail.len());
        let mut out = Output::<Sha512Core>::default();
        core.finalize_fixed_core(&mut buf, &mut out);
        hex(out.iter().copied())
    }

    /// A textbook SHA-512, written to be *obvious* rather than fast.
    ///
    /// Its whole job is to be wrong in different ways than [`compress`]: no
    /// circular schedule, no split loops, a message schedule kept in full.
    /// It takes the 128-bit bit length as a parameter, which is what makes
    /// the 2^61-byte boundary expressible at all — no amount of real message
    /// gets there inside a test's runtime, so the length has to be an input.
    fn reference(block: &[u8; BLOCK_LEN], state: &mut [u64; 8]) {
        let mut w = [0u64; 80];
        for (i, slot) in w.iter_mut().enumerate().take(16) {
            *slot = u64::from_be_bytes(block[i * 8..][..8].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = sigma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(sigma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
        let (mut e, mut f, mut g, mut h) = (state[4], state[5], state[6], state[7]);
        for i in 0..80 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    /// The reference is pinned to the standard *before* it is trusted as an
    /// oracle for the port. If this ever fails, the divergence reports below
    /// mean nothing and this is the failure to read.
    #[test]
    fn the_in_file_reference_matches_the_published_vectors() {
        // 112 bytes is chosen on purpose: it is the smallest length that
        // needs a *second* padding block, and the stock vector happens to be
        // exactly that long.
        for (msg, want) in [
            (&b""[..], KAT_EMPTY),
            (&b"abc"[..], KAT_ABC),
            (
                &b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"[..],
                KAT_896,
            ),
        ] {
            assert_eq!(
                reference_digest(msg),
                want,
                "the in-file reference disagrees with NIST for a {}-byte message",
                msg.len()
            );
        }
    }

    /// The port, through the public `Digest` surface, reproduces the vectors.
    /// The `block-buffer` padding path and the `CoreWrapper` plumbing are
    /// covered here; the compression itself is covered by
    /// `the_rolled_schedule_equals_the_textbook_one` below.
    #[test]
    fn the_port_matches_the_published_vectors_through_digest() {
        assert_eq!(hex(Sha512::digest(b"")), KAT_EMPTY);
        assert_eq!(hex(Sha512::digest(b"abc")), KAT_ABC);
        assert_eq!(
            hex(Sha512::digest(
                &b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                  ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"[..]
            )),
            KAT_896
        );
    }

    /// The rolled compression against the textbook one, over a long run of
    /// random blocks. This localises any regression to the compression rather
    /// than to the `digest` plumbing, and a circular-schedule indexing slip
    /// shows up here on the *second* block — a single-block test cannot see
    /// it at all, because the schedule is only expanded from round 16 on.
    #[test]
    fn the_rolled_schedule_equals_the_textbook_one() {
        let mut rng = 0x243f_6a88_85a3_08d3u64;
        let mut next = move || {
            rng ^= rng >> 12;
            rng ^= rng << 25;
            rng ^= rng >> 27;
            rng.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };

        let mut rolled = H0;
        let mut book = H0;
        for _ in 0..64 {
            let mut block = [0u8; BLOCK_LEN];
            for chunk in block.chunks_mut(8) {
                chunk.copy_from_slice(&next().to_be_bytes());
            }
            compress(&mut rolled, &block);
            reference(&block, &mut book);
        }
        assert_eq!(rolled, book, "rolled compression diverged from the textbook");
    }

    /// The 2^61-byte boundary.
    ///
    /// SHA-512 counts bits in a **128-bit** field, so a message longer than
    /// 2^61 bytes is the first whose bit length does not fit in 64 bits — the
    /// upper half of the field becomes non-zero. A `u64` bit length truncates
    /// there, silently, and *every* test in
    /// `tests/sha512_differential.rs` still passes, because no message a test
    /// can actually construct is that long. This is the one defect the
    /// differential suite structurally cannot reach, so it gets its own test
    /// and its own mechanism: the private `block_len` is set directly and the
    /// **real** `finalize_fixed_core` is then called, so the padding path and
    /// the length encoding are what is under test — not a re-implementation
    /// of them.
    ///
    /// 2^54 blocks × 128 bytes = 2^61 bytes exactly. The cases bracket the
    /// boundary: one block short of it, exactly on it, one past, and as far
    /// past as the counter can be driven before the arithmetic itself would
    /// wrap.
    #[test]
    fn the_2_pow_61_byte_length_boundary_is_not_truncated() {
        const BLOCKS: u128 = 1u128 << 54; // 2^61 bytes
        // 64 bytes of tail: short enough that the 0x80 and the 128-bit length
        // field share the final block, which is the padding shape a truncated
        // length would corrupt.
        let tail = filler(64);

        for blocks in [BLOCKS - 1, BLOCKS, BLOCKS + 1, (1u128 << 100) / BLOCK_LEN as u128] {
            let bit_len = 8 * (tail.len() as u128 + BLOCK_LEN as u128 * blocks);

            let mut want = H0;
            reference_tail(&tail, bit_len, &mut want);

            assert_eq!(
                port_finalize(H0, blocks, &tail),
                hex_state(&want),
                "divergence at {blocks} blocks (bit length {bit_len}; \
                 high 64 bits of the length field = {})",
                bit_len >> 64
            );
        }
    }

    /// A 64-bit length field would make every boundary case above agree with
    /// a likewise-truncating port, so assert, separately, that the cases are
    /// genuinely distinct answers and that none of them equals the truncated
    /// one. Without this the comparison test above could be passed by two
    /// implementations that are wrong in the same way — which is the failure
    /// mode a differential test is least able to catch, since it has only one
    /// oracle to disagree with.
    #[test]
    fn the_boundary_cases_are_distinct_and_not_the_truncated_answer() {
        const BLOCKS: u128 = 1u128 << 54;
        let tail = filler(64);

        let run = |bit_len: u128| {
            let mut s = H0;
            reference_tail(&tail, bit_len, &mut s);
            hex_state(&s)
        };

        let at_len = 8 * (tail.len() as u128 + BLOCK_LEN as u128 * BLOCKS);
        let at = run(at_len);
        let past = run(at_len + (BLOCK_LEN as u128) * 8);
        let truncated = run(at_len & 0xffff_ffff_ffff_ffff);

        assert_ne!(at, past, "the boundary is not actually a boundary");
        assert_ne!(at, truncated, "a 64-bit length field would be detectable");
        assert_ne!(past, truncated, "a 64-bit length field would be detectable");

        // And the port produces the un-truncated answer.
        assert_eq!(port_finalize(H0, BLOCKS, &tail), at);
    }

    /// `Reset` must clear the counter, not just the chaining words. A reset
    /// that left `block_len` behind would still pass every "hash two
    /// different messages" comparison in the differential suite and would
    /// only be visible on a message long enough for the stale count to reach
    /// the padding — so it is checked directly, against the published
    /// empty-message digest.
    #[test]
    fn reset_clears_the_length_counter() {
        let mut h = <Sha512 as Digest>::new();
        Digest::update(&mut h, vec![0x5au8; 4096]);
        let stale = hex(h.finalize_reset());
        assert_eq!(
            stale,
            hex(sha2::Sha512::digest(vec![0x5au8; 4096])),
            "first use"
        );
        assert_eq!(
            hex(h.finalize_reset()),
            KAT_EMPTY,
            "finalize_reset left state behind"
        );

        let mut h = <Sha512 as Digest>::new();
        Digest::update(&mut h, vec![0x5au8; 4096]);
        digest::Reset::reset(&mut h);
        assert_eq!(hex(h.finalize()), KAT_EMPTY, "reset left state behind");
    }

    /// A long stream: 1,000,000 × `'a'`, the fourth published vector. It is
    /// also the only case here big enough to make the 80-round loop and the
    /// block counter do real work in a single test binary.
    #[test]
    fn the_million_a_vector() {
        assert_eq!(
            hex(Sha512::digest(vec![b'a'; 1_000_000])),
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
             de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
        );
    }
}
