//! US-1070 — the differential test for the rolled SHA-512 compression.
//!
//! `platform::sha512` (US-1070) replaces the stock `sha2` soft backend on the
//! two SHA-512 call sites the EPIC names (`apps/fido/src/stateless.rs:170`,
//! `apps/oath/src/oath_core.rs:43`). Stock `sha2`'s soft backend unrolls all 80
//! rounds into straight-line code: 10,544 bytes of `.text` on this build, of
//! which the instruction cache cannot hold what it needs to hold. The port is only safe if it is **byte identical**, and the EPIC
//! says so in as many words: *"This is the whole safety argument; a performance
//! port without it is unacceptable."*
//!
//! **The harness is a generic function, not a test of a particular type.** It
//! is parameterised over `D: Digest + BlockSizeUser` and every case is checked
//! twice:
//!
//! 1. against the **NIST known-answer vectors** below, which anchor the whole
//!    file to ground truth that neither implementation gets to choose, and
//! 2. against **stock `sha2`**, which is the thing the port claims to be a
//!    drop-in for.
//!
//! That is what makes the ordering meaningful: the story requires this file to
//! **pass on `sha2` before the swap**, which it does — running it with
//! `sha2::Sha512` as the subject is a real, non-vacuous run of every case
//! below, and it is the run that proves the harness is not secretly written to
//! agree with the new code. Only once that is true is
//! `fapico2_platform::sha512::Sha512` added to `differential()`, and the same
//! cases are re-run with it in the subject seat.
//!
//! **What the cases are chosen to cover.** SHA-512's compression function
//! reads a 128-byte block and an 80-word message schedule; everything else is
//! padding. The interesting inputs are therefore (a) every residue of a message
//! length modulo 128 and 129 — which is what decides how many padding bytes
//! the final block carries and whether an extra block is emitted — and (b)
//! arbitrary *chunk splits*, because a streaming caller (`Hkdf`, `Hmac`)
//! delivers the same bytes in whatever sizes the caller happens to use and a
//! buffer boundary bug is invisible to any one-shot test. The 128-bit length
//! counter that SHA-512 inherits from its length field is covered separately,
//! where a private field is reachable: see `platform::sha512`'s own unit test
//! (module doc, "The 2^61-byte boundary").
//!
//! **No randomness escapes the process.** The "random" cases are a fixed-seed
//! xorshift64\* stream, so a failure here reproduces exactly.

use sha2::digest::core_api::BlockSizeUser;
use sha2::digest::{Digest, FixedOutputReset, Reset};

/// The published FIPS 180-4 SHA-512 known-answer vectors — the four the
/// standard prints for SHA-512. (SHA-512/**224**'s
/// `abcdefghbcdefg…`-style 56-byte vector is deliberately *not* used — it is a
/// different algorithm with a different IV and a different output length, and
/// pasting it here would be a mistake dressed as coverage.)
///
/// Independently confirmed against CPython's `hashlib.sha512` while this file
/// was written, so the literals are not simply "whatever our code produces".
const KATS: &[(&str, &[u8], &str)] = &[
    (
        "empty message",
        b"",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    ),
    (
        "one block, shorter than the 0x80 pad byte",
        b"abc",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
    (
        "896-bit message (multi-block, no extra pad block)",
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
         ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
         501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    ),
];

/// The fourth published vector, kept out of [`KATS`] because a 1 MB message
/// does not fit the `&'static [&[u8]]` shape without allocating it for every
/// subject. It is the only vector that exercises a stream long enough to
/// matter for the block counter, so it stays — in its own case.
const MILLION_A_DIGEST: &str =
    "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
     de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";

/// Message lengths that straddle every way a 128-byte block boundary can be
/// interesting. The EPIC names 0/1/111/112/113/127/128/129/239/240/241; the
/// rest extend the same shape to a second and a third boundary and out to
/// several kilobytes, because "past one block" is where a schedule that
/// re-reads stale words would show up.
///
/// 111/112/113 and 239/240/241 are the important pair: 112 is the shortest
/// length whose `0x80` collides with the length field, so it is the smallest
/// message that emits a *second* padding block, and 240 is the same shape one
/// block later.
const BOUNDARY_LENGTHS: &[usize] = &[
    0, 1, 2, 3, 111, 112, 113, 126, 127, 128, 129, 130, 239, 240, 241, 255, 256, 257, 383, 384, 385,
    511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097, 8191, 8192, 8193,
];

/// Chunk sizes a streaming caller might realistically split on. The point is
/// not that these are common — it is that none of them is a multiple of 128 in
/// a way that keeps the buffer aligned, and that some straddle the point where
/// `block-buffer` has to fill and compress in the same call.
const CHUNK_SPLITS: &[usize] = &[1, 2, 3, 7, 31, 64, 127, 128, 129, 200, 255, 256, 1000];

/// A fixed-seed xorshift64\* stream. Deterministic on purpose: see the module
/// doc. Not a cryptographic generator and not used as one — it only has to
/// produce inputs nobody hand-picked.
struct Xorshift64Star(u64);

impl Xorshift64Star {
    fn new(seed: u64) -> Self {
        Xorshift64Star(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&word[..n]);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Every case runs against the subject `D` twice-anchored: to a published KAT
/// where one exists, and always to stock `sha2`.
///
/// The failure messages name the subject and the case, because after the swap
/// "a digest differs" is not a debuggable report on its own.
fn suite<D>(subject: &str)
where
    D: Digest + BlockSizeUser + Default + Reset + FixedOutputReset,
{
    // The drop-in property itself. HMAC pads keys with `block_size` zeros and
    // builds ipad/opad out of a block-sized buffer, so a SHA-512 that reported
    // the wrong block size would be a *silently different MAC*, not a compile
    // error. Pin both numbers.
    assert_eq!(
        <D as Digest>::output_size(),
        64,
        "{subject}: output size must be 64 bytes (SHA-512, not SHA-384/512-224)"
    );
    assert_eq!(
        <D as BlockSizeUser>::block_size(),
        128,
        "{subject}: block size must be 128 bytes (SHA-512)"
    );

    nist_known_answers::<D>(subject);
    block_boundaries::<D>(subject);
    streaming_splits::<D>(subject);
    random_inputs::<D>(subject);
    api_surface::<D>(subject);
}

fn nist_known_answers<D: Digest>(subject: &str) {
    for (name, msg, want) in KATS {
        assert_eq!(hex(&D::digest(msg)), *want, "{subject}: NIST KAT `{name}`");
    }

    // 1,000,000 x 'a' — 1,000,000 bytes = 7,812 full blocks plus a 64-byte
    // tail, so the length counter crosses four digits and the schedule is fed
    // from a long stream. The one vector where "past one block" is really
    // past *many*.
    let million = vec![b'a'; 1_000_000];
    assert_eq!(
        hex(&D::digest(&million)),
        *MILLION_A_DIGEST,
        "{subject}: NIST KAT `1,000,000 x 'a'`"
    );
    assert_eq!(
        hex(&sha2::Sha512::digest(&million)),
        *MILLION_A_DIGEST,
        "sanity: the oracle itself matches the published vector"
    );
}

fn block_boundaries<D: Digest>(subject: &str) {
    let mut rng = Xorshift64Star::new(0x5EED_1070_80AD_0001);
    for &len in BOUNDARY_LENGTHS {
        let mut msg = vec![0u8; len];
        rng.fill(&mut msg);
        let mine = D::digest(&msg);
        let theirs = sha2::Sha512::digest(&msg);
        assert_eq!(
            hex(&mine),
            hex(&theirs),
            "{subject}: one-shot digest at length {len}"
        );
    }
}

fn streaming_splits<D: Digest>(subject: &str) {
    let mut rng = Xorshift64Star::new(0x5EED_1070_57EA_0002);
    // Two length families: the boundary residues, and lengths long enough that
    // a chunked update compresses several blocks per call.
    let mut lengths: Vec<usize> = BOUNDARY_LENGTHS.to_vec();
    for len in [1700usize, 4096, 5000, 9001] {
        for delta in 0..8 {
            lengths.push(len + delta);
        }
    }

    for &len in &lengths {
        let mut msg = vec![0u8; len];
        rng.fill(&mut msg);
        let one_shot = D::digest(&msg);

        for &chunk in CHUNK_SPLITS {
            let mut h = D::new();
            for part in msg.chunks(chunk.max(1)) {
                Digest::update(&mut h, part);
            }
            let got = h.finalize();
            assert_eq!(
                hex(&got),
                hex(&one_shot),
                "{subject}: {len} bytes fed in {chunk}-byte chunks"
            );
        }
    }
}

fn random_inputs<D: Digest>(subject: &str) {
    let mut rng = Xorshift64Star::new(0x5EED_1070_4A4D_0003);

    // Short messages: covers the residues again but with unpredictable
    // content, so a content-dependent schedule bug cannot hide behind a
    // repeated pattern.
    for i in 0..512 {
        let len = (rng.next_u64() % 2049) as usize;
        let mut msg = vec![0u8; len];
        rng.fill(&mut msg);
        assert_eq!(
            hex(&D::digest(&msg)),
            hex(&sha2::Sha512::digest(&msg)),
            "{subject}: random short case {i} (len {len})"
        );
    }

    // Long messages, where several blocks go through per update and the
    // multi-block path in `update_blocks` is what runs.
    for i in 0..32 {
        let len = (rng.next_u64() % 40_000) as usize;
        let mut msg = vec![0u8; len];
        rng.fill(&mut msg);
        assert_eq!(
            hex(&D::digest(&msg)),
            hex(&sha2::Sha512::digest(&msg)),
            "{subject}: random long case {i} (len {len})"
        );
    }
}

fn api_surface<D: Digest + Default + Reset + FixedOutputReset>(subject: &str) {
    let msg = b"the quick brown fox jumps over the lazy dog, repeatedly and at length";

    // `new_with_prefix` and `chain_update` are the two `Digest` conveniences a
    // caller reaches for instead of `update`; a drop-in has to agree there too.
    assert_eq!(
        hex(&D::new_with_prefix(msg).finalize()),
        hex(&sha2::Sha512::digest(msg)),
        "{subject}: new_with_prefix"
    );
    assert_eq!(
        hex(&D::new().chain_update(msg).finalize()),
        hex(&sha2::Sha512::digest(msg)),
        "{subject}: chain_update"
    );

    // `finalize_reset` / `reset`: reusing one instance must land back on the
    // starting state, which is the case a MAC gets wrong if it forgets the
    // length counter along with the chaining state. So: hash a **multi-block**
    // message, reset, then hash *nothing* and check the result is the
    // empty-message digest.
    //
    // The multi-block part is not decoration. A reset that cleared the eight
    // chaining words but left `block_len` at its stale value is invisible to
    // a message shorter than 128 bytes — no block was ever compressed, so the
    // counter was already zero and the bug has nothing to show. Feed it
    // something past a block boundary or the test passes anyway; that exact
    // gap was found by mutating `Reset` to do this and watching this
    // assertion stay green with a 63-byte message.
    let mut big = msg.to_vec();
    big.extend_from_slice(&[0xa7u8; 1000]);
    assert!(
        big.len() > 1024,
        "the reset cases must run on a multi-block message"
    );

    let mut h = D::new();
    Digest::update(&mut h, &big);
    assert_eq!(
        hex(&h.finalize_reset()),
        hex(&sha2::Sha512::digest(&big)),
        "{subject}: finalize_reset first use"
    );
    assert_eq!(
        hex(&h.finalize_reset()),
        hex(&sha2::Sha512::digest(b"")),
        "{subject}: finalize_reset did not restore the initial state"
    );

    let mut h = D::new();
    Digest::update(&mut h, &big);
    Reset::reset(&mut h);
    Digest::update(&mut h, b"");
    assert_eq!(
        hex(&h.finalize()),
        hex(&sha2::Sha512::digest(b"")),
        "{subject}: reset"
    );

    // And the reuse that a `Hmac` actually performs: a fresh key after a
    // dirty instance.
    let mut h = D::new();
    Digest::update(&mut h, msg);
    let _ = h.finalize_reset();
    Digest::update(&mut h, msg);
    assert_eq!(
        hex(&h.finalize()),
        hex(&sha2::Sha512::digest(msg)),
        "{subject}: reuse after finalize_reset"
    );
}

/// The hasher under test, and the one it must match.
///
/// Ordered deliberately: `sha2` is listed first and is expected to be listed
/// first when this file was first run — the EPIC's ordering requirement is
/// that the suite is green on stock `sha2` *before* anything is swapped, and
/// keeping the stock entry above the port makes the order in which a reader
/// evaluates the guarantees the same as the order they were established in.
///
/// So this function asserts two separate things and the second one only means
/// something because of the first:
/// 1. the suite is sound — stock `sha2`, hashed every way the suite knows
///    how, reproduces the published NIST vectors; and
/// 2. the port is interchangeable — `platform::sha512::Sha512`, through the
///    identical suite, produces identical bytes, including identical bytes to
///    the `sha2` run in (1).
#[test]
fn differential() {
    suite::<sha2::Sha512>("sha2::Sha512 (stock — the reference, and the drop-in's oracle)");
    suite::<fapico2_platform::sha512::Sha512>("platform::sha512::Sha512 (US-1070 rolled)");
}
