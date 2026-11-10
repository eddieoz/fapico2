//! US-1824 (WARM-BOOT-SERVE): `LazyDrbg` — seed-once-then-serve cell.
//!
//! Host tests. The cell starts unseeded; draws refuse `NotSeeded` and leave
//! the caller's buffer untouched (D-9). Seeding once makes it ready; a
//! second seed is a bug (asserted).

use fapico2_platform::trng::{LazyDrbg, Trng, TrngError};
use zeroize::Zeroizing;

struct RefusingSource;
impl fapico2_platform::drbg::SeedSource for RefusingSource {
    fn seed(&mut self) -> Result<fapico2_platform::drbg::SeedMaterial, fapico2_platform::drbg::SeedError> {
        Err(fapico2_platform::drbg::SeedError::Trng(TrngError::Stalled))
    }
}

struct WorkingSource;
impl fapico2_platform::drbg::SeedSource for WorkingSource {
    fn seed(&mut self) -> Result<fapico2_platform::drbg::SeedMaterial, fapico2_platform::drbg::SeedError> {
        Ok(fapico2_platform::drbg::SeedMaterial {
            seed: Zeroizing::new([0u8; fapico2_platform::drbg::OUTLEN]),
            nonce: Zeroizing::new([0u8; fapico2_platform::drbg::NONCE_LEN]),
        })
    }
}

#[test]
fn unseeded_fallible_refuses() {
    let mut cell: LazyDrbg<RefusingSource> = LazyDrbg::new();
    assert!(!cell.is_ready());
    let mut buf = [0xABu8; 8];
    assert_eq!(cell.try_random_bytes(&mut buf), Err(TrngError::NotSeeded));
}

#[test]
fn unseeded_infallible_leaves_buffer_untouched() {
    let mut cell: LazyDrbg<RefusingSource> = LazyDrbg::new();
    let mut buf = [0xABu8; 8];
    let before = buf;
    cell.random_bytes(&mut buf);
    assert_eq!(buf, before, "D-9: unseeded cell must leave buffer untouched");
}

#[test]
fn seeded_once_becomes_ready() {
    let mut cell: LazyDrbg<WorkingSource> = LazyDrbg::new();
    assert!(!cell.is_ready());
    cell.seed(WorkingSource).expect("seed should succeed");
    assert!(cell.is_ready());
    // a draw now works (no longer NotSeeded)
    let mut buf = [0u8; 4];
    assert!(cell.try_random_bytes(&mut buf).is_ok());
}

#[test]
#[should_panic(expected = "seeded-once violated")]
fn second_seed_is_a_bug() {
    let mut cell: LazyDrbg<WorkingSource> = LazyDrbg::new();
    cell.seed(WorkingSource).expect("first seed");
    let _ = cell.seed(WorkingSource);
}