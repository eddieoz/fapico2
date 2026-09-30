//! Shared helpers for the fapico2-openpgp integration tests.
//!
//! The US-950 AES roundtrip is pinned twice — once over opcard's virt
//! dispatch (`tests/dispatch.rs`) and once over the platform `SyscallRunner`
//! client the RP2350 actually builds (`tests/device_pso.rs`) — because
//! `Mechanism::Aes256Cbc` has no arm in the platform `OpcardDispatch` and
//! falls through to trussed core, so a device build could reach PSO:ENCIPHER
//! and fail while the virt path stayed green. The point of a twin is that the
//! two paths are genuinely comparable, so the request encoder and the
//! host-side reference cipher live here instead of being copy-pasted: a
//! divergence between the twins is then impossible to introduce by accident.

/// PSO:ENCIPHER (INS 2A, P1P2 = 86 80) with the raw plaintext — §7.2.11.
/// Extended Lc (3-byte) + no Le, the same shape as `pso_decipher_apdu`: the
/// `02`-prefixed reply is shorter than the block count the host sends plus
/// the indicator only for large DOs, and the dispatcher sizes the response
/// buffer itself.
pub fn pso_encipher_apdu(data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00u8, 0x2A, 0x86, 0x80, 0x00];
    apdu.extend_from_slice(&(data.len() as u16).to_be_bytes());
    apdu.extend_from_slice(data);
    apdu
}

/// AES-256-CBC encrypt with a zero IV and no padding — the exact operation
/// the card's AES encipher path performs (trussed `Aes256Cbc` uses
/// `cbc::Encryptor` with `NoPadding`, and an empty nonce → IV = 0). The
/// mirror of the twins' `aes256_cbc_zero_iv_decrypt`.
pub fn aes256_cbc_zero_iv_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncrypt as _, KeyInit as _};

    let cipher = aes::Aes256::new_from_slice(key).expect("32-byte AES key");
    assert_eq!(plaintext.len() % 16, 0, "CBC operates on whole blocks");
    let mut previous = [0u8; 16]; // zero IV
    let mut out = Vec::with_capacity(plaintext.len());
    for chunk in plaintext.chunks(16) {
        let mut block = aes::Block::clone_from_slice(chunk);
        for (b, p) in block.iter_mut().zip(previous.iter()) {
            *b ^= p;
        }
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
        // CBC chains the previous *ciphertext* block, not the previous
        // plaintext one (the mirror of `aes256_cbc_zero_iv_decrypt`, which
        // copies the ciphertext chunk it just consumed).
        previous.copy_from_slice(&block);
    }
    out
}
