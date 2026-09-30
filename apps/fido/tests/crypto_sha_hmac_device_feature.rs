//! S-701-1 TDD: the device-feature crypto path (sha2/hmac/aes compiled for
//! `device`) produces the pinUvAuth primitives the PIN protocol depends on.
//!
//! `pin_hash_matches_host_vectors` — the primitives are anchored against
//! published vectors (FIPS 180 SHA-256, RFC 4231 HMAC-SHA256) and the
//! truncated PIN-hash / pinUvAuthParam forms used by the CTAP2 clientPin
//! protocol (the same classes the pytest suite `tests/pico-fido/
//! test_010_pin.py` exercises end-to-end through python-fido2).

use fapico2_fido::crypto;

fn hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[test]
fn pin_hash_matches_host_vectors() {
    // FIPS 180-4 SHA-256 vector.
    assert_eq!(crypto::sha256(b"abc"), hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    assert_eq!(crypto::sha256(b""), hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

    // pin_hash: SHA-256 truncated to 16 bytes (CTAP2 clientPin pinHash).
    let pin_hash = crypto::pin_hash(b"1234");
    assert_eq!(pin_hash.as_slice(), &crypto::sha256(b"1234")[..16]);
    assert_eq!(pin_hash.len(), 16);

    // RFC 4231 test case 2: HMAC-SHA256("Jefe", "what do ya want for nothing?").
    let mac = crypto::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(mac, hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    // The _into form (the device command path's shape) matches.
    let mut mac2 = [0u8; 32];
    crypto::hmac_sha256_into(b"Jefe", b"what do ya want for nothing?", &mut mac2);
    assert_eq!(mac2, mac);

    // pinUvAuthParam v1: HMAC-SHA256 truncated to 16 bytes.
    let truncated = &crypto::hmac_sha256(b"Jefe", b"what do ya want for nothing?")[..16];
    assert_eq!(truncated.len(), 16);
    assert_eq!(truncated, &mac[..16]);

    // AES-256-CBC round trip through the in-place device core (NoPadding).
    // NIST SP 800-38A F.2.1 CBC-AES256 encrypt vector, block 1 only.
    let key = [0x60u8, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
               0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4];
    let iv = [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let pt = [0x6bu8, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
    let mut buf = pt;
    crypto::aes256_cbc_encrypt_into(&key, &iv, &mut buf).unwrap();
    assert_eq!(buf, [
        0xf5u8, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6]);
    crypto::aes256_cbc_decrypt_into(&key, &iv, &mut buf).unwrap();
    assert_eq!(buf, pt, "decrypt inverts the in-place encrypt");
}
