//! The applet-shaped measurement unit for US-1634 (epic `NOSTR-APPLET`):
//! every public primitive is reachable, so the linked `text` is the honest
//! flash cost of carrying this second secp256k1 implementation on the board.
//! Built detached from the firmware's own graph on purpose — the number this
//! produces is the *marginal* cost of the crate, recorded in ADR 0005.
#![no_std]
#![no_main]

use nostr_secp_spike::{
    bip340_sign, bip340_verify, calc_padded_len, conversation_key, decrypt_with_ck,
    encrypt_with_ck, message_keys, xonly_pubkey, MAX_PAYLOAD,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut out = [0u8; MAX_PAYLOAD];
    let mut pt = [0u8; 1900];
    let mut r = 0u32;

    let sk = [1u8; 32];
    let peer = [2u8; 32];
    let aux = [3u8; 32];
    let msg = [4u8; 32];

    let pk = xonly_pubkey(&sk).unwrap_or([0; 32]);
    r ^= pk[0] as u32;
    r ^= bip340_sign(&sk, &msg, &aux)
        .unwrap_or([0; 64])
        .iter()
        .fold(0u32, |a, b| a.wrapping_mul(3).wrapping_add(*b as u32));
    r ^= bip340_verify(&pk, &msg, &[0u8; 64]).unwrap_or(false) as u32;
    let ck = conversation_key(&sk, &peer).unwrap_or([0; 32]);
    let mk = message_keys(&ck, &msg);
    r ^= mk.chacha_key[0] as u32 ^ mk.chacha_nonce[0] as u32 ^ mk.hmac_key[0] as u32;
    r ^= calc_padded_len(1900).unwrap_or(0) as u32;
    let n = encrypt_with_ck(&ck, &msg, &pt, &mut out).unwrap_or(0);
    let m = decrypt_with_ck(&ck, &out[..n], &mut pt).unwrap_or(0);
    r ^= m as u32 ^ out[0] as u32;

    // Park the result where no optimiser can fold it away.
    unsafe {
        core::ptr::write_volatile(0x4000_0000 as *mut u32, r);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
