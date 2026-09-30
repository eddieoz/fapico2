// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

//! US-947: OpenPGP KDF-DO (tag F9) — structure and PUT validation.
//!
//! # Structure (verified against the OpenPGP card spec 3.4 §4.3.2 and gpg)
//!
//! The card-side reference is gpg itself: `g10/card-util.c gen_kdf_data`
//! builds the KDF-DO that `kdf-setup` PUTs, and scdaemon
//! (`scd/app-openpgp.c pin2hash_if_kdf`) re-reads it expecting exactly
//! 90 or 110 bytes with byte 2 == 0x03. The PUT/GET data is the *raw*
//! value — no F9 TLV prefix:
//!
//! ```text
//! off:  81 01 00                                   (3 bytes)
//! on:   81 01 03        KDF_ITERSALTED_S2K
//!       82 01 08 | 0A   SHA-256 | SHA-512
//!       83 04 xx xx xx xx   iteration count, 4-byte big-endian
//!       84 08 <8>       salt-U (PW1)
//!       [85 08 <8>      salt-R (resetting code)
//!        86 08 <8>]     salt-S (PW3)     — three-salt (110 B) form only
//!       87 20 <32>      initial PW1 hash
//!       88 20 <32>      initial PW3 hash
//! ```
//!
//! # The card stores the parameters; the host derives
//!
//! PSO:DECIPHER ECDH returns the **raw** ECDH shared point whatever the
//! KDF-DO says. GnuPG applies the key-encryption-key derivation in software
//! on the client side (`g10/ecdh.c` `extract_secret_x` then `derive_kek`,
//! keyed on the KDF parameter blob carried in the *public key*, not on the
//! KDF-DO), so a card that derived too would double-derive and silently
//! fail every real gpg decryption. The KDF-DO is kept so the host can read
//! the parameters back with GET DATA F9 and derive locally.

use iso7816::Status;

/// PUT DATA F9 gate (US-947 decision 1): only the two valid shapes are
/// stored; anything else answers `IncorrectDataParameter` (6A80) — the
/// card's parameter-validation convention (US-943/945) — and the caller
/// performs no state write, so the stored DO is unchanged.
pub fn validate(kdf_do: &[u8]) -> Result<(), Status> {
    if is_valid(kdf_do) {
        Ok(())
    } else {
        warn!("PUT DATA F9 rejected: malformed KDF-DO ({} bytes)", kdf_do.len());
        Err(Status::IncorrectDataParameter)
    }
}

/// The exact gpg kdf-setup layouts: `81 01 00` (off), or 90 bytes (single
/// salt) / 110 bytes (three salts) with every TLV and the overall length
/// checked exactly.
fn is_valid(kdf_do: &[u8]) -> bool {
    if kdf_do == [0x81, 0x01, 0x00] {
        return true;
    }
    if kdf_do.len() != 90 && kdf_do.len() != 110 {
        return false;
    }
    if &kdf_do[0..3] != &[0x81, 0x01, 0x03] {
        return false;
    }
    if &kdf_do[3..5] != &[0x82, 0x01] {
        return false;
    }
    match kdf_do[5] {
        0x08 | 0x0A => {}
        _ => return false,
    }
    if &kdf_do[6..8] != &[0x83, 0x04] {
        return false;
    }
    // A zero iteration count is not a usable s2k count.
    if kdf_do[8..12] == [0, 0, 0, 0] {
        return false;
    }
    if &kdf_do[12..14] != &[0x84, 0x08] {
        return false;
    }

    // Three-salt (110 B) form carries salt-R (85) and salt-S (86).
    let mut p = 22;
    if kdf_do.len() == 110 {
        if &kdf_do[p..p + 2] != &[0x85, 0x08] {
            return false;
        }
        p += 10;
        if &kdf_do[p..p + 2] != &[0x86, 0x08] {
            return false;
        }
        p += 10;
    }
    if &kdf_do[p..p + 2] != &[0x87, 0x20] {
        return false;
    }
    p += 34;
    if &kdf_do[p..p + 2] != &[0x88, 0x20] {
        return false;
    }
    p += 34;
    debug_assert_eq!(p, kdf_do.len(), "layout bookkeeping must cover the whole DO");
    true
}
