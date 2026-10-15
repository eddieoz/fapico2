# audit-secp256kfun — red-team probes for the Nostr applet's secp256kfun

Detached probe crate backing `docs/audits/secp256kfun-nostr-security-audit.md`.
Not a member of the fapico2 workspace (same exclusion precedent as
`spike-secp256kfun/`), so the supply-chain gates never see it.

## What it proves

1. **Applet BIP-340 conformance, byte-exact.** `tests/bip340_conformance.rs`
   `#[path]`-includes the live `apps/nostr/src/crypto.rs` (no copy, no drift)
   and runs the full BIP-340 reference vector set
   (`spike-secp256kfun/vectors/bip340.csv`, 19 rows): every signable row
   reproduces the reference signature byte-for-byte, `xonly_pubkey` matches
   the `pk` column, an in-probe verifier agrees with all 19 verify verdicts,
   and the scalar/x-only edge cases behave exactly at the BIP-340 bounds.
2. **The device arithmetic is correct, not just the host arithmetic.** The
   RP2350 (thumbv8m, 32-bit) compiles `field_10x26.rs` + `scalar_8x32.rs`;
   every host test in the repo compiles `field_5x52.rs` + `scalar_4x64.rs`.
   The lib includes the *device* sources verbatim on the host and
   differential-tests them against `src/device_vectors.rs` — 314 field cases
   and 182 scalar cases (edges around p and n, doubling, cross products)
   whose expected values come from plain modular arithmetic in
   `tools/gen_device_vectors.py`. All match.
3. **Constants verified from first principles.** `tools/bip340_python_verify.py`
   is an independent pure-python secp256k1/BIP-340 oracle. It verifies every
   hardcoded constant in the vendored backends (p, n, n/2, 2^256−n, the
   26-bit and 52-bit field limb minuends, the fold constant 0x1000003D1, G,
   the Tonelli–Shanks exponent (t−1)/2 for S=6, the sqrt chain (p+1)/4
   exponent), the GLV endomorphism (`λ·Q = (β·x, y)`, `MINUS_LAMBDA = n−λ`,
   the EEA identity), and independently verifies/reproduces all 19 CSV rows.
4. **NIP-44 v2 adversarial surface.** `tests/nip44_adversarial.rs` runs the
   full published vector set through the live `apps/nostr/src/nip44.rs`
   (conversation keys, message keys, encrypt/decrypt, invalid payloads, the
   65535-byte long-message rows), then sweeps every truncation offset and
   every single-bit flip of a valid payload (all refused cleanly, no panic),
   checks the `MAX_PLAINTEXT`-anchored capacities, and cross-checks
   `calc_padded_len` (both twins) against an independently formulated
   reference over the whole 0..=65640 domain.

## Rerun

```bash
python3 audit-secp256kfun/tools/bip340_python_verify.py      # python oracle
python3 audit-secp256kfun/tools/gen_device_vectors.py        # regenerate vectors
cd audit-secp256kfun && cargo test                            # 26 Rust probes
```

The registry paths in `src/lib.rs` (the `#[path]` includes of the verbatim
`field_10x26.rs` / `scalar_8x32.rs`) pin secp256kfun 0.12.1's extracted
source at `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`; their
checksums were verified against `Cargo.lock` as part of the audit.

Status as of 2026-10-14: **all 26 Rust tests + all python oracle checks pass.**
