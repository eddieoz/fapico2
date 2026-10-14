# Spike notes — `secp256kfun` for the Nostr applet (US-1632, US-1633)

The detached workspace for Phase 0 of epic `NOSTR-APPLET`. It must stay out of
the fapico2 workspace graph (`[workspace]` stub in `Cargo.toml`) so the
supply-chain gates see the real dependency set only when US-1636 updates it.

## US-1632 — the build

`nostr-secp-spike` compiles `#![no_std]` with **no `alloc`** and links for
`thumbv8m.main-none-eabi` at `opt-level = "z"` (the release profile also pins
`lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = true`).

Recorded 2026-10-10, toolchain rustc 1.99.0, target `thumbv8m.main-none-eabi`
installed. Dependency set and features:

| crate | version | features |
|---|---|---|
| `secp256kfun` | 0.12.1 | `default-features = false` (drops `std`; brings `subtle-ng 2.5.0`, `secp256kfun_arithmetic_macros 0.2.0` — the two §7-forecast packages) |
| `sha2` | 0.10.9 | `default-features = false` |
| `hmac` | 0.12.1 | `default-features = false` |
| `chacha20` | 0.9.1 | `default-features = false` |

`chacha20 0.9.1` has no default features to disable (`std`/`zeroize` are the
only optionals); the `ChaCha20` type and the `cipher::{KeyIvInit,StreamCipher}`
traits are available without any feature.

`secp256kfun 0.12.1` is edition-2024 / rust-version 1.85 — the firmware's
pinned toolchain satisfies this (host rustc 1.99.0 used here; the firmware
workspace pins its own toolchain in `rust-toolchain.toml`, unaffected by this
detached spike).

**The measurement bin** (`src/bin/spike_size.rs`, `cargo build
--target thumbv8m.main-none-eabi --release`): an applet-shaped unit whose
`_start` reaches every public primitive, so `--gc-sections` keeps what an
applet would actually carry. `size` on the linked ELF:

```
   text      data      bss      dec      hex
  25046         0        0    25046     61d6   spike_size
```

**25,046 B of `text` is the measured marginal flash cost** of a second,
independent secp256k1 implementation at `opt-level = "z"` — the number ADR
0004's D8 decision is written on (US-1634). For contrast: the ratchet raise
US-1630 settled left 44,032 B of deliberate headroom, and the firmware's
`text` was 861,912 B at the measurement date.

The spike links with rust-lld's default layout — the firmware's
`.cargo/config.toml` `-Tlink.x`/`-Tdefmt.x` args are overridden via
`RUSTFLAGS` because cargo *appends* target `rustflags` across config files
rather than replacing them.

## US-1633 — the vectors and the unhashed-x pin

`tests/vectors.rs` runs, on the host target:

- **BIP-340** (`vectors/bip340.csv`, bitcoin/bips master): all sign rows and
  all verification rows, including the refusal rows whose public key is
  intentionally off-curve — those are the rows where `from_xonly_bytes`
  returns `None` and `bip340_verify` reports `Err(InvalidPeerX)`, which is the
  "did not verify" reading the rows demand.
- **NIP-44 v2** (`vectors/nip44.vectors.json`, sha256
  `269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040` — the
  checksum the NIP itself publishes): 36 conversation-key rows (+9 refusal
  rows), 33 message-key rows, the calc_padded_len table plus the `1`/`32`/`0`
  edges, 11 encrypt round-trips **byte-exact against the reference payload**,
  13 hostile decrypt payloads, 4 long-message vectors anchored by sha256 over
  the **compressed (base64)** payload — the anchors are over the form a NIP-44
  client transmits, not the raw bytes.
- `nip44_encrypt_forbidden_lengths_refused`: 0, 65536, 100000, 10000000 all
  refused with `InvalidMessageLen`.

**The §2.5 pin — which API yields the unhashed x:** the shared point is
`op::scalar_mul_point(a, B)` with `B =
Point::<EvenY, Public, NonZero>::from_xonly_bytes(peer_x)` (y assumed even —
exactly the reference's `'02'+pubkey` lift), and the x fed to
`HMAC-SHA256(key = "nip44-v2")` is the **raw coordinate** from
`Point::coordinates().0` (equivalently `to_xonly_bytes()`). `secp256kfun`
never hashes this leg. The proof is the vector set itself: every
`get_conversation_key` row passes with the raw coordinate and would fail under
any hashing accessor. `tests/conversation_key_uses_unhashed_shared_x` states
that explicitly.

Two transcription traps this spike hit, worth keeping visible:

1. **BIP-340's aux is tag-hashed before the XOR.** The nonce seed is
   `t = bytes(d) ⊕ hashBIP0340/aux(aux)` — an earlier draft XORed the raw
   `aux` bytes and every vector failed identically (both this spike and an
   independent re-derivation). The challenge/nonce tags are doubled
   (`SHA256(tag) ‖ SHA256(tag) ‖ …`) as usual.
2. **The NIP-44 ciphertext covers the 2-byte unpadded-length prefix.**
   The reference's `pad()` returns `prefix ‖ plaintext ‖ suffix` and the whole
   of it is encrypted: `ct_len = 2 + calc_padded_len(n)` — not
   `calc_padded_len(n)`. A payload encrypted with the prefix outside the
   ciphertext is 2 bytes short and matches no vector. `decrypt_with_ck`'s
   check `ct_len == 2 + calc_padded_len(unpadded_len)` is the same
   arithmetic the reference's `unpad()` performs.

## API notes for Phase 1/2 (the applet's `§2.5` rows)

- Scalar validation (`IMPORT_KEY`): `Scalar::<Secret, NonZero>::from_bytes`
  returns `None` for zero **and** for values ≥ the curve order — the BIP-340
  bounds on `d'` for free.
- Point lifting (`NIP-44` peer/sender x): `Point::<EvenY, Public,
  NonZero>::from_xonly_bytes` returns `None` for x ≥ p and for x = 0 (the
  `y² = x³ + 7` solve fails) — the curve-point validation of US-1656 is this
  constructor.
- Scalar multiplication goes through `op::scalar_mul_point`, `.normalize()`,
  `.non_zero()`; y-parity is `.is_y_even()`; the x-only encoding is
  `.coordinates().0`. There is no `schnorr` module in 0.12 — BIP-340 is
  hand-rolled on these ops (~60 lines), which is what `bip340_sign` here is.
- No `alloc` is touched anywhere in the spike; every buffer is caller-owned.
