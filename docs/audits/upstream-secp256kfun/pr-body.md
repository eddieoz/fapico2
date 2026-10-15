`Scalar8x32::from(u64)` masks its input with `0xFFFF` instead of
`0xFFFF_FFFF`, silently dropping bits 16–31: `From(0x1_0000u64)`
produces zero and `From(0x1234_5678_9ABC_DEF0u64)` loses bits 16–31.
The 64-bit backend's equivalent conversion is correct, so host-side
tests never see this. The mask is inherited: it appears in
k256's `scalar_8x32.rs` at its final pre-removal state (commit
`9748fd9853` in the RustCrypto/elliptic-curves monorepo, where k256
then lived); k256 deleted the backend in September 2021 (PR #409,
`U256` refactor), so the code was vendored with the bug rather than
introducing it.

The impl is currently unreachable: no caller exists inside the crate
(the public integer conversions on the API `Scalar` take the
range-checked byte-array path, the wrapper's own `From<u32>` chain into
it is uncalled, and `mod vendor`/`mod backend` are private), so this is
a latent hazard rather than a live bug and no released behaviour
changes with the fix. The conversion is non-reducing by design,
consistent with `From<u32>` on the same type and with
`Scalar4x64::From<u64>`.

The change is one line plus a unit test in the file's own `#[cfg(test)]`
module, which the armv7 CI leg (`cross test --all-features`) compiles
and runs. To reproduce the failure on the pre-fix code, revert the
hunk and run `cross test --target armv7-unknown-linux-gnueabihf -p
secp256kfun` (requires `cross`/Docker; the test only compiles on
32-bit targets); the added test fails on `0x1_0000u64`. It was also
verified fails-before/passes-after by compiling the pre- and
post-patch backends verbatim on a host and comparing against plain
modular arithmetic.

Found during an independent audit of the crate; details and lineage in
#<ISSUE-NR> (audit validation report).
