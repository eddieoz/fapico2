# fapico2-release-alpha-v0.3.1 — Release Notes

**Date:** 2026-10-25 · **Target:** Raspberry Pi Pico 2 (RP2350), USB-connected
**Theme:** the code-review hardening release (PR
[#20](https://github.com/eddieoz/fapico2/pull/20)) — dead code removed, one
inert security mechanism deleted, two wire-shape corrections, and the
dependency graph cleared of two fresh RUSTSEC advisories.

**This is an alpha.** Alpha/beta images keep the debug port available and burn
nothing irreversible into OTP ([ADR 0002](adr/0002-provisioning-policy.md)).

## What changed, in order of weight

### The FIDO allocator's generation table was fiction — now deleted, docs honest

`FidoAllocator` carried a per-slot "high-water" generation table whose write
branch could never feed its read branch: it wrote entries only for *occupied*
slots and returned at the first *free* one, so every free-slot allocation
issued generation 1 and the 848-entry table never affected any output. The
module doc claimed per-slot generation monotonicity "survives a power cycle" —
true only for slots whose header still parses. The inert table is deleted
(behaviour-preserving by construction) and the docs now state the real rule:
rewrites and deletes of readable records are monotonic; a slot whose header
was destroyed (torn commit, interrupted erase) re-enters at generation 1, the
MAC-bound `IndexEntry::generation` field is the recorded backstop, and seeding
the floor from the index is written up as the fix if the residual is ever
judged live.

### Two wire-shape corrections (checked against the extension's senders)

- **`GENERATE_KEY` with an out-of-range index now answers `6A80`** (wrong
  data) like every other idx-taking command, instead of `6A84` (occupied) —
  the old word told the user a nonexistent slot was "taken".
- **`VERIFY_PIN` and `LOCK` now enforce P1 = P2 = 0** with `6A86`, exactly as
  their dialect docs have always specified (and as `CEREMONY_START` already
  did). Verified against every sender before tightening: the
  fapico2-nostr-extension's PIN handlers already send zeros, and the shape
  refusal consumes nothing — a malformed VERIFY with the *correct* PIN burns
  no retry (`tests/wire.rs::pin_verbs_refuse_nonzero_p1_p2`).

A third classification change is set-equal: the PIV-PIN-wrapped DEK
(`EF_DEK_PWPIV 0x109D`) now sits in `is_openpgp_migration_fid` with the rest
of the C `files.h` DEK table, so the migration lists restate each other
honestly. No record changes behaviour — the migration path admitted it
through a duplicate arm before.

### The supply chain: two RUSTSEC advisories cleared, one accepted

`RUSTSEC-2026-0385` (`ctutils`) and `RUSTSEC-2026-0387` (`crypto-bigint`) —
both published 2026-10-23 — are constant-time defects in primitives the
firmware's crypto stack rides on. The 0.7 line is bumped past them
(`crypto-bigint` 0.7.5 → 0.7.9, carrying `ctutils` 0.4.2 → 0.4.5). The two
*older* locked crypto-bigint generations (0.2.5, 0.5.5) have no patched
release in their own lines; the advisory is accepted in `deny.toml` with the
reason written out — the workspace spans three RustCrypto generations for
trussed/opcard compatibility, and the honest label is "no patch exists for
the versions we are pinned to", not "not affected"
([docs/supply-chain.md](supply-chain.md) carries the refreshed figures).

### Dead code and rot

Dead-code removals across `platform/`, `apps/` and `firmware/` (each verified
zero-references across every crate, test, CI job and doc): `BufferImageSource`,
`AutoPresence`, `DecodedRecord::into_body`, `NostrRegion::legacy_window_open`,
`gcm_unwrap_serial_aad_pub`, `is_config_locked`, `is_restore`,
`region_counter_window`, `E_MIGRATION_NO_REGION`, `DEFAULT_MAX_LARGE_BLOB`
(which contradicted the shipped `maxLargeBlob = 1024`),
`UNCONFIGURED_USB_ITF` (its documented behaviour existed nowhere), and the
dead test helpers. Two latent bugs fixed on the boot path: `cflash::reserved`
now saturates (a hand-built partition could underflow into a wrapped end
address), and the partition-table scan keeps looking past a truncated block
instead of aborting. Comment rot corrected where prose contradicted code
(the C-parity "either/both words" note, a doc block pasted onto the wrong
function in `nostr_store.rs`, the enumerate-cap comment naming the wrong
bound). Three security residuals — the OATH torn-record GCM nonce re-spend,
the pre-carve orphan that can block the Nostr custody ceremony, and the
generation-1 re-entry above — are now recorded next to the code they
describe, each with the attack and the fix written down.

## Upgrading from v0.3.0

Nothing to do. No data-format change, no storage migration, no new refusal a
conforming client reaches: the extension's own suite (408/408) and the
firmware emulator suites both pass against this build unchanged. The custody
ceremony, the PIN gate and the identity set behave exactly as v0.3.0's
[release notes](release-notes-alpha-v0.3.0.md) describe.

## Verification

Both clippy gates (`-D warnings`, host and thumb), 1,867 host tests, 158
firmware lib tests, the full emulator suite, the six structural gates, the
device-integration gate (boot chain 93,764 B ≤ 98,304 B, arena demand
re-measured at 14,344 B), cargo-deny and cargo-vet all green on the exact
commit this tag names.
