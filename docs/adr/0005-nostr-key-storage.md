# ADR 0005: Nostr key storage — device-bound keyregion domain, and the second secp256k1 implementation

**Status:** Accepted (2026-10-10)
**Supersedes:** nothing
**Superseded by:** nothing
**Amended by:** [ADR 0006](0006-nostr-pin-custody.md) (2026-10-15) — the custody row, below
**Context docs:** [`docs/tasks/nostr-applet-design.md`](../tasks/nostr-applet-design.md) §2.4–§2.5
(the approved design; its Decision Log §9.1 D4 and D8 are the authority for the "why"),
[`docs/tasks/EPIC-nostr-applet.md`](../tasks/EPIC-nostr-applet.md) US-1634, US-1637.
**Measurement evidence:** `spike-secp256kfun/spike-notes.md` in the `feat/nostr` worktree
(US-1632/US-1633/US-1634), Phase −1 gates green on the unmodified-for-Nostr tree.

## Decision

Two decisions, recorded together because the second one is only defensible on a
measurement the first one's shape produces:

1. **Nostr identity keys live in `platform/src/keyregion` as a third domain
   (`KeyDomain::Nostr = 3`), sealed under a key derived
   `derive_payload_key(otp_key_1, chipid, NOSTR_PAYLOAD_SECRET)` — device-bound,
   depending on nothing `authenticatorReset` or management `RESET` can destroy.**
   One record per identity in a 1024-byte slot
   (`scalar(32) ‖ npub(32) ‖ label(≤32 bytes) ‖ flags(1)` → 97 B plaintext, ~125 B
   sealed), sealed with the existing `seal_payload`/`open_payload` whose `RecordAad`
   binds **domain, slot and generation** — a Nostr record physically cannot open as
   a FIDO or OATH record. No PIN-derived input anywhere in the derivation.
2. **Two independent secp256k1 implementations in the shipped binary are accepted
   for v1, on the measurement recorded below.** Nostr signing is BIP-340 on-device
   via `secp256kfun` (`default-features = false`); routing through the trussed
   `Client` is rejected.

### The geometry (US-1639 follows from this, not the other way round)

Nostr's 8 slots are carved **from the top of FIDO's range** so
`FidoAllocator::alloc` — which grows from `FIDO_FIRST_SLOT` upward
(`fido_store.rs:467`) — leaves every existing record's address unchanged.
`FIDO_CAPACITY` falls **856 → 848**. The tiling asserts
(`keyregion/mod.rs:326-333,344,345`), `is_nostr_slot` (published beside
`is_oath_slot`/`is_fido_slot`, `oath_store.rs:276` precedent) and
`platform/tests/key_region_capacity.rs` all gain the Nostr term, because the
region is fully tiled and the build refuses to compile otherwise.

**The carve is enforced, not described.** Keeping a record's *address* stable does
not keep it *safe*: the vacated top slots become a Nostr-writable overwrite target,
and `alloc` scanning only `FIDO_FIRST_SLOT..FIDO_SLOT_LIMIT` will not report `Full`.
All four `is_fido_slot` guard sites (`fido_store.rs:506,1103,1340,1454`) stop
covering the carved slots, and `fido_slot_at` refuses out-of-range indices typed.

### The occupancy guard (§2.4.2's required design element)

The Nostr store must not write a slot whose occupant it cannot identify. The
predicate asks two different questions, **in this order**:

1. Slot reads back **virgin** (`RecordOccupancy` — never written) → free; write it.
2. Slot reads back **occupied** → it must **open successfully as a Nostr record**
   (`KeyDomain::Nostr` AAD match + AEAD authentication) before reuse. If it does
   not, it holds a FIDO record or something else, and the write is **refused**.

An earlier draft phrased rule 2 as "refuse a slot that is not provably empty",
which is self-defeating — a virgin slot does not open, so as written the applet
could never write anything. Virgin and occupied are different questions; the check
asks both, in that order.

## Why device-bound (and what killed the user-bound alternative)

A Nostr identity is a **publishing identity — non-revocable, recoverable by no
one**. OATH reaches device-bound because a TOTP seed is disposable; FIDO because
pin-gating would orphan every pre-PIN credential and require a whole-region re-key
transaction. Nostr inherits both reasons **and** adds one nobody had enumerated
before the third review pass:

**`pin_hash` and `device_random` both live in the FIDO keystore, and two ordinary,
single-touch operations destroy them** — `authenticatorReset` (CTAP2 `0x07`,
touch-gated) reaches `DeviceKeystore::reset` (`device_keystore.rs:2889-2895`),
which clears `pin_hash`; `reset_from_seed` (`:2860`) **rotates `device_random`**
(so stated at `device_core.rs:2567`); management `RESET` also wipes the keystore
slot. Neither takes a PIN token, and the Nostr applet controls neither. So the
user-bound derivation — the second draft's posture, citing `region_pin_secret` as
precedent — produces exactly one of two bad outcomes:

- if `apps/nostr` implements `App::factory_wipe`, the identity is **deleted** by a
  button the user pressed for something else (deletion is otherwise unrecoverable);
- if it does not, the records survive sealed under a key derived from state that no
  longer exists: **unopenable forever, still consuming slots, indistinguishable
  from valid data.**

Both branches are bad, and the applet cannot prevent either from inside its own
`process()`. `AGENTS.md` §5's rule applies: the complexity does not stop an
attack — it introduces a new *data-loss* failure mode. **Device-bound records
survive `authenticatorReset` intact because nothing the reset destroys is an input
to their key.** A side benefit the user should hear: the forgotten-PIN recoveries
(`MAX_PIN_RETRIES = 8`, `pin.rs:51` — after which only the resets above remain)
become *safe*.

The rules that follow (design requirements, not suggestions):

1. A Nostr record's key depends on nothing `authenticatorReset` or management
   `RESET` can destroy — satisfied by construction.
2. The applet implements `factory_wipe` **deliberately** (erase Nostr slots, no
   indistinguishable residue), and the wipe is **announced by the host
   pre-flight** (enumerate via `LIST_KEYS`, show what will be destroyed, refuse
   without acknowledgement) — `App::factory_wipe` returns `()` and cannot report
   (US-1650).
3. Proposing the user-bound derivation again requires solving whole-region
   re-keying on `authenticatorReset` first — a real transaction with a real
   power-cut failure mode, which `device_keystore.rs:3441-3478` declined to ship
   for FIDO. (That function's own doc says **"Device-rooted, not PIN-gated —
   deliberately"**; the `_pin_state` parameter is unused.)

What the user gets — and the design claims nothing beyond it: a Nostr identity is
not extractable from flash without the OTP row *and* the chip-id, unreadable by
other applets, and unusable without a physical touch — including `EXPORT_KEY`,
the one command that hands the key to a host at all. That property holds until the
user presses once on `EXPORT_KEY`; the README (US-1676) recommends
generate-in-software-then-`IMPORT_KEY` precisely so the user chooses which posture
they are in.

### Rejected storage backends

| Alternative | Why rejected |
|---|---|
| The 24-entry `Rp2350SecureStore` | Legacy backend, 512 B/value cap, shared with FIDO/OATH/OTP/mgmt. `AGENTS.md` §5 names it as the accreted third backend; a new applet on it moves backwards. |
| A new trussed/opcard-wrapped backend | Needs `Client`, `DevicePlatform`, the heap. `deny-graph.toml` reserves backend choice to `fapico2-platform`. A Nostr applet needs none of trussed's file model. |
| A hand-rolled flash record | That is what `keyregion` already is, better. |
| A separate flash region | A second backend is a decision that must be argued, and one already exists that fits. |

### deny-graph consequences (§2.4.1c)

Device-bound needs only platform-owned inputs, so **no `fapico2-nostr →
fapico2-fido` edge exists and none is added to `deny-graph.toml`'s
`applet_edges_allow`** — R1 ("every crate under `apps/` reaches its neighbours
only through `fapico2-platform`") holds with nothing given up. The user-bound
alternative would have needed that edge.

## The two-implementation decision, on the measurement (D8, US-1634)

`secp256kfun 0.12.1` puts a **second, independent** secp256k1 implementation in
the shipped binary beside the platform-owned one (`k256 0.13.4` is in the lock as
a dev-dependency of `fapico2-openpgp` and via `trussed-secp256k1`;
`deny-graph.toml` covers neither `k256` nor `secp256kfun`). That is a real
decision, and the design gated it on a measurement rather than a projection:

| Quantity | Value | Source |
|---|---|---|
| Spike `text` for `thumbv8m.main-none-eabi`, `opt-level = "z"`, LTO, `panic = "abort"` | **25,046 B** | `spike-secp256kfun` (`size` on `src/bin/spike_size.rs`, every public primitive reachable) |
| Deliberate ratchet headroom (US-1630's decision) | **44,032 B** | budget raise 1621 → 1664 KiB, 2026-10-07, recorded in `platform/src/flashmap.rs` + `docs/size-report.md` |
| Firmware `text` at measurement date | 861,912 B | `check_size_report.py` on 927c630 |
| Worst call chain / ceiling | 93,716 B / 98,304 B (margin 4,588 B) | `check_boot_chain.py` on 927c630 |

**Decision: accepted.** The spike's applet-shaped cost fits inside the deliberate
headroom with ~19 KB to spare, and the alternative — routing Nostr's BIP-340 sign
and NIP-44 ECDH through the trussed `Client` — drags in `DevicePlatform`, the heap
and a backend crate this applet may not name, for a handful of scalar
multiplications. `deny-graph.toml`'s comment already sanctions ordinary RustCrypto
library uses; ADR 0005 makes the second curve deliberate so a later reader meets
the decision, not the accident.

**Provisional on two re-measures**, both owned by later stories:

- the **call-chain** delta (US-1652) — the new `App::process` root also raises the
  chain-root floor to 7, and §8.3's `FidoAllocator::alloc` materialisation warning
  applies;
- the **ratchet** delta (US-1675) — if the real in-firmware delta exceeds what the
  ratchet can absorb, the ratchet is re-baselined with the reason written in the
  EPIC, not silently.

## Consequences

- `FIDO_CAPACITY` is a **measurement** again: `docs/capacity.md:92`'s "the 856 is
  measured, not asserted" line moves with the carve (US-1675), as do
  `apps/fido/tests/capacity_boundary.rs:43` and the ten prose sites in
  `apps/fido/src/device_keystore.rs`.
- The forgotten-PIN journey ends in a management RESET that destroys Nostr
  identities with everything else (D6, `docs/nostr-presence-audit.md` F-A3);
  what the device-bound derivation guarantees is that a *scoped* reset — CTAP2
  `authenticatorReset`, which erases only FIDO's range — leaves Nostr records
  sealed and recoverable, not orphaned.
- A future story that wants Nostr keys to survive into a multi-vault future must
  re-open §2.4.1 rule 3 (whole-region re-keying) before touching this shape.
- The spike stays a detached workspace until US-1636 brings the real dependency
  set through `cargo vet`, the SBOM set-diff and the crate-graph gate — with
  `0BSD` (`secp256kfun`'s licence) added to `deny.toml`'s allow-list as an
  explicitly reviewed edit (US-1635).

## Amendment (US-1686, 2026-10-10): the scalar's RAM lifetime is accepted, not zeroized

**Review finding (P2):** `NostrIdentity` is `Copy`, so its `scalar: [u8; 32]`
persists in stack/heap memory after `EXPORT_KEY` answers and after
`DELETE_KEY` tombstones the record — no zeroization on drop, the same shape
as every existing store (OATH's records carry key material the same way).
This amendment states the trade the review found unstated.

**The attack zeroize-on-drop would stop:** an attacker with a RAM *scrape of
freed memory* after a signing ceremony recovers the scalar from `Copy`
memory the flash seal does not cover.

**Why the answer is accepted for now:** on this hardware that attack has no
path that zeroization would close. The RP2350 is single-core with a
cooperative executor — no page cache, no swap, no core dumps, no second
context whose memory the scalar could linger in; the only realistic
RAM-scrape path is the SWD debug port, and while it is open the attacker
reads **live** memory anyway (the scalar in the middle of the ceremony, the
derived store key, every other applet's key material —
[`docs/debug-access-risk.md`](../debug-access-risk.md) owns that window and
its closure). Zeroizing the scalar at drop would add a wrapper-type or
per-call-site design change to `NostrIdentity` — a `Copy` type cannot
implement `Drop` — and would leave the OATH, FIDO and OpenPGP stores
unchanged, protecting exactly one secret against exactly the adversary the
debug port already hands everything to. Simpler is better security (AGENTS
§5): the mechanism stops an attack no reachable adversary can mount, and its
complexity would be inconsistent with every store it sits beside. The
precedent stays the one `nostr_store.rs` already applies to logs — the
scalar is never `Debug`-printed — and this amendment applies the same
discipline to the decision itself: named, not silent.

**Revisit conditions — either of these re-opens the decision:**

1. **The first `-release` tag** (ADR 0002) closes the debug port. Once live
   RAM is no longer readable by the physical adversary, the residual exposure
   is precisely the freed-`Copy`-memory scrape — at that point the calculus
   inverts and a zeroization mechanism (most naturally an explicit
   `zeroize()` at the EXPORT_KEY/DELETE_KEY/NIP-44 paths, with the size delta
   carried in `docs/size-report.md`) becomes the honest answer.
2. **Any multi-core or DMA future** — a second execution context, an
   I/O engine reading guest RAM, or any feature that widens what can observe
   memory outside the cooperative executor's model.

Until one of those fires, no code changes: the record of this decision is
the mechanism.

## Amendment (US-1718, 2026-10-15): the custody row — the stated property gains the burned OTP page

**The stated property** — *"a Nostr identity is not extractable from flash
without the OTP row and the chip-id"* — is **amended, not cited**: after the
custody-migration ceremony ([ADR 0006](0006-nostr-pin-custody.md), US-1712..1715)
the property reads

> a Nostr identity is not extractable from flash without **the OTP row, the
> chip-id, and the burned custody page's read-back contents** — and the
> legacy constant-KDF, the key this ADR's decision 1 originally named, opens
> **no record, including the PIN record**, once the reseat marker stands.

What the ceremony adds to the derivation: the region key becomes
`derive_nostr_payload_key(otp_key_1, chipid, custody_row_readback)` — the
secret is the **read-back contents of a burned, page-locked OTP page**
(`platform/src/custody.rs::assess`), contents-authoritative by design
(US-1712): deterministic across boots and firmware generations, but existing
nowhere in any flash image, so a flashed-back old firmware derives only the
legacy key and opens nothing. Three properties carry the amendment:

1. **The completeness assertion** (US-1713, host-tested in
   `platform/tests/nostr_store.rs` and re-checked at every boot attach,
   `firmware/src/boot.rs::nostr_custody_region`): once the marker stands,
   no slot opens under the legacy KDF — the dual-KDF window exists only for
   the marker-less interrupted state.
2. **The consent gate** (US-1715): the burn never fires as a side effect —
   no command but the explicit `CEREMONY_START` verb writes the OTP page,
   and a declined migration leaves the board legacy-sealed and pending,
   extractable by the old image by the user's own recorded choice.
3. **The fail-closed fault** (`SW_SEALED_UNAVAILABLE`): a custody-row read
   fault yields a non-latching, RAM-only refusal of every command — never a
   guess at a key, never `fatal_boot`, destruction still management-`RESET`-only.

The original device-bound derivation (decision 1) remains the pre-ceremony
posture and the fallback for virgin/torn custody rows; the amendment does
not re-key anything the ceremony has not consented to migrate. What the
amendment deliberately does **not** claim: stop the custom-firmware
adversary (that is O5's secure boot at the `-release` boundary), or stop a
downgrade from destroying the sealed set (the destruction residual is
recorded once in [ADR 0006's downgrade section](0006-nostr-pin-custody.md)).
