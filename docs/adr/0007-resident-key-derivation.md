# ADR 0007: Resident credential keys are identity-derived — the key for (rp, user) is a function of the device and the identity

**Status:** Accepted (2026-10-31)
**Supersedes:** nothing (amends the half-parity the 2026-10-04 region backend
inherited: resident credential **IDs** were derived, resident **keys** were not)
**Context docs:** [`docs/audits/2026-10-30-wrong-key-assertion-drift.md`](../audits/2026-10-30-wrong-key-assertion-drift.md)
(root-cause analysis — the authority for this ADR's Context and for the
computational proof), the upstream bug report
`../safe-passkeys-tutorial/docs/fido2-key-wrong-key-signing-bug-report.md`;
the landing stories US-1719..1729 of EPIC FIDO-RESIDENT-DRIFT.

## Context

A user re-registered a resident passkey for the same RP ID and the same
`user.id` and every later assertion for that credential verified under a key
the RP had never registered. The analysis doc traced it to three landmasses
that only produced the failure together:

1. **Resident credential IDs are deterministic** —
   `SHA-256("fapico2-resident-id" ‖ SHA-256(rp_id) ‖ user_handle)`. Same
   (rp, user) ⇒ the *same credential ID* on every registration. This was
   deliberate C parity (pico-fido `cbor_make_credential.c:524`) and is now
   **frozen** (below).
2. **The credential key was not.** Every registration minted a fresh TRNG
   scalar. The C reference derives the key *from* the resident ID
   (`cbor_make_credential.c:521-526`, `fido_load_key` → `fido.c:325`); fapico2
   took the ID derivation and not the key derivation — half-parity.
3. **The region backend appends and never dedupes**, while by-ID lookup served
   the *oldest* same-ID record. So a re-registered credential was minted,
   attested at registration time, and immediately shadowed: its assertions
   were signed with the oldest registration's key — **the silent foreign-key
   signature**. The duplicate set that made it reachable accumulated silently,
   one slot per re-registration, on any board where a client re-ran
   registration without an exclude list.

A full factory reset was the only cure, and it was temporary: the *next*
re-registration recreated the shadowing. The computational proof in the
analysis doc §1 confirms the mechanism from the reporter's own data — the
derived ID `3b810ef7…abced0a` is byte-equal to the reported one, so every
registration that application ever performed produced that same ID.

## Decision

**For `options.rk == true` ES256 credentials, the signing key is derived, not
drawn.** One shared helper, called by both twins
(`device_core.rs` makeCredential, `app.rs` twin makeCredential — AGENTS.md §1
discipline; a change to one twin only is the exact defect class US-1514 and
the PR #3 dialect work recorded):

```text
first round:  HMAC-SHA256(hkey_bytes, "fapico2/resident-key/v1" ‖ cred_id)
rehash n:     HMAC-SHA256(hkey_bytes, "fapico2/resident-key/v1/rehash" ‖ [n as u8] ‖ cred_id)
```

implemented as `crypto::derive_resident_scalar`
(`apps/fido/src/crypto.rs`, "US-1721 — the deterministic resident credential
key"). The seed is accepted if it is a valid P-256 scalar (the same
`SecretKey::from_slice` rule the TRNG sampler applies); a rejected round is
re-hashed with the rehash domain and the attempt byte, capped at
`RESIDENT_DERIVE_MAX_ATTEMPTS = 32`. Exhaustion returns `None`, and both call
sites map it to `CTAP2_ERR_KEY_STORE_FULL` — fail closed, never loop
(US-1007's lesson). A `cred_id` wider than `RESIDENT_CRED_ID_MAX = 64` is
refused rather than truncated — a silent truncation would be a second,
quieter derivation. Non-resident credentials keep TRNG keys and random IDs,
unchanged.

**The root is `hkey`** — the device's long-lived P-256 key-agreement key, the
one the clientPIN handshake already uses, drawn from the TRNG at boot/reset.
It is the same root and the same byte form the largeBlobKey derivation uses
(`device_core.rs`: `hmac_sha256_into(hkey, &cred_id, …)`), so the resident key
and the largeBlobKey are siblings under one device secret. No new OTP row, no
new stored key, no TRNG in the derivation. This is §5 rule 3 applied: the
boring mechanism is an HMAC under a secret the device already holds, and it
names the thing that stops the trivial attack — the credential ID is public
(it is handed to every client), so derivation from the ID alone would forge a
key from `(rp, user)`; the device secret is what makes it unforgeable.

**The accepted semantic consequence, in one honest sentence: resident
re-registration is idempotent — the key for (rp, user) is a function of the
device + identity, exactly like pico-fido, and re-running registration cannot
rotate the key.** Applications that need multiple independent keys per
identity use separate RPs, non-resident credentials, or multiple devices. This
is what C parity means: in pico-fido the same property holds, and no one calls
it a loss there.

**The ID derivation is frozen and must not change.** Deployed records are found
*by* that derivation, and the derivation is byte-compatible with the reference
— the computational proof above is a byte-equality against a real
registration. Changing the ID derivation orphans every resident credential
already enrolled; there is no version-2 ID to migrate to without breaking
every client that has pinned one.

## Consequences

- **The attack is closed at its root.** With the key a function of the ID, a
  duplicate same-ID record is harmless: either record signs identically. The
  silent foreign-key signature is no longer reachable even before the
  duplicate can form.
- **US-1722 (CTAP 2.1 §6.1.3 overwrite on MC)** stops the accumulation:
  re-registration replaces rather than appends, so the region no longer burns
  a slot per re-registration. **US-1723/US-1724 (the assertion signs the
  record the match step resolved, slot-addressed; by-ID resolution prefers the
  newest)** are independent defenses: even a store that somehow holds
  duplicates answers coherently, newest-first, instead of by index-ordinal
  luck. Three layers, each of which would have stopped the reported incident
  at a different point; the derivation is the one that removes the mechanism,
  the other two remove the conditions.
- **US-1725..1729 close the adjacent hazards** the trace found (RP-qualified
  exclude/migration lookups, same-ID credMgmt deletion, migration collision
  loss, counter-window slot reuse, index-generation rejection).
- **Key rotation for a resident identity is out of scope by design.** Deleting
  the credential and re-registering under the *same* (rp, user) yields the
  same key. The escape hatches are the non-resident arm (TRNG, random ID) and
  factory reset (re-draws `hkey`, rotating every derived key at once).
- **The derivation is deterministic and public in shape.** Publishing the
  domain strings here is deliberate — the secrecy lives entirely in
  `hkey_bytes`, which is the property HMAC gives us and the one a bespoke
  construction would risk.

### The residual, recorded honestly

The **host twin** derives only for ES256/ESP256 resident credentials (both are
P-256 here, so the 32-byte scalar serves either label). A resident
makeCredential under EdDSA, P-384 or P-521 on the host twin keeps a TRNG key
under a *derived* ID — the half-parity shape in miniature. This is unreachable
on the device path, which serves ES256 only and rejects every other
algorithm, so the shipped property is complete on the only path that ships;
the `app.rs` call site carries the comment, and multi-algorithm work must
extend the derivation to those curves or refuse the (resident, non-P-256)
combination rather than silently mixing derived IDs with random keys.

### The rejected alternatives

- **CTAP 2.1 overwrite alone (analysis §7 direction 2) — REJECT as the whole
  fix, SHIP as US-1722.** Overwrite keeps random keys and stops the
  accumulation, but it does not make duplicate records harmless — a record
  that survives any future dedup gap signs with a foreign key again. It is
  the capacity half, not the security half; the analysis doc's own closing
  line ("neither subsumes the other") decided shipping both.
- **Refuse duplicate registration loudly** (`ExcludeCredentialDescriptor` or
  `LimitExceeded` on a same-ID hit) — REJECT: it breaks clients that
  legitimately re-register (browsers retry registration on transient
  failures), and pico-fido does not refuse — it is idempotent, and being
  drop-in compatible with the reference's behaviour is the point of C parity.
- **A version-2 credential ID derivation** that salts in a per-registration
  nonce, restoring per-registration keys — REJECT: it re-introduces the
  foreign-key surface it was invented to avoid (deterministic lookups by the
  old ID would miss the new record), orphans every deployed credential, and
  the idempotence sentence above already prices what it would buy.
- **A new OTP row as the derivation root** — REJECT: `hkey` already roots the
  largeBlobKey and the clientPIN machinery; a second device secret is a second
  thing that can be unreadable at boot, and §5 rule 1 asks for one hierarchy,
  not two.
