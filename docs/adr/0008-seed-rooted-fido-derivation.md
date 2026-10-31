# ADR 0008: The vendor master seed governs the FIDO derivation root — restoring the phrase restores the wallet

**Status:** Accepted (2026-10-31)
**Supersedes:** nothing (amends [ADR 0007](0007-resident-key-derivation.md)'s
subject — that ADR froze *what the resident key is a function of*; this ADR
changes *what roots that function*, from `hkey` alone to a seed-governed
`froot`)
**Context docs:** [`docs/tasks/EPIC-fido-seed-root.md`](../tasks/EPIC-fido-seed-root.md)
(the settled root-cause chain, §1, and the invariants, §2 — the authority for
this ADR), [`docs/backup-seed.md`](../backup-seed.md) (the custody statement
this decision makes true), [ADR 0007](0007-resident-key-derivation.md) (the
identity-derived resident key this root feeds); the landing stories
US-1734..1739 of EPIC `FIDO-SEED-ROOT`.

## Context

ADR 0007 made the resident credential key deterministic:
`HMAC-SHA256(root, "fapico2/resident-key/v1" ‖ cred_id)`, with the root being
the device's `hkey` bytes. That fixed the same-device drift (the silent
foreign-key signature), but it left the backup seed — the 32-byte blob
`EXPORT`/`LOAD` move between boards under the MSE channel — **inert**: a
repo-wide sweep found no consumer outside the vendor transport, its snapshot
slot and the fuzz target. The credential **ID** is device-independent
(`SHA-256("fapico2-resident-id" ‖ SHA-256(rp_id) ‖ user_handle)`), so a board
restored from the phrase and re-registered for the same (rp, user) produced
the *same ID* under a *different key* — the wallet split across two roots,
of which only the portable one was exported. Restoring the seed changed
nothing; the phrase was custody without authority, and
`docs/backup-seed.md`'s "passkeys are NOT in it" sentence was the honest
description of a broken contract.

The reference implementations do not help: pico-fido keys its ratchet from
the device-resident `keydev` and has **no restore at all**
(`fido.c:325 derive_key`); RS-Key is the only sibling where restore works,
because it made the seed the root.

## Decision

**The FIDO derivation root `froot` is a function of the master seed when one
is installed, and of the `hkey` bytes when it is not:**

```text
seeded:    froot = HMAC-SHA256(key = master_seed, data = "fapico2/fido-root/v1")
seedless:  froot = hkey.to_bytes()          (byte-identical to every prior version)
```

implemented as `crypto::derive_froot` / `FIDO_ROOT_DOMAIN`
(`apps/fido/src/crypto.rs`), with one accessor `froot()` on **both twins**
(`device_app.rs` and `app.rs` — AGENTS.md §1 discipline; the twin rule bit
this codebase before). Derived on demand, never stored, never logged; the
returned array is scratch key material kept in the smallest scope.

Three decisions ride with it:

1. **The resident wallet derives from `froot`.** makeCredential, the
   largeBlobKey (`HMAC(froot, cred_id)`) and getAssertion all key from
   `froot` (US-1735). The same seed on two boards derives the same passkey
   private key for the same (rp, user). The seedless arm is *the old bytes*,
   so every deployed seedless device derives exactly what it derived before
   this ADR existed — byte-for-byte, pinned by known-answer vectors.

2. **Serving time derives; the stored scalar is a cross-check target**
   (US-1736). getAssertion computes the resident scalar from
   `(froot, cred_id)` at sign time instead of trusting the record's stored
   `private_key` — that is what lets a restored board sign an identity whose
   record carries no usable stored scalar. The stored scalar is not dead
   bytes: the record's stored public key is compared against the derived
   scalar's public key, and a disagreement **never signs** — the orphan gate
   answers `CTAP2_ERR_NO_CREDENTIALS` for that request, treating a wrong
   record exactly like a missing one (US-1573's rule, the drift epic's
   fail-closed rule verbatim). The gate exists for paths the public API does
   not control (snapshot migration, region fallback); the LOAD policy below
   makes the state unreachable through the API itself. Non-resident
   credentials keep their TRNG keys and stored scalars — they are
   device-bound by design and outside the wallet's scope.

3. **`LOAD` is reset-first (US-1737).** Installing a seed while resident
   credentials exist and the incoming seed differs from the installed one
   would orphan every stored key at a stroke, so `LOAD` refuses
   `0x30 NotAllowed` while residents exist — arm 1 (residents, no seed yet)
   before the MSE channel, arm 2 (residents, differing seed) after the AEAD
   opened, both placed so an unauthenticated caller learns only what
   `backup_auth` already told it. Same-seed reinstall is idempotent and
   legal: `froot` is stable under it, so it cannot orphan anything.
   `authenticatorReset` wipes the residents (and leaves the vendor seed
   alone), making the install legal — reset first, then restore.

### The argument, in AGENTS.md §5's terms — the attack named both ways

The choice trades a real protection for a real capability, and both sides
must be stated as attacks, not preferences:

**What seed-governance buys.** Under `hkey`-only rooting, the attack the
design cannot stop is *hardware mortality*: `hkey` is a TRNG secret that
leaves no export path, so a dropped, drowned or bricked board takes every
resident passkey with it, and the phrase the user was told is their backup
restores nothing. A backup that restores nothing is not a backup — and per
§5's capacity corollary, an authenticator that loses the user's wallet gets
returned or left in a drawer. The user-facing contract ("this phrase is your
wallet") becomes true.

**What it costs, plainly.** The BIP-39 phrase alone reproduces every resident
passkey key — no device, no PIN, no touch. Anyone who holds the phrase holds
the wallet. The blast radius the current `hkey`-rooted design contains (a
phrase leak is a custody incident, nothing more) is given up **knowingly**:
the export window plus the `FINALIZE` seal become load-bearing, and a seed
leak is total FIDO compromise *for that wallet*. That is the same trade
every BIP-39 hardware wallet has made, priced in the open rather than
inherited.

**What stays device-bound, by name** — so nobody "completes" the seed
governance over these later:

| Stays device-bound | Where | Why |
|---|---|---|
| `hkey` itself (pinUvAuth-P1 ECDH `derive_shared`, clientPIN `getKeyAgreement`, MSE channel device key) | `device_core.rs:2371, 2526`; `vendor_state.rs mse_channel` | A seed LOAD must not rotate the key-agreement identity mid-channel or break a PIN handshake; the MSE pubkey is pinned unchanged by the non-wallet-roles scenario |
| Stateless U2F master | `stateless::master_from_device_random` (`device_random`-rooted) | Rotating it at seed-LOAD time would break every existing U2F registration on the same board, for a credential class the wallet framing never promised |
| Attestation identity | `attestation.rs` / `attestation_cert.rs` | The board's per-device identity is not the wallet's |
| hmac-secret per-credential `credRandom` | `hmac_sha256(hkey_bytes, b"fapico2-hmac-cred-random")` sites (`device_core.rs:3233-3235`, `app.rs:758-760`) | Stored, device-sealed, **not restored** — named here so nobody assumes they ride the phrase |
| Every other applet (OATH, PIV, OpenPGP, Nostr, …) | their own keyregion domains | Sealed under `otp_key_1 ‖ chipid`; unexportable by construction |
| The keyregion at-rest seal | `otp_key_1 ‖ chipid` | A restored board decrypts nothing of the old board's *stored* records — which is exactly why GA derives rather than reads |

**The seed is not for OTP.** `otp_key_1` is the RP2350 fuse root for at-rest
sealing, unexportable by construction; the phrase was never "the OTP key" and
must never be described as one (AGENTS.md §9 says the same thing in the
implementer's voice).

### Divergences from the siblings, recorded so nobody "fixes" them

| Sibling behaviour | fapico2 | Why the divergence stands |
|---|---|---|
| RS-Key derives U2F/stateless from the seed too (`keyderiv.rs:31-42`) | fapico2 does not — the U2F master stays `device_random`-rooted | See the table above; breaking same-board U2F registrations at upgrade time buys nothing the wallet framing promised |
| RS-Key's resident ID is serial-bound | fapico2's resident ID has no chip input (`device_core.rs:1435-1444`, ADR 0007, frozen) | The device-independent ID is what makes same-seed/same-identity restore produce *the same credential*, not just the same key |
| pico-fido has no restore at all (`fido.c:325`) | restore is the point | pico-fido keys everything from the device-resident `keydev`; there is no phrase to restore |
| — | **Counter regression on restore is documented, not fixed** | A restored board starts a credential's counter at 1 where the old board was at *N*; some RPs warn or reject. The old counter lives in the old board's records and no derivation can produce it. `docs/backup-seed.md` carries the warning and the re-register advice |

## Consequences

- **The 2026-10-31 field report is closed at its root.** Same seed, same
  (rp, user) ⇒ same credential ID (ADR 0007, unchanged) *and* same key
  (this ADR). The probe (`scripts/probe_seed_restore.py`) prints `SAME-KEY`
  where the defect printed `DIFFERENT-KEY` with equal IDs.
- **The seedless path is frozen at the vectors.** `froot == hkey_bytes`
  means every pre-epic record signs unchanged with no migration — and it
  also means changing `FIDO_ROOT_DOMAIN`, the derivation domain strings or
  the input order orphans every deployed passkey *and* every restored one.
  `tests/seed_root_vectors.rs` pins exact hex literals computed by an
  independent implementation; treat them like ADR 0007's byte-equality
  proof.
- **The seed is monotonic.** `set_master_seed` is reachable only from
  `LOAD`, only replaces, never clears; once a device is seed-governed it
  stays so short of a secure-partition nuke. No path may add a clearing
  route — a seed that could silently vanish would strand the derivation
  root.
- **The old wallet stays unrecoverable, by design.** Credentials created
  before a seed governed were keyed by an `hkey` that left no export path;
  the honest answer is re-register once on a seed-governed board. Exporting
  `hkey` or stored scalars to migrate them was rejected (below).
- **Evidence:** `apps/fido/tests/seed_root_restore.rs` (same-seed /
  different-seed / seedless-guard twins), `apps/fido/tests/seed_root_vectors.rs`
  (the frozen known-answer vectors), and the reset-first scenarios in
  `apps/fido/tests/vendor_backup.rs`
  (`load_on_a_board_with_resident_credentials_refuses`,
  `load_on_a_wiped_board_succeeds`, `a_different_seed_over_residents_refuses`).

### The rejected alternatives

- **Full RS-Key adoption (HKDF-SHA512 ratchet, seed-derived U2F master) —
  REJECT.** §5 rule 3: fapico2 already has the derivation shape it needs
  from ADR 0007; a second KDF and a second seeded role each add surface
  without naming an attack the HMAC root does not stop.
- **Device-side seed GENERATE (a new vendor byte) — REJECT.** Wire change
  (AGENTS.md §2 freeze) for entropy a host draws as well as the TRNG; the
  host-entropy provenance warning in `backup_fido.py --generate` is the
  honest residue.
- **Exporting `hkey`/stored scalars to migrate a pre-epic wallet — REJECT.**
  It recreates the extraction path ADR 0006 deleted for Nostr, for a wallet
  whose records the seed cannot reconstruct anyway.
- **Trust the stored scalar at GA (no serving-time derivation) — REJECT.**
  It re-splits the wallet across roots: a restored record without a usable
  stored scalar could never sign, which is the restore story failing one
  level down.
- **Silent LOAD-over-residents (install and let the orphan gate sort it
  out) — REJECT.** Fail-closed means refusing at the API, not detecting the
  wreckage afterwards; the gate is belt-and-braces for paths the API does
  not reach, not a licence for the API to create the state.

### The residual, stated honestly

- **The phrase is the wallet, and the wallet is only the resident FIDO
  keys.** U2F/stateless credentials, hmac-secret secrets, and every other
  applet die with the board. `docs/backup-seed.md` says exactly this; the
  phrase's scope must not be broadened in prose faster than the derivation
  follows in code.
- **The export window is load-bearing.** Between `EXPORT` and `FINALIZE`
  the seed exists host-side in plaintext form. The seal is one-time and
  touch-gated; the residual is the window itself, priced in the decision
  above.
- **Counter regression is documented, not fixed** (see the divergence
  table) — some RPs will warn or reject a restored credential's first
  assertion; re-registration is the remedy.
