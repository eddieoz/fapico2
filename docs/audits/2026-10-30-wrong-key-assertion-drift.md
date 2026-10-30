# Root-cause analysis: "wrong key signs assertions for the right credential ID"

**Date:** 2026-10-30
**Analysed against:** fapico2 @ `9ac38f2` (v0.3.1 lineage; the decisive storage semantics landed `587ea10`…`3bc0f58`, 2026-10-04)
**Input:** `../safe-passkeys-tutorial/docs/fido2-key-wrong-key-signing-bug-report.md` (Eddie Oz, 2026-10-30)
**Method:** systematic debugging — every claim below was verified in source at the cited line, and the decisive one is confirmed *computationally from the report's own data*. The affected device was factory-reset, so no device forensics were possible; none turned out to be needed.

---

## 1. Verdict

The reported behaviour is real, is in this firmware, and is **not intermittent** — it is deterministic once its preconditions hold. It reproduces whenever a board on the region backend (2026-10-04+) registers **two or more resident credentials for the same RP ID with the same `user.id`**:

1. **Resident credential IDs are deterministic.** `device_core.rs:1381-1390` derives the ID as
   `SHA-256("fapico2-resident-id" ‖ SHA-256(rp_id) ‖ user_handle)`.
   Same RP + same `user.id` ⇒ the **same credential ID** on every registration.

2. **The credential key is not.** `device_core.rs:1356-1368` mints a fresh TRNG scalar for every registration. (This is the divergence from the C reference — §4.)

3. **The region backend never dedupes.** `FidoRecordStore::put` (`fido_store.rs:1002-1046`) unconditionally allocates a new slot and appends a new index entry. The CTAP 2.1 §6.1.3 "overwrite an existing discoverable credential with the same (rpId, userId)" semantics are **not implemented on this path**. (The pre-region snapshot backend *did* replace by ID — `device_keystore.rs:2568-2580` — which is why the bug surfaced only after the 2026-10-04 region epic, and why every host test still passes: §6.)

4. **Assertion lookup is by-ID, first-match-in-index-order.** Both the allowList match (`device_core.rs:1668-1688`) and `build_assertion`'s re-fetch (`device_core.rs:1859` → `CredentialIdLocator::locate`, `fido_store.rs:781-803`) walk candidates in index ordinal order and return the **first** record whose opened plaintext carries the requested ID. With duplicate same-ID records, that is the **oldest** one — `K_A` — and its private key signs (`device_core.rs:1877`).

So: every re-registration for that (RP, `user.id`) mints a fresh key that is **immediately shadowed** by the oldest same-ID record. Registration attests the fresh key; assertions for that ID sign with the old one. Factory reset (full region wipe) is indeed the only cure. **The firmware is the root of the credential-to-key binding, and here it served an assertion under a key the RP never registered for that credential** — the report's §6 trust-model violation, exactly.

### The computational proof

The report supplies RP ID, `user.id` and the credential ID. Recomputing the firmware's derivation:

```
rp_id_hash        = SHA-256("localhost")
                  = 49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763
user.id           = keccak256("Safe Owner")
                  = eff5a3041317ca36bc0f7af6d3940cce529e44412748add83c4d1a8f6bb449e6
derived cred id   = SHA-256("fapico2-resident-id" ‖ rp_id_hash ‖ user.id)
                  = 3b810ef7e868adf706e0692fc5720a314e4ec58c314df74d425939632abced0a
reported cred id  = O4EO9-horfcG4GkvxXIKMU5OxYwxTfdNQlk5Yyq87Qo  (base64url)
                  = 3b810ef7e868adf706e0692fc5720a314e4ec58c314df74d425939632abced0a   ← byte-equal
```

Negative controls (SHA-3-256 instead of keccak-256; lowercase `"safe owner"`) do **not** match — the agreement is not coincidence. This single equality confirms three things at once: the affected device runs this firmware; the resident branch executed (`req.rk == Some(true)` — Chrome maps `residentKey: 'preferred'` to `rk: true`); and **every registration the application ever performed for this (RP, user.id) produced the same credential ID** — the precondition for the whole failure.

---

## 2. Every reported observation, explained

| # | Report observation | Mechanism in this codebase |
|---|---|---|
| O1 | Registration attests fresh `K_new`; **one** assertion immediately after verifies under `K_new` | The immediate post-registration probe did not pin the ID (empty `allowCredentials`) → **discovery path**, which enumerates the RP's credentials **newest-first** (`device_core.rs:1750-1755`, "the RP's newest passkey is the one a browser expects first") and serves the just-created record. With deterministic IDs the response ID is identical either way, so the app cannot distinguish the two paths by ID. |
| O2 | All later assertions for the pinned ID verify under `K_A` | Pinned `allowCredentials` → by-ID probe → **first index-order match = oldest same-ID record** (`fido_store.rs:781-803`; "the first match in index order wins", `index.rs:875`) → `K_A`'s key signs (`device_core.rs:1877`). The RP-qualified match step (`device_core.rs:1670-1680`) and the None-RP re-fetch (`device_core.rs:1859`) walk the same ordinal order, so they agree on which duplicate serves. |
| O3 | Drift target rotates across sessions (`K_A` → `K_B` → `K_A`) | Which duplicate is "first" is a pure function of **index ordinal state**. Within a session flash state is stable → drift is consistent (session 2: all probes `K_B`). Between sessions it is reshaped by: new registrations landing in freed early cells (`find_free_entry_cell`, `fido_store.rs:2023-2041` — deletes free cells and the next write takes the earliest), credential deletion + sector compaction, and torn counter-bump commits at unplug (recycled slots at generation 1, stale-but-authenticating index entries — `fido_store.rs:442-456`, `commit::recover`). `K_B` never appearing in the app's attestation records is expected: it is the key of another *same-ID* record minted in a session the app did not log (any re-registration from any client derives the same ID). |
| O4 | `signCount = 268`, "old credential's lineage" | Counters are **per record** (CBOR key 6 in the record body, `device_keystore.rs:851-852`, bumped in place at the slot, `device_keystore.rs:3900-3922`). The served record is `K_A`'s, so its counter absorbed every drifted assertion. 268 is `K_A`'s age plus the failed attempts. |
| O5 | Bogus random credential ID → `NotAllowedError` | The probe opens each candidate and byte-compares the ID in full (`device_keystore.rs:3399-3400`); no candidate matches → `CTAP2_ERR_NO_CREDENTIALS` (0x2E) (`device_core.rs:1776-1778`). The filter works — the defect is duplicate IDs, not a broken filter. |
| O6 | Factory reset cures it | Reset wipes region + snapshot and re-draws the device secret. The next registration is the *only* same-ID record — first-match = newest = correct. Correct until the **second** registration for the same (RP, `user.id`) recreates the shadowing. |
| O7 | Many registrations, one RP, identical `user.id`, `residentKey: 'preferred'` | Exactly the precondition: deterministic ID derivation + random key + append-without-dedup. The application's exclude list was evidently empty (the exclude-list check only iterates `req.exclude`, `device_core.rs:1249`), so nothing refused the re-registrations. |
| O8 | `rawId` byte-equal to the requested ID | The response's credential ID is an **echo of the request entry**, not a read-back of the served record (`device_core.rs:1964-1967` pushes `cred_id` from `matched`, which holds request IDs). With deterministic IDs echo and record agree anyway; the browser attributed the assertion to the requested credential because the ID genuinely is that credential's ID. |

The report's §4 guess ("a short-lived session cache… served before the persistent binding is consulted") is not the mechanism — there is no credential cache; the region's on-demand window is zeroized on every lookup (`on_demand.rs:433`). O1 is the discovery path's newest-first order.

---

## 3. The report's §7 hypotheses, adjudicated

| §7 hypothesis | Verdict |
|---|---|
| "Credential record written to volatile memory… persisted with a stale key reference" | **Excluded.** There is no RAM window: `put` commits the record durably (record commit, then index entry last) *before* the MC reply is built (`fido_store.rs:1016-1039`). The just-created record is never served from volatile state. |
| "Index/lookup keyed by `(rpId, userId)`… colliding with a dedup path" | **Half right — the collision is real but it is in the ID *derivation*, not a lookup.** No lookup path anywhere resolves by (rpId, userId) (`user_handle` is only echoed, `device_core.rs:1974-1979`). The dedup that *would* have absorbed the collision exists on the snapshot backend (replace-by-ID) and is absent on the region backend. |
| "Cache eviction or storage-full behavior re-pointing a credential handle" | **Excluded.** No cache; capacity-full is a clean `CTAP2_ERR_KEY_STORE_FULL` refusal (`fido_store.rs:489`, mapped at `device_core.rs:1560-1568`). The record layer cannot cross-pair: one AEAD body per credential with the AAD binding slot+generation (`record.rs`), ID and key inside the same plaintext. |
| "Reset destroyed the evidence" | True and moot — the mechanism is confirmed from the report's own data (§1 above) and reproduces deterministically (§7). |

---

## 4. Why the C reference cannot exhibit this bug — the actual divergence

pico-fido also derives resident IDs deterministically (`cbor_make_credential.c:524`, `credential_derive_resident`), but it **derives the private key from the credential ID too**:

- makeCredential: `fido_load_key(curve, key_seed, &ekey)` with `key_seed = cred_idr` (the derived resident ID) — `cbor_make_credential.c:521-526, 672`;
- getAssertion: the key is re-derived from the served credential's ID — `cbor_get_assertion.c:556-563, 706`.

Deterministic ID ⇒ deterministic key ⇒ re-registration is **idempotent**: the old and new records are interchangeable, and even a duplicate record cannot sign with a foreign key. fapico2's comment calls the ID derivation "C parity" (`device_core.rs:1378`, host twin `app.rs:3508-3520`) — parity was implemented for the ID and **not** for the key. That half-parity is the root cause: it imports the C firmware's ID collision surface without its key-immutability protection, onto a backend that appends instead of replaces.

The 2026-10-04 region epic is the regression surface (not a specific commit within it): snapshot `store_credential` replaced by ID (`device_keystore.rs:2568-2580`), so pre-region boards destroyed the old record on re-registration and the newest key simply took over; `FidoRecordStore::put` appends. The host twin (`app.rs` / `keystore.rs:311-318`) still replaces by ID — **which is why every host test and the emulator pass while hardware drifts**. This is AGENTS.md §1's twin trap, caught by a real device.

---

## 5. Contributing factors and adjacent hazards found during the trace

1. **No CTAP 2.1 overwrite on the region path.** §6.1.3 lets/expects an authenticator to overwrite a discoverable credential with the same (rpId, userId); the firmware neither implements it nor refuses via the exclude list when the RP sends none. Every re-registration silently accumulates a shadowed duplicate and burns a slot (of 844).
2. **`MAX_RP_CREDENTIALS = 16` bounds the None-RP probe** (`fido_store.rs:533`, structural walk `fido_store.rs:756-779`) that `build_assertion`'s re-fetch uses — on a device with >16 FIDO entries, a credential matched in step 1 can be unfindable in step 2 → spurious `NoCredentials` (fail-closed, but wrong).
3. **Migration collision is data loss:** `migrate_snapshot_to_region`'s `contains_credential` is a by-ID probe; on collision it answers `already_present` and **retires the snapshot credential without ever copying it** (`device_keystore.rs:4486-4489`, `retire_credentials` `:4515`). Under this bug's workload (same ID in both backends is guaranteed), a migration re-run can destroy a credential.
4. **Counter window keyed by slot** (`device_keystore.rs:3951`): a pending counter for a freed/reused slot can bleed into the new credential in that slot — signCount corruption only.
5. **Discovery vs by-ID ordering disagree** (newest-first vs oldest-first). With unique IDs this is invisible; with duplicate IDs the two paths answer different credentials for the same request shape — worth fixing regardless of the root cause.

---

## 6. Why nothing caught it

- **Twin mask:** the host twin replaces by ID (§4) — `tests/` and the emulator cannot see append-shadowing by construction.
- **Vector mismatch:** the bug needs *re-registration with an unchanged `user.id`*, which no test does on the region path.
- **Invisible from Python:** `python-fido2` verifies nothing about which key signed — the assertion is structurally perfect (right ID, right RP hash, UP/UV set, monotone counter). Only cryptographic verification downstream — the ERC-4337 `AA24` — exposes it. The report's ruled-out table (§5) is consistent with everything found here.

---

## 7. Fix directions (ranked; not implemented here)

1. **Make the resident key deterministic from the resident ID (true C parity).** Derive the scalar as e.g. `HKDF/HMAC(device-root, "fapico2/resident-key/v1" ‖ cred_id)` — the same shape `largeBlobKey` already uses (`device_core.rs:1402-1405`: `hmac_sha256_into(hkey, &cred_id, …)`). Re-registration becomes idempotent (same ID ⇒ same key), duplicate records become harmless, and the excluded-list/overwrite question mostly evaporates. This restores the reference's coherence: the credential ID *is* the key commitment.
2. **Implement CTAP 2.1 §6.1.3 overwrite on MC:** before `put`, locate any existing region record with the same (rpIdHash, user_handle) and delete it (tombstone + `clear_index_entries` + compact), then store the new one. Keeps random keys; makes re-registration replace rather than accumulate.
3. **Integrity guard regardless of 1/2:** sign with the record the match step identified (slot-addressed, as `bump_sign_counter` already is) instead of re-resolving by ID in `build_assertion`, and make the match step refuse duplicates loudly (`LimitExceeded`/internal error) rather than silently first-match. Also align discovery and by-ID ordering.
4. **Close the adjacent hazards** in §5 (16-bound re-fetch, migration collision loss, counter-window slot reuse) — each is small next to 1–3, and 5.3 should ship with whatever fix lands because this workload triggers it.

1 + 2 together is the defensible end state; 1 alone stops the wrong-key signature (the security property), 2 alone stops the duplicate accumulation (the capacity property), and neither subsumes the other.

---

## 8. Bench reproduction (deterministic, no hardware needed)

The report's §8 sketch is exactly right, and the device-twin harness can pin it as a test:

- Boot `device_app::FidoApp` with `HostTrng`/`HostSecureStore` (as `apps/fido/tests/credmgmt_ctap2_spec.rs::device_twin` does) and drive `process_ctap2_with_store` so the **region path** is live (the shipped one).
- MC ×3: same RP (`localhost`), same `user.id` (`keccak256("Safe Owner")`), `rk: true`, empty exclude list.
- GA with `allowCredentials: [id₀]` (the — identical — derived ID) and verify each signature against each registration's attested key.
- **Expected (bug):** every assertion verifies under registration **#1**'s key; registrations #2/#3 are minted and immediately shadowed. A GA with empty `allowCredentials` verifies under **#3** (newest-first discovery). On the host twin the same script passes — the differential *is* the regression test.

On hardware, the same steps on any current build reproduce the report's episode exactly; a device holding ≥2 same-ID records for one RP is diagnosable via credMgmt enumeration (the same ID listed more than once, `totalCredentials` > distinct IDs) without a reset.

---

*AAGUID for the report's vendor fields: it was not captured, but the byte-exact ID derivation match (§1) identifies the firmware more strongly than the AAGUID would have.*
