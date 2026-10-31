# fapico2-release-alpha-v0.4.0 — Release Notes

**Date:** 2026-10-31 · **Target:** Raspberry Pi Pico 2 (RP2350), USB-connected
**Theme:** the phrase is the wallet (PR
[#24](https://github.com/eddieoz/fapico2/pull/24), EPIC
[`FIDO-SEED-ROOT`](tasks/EPIC-fido-seed-root.md)) — the backup seed stops
being inert and becomes the FIDO derivation root, with the book (PR
[#26](https://github.com/eddieoz/fapico2/pull/26)) telling users both halves
of that truth.

**This is an alpha.** Alpha/beta images keep the debug port available and burn
nothing irreversible into OTP ([ADR 0002](adr/0002-provisioning-policy.md)).

## The defect this release closes

The 2026-10-31 field report: a seed exported from board A and imported into
board B, then re-registering the same passkey, produced a **different wallet**
on B — while delete-and-recreate on one board reproduces its key
consistently. The settled chain (every line read, EPIC §1): the resident
credential **ID** is device-independent
(`SHA-256("fapico2-resident-id" ‖ SHA-256(rp_id) ‖ user_handle)`), so the
browser treated B's registration as "the same slot"; the signing **scalar**
was keyed by a per-device TRNG `hkey`; and the backup "master seed" that
`EXPORT`/`LOAD` move between boards had **no consumer anywhere in the tree**.
Custody without authority: the wallet was split across two roots and only the
portable one was exported.

## What changed

### The seed governs the derivation root — and only the wallet

`froot = HMAC-SHA256(master_seed, "fapico2/fido-root/v1")` when a seed is
installed; the device's own root bytes when it is not — **byte-identical for
every deployed seedless device**, pinned by known-answer vectors computed
with an independent implementation ([ADR 0008](adr/0008-seed-rooted-fido-derivation.md)).
makeCredential, the largeBlobKey and getAssertion all key from `froot`.

The argument is named both ways in the ADR, per the repository's own rule:
what seed-governance buys (the wallet survives the hardware — a backup that
restores nothing is not a backup), and what it costs plainly (the BIP-39
phrase alone reproduces every governed passkey key, so the export window and
the `FINALIZE` seal become load-bearing). What stays device-bound is listed
by name: the ECDH roles of `hkey` (pinUvAuth-P1, clientPIN getKeyAgreement,
the MSE channel), the stateless U2F master, hmac-secret `credRandom`,
attestation identity, every other applet, and the keyregion at-rest seal.

### Serving time derives; the record is the cross-check

getAssertion computes the resident scalar from `(froot, cred_id)` at sign
time and never trusts the stored scalar — that is what lets a restored board
sign an identity whose record carries no usable stored key. The record's
stored public key is compared against the derivation, and a disagreement
**never signs**: `CTAP2_ERR_NO_CREDENTIALS`, absence rather than a fault. The
orphan gate is reachable only through paths the public API does not control,
because the LOAD policy below makes the state unreachable through the API.

### `LOAD` is reset-first, and the count cannot lie

`LOAD` answers `0x30 NotAllowed` while the board holds FIDO records and the
incoming seed would change the root; a byte-identical same-seed reinstall
stays legal (the root is stable under it). The gate's record count is a
tri-state: a backend that cannot be read reports "unknown", never "empty" —
a faulted region index refuses with the same `0x30` and the same reset-first
remediation rather than being counted as zero. Arm 1 (records, no seed)
refuses before the MSE channel; arm 2 (records, differing seed) after the
AEAD opened — an unauthenticated caller learns only what the MAC already
told it.

### The proof

A board nuked to bare silicon, reflashed with this firmware, and restored
from the 24-word phrase **alone** re-registered the same identity under the
byte-identical P-256 key and served a signature under it — `SAME-KEY`. The
full cycle, commands and outputs, is
[the hardware transcript](audits/2026-10-31-seed-restore-proof.md); the
pre-epic firmware ended the same cycle `DIFFERENT-KEY` with equal credential
IDs, which is also reproduced as the RED run of
`apps/fido/tests/seed_root_restore.rs`.

### The book, the tool and the docs

The book's seed-backup chapter states both halves together: the phrase is the
wallet for credentials created while the seed governs, and the blast radius
matches — anyone holding the phrase holds every governed passkey key. It
documents the reset-first restore procedure and the counter-regression
warning. `backup_fido.py` maps the `0x30` refusal to the same reset-first
guidance, verifies the install took before reporting success (and before
printing a `--generate` phrase), and states that `--generate`'s entropy came
from the host. README, AGENTS.md §9 (the implementer's trap list) and
`docs/backup-seed.md` carry the same scope; the picoforge Backup screen
should render the `0x30` refusal with the same guidance (out of tree,
tracked separately).

## Known boundaries (each is a deliberate refusal)

* **Credentials created before a seed was installed are not restorable** —
  their keys were functions of the old board's device root, which left no
  export path. Re-register once on a seed-governed board; from then on the
  phrase carries them.
* **U2F/stateless registrations, hmac-secret secrets and every other
  applet's keys are not in the phrase** — device-sealed, none identity-derived.
* **The signature counter regresses on restore** (a restored credential
  starts at 1); some RPs warn or reject — re-register with any that do. A
  property of any seed-restore design; documented, not fixed.
* **The seed is monotonic** — `LOAD` replaces, never clears; short of a
  secure-partition nuke a seed-governed board stays seed-governed.

## Upgrading from v0.3.3

**Reflash.** No record-format change, no storage migration — the seedless
derivation is byte-identical, so every existing passkey keeps working
unchanged (pinned by the vectors and the full host suite). After flashing:

* the board behaves exactly as v0.3.3 until you install a seed;
* installing a seed for the first time requires the board to be free of
  resident passkeys (reset first — `ykman fido reset` — which also clears
  the PIN and **not** the vendor seed);
* the host tool refuses an install that would orphan passkeys and tells you
  so; the book documents the whole procedure.

The emulator-side note: host builds now derive the FIDO root from the
persisted `device_random` (the previous per-process random root would have
failed the new orphan gate after every restart — caught by the restart test,
fixed in the same release).

## Verification

All CI checks green on the exact content this tag names: clippy
(`-D warnings`, `--all-targets`), 311 host tests across 83 binaries, the 13
structural gates, the emulator suites (70 passed), cargo-deny/vet, and the
docs gate. The book builds (`mdbook build book`). The two fresh-eyes review
rounds on the branch are recorded in commit `765e0b0`'s message — the second
found the fail-closed gap the tri-state count closes. Hardware legs already
run: the nuke-restore `SAME-KEY` cycle above; pending for the field: a
pre-epic board flashed with this image used seedlessly (the informal
back-compat check every deployed seedless device performs by existing).
