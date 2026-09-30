# GitHub CI/CD + supply-chain security — design

**Date:** 2026-09-30. **Status:** approved (two decisions taken 2026-09-30).

Scope: the GitHub Actions configuration for `fapico2`, and the security
measures that go with it. This document records the design; it does not
itself change behaviour.

---

## 1. What already exists

The tree is not starting from zero, and the design below is mostly about
closing gaps in machinery that is already here.

| Asset | State |
|---|---|
| `.github/workflows/ci.yml` | 13 jobs: host tests, clippy, device build, advertise/serve, heap, persist, attestation, rng-path, erase-budget, structural gates, supply-chain (cargo-deny + cargo-vet + SBOM), fuzz (8 targets), pytest |
| `.github/workflows/release.yml` | tag-triggered; keyless cosign + `attest-build-provenance` + artefact-agreement gate |
| `.github/workflows/phase3-gate.yml` | the US-360 integration gate |
| `supply-chain/` | `sbom.cdx.json`, `audits.toml`, `imports.lock`, `exemption-reasons.toml` |
| `tests/scripts/` | ~30 gate scripts, each with negative controls |
| `.github/dependabot.yml` | cargo + github-actions ecosystems, grouped |
| `SECURITY.md` | private vulnerability reporting, no-bounty, no-SLA |

Two properties are already strong and must not regress:

- **Reproducibility.** `ci.yml` builds twice from two different source
  directories with separate target dirs and requires `cmp` equality, plus a
  flash-budget ratchet (`FIRMWARE_FLASH_BUDGET_KIB`, currently 1524).
- **Gate-with-negative-controls.** The policy scripts run against committed
  fixtures on every push, so a policy that stops refusing is caught on the
  next push rather than at release time.

---

## 2. The gap being closed

`release.yml` fires only on `v*` tags, and its own header states plainly that
it has never run:

> This workflow has NEVER RUN… The cosign step and the attestation step below
> are therefore unexercised code… The first real tag is when the other half
> gets its first real test, and it should be expected to need fixing.

So the release path is untested, and the merge path produces no artifact at
all beyond ephemeral CI uploads.

---

## 3. The two decisions

### Decision A — no release on merge; release is manual only

A merge to `main` produces **no** GitHub Release. The release is built and
published **only when a human triggers it**.

Rationale, and why it is the right call rather than a compromise:

- A release per merge is release-note noise and burns the GitHub Release
  timeline (1000 per repo).
- It also manufactures supply-chain risk: every merge would mint a
  Fulcio certificate and a Rekor entry, so a compromised dependency or a
  typo'd push becomes a *signed, published* artefact. Attestation is cheap;
  *publishing signed things automatically* is the expensive part.
- The unsigned UF2 is precisely the artefact CI is entitled to build, because
  the secure-boot private key is deliberately **outside** the repository
  (`.gitignore` ignores `secrets/*`; only `secrets/README.md` is tracked).
  CI cannot produce a secure-boot-sealed image and must not pretend to.

The cost of this decision is accepted deliberately: the cosign and attestation
steps stay unexercised until a human runs a release. Mitigation is the
**dry-run mode** in §5.2 — the whole path can be exercised on demand,
publishing nothing, so "expect to need fixing" becomes a scheduled exercise
rather than a surprise on the first real tag.

### Decision B — all of Tier 1 is in scope

Token scoping, SHA pinning, `persist-credentials`, pinned runner label,
CODEOWNERS, and a committed ruleset JSON.

---

## 4. The model

Two lanes, differing in trust:

| Lane | Trigger | Trust | Output |
|---|---|---|---|
| **PR** | `pull_request` | **untrusted** — executes fork code | Gate results only. No secrets, no `id-token: write`, no publishing, minimal token. |
| **Release** | `workflow_dispatch` (manual), plus `v*` tags | trusted, human-initiated | Build → sign → attest → publish Release |

`push` to `main` runs the same gates as PR (it is a no-secrets lane), and
uploads the UF2 as a CI artifact for convenience. It does **not** publish a
Release. That is the difference from Decision A's rejected alternative.

---

## 5. Security measures

### 5.1 Token scoping (highest value)

`ci.yml` currently declares **no `permissions:` block at all**, so every job
inherits the repository-default `GITHUB_TOKEN`. Since `ci.yml` runs on
`pull_request` — which executes untrusted fork code — this is the single
largest exposure in the tree.

- Top-level `permissions: contents: read` in every workflow.
- Per-job elevation only where genuinely needed.
- The release job gets `id-token: write` + `attestations: write` +
  `contents: write`, matching what `release.yml` already declares.
- Never `pull_request_target` on any path that reaches the release job.

### 5.2 Action pinning

All third-party actions pinned to full 40-char commit SHAs, never tags and
never branches.

`dtolnay/rust-toolchain@stable` and `@nightly` are removed from the build
entirely, replaced by the runner's preinstalled `rustup` plus the committed
`rust-toolchain.toml`. This is stronger than pinning them would be: those
refs are **branches with `protected: false`** (verified via the GitHub API),
and the action's design is "the `@ref` selects the toolchain", so the mutable
part is the ref→toolchain mapping, not the action code. Pinning the SHA
freezes the code while leaving the mapping mutable. Deleting the dependency
removes the question.

### 5.3 Release dry-run

`release.yml` gains a `dry_run` input. When true it performs the entire
build → sign → attest → verify chain and publishes nothing. This is what
keeps Decision A's accepted cost under control.

### 5.4 Governance

- **CODEOWNERS** on `.github/**`, `supply-chain/**`, `tests/scripts/**`,
  `secrets/**`, `deny.toml`, `deny-graph.toml`, `.cargo/**`,
  `firmware/src/boot.rs`, `firmware/src/uf2gen.py` — otherwise a PR can edit
  the gates that judge it.
- **Ruleset JSON** committed to the repo and applied via `gh api`. GitHub has
  no in-repo YAML for rulesets, but supports JSON import; committing the JSON
  makes the policy reviewable in a PR. Requires a PR, the gate jobs as
  required status checks with `strict_required_status_checks_policy: true`,
  code-owner review on `.github/**`, no force-push, squash-only.

---

## 6. Findings raised while designing

These are reported, not fixed here — they are outside the CI-configuration
scope of this document.

1. **`phase3-gate.yml` references `actions/setup-rust@v1`, which does not
   exist.** The GitHub API returns 404 for the repository; no such repo
   exists under the `actions` organisation. This workflow's jobs fail at
   *Set up job*, before any step runs. Observed failing on every recent run.
   Replace with the same `rustup` treatment as §5.2.

2. **`actions/checkout@v4` emits a Node.js 20 deprecation warning** on
   current runners (observed as a workflow annotation). RS-Key has already
   moved to v7. Pin a current major.

3. **`cargo test --workspace` fails with exit code 101** on the current
   `main` (`56e57b0`). This is a genuine test failure, unrelated to
   configuration, and predates this work.

4. **Dependabot runs are failing** (cargo and github-actions). Worth
   investigating separately — a failing dependency updater is a supply-chain
   control that is quietly not working.

5. **`pytest-gate` can pass vacuously.** It checks out the sibling
   `pico-fido2` harness with `continue-on-error: true`, then gates every
   subsequent step on `hashFiles('pico-fido2/tests/requirements.txt')`. If the
   checkout fails, the gate is green having run nothing — a *silent* pass,
   which is a stronger failure mode than an absent gate. Recommend making a
   missing harness either a hard failure or a loud non-blocking annotation.

---

## 7. Explicitly out of scope

- Changing what any gate *asserts*. This work is about trust boundaries and
  token scope, not test semantics.
- The pre-existing `cargo test` failure.
- Secure-boot signing. That key is out of the repository by design; CI builds
  unsigned images only.
- SLSA L3. Requires moving the build into a reusable workflow in a separate
  protected repository. Reasonable later; L2 from an in-repo reusable
  workflow is the right target now.
