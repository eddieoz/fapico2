# Branch ruleset — how to apply

`main.json` is a GitHub **ruleset**, not a workflow. GitHub has no
`.github/rulesets.yaml`; rulesets are configured through Settings or the REST
API. Committing the JSON anyway makes the policy reviewable in a pull request,
which is the point — a security control nobody can read in a diff is not one
anyone will maintain.

**This file is inert until applied.** Nothing enforces it today.

## Apply

Settings → Rules → Rulesets → New ruleset → **Import a ruleset** → pick
`main.json`.

Or:

```bash
gh api --method POST repos/eddieoz/fapico2/rulesets \
  --input .github/rulesets/main.json
```

Verify:

```bash
gh api repos/eddieoz/fapico2/rulesets
```

## What it enforces

- A pull request is required; **squash only**; no force-push; no deletion.
- One approving review, stale approvals dismissed on push, threads resolved.
- `require_code_owner_review` — see `.github/CODEOWNERS`. Without an
  approving review from a code owner, a PR touching `.github/workflows/`,
  `tests/scripts/`, `supply-chain/`, `deny.toml`, `.cargo/` or
  `firmware/src/boot.rs` cannot merge. **This is the control that stops a PR
  from editing the gate that judges it**, and it is inert until both this
  ruleset and CODEOWNERS are in place.
- `strict_required_status_checks_policy: true` — CI must have run against the
  current head. Without it, a green run from an older commit satisfies the
  check and the code that was never tested is the code that merges.

## Two gaps this ruleset does NOT close

**1. The fuzz jobs are not required checks.** `ci.yml`'s fuzz job is a matrix,
so its check name is `fuzz <target> (15-min smoke)` — different per target, and
not statically nameable. The 8 targets therefore run on every push but nothing
*requires* them to pass. Adding a context that never posts would silently block
every merge; omitting them means a fuzz regression does not block. This is a
real hole, and it needs either a single non-matrix summariser job or a
manually-maintained list of the 8 target names.

**2. The `Phase 3 Gate` workflow is not required.** `phase3-gate.yml` is a
*separate workflow* from `ci.yml` and its check is named `gate`. Its content
largely duplicates `ci.yml`'s `pytest gate`, but it is not in the required list
above. Decide deliberately whether it is redundant (and delete it) or
independent (and require it).

## Signed commits

Not enabled here, on purpose. With a squash-only, single-reviewer,
single-maintainer workflow, requiring commit signatures forces a rebase and
force-push by the author for any commit made without signing configured — a
real workflow cost for a threat model where the reviewer is the same person as
the author. Revisit when there is more than one contributor, or when the repo
takes outside patches.

## Note on `bypass_actors`

Left empty deliberately. Adding yourself as a bypass actor to avoid being
locked out during setup would also mean the ruleset can be bypassed
indefinitely. If you do get locked out, repository admins can still delete or
deactivate the ruleset.
