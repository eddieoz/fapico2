# Decision log — upstream submission package (secp256kfun)

Skill: multi-agent-brainstorming (structured design review). One designer,
three reviewers, one arbiter. Disposition: **APPROVED** (after revision).

## Understanding Lock

User request: "prepare a pr report for upstream … analyse the original repo,
check their format for reporting, official channels … professional auditing
report, submit evidence for validating the crates and a report about the dead
code." Locked understanding: two artifacts (audit-validation report; dead-code
bug fix) targeted at LLFourn/secp256kfun, drafts only. User confirmed via
structured questions: **drafts only, no submission**; **distilled issue +
gist** for evidence; submission will go through `gh` (user executes).

## Decisions

| # | Decision | Alternatives | Rationale |
|---|---|---|---|
| D1 | Target LLFourn/secp256kfun only; no RustCrypto filing | Also file at RustCrypto/elliptic-curves | Bug is live in secp256kfun's shipped crate; k256 deleted the backend in 2021 (PR #409), so current k256 is unaffected — lineage note suffices |
| D2 | Issue (audit report) + fix PR, cross-linked | Single PR; security email | No SECURITY.md exists (verified); finding is unreachable dead code → no embargo argument; their own #247 precedent is exactly audit-driven fixes |
| D3 | Patch = one-line mask fix + in-file regression test + CHANGELOG entry | Larger refactor; upstream-repo test outside the vendored file | In-file test is what their armv7 CI leg compiles; minimal reviewable diff; matches their changelog style |
| D4 | Full audit report → gist; issue body = distilled summary | Full text in the issue; link to fapico2 repo | Keeps fapico2-internal references out of their tracker; evidence stays publicly verifiable at a stable URL |
| D5 | Omit upstream CLAUDE.md's "Conversation History" PR section | Comply with pasted history; mention omission in PR | Complying would leak unrelated internals; the PR body already discloses the origin (independent consumer audit) via the linked issue — transparency preserved, opacity justified |
| D6 | Do not submit; hand the user a runbook with exact `gh` commands | Submit via gh as eddieoz | User explicitly chose drafts-only |

## Objections raised and resolutions

**Skeptic (blocker):** cited commit `9748fd9853` "does not exist / postdates
removal" and "deleted by PR #408 is wrong". **Resolution:** partially accepted
after arbiter re-verification with direct fetches — the commit citation is
CORRECT (file present at `9748fd9853`, HTTP 200, mask intact; the Skeptic's
404 came from querying the path without the `scalar/` segment; the commit is
simultaneously the merge of #415 and the parent of the removal squash), while
the PR number is WRONG — #408 is the p256 twin, #409 ("k256: use U256…",
merged 2021-09-08, squash `4eed022587`) is the remover; its title merely
references #408. All documents corrected to PR #409 with the squash commit
cited. **Skeptic (should-fix, accepted):** rand_core is a hard dep, not
optional (gist reworded); runbook cd-context and `--head eddieoz:…` fixed;
armv7 `cargo check … --tests` pre-flight added; 496→508 case-count
consistency; changelog `### Fixed` heading removed (their style is
bold-lead bullets); placeholder count fixed; PR-body title duplication
removed; non-reducing semantics noted in test doc-comment and PR body;
date wording generalized to "October 2026".

**Constraint Guardian (blocker):** PR #408 → #409 (same finding, accepted).
**(should-fix, accepted):** "twin trap" fapico2 jargon removed from gist;
"red-team/security-audit capacity" role claim dropped; disclosure re-check
step (0.5) added to the runbook; gist tense fixed ("reported upstream with a
proposed fix" — gist publishes before the PR exists).

**User Advocate (should-fix, accepted):** lineage now names the
**RustCrypto/elliptic-curves monorepo** (where k256 then lived) in all four
documents — the single checkable claim that previously failed its own check;
issue no longer promises an existing PR ("link to follow in the comments") and
a runbook Step 4 comments the PR URL onto the issue; Step 0.7 now passes
`--tests` so the pre-flight actually compiles the new test code; Step 2 uses
absolute paths; "full audit of the crate" scoped to "primitive-API surface";
`Scalar8x32::From<u64>` notation fixed to `From<u64> for Scalar8x32`; H1
deduplication; harness-availability route made concrete; `cross`/Docker
requirement noted in the PR's reproduce line; "pool-style aux" parenthetical
added; placeholder grep pre-check added; patch author-date caveat documented.
**(nit, rejected):** none — all nits were cheap and applied.

## Exit criteria

Understanding Lock ✅ · three reviewer agents invoked ✅ · objections resolved
or explicitly rejected ✅ · decision log complete ✅ · arbiter declaration ✅.

**Arbiter disposition: APPROVED.** The package is submission-ready; execution
is the user's (drafts-only decision).
