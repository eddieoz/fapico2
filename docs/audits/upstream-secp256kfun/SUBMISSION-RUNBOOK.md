# Submission runbook — upstream secp256kfun

Everything here is **prepared, not submitted**. Execute in order; each step
prints a URL you need in a later step. Channels and conventions verified
October 2026: no SECURITY.md/CONTRIBUTING → public issue + PR is the channel
(re-check before submitting — see Step 0.5); PR titles are plain
`crate: description`; `CHANGELOG.md` has an `## UNRELEASED` section (the patch
already adds the entry); their CI compiles and tests the 32-bit backend on
`armv7-unknown-linux-gnueabihf`.

## Artifacts in this directory

| File | What it is |
|---|---|
| `0001-secp256kfun-fix-truncating-From-u64-in-the-32-bit-sc.patch` | `git am`-ready patch: one-line fix + regression test + CHANGELOG entry, upstream authorship style, no AI trailers |
| `issue-body.md` | the audit-validation report for the issue tracker (one `<GIST-URL>` placeholder) |
| `gist-secp256kfun-0.12.1-security-audit.md` | full technical audit, upstream-facing, gist-ready |
| `pr-body.md` | PR description (one `<ISSUE-NR>` placeholder) |

## Step 0 — verify the patch still applies (upstream may have moved)

```bash
gh repo clone LLFourn/secp256kfun /tmp/skfun-check -- --depth 1
cd /tmp/skfun-check && git checkout -b fix/scalar8x32-from-u64
git am /home/eddieoz/Projects/git/pico/fapico2/docs/audits/upstream-secp256kfun/0001-*.patch
# if it applies cleanly, this branch IS the PR branch — push it in step 3
```

## Step 0.5 — re-check the disclosure channel

```bash
gh api repos/LLFourn/secp256kfun/contents/SECURITY.md --jq '.name' 2>/dev/null && echo "SECURITY.md now exists — prefer its channel" || echo "no SECURITY.md — public issue + PR is fine"
```

The finding is unreachable dead code, so there is no embargo argument — but if
a private-reporting channel has appeared since preparation, use it.

## Step 0.7 — optional pre-flight: compile the patch on the 32-bit target

Their armv7 CI will run the new test; you can check compilation locally first
(`cargo check` needs no linker, unlike `cross test`):

```bash
cd /tmp/skfun-check
rustup target add armv7-unknown-linux-gnueabihf
cargo check -p secp256kfun --all-features --tests --target armv7-unknown-linux-gnueabihf
# --tests matters: everything in the patch beyond one token lives under #[cfg(test)]
```

## Step 1 — publish the full audit report as a gist

```bash
cd /home/eddieoz/Projects/git/pico/fapico2
gh gist create docs/audits/upstream-secp256kfun/gist-secp256kfun-0.12.1-security-audit.md \
  --desc "Independent security audit — secp256kfun 0.12.1 (validation report)"
# add --public if you want it searchable (default is a secret gist — fine for linking)
# → prints https://gist.github.com/eddieoz/<GIST-ID>
```

Replace `<GIST-URL>` in `issue-body.md` with the printed URL.

## Step 2 — file the issue

```bash
gh issue create --repo LLFourn/secp256kfun \
  --title "Independent security audit of secp256kfun 0.12.1 — validation report (one latent vendored-arithmetic bug)" \
  --body-file /home/eddieoz/Projects/git/pico/fapico2/docs/audits/upstream-secp256kfun/issue-body.md
# → prints https://github.com/LLFourn/secp256kfun/issues/<ISSUE-NR>
```

Fill `<ISSUE-NR>` in `pr-body.md`, and (optionally) append the issue URL to the
gist as a back-link.

## Step 3 — push the branch and open the PR

```bash
cd /tmp/skfun-check                       # the branch from step 0
gh repo fork LLFourn/secp256kfun --remote --remote-name fork   # once
git push fork fix/scalar8x32-from-u64
gh pr create --repo LLFourn/secp256kfun --draft \
  --head eddieoz:fix/scalar8x32-from-u64 \
  --title "secp256kfun: fix truncating From<u64> in the 32-bit scalar backend" \
  --body-file /home/eddieoz/Projects/git/pico/fapico2/docs/audits/upstream-secp256kfun/pr-body.md
```

Before Step 2/3, check no placeholder survived:

```bash
grep -n '<GIST-URL>\|<ISSUE-NR>\|<PR-URL>' docs/audits/upstream-secp256kfun/*.md && echo "FILL PLACEHOLDERS FIRST" || echo "placeholders resolved"
```

The PR opens as a **draft** — remove the draft flag when you're satisfied
(`gh pr ready`).

## Step 4 — close the loop: link the PR from the issue

```bash
gh issue comment <ISSUE-NR> --repo LLFourn/secp256kfun \
  --body "Companion fix PR: <PR-URL>"
```

(The issue body says "link to follow in the comments" — this step fulfils it,
so the issue never promises a PR it doesn't name.)

## Verification already performed (so you can answer reviewer questions)

- Patch applies cleanly on master `74d18bbf` (verified during preparation;
  re-verify at Step 0).
- The regression test **fails before / passes after**: both backends were
  compiled verbatim on a host and compared to plain modular arithmetic.
  Original drops bits for `0x10000`, `0x1234_5678_9ABC_DEF0`,
  `0xFFFF_FFFF_FFFF_FFFF`; patched matches the oracle on all cases.
- The impl is unreachable from outside the crate (`mod vendor`/`mod backend`
  private) and has no in-crate callers (grep over the full tree, including the
  `From<u32> → From<u64>` wrapper chain).
- The identical mask exists in RustCrypto/k256's `scalar_8x32.rs` at its final
  pre-removal state (commit `9748fd9853`; the backend was deleted by PR #409,
  squash commit `4eed022587`, September 2021) — inheritance, not introduction.
  Note their PR #408 is the p256 twin; #409 is the k256 one — and the
  monorepo is RustCrypto/elliptic-curves (where k256 then lived).
- Their armv7 CI leg compiles the 32-bit backend, so the new test runs there;
  the 64-bit legs are unaffected (the file is cfg'd out). `rustfmt --check`
  passes on the patched tree.
- The patch's author date is the preparation machine's local time (UTC+3);
  if you care about a same-day UTC date, re-commit just before pushing.
- Upstream `CLAUDE.md` asks agent-written PRs to include a conversation-history
  section; we deliberately omit it — the PR body already discloses the origin
  (independent consumer audit) via the linked issue, and pasting session
  history would leak unrelated internals. Be ready to say so if asked.

## Order rationale

gist (evidence, stable URL) → issue (the audit report links the gist and the
PR; the PR links the issue) → PR. Filing the issue first also gives the
maintainer the finding without waiting on a PR review.
