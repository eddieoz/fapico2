#!/usr/bin/env python3
"""US-1063: what a release attestation has to say before it is believed.

The signing half of US-1063 — `cosign sign-blob` with keyless OIDC, and the
GitHub build-provenance attestation — cannot be exercised outside GitHub
Actions. There is no OIDC issuer here, no Fulcio, no Rekor, and the only
honest thing to say about that half is that it is unexercised.

The *policy* half can be, and is. This file is that policy:

    A build-provenance attestation is ACCEPTED only if all of the
    following hold. Anything else is REFUSED, and the refusal says which
    one.

      P1  the statement is a SLSA provenance v1 statement;
      P2  the OIDC issuer that signed it is GitHub Actions'
          (`https://token.actions.githubusercontent.com`), read from the
          certificate the caller supplies;
      P3  `buildDefinition.externalParameters.workflow.path` is the
          reusable release workflow — `.github/workflows/release.yml`;
      P4  `runDetails.builder.id` names the same repository AND the same
          workflow path as P3;
      P5  the statement's subject digest is the sha256 of the artefact
          actually being published.

P3 and P4 together are the `job_workflow_ref` property the story names.
The distinction they draw is the whole point of the story: **"CI passed"
is not the same claim as "the release was produced by the reusable
release workflow"**. An attestation minted by any other job — a fork, a
maintainer's ad-hoc `workflow_dispatch`, a re-run of a one-off YAML file
somewhere else in the repository — satisfies "CI passed" and fails here.

Running it
----------

With no arguments (what CI runs on every push) the gate exercises the
policy against the committed fixtures in `tests/scripts/fixtures/provenance/`
and requires that every negative control is REFUSED. That is what keeps
this step from being decorative: a change to the policy that stops
refusing `built-elsewhere.json` turns the gate red on the next push, not
at the next release.

Against a real release:

    python3 tests/scripts/check_release_provenance.py \\
        --attestation provenance.jsonl \\
        --certificate fulcio.crt \\
        --subject firmware/fapico2.uf2 \\
        --expected-workflow .github/workflows/release.yml

WHAT IS NOT VERIFIED HERE, stated plainly
-----------------------------------------

  * that the signature is valid (that is `cosign verify-blob --bundle`,
    which needs the Rekor bundle and a network or transparency-log mirror);
  * that the OIDC token was really issued by GitHub (that is what
    `cosign verify-blob --certificate-identity-regexp` and the Fulcio
    chain check);
  * that a release ever happened.

This gate checks the CONTENT of an attestation, over the SAME function
that a release runs. The cryptographic binding is cosign's job and is
called by the release workflow; claiming otherwise here would be the
decorative-gate failure this epic is about.

Stdlib only, Python 3.8+. Exit 0 on PASS, 1 on FAIL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import certinfo  # noqa: E402  — sibling script, imported by path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "provenance"

SLSA_PREDICATE = "https://slsa.dev/provenance/v1"
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_BUILDER_PREFIX = "https://github.com/"
REPO = "eddieoz/fapico2"

# name -> (must be accepted?, one line saying what it is)
CONTROLS = {
    "good.json": (True, "the shape a release is supposed to produce"),
    "built-elsewhere.json": (False, "a release built outside the reusable "
                                   "workflow, by another repository"),
    "wrong-repository.json": (False, "the right workflow, the wrong repository"),
    "subject-mismatch.json": (False, "an attestation whose subject digest does "
                                     "not match the published artefact"),
    "wrong-predicate.json": (False, "an attestation of something that is not "
                                    "build provenance"),
}


class Refusal(Exception):
    """A named policy check failed. The message is the finding."""


def _dig(node, *keys):
    for k in keys:
        if not isinstance(node, dict) or k not in node:
            raise Refusal(f"the statement has no {'.'.join(keys)}")
        node = node[k]
    return node


def _workflow_parts(builder_id: str) -> tuple[str, str]:
    """`https://github.com/<repo>/.github/workflows/<file>@<ref>` -> (repo, path)."""
    m = re.match(
        r"^https://github\.com/(?P<repo>[^/]+/[^/]+)/(?P<path>\.github/workflows/[^@]+)",
        builder_id,
    )
    if not m:
        raise Refusal(
            f"runDetails.builder.id is {builder_id!r}, which is not a "
            f"GitHub workflow URL of the form "
            f"https://github.com/<owner>/<repo>/.github/workflows/<file>@<ref>"
        )
    return m.group("repo"), m.group("path")


def check_provenance(statement: dict, subject: bytes, issuer: str | None,
                     expected_workflow: str, expected_repo: str = REPO,
                     unsigned_ok: bool = False, notes: list[str] | None = None,
                     expected_commit: str = "") -> None:
    """Raise Refusal unless the attestation is acceptable. No return value.

    Split out from `main` so the fixtures and a real release go through the
    SAME function — a policy that is only exercised against its own test
    data is a policy nothing has checked.
    """
    # P1 — it is build provenance at all.
    ptype = statement.get("predicateType")
    if ptype != SLSA_PREDICATE:
        raise Refusal(
            f"predicateType is {ptype!r}, expected {SLSA_PREDICATE!r}. This is "
            f"an attestation of something other than build provenance."
        )

    # P2 — signed by GitHub Actions' identity provider.
    #
    # `--unsigned` is the escape hatch, and it is an ESCAPE HATCH rather than
    # a relaxation: it is only honoured when no certificate was supplied at
    # all, it says so out loud, and a gate invoked WITHOUT it behaves exactly
    # as before. That asymmetry is the point — a release that silently lost
    # its signature check would be indistinguishable from one that never had
    # one, and "P2 was not checked" has to be something a reader can see in
    # the run log rather than infer from a missing line.
    if issuer is None:
        if not unsigned_ok:
            raise Refusal(
                "no signing certificate was supplied, so the OIDC issuer cannot "
                "be checked. Refusing rather than assuming: an attestation "
                "whose signer is unknown is not evidence of anything."
            )
        (notes if notes is not None else []).append(
            "P2 NOT CHECKED (--unsigned): this release is NOT cosign-signed. "
            "The attestation's signer is unverified here. The trust anchor is "
            "the GPG-signed tag, not this attestation.")
    elif issuer.rstrip("/") != GITHUB_OIDC_ISSUER:
        raise Refusal(
            f"the signing certificate's OIDC issuer is {issuer!r}, expected "
            f"{GITHUB_OIDC_ISSUER!r}. The identity that produced this artefact "
            f"is not GitHub Actions."
        )

    build = _dig(statement, "predicate", "buildDefinition")

    # P3 — the reusable release workflow is what built it.
    wf = _dig(build, "externalParameters", "workflow")
    wf_path = wf.get("path") if isinstance(wf, dict) else wf
    if isinstance(wf_path, str) and wf_path.startswith("https://"):
        # Some producers inline the full ref rather than the path.
        _, wf_path = _workflow_parts(wf_path)
    if wf_path != expected_workflow:
        raise Refusal(
            f"the attestation says the build ran {wf_path!r}, not the reusable "
            f"release workflow {expected_workflow!r}.\n"
            f"  This is the `job_workflow_ref` property, and it is the reason "
            f"this gate exists. \"CI passed\" is a different claim: a job in "
            f"this repository, a fork, a maintainer's ad-hoc dispatch — all "
            f"of them pass CI and none of them is the release workflow."
        )

    # P4 — the builder agrees, and it is our repository.
    builder_id = _dig(statement, "predicate", "runDetails", "builder").get("id", "")
    repo, path = _workflow_parts(builder_id)
    if repo != expected_repo:
        raise Refusal(
            f"runDetails.builder.id names repository {repo!r}, expected "
            f"{expected_repo!r}. The artefact was built somewhere else."
        )
    if path != expected_workflow:
        raise Refusal(
            f"runDetails.builder.id names workflow {path!r}, expected "
            f"{expected_workflow!r}. externalParameters and runDetails "
            f"disagree about what built this, which means the statement is "
            f"not internally consistent and neither half can be believed."
        )

    # P5 — the attestation is about THIS artefact, built from THIS source.
    #
    # Two halves. The subject digest must be the artefact's, and — on the
    # release path, where the caller knows the commit — the statement must
    # name that commit. The second half replaced a rule that required the
    # ARTEFACT to appear in `resolvedDependencies`, which is not a property
    # SLSA provenance has: it lists the SOURCE there and the output in
    # `subject`. No real attestation could satisfy it; the fixture could
    # only because the entry was hand-added to fit the rule. See the branch
    # below for the property it actually protects.
    actual = hashlib.sha256(subject).hexdigest()
    subjects = statement.get("subject") or []
    if not subjects:
        raise Refusal("the statement has no subject, so it is about nothing.")
    for s in subjects:
        claimed = (s.get("digest") or {}).get("sha256")
        if claimed != actual:
            raise Refusal(
                f"the attestation's subject digest is {claimed!r}, but the "
                f"artefact being published hashes to {actual!r}.\n"
                f"  This is the red the story names: `cosign verify-blob` on a "
                f"UF2 whose attestation describes a different UF2. Either the "
                f"artefact was modified after signing, or the signature belongs "
                f"to something else."
            )
    deps = build.get("resolvedDependencies") or []
    if expected_commit:
        # P5, release path. The property this rule is FOR is "this statement
        # describes this one build of this one source". SLSA provenance puts
        # the source in `resolvedDependencies`, and the subject in
        # `subject`; requiring the artefact to appear as its own dependency —
        # which is what this rule used to do — is not a property the format
        # has, so a real `actions/attest-build-provenance` statement can
        # never satisfy it. (The committed fixture could, because the entry
        # was hand-added to satisfy it. That is the trap: a fixture shaped to
        # the rule rather than to reality tests nothing about reality.)
        #
        # So the release path checks the real thing instead, and it is the
        # stronger of the two: the attestation must name the exact commit
        # this run built from. That is what binds these bytes to this tag,
        # which is the claim the whole release rests on and the one
        # `--verify-tag` alone cannot make.
        commits = {(d.get("digest") or {}).get("gitCommit") for d in deps}
        if expected_commit not in commits:
            raise Refusal(
                f"the attestation does not name the commit this release was "
                f"built from ({expected_commit}); its resolvedDependencies name "
                f"{sorted(c for c in commits if c)}.\n"
                f"  The subject digest matches the artefact, but a statement "
                f"that names a different source is a statement about a "
                f"different build."
            )
    else:
        # P5, fixture path. Kept so the committed negative controls still
        # exercise something, and so CI does not need a commit to know.
        dep_digests = {(d.get("digest") or {}).get("sha256") for d in deps}
        if actual not in dep_digests:
            raise Refusal(
                f"no resolvedDependency in the attestation carries the "
                f"artefact's sha256 ({actual}). The subject and the dependency "
                f"list disagree, so the statement does not describe a single "
                f"build."
            )


def self_test(expected_workflow: str, expected_repo: str = REPO) -> list[str]:
    """Exercise the policy against the committed fixtures."""
    subject = (FIXTURES / "subject.bin").read_bytes()
    issuer = (FIXTURES / "issuer.txt").read_text().strip()
    problems: list[str] = []
    for name, (should_accept, what) in sorted(CONTROLS.items()):
        path = FIXTURES / name
        if not path.is_file():
            problems.append(f"fixture {name} is missing — the policy is no "
                            f"longer exercised against the case it was written for")
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        try:
            check_provenance(doc, subject, issuer, expected_workflow, expected_repo)
            accepted, why = True, ""
        except Refusal as exc:
            accepted, why = False, str(exc).splitlines()[0]
        if accepted != should_accept:
            problems.append(
                f"fixture {name} ({what}) was "
                f"{'ACCEPTED' if accepted else 'REFUSED'}, and it must be the "
                f"other. {('It should not have been accepted: ' + why) if accepted else ''}"
            )
    # A missing issuer is its own control: the policy must refuse an
    # attestation whose signer it cannot identify.
    doc = json.loads((FIXTURES / "good.json").read_text(encoding="utf-8"))
    try:
        check_provenance(doc, subject, None, expected_workflow, expected_repo)
        problems.append("the policy ACCEPTED an attestation with no signing "
                        "certificate; an unknown signer is not evidence")
    except Refusal:
        pass

    # The escape hatch must be narrow and loud. It has to permit the release
    # AND say that P2 was not checked — a gate that quietly stopped checking
    # the signer is worse than one that refuses, because nobody can see that
    # the check is gone.
    notes: list[str] = []
    try:
        check_provenance(doc, subject, None, expected_workflow, expected_repo,
                         unsigned_ok=True, notes=notes)
    except Refusal as exc:
        problems.append(f"--unsigned did not permit an unsigned release: {exc}")
    if not any("NOT CHECKED" in n for n in notes):
        problems.append("--unsigned passed without reporting that P2 was not "
                        "checked; a dropped signature check has to be visible")
    # P5 on the release path: the attestation must name the commit this
    # release was built from. good.json carries a zero gitCommit, so that is
    # the one it can be made to name; the wrong commit must be refused.
    good = json.loads((FIXTURES / "good.json").read_text(encoding="utf-8"))
    deps = good["predicate"]["buildDefinition"]["resolvedDependencies"]
    real = "1" * 40
    for dep in deps:
        if "gitCommit" in (dep.get("digest") or {}):
            dep["digest"]["gitCommit"] = real
    try:
        check_provenance(good, subject, issuer, expected_workflow, expected_repo,
                         expected_commit=real)
    except Refusal as exc:
        problems.append(f"an attestation naming the built commit was refused: {exc}")
    try:
        check_provenance(good, subject, issuer, expected_workflow, expected_repo,
                         expected_commit="2" * 40)
        problems.append("an attestation naming the WRONG commit was accepted; "
                        "that is a statement about a different build")
    except Refusal:
        pass

    # And it must not suppress a real issuer check: a certificate that IS
    # present is still compared against the OIDC issuer, flag or no flag.
    try:
        check_provenance(doc, subject, "https://example.invalid/",
                         expected_workflow, expected_repo,
                         unsigned_ok=True, notes=[])
        problems.append("--unsigned suppressed the issuer comparison for a "
                        "certificate that names the wrong OIDC issuer")
    except Refusal:
        pass
    return problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--attestation", help="a real provenance statement (JSON)")
    ap.add_argument("--certificate", help="the signing certificate (PEM)")
    ap.add_argument("--subject", help="the artefact being published")
    ap.add_argument("--expected-workflow", default=".github/workflows/release.yml")
    ap.add_argument("--expected-repo", default=REPO,
                    help="owner/name of the repository a release of this "
                         "project may be built from (default: %(default)s)")
    ap.add_argument("--expected-commit", default="",
                    help="the commit this release was built from; the "
                         "attestation must name it in resolvedDependencies. "
                         "Omitted on the fixture path, where no commit is known.")
    ap.add_argument("--unsigned", action="store_true",
                    help="this release is not cosign-signed, so P2 (the "
                         "signer's OIDC issuer) cannot be checked. Honoured "
                         "ONLY when no --certificate is given, and reported "
                         "loudly. Without this flag a missing certificate is "
                         "still a refusal.")
    args = ap.parse_args(argv[1:])

    if not (args.attestation and args.subject):
        print("US-1063 provenance policy (self-test against committed fixtures; "
              "a real attestation is only checkable at release time)")
        problems = self_test(args.expected_workflow, args.expected_repo)
        for name, (ok, what) in sorted(CONTROLS.items()):
            print(f"  {'ACCEPT' if ok else 'REFUSE':6s}  {name:26s} — {what}")
        print("  REFUSE  <no certificate>       — an unknown signer is not evidence")
        print()
        print("  NOT verified by this gate, and not claimed: signature validity, "
              "the Fulcio chain,\n  the OIDC token itself. Those are cosign's "
              "(`cosign verify-blob --bundle`), and they\n  need GitHub "
              "Actions. See the release workflow.")
        if problems:
            print()
            for p in problems:
                print(f"  FAIL: {p}")
            print("\nRESULT: FAIL")
            return 1
        print("\nRESULT: PASS")
        return 0

    statement = json.loads(Path(args.attestation).read_text(encoding="utf-8"))
    subject = Path(args.subject).read_bytes()
    issuer = None
    if args.certificate:
        # The issuer lives in an X.509 extension, and the only text form in
        # which that extension is legible is openssl's rendering of it — a
        # raw PEM is base64 and never contains the OID. Searching the PEM
        # directly (as this did) meant `issuer` was always None on a real
        # keyless certificate, so P2 refused every genuine release with "no
        # signing certificate was supplied". The committed fixtures could not
        # catch it: they pass the issuer in as a bare string and never read a
        # certificate. See tests/scripts/certinfo.py.
        issuer = certinfo.issuer(Path(args.certificate))
    print(f"US-1063 provenance policy — {args.attestation}")
    notes: list[str] = []
    try:
        check_provenance(statement, subject, issuer, args.expected_workflow,
                         args.expected_repo, args.unsigned, notes,
                         args.expected_commit)
    except Refusal as exc:
        print(f"  REFUSED: {exc}")
        # P2's "no signing certificate was supplied" is ambiguous on its own:
        # it reads the same whether the file is missing, is empty, is not a
        # PEM, or was rendered in a form this did not recognise. Two dry runs
        # were spent telling those apart from the outside. Say what was seen.
        if issuer is None and args.certificate:
            print(certinfo.format_explanation(
                certinfo.explain(Path(args.certificate))))
        print("\nRESULT: FAIL")
        return 1
    print("  ACCEPTED")
    for note in notes:
        print(f"  WARNING: {note}")
    print("\nRESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
