# Archive — past investigations and their verdicts

Everything in this directory is a **historical record**: acceptance runs,
root-cause investigations and remediation notes for work that is finished. The
documents are kept verbatim because re-deriving them is expensive and the
evidence is cited from elsewhere; none of them describes current behaviour.
For what is true today, start at [`../INDEX.md`](../INDEX.md).

One-line verdicts, so nobody has to read 3,000 lines to learn what happened:

| Document | What it was | Standing verdict |
|---|---|---|
| [`webauthn-acceptance-us1518.md`](webauthn-acceptance-us1518.md) | US-1518 scripted WebAuthn acceptance vs the fixed firmware (2026-10-02) | Passed; superseded by later real-site runs |
| [`webauthn-browser-failure-class-us1520.md`](webauthn-browser-failure-class-us1520.md) | US-1520: which Chrome failure-table row our board produced | Row identified; two-board control run in [`webauthn-failure-class-device-rows.md`](webauthn-failure-class-device-rows.md) |
| [`webauthn-failure-class-device-rows.md`](webauthn-failure-class-device-rows.md) | US-1521 two-board control run | Result was the opposite of the expected row — single-board readings are unreliable |
| [`webauthn-epic-corrections.md`](webauthn-epic-corrections.md) | Durable corrections record for the US-1501…1527 epic plan | All corrections applied; kept as the epic's evidence index |
| [`webauthn-u2f-v2-advertisement-us1531.md`](webauthn-u2f-v2-advertisement-us1531.md) | US-1531/32/33: why registration failed on demo.yubico.com, x.com, proton.me | Fixed; the advertisement rules now live in `apps/fido` and their tests |
| [`webauthn-us1503-press.md`](webauthn-us1503-press.md) | US-1503: does a real button press complete a parked request? | Yes (raw transcripts in `../evidence/us1503/`) |
| [`webauthn-us1527-real-sites.md`](webauthn-us1527-real-sites.md) | US-1527: human-run passkey registration on real sites | token2.com and webauthn.io pass; the x.com failure is the US-1531 fix |
| [`openpgp-default-pin-message.md`](openpgp-default-pin-message.md) | GnuPG "Card error" on factory PINs | The requested fix is not achievable within the spec; deferred, do not re-derive |
| [`openpgp-kleopatra-pgpony-investigation.md`](openpgp-kleopatra-pgpony-investigation.md) | Kleopatra "test card" / PGPOpony key visibility (2026-10-05) | Serial display is a spec-rendering artifact, not a firmware defect; PGPOpony visibility is client-side |
| [`SECURITY-ASSESSMENT-ROUND3-REMEDIATION.md`](SECURITY-ASSESSMENT-ROUND3-REMEDIATION.md) | Round-3 red-team remediation record (F1/F3 fixed, F2 accepted) | F1/F3 fixed with hardware evidence; F2's accepted-risk record is [`../debug-access-risk.md`](../debug-access-risk.md) |

The two `webauthn-discovery-*.md` files and the security/storage/budget
records that are still cited from code, CI or other documents were **not**
archived; they remain at `docs/` — see the index.
