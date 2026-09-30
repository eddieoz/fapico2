# EPIC: Rewrite the stateless U2F key-handle derivation (provenance remediation)

**Epic ID:** `REWRITE-STATELESS-U2F`
**Status:** Draft
**Tree:** `fapico2/`
**Story point convention:** 1 point = ≤1 day, independently verifiable, TDD
where a test can run on the host; BDD scenarios (Gherkin) are written first
and become the names of the Rust tests that satisfy them.
**Source of this epic:** the provenance audit
([`docs/provenance.md`](../provenance.md), 2026-09-30), which found
`apps/fido/src/stateless.rs` to be a documented, byte-faithful translation of
`pico-fido`'s (AGPL-3.0) stateless U2F derivation, with translated fragments
carried into `u2f.rs` and `device_core.rs`'s U2F section.

---

## Epic goal

Replace the stateless U2F key-handle construction with an **independently
designed** one, so that the FIDO app's stateless-credential path can be
asserted clean-room and the workspace can move toward a permissive license
(`MIT OR Apache-2.0`), per the provenance audit's remediation list.

## Why this is safe to change (facts the epic rests on)

1. **U2F key handles are opaque to clients.** The FIDO U2F spec never
   interprets handle bytes; only the token does. No client-visible contract
   changes.
2. **Current handles are already not C-firmware interoperable.** The master
   key comes from fapico2's own `device_random` (label `b"fapico2 u2f master
   v1"`), not the C `ef_keydev` slot. Changing the *algorithm* therefore
   breaks nothing that worked across firmwares.
3. **Re-enrollment is the only consequence.** A device updated mid-life will
   refuse its pre-update U2F registrations (tag verify fails); users
   re-enroll. This must be stated in the release notes (US-1107), not hidden.
4. **What is actually translated** (audit evidence): the 67-byte HKDF-SHA512
   self-chaining scratch (`stateless.rs:112-129`, comment *"outk mirrors the
   C 67-byte scratch"*); the MSB-forced path words (`u2f.rs:62`,
   `device_core.rs:3295`, comments *"C: val |= 0x80000000"*); the
   `appId ‖ keyHandle[0..32]` HMAC tag; the per-word MSB detection gate in
   `is_stateless` (`stateless.rs:101-105`). None of it is in any FIDO
   specification.

## Constraints

- `no_std`, no heap on the device path (`heapless` only), zeroize on drop for
  every derived secret (US-704 precedent in the current `StatelessScalar`).
- The size gate applies: the device `text` ceiling and the size report
  re-measure story (US-1108) are part of Definition of Done.
- CTAP1/U2F black-box behaviour must stay spec-compliant: `tests/pico-fido/
  test_052_u2f.py` stays green, and `python-fido2` must keep registering and
  authenticating against the emulation binary.
- **Out of scope** (see "Scope boundary" below): `app.rs::
  derive_large_blob_key`'s SLIP-0022 chain, the PIN-layer naming/orderings in
  `device_core.rs`, the PIV mockup crate, the NOTICE and `vendor/x448`
  license fixes.
- Story IDs use the US-11xx range; if any collides with an existing story,
  renumber the collision, not the audit trail.

## Scope boundary — what this epic clears, and what it does not

**Clears:** the FIDO *stateless-credential* area — `stateless.rs` whole, and
the U2F sections of `u2f.rs` / `device_core.rs`. After US-1108, the
provenance record can assert that area clean-room.

**Does not clear** (each is a separate remediation item; all are recorded in
`docs/provenance.md`):

1. `apps/piv/` — derivative-evident mockup. **Deletion is excluded by
   decision of the owner: PIV is needed for PicoForge compatibility.** The
   remediation is an independent rewrite of the mockup's expression while
   keeping the PicoForge-facing byte surface (Phase E, US-1109/US-1110).
2. `app.rs::derive_large_blob_key` — the C "SLIP-0022" HMAC chain with C's
   literal labels; re-derive with fapico2's own labels, **versioned**, so
   existing credentials keep their large-blob keys. (Phase E, US-1111.)
3. `device_core.rs`'s PIN layer — C-carried naming (`needs_power_cycle`,
   `new_pin_mismatches`, `hkey`) and free-choice orderings (the 3-strike
   power-cycle latch, decrement-retries-before-compare). This epic only
   rewrites the file's **U2F section**; the PIN layer remains suspect and
   with it the file as a whole. (Phase E, US-1112.)
4. `vendor/opcard` — **LGPL-3.0-only and linked into every build** (the
   OpenPGP card layer, +2,111 lines of local modifications). No rewrite of
   CTAP code changes this: a fully permissive *workspace* requires replacing
   opcard (major) or adopting a dual-track license strategy. **Strategic
   decision — own ADR** (Phase E, US-1115).
5. `vendor/x448` (unlicensed upstream attribution) and the NOTICE opcard
   claim — license hygiene. (Phase E, US-1114.)
6. `apps/oath/src/otp.rs`'s test helpers verbatim-porting picoforge's (AGPL)
   `pad_challenge` — host-test-only; re-derive independently. Also the
   `cfs.rs` layout-diagram paraphrase. (Phase E, US-1113.)

**Therefore:** completing Phases A–D **plus Phase E** makes the first-party
tree assertable clean-room, at which point `MIT OR Apache-2.0` for fapico2's
own crates is defensible. **The combined firmware is AGPL-3.0-or-later as of
2026-09-30** (license moved from GPL-3.0-or-later; LGPL-3.0-only opcard is
compatible into AGPL, so the whole work carries AGPL) — Phase E's rewrite
work is now hygiene and the prepared permissive path, not a compliance
prerequisite. US-1115 decides only whether to pursue more openness by
replacing opcard.

## BDD conventions for this epic

- Every story's scenarios are written in Gherkin **before** implementation
  and live as Rust tests whose names carry the scenario wording
  (`given_<g>when_<w>then_<t>` or a close, readable form).
- Device-path tests run under the `device` feature on the host target
  (precedent: `apps/fido/tests/stateless_keyhandle.rs`,
  `u2f_device_bounds.rs`); end-to-end scenarios run against the emulation
  binary over the existing pytest harness.
- Red first: a story's tests must fail (compile-error counts as red) before
  the implementation that satisfies them lands in the same story or the next.

---

## Phase A — Design (1 story)

### US-1101: ADR for the v2 stateless construction
**As a** firmware maintainer **I want** a written design for the replacement
derivation **so that** the implementation has an independent, reviewable
specification instead of a C skeleton to imitate.
- [ ] New ADR under `docs/adr/` specifying: KDF choice and domain-separation
      labels (all fapico2-prefixed, registered in a label table inside the
      ADR), handle layout (64 bytes: `version ‖ path ‖ tag` or an explicitly
      argued alternative), the master-key source (persisted `device_random`,
      HKDF-SHA256), and the version/refusal policy for handles minted under
      v1.
- [ ] The ADR states the negative space explicitly: **no** 67-byte scratch,
      **no** MSB-forced path words, **no** SLIP-0022-style label chain, **no**
      per-word MSB gate as the stateless-shape test — each named so a reviewer
      can grep for them.
- [ ] The ADR records the re-enrollment consequence (fact 3) as an accepted
      trade-off.
- [ ] Decision records follow the repo's ADR format; the label table is the
      single place future stories may add labels.

**Acceptance:** ADR merged; a reviewer can implement from it without reading
`stateless.rs` or any C file.

---

## Phase B — Tests first (2 stories)

### US-1102: Red — the v2 contract suite
**As a** firmware developer **I want** failing tests that pin the *contract*
of the new module **so that** the implementation is driven by behaviour, not
by the old code's shape.
- [ ] Write the contract suite against a compile-stub of the new API
      (`mint`, `resolve`, `verify`, `is_recognized` — names per the ADR).
      Target file: `apps/fido/tests/stateless_keyhandle_v2.rs` (the existing
      `stateless_keyhandle.rs` stays until US-1106 flips it).
- [ ] Scenarios (Gherkin, one test each), minimum set:

```gherkin
Feature: Stateless U2F key handles v2
  Scenario: Round-trip under the same master
    Given a device master key
    When a handle is minted for an application id
    Then resolving that handle yields a scalar whose verification succeeds
    And the verification succeeds again on a freshly derived master instance

  Scenario: A different application id does not verify
    Given a minted handle for application A
    When verification is attempted with application B
    Then it fails

  Scenario: A tampered tag does not verify
    Given a minted handle
    When any single tag byte is flipped
    Then verification fails for every position of the flip

  Scenario: A v1-shaped handle is not recognized
    Given a 64-byte handle whose every path word has the MSB set
    When the recognizer is asked whether it is a v2 handle
    Then it answers no
    And resolving it fails

  Scenario: Minting is randomized and resolving is deterministic
    Given two mints for the same application id and master
    Then the handles differ (fresh random path per mint)
    But each resolves to the same scalar as itself
```

- [ ] A determinism-across-boot scenario: master re-derived from the same
      persisted `device_random` resolves a handle minted "before the reboot"
      (host test simulating the reboot by reconstructing the store).
- [ ] All tests red.

### US-1103: Red — known-answer vectors with independent provenance
**As a** auditor **I want** KATs whose generator is not the code under test
**so that** the vectors evidence the construction, not itself.
- [ ] Add `apps/fido/tests/stateless_v2_kat.rs` with vectors embedded as
      constants plus a header naming their generator.
- [ ] The generator is a small standalone script (Python `hashlib`/
      `cryptography`) committed under `tests/scripts/gen_stateless_v2_kat.py`,
      documented to implement the ADR's construction independently; the
      vectors in Rust are its output.
- [ ] Tests red (implementation does not exist yet).

---

## Phase C — Implementation (3 stories)

### US-1104: Green — master key v2, mint, resolve, verify
**As a** firmware developer **I want** the v2 construction implemented in
`stateless.rs` **so that** the contract suite turns green.
- [ ] Replace the module's derivation core per the ADR: new master label
      (`v2`), new path→scalar derivation, new tag construction, new
      recognition predicate. Delete the 67-byte scratch, the MSB forcing, and
      the C-shaped gate in the same commit — no dual-path residue.
- [ ] `StatelessScalar` keeps its zeroize-on-drop behaviour; new secrets get
      the same treatment.
- [ ] US-1102 and US-1103 suites green; existing `stateless_keyhandle.rs`
      (v1) red — expected, flipped in US-1106.

### US-1105: Green — legacy-handle refusal policy
**As a** device owner **I want** pre-update U2F registrations to fail safely
and legibly **so that** the update cannot silently authenticate or corrupt
state.
- [ ] Scenarios (in `stateless_keyhandle_v2.rs`):

```gherkin
  Scenario: A v1 handle at authenticate time
    Given a device whose master is v2
    When a register/authenticate request presents a v1-shaped handle
    Then the applet answers the U2F wrong-data error
    And no credential state changes

  Scenario: A v2 handle after the master rotated
    Given handles minted under an old device_random
    When the device_random is replaced (factory reset, re-provision)
    Then the same handles fail verification
    And the applet answers the same wrong-data error
```

- [ ] The refusal path is documented in the module docs as the
      re-enrollment contract, cross-referenced from the release notes story.

### US-1106: Rewire the call sites; delete the v1 surface
**As a** firmware developer **I want** `u2f.rs` and `device_core.rs`'s U2F
section on the v2 API **so that** no translated code path remains reachable
or present.
- [ ] `u2f.rs`: `stateless_handle` mints v2; `u2f_authenticate` resolves
      through the new verify; the *"C: val |= 0x80000000"* comments and
      *"C `verify_key` path"* framing go with the code they describe.
- [ ] `device_core.rs` U2F section (≈ lines 3260-3462): same rewire; its
      duplicated derivation and `// C:` annotations are removed with it.
      (PIN-layer naming elsewhere in the file is out of scope.)
- [ ] Delete `apps/fido/tests/stateless_keyhandle.rs` (v1 suite) or rewrite
      it as the v2 call-site suite — whichever leaves the smaller total.
- [ ] Neighbouring suites stay green: `u2f_device_bounds.rs`,
      `u2f_presence.rs`, `counter_monotonic.rs`, `counter_batching.rs`,
      `heapless_cbor.rs` (the `process_u2f` signature must not change).

---

## Phase D — Acceptance and record-keeping (2 stories)

### US-1107: Black-box acceptance over the emulation binary
**As a** release owner **I want** the C-gating U2F pytest suite green on the
rewritten firmware **so that** the rewrite is proven at the protocol level,
not only in unit tests.
- [ ] Build the emulation binary; `tests/pico-fido/test_052_u2f.py` green.
- [ ] Add one regression scenario to the suite (or a sibling file): register
      → sign → verify signature, plus one *negative* check that a malformed
      64-byte handle answers the standard U2F error rather than panicking or
      erroring differently.
- [ ] Release notes entry (US-392's document): U2F stateless registrations
      from previous firmware versions require re-enrollment after update;
      reason stated in one line.
- [ ] Emulation + host suites green: `cargo test --workspace --target
      x86_64-unknown-linux-gnu --exclude fapico2-firmware` and `cargo test -p
      fapico2-firmware --lib -- --test-threads=1`; both clippy gates clean.

### US-1108: Provenance flip, marker gate, size re-measure
**As a** maintainer **I want** the records to reflect the rewritten reality
**so that** the relicensing argument rests on verifiable statements.
- [ ] `docs/provenance.md`: `stateless.rs` and the U2F sections of
      `u2f.rs`/`device_core.rs` move from DERIVATIVE-*/SUSPECT to CLEAN-ROOM
      with a pointer to the ADR and the KAT provenance.
- [ ] New gate `tests/scripts/check_provenance_markers.py`: fails when a
      banned marker appears. **Scope and marker list matter** — a naive
      "mirrors the C" ban would fail today on ~10 CLEAN-ROOM files that use
      the phrase to *document an interface fact* (`cflash.rs`, `usb.rs`,
      `hid_control.rs`, `migration.rs`, `mgmt/lib.rs`), and the `otp.rs`
      verbatim-port helpers are outside this epic. So:
      * paths: `apps/fido/src/` only (extend as the sibling remediations
        land);
      * banned strings: `Ported from the C firmware`, `verbatim port of`,
        `C: val |= 0x80000000`, `mirrors the C 67-byte scratch`,
        `derive_key`, byte-for-byte, `C \`verify_key\``;
      * each hit must be a comment/line a human confirmed is translated-code
        lineage, so the gate file carries the rationale per pattern (same
        shape as `check_debug_strip.py`).
      Wire it into the CI gate list.
- [ ] If the device image moved: `./build.sh`, re-measure with
      `measure_task_arena.py` and `check_size_report.py`'s own renderer, and
      re-splice `docs/size-report.md` by its documented procedure.
- [ ] All 24 gates green.

---

## Phase E — Sibling remediations (first-party clean-room completion)

Phase A–D clear the stateless area; Phase E clears the rest of the
first-party tree so `docs/provenance.md` can assert it clean-room end to end.
PIV is explicitly **not** deletable (owner decision: PicoForge compatibility
requires it), so its stories rewrite expression while pinning behaviour.

### US-1109: PIV characterization suite — pin the PicoForge-facing surface
**As a** firmware maintainer **I want** the PIV mockup's observable wire
behaviour pinned by tests **so that** the expression rewrite in US-1110
cannot silently change what PicoForge sees.
- [ ] New `apps/piv/tests/wire_surface.rs`: characterization tests over
      SELECT FCI, VERIFY (retry counter semantics, `63Cx` on wrong PIN),
      CHANGE REFERENCE, RESET RETRY, GET DATA / PUT DATA (including the
      unknown-FID and malformed-tag responses), and MANAGEMENT KEY auth
      (witness/mutual and single paths).
- [ ] Scenarios (Gherkin, one test each), minimum set:

```gherkin
  Feature: PIV wire surface (PicoForge compatibility)
    Scenario: SELECT returns the FCI template the client expects
      Given a reset PIV applet
      When the PIV AID is selected
      Then the FCI bytes match the pinned template
      And the status word is 9000

    Scenario: A wrong management key authenticates nothing and counts
      Given the default management key
      When AUTHENTICATE is presented with a wrong key
      Then the status word is the pinned failure SW
      And a subsequent correct attempt still succeeds

    Scenario: GET DATA for an unknown object answers the pinned SW
      Given a reset PIV applet
      When GET DATA names an object id outside the known table
      Then the response is the pinned SW, not a panic or a different error
```

- [ ] Where a pinned behaviour is a **client-compat fact** (FCI template,
      unknown-FID SW, `63Cx` ladder), the test names it as such — these are
      the byte surfaces PicoForge depends on and the rewrite must preserve
      them byte-for-byte while changing nothing else.
- [ ] Suite green against the current mockup (characterization, not red).

### US-1110: PIV independent rewrite — new expression, same wire surface
**As a** licensing owner **I want** the PIV mockup's expression rewritten
independently of `piv.c`/`crypto_utils.c` **so that** the crate can be
asserted clean-room without touching what PicoForge sees.
- [ ] Working from US-1109's pinned surface, re-implement each command path
      from the PIV spec (NIST SP 800-73-4) and the ADR'd design decisions —
      not from the C source. Different helper decomposition, different
      naming, original comments.
- [ ] The C-carried artifacts go: the `C <identifier>` mapping comments, the
      branch-for-branch `authenticate_mgm` shape, the replicated GET DATA
      clause ordering, the `tlv.c` walker quirk (re-derive the walk from the
      TLV rules the PIV spec actually requires; any compat quirk that
      US-1109 proves PicoForge depends on stays, documented as a wire-surface
      fact).
- [ ] The KDF chain used on **storage/migration of C-produced records**
      (`"DEVICE/ROOT"` 12-byte-with-NUL form and friends) is **kept** where
      US-1110's tests prove data written by the C firmware must still open —
      that is an interface fact and moves to the provenance disclosure list,
      not the rewrite. The internal chain for fapico2-originated state uses
      fapico2's own labels.
- [ ] The `"Pico Keys PIV"` FCI branding string: decide in the ADR note —
      keep if PicoForge matches on it (US-1109 pins the answer), else
      fapico2's own label.
- [ ] US-1109 suite stays green byte-for-byte; `cargo test -p fapico2-piv`
      green; both clippy gates clean.

### US-1111: largeBlobKey — versioned fapico2 derivation
**As a** credential owner **I want** large-blob keys derived from fapico2's
own construction **so that** the last translated crypto chain in `app.rs` is
gone without breaking existing credentials.
- [ ] First pin the current semantics: where the key lives (derived on
      demand vs stored with the credential) — write the test that proves
      which, because the migration story depends on the answer.
- [ ] Scenarios (Gherkin):

```gherkin
  Feature: largeBlobKey derivation v2
    Scenario: A new credential gets a key from the v2 chain
      Given a make-credential with the largeBlobKey option
      When the credential is created
      Then its large-blob key is the v2 derivation of its credential id
      And the key is a valid AES-256 key for large-blob operations

    Scenario: Existing credentials keep their stored keys
      Given a credential created before the v2 cutover
      When its large blobs are read and written
      Then the stored key is used unchanged
      And no re-derivation is attempted

    Scenario: The derivation is deterministic per credential id
      Given the same credential id and device master
      When the key is derived twice
      Then both derivations agree
```

- [ ] If the key is **derived on demand** (not stored), the v2 cutover
      invalidates existing large blobs the way the U2F cutover invalidates
      handles — state that in the story's outcome note and the release-notes
      line in US-1107 either way, from evidence, not assumption.
- [ ] New labels registered in the US-1101 label table; KAT generated by the
      US-1103 script extended for the chain; `app.rs`'s SLIP-0022 chain
      deleted in the same commit.

### US-1112: device_core.rs PIN layer — de-C-parity refactor
**As a** licensing owner **I want** the PIN layer's C-carried naming and
orderings replaced **so that** `device_core.rs` as a whole leaves the
suspect column.
- [ ] Characterization tests first (green): the observable CTAP2 PIN
      behaviour — retry counter render (`63Cx`), blocked state, power-cycle
      requirement after the new-PIN mismatch latch, decrement-on-failure
      semantics, PIN-protocol v2 verifier path. These are spec-visible or
      security-posture behaviours and **must not change**.
- [ ] Then the refactor, behaviour-neutral by the pinned tests:
      rename `needs_power_cycle` / `new_pin_mismatches` / `hkey` to
      fapico2-native names (e.g. `requires_reinit`, `fresh_pin_mismatches`,
      `pin_agreement_key` — final names in the story, not here); rewrite the
      comments that narrate C orderings ("C parity",
      "decrement retries before comparison (C parity)") into statements of
      this firmware's own rule; re-express the 3-strike latch with its own
      decomposition (the *behaviour* stays — it is a security choice this
      firmware makes, but the expression is C's).
- [ ] The C-internal `encIdentifier`/`encCredStoreState` label reuse in the
      get-info device-state block: decide per US-1101's label table — if the
      strings are load-bearing for anything fapico2-local, they are
      fapico2's to rename; no C-produced data carries them.
- [ ] No observable behaviour change: the full `apps/fido` suite (including
      `pin.rs`, `pin_lockout.rs`, `pin_verifier.rs`, `pin_perms.rs`,
      `device_core_mc_ga.rs`) green unchanged.

### US-1113: Interop test helpers — re-derive, don't transcribe
**As a** licensing owner **I want** the AGPL-derived test helpers replaced
with independently written equivalents **so that** the test tree is inside
the clean-room claim too.
- [ ] `apps/oath/src/otp.rs` (~2475-2500): re-derive `client_pad_challenge`
      from the padding *rule* (pad byte must differ from the frame's last
      byte; frame is 64 bytes) with original naming and comments; same for
      `firmware_trim` (the trailing-byte trim is YubiKey protocol semantics
      — implement from the rule, cite the rule, not a C line).
- [ ] Prove equivalence the TDD way: property test that the re-derived
      helpers agree with the old ones on randomized inputs **in the same
      commit**, then delete the transcribed versions.
- [ ] `platform/src/cfs.rs:7-10`: paraphrase the ASCII layout diagram
      (field names are the format's own; the prose around them becomes
      original).

### US-1114: License hygiene — x448 and NOTICE
**As a** release owner **I want** the third-party license record accurate
**so that** the relicensing argument is not undermined by its own SBOM.
- [ ] `vendor/x448`: its LICENSE admits upstream ships no license — replace
      the vendored copy with the RustCrypto `x448` crate (Apache-2.0 OR MIT)
      as a normal dependency, or drop it if the x448 use can ride an
      existing curve crate. Either way the fabricated BSD-3 attribution is
      removed.
- [ ] Verify `vendor/ed448-goldilocks`'s BSD-3 text against the pinned
      upstream commit (upstream presents MIT OR Apache-2.0); correct the
      attribution to whatever the pinned commit actually carries.
- [ ] NOTICE: replace the false "library sources unmodified" opcard claim
      with the real one (modified and extended, remaining LGPL-3.0-only,
      sources conveyed); retitle the license table so crates.io deps are not
      labelled "vendored"; add the trussed family (Apache-2.0 OR MIT) and the
      RustCrypto crates.
- [ ] Wire the corrected claims into a small gate check (extend
      `check_supply_chain.py` or a sibling) so they cannot silently rot.

### US-1115: ADR — the opcard strategy decision
**As a** product owner **I want** a written decision on the LGPL-3.0-only
opcard dependency **so that** the ceiling on the firmware's license is a
choice, not an accident.
- **2026-09-30: the license half of this decision was taken.** The workspace
  was relicensed to **`AGPL-3.0-or-later`** (sole copyright holder; the
  provenance audit showed AGPL is the honest label for the derivative
  portions). Under AGPL, LGPL-3.0-only opcard is compatible, so the combined
  firmware is AGPL end to end and the dual-track branch below is **moot**.
  What remains to decide here is only whether to *pursue more openness*:
- [ ] The ADR evaluates, with effort/size estimates grounded in this tree:
      (a) **replace** opcard with an in-house OpenPGP card layer (major —
      it is the full OpenPGP 3.4 command set) as the only route to a
      fully permissive combined work, or (b) **status quo** (stay AGPL;
      commercial dual-licensing of first-party code remains available to
      the copyright holder, as the upstreams do).
- [ ] Input facts recorded: opcard is linked into every build; fapico2's
      modifications are +2,111 lines; the OpenPGP app is one of the three
      hardware-accepted command sets; the v1.0.0 shipping posture.
- [ ] The decision names the license the *combined firmware* can carry and
      the license fapico2's own crates carry; `docs/provenance.md` and the
      workspace `Cargo.toml` `license` fields are updated in the same
      change if the decision moves them.

### US-1116: Final provenance assertion + gate coverage extension
**As a** maintainer **I want** the marker gate extended and the provenance
record finalized **so that** the clean-room claim is enforced, not
narrated.
- [ ] Extend `check_provenance_markers.py` (from US-1108) from
      `apps/fido/src/` to `apps/`, `platform/src/`, `firmware/src/` — now
      safe, because US-1109–US-1114 removed every transcribed-lineage text
      it would otherwise false-positive on (`piv` mapping comments, `otp.rs`
      verbatim-port helpers, `cfs.rs` diagram).
- [ ] `docs/provenance.md`: every area row CLEAN-ROOM (or explicitly
      LGPL-attributed for opcard under US-1115's decision); the
      disclosure list is the only place C interface facts appear.
- [ ] Full sweep green: workspace + firmware-lib tests, both clippy gates,
      all gates.

---

## Dependency graph

```
US-1101 (ADR)
   └→ US-1102 (red contract) ─┐
   └→ US-1103 (red KATs) ─────┼→ US-1104 (green core) → US-1105 (refusal policy)
                                                     └→ US-1106 (rewire + delete v1)
                                                            └→ US-1107 (black-box)
                                                                   └→ US-1108 (records)

Phase E (independent of A–D except where noted):
US-1109 (PIV surface pin) → US-1110 (PIV rewrite)
US-1111 (largeBlobKey v2)          [uses US-1101's label table + US-1103's KAT script]
US-1112 (device_core PIN de-parity)
US-1113 (interop helper re-derivation)
US-1114 (x448 + NOTICE hygiene)
US-1115 (opcard strategy ADR)  ← bounds the combined firmware's license
US-1116 (final assertion + gate extension)  [after all of the above]
```

US-1102 and US-1103 can run in parallel; US-1107 needs a firmware build; the
release-notes line in US-1107 can land any time after US-1105 fixes the
refusal policy. In Phase E, US-1110 needs US-1109's pinned surface;
US-1116 needs everything before it. All other Phase E stories are
independent and can run in any order or in parallel.

## Definition of Done (epic level)

- [ ] Every story's scenarios green; no v1 derivation code or comments remain
      under `apps/fido/src/`.
- [ ] `grep -rn "67" apps/fido/src/stateless.rs` (the scratch size) and the
      US-1108 marker gate both clean.
- [ ] `docs/provenance.md` updated; `test_052_u2f.py` green on emulation.
- [ ] Size report and arena stamp re-measured if the image moved.
- [ ] Phase E: PIV wire surface pinned byte-for-byte through its rewrite;
      largeBlobKey chain and PIN-layer naming re-derived with the pinned
      behaviour unchanged; transcribed test helpers gone; NOTICE/x448
      accurate; opcard strategy decided by ADR; marker gate covers the whole
      first-party tree and `docs/provenance.md` asserts it.
