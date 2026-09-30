# EPIC: Device memory & flash budget (RAM headroom, curve configuration)

**Epic ID:** `DEVICE-MEMORY-FLASH-BUDGET`
**Status:** Draft
**Tree:** `fapico2/`
**Story point convention:** 1 point = ≤1 day, independently verifiable, TDD
where a test can run on the host; BDD scenarios (Gherkin) are written first
and become the names of the Rust tests that satisfy them.
**Source of this epic:** the measured state of the shipping image
(`docs/size-report.md`, 2026-09-30) plus a review of the RAM static map
against the gate scripts in `tests/scripts/`.

---

## Epic goal

Restore **RAM headroom** on the RP2350, and make the OpenPGP card's
higher-cost NIST curves a **build-time choice** rather than a fixed cost —
without changing what any shipped device does on the wire.

Today the device carries **4 bytes of slack**. That is the entire finding
this epic exists to answer, and it is worth stating plainly because it is
not a "tight" budget, it is a closed one.

## Facts the epic rests on (measured, not estimated)

1. **RAM is full.** RAM statics 420,672 B (`.data` + `.bss` + `.uninit`) plus
   the main stack zone 111,588 B = **532,476 B of 532,480 B**. The 4 B is
   `ALIGN(4)` slack in `cortex-m-rt`'s `link.x`, not margin.
2. **The linker does not fail on a new static.** It shrinks the main stack
   region until the boot path overflows it. That is the real dark-boot
   mechanism (DARK-BOOT-1, US-1010), and it is why "the build succeeded" is
   not evidence that the device will boot.
3. **Flash is not the constraint.** `text` 813,508 B against a 3,670,016 B
   ceiling — 22% used, 2.86 MB free. Phase D exists because the wins are
   real and cheap, **not** because flash is scarce.
4. **The gates are:** `RAM_CEILING = 434,176` (= 532,480 −
   `CHAIN_CEILING` 98,304, imported by `check_size_report.py` from
   `check_boot_chain.py`); `CEILING = 3,670,016` for `text`; the
   task-arena stamp (`arena_stamp.py` / `measure_task_arena.py`).
   Headroom today: **13,700 B of `bss`**.
5. **The single largest RAM item is dead weight.**
   `MigrationBuffers` (`platform/src/migration.rs:234`) bundles a
   always-needed `scratch: [u8; 16384]` with **five** 16 KiB class
   accumulators (81,920 B) that only `migration::run()` — the once-per-device
   first-boot walk — ever touches. Two instances exist
   (`firmware/src/boot.rs:307` and `MigrationAuthority.bufs` at
   `platform/src/trusted_backend/dispatch.rs:155`), so both carry both
   halves.
6. **One of the two instances never touches an accumulator at all.** All
   seven `MigrationPinAuthority` methods plus `wrapping_key`
   (`dispatch.rs:221, 228, 251, 261, 278, 292, 317`) pass the buffer only to
   functions that read `bufs.scratch`. Its 81,920 B of accumulators are
   permanently zero-length — written only by the `write_bytes` zeroing at
   `dispatch.rs:210`. **163,840 B of permanently-resident, permanently-empty
   memory**, plus ~2 KB of scratch that is genuinely needed.
7. **The two instances cannot be merged.** `device_shell.rs:261` calls
   `self.card.migration_pin_ready(source)` while the `bufs` parameter is still
   mutably borrowed at `:252`; that call re-enters `MigrationAuthority`
   through trussed and takes `self.bufs.borrow_mut()`. Both are live in one
   frame. Any proposal that reaches for "share one buffer" is proposing UB.
8. **The p384/p521 split is the whole Phase C design.**
   `trussed-core`'s `p384 = []` is an **empty marker feature** gating only the
   `Mechanism::P384` data-model variant. `trussed`'s
   `p384 = ["trussed-core/p384", "dep:p384"]` is where the ~174 KB of curve
   arithmetic lives. Keeping the marker is what lets the fail-closed gate
   still refuse a P-384r1 `PUT DATA` with `6A80` instead of failing to parse
   it — the US-966 precedent, stated in `vendor/opcard/src/card.rs:410-418`.
9. **This has already been proven the hard way once.** US-1070 rolled SHA-512
   into a function 8.9× smaller than the stock one and the image still *grew*
   864 B, because the original stayed in the closure. `size-report.md`
   records the lesson: *"A symbol that is present in one build and absent in
   the next says more about what the shipping image contained than any figure
   in this document does."*

## Constraints

- `no_std`, no heap on the device path (`heapless` only). The one sanctioned
  allocator stays sanctioned (`check_heap_gate.py`, US-961) — this epic adds
  none and removes none.
- Every story is **behaviour-preserving on the device path**. Migration is
  the one subsystem here that can destroy credentials, so Phase B is a
  refactor with a byte-level baseline, never a behavioural edit.
- Ceilings and stamps are re-measured, not reasoned about. Size claims are
  measured with `check_size_report.py`'s own `measure_elf()`.
- `panic = "abort"`: a panic on any touched path is a brick, not a stack
  unwind. New code follows the existing write-once `static mut` discipline
  and adds no new panics on reachable paths.
- Story IDs use the US-12xx range; US-11xx is taken by
  `EPIC-rewrite-stateless-u2f.md`.

## Scope boundary

**In scope:** the `MigrationBuffers` shape, the embassy task-arena step, the
p384/p521 build switch and its advertisement, dead USB dependency features,
`sha2` generation consolidation, and the stale build configuration.

**Out of scope, with the reasoning recorded so it is not re-litigated:**

1. **Firmware compression and running from SRAM.** Arithmetically impossible
   here. 758 KB of `.text` cannot be decompressed into a 111 KB stack zone —
   the ratio is wrong by ~7× — and 2.86 MB of flash sits unused. This is the
   advice most firmware-size guides lead with; it targets an RP2040-shaped
   problem this board does not have.
2. **`panic_immediate_abort`, hand-rolled `memcpy`/`memset`, `opt-level =
   "s"` A/B.** All bounded by the measured 17,536 B of
   `core + compiler_builtins + alloc`, against `unsafe`-correctness risk on a
   security device. Fact 9 is the recorded evidence that "smaller function"
   does not mean "smaller image".
3. **Compiling migration out of production builds.** Unlike
   `FAPICO2_FOREIGN_IMAGE_WIPE`, migration is **not** dead on a migrated
   device: the runtime APDU paths (`boot.rs:685`, `boot.rs:751`) complete the
   capture after boot, and `has_openpgp_capture()` is
   `store.contains(SLOT_OPENPGP_SOURCE)` — a runtime fact, unknowable at
   build time. A build without migration would strand every device caught
   mid-migration.
4. **Flash-backing the EFS/VFS volumes (64 KB).** Real, but it converts
   currently-ephemeral trussed state into persistent state. A product
   decision, deliberately left open rather than taken by a memory budget.
5. **Removing the three required backends (RSA, secp256k1, Brainpool).** They
   are advertised, so removing one is a lie, not a size win. Phase C's p384 /
   p521 handling is the model for doing this correctly, including for
   features that are on by default.

---

## BDD conventions for this epic

- Every story's scenarios are written in Gherkin **before** implementation
  and live as Rust tests whose names carry the scenario wording
  (`given_<g>when_<w>then_<t>` or a close, readable form).
- **Red first.** A story's tests must fail before the implementation that
  satisfies them lands. A compile error counts as red — US-1202 and US-1204
  are retyping stories whose red *is* a compile failure, and that is stated
  per story rather than glossed.
- **Characterization is green first, and says so.** US-1201 pins behaviour
  that already works; it is not red, and a story that says "all tests red"
  for it would be lying.
- **Size claims are asserted as absent symbols.** A story passes when
  `arm-none-eabi-nm` shows the symbol is **gone** (fact 9), not when the
  byte count looks smaller. Byte counts belong in `size-report.md`.
- Device-path behaviour runs under the `device` feature on the host target;
  end-to-end scenarios run against the emulation binary over the existing
  pytest harness.

---

## Phase A — Pin the behaviour before touching it (1 story)

### US-1201: Characterization — byte-level baseline for the migration class slots
**As a** firmware maintainer **I want** the migration subsystem's observable
output pinned byte-for-byte **so that** Phase B's retyping and restructure can
be proven behaviour-preserving rather than merely plausible.
- [ ] New `platform/tests/migration_baseline.rs`. Fixture: a C data partition
      (`tests/scripts/fixtures/`) carrying records in **all five** classes
      (OpenPGP, OATH, OTP, PIV, FIDO container) plus the FIDO keydev and
      management `EF_DEV_CONF` records, so every `push_tlv` arm and both
      scratch-only arms execute.
- [ ] Scenarios (Gherkin, one test each):

```gherkin
  Feature: Migration class-slot baseline (characterization)
    Scenario: Every class slot receives a byte-exact TLV stream
      Given a C partition holding records in all five classes
      When migration runs against an empty store
      Then each of the five slots holds the recorded baseline bytes
      And the per-class record counts match the fixture

    Scenario: The captured OpenPGP stream round-trips through chunked write
      Given an OpenPGP class stream that exceeds one store value
      When migration writes it
      Then the chunked read-back equals the accumulated stream byte-for-byte
      And the capture authenticator over the stream matches

    Scenario: A class stream past the per-class cap is refused, not truncated
      Given an OATH class whose TLV stream exceeds the 16 KiB cap
      When migration runs
      Then it returns SlotOverflow
      And no class slot has been written

    Scenario: The runtime authority paths use scratch only
      Given a store holding an OpenPGP capture
      When every MigrationPinAuthority method is exercised
      Then the stable wrapping key returned is the recorded one
      And a refused passphrase spends exactly one attempt
```

- [ ] The baselines are **committed constants**, not regenerated on the fly;
  a reviewer diffs them. Each records which arm of the match produced it.
- [ ] Suite is **green against the current code**. This is characterization.
      If it cannot be made green, stop and report — a red characterization
      means something is already wrong and Phase B is not the story to fix it.
- [ ] `tests/scripts/check_us413_feasibility.py` stays green (the US-413
      migration gate is authoritative for this subsystem).

**Acceptance:** baselines committed; suite green; a reviewer can diff the five
slots and see exactly which bytes each class contributes.

---

## Phase B — RAM headroom (~155 KB)

### US-1202: Red — `MigrationScratch` and the accumulator become unreachable from the authority
**As a** firmware maintainer **I want** the authority's buffer type to not
carry accumulators **so that** the 81,920 B of permanently-empty memory is
removed by the compiler rather than by discipline.
- [ ] Scenarios (Gherkin, one test each):

```gherkin
  Feature: Migration scratch decoupling
    Scenario: The authority's type cannot reach a class accumulator
      Given the MigrationAuthority's buffer type
      When it is inspected as a type
      Then it has a scratch field and no class accumulator fields

    Scenario: Authority verification is unchanged by the narrowing
      Given a capture whose PW1 verifier matches the presented passphrase
      When the authority's verify method is called
      Then it returns the same stable wrapping key as US-1201 recorded
      And no slot is written
```

- [ ] Add `MigrationScratch { scratch: [u8; MAX_WHOLE_PAYLOAD] }` beside
      `MigrationBuffers` in `platform/src/migration.rs`.
- [ ] The type-shape scenario is a compile-time assertion: construct a
      `MigrationScratch` and take `&mut .scratch`; any field access to an
      accumulator **must not compile**. Record that in the story outcome.
- [ ] **Red** — this story lands the type and the failing tests only; the
      authority is not yet retyped. Red here is a compile error by design.

**Acceptance:** tests red for the stated reason (the authority still holds
`RefCell<MigrationBuffers>`).

### US-1203: Green — retype `MigrationAuthority` onto the narrow buffer
**As a** firmware maintainer **I want** the authority to hold only what it
uses **so that** ~81,960 B of `.bss` is returned to the stack zone.
- [ ] `dispatch.rs:155`: `bufs: RefCell<MigrationScratch>`.
- [ ] Retype to `&mut MigrationScratch` the scratch-only migration functions
      the authority calls — `captured_openpgp_pw1_retries`,
      `verify_captured_openpgp_pw1`, `captured_openpgp_pw3_retries`,
      `verify_captured_openpgp_pw3`, `captured_openpgp_rc_retries`,
      `verify_captured_openpgp_rc`, `wrapping_key`'s
      `read_openpgp_capture`. Every one of these touches only `bufs.scratch`;
      the compiler now enforces it.
- [ ] `new_in_place`'s `write_bytes` (`dispatch.rs:209-210`) is
      `size_of`-derived and adapts unchanged. Both constructors
      (`boot.rs:296`, `host.rs:384`) need no change — zero-initializing a
      `MigrationScratch` is correct.
- [ ] The device_shell call sites that pass `bufs` into authority-reachable
      paths are retyped consistently.
- [ ] **The payoff assertion:** `arm-none-eabi-nm -S` on the release ELF
      shows `PIN_AUTHORITY` at ~16.4 KB (from 98,404 B). Recorded in
      `size-report.md`; the symbol-size delta is the test evidence.
- [ ] US-1201 suite green, byte-for-byte. `cargo test -p fapico2-platform`
      green.

**Acceptance:** `.bss` down ~81,960 B; US-1201 baselines unchanged; the
authority cannot reach an accumulator at the type level.

### US-1204: Red — one shared accumulator, and one classifier
**As a** firmware maintainer **I want** `run()` to fill a single accumulator
**so that** four 16 KiB buffers leave `MIG_BUFS`.
- [ ] Scenarios (Gherkin, one test each):

```gherkin
  Feature: Single shared migration accumulator
    Scenario: Every class slot is byte-identical to the baseline
      Given a C partition holding records in all five classes
      When migration runs
      Then each of the five slots matches US-1201's recorded baseline bytes
      And the per-class record counts are unchanged

    Scenario: Each record is read from flash exactly once
      Given the fixture partition
      When migration runs
      Then the number of C-partition record reads is unchanged by the restructure

    Scenario: The two classifiers cannot disagree
      Given the preflight slot-budget classifier
      When it is compared against the fill loop's classifier for every fid
      Then they assign the same class for every fid
```

- [ ] The second scenario guards the actual risk: the restructure iterates
      `recs` once per class, so it must be shown that filtering does not
      cause a record to be read twice or skipped.
- [ ] The third scenario is the latent-bug guard. The classifier currently
      exists **twice** — preflight (`migration.rs:999-1013`) and fill loop
      (`1085-1138`) — and `is_openpgp_capture_fid` (`:927`) overlaps the
      `0xCE00..=0xD0FF` FIDO range, so correctness rests on match-arm order
      with **nothing** asserting the copies agree. If the preflight and the
      loop ever classified one fid differently, the 16-slot budget check
      would silently admit a class the loop never writes.
- [ ] **Red** — tests land against the five-accumulator shape.

### US-1205: Green — `run()` fills one accumulator; `class_of` is the only classifier
**As a** firmware maintainer **I want** a single accumulator and a single
classifier **so that** `MIG_BUFS` drops from 98,324 B to ~32,770 B and the
duplicated classifier cannot drift.
- [ ] Extract `fn class_of(fid: u16) -> Option<Class>` encoding the exact
      current arm order — `0xCC00` keydev, `0x1122` management conf,
      `is_openpgp_capture_fid` **before** the specific ranges, `0xBA00..=0xBAFF`
      OATH, `0xBB00..=0xBB03 | 0x10A0` OTP, the PIV set, the FIDO set. The
      predicate-before-ranges order is load-bearing and is called out in the
      doc comment.
- [ ] `run()` loops over the five classes; each pass clears `acc`, filters
      `recs`, and writes that class's slot. The `bufs.openpgp` post-loop block
      (`:1145-1181`, which writes, read-back-verifies, computes the capture
      MAC and seeds the retry budgets) moves inside the OpenPGP pass unchanged
      (that block is `:1145`–`:1182` today).
- [ ] `scratch` and `acc` stay **separate**. `read_whitelisted` into `scratch`
      followed by `push_tlv` into `acc` is sequential, so sharing one buffer
      would need front-reserve; the fragility is not worth 16 KiB.
- [ ] `SlotOverflow` semantics are unchanged: the cap is still the same
      16 KiB secure-store limit, applied per class.
- [ ] US-1204 green; US-1201 baselines unchanged byte-for-byte.

**Acceptance:** `.bss` down a further ~65,554 B; all five slot baselines
identical to US-1201.

### US-1206: Embassy task arena 32,768 → 24,576
**As a** firmware maintainer **I want** the arena sized to measured demand
plus real headroom **so that** 8,192 B of `.bss` returns to the stack zone.
- [ ] `firmware/Cargo.toml:92`: `task-arena-size-32768` →
      `task-arena-size-24576` (the feature exists in embassy-executor 0.7).
- [ ] Measured demand is 17,760 B, so this keeps +38% headroom (down from
      +85%). The arena's six tasks are `ccid_task` 8,600 · `hid_task` 8,144 ·
      `usb_task` 736 · `embassy_main` 168 · `led_heartbeat` 56 ·
      `button_poll` 56.
- [ ] Re-measure with `measure_task_arena.py` and re-stamp
      (`arena_stamp.py`). **The stamp is the safety net**: a future task that
      does not fit turns the gate red rather than corrupting a task future.
- [ ] Recorded in `size-report.md` with the new demand number, not carried
      forward from the previous entry.

**Acceptance:** arena 24,576 B; stamp re-verified against post-change
sources; device boots.

---

## Phase C — p384/p521 as a build-time choice (~174 KB)

### US-1207: Red — the two-configuration matrix
**As a** release owner **I want** advertisement, service and refusal checked
in **both** curve configurations **so that** turning the curves off cannot
produce a card that lies.
- [ ] Scenarios (Gherkin, one test each), run against both configurations:

```gherkin
  Feature: OpenPGP NIST curve build configuration
    Scenario: The full build advertises P-384r1 and P-521r1
      Given a build with both curve features on
      Then GET DATA of the algorithm attributes names P_384 and P_521
      And the served table reports both curves served

    Scenario: The min build does not advertise them
      Given a build with both curve features off
      Then GET DATA of the algorithm attributes does not name P_384 or P_521
      And the served table reports them unserved

    Scenario: An unserved curve attribute is refused, not mis-parsed
      Given a min build
      When PUT DATA presents a P-384r1 algorithm attribute
      Then the status word is 6A80
      And the same holds for P-521r1

    Scenario: The default build is the full one
      Given the default feature set
      Then both curves are advertised
```

- [ ] The refusal scenario is the one that must not be traded away. It is
      the reason fact 8 splits marker from arithmetic: without the
      `trussed-core` marker the gate cannot even **name** the attribute, and
      a card that cannot name what it refuses is a card whose behaviour on a
      hostile input is undefined.
- [ ] Extend `check_advertise_serve_coupling.py` to run this suite in both
      configurations and cross-check. See the design note below.
- [ ] **Red** — the features do not exist yet.

**Design note, stated rather than hidden.** `advertise_serve.rs` currently
insists that `serves_*` is *"a real read of `BACKENDS`, not a restatement of
the `cfg`"* — a position earned from a real defect (a `not(...)` arm
hardcoding `false` made the test measure its own assumption). P-384 and
P-521 have **no `Backend::` variant** — they are served inside trussed, not by
a swappable backend — so there is no `BACKENDS` entry to read and a `cfg!` is
the only handle available. The discrimination therefore cannot live in the
test; it must live in the **gate**, which runs the same suite under both
feature sets and requires both to pass. The comment in `advertise_serve.rs`
is updated to say this, rather than leaving a documented philosophy silently
broken in one branch of the table.

### US-1208: Green — the platform stops pulling the arithmetic
**As a** firmware maintainer **I want** `p384`/`p521` off `trussed` **so that**
~174 KB of curve arithmetic leaves the image.
- [ ] `platform/Cargo.toml`: remove `"p384"`, `"p521"` from the unconditional
      `trussed` feature list; add `p384 = ["trussed/p384"]`,
      `p521 = ["trussed/p521"]`.
- [ ] **`trussed-core`'s marker features stay on** (via opcard's direct
      `trussed-core` dependency). This is the whole point of fact 8.
- [ ] US-1207's refusal scenarios green with the arithmetic gone — that is
      the proof the marker was kept for a reason.

### US-1209: Green — advertisement switches in vendored opcard
**As a** firmware maintainer **I want** the card to stop naming curves it
does not serve **so that** the advertisement follows the build.
- [ ] `vendor/opcard/Cargo.toml`: add `p384-advertise = []`,
      `p521-advertise = []`, leaving `trussed-core`'s `p384`/`p521`
      unconditional. Advertise-only, mirroring the `brainpool-backend` split.
- [ ] `vendor/opcard/src/card.rs`: `#[cfg(feature = "p384-advertise")]` on
      `Self::P_384` and `#[cfg(feature = "p521-advertise")]` on `Self::P_521`
      in **both** `default_gen` (`:419`) and `default_import` (`:450`). An
      import of an unserved algorithm is the same lie as advertising it
      (US-962).
- [ ] Follow the repo's vendor-patch convention: the comments above each
      change name the story, in the style US-962/945/966 used.
- [ ] `default_gen`'s doc comment is extended with the build-configuration
      rationale, alongside the US-966 Brainpool paragraph.

### US-1210: Green — wiring, defaults, and the build guard
**As a** release owner **I want** the switch in one place with a safe default
**so that** existing builds are unchanged and invalid combinations cannot ship.
- [ ] `apps/openpgp/Cargo.toml`: `p384-backend = ["fapico2-platform/p384",
      "opcard?/p384-advertise"]`, same for p521. **One switch drives both
      sides** — serving and advertising — per US-962.
- [ ] `firmware/Cargo.toml`: the curve features go in the crate's `default`,
      **not** in `device`. The required backends (RSA, secp256k1, Brainpool)
      stay in `device` because removing them breaks the card; these are
      removable extras. Disabling is therefore
      `--no-default-features --features device`, which reads unambiguously on
      a release command line.
- [ ] `platform/build.rs`: `FAPICO2_OPENPGP_CURVES` (`full` = default |
      `min`), validated against the resolved feature set, `panic!`ing on any
      value that is neither, and hard-failing when the environment asks for a
      combination the features cannot deliver — the same shape as
      `FAPICO2_FOREIGN_IMAGE_WIPE` (firmware/build.rs:119), and for the same
      reason: an explicit, auditable build-time decision rather than a
      default that can drift.
- [ ] **This env parameter cannot do the gating, and the epic says so in
      code.** `build.rs` emits `rustc-cfg`, which substitutes a value into
      code already selected for compilation; it cannot remove a dependency
      feature. Cargo resolves features before build scripts run. The env
      parameter's job is to **refuse to ship an inconsistent build**, not to
      select the curves. Writing it as a `cfg` gate would flip the
      advertisement and leave all 174 KB in the image — fact 9, exactly.
- [ ] Default-configuration scenario green; US-1207 matrix green in both.

### US-1211: Black-box — the card is correct in both configurations
**As a** credential owner **I want** the OpenPGP card to behave correctly in
either configuration **so that** a `min` build is a supported product, not a
stripped experiment.
- [ ] Against the emulation binary, in both configurations: `gpg --card-status`
      lists exactly the algorithms that build serves; `gpg --card-edit` for a
      P-384r1 key is refused on a `min` build and accepted on a `full` build;
      a P-256 key round-trips (sign + verify) in both.
- [ ] **Absent-symbol assertion:** `arm-none-eabi-nm` on the `min` ELF returns
      zero `fiat_p384_*` and zero `fiat_p521_*` symbols. This is the test.
      "The image is 174 KB smaller" is a `size-report.md` line, not a pass
      condition (fact 9).
- [ ] `check_advertise_serve_coupling.py` green having run the suite twice.

---

## Phase D — Flash housekeeping (4 stories)

### US-1212: `embassy-usb` without the unused `usbd-hid` default
**As a** firmware maintainer **I want** no dead USB crate in the tree **so
that** flash goes to code that is actually reached.
- [ ] `platform/Cargo.toml:172`: add `default-features = false`. The default
      `usbd-hid` feature is never used — the project hand-rolls the report
      descriptor in `HidInterfacesHandler::control_in_ctap` and never touches
      `embassy_usb::hid::HIDBuilder` — but it drags in `usbd-hid`,
      `usb-device`, `usbd-hid-macros`, `usbd-hid-descriptors` and
      `ssmarshal`.
- [ ] `check_supply_chain.py` and `supply-chain/exemption-reasons.toml` are
      updated: those crates leave the in-device closure and their entries must
      say so rather than continue to claim coverage.
- [ ] Absent-symbol assertion: no `ssmarshal` / `usbd_hid` symbols in the ELF.

### US-1213: One `sha2`, not three
**As a** firmware maintainer **I want** a single SHA-2 implementation **so
that** ~10 KB of duplicate compression leaves the image.
- [ ] Three generations link today: 0.9 (via `p256 0.13`), 0.10 (the house
      stack), 0.11 (via `bp256`) — three separate `compress256` bodies.
- [ ] Path: move `p256` to the `0.13`-generation line that uses `sha2 0.10`
      (or pin `bp256` to the `sha2 0.10` generation). Whichever is taken is
      recorded with the reason.
- [ ] `p256-cortex-m4` is patched to a git tag upstream
      (`vendor/opcard/Cargo.toml`), so the `p256` upgrade path is checked
      against that patch before it is attempted.
- [ ] Absent-symbol assertion: exactly one SHA-256 compression symbol remains.

### US-1214: The rolled SHA-512 actually replaces the stock one
**As a** firmware maintainer **I want** one SHA-512 **so that** the ~8.4 KB of
duplicated compression leaves the image.
- [ ] `platform/src/sha512.rs` rolled the stock compression from 10,544 B to
      1,188 B, but the stock `sha2::sha512::compress512` is **still linked** —
      something still routes through `sha2::Sha512` or `salty`'s own. The
      stated 8.9× saving was never realized.
- [ ] Find the remaining caller and route it through the rolled
      `digest`-trait implementation.
- [ ] This story exists because it is the second half of fact 9: the work was
      done and the win was not collected. The story's acceptance is the
      absent symbol, not the function's size.

### US-1215: Build configuration hygiene (no size impact)
**As a** firmware maintainer **I want** the build configuration to describe
the build that actually runs **so that** a maintainer is not misled.
- [ ] `rust-toolchain.toml:3` pins `thumbv6m-none-eabi`, the **dropped
      RP2040 target**, while every build path uses `thumbv8m.main-none-eabi`.
      CI papers over it by running `rustup target add` explicitly. Fix the
      pin; note that this target is no longer distributed.
- [ ] `firmware/.cargo/config.toml` carries an inert `[profile.release]` —
      profiles in `.cargo/config.toml` are an unstable feature and are ignored
      on stable cargo — duplicating the authoritative workspace-root profile,
      and it omits the `-Tlink.x` the root config passes. Delete it, or make
      the asymmetry deliberate and documented.
- [ ] Recorded as zero-byte, because a corrected config that changes nothing
      should say nothing about size.

---

## Phase E — Records (1 story)

### US-1216: Size report, gates, and release notes
**As a** maintainer **I want** the measurements and the user-facing contract
recorded **so that** the next change is made against facts.
- [ ] `docs/size-report.md`: one measured entry per phase, each stating what
      moved, the command run verbatim, and the resulting `text` / `.bss` /
      stack zone / task-arena numbers. Phase B's entry carries the
      `PIN_AUTHORITY` and `MIG_BUFS` symbol sizes as the evidence, per fact 9.
- [ ] Gate re-runs, all recorded: `check_size_report.py`,
      `check_boot_chain.py`, `check_async_frame.py`,
      `measure_task_arena.py` (re-stamped), `check_heap_gate.py`,
      `check_advertise_serve_coupling.py` (both configurations),
      `check_us413_feasibility.py`, `check_supply_chain.py`.
- [ ] `docs/known-gate-divergences.md` SF-1 updated with the new `bss`
      figure, and `docs/capacity.md`'s algorithm set reconciled with the
      `min` build.
- [ ] Release notes: state that a `min`-curve build exists, that it stops
      advertising P-384r1/P-521r1, and that the default build is unchanged.
      An operator must not have to read this epic to know which build they
      have.

---

## Dependency graph

```
US-1201 (baseline, GREEN not red)
   └→ US-1202 (red: MigrationScratch) → US-1203 (green: authority retyped)
   └→ US-1204 (red: one accumulator)  → US-1205 (green: run() + class_of)
   US-1206 (arena)   [independent; re-stamps after 1203+1205 land]

US-1207 (red: two-configuration matrix)
   └→ US-1208 (green: platform features) → US-1209 (green: opcard advertise)
                                            └→ US-1210 (green: wiring + guard)
                                               └→ US-1211 (black-box)

US-1212 → US-1213 → US-1214   [sequential: each re-measures the same image]
US-1215   [independent, no size impact]

US-1216 (records)  [after everything; needs a final build]
```

US-1202 and US-1204 can proceed in parallel; US-1206 must land **after** both
Phase B greens so the arena stamp is taken against the final static map. The
Phase D stories are sequential because each re-measures the same image and a
parallel build would race `target/`. US-1211 needs an emulation build, so it
is the longest pole in Phase C.

## Definition of Done (epic level)

- [ ] `.bss` reduced by ≥140 KB against the 13,700 B starting headroom;
      `RAM_CEILING` (434,176 B) passes with the margin stated.
- [ ] `arm-none-eabi-nm` shows **no** `fiat_p384_*`, `fiat_p521_*`,
      `ssmarshal`/`usbd_hid`, duplicate SHA-256 compression, or stock
      `sha2::sha512::compress512` symbols in the `min` build — each asserted
      as an absent symbol, not as a byte delta.
- [ ] Every US-1201 baseline byte-for-byte unchanged after Phase B; the
      migration suites green.
- [ ] A P-384r1/P-521r1 attribute is refused with `6A80` on a `min` build,
      not mis-parsed.
- [ ] Default build unchanged in behaviour; a `min` build documented in the
      release notes.
- [ ] All gates listed in US-1216 green, in both Phase C configurations.
