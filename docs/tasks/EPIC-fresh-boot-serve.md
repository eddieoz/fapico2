# EPIC: The fresh boot — a factory-new board enumerates while warming (US-1913…US-1930)

**Epic ID:** `FRESH-BOOT-SERVE`
**Status:** Phase 0 (the RS-Key-shaped fix, US-1927…US-1930) is the **active
implementation** — owner decisions 2026-11-20 in the Decision Log (O-28).
**Phase 0 is implemented** (2026-11-20, branch `fix/darkboot-1119`:
US-1927 → US-1928 → US-1929 → US-1930, plus KEPT US-1922 and US-1924's
guard/move; each story its own commit, `--no-gpg-sign`).

**2026-11-20 correction (O-30): the retail incidents were never a TRNG
stall.** The third field video + the owner's fresh-board A/B reproduction
decoded into a deterministic refusal — `derive_drbg_seed`'s migration-era
`NeverBootC` guard fired on every factory-zero OTP row, pre-USB, forever —
and Phase 0's residual ("waits forever, visibly") is what made it a silent
blink instead of a legible park. Three correction stories are **landed**:
**US-1931** (the zero row seeds; the pinning test inverted), **US-1932**
(permanent seed-state refusals park legibly on both arms; freshness still
never parks; halt sites 21 → 23), **US-1933** (the tuned construction config
actually reaches the registers; CONFIG-PIN in `check_rng_path.py`). Full
record: [`docs/audits/2026-11-20-retail-virgin-otp-row-brick.md`](../audits/2026-11-20-retail-virgin-otp-row-brick.md);
ADR 0004 amendment 7 re-draws the park domain three-way. The one open item
remains **US-1926's owner-run decode** — now meaningful, because US-1933
made the shipped tuning real at construction (O-28 decision 3). The
pending-identity architecture (US-1915…US-1919) is **STILL SUSPENDED pending
US-1926's measurement**: the retail incidents it was motivated by are now
explained and fixed; a genuine TRNG stall on some units remains possible and
is the measurement's subject.
**Tree:** `fapico2/`
**Story point convention:** 1 point = ≤1 day, independently verifiable, TDD
where a test can run on the host; Gherkin scenarios are written first and
become the names of the Rust tests that satisfy them.
**Source of this epic:** the 2026-11-19 retail incident — two v0.7.0 boards
bought at Robocore blinked fast ~60 s, parked, and never enumerated;
diagnosed frame-by-frame and code-pinned in
[`docs/audits/2026-11-19-retail-first-boot-dark-park.md`](../audits/2026-11-19-retail-first-boot-dark-park.md).
**Owner direction (inherited, standing):** the TRNG remains the **sole
entropy source**; freshness failures degrade, identity failures park
(ADR 0004). This epic removes the **last** freshness park from the boot
path — the one the fresh-install legacy bring-up still owns — without
moving anything out of the identity-park domain.

---

## Epic goal

**A factory-fresh board enumerates and serves its deterministic surface the
moment it is plugged in — whatever the shelf dwell — and only its first
creation operation waits for randomness.**

Today a board that has never completed a boot (every retail unit) takes
`boot_needs_legacy_bringup == true` and runs the **pre-epic blocking
bring-up before USB**: the record draw (`ensure_boot_entropy_blocking`, 60 s
blink, park `0011`), then the DRBG seed (`seed_drbg_blocking`, another 60 s
blink, park `0100`), and only then applet construction and `RUNG_USB`. A
TRNG stalled by a long-dwell cold episode — and warehouse + shelf storage is
the longest dwell a board ever experiences — consumes the budget(s), parks
legibly, and the customer sees a dark device that never appears on `lsusb`.
WARM-BOOT-SERVE fixed exactly this for provisioned boards and
**deliberately kept it for fresh installs** (`boot.rs:1110-1124`); its own
hardware validation (US-1831/1832) never covered a fresh install on a
stalled TRNG. The two Robocore units are that missing film.

The fix finishes what WARM-BOOT-SERVE's US-1822 originally planned: the
fresh-install construction draws move **into the bring-up task**, behind the
same Warming gate the provisioned path already has. Construction stops
drawing; `boot_needs_legacy_bringup`, both `*_blocking` sites, and the
legacy branches die; a fresh board takes the provisioned posture —
enumerate in ~7 s, refuse creation-class operations with the one honest
warming answer until Ready.

## Constraints

- **The TRNG is the only entropy source** (owner direction, standing since
  2026-11-10). No second source; counters are bookkeeping only.
- **No DRBG output before the TRNG-nonce seed.** The cell's
  seed-once-then-serve discipline (US-1824) is untouched; the task's
  sequence keeps the seed before every cell draw.
- **US-918's invariant is preserved, three-state:** the entropy record
  still precedes every bound derivation — a record-**absent** board's task
  draws the record first, exactly as `ensure_boot_entropy_blocking` did;
  a record-slot-**unreadable** board never redraws (the US-918 refusal,
  now expressible in the pure core — D-6) and stays Warming while serving
  deterministic operations.
- **Identity failures park as before.** `read_otp_key_1` / `read_chipid` /
  store mount / manifest keep their budget, silence and immediate park
  (ADR 0004's domain untouched). `init_drbg_cell` stays in the boot path
  with its identity reads; the 2026-11-10 ordering constraint
  (init-before-seed, the UB the 19:09 video caught) is preserved by
  construction. **Corrupt stored identity stays fatal at the construction
  site** (`device_app.rs:575-579`'s fail-closed policy) — only `NotFound`
  defers to the task (D-7).
- **One rhythm, one meaning.** Phase 0 adds **two** collision-tested LED
  shapes (US-1928), both progress bursts layered on the warming blink, and
  neither fires on a healthy boot: the record-draw site's bursts pulse
  **120 ms lit**, the seed site's **300 ms lit** (both 450 ms period —
  unique on-times and period against the whole GPIO25 table), `K` pulses =
  5-s-units waited at that site, capped at 9. A continuous warming blink
  that never changes tells a video decoder nothing — the owner's 2026-11-20
  direction (O-28) is that the retry state must be *identifiable from
  video*, the instrument every account of this failure has been read from.
  The 400 ms draw notice **stays in Phase 0** (D-3's deletion is scoped to
  the suspended architecture stories — the notice is the record site's
  start marker).
- **Freshness never parks (Phase 0's core decision, O-28).** The two
  legacy blocking sites lose their `fatal_boot` — a budget expiry re-arms
  the retry loop forever. `TrngRefused`/`DrbgRefused` remain reachable only
  through the TIMER0-clock-liveness parks (`main.rs:527`, `:682`) — the
  clock dead is an infrastructure failure, not freshness, and keeps its
  signature. Halt sites 23 → **21**.
- **The twin trap is scoped:** the **pending-state refusals land in both
  twins** (`device_core.rs` **and** `app.rs`) — the pending state exists on
  both. The **pool-emptiness gates do not**: they are deliberately
  device-path-only, recorded in-source (`device_core.rs:1256-1260`,
  `:2522-2525` — "not a missed twin"); do not re-twin them.
- **Refusal classes do not move** (US-1823's table stands). This epic
  re-homes draws. The refusals this epic **adds** — the hkey/keystore/
  attestation-dependent reads on a pending board, and **reset on both
  arms** (D-5's extension, Skeptic objection 2: `handle_reset` draws today
  with no warming gate) — all answer the **existing** warming reason. One
  reason, one code path.
- **The task's identity draws ride the fallible seam** (D-8):
  `SecretKey::random` over `TrngAdapter`'s infallible `fill_bytes` on an
  unseeded cell leaves the buffer untouched and loops forever — a hung
  executor is a new dark park. The task uses
  `TrngAdapter::try_fill_bytes`/the US-1007 fallible keygen shapes, and a
  rig test proves a refused draw cannot hang.
- **No SWD, ever**; hardware readings are video-decoded; device lanes are
  consent-gated (EPIC `HW-LANE-CONSENT`, US-1900/1901). The hardware
  stories here carry `hw_guard.require` — and US-1924's vehicle gains it
  too (Constraint Guardian objection 3: `scripts/` is invisible to
  `check_hw_isolation.py`'s sweep today).
- Story IDs use US-1913+ (US-1912, `HW-LANE-CONSENT`, is the highest
  existing). Commits carry no AI trailers; author
  `eddieoz <eddieoz@pm.me>` only.

## Facts the epic rests on (measured or code-pinned)

1. **The 2026-11-19 incident** (the audit): two Robocore v0.7.0 units,
   fast blink ~60 s → stop → never enumerated ("não chega ao passo do
   fa20"); video decode shows blink, no 1 Hz heartbeat in 73.8 s; the
   `0100` in the filename names `seed_drbg_blocking`'s park.
2. **The discriminator** (`firmware/src/boot.rs:1202`):
   `!(boot_entropy_record_present(store) && hkey_present(store))` — a
   fresh install routes to the legacy inline sequence
   (`firmware/src/main.rs:786-789, 832-834`). No host test pins it, and it
   **cannot be host-tested as it stands**: `mod boot` is bin-only
   (`main.rs:158`, required-features `device`) and the store type is
   device-gated — US-1914 must genericize it into a lib module to
   characterize it (Constraint Guardian objection 4).
3. **The fresh-arm construction draws** (`apps/fido/src/device_app.rs:557-630`,
   `boot_in_place`): `DeviceKeystore::fresh` (stateless-U2F
   `device_random`; fallible seam, `device_keystore.rs:1577`),
   `attestation::provision` (fresh TRNG key + cert; **infallible** adapter
   today), the hkey `SecretKey::random` + persist (**infallible** adapter),
   and the pool fill. All are **cell** draws, not raw-TRNG draws
   (main.rs:802-809: both app boots are served from the cell) — after the
   task seeds the cell they can run in the task, but **only through the
   fallible seam** (D-8): an unseeded cell's infallible draw silently
   leaves the buffer untouched (`trng.rs:2094-2105`) and
   `NonZeroScalar::random` loops on the zero keystream.
4. **`ensure_fw_manifest` draws nothing** (`boot.rs:2137-2176`): image
   hash + store read/stamp, deterministic. The manifest's identity posture
   is untouched by this epic.
5. **Reset draws randomness today with no warming gate** (Skeptic
   objection 2, verified): `device_core.rs:2905` `handle_reset` draws the
   seed (`:2940`) and regenerates the hkey via `try_fill_valid_with` —
   `take_random` is `stretch_pool` (`:703`), which on an empty pool serves
   SHA-256-of-empty keystream bytes: **attacker-derivable constants**, and
   the hkey regen accepts and persists them. A reset during the warming
   window on a provisioned board rotates `device_random` and the
   key-agreement hkey to publicly computable values. This epic closes it
   (reset joins the warming refusal class on both arms and both entry
   paths — the CTAP2 opcode and `factory_reset`).
6. **Store writes are durable at call time** (`boot.rs:1500`: "the store
   boots factory-fresh even if the power is cut"). The install order is
   therefore a crash-surface, not a theory: **every** intermediate state
   (any subset of {record, hkey, keystore, attestation} persisted) must
   boot to a sane next state — which holds iff pending is **store-derivable
   per item** and construction never draws on any pending arm (D-6;
   Skeptic objection 1's brick window: hkey-persisted + keystore-absent
   under a hkey-only predicate parks fatally at `DeviceKeystore::fresh` →
   `Err(Entropy)` → `Reason::KeystoreFailed`, before USB, unrecoverable by
   VBUS).
7. **The provisioned path already works** (WARM-BOOT-SERVE hardware
   status): no boot-path draw, USB ~5-7 s, task warms in the background,
   creation-class refusals wired (US-1826), status TLV live (US-1827),
   warming blink live (US-1828). This epic makes the fresh arm take
   exactly that posture.
8. **The 2026-11-10 measurement**: a long-dwell cold episode refused four
   ~63 s windows across three bounded reboots; only VBUS removal clears
   the episode; the wait can exceed **4.4 minutes**. Budget sizing
   (60 s/step) is inherited; the stall's mechanism stays US-1835's
   question. The docs must own the honest ceiling (User Advocate
   objection 1).
9. **The bring-up task's shape** (`main.rs:1650`): loop { `try_seed_drbg_once`
   → refill pools → publish Ready }, retries forever, no park; it
   early-returns on the legacy path (`entropy_ready()`), which is the line
   this epic deletes.
10. **The quarantine refusals already exist for every creation class**
    (US-1826, device path) **except reset** (Fact 5) — a fresh board
    post-fix refuses the same set; the new work is gating the
    hkey/keystore/attestation **reads** that today cannot even be reached
    while the boot path still blocks, plus the reset closure.
11. **`install_nostr_providers`' re-install seam exists** (main.rs:1674) —
    the task already installs a provider into a constructed applet after
    seeding; the identity install follows the same shape.
12. **The emulator has no legacy branch and no bring-up task**
    (`emul_main.rs:692` — fresh boots draw from `HostTrng`): the pending
    arm and the rewired wipe arm have **zero emulator coverage**. A green
    emulator suite says nothing about this epic's device arm — the §3/§8
    asymmetry lesson; the hardware leg (US-1923) is the proof.
13. **`region_degradation.rs:361` pins 23 halt sites** (its own header
    records US-1825's 22 → 23 move; the two `*_blocking` parks are
    included). This epic: 23 − 2 = **21**, re-derived by the survey.
14. **`scripts/probe_warm_boot_validation.py` carries no `hw_guard.require`**,
    and `tests/scripts/check_hw_isolation.py:70-134` sweeps only
    `redteam/`, `tests/scripts/`, `tests/hardware/`, `tests/soak/` —
    `scripts/` is invisible to the CI gate (Constraint Guardian
    objection 3).
15. **The reference firmwares' boot sequences, decoded 2026-11-20** (audit
    §"The reference boot sequences, decoded"): pico-fido has no
    boot-blocking entropy acquisition at all (bounded mixer warm-up, no
    DRBG/record/park, keys derived or lazy-generated on first USB select);
    RS-Key had our exact stall — 30–105 s on every boot on one unit — and
    fixed it at the peripheral layer (`sample_count: 25 → 1000`, ~1.5 s
    boot, HW-verified). Neither has any "give up" outcome on the entropy
    path; **the park is uniquely ours**. And we ship the exact
    configuration RS-Key identified as the stall
    (`TrngConfig::default()` = `sample_cnt1: 25`, `trng.rs:276-286`) with
    `MAX_ENTROPY_WAIT_MS = 20` calibrated to it — the budget RS-Key's
    finding shows a health-test loop can blow through on a healthy
    peripheral.

## Stories

> **Phase 0 scope note (O-28, 2026-11-20).** The architecture stories
> US-1915…US-1919 are **suspended** pending US-1926's measurement: Phase 0
> (US-1927…US-1930) tunes the peripheral and removes the parks while
> keeping the current boot structure, and the measurement decides whether
> the architecture is still needed. US-1914's characterization stays valid
> under Phase 0 (the discriminator remains); US-1913's inventory red was
> the architecture's ("no draw in the fresh arm") — suspended with it.

### US-1913: Blocker survey — the pre-USB draw inventory, both arms
**[SUSPENDED — architecture-scoped; revisit with the US-1915…1919
re-scope.]**
**As a** developer **I want** every draw between power-on and `RUNG_USB`
inventoried and pinned **so that** no story below moves a draw the survey
did not name.

```gherkin
Feature: The pre-USB randomness inventory
  Scenario: The boot path draws nothing from the TRNG on either arm
    Given the tree's boot.rs and main.rs boot-path sources
    Then neither contains a raw-TRNG draw site after this epic
  Scenario: Construction draws only from the cell
    Given FidoApp::boot_in_place and FidoApp::new
    Then every draw routes through the DRBG cell handle
  Scenario: The other applets construct without randomness on a fresh board
    Given the OATH, Nostr, OpenPGP, PIV, mgmt, rescue and vendor_led
        constructors
    Then none draws from an unseeded cell (their pools start empty,
        refilled by the task)
```

- [ ] Source-pinned host test (`apps/fido/tests/consumer_map.rs` extension
      or a new `apps/fido/tests/boot_draw_inventory.rs`, the
      `bootphase.rs` include_str pinning shape — the runnable red): the
      `boot_in_place` fresh arm contains no draw site; boot.rs/main.rs
      contain no raw-TRNG draw outside the identity reads' error arms.
- [ ] The survey's verdicts written into this file's **Gate inventory**
      table, including the exact halt-site re-derivation (Fact 13: 23 − 2
      = 21) and the flash-ratchet expectation.

**Acceptance:** no story below lands without its gate named, and the
inventory test fails on `main` exactly where the fresh arm still draws.

### US-1914: Characterization — the discriminator pinned before it dies
**As a** future investigator **I want** `boot_needs_legacy_bringup`'s
current truth pinned **so that** the fix's delta is a measurement, not a
memory (audit prediction 4).

```gherkin
Feature: The fresh-install discriminator
  Scenario: An empty store routes to the legacy path
    Given a store with no entropy record and no hkey
    Then boot_needs_legacy_bringup is true
  Scenario: A provisioned store routes to the task path
    Given a store with a 64-byte entropy record and a 32-byte hkey
    Then boot_needs_legacy_bringup is false
  Scenario: Half-provisioned stores route to the legacy path
    Given a store with the record but no hkey, and one with the hkey but
        no record
    Then boot_needs_legacy_bringup is true for both (the repair-boot arms)
```

- [ ] **Named refactor (the story's real work):** genericize the
      discriminator over `&dyn SecureStore` and host it in a lib-side
      module so the predicate is host-runnable at all — today `mod boot`
      is bin-only and the store type is device-gated (Fact 2). The
      behaviour is unchanged; the test pins it.
- [ ] The characterization test (green-on-main by design — **not** a red;
      the runnable reds live in US-1913/US-1915/US-1916), marked in-code
      as what US-1919's source-pin absence test replaces.

**Acceptance:** the discriminator's behaviour is a pinned, host-runnable
fact before anything moves.

### US-1915: Red — the fresh-arm bring-up sequence is a pure core
**[SUSPENDED — pending the Phase 0 re-scope; the design below remains the
plan of record if the architecture is still needed after US-1926's
measurement.]**
**As a** the boot **I want** record → seed → identity → pools → Ready as an
explicit, host-tested sequence **so that** the fresh install's order and
its crash surfaces are decisions, not accidents.

```gherkin
Feature: The fresh-install bring-up sequence
  Scenario: The record is drawn before the seed
    Given a fresh board (nothing persisted) and a healthy TRNG
    Then the sequence draws the record, persists it, seeds the cell,
        and only then draws identity material
  Scenario: An unreadable record slot never redraws (D-6)
    Given a board whose record slot read errors (not NotFound)
    Then the sequence refuses the draw, stays Warming, serves
        deterministic operations, and the status says so
  Scenario: Identity material is drawn per missing item, from the cell,
    through the fallible seam
    Given the cell seeded and the store missing any subset of
        {hkey, keystore, attestation}
    Then the sequence draws and persists exactly the missing items,
        each through the fallible seam (D-8)
  Scenario: Every crash intermediate state boots pending, never parks
    Given each subset of {record, hkey, keystore, attestation} persisted
        (the durable-write fact, Fact 6)
    Then the next boot constructs pending from the store alone (D-6) and
        the task completes the missing items — no state parks
  Scenario: A wedged TRNG stays Warming forever and serves deterministic
    Given a TRNG that always refuses
    Then the sequence never parks, the state stays Warming, and the
        pollable status says so
  Scenario: A provisioned board skips the identity steps
    Given a board with record and all identity items present
    Then the sequence goes seed → pools → Ready with no identity draw
  Scenario: A repair boot redraws only what is absent
    Given a board with the identity items present but the record absent
    Then the sequence draws the record, seeds, and skips the identity
        steps
```

- [ ] `firmware/src/entropy_bringup.rs` extended (pure, mirroring the
      existing `State::step` shape): `record_slot ∈ {Present, Absent,
      Unreadable}` (three-state — D-6, Constraint Guardian objection 6),
      per-item identity presence (`hkey/keystore/attestation` booleans,
      not one bit), `Step::{Record, Seed, Identity, Pools}`,
      `next_step(...)`; no hardware types.
- [ ] The seven scenarios above as Rust test names, including the
      crash-subset matrix (Fact 6) — the test that kills the draft's
      brick window.
- [ ] **Install-order constraint pinned per item:** the store write
      precedes the applet flag clear for each item; because pending is
      store-derivable per item (D-6), **any** persistence order is safe —
      the test proves it rather than pinning one order.

**Acceptance:** the whole fresh-install policy — including its crash
surfaces — is assertable on the host.

### US-1916: Red — construction without randomness on every pending arm
**As a** the applet **I want** `boot_in_place` to construct without drawing
whenever any identity item is missing **so that** USB comes up on a stalled
TRNG and no half-installed state can park.

```gherkin
Feature: Pending-arm construction
  Scenario: A fresh partition constructs pending
    Given a store whose hkey read is NotFound
    Then the applet constructs with the pending flag set and no draw call
  Scenario: Any half-installed store constructs pending
    Given a store with any subset of the identity items present
    Then the applet constructs pending (store-derivable, D-6) and never
        draws — the DeviceKeystore::fresh-on-unseeded-cell fatal arm
        becomes unreachable
  Scenario: A corrupt identity stays fatal at the construction site (D-7)
    Given a store whose keystore snapshot or attestation identity read
        errors as Corrupt
    Then construction parks exactly as today (fail-closed, ADR 0004) —
        only NotFound defers
  Scenario: A pending applet refuses the hkey-dependent reads
    Given a pending applet
    Then clientPIN legs, the pinUvAuth mint/salts, froot() derivation and
        the vendor 0x41 identity reads answer the warming refusal before
        any state read — the gate inventory enumerates every
        hkey/keystore/attestation/froot use site
  Scenario: getAssertion on a pending board returns NO_CREDENTIALS before
    any derivation
    Given a pending applet and a getAssertion request
    Then the no-residents early return precedes any froot() use — a
        pending board cannot hold residents (makeCredential refuses while
        pending, so none can have been created)
  Scenario: A pending applet still serves its deterministic surface
    Given a pending applet
    Then getInfo answers and the management status TLV reads warming
  Scenario: The host twin refuses identically where the pending state
    exists
    Given the twin app.rs applet in the pending state
    Then every pending-gate refusal reason and opcode coverage matches
        the device twin (the pool gates stay device-only per the
        in-source record)
```

- [ ] Source-pin test: no draw call on any pending construction arm.
- [ ] Host twin tests (`apps/fido/tests/`) driving `process_ctap2` on a
      pending applet — refusal parity across twins for the pending gate.
- [ ] **D-1 (as revised):** the pending mechanism is a `fresh_pending`
      gate flag + per-item install seam, **not** an `hkey: enum` — with
      the Skeptic objection 4 mitigation: the flag drops the compiler
      backstop, so US-1916's gate inventory **enumerates** every
      `hkey`/`keystore`/`attestation`/`froot()` use site
      (`device_core.rs:1489, 1533, 2187`; `app.rs:1669, 1706, 2364`) and a
      host test pins each behind the gate. The dummy field values are
      named here (a fixed non-zero hkey placeholder that no gated site can
      read; the keystore/attestation placeholders likewise) — the enum
      alternative stays rejected (~30 match arms across two twins) but the
      audit burden it would have bought for free is paid explicitly here.

**Acceptance:** the pending arms are red on `main` (draws exist), green
when US-1918/US-1919 land; no gated site can read a placeholder.

### US-1917: Green — the pending gate, the reset closure, and the refusals
**As a** a customer on day one **I want** honest refusals **so that**
"reads work, creation waits" holds for a fresh board too — and so that
nothing can rotate identity material to computable constants.

```gherkin
Feature: The pending-fresh refusal set
  Scenario: Creation-class operations refuse while warming or pending
    Given a board in the warming state (either arm)
    Then makeCredential, clientPIN mint/salts, hmac-secret credRandom
        creation, vendor backup LOAD, Nostr GENERATE/custody ceremony,
        OATH SET_CODE, OpenPGP keygen/GET CHALLENGE and PIV keygen all
        answer the existing warming refusal — no new refusal reason
  Scenario: Reset refuses while warming — the CTAP2 opcode (D-5)
    Given a board in the warming state (either arm)
    Then authenticatorReset answers the warming refusal before any draw —
        closing Fact 5's computable-hkey defect on both arms
  Scenario: Reset refuses while warming — the management path
    Given a board in the warming state
    Then the management RESET / factory_reset path answers the same
        refusal — a durable wipe must not race the task's install
        (Skeptic objection 3's orphan window)
  Scenario: The hkey-dependent reads refuse while pending
    Given a pending board
    Then the pinUvAuth verification path and the vendor 0x41 mint answer
        the warming refusal (they cannot run without the hkey)
  Scenario: The advertisement does not lie (D-2)
    Given a warming or pending board
    Then getInfo's makeCredUvNotRqd/U2F_V2/alwaysUv rows keep deriving
        from pin_state exactly as §4 of AGENTS.md pins them — the
        controlling precedent is US-1826's shipped gate
        (`device_core.rs:1247-1263`, `:2506-2530`): the refusal is
        retryable (0x7F), pollable (US-1827), self-resolving, and the
        advertisement describes the PIN state, not entropy readiness
```

- [ ] The `fresh_pending` flag + `warming_gate()` predicate on the applet,
      **both twins** for the pending gate; every site US-1916's inventory
      names.
- [ ] The reset closure on **both entry paths** (CTAP2 opcode,
      `factory_reset`), **both arms** — the one genuinely new wire
      behaviour this epic adds.
- [ ] Host tests per refusal, twins in parity for the pending set; the
      emulator suites' reset-during-fresh flows inventoried (they go red
      and are updated — Skeptic objection 8).
- [ ] **Decisions recorded in-story:** D-2 (advertisement unchanged, with
      the §4 lineage and the bounded-window caveat), D-5 (reset refuses
      while warming on both arms and both entry paths; the recovery path
      is unplug/replug, which the docs own).

**Acceptance:** no creation operation serves zeros or computable constants
on any warming/pending board; every refusal names warming; the twins are
identical in refusal reason wherever the pending state exists.

### US-1918: Green — the task performs the fresh sequence
**As a** the bring-up task **I want** to draw, persist and install the
fresh identity in the background **so that** the boot path never blocks on
it and no task-side draw can hang the executor.

```gherkin
Feature: The task's fresh-install steps
  Scenario: The task runs the pure core's sequence
    Given the boot reached serving with the cell unseeded
    Then the task executes Record → Seed → Identity → Pools → Ready per
        US-1915's state machine, retrying each step forever
  Scenario: The record draw keeps its budget semantics and refuses to
    redraw an unreadable slot
    Given a record-absent board
    Then the task's record draw rides the bounded probe (US-1802
        semantics) with the wait-blink cadence owned by the task, no
        park, no reboot; an Unreadable slot answer never redraws (US-918)
  Scenario: The identity draws ride the fallible seam (D-8)
    Given the cell seeded and identity items missing
    Then every task-side identity draw goes through
        TrngAdapter::try_fill_bytes / the US-1007 fallible keygen — and a
        rig test proves a refused draw returns an error rather than
        hanging the executor
  Scenario: Corrupt identity parks from the task, legibly (D-7)
    Given a task-side identity step answering Corrupt/unreadable
    Then the task classifies it and parks with a named signature
        (counted in US-1920's halt-site delta) — only NotFound retries
  Scenario: The identity install persists before it publishes
    Given identity items drawn
    Then each is written to the store before the applet is updated, and
        the pending flag is cleared last — per item, so every crash
        intermediate is store-derivable (D-6)
  Scenario: Ready publishes only after the pools
    Given all steps complete
    Then the pools refill before publish_entropy_ready, as US-1825
        established for the provisioned arm
```

- [ ] `entropy_bringup_task` extended in `main.rs`: the record-draw body
      (the old `ensure_boot_entropy_blocking` inner loop, three-state),
      the per-item identity install (`install_fresh_identity`), the pool
      refill; the `entropy_ready()` early-return deleted.
- [ ] **The probe plumbing named:** the task's record draw needs a TRNG
      probe whose ownership today dies into `init_drbg_cell`
      (`main.rs:821` consumes `seed_probe`; `spare_probe()` is wipe-gated,
      `boot.rs:870-882`) — US-1918 defines the probe's new ownership
      (Skeptic objection 7).
- [ ] The task owns the TRNG draws under its own `check_rng_path.py`
      allowlist entries (US-1913's inventory names them).
- [ ] The 400 ms draw notice is **deleted**, not moved (D-3); the
      wait-blink pin test updates together (US-1920); the decode method's
      lost record-vs-seed discriminator is recorded in US-1921 (the status
      TLV replaces it).

**Acceptance:** pure-core sequence tests (US-1915) + platform
`LazyDrbg`/fallible-seam rig tests prove the sequence, its retry-forever
posture, and its hang-freedom; the task's **wiring** is
hardware-validated (US-1923), not host-simulated (Constraint Guardian
objection 8).

### US-1919: Green — the boot path stops blocking, the legacy path dies
**As a** the boot **I want** no freshness draw or park before `RUNG_USB` on
any store state **so that** the 2026-11-19 incident cannot recur.

```gherkin
Feature: No freshness park before USB
  Scenario: The legacy branches are gone
    Given main.rs
    Then no `boot_needs_legacy_bringup`, `ensure_boot_entropy_blocking` or
        `seed_drbg_blocking` call site remains, and boot.rs exports neither
  Scenario: The foreign-image wipe arm continues with a fresh store and
      the task's bring-up
    Given a foreign-image boot
    Then the wipe runs, the US-918 slot is cleared (redrawn by the task),
        the spare probe's ownership transfers per US-1918, and no inline
        seed happens
  Scenario: Identity parks survive
    Given an unreadable OTP row, store or manifest
    Then the boot parks exactly as today — plus D-7's task-side Corrupt
        park, with the halt-site count re-derived (21)
  Scenario: The 2026-11-19 script cannot recur
    Given a fresh board and a TRNG that refuses for the whole video
    Then the boot enumerates within its normal ~7 s, blinks warming, and
        never emits 0011/0100
```

- [ ] `main.rs:786-789` and `832-834` deleted; `init_drbg_cell` stays (the
      ordering constraint comment moves with it); the pool-fill arm at
      `main.rs:921/923` unifies on the empty-pool arm.
- [ ] The foreign-image wipe arm rewired (the idempotency comment at
      `boot.rs:1125-1131` documents the seam this deletes); the emulator
      asymmetry recorded — this arm has **no emulator coverage**
      (`emul_main.rs:692`), the hardware leg is its proof (Fact 12).
- [ ] US-1914's characterization test replaced by the source-pin absence
      test (the discriminator's death is the assertion).
- [ ] The `entropy_draw_notice` fn and its gate removed (D-3).

**Acceptance:** the inventory test (US-1913) goes green on both arms; the
absence pin names the deleted exports.

### US-1920: Gates — the ratchets learn the new shape
**[SUSPENDED — the architecture's gate deltas; Phase 0's own gate work
lives in US-1929/US-1930.]**
**As a** CI **I want** every gate updated with its recorded delta **so
that** the series passes everything the repo gates on.

- [ ] `check_rng_path.py`: allowlist rewritten — the task owns the record,
      seed, hkey, keystore and attestation draws; boot.rs/main.rs stay at
      zero; the rng-path CI job's coverage list extended.
- [ ] `apps/fido/tests/region_degradation.rs`: halt-site count **23 → 21**
      (Fact 13; re-derived by US-1913, plus D-7's task-side park if it is
      a `fatal_boot` site — the survey names it).
- [ ] `firmware/src/wait_blink.rs` tests: the `busy_wait_us(400_000)`
      draw-notice pin deleted with D-3.
- [ ] `bootphase.rs`: the `P_BOOT_ENTROPY`/`P_DRBG` marks and RUNG semantics
      updated (RUNG_DRBG stays "the cell exists"; the entropy rung loses
      its blocking meaning).
- [ ] `tests/scripts/check_boot_clock_order.py` and
      `check_foreign_image_wipe.py` re-run against the new signatures; the
      foreign-image wipe gate's cfg wording untouched.
- [ ] `tests/scripts/check_hw_isolation.py`: US-1924's vehicle enters the
      guarded inventory (see US-1924) — the sweep or the location changes,
      this gate re-derives.
- [ ] **Flash-budget ratchet** (`ci.yml` `FIRMWARE_FLASH_BUDGET_KIB: 1704`,
      the device job): the epic deletes ~2 blocking functions and adds a
      state machine + `install_fresh_identity` + task steps — net measured
      over the release ELF; `./scripts/pre_push_check.sh --full` is the
      merge gate (Constraint Guardian objection 2).
- [ ] `check_dbg_release_gate.py`: no impact expected (D-3 deletes a plain
      fn); re-run to prove it.
- [ ] `python3 tests/scripts/measure_task_arena.py` re-run **after
      US-1919** (the demand is only final when the moves are done) and the
      fresh stamp committed — the task future grows (Fact 6's install
      work). **Named fallback if demand crosses the budget:** split the
      install across task iterations (one item per poll) rather than
      enlarging the arena — recorded here so the choice is a decision.
      The US-939 frame discipline re-established for task-side calls
      (keystore scratch stays out of the executor frame; Skeptic
      objection 6).
- [ ] `cargo test -p fapico2-firmware --lib`,
      `cargo test -p fapico2-fido --target x86_64-unknown-linux-gnu`,
      clippy, `./build.sh` (uf2gen.py), `./run_tests.sh --suites-only` if
      the venv is available; `./scripts/pre_push_check.sh --full` before
      push.

**Acceptance:** CI-shaped green with every delta recorded in-gate.

### US-1921: Docs — ADR 0004 amendment 5 and the reading tables
**[SUSPENDED — superseded by US-1930 for Phase 0 (amendment 6 + the burst
rows); amendment 5's content applies only if the architecture resumes.]**
**As a** an operator with a fresh board **I want** the docs to name what I
am seeing **so that** the seventh account of this failure is not written
from scratch.

- [ ] ADR 0004 amendment 5: the park domain shrinks to identity **for every
      store state** — the fresh-install legacy carve-out is deleted with
      its citation (the 2026-11-19 audit); freshness failures degrade on
      day one too; D-7's task-side Corrupt park is the one new park, named.
- [ ] `docs/boot-freeze.md`: the "Fresh install: blink window, then one
      long-flash signature" row **stays in the live table, annotated
      "v0.7.0 field units only"** — field units still reach it until
      reflashed or pre-warmed (User Advocate objection 4); the first-boot
      row becomes "blink (minutes, ceiling below) → heartbeat; creation
      waits"; the 400 ms draw-notice row retires (D-3) with the note that
      the LED alone no longer discriminates record-window from seed-window
      refusals — the status TLV does (Skeptic objection 10).
- [ ] `book/troubleshooting/boot.md` (the canonical customer answer — the
      US-1833 convention, named here as the single place of truth) and
      `book/getting-started/index.md` updated by path, with the stale
      claims listed: "up to three bounded reboots" (deleted behaviour),
      blink "up to ~1 minute" (the honest number is **minutes — measured
      > 4.4 min on a long-dwell board**), the draw-notice section, the
      fresh-install park paragraph, and "do not unplug" **reconciled** with
      the power-cycle accelerator: reads work while warming; unplugging is
      safe on a fresh board and is the measured fix for a stalled episode.
- [ ] The ceiling row (User Advocate objection 1): "warming can take
      minutes; if it exceeds ~5 min, unplug, wait 5-10 s, replug — power
      removal clears the cold episode (measured), and on a fresh board it
      loses nothing (the store write precedes the flag clear)"; and the
      reset clause: "reset refuses while the board is blinking — that is
      expected; there is nothing on it yet."
- [ ] The client-display sentence (User Advocate objection 2): "your tool
      will show a generic failure during warming; the LED and the status
      tag are the only warming indications; retry after the blink settles."

**Acceptance:** no doc claims a fresh install can park on freshness (short
of D-7's Corrupt park and the v0.7.0 field-unit row); every reading keeps
exactly one meaning; the customer's first stop is named.

### US-1922: Docs/process — the QC pre-warm and the customer's interim answer
**[KEPT — the QC pre-warm and the pt-BR artifact are Phase 0-adjacent and
can land any time; they do not depend on the architecture.]**
**As a** the production pipeline **I want** retail units pre-warmed before
sale **so that** no customer unit ever reaches a first-boot stall.

- [x] ADR 0002 amendment: **QC pre-warm is provisioning policy** — every
      unit is powered once to a completed boot before sale (one completed
      boot persists record + identity and permanently converts the unit to
      the serve-while-warming path; zero firmware dependency; no host
      needed). **The completion instrument is the LED**: ladder → warming
      blink → 1 Hz settle = pass; a `0011`/`0100` signature = retry the
      power cycle (on v0.7.0's legacy path this parks legibly at QC — QC
      selects for boards that completed; Constraint Guardian objection
      11). The Robocore channel's existing stock gets the same one-time
      power-on.
- [x] The customer-facing interim row (pre-fix firmware), with the explicit
      old-vs-new discriminator: **a long-flash signature means v0.7.0
      firmware; blinking past ~2.5 minutes without a signature means fixed
      firmware** — and the reassurance (audit prediction 2): *after one
      successful boot this never happens again — it is a first-boot
      defect only.*
- [x] **The seller/customer artifact in the customer's own vocabulary**
      (User Advocate objection 6): a short pt-BR insert (book page or
      printed card) with no firmware terms — *"piscando rápido por até
      alguns minutos = funcionando; um sinal longo e depois escuro = tire
      da USB, espere 5 s, conecte de novo, repita — depois de uma
      inicialização completa isso nunca mais acontece."*

**Acceptance:** the policy, the instrument, and the artifact exist where
the next support conversation will find them — the book's troubleshooting
page for customers, ADR 0002 for the pipeline.

### US-1923: Hardware validation — the missing film, on the owner's board
**[SUPERSEDED by US-1926's owner-run measurement for Phase 0; the
architecture's ceremony decode (MC refuses-then-succeeds) re-forms here if
it resumes.]**
**As a** the owner **I want** a fresh install on a cold-stalled TRNG
observed on video **so that** the epic's claim is a measurement.

- [ ] **Consent-gated (HW-LANE-CONSENT):** flash the fix; wipe the store to
      the fresh state; leave the board unpowered long enough to reproduce
      the long-dwell episode; record from power-on.
- [ ] Decode and assert: enumeration within the normal ~7 s while the TRNG
      is still stalled (CCID status TLV reads warming); a makeCredential
      during the stall refuses with the warming answer and **succeeds
      after Ready**; the LED shows ladder → warming blink → 1 Hz; no
      `0011`/`0100` anywhere in the take; the warming window's real
      duration recorded against the docs' ~5 min ceiling.
- [ ] **Real-client display verified** (User Advocate objection 2):
      PicoForge provisioning during a stall (what it actually shows when
      creation refuses) and a logged-Chrome registration
      (`scripts/drive_logging_chrome.py` shape) — the wire honesty is
      US-1917's; this is the tool honesty.
- [ ] Record the decode table in the audit doc's validation section; the
      2026-11-19 audit's predictions 1-3 close against it.

**Acceptance:** the epic's goal sentence, on video — wire and tool.

### US-1924: Hardware validation — the customer's units
**[KEPT, with the US-1927 prerequisite — the probe's guard/isolation work
(Constraint Guardian objection 3) applies to any device leg.]**
**As a** the customer **I want** my two Robocore boards to work on day one
**so that** the product I bought is the product that works.

- [x] `scripts/probe_warm_boot_validation.py` gains the fresh-install flow
      (turnkey, timestamped, film-correlatable — the US-1832 probe shape)
      **and carries `hw_guard.require`** (destructive tier for any wipe
      leg) — and the flow moves into `tests/scripts/` (or
      `check_hw_isolation.py`'s sweep is extended to cover it), closing
      the gap in Fact 14 (Constraint Guardian objection 3).
- [ ] With the owner's consent, the fixed image on one of the customer's
      units (or the owner's stock) repeats US-1923's script; the outcome
      recorded in the audit doc.

**Acceptance:** the units that reproduced the incident pass the guarded
probe. *(Second box pending — owner-run device leg; the guarded
`--fresh-install` probe is ready and consent-gated.)*

### US-1925: Sequencing close-out
**[KEPT — runs at each phase boundary.]**
**As a** the epic owner **I want** the story map updated as gates resolve
**so that** the epic file stays the plan of record.

### US-1926: The measurement — the cold episode at the tuned configuration
**As a** the owner **I want** the cold-episode boot filmed at the tuned
configuration **so that** the warming window's new size is a measurement
and D-8's mechanism row closes.

**Owner-run device leg (O-28):** the agent implements, gates and builds;
the owner flashes and films. *(2026-11-20: the Phase 0 build is ready —
`firmware/fapico2.uf2` at the tuned configuration; the guarded probe is
`tests/scripts/probe_warm_boot_validation.py --fresh-install
--assert-touch --pin --max-wait 3600`, run before power-on.)*

- [ ] **The control is already banked:** the stock-config recordings — the
      2026-11-09 decode (≥ 20.4 s settle) and the 2026-11-10 four-window
      refusal (> 4.4 min) — are the baseline; no re-run needed.
- [ ] Flash the Phase 0 build (`sample_cnt1: 1000`); leave the board
      unpowered for the established long dwell; record from power-on.
- [ ] Decode: the entropy windows' duration at the tuned config; whether
      the health-test loop still fires (bursts identifying the site and
      elapsed time make this readable from video alone); a healthy
      boot's total time (RS-Key's comparable: ~1.5 s for 48 B).
- [ ] If the window collapsed: record the number in the audit doc and
      D-8's mechanism row ("health-test loop at `sample_cnt1: 25`;
      tuned → measured X s"); the architecture re-scope review follows
      (US-1915…1919 remain suspended until the owner decides).
- [ ] If it did not: the bursts decode which site waits and for how long
      — that table goes into the audit doc; the architecture re-scope
      keeps its full justification.

**Acceptance:** D-8's mechanism row says "measured" with the two numbers
(stock vs tuned), and the fresh-install UX at the tuned config is one
decoded boot — no park, no `0011`/`0100`, enumeration in the recorded
time.

---

## Phase 0 — the RS-Key-shaped fix (US-1927…US-1930, the active plan)

**Goal:** the board tunes the peripheral so a healthy draw succeeds on the
first generation (~1.5 s, RS-Key's measured shape), and **never parks on
freshness** — a budget expiry re-arms the retry forever, with a
collision-tested progress burst that tells a video decoder which site is
waiting and for how long. The boot structure (two paths, blocking
fresh-install bring-up) is **unchanged** in Phase 0; the measurement
(US-1926) decides whether the suspended architecture is ever needed.

### US-1927: Red — the TRNG configuration and its budget are one fact
**As a** the boot **I want** `sample_cnt1`, `MAX_ENTROPY_WAIT_MS` and
`MAX_ENTROPY_POLLS` pinned as a self-consistent triple **so that** the
tuning cannot ship with a budget calibrated to a configuration it no longer
runs (`trng.rs:256-267`'s void, closed by construction).

```gherkin
Feature: The TRNG configuration/budget triple
  Scenario: The shipped configuration is RS-Key's measured-good tuning
    Given TrngConfig::default
    Then sample_cnt1 is 1000 (RS-Key firmware/src/main.rs:601-609:
        "sample_count = 1000", the autocorrelation health check passes on
        the first generation) and rnd_src_sel is 1
  Scenario: The wall budget covers the measured generation time
    Given the shipped configuration
    Then MAX_ENTROPY_WAIT_MS is at least twice the measured per-block
        generation time (RS-Key: 48 B ≈ 1.5 s → 24 B ≈ 750 ms)
  Scenario: The poll cap stays above the wall budget
    Given liveness < MAX_ENTROPY_WAIT < MAX_ENTROPY_POLLS (trng.rs:905)
    Then MAX_ENTROPY_POLLS at the loop's 1-2 µs cost covers
        MAX_ENTROPY_WAIT — re-derived whenever either moves
  Scenario: The budget is only nominal for the shipped configuration
    Given a post-soft-reset peripheral (rnd_src_sel 0, sample_cnt1 0)
    Then is_budget_nominal is false — the restore discipline still has
        something to restore
  Scenario: The field can hold the tuning
    Given SAMPLE_CNT1 takes the tuned value
    Then the config field's type holds it (u8 → u32; the register write
        already cast to u32, trng.rs:1630)
```

- [x] `platform/src/trng.rs`: `sample_cnt1: u8` → `u32`
      (`:273`); `TrngConfig::default()` → `sample_cnt1: 1000`
      (`:283`); `capture` signature widened (`:294`); `is_budget_nominal`
      exact-match against a named `BUDGET_SAMPLE_CNT1: u32 = 1000`
      (`:310-314` — the 20–25 window is the fast config's window, and the
      budget no longer assumes it).
- [x] `MAX_ENTROPY_WAIT_MS` 20 → **2000** (`:225`, ≥ 2× the measured
      750 ms); `MAX_ENTROPY_POLLS` `1 << 19` → **`1 << 21`**
      (`:527`, re-derived: 1–2 µs/iter × 2.1 M ≈ 2.1–4.2 s > 2.0 s — the
      `liveness < WAIT < POLLS` ordering at `:905` restored); the
      `:508` doc formula updated.
- [x] New const `MEASURED_EHR_GEN_MS_AT_SHIPPED_CONFIG: u64 = 750` with the
      RS-Key citation, and the host test asserting
      `MAX_ENTROPY_WAIT_MS >= 2 * MEASURED_EHR_GEN_MS_AT_SHIPPED_CONFIG`
      — the red this story turns green (today: 20 ≥ 1500 fails).
- [x] The `drbg_seed.rs:271` relation re-checked
      (`MAX_ENTROPY_WAIT >= 2 * ENTROPY_CLOCK_TICKS_PER_MS`: 2,000,000 ≥
      2,000 ✓); the "20 ms — 10× the datasheet's ~2 ms" docs updated to
      the tuned reality with the RS-Key measurement as the citation.
- [x] `main.rs:536`/`:686` probe constructions pick the new default
      automatically; `emul_main.rs` unaffected (no device TRNG).
- [x] The health tests are **not** touched — no bypass bit, no weakened
      test; the tuning only decorrelates ROSC samples (RS-Key's finding:
      entropy quality unchanged).

**TDD:** red = the consistency test above fails against today's
(20 ms, 25-sample) constants; green = the triple green together.

**Acceptance:** a host test fails if anyone moves one member of the triple
without the others; the shipped config is RS-Key's measured-good one.

### US-1928: Red — the progress burst is a pure, collision-free instrument
**As a** an owner reading a video **I want** the retry state identifiable
from the pin alone **so that** the next account of this failure is decoded,
not guessed (O-28: "a continuous wait-blink tells nothing").

```gherkin
Feature: The progress burst
  Scenario: No burst on a healthy boot
    Given a draw succeeding without a failed attempt
    Then no sleep runs and no burst is emitted — the boot cost is
        unchanged
  Scenario: The burst starts after twenty failed-attempt steps
    Given 19 steps of waiting (the blink only runs between failed
        attempts)
    Then no burst is due
    Given 20 steps
    Then one burst of one pulse is due
  Scenario: The burst count grows with the wait and caps at nine
    Given 40 steps → 2 pulses; 180 steps → 9 pulses (capped)
    Then each pulse names one 5-second unit waited at this site
  Scenario: The burst shape identifies the waiting site
    Given the record-draw site waiting
    Then the burst pulses are 120 ms lit / 330 ms dark
    Given the DRBG-seed site waiting
    Then the burst pulses are 300 ms lit / 150 ms dark — same period,
        different on-time
  Scenario: The burst collides with no other pin driver
    Given the full GPIO25 driver table (ladder 25/55, heartbeat 500/500,
        draw notice 400, signature bits 200 lit, preamble 1200,
        wait-blink 80/170)
    Then neither burst's on-time (120, 300) nor their period (450)
        matches any row
  Scenario: The burst ends at the pin's resting level
    Given a burst of K pulses
    Then the sequence ends Off — stepping out leaves the pin dark
```

- [x] `firmware/src/wait_blink.rs` extended (pure, the US-1803 shape):
      `ProgressSite::{Record, Seed}`, `PROGRESS_BURST_EVERY_STEPS = 20`
      (5 s), `PROGRESS_BURST_MAX_PULSES = 9`,
      `progress_burst_pulses(steps) -> u64`, and
      `progress_burst_levels(site, steps) -> impl Iterator<Item = Level>`
      over `boot_ladder::Level`.
- [x] On-time constants: `120` (record) / `300` (seed), both with a
      **450 ms** period (330/150 dark respectively — `120+330` and
      `300+150`; the signature-bit run's 400 ms period is the near-miss
      the period check exists for).
- [x] The collision test (`wait_blink.rs:131`) extended: two new rows and
      the burst's on-times/period asserted against every existing row.
- [x] The six scenarios above as Rust test names.

**TDD:** red = the module members missing; green = the scenarios above.

**Acceptance:** a human watching the pin sees the warming blink, and every
5 s of waiting adds a readable pulse-count that names the site by its
on-time; nothing else on the pin can produce either shape.

### US-1929: Green — the entropy sites never park
**As a** a customer with a brand-new board **I want** the boot to wait
forever rather than give up **so that** the retail incident's park — the
outcome both reference firmwares lack — cannot happen on any unit.

```gherkin
Feature: Freshness never parks
  Scenario: The record draw re-arms forever
    Given the record draw refused across one whole 60 s budget
    Then the site re-arms the retry — no fatal_boot, no signature, the
        warming blink continues and bursts identify the site
  Scenario: The DRBG seed re-arms forever
    Given the seed refused across one whole 60 s budget
    Then the site re-arms the retry — same posture, seed-site bursts
  Scenario: The park signatures leave the freshness sites
    Given the tree's fatal_boot call sites
    Then boot.rs holds two fewer (23 → 21) and TrngRefused/DrbgRefused
        are reachable only through the TIMER0 clock-liveness parks
        (main.rs:527, :682 — infrastructure, not freshness)
  Scenario: A healthy boot is unchanged
    Given a TRNG that settles in the normal time
    Then the boot takes the tuned draw time (~1.5 s per site) and
        enumerates as before — no blink, no burst, no added latency
  Scenario: The stale docs stop lying
    Given otp_retry.rs's module doc, entropy_reset.rs's doc and the two
        site doc comments
    Then none claims a park, a bounded reboot, or a 60 s give-up — the
        bounded-reboot machinery has been unwired since US-1825
        (entropy_reset.rs: declared lib.rs:121, zero callers), and ADR
        0004 amendment 6 records the supersession
```

- [x] `boot.rs::seed_drbg_blocking` (`:1124`): the
      `.is_none() → fatal_boot` arm becomes an outer `loop` that re-arms;
      `ensure_boot_entropy_blocking` (`:1214`) likewise. The 400 ms draw
      notice and the US-918 unreadable-slot refusal are untouched.
- [x] The two wait-sleep wrappers (record/seed) count steps in a boot-path
      static and drive `progress_burst_levels` — zero cost on success (the
      sleep only runs between failed attempts).
- [x] `apps/fido/tests/region_degradation.rs`: the count 23 → **21** with
      the delta comment continued (the epic's own convention — the test
      header records every deliberate move).
- [x] Doc updates: `otp_retry.rs` module doc (the "reboots boundedly"
      sentence is stale — US-1825 unwired it; now: re-arms forever),
      `entropy_reset.rs` doc (superseded-mechanism note), both site doc
      comments (`boot.rs:1110-1123`, `:1206-1212`).
- [x] `firmware/src/lib.rs` arena stamp re-measure after the edits
      (`measure_task_arena.py`); commit the fresh stamp with the series.

**TDD:** red = the halt-site gate counting 23 with the two freshness sites
present, plus the doc source-pins; green = 21 and the never-park loops.

**Acceptance:** no code path parks on freshness; the gate pins the new
count; a healthy boot is latency-identical to the tuned draw.

### US-1930: Gates and docs — amendment 6 and the reading tables
**As a** an operator **I want** every LED reading and every policy doc to
match Phase 0's behaviour **so that** the next video is decoded against a
true table.

- [x] ADR 0004 **amendment 6**: freshness failures never park at boot —
      the legacy carve-out's parks (amendment 3's mechanism, deleted by
      US-1825; the sites' parks retained by US-1825) are now removed
      entirely; the park domain is identity plus clock-liveness, cited
      with the RS-Key finding and the 2026-11-19 audit.
- [x] `docs/boot-freeze.md`: the "Fresh install: blink window, then one
      long-flash signature (`0011`/`0100`)" row moves to the superseded
      table **annotated "v0.7.0 field units only"** (the field units still
      park until reflashed or pre-warmed — the US-1921 learning); a new
      row documents the bursts (120 ms = record site, 300 ms = seed site,
      K = 5-s-units, cap 9); the 400 ms notice row keeps its meaning.
- [x] The book's troubleshooting boot page: the burst row added, the
      fresh-install row updated ("blinking may continue for minutes —
      each burst pulse names a 5-second unit; the board is working;
      unplug 5 s only to accelerate"), the identity-signature rows
      unchanged.
- [x] D-8's mechanism row: marked "measured pending" until US-1926's
      decode lands, then closed with the two numbers.
- [ ] Full gate run: `cargo test -p fapico2-firmware --lib`,
      `cargo test -p fapico2-fido --target x86_64-unknown-linux-gnu`,
      `cargo test -p fapico2-platform`, clippy, `./build.sh`
      (uf2gen.py), `./run_tests.sh --suites-only` if the venv exists,
      `./scripts/pre_push_check.sh --full` before push; the flash-budget
      ratchet re-checked (net: config + burst generator + loops, minus two
      fatal sites).

**Acceptance:** CI-shaped green; every reading the pin can produce has
exactly one documented meaning; the amendment records the supersession.

---

## Sequencing

**Phase 0 (active, US-1927…US-1930):**

US-1927 (config/budget triple) → US-1928 (burst generator; parallel with
US-1927) → US-1929 (never-park sites; needs both) → US-1930 (gates/docs)
→ **US-1926 (the measurement — owner-run)** → the re-scope review.

*Status 2026-11-20:* US-1927…US-1930, US-1922 and US-1924's guard/move
are **landed** on `fix/darkboot-1119` (one commit per story); the
release UF2 is built and the full gate set is green. US-1926 awaits the
owner's flash-and-film; the re-scope review follows it.

**Then the re-scope review (the owner decides):** if the tuned window
collapses to seconds, US-1915…US-1919 (the pending-identity architecture)
are dropped with their recorded rationale; if the window survives at
minutes on some units, the architecture resumes as written — its crash
surfaces (O-1) and refusal set (O-2/O-3) stay valid either way.

**Suspended (US-1913, US-1915…US-1919):** the architecture sequence as
originally planned — US-1914's characterization and US-1920…1922's
gate/doc content are partially absorbed into Phase 0 (US-1930); the
hardware validation re-forms as US-1926's owner-run leg.

### Gate inventory (US-1913's verdicts land here)

| Gate | File | Current pin | Delta this epic forces |
|---|---|---|---|
| rng-path | `tests/scripts/check_rng_path.py` (CI `rng-path-gate`) | task owns seed + pools | The task additionally owns record, hkey, keystore, attestation draws; boot.rs/main.rs stay 0; coverage list grows |
| halt-site | `apps/fido/tests/region_degradation.rs` | **23** halt sites (Fact 13) | **Phase 0 (US-1929): 23 → 21** — the two freshness parks leave boot.rs; `TrngRefused` stays reachable via the clock-liveness parks. The architecture's later delta (−2 more for the deleted blocking fns + D-7's task-side park) re-derives if it resumes |
| flash-budget ratchet | `ci.yml` `FIRMWARE_FLASH_BUDGET_KIB: 1704` + device job | 1704 KiB | Net over the release ELF measured; `pre_push_check.sh --full` is the merge gate |
| task-arena stamp | `TASK_ARENA_DEMAND_B_STAMP` | fingerprints firmware closure | Task future grows → re-measure **after US-1919**, commit the stamp; named fallback: split install across iterations |
| wait-blink pin | `firmware/src/wait_blink.rs` tests | `busy_wait_us(400_000)` in boot.rs | D-3 deletes the notice → pin deleted |
| bootphase rungs | `firmware/src/bootphase.rs` tests | `P_BOOT_ENTROPY`/`P_DRBG` marks | Marks lose their blocking meaning; rung count re-checked |
| foreign-image-wipe | `tests/scripts/check_foreign_image_wipe.py` | cfg wording | cfg untouched; the wipe arm's behavior rewired (US-1919); no emulator coverage (Fact 12) |
| boot-clock-order | `tests/scripts/check_boot_clock_order.py` | references `init_drbg`/`fatal_boot` | `seed_drbg_blocking` dies → gate's references updated |
| consumer map | `apps/fido/tests/consumer_map.rs` | US-1821 coverage | Coverage learns the new task draw sites |
| dbg-release | `tests/scripts/check_dbg_release_gate.py` (CI `gates`) | dbg-log cfg | No impact expected; re-run to prove (D-3 deletes a plain fn) |
| hw-isolation | `tests/scripts/check_hw_isolation.py` | sweeps 4 dirs | `scripts/` probe enters the guarded inventory (US-1924) or moves |
| discriminator | (new, US-1914) | none today — the audit's gap | Characterization first (needs the lib-side genericize), source-pin absence after US-1919 |

## Out of scope (recorded, not silently dropped)

- **A second entropy source** — owner-rejected standing rule.
- **The stall's mechanism** (thermal vs analog re-formation) — US-1835
  owns the discriminating experiment; this epic is mechanism-independent
  by construction.
- **Repair-boot seal semantics on a redrawn record** — a boot that lost
  the record but kept its identity redraws the record (US-918's invariant
  demands it) and inherits today's downstream behaviour unchanged,
  including whatever it does to `kbase`-bound seals. The legacy path had
  exactly this behaviour; this epic re-homes the draw, not the policy.
- **PicoForge client changes** — the wire obligation is US-1827's, already
  shipped; the fresh board's warming status rides the same TLV (D-4: no
  new bit — one meaning, "entropy settling", for both arms). The tool
  display is verified, not changed (US-1923).
- **U2F/CTAP1 servability** — unchanged (not servable over CTAPHID yet);
  the §4 recorded edge (a PIN-less board advertising `U2F_V2`) still
  stands, and the stateless U2F master is pending-until-Ready on a fresh
  board.
- **The 60 s budget sizing** — inherited from US-1802; the task retries
  forever, so the budget now sizes a step, not a park.
- **The emulator's missing pending arm** (Fact 12) — recorded as a
  coverage asymmetry, not fixed here; the hardware leg carries it.

## Decision Log (multi-agent review record)

**Process:** three constrained reviewers (Skeptic/Challenger, Constraint
Guardian, User Advocate) reviewed the 2026-11-19 draft against the code;
the arbiter ruled on each objection. All three verified claims against
file:line.

| # | Objection (reviewer) | Ruling | Where it landed |
|---|---|---|---|
| O-1 | Blocker: hkey-only pending predicate + durable writes = a permanent-brick crash window (hkey persisted, keystore absent → `DeviceKeystore::fresh` on unseeded cell → fatal `KeystoreFailed` before USB, unrecoverable) | **Accepted.** Pending is store-derivable **per item** across all four artifacts; construction never draws on **any** pending arm; the crash-subset matrix is a pinned US-1915 scenario (D-6) | Constraints, Facts 6, US-1915, US-1916 |
| O-2 | Blocker: `handle_reset` draws twice with no warming gate; empty-pool `stretch_pool` serves computable constants and the hkey regen persists them (Fact 8 as drafted was false) | **Accepted.** Reset joins the warming refusal class on both arms; Fact 8 rewritten (now Fact 5); the constraint sentence corrected | Facts 5/10, US-1917 |
| O-3 | Major: mgmt RESET / `factory_reset` bypasses the CTAP2 gate — durable wipe racing the task's install can orphan credentials | **Accepted.** The management path joins the closure (US-1917) | US-1917 |
| O-4 | Major: D-1 names no dummy values; the flag drops the compiler backstop; `froot()` becomes a public constant on pending boards unless every site is gated | **Accepted with mitigation.** D-1 revised: the gate inventory enumerates every `hkey`/`keystore`/`attestation`/`froot()` site and a host test pins each behind the gate; dummy values named in-story; the enum stays rejected with its cost paid explicitly | US-1916 |
| O-5 | Major: task-side identity draws on the infallible seam hang the executor (`NonZeroScalar::random` on an untouched buffer) — a new dark park | **Accepted.** D-8: fallible seam required, hang-freedom pinned by a rig test | Constraints, Facts 3, US-1915, US-1918 |
| O-6 | Major: one arena re-measure is optimistic; US-939 frame discipline must be re-established; no named budget fallback | **Accepted.** US-1920 re-measures after US-1919; the split-install fallback is recorded; the frame discipline named | US-1920 |
| O-7 | Major: the wipe-arm rewire is under-specified (probe ownership) and has zero emulator coverage | **Accepted.** US-1918 names the probe plumbing; Fact 12 + US-1919 record the asymmetry | Facts 12, US-1918, US-1919 |
| O-8 | Minor: D-5's "nothing a reset would give" ignores `ykman fido reset` as a recovery loop; emulator reset suites go red | **Accepted.** D-5's rationale reworded (recovery is unplug/replug, docs own it); suite inventory added | US-1917, US-1921 |
| O-9 | Minor: D-2 re-walks §4's named failure shape without citing it | **Accepted.** D-2 cites US-1826's shipped gate as the controlling precedent + the bounded-window caveat (the Constraint Guardian's independent ruling concurs: **D-2 stands**) | US-1917 |
| O-10 | Minor: deleting the draw notice costs the incident-forensics discriminator | **Accepted.** US-1921 records what the decode method loses; the status TLV replaces it; D-3 stands | US-1921 |
| O-11 | Major (Guardian): halt-site arithmetic stale (pin is 23, not 21; "21−2=19" wrong) | **Accepted.** 23 − 2 = 21, re-derived by the survey | Facts 13, US-1920, gate table |
| O-12 | Major (Guardian): flash-budget ratchet missing from the gate table | **Accepted.** Row added | Gate table, US-1920 |
| O-13 | Blocker (Guardian): the named probe vehicle carries no `hw_guard.require` and `scripts/` is invisible to `check_hw_isolation.py` — the 2026-11-16 incident class | **Accepted.** US-1924 adds the guard + destructive tier and moves/extends the sweep; gate row added | Facts 14, US-1924, gate table |
| O-14 | Major (Guardian): US-1914's "red" is not runnable (bin-only module, device-gated store type); mislabeled | **Accepted.** Story relabeled characterization; the lib-side genericize is named as its real work; the runnable reds live in US-1913/1915/1916 | Facts 2, US-1914 |
| O-15 | Major (Guardian): corrupt-identity fatal policy would silently become warm-forever in the task | **Accepted.** D-7: Corrupt/unreadable stays fatal at the construction site; task-side Corrupt parks legibly, counted in the halt-site delta | Constraints, Facts, US-1915/1916/1918/1920 |
| O-16 | Major (Guardian): the pure core folds NotFound and Err into one bool; identity_pending is one bit for three items | **Accepted.** Three-state record slot + per-item identity presence (D-6); the unreadable-slot scenario pinned | US-1915 |
| O-17 | Minor (Guardian): the twin demand over-scopes — pool gates are deliberately device-only, recorded in-source | **Accepted.** Twin demand scoped to the pending gate; the in-source record cited | Constraints, US-1916 |
| O-18 | Minor (Guardian): US-1918's acceptance overstates host provability | **Accepted.** Acceptance reworded: pure core + rig + source pins; wiring hardware-validated | US-1918 |
| O-19 | Minor (Guardian): dbg-release row missing; `tests/consumer_map.rs` path wrong | **Accepted.** Row added; path fixed to `apps/fido/tests/` | Gate table |
| O-20 | Blocker (Advocate): the honest warm window is minutes (measured > 4.4 min) and no doc owns the ceiling or the exceeded-it action | **Accepted.** The ~5 min ceiling row + the unplug-5-10-s action in US-1921; asserted in US-1923 | US-1921, US-1923 |
| O-21 | Major (Advocate): nothing verifies what real clients display during the window (Chrome shows a generic failure) | **Accepted.** US-1923 verifies PicoForge + logged-Chrome display; US-1921 writes the client-display sentence | US-1921, US-1923 |
| O-22 | Major (Advocate): the doc story misses the two book files by path and leaves "do not unplug" contradicting the accelerator | **Accepted.** Paths + stale-claim list + the reconciliation in US-1921 | US-1921 |
| O-23 | Major (Advocate): the superseded-row convention is false for field units; the interim row's discriminator is ambiguous | **Accepted.** The signature row stays live, annotated "v0.7.0 field units only"; the signature-vs-no-signature discriminator stated | US-1921, US-1922 |
| O-24 | Minor (Advocate): no named single place of truth for the confused customer | **Accepted.** The troubleshooting boot page named (the US-1833 convention) | US-1921 |
| O-25 | Major (Advocate): the affected audience (pt-BR customer, seller) has no artifact they can act on | **Accepted.** The pt-BR insert is a US-1922 deliverable | US-1922 |
| O-26 | Minor (Advocate): reset-refusal undiscoverable; "never again after one boot" reassurance missing | **Accepted.** Both clauses in US-1921/US-1922 | US-1921, US-1922 |
| O-27 | Positive verification (Guardian): no fail-closed violation found in the core design — D-9 zeros, US-918 ordering, no lock/absence leak, §2 dual-homing untouched | **Recorded.** The design's security core stands as drafted | — |
| O-28 | **Owner decisions (2026-11-20, the stress-test review of `../pico-fido` and `../RS-Key`):** (1) scope = **tune + never-park first** (RS-Key-shaped); the pending-identity architecture re-scoped after the measurement; (2) a pathological unit **waits forever, visibly** — and the retry blink must be *information-bearing*: "a continuous wait-blink tells nothing … a different blink during retry can help us identify what the device is doing after some cycles. It will help to debug through video"; (3) the device leg is **owner-run** (agent implements, gates, builds; no `FAPICO2_HW_TESTS` in the session) | **Accepted.** Phase 0 (US-1927…US-1930) is the active plan; the architecture (US-1915…1919) suspended pending US-1926's measurement; the burst shapes (120/300 ms, 450 ms period) are the video-forensics instrument, collision-tested per US-1803's rule; the entropy record stays (frozen: US-918, ADR 0008 — RS-Key's record-less design is not wholesale-copyable) | Header/Status, Constraints, Phase 0 stories, Sequencing |
| O-29 | Arbiter integration notes for Phase 0: (a) the halt-count delta lands in US-1929, not US-1920 (23 → 21 by never-park; `TrngRefused`/`DrbgRefused` stay reachable via the TIMER0 clock-liveness parks, `main.rs:527`/`:682` — infrastructure, not freshness); (b) the poll cap must move **with** the budget (`liveness < MAX_ENTROPY_WAIT < MAX_ENTROPY_POLLS`, `trng.rs:905` — `1 << 19` ≈ 0.5–1 s would cap a 2000 ms budget short; `1 << 21`); (c) `entropy_reset.rs` is already unwired dead code since US-1825 (declared `lib.rs:121`, zero callers) — the never-park change supersedes amendment 3's mechanism permanently; the module gets a superseded-mechanism doc, not a deletion; (d) the 400 ms draw notice stays in Phase 0 (D-3 scoped to the suspended stories) | **Accepted.** Encoded in the Constraints, US-1927/1929/1930 task lists, and the gate table | Constraints, US-1927, US-1929, US-1930, Gate inventory |
| O-30 | **Owner evidence + the third field report (2026-11-20, this session):** a brand-new Pico 2 flashed with v0.7.1 fails identically to the third field video, and after pico-fido or RS-Key completes one boot on the same board, fapico2 works — the persistent first-boot difference between the reference firmwares and us is their OTP burn. Three parallel read-only reviewers + the session's own trace converged: the retail incidents are `NeverBootC` on the factory zero row (deterministic, in-process, zero probe budget — the burst spacing proves the TRNG was never reached), not a dwell stall. Rulings: (1) US-1931 removes the guard from the seed path only (`derive_kbase`/`derive_kbase_c` keep it — migration semantics); the pinning test is inverted, and the two replacement tests carry the fail-closed half (no record still refuses, before the peripheral); (2) US-1932 restores the legible park for *permanent* seed-state faults only, classified by a pure host-pinned predicate — freshness keeps US-1929's never-park; the park domain re-drawn in ADR 0004 amendment 7 (21 → 23 halt sites); (3) US-1933 ships the tuned config at construction and pins it structurally (CONFIG-PIN) — the US-1927 tuning had never reached the registers at cold boot; (4) the dwell/TRNG attribution of the 2026-11-09/19 audits is superseded for the retail incidents (it survives as US-1835's separate question); (5) the owner's probe offer stays unused — the mechanism was pinned before hardware reads were needed | **Accepted.** US-1931/1932/1933 landed, one commit each; audit `2026-11-20-retail-virgin-otp-row-brick.md`; US-1926 stays open (now measuring a genuinely-tuned boot) | Status, US-1931…1933, Decision Log, ADR 0004 amendment 7, audit |

**Arbiter disposition: APPROVED after revision.** Two Blockers (O-1, O-2)
and one Blocker-grade consent gap (O-13) are resolved in this revision;
all twenty-seven objections are either integrated (listed above) or
explicitly ruled on. No objection was rejected outright; the two standing
decisions (D-2 advertisement, D-1 flag-over-enum) survived with their
lineage recorded and their audit burden made explicit.

**Re-baselined 2026-11-20 (O-28):** Phase 0 supersedes the sequencing —
the never-park posture and the peripheral tuning land first, the
architecture resumes or drops on the measurement. The review verdicts
(O-1…O-27) continue to govern whichever path the re-scope picks: the
crash-surface matrix, the reset closure and the corrupt-identity policy
are requirements of *any* boot that constructs identity, tuned or not.
