# CI/test evaluation — 2026-11-11

Why every PR breaks GitHub Actions one to three times, what that costs, and
what this branch changed. Written on `ci/optimization`, the branch that
implements the changes; everything marked **implemented** is in this tree.

## 1. The recurring failure modes (evidence)

Pull requests were routinely red on first push despite green local runs. The
last week of runs on `fix/darkboot` (PR #139, EPIC WARM-BOOT-SERVE) shows the
actual causes, in order of how often they fired:

| # | Cause | Evidence | Local cost to catch |
|---|---|---|---|
| 1 | **Flash-budget ratchet** — any image growth reds `device-build` until the five-file ratchet dance is done (ci.yml env, `flashmap.rs`, `board_def.rs`, `docs/size-report.md`, mutation anchor) | run 42903283447: `shipping UF2 1737728 B exceeds the 1696 KiB ratchet`; the same failure repeatedly across September/October raises (seven in six weeks, see the ci.yml env block's own history comments) | ~10 min with a device build (`pre_push_check.sh --full`) |
| 2 | **Task-arena stamp staleness** — `TASK_ARENA_DEMAND_B_STAMP` is a byte-exact fingerprint over the whole firmware source closure; comment-only edits stale it | run 42897099671: `device-build` exit 101 on a measurement gate | ~1 s (`measure_task_arena.py --check`) |
| 3 | **`Gates (mutation)` red on push** — the full 26-gate mutation harness (9–60 min) triggered on every push touching `tests/scripts/**` or `.github/workflows/**`, unbranched | runs 42905911109, 42897091790, 42498711443, 42501444956 — failed on nearly every push of both `fix/darkboot` and `fix/config-save` | n/a (the PR's own wiring half in ci.yml already asserts gate reachability) |
| 4 | **pytest-gate suite failures** — the emulator suites failing on a fresh tree | run 42897099671 (two red jobs) | `run_tests.sh --suites-only` |

The common shape of 1–3: **the thing that fails is the thing `run_tests.sh`
never exercises**. Its full mode runs clippy, host tests, seven structural
gates and the suites — all host-side. The device-side gates (ratchet, stamp,
size budgets, reproducible build) have no local driver at all. That is the
local/CI parity gap, and it is why "ready locally" did not mean "ready on
push".

## 2. The structural costs (what the review measured)

- **12 flat jobs, zero caching.** No `actions/cache`, no rust-cache, no
  concurrency group. Every push paid twelve cold checkouts, cold toolchain
  installs, and cold compiles; a superseded push raced its own replacement.
  Measured job durations (run 42905919786): pytest-gate 12 m, cargo-test 11 m,
  device-build 7 m, supply-chain 3.4 m, clippy 1.3 m, six structural-gate jobs
  7 s–1 m each. Wall ≈ 12 m, but job-minutes ≈ 45+, most of it repeated work.
- **`cargo install cargo-vet --locked`** compiled from source on every run in
  three workflows (ci.yml supply-chain, gates-mutation, release.yml).
- **The mutation harness on the push path** ran its full cold-build table for
  a PR check that ci.yml's `--workflows-only` half already covers in a second.
- **Toolchain installed twice per push** (host-tests and clippy were separate
  cold jobs on the same toolchain).
- **Test mass:** ≈ 1,850 `#[test]`s in ~230 test-target files, 441 inline unit
  tests, plus the pytest trees. The sweep below found this mass dense but
  **not rotten** — the cost driver was CI structure, not ghost tests.

## 3. What this branch changed (implemented)

| Change | File(s) | Effect |
|---|---|---|
| **12 jobs → 5** (`host` = tests+clippy+erase-budget; `device` = device gates+advertise/serve; `gates-py` = the seven structural gates+wiring half+boot-ladder; supply-chain; pytest-gate) | `ci.yml` | one checkout/toolchain per concern instead of twelve; clippy fails fast in front of the tests; no gate script moved to a weaker position — every gate body is byte-identical, and `test_gates.py --workflows-only` passes unchanged on the new layout (the US-1042 reachability model is generic over job structure) |
| **Caching** — Swatinem/rust-cache v2.9.3 (SHA-pinned, `cache-on-failure`) in host/device/supply/pytest/gates-mutation; cargo-vet binary cache (actions/cache v4.3.0, version-keyed) in supply-chain and gates-mutation; `cache: pip` on both setup-python steps | `ci.yml`, `gates-mutation.yml` | cold cargo builds stop being paid per push; cargo-vet's from-source compile happens once per version bump |
| **Concurrency** — `group: ci-${{ github.ref }}`, `cancel-in-progress` on PRs only | `ci.yml` | a superseded push cancels its own predecessor; main always runs to completion |
| **Timeouts** — host 40, device 40, gates-py 15, supply 20, pytest 30, mutation 60 (already had) | `ci.yml` | a hung job costs its budget, not the 360-min default |
| **Mutation harness off the feature-branch push path** — nightly 03:30 UTC + push to `main` (same paths filter) + `workflow_dispatch` | `gates-mutation.yml` | cause #3 gone. The old header argued push-over-cron because GitHub disables scheduled workflows after 60 days of repo inactivity; that is answered by the repo being active (fuzz-nightly runs daily), by the main-push trigger firing on every gate-script landing, and by `--workflows-only` still running on every PR. The residual-risk note (a gate can rot without its own file changing) is unchanged and still true — the nightly run is what catches it |
| **Pre-push parity check** — `scripts/pre_push_check.sh --quick` (~2 min: stamp `--check`, 16 structural gates, clippy) and `--full` (adds device build, size budgets, the ratchet arithmetic mirrored exactly from ci.yml, and the emulator suites) | new script, `AGENTS.md` | causes #1 and #2 move from a 12-min CI round trip to a 2-min local one; `--full`'s ratchet comparison is the same UF2, the same `FIRMWARE_FLASH_BUDGET_KIB` read from ci.yml, the same comparison — a `--full` pass means the device job's ratchet step passes |
| Doc reference | `AGENTS.md` §Build/flash/test | the pre-push rule is written where the ratchet/stamp dance is documented |

**The ratchet step in `device` is byte-identical** to the old `device-build`
job's. `tests/scripts/test_gates.py::check_repro_ratchet_wired` asserts exact
strings of that step (`cmp /tmp/fapico2-a.uf2 /tmp/fapico2-b.uf2\n`,
`if [ "$SHIPPING" -gt "$BUDGET_BYTES" ]; then`, …) and requires exactly one
step per workflow to use `FIRMWARE_FLASH_BUDGET_KIB` — this was the constraint
that shaped the consolidation.

## 4. The test-mass verdict (the dedup sweep)

The sweep looked for ghosts and exact duplicates. Result: **no deletions**;
every candidate turned out to carry a named reason.

- **15 `#[ignore]`d Rust tests** across 13 files: every one is a deliberate,
  documented record — characterization tests that pin a pre-fix defect's
  behaviour (US-1600 baselines, US-1719/US-1609 records, `seed_root_restore`
  red-baselines, the `vendor41` debt listing). Several carry prose explicitly
  refusing `#[ignore]` for their siblings. These are the repository's
  negative-control culture, not rot.
- **pytest skips**: all conditional and legitimate — RSA-2048 modules skip on
  a device that ships RSA-3072, gnuk-only feature skips, hardware-vault and
  silent-phase environment gates. No unconditional skips.
- **`continue-on-error`**: zero uses (the only mention is ci.yml's historical
  comment about the old skipped-everything pytest job).
- **Overlap inventory** (same behaviour at multiple layers):

| Behaviour | Layers | Verdict |
|---|---|---|
| PicoForge docs caveat | `check_picoforge_compat_docs.py` + `tests/harness/test_docs_gate.py` | **keep both** — stated intent: "a README rewrite should not need the emulator to be caught"; the pytest copy re-proves it where conftest loads |
| Nostr keymgmt/PIN/touch | `apps/nostr/tests/*` (host) + `tests/harness/test_nostr_*.py` (CCID emulator) | **keep both** — different dialect layers: unit semantics vs the wire CCID contract the extension speaks |
| Rescue protocol | `apps/rescue/tests/protocol.rs` + `tests/harness/test_rescue_*.py` | **keep both** — same shape as Nostr |
| FIDO PIN/U2F | `apps/fido/tests/{pin*,u2f_*}` + `tests/pico-fido/test_010_pin.py`, `test_052_u2f.py` | **keep both** — host twin vs python-fido2 client stack; §1's twin trap is exactly what the second layer guards |
| OpenPGP | `apps/openpgp/tests` + `tests/openpgp/*` (gnuk-derived) + `tests/harness/test_openpgp_{pin_gate,pw_status,int_auth}.py` + `vendor/opcard/tests` | **keep** — four layers, four owners (app logic, card protocol, harness gates on US-912/913/926, upstream card logic) |
| Entropy starvation | `platform/tests/{drbg_seed_stall,trng_wedge}.rs` + `tests/harness/test_entropy_starve.py` + `p8_rng_starve.py` (hardware) | **keep** — three layers, three environments (unit, emulator, board) |
| Boot refusal / restart | platform Rust tests + `tests/harness/test_boot_refuse.py` / `test_restart.py` | **keep both** — process-level persistence is only observable in the emulator |
| Root-level `tests/test_openpgp_*.py` (7 files) | vs `tests/openpgp/` | **keep** — not copies: US-335/336/912 journey tests with their own coverage, wired by name in `run_tests.sh` |

The AGENTS.md §5 rule ("name the attack the complexity stops") applied to the
test mass: for each overlap above the named thing the second layer stops is a
**twin/dialect divergence** — the repository's own documented failure mode
(§1: fixing only `app.rs` passes every host test and changes nothing on
hardware). Deleting a layer saves seconds of CI and gives back exactly the
class of bug the layers were added to catch.

## 5. Deferred (named, not done)

- **The reproducible-build double build** in the device job is the remaining
  big cost (~half the device job's 7 m). It is also a security property (the
  image is a function of the source); making it nightly-only would trade a
  real guarantee for minutes. Left as is.
- **`release.yml` is largely unexercised** (its own header says so; cosign is
  deferred, dry_run defaults true). Fixing that is a release story, not a CI
  throughput one.
- **`ccid_reasm::tests` shared-clock flake** is papered over with
  `--test-threads=1` in two places. The real fix is the module's own locking;
  deliberately not smuggled into this series.
- **pages.yml** still uses moving tags (`@v4`, `@v5`) and `ubuntu-latest`; the
  divergence from the SHA-pinning posture is acknowledged in ci.yml's
  supply-chain comment and untouched here.
- **The flash-budget ratchet itself** still hard-fails CI (by choice — the
  user opted for catching it locally rather than softening it). The raise
  remains one command: `python3 tests/scripts/raise_flash_budget.py <KiB> --reason`.

## 6. How to verify this document's claims

```bash
python3 tests/scripts/test_gates.py --workflows-only   # wiring half on the new layout
./scripts/pre_push_check.sh --quick                    # ~2 min
./scripts/pre_push_check.sh --full                     # device build + ratchet + suites
python3 tests/scripts/test_gates.py                    # full mutation table (~30–60 min)
```

CI after this branch: 5 jobs instead of 12, warm cargo caches from the second
run on, no mutation red on feature-branch pushes, and `--full` catches the
ratchet/stamp failures before they leave the machine.
