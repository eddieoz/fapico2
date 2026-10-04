# Known gate divergences — S-722-5

Date: 2026-09-17. The standing waiver covers only the two historical FIDO
failures below. On 2026-09-17 the user approved two gate substitutions for
S-721-4 acceptance: sorted complete failure-line equality replaces raw-byte
OpenPGP comparison (D-1/D-2 untouched), and sequential per-module pytest
processes replace the single-process merged run. D-3 documents why the
combined invocation cannot pass today; the combined red run is evidence, not
waived green. Final gates have been run under those substitutions.
The register keeps growing past that record; **D-5** (below) adds an
OpenPGP-suite red run on `feat/picocompat`. As of **2026-09-27** that entry is
**resolved**: reproduce-at-BASE has been run and the failure sets are
identical, so it is classified as **pre-existing** and additionally
**attributed** — the US-912 factory-PIN gate, plus a panic in
`vendor/opcard/src/state.rs:471-473` that kills the emulator mid-suite. It is
still not covered by the substitutions or the standing waiver above and it
remains red; it is simply no longer anyone's open question.

## Standing waiver

**Standing instruction: "reproduce-at-BASE before counting against any Phase-7 story".**
When a FIDO suite run has only these two known failures with the recorded
signatures, report **"PASS modulo the register"**, retaining the actual pytest
failure count and exit code. New failures or changed signatures require separate
investigation; this waiver does not cover other gates.

The category **client-side CTAP-2.3 strictness** is the standing waiver's
classification, not a standards-compliance finding or proof that the client is
wrong. The assertions reject observed lengths. The historical A/B establishes
that those failures already occur at BASE; it does not settle the correct
credential-store-state format.

## Register — one row per divergence

Here “historical CURRENT” means `e274a0dcaf9ec6a3885a16e76f447775ffdf2571`,
not the later documentation-time HEAD.

| ID / test identity | Error signature | A/B-at-BASE evidence (throwaway worktree) | Affected files | Category / standing instruction |
|---|---|---|---|---|
| D-1: `pico-fido/test_000_getinfo.py::test_get_info_ctap_23_fields_are_well_formed` | `assert 64 == 32`: `len(info.enc_cred_store_state)` is 64 bytes, expected 32; test line 41. No internal block layout inferred. | BASE 16:54:17Z and 16:54:37Z; historical CURRENT 16:57:29Z. Same assertion; each invocation reports one failure. | None changed in-app under `apps/fido/` in the required diff. Firmware wrapper/artifact changes are listed below. | Client-side CTAP-2.3 strictness; **reproduce-at-BASE before counting against any Phase-7 story**. |
| D-2: `pico-fido/test_000_getinfo.py::test_enc_cred_store_state_changes_with_resident_credentials` | `assert 48 == 16`: `len(before)` from `ctap.get_info().get_cred_store_state(persistent_token)` is a 48-byte decrypted state, expected 16; test line 81. Failure here does not establish whether later state-change assertions would pass. | BASE 16:54:37Z; historical CURRENT 16:57:29Z. Same assertion; each reports one failure and `PYTEST_EXIT=1`. | None changed in-app under `apps/fido/` in the required diff. Firmware wrapper/artifact changes are listed below. | Client-side CTAP-2.3 strictness; **reproduce-at-BASE before counting against any Phase-7 story**. |
| D-5: `tests/openpgp/` full suite (`bash run_openpgp_tests.sh -q`) | `179 failed, 337 passed, 566 skipped in 971.04s`, `EXIT=1`. All OpenPGP key-management; representative `030_kdfsingle/test_074_adminless_kdfsingle.py::Test_Personalize_Reset::*`, `test_075_adminless_kdfsingle.py::Test_Remove_Keys::*`, `test_076_adminless_kdfsingle.py::Test_Reset_PW3::*`, `090_finalize/test_080_kdf_none.py::test_verify_pw3`, `test_091_reset_attr.py::Test_Reset_ATTRS::*`. 128 are `TimeoutError`. Deterministic. | **SATISFIED 2026-09-27.** Throwaway worktree at `5f11e14`, binary rebuilt, script run: `179 failed, 337 passed, 566 skipped in 971.04s`, `EXIT=1` — and the 179 `FAILED` ids **diff empty** against the HEAD run. Two candidate explanations tested and handled: cross-session keystore/port contention (rejected — same failures with the other session idle) and a stale emulator holding 35963 so pytest drove the wrong binary (now blocked in the script). | `git diff 5f11e14..HEAD --stat -- apps/openpgp platform` empty **and now backed by a behavioural A/B**. | **Pre-existing, reproduce-at-BASE satisfied, attributed.** Root cause is two device behaviours, not 179 defects: (1) the US-912 factory-PIN gate refuses the suite's `change_passwd` from a factory card; (2) `vendor/opcard/src/state.rs:471-473` does `.expect("New pin should not fail")` on a `get_pin_key` that returns `FilesystemWriteFailure`, **panicking the emulator mid-suite**. Still red, still not waived, still not Phase-F's to fix; needs its own root-cause cycle. |
| D-4: `pico-fido/test_051_ctap1_interop.py::test_authenticate_ctap1_through_ctap2` | `fido2.ctap.CtapError: CTAP error: 0x2E - NO_CREDENTIALS` raised by python-fido2's CTAP2 `get_assertion` on the allow-listed GA leg (test drives CTAP1 registration through the CTAP2 path). 3 sibling tests in the module pass. | Reproduced 2026-09-24 at the review branch AND at BASE `36bb254` (detached checkout, incremental rebuild of the branch binary): `pytest tests/pico-fido/test_051_ctap1_interop.py -q` → **1 failed, 3 passed** on both sides, identical signature. Pre-existing on the branch; not a review regression. | No app source at fault identified; failure set is stable across runs and independent of the review's fix commits. | CTAP1-through-CTAP2 credential path — outside the standing D-1/D-2 class; classified **pre-existing divergence, reproduce-at-BASE satisfied**. Do not count against any Phase-7 story; needs its own root-cause cycle (stateless-U2F/CTAP1 interop follow-up) before any story claims the CTAP1 leg. |

| D-8: the TRNG wait budget is a datasheet average × 10, not a measured maximum (US-1005) | `Rp2350Probe`'s wait ends on a **wall-clock budget** `MAX_ENTROPY_WAIT` (20 ms — 10× the ~2 ms *average* generation time RP2350 §12.12.2 quotes for `embassy-rp`'s default `Config`) or on an independent hard cap `MAX_ENTROPY_POLLS` (2^18 status reads), whichever is first. Supersedes the original 64-poll ceiling, which was ~4 µs of spinning against a ~2 ms healthy generation — it would have returned `Stalled` on good silicon and, `init_drbg` being fatal, refused to boot. | Not applicable — this is a **device timing property**. No board was attached. `platform/tests/trng_wedge.rs` drives a fake `EntropyClock` and pins both edges of the deadline (`a_block_ready_just_inside_the_budget_is_still_served` / `..._just_past_...`), which is the property the old poll count got backwards; `apps/openpgp/tests/rng_stall.rs` proves the logic above the peripheral. Neither observes silicon timing. | `platform/src/trng.rs` (`EntropyClock`, `MAX_ENTROPY_WAIT_MS`, `rp2350::Rp2350Timer`), `firmware/src/boot.rs` (`init_drbg`). **Assumptions that would void the claim:** (1) the budget is sized for the config `embassy-rp`'s `initialize_rng` writes (sample_count 25, all three health tests enabled) — a future change routing construction away from `embassy_rp::trng::Trng::new` leaves power-on defaults, which the datasheet says are *slower*; (2) the 1 MHz timer convention `embassy-time` already assumes. | **Unproven without hardware — do not read as green.** A silicon part slower than 10× the datasheet average would return `Stalled` and refuse to boot. That is the correct fail-closed direction, but it is possible. Full entry below. |
| D-9: `RngCore::fill_bytes` is infallible by contract, and two device caller classes depend on that (US-1006) | **AMENDED 2026-09-29 (US-1007 defect fix) — the predicted symptom was WRONG.** This entry predicted a starved FIDO `hkey` would be "all zeros"; it is an **infinite rejection loop** instead. `SecretKey::random` is a rejection sampler, not one draw: it rejects a zero scalar and the next draw is the same untouched buffer, so it never resolves — silent and unbounded, where the prediction was loud. The `fill_rng_pool` analysis (item 2) is unaffected and still the worse of the two. | Host-side: `apps/fido/tests/keygen_bounded.rs` reproduces the spin against a cap-less sampler (it hangs; killed at a 20 s ceiling) and pins the fix at exactly `KEYGEN_MAX_ATTEMPTS` draws. Live: `tests/harness/test_entropy_starve.py::test_starved_fido_keygen_answers_a_clean_error` — CTAP `0x7F` in **82 ms**, ~98x under the 8 s hang ceiling. | **Partly fixed.** Bounded + made fallible: `Trng::try_random_bytes` (new provided method; overridden by `HostTrng` and `DrbgTrng`), both `crypto` adapters forwarding to it, `crypto::try_fill_valid{,_with}` capping the rejection at `KEYGEN_MAX_ATTEMPTS`; device request paths (`device_core.rs` credential keygen and reset-`hkey`) now answer `Ctap2Response::Other`; all four host `makeCredential` curves converted. **Still open:** the device *boot* samplers — `device_app.rs` (`hkey`, `new` + fresh-partition arm) and `attestation::generate_from` — still call `SecretKey::random`, and `boot_in_place` calls `attestation::provision` unconditionally, so `init_drbg` succeeding does not protect them. | **The reachability premise is withdrawn, not restated** (`RESEED_INTERVAL` = 256). It used to read "practically unreachable today (`init_drbg` refuses fatally at boot)" — and that argument rests on behaviour that is currently **unexplained**: `init_drbg` refusing fatally is the leading hypothesis for this branch's parked dark boot (see `.superpowers/sdd/progress.md`, HARDWARE FINDING 2026-09-29). An entry cannot lean on a hypothesis that is itself an open question, because if the hypothesis is right the premise is not a premise at all. The claim that is *not* withdrawn is narrower and is the one the entry already makes: the argument covers a peripheral dead **at boot** only, not a generator that seeds and later fails, which is exactly what the device request paths were — and those are now bounded. Follow-up: the boot samplers above. Full entry below. |
| D-11: `Rp2350Probe` and `embassy-rp`'s `blocking_fill_bytes` interleave on one TRNG singleton (US-1005 / I-1) | `firmware/src/main.rs` builds three handles over the same `0x400f_0000` register block — `Rp2350Trng` (the boot-path driver, US-1005's `from_peri`), `Rp2350Probe` (the bounded seed probe), and the migration-nonce `MIG_TRNG` — and since the I-1 fix the **boot sanity draw** is also a `Rp2350Probe` draw rather than a driver draw, so the two implementations now genuinely alternate within one boot. The review verified they are symmetric: `blocking_fill_bytes` calls `start_rng()` per fill (`embassy-rp-0.10.0/src/trng.rs:330-344`) and `Rp2350Probe::read_into` does the same `start()`/`stop()` pair per block, so neither can inherit the other's state. | Not applicable — a **device concurrency assumption**, not a test-suite divergence. `platform/tests/trng_wedge.rs` drives a fake `EntropyClock` and a fake `TrngProbe`; it does not model two implementations over one peripheral, because nothing host-side can. | Symmetry is argued from the two sources above and is **not** verified on silicon. What makes it sound on paper: single core, cooperative executor, no `.await` inside any of these calls, so no interleaving is possible at all — the handles are used in sequence within `main`, and the request-path use (`MIG_TRNG`) is inside the CCID task's synchronous section. | **A recorded assumption, not a measurement.** If a future change makes any of these `async`, or introduces a second executor, the symmetry argument stops applying and this entry must be re-derived. No board was attached, so nothing here is verified against silicon. Full entry below. |
| D-10: `migration_nonce()` was an unbounded peripheral draw inside a CCID request (US-917) — **CLOSED 2026-09-29 (US-1005)** | **Was:** `firmware/src/boot.rs`'s `MIG_TRNG` / `migration_nonce()` are called from `DeviceMigrationHandler::complete` and `complete_other_class` — **inside a CCID APDU request** — and drew 12 bytes per migration through `embassy-rp`'s unbounded `blocking_fill_bytes`. **Now:** the handle is `boot::MIG_PROBE`, a second `Rp2350Probe`, and the draw is `platform::trng::try_migration_nonce` — a bounded `probe_bytes` plus an all-zero refusal. The unbounded wait is gone; see the full entry for what remains. | Host-side, and it is new coverage rather than a moved one: `platform/tests/migration_nonce.rs` drives the real `try_migration_nonce` against a `TrngProbe` that never validates a block and asserts `Err(Stalled)` **after exactly `MAX_ENTROPY_WAIT` polls** — an early return would mean the bound is not what ends the wait, and a test that merely asserted "an error came back" would also pass against an unbounded loop that happened to give up. A second case pins the D-12 distinction (`ClockStalled`, not `Stalled`) through the new call site, and two more pin the all-zero refusal and the single-zero-byte non-refusal. | `platform/src/trng.rs` (`try_migration_nonce`, `MIGRATION_NONCE_LEN`, the one-block compile-time assertion), `platform/tests/migration_nonce.rs` (new), `firmware/src/boot.rs` (`MIG_TRNG` → `MIG_PROBE`, `migration_nonce` fallible, both call sites refuse with `ClassStatus::Error`), `firmware/src/main.rs` (the second `Rp2350Probe::new` + its own `require_advancing`; the `Rp2350Trng::from_peri` count drops 2 → 1). `check_rng_path.py`'s caps tighten to make the regression red on its own. | **Closed for the property it was filed for: no unbounded entropy wait on a request path.** Two things are *not* claimed. (1) The nonce comes from the **peripheral**, not the DRBG — the generator is moved by value into the trussed platform and there is no handle left to draw from inside a CCID request; for a one-off 12-byte at-rest AEAD nonce the two routes differ by an HMAC, and the reasoning is in `try_migration_nonce`'s docs. (2) The wait's *budget* is still reasoned, not measured (D-8), and the peripheral is still unmeasured on silicon. Full entry below. |
| D-13: the OTP lock register was read nowhere in this tree, and every row `Layout::rp2350()` names is inside the page the C reference locks (US-1083, which blocks US-1081) | `platform/src/boot_key.rs` shipped with no reference to a lock state, so a burn was attempted whatever `otp_hw->sw_lock[page]` said. A blank-row pre-flight cannot see a `READ_ONLY` page, because `READ_ONLY` lets the read succeed — the row reads virgin, the presence grant is spent, and the failure lands at `program_row`. | Not applicable — a **missing check**, not a suite divergence. The C reference in this repository locks a page by writing `0b1100` to `sw_lock` (`pico-keys-sdk/src/otp/otp_rp2350.c:88-95`) and calls it for the OTP-MKEK rows; `OTP_ROWS_PER_PAGE` is 64 and `Layout::rp2350()`'s rows (`0x08`..`0x0C`) are all in page 0. The bit positions and value encodings are **transcribed** from `pico-sdk`'s `hardware/regs/otp.h` and cross-checked against that `0b1100` write, not read out of a datasheet here. | Fixed in `cb278d2`: `Otp::lock_state` (required trait method, three-valued), `LockWord`/`LockField`, `Provisioner::check_lock_state` over **both** written rows, placed as step 1b — before the presence grant, so a locked device costs no press. No `set_lock`, deliberately. Gate `check_otp_provisioning_precondition.py` mutation-proven (baseline 0, broken 1). | **Closed in code; three things stay open and are not closed by this row.** `Layout::rp2350()`'s row numbers are still unverified (US-1081's own caveat). A device `impl Otp` does not exist, so nothing reads the register. And the provisioning path still has **no reachable trigger** — delivered and enforced in the path that exists, but not reachable on a device, which is a different thing from missing. Full entry below. |
| D-14: the key row's "write-lock" is a runtime-only register that does not survive reset (US-918) | `otp_hw_write_lock_key_row()` runs every boot (baseline and branch) and does one `sw_lock.modify(..set_nsec(READ_ONLY))`. rp-pac documents the register: locks "are initialised from the OTP lock pages at reset… can be written to further advance the lock state of each page (**until next reset**)". So the lock is per-boot; a power cycle reverts to the OTP lock pages. US-918's property is not provided. | Not applicable — a **mis-claimed security property**, not a suite divergence. Verified in the vendored `rp-pac-7.0.0/src/rp235x/otp.rs:17`. The C reference does the other half too: `otp_lock_page()` (`pico-keys-sdk/src/otp/otp_rp2350.c:88-95`) **burns** the lock-page row via `rom_func_otp_access` (SBPI) *and then* writes `sw_lock`; this tree does only the second. | `firmware/src/boot.rs::otp_hw_write_lock_key_row` (doc comment), `firmware/src/main.rs:483` (call-site comment), `platform/src/ckey.rs:78`. **Behaviour deliberately unchanged** — removing the write is the owner's call. | **Claim corrected in place; the real fix is a product decision that has not been taken.** Achieving it needs an irreversible SBPI lock-page burn plus a decision about who may provision a unit. Residual: software-level write access to the key row by later code on the same device — not a new remote surface, and smaller than US-924's separate read-exposure. Full entry below. |
| D-6: OpenPGP `VERIFY` never answers `6983` for an exhausted retry counter | Ten wrong PINs on a personalised card answer `63C2`, `63C1`, then `63C0` — and `63C0` for every attempt after, forever. `6983` (ISO 7816 "authentication method blocked") is never emitted on the normal path. Pinned by `apps/openpgp/tests/picoforge_reset.rs::wrong_pin_exhausts_at_three_and_reports_63c0_not_6983`. | Not applicable — this is a **device behaviour**, not a test-suite divergence, so reproduce-at-BASE is not the right instrument. Verified in source at `vendor/opcard/src/state.rs:1316-1318`: the `migration_source.is_none()` arm returns `Status::RemainingRetries(remaining)` unconditionally, so zero renders `63C0`; only the migration arm (`:1319-1327`) maps `Some(0)` to `OperationBlocked`. | No Phase F change touched `vendor/opcard`; `git diff 5f11e14..HEAD --stat -- vendor` is empty. | **Consequence: a client that detects a blocked PIN by watching for `6983` can never detect it here.** PicoForge's factory reset happens to survive — it burns all ten attempts and proceeds, reaching the right end state by exhaustion rather than by detection (`openpgp.rs:438-457`). The card demonstrably *has* the `6983` path and does not take it off the migration route. Not a Phase F fix; recorded for the owner. |
All timestamps above are UTC on 2026-09-17. The BASE full-suite run
records `2 failed, 280 passed, 4 skipped, 8 warnings in 142.62s (0:02:22)`
and `PYTEST_EXIT=1`, with exactly D-1/D-2 failing. The existing
acceptance record reports the same 280/2/4 for the
historical current suite. The archived current-side logs here are focused
per-test runs, not a second full-suite transcript.

## D-3 — merged-suite fixture port collision (harness, not firmware)

**Identity:** `merged/test_fido_rk_register.py` — both resident-credential
tests error at setup (`OSError: [Errno 98] Address already in use`,
`harness/ccid.py:153`) whenever `merged/` runs in **one pytest process**
after `merged/test_app_switching.py`.

**Cause (verified by code trace, 2026-09-17):** the root
`tests/conftest.py:50–61` `emulator` fixture is **session-scoped** and holds
the 127.0.0.1:35963 listener until pytest-session teardown;
`test_app_switching.py:70–74` consumes it module-scoped without releasing it,
and the trimmed-build test skips at `test_app_switching.py:142–144` **before**
its line-146 `emulator.stop()` would run. `fresh_emulator`
(`test_fido_rk_register.py:66–76`) is function-scoped and starts a second
listener on the same default port, so its `start()` fails before its own
`try/finally` cleanup. `SO_REUSEADDR` (`harness/ccid.py:152`) does not allow a
second active listener on the same address. The firmware binary is never
launched by the failing fixture — this is a host harness lifecycle problem,
not a credential-storage regression.

**Evidence:** the combined gate run reported **3 passed, 1 skipped, 2 errors**
(fixture port collision, see cause above); the module-split re-run reported
3 passed/1 skipped and 2 passed, both exit zero. Detailed transcripts and the
split runner remain in the local archive.

**Disposition: approved gate substitution, 2026-09-17.** The user accepted
sequential whole-module pytest processes with fresh persistence: app-switching
3 passed/1 skipped, resident credentials 2 passed, both exit zero. Thus the
accepted merged gate is **5 passed, 1 skipped**. The combined invocation remains
red and would need a fixture-lifetime correction; no suite was edited. This
specific substitution is not an extension of the D-1/D-2 standing waiver.

## D-5 — OpenPGP suite divergence (RESOLVED 2026-09-27: reproduce-at-BASE satisfied, and attributed)

**Status: pre-existing, reproduce-at-BASE SATISFIED, and now attributed.** The
outstanding step recorded below has been carried out, and the classification
has moved from *unattributed* to *pre-existing, with an identified root cause*.

### The reproduction

A throwaway worktree was created at `5f11e14` (detached; the commit before the
Phase D range on this branch), the host emulation binary rebuilt there by the
script itself, and `bash run_openpgp_tests.sh -q` executed:

```text
BASE  5f11e14:  179 failed, 337 passed, 566 skipped in 971.04s (0:16:11)   EXIT=1
HEAD  (branch): 179 failed, 337 passed, 566 skipped in 971.36s (0:16:11)   EXIT=1
```

Counts are not merely equal — the **failure sets are identical**. Extracting
every `FAILED` line from both runs and diffing them gives an empty diff across
all 179 test ids, so no test fails at HEAD that did not already fail at BASE:

```text
$ grep '^FAILED' base.log | sed 's/ - .*//' | sort > base.txt
$ grep '^FAILED' head.log | sed 's/ - .*//' | sort > head.txt
$ diff base.txt head.txt && echo IDENTICAL
IDENTICAL
```

This is the D-4 model of a correctly-attributed entry, and it discharges the
reproduce-at-BASE obligation this register set for itself.

### What was ruled out first

A plausible-sounding alternative was **cross-session contamination**: another
session working the same repository shares `/tmp/fapico2_openpgp_keystore` and
the relay port, and the emulator was observed emitting
`FilesystemWriteFailure` at the moment the other session was mid-run. That
explanation was tested and **rejected** — with the other session idle the same
179 failures reproduced (and the run got *faster*, 470s vs 971s, because it was
no longer competing). The failures are not an artefact of interference.

A second trap was found and eliminated rather than reasoned about. A stale
`fapico2-emulation` left over from an earlier run holds port 35963; the newly
started emulator then dies on `AddrInUse`, and **pytest silently drives the
stale binary** and reports a full suite of results for code that is not on
disk. This is invisible in pytest's output. `run_openpgp_tests.sh` now refuses
to start when 35963 is already listening, and waits for the emulator to attach
to *its* relay instead of sleeping a fixed interval. The same commit fixed the
script's argument handling: a test path used to be **appended** to
`tests/openpgp/`, so asking for one test ran the whole suite.

### The actual root cause

Two pre-existing device behaviours produce all 179 failures; they are not 179
independent defects.

1. **The US-912 factory-PIN gate contradicts the suite's starting assumption.**
   **Corrected 2026-10-04 — the mechanism stated here was wrong, and it has been
   re-verified against the code and the suite.**

   The claim was that US-912 "refuses PIN changes and key operations while the
   factory PINs are in force, so those calls return a non-`9000` status word".
   Two parts of that are false:

   * **`change_passwd` is not gated.** `change_reference_data`
     (`vendor/opcard/src/command.rs:411`) is INS `0x24` CHANGE REFERENCE DATA,
     and it carries no `factory_defaults_in_force()` check. Only key operations
     — `PSO:SIGN` (`pso.rs:79`), `PSO:DECIPHER` (`pso.rs:292`), `INT-AUTH`
     (`pso.rs:379`), `GENERATE` (`command.rs:500`) — and `TERMINATE DF`
     (`command.rs:521`) are. Personalisation is always available, which is what
     lets an owner escape this state at all.
   * **The suite lifts the gate before it needs the operations.**
     `card_test_personalize_reset.py:65` changes PW3 and `:73` changes PW1, in
     that order. `State::set_pin` (`state.rs:1449-1458`) sets each `*_changed`
     flag to `new_pin != DEFAULT`, so once both have been moved away from their
     defaults `factory_defaults_in_force()` (`state.rs:1417`) returns `false` and
     the gate is open for the rest of the run.

   What is *not* established here is whether US-912 contributes to the 179
   failures by some other route — the second root cause below (a panic that
   kills the emulator, which would also explain the 128 `TimeoutError`s) is a
   live candidate and may account for them alone. That is a separate
   root-cause cycle, and it is still open. **The correction matters now because
   this paragraph was the recorded justification for the gate being a deliberate
   divergence from the suite**: if it had been read literally, the tempting
   response would have been to ungate the key operations, removing a security
   control on the strength of a claim about a code path that does not exist.

2. **A panic in `set_reset_code` kills the emulator mid-run.**
   `vendor/opcard/src/state.rs:471-473`:

   ```rust
   #[allow(clippy::expect_used)]
   let rc_key = syscall!(client.get_pin_key(Password::ResetCode, new_pin))
       .result
       .expect("New pin should not fail");
   ```

   That call returns `FilesystemWriteFailure`; the `expect` panics and takes
   the whole emulator process down. Every test ordered after that point blocks
   in `_recv_exact` and dies as a `TimeoutError` — 128 of them. The
   `#[allow(clippy::expect_used)]` shows the panic was knowingly suppressed at
   the time it was written.

A filesystem error panicking a security applet is a real robustness defect
worth its own fix cycle — on device it is a reset, not a test failure. **It is
not Phase-F work and is not fixed here.**

### Consequence for the Phase F conformance tests

The PicoForge tests sort after the numeric directories, so they run last and
were casualties of (2): they failed with a 30s socket timeout while the relay
had nothing behind it. `tests/openpgp/conftest.py` now exposes `live_card` and
`require_live_card`, which probe the card first and **skip** — naming this row
— only when the emulator does not answer at all. The skip is deliberately
narrow: a wrong status word, a malformed TLV or a failed assertion still
fails, so a real regression cannot hide behind it. The five Phase F tests pass
when the card is alive, and each is additionally pinned in-process by a Rust
twin under `apps/openpgp/tests/` that does not depend on suite ordering.

**Not waived, and not Phase-F's to fix.** The suite is red for reasons that
predate this branch; the right disposition is a dedicated root-cause cycle for
the `set_reset_code` panic and a decision on whether the upstream suite or the
US-912 gate gives way.
   *pre-existing divergence, reproduce-at-BASE satisfied* on D-4's model. If
   they do not, the delta is attributable and a root-cause cycle is owed.

**Classification: unattributed; reproduce-at-BASE outstanding.** Explicitly
*not* the D-1/D-2 client-side-CTAP-2.3-strictness class, and explicitly *not*
covered by the standing waiver — that waiver is scoped to the two historical
FIDO failures in `pico-fido/`, and this is a different suite. The failure is
**not counted against any Phase D or E story**, on the same footing as D-3 and
D-4; and it is equally **not claimed as pre-existing**, because nothing
establishes that.

**D-3 does not cover this — do not apply D-3's approved substitution.** D-3 is
a **different suite**: `merged/`, not `tests/openpgp/`. Its recorded cause is a
session-scoped `emulator` fixture holding the 127.0.0.1:35963 listener until
pytest-session teardown, so a second listener cannot bind and the failures
surface at setup as `OSError: [Errno 98] Address already in use`. The failures
here are a **different shape** — `TimeoutError` raised from inside tests, not
`OSError` at setup — and the OpenPGP suite is driven by the shared relay
(`tests/harness/ccid_relay.py`, `CCID_PORT = 35963` for the emulator's dial-in
and `CLIENT_PORT = 35970` for test clients, `tests/conftest.py:470`), started
once by `run_openpgp_tests.sh` outside pytest. D-3's user-approved substitution
— sequential whole-module pytest processes with fresh persistence — was accepted
for the merged gate only and does not extend here; do not read it as cover for
this red run.

**Unverified observation, deliberately not a claim.** The representative failing
tests all take the same `card` fixture
(`test_091_reset_attr.py::Test_Reset_ATTRS::*` → `card`; the
`Test_Personalize_Reset` / `Test_Remove_Keys` / `Test_Reset_PW3` classes in
`card_test_personalize_reset.py` → `card`;
`test_080_kdf_none.py::test_verify_pw3(card)`), and `card` is session-scoped
(`tests/conftest.py:554`) over the session-scoped `ccid_card` (`:524`), whose
socket is set to a 15-second timeout. So the timeouts are *consistent with* a
single shared session-scoped card behind a bounded socket timeout. That is an
observation from reading the fixtures, **not a root cause**: no per-test run,
no per-test isolation and no BASE comparison was performed to support it, and
the suite was deliberately not re-run for this documentation task. No cause is
asserted, and none should be inferred from this paragraph.

## Exact historical provenance

The provenance transcripts (retained in the local archive) record:

- At 16:52:50Z, creation of detached worktree `/tmp/fapico2-ab-base-837d5a1`
  at BASE `837d5a169ab5debf787e61508009656d2d83dde6`.
  `status --porcelain` emitted nothing; both `diff --exit-code` and
  `diff --cached --exit-code` emitted no differences.
- BASE `Cargo.lock` SHA-256:
  `8f5f20b8c5eb1c2bb7069eeedf42a33e3684f1d2af82bfd3ccda9b64efbf5206`.
  The build transcript records
  rustc 1.94.1, cargo 1.94.1, a separate `CARGO_TARGET_DIR`, and a successful
  host emulation build.
- BASE binary SHA-256:
  `1a05e0e82b4b5661ab0a2da1f21cc6ac4491583f8b82273ae2d41c9dbfe0ab05`.
- Historical CURRENT HEAD: `e274a0dcaf9ec6a3885a16e76f447775ffdf2571`.
  Its existing host binary was copied as `ab-current-emulation`; source and
  copy hashes match:
  `bba86357505582824d5bdedfa14ad3da23d078ec7fac5f9e6faea50dfd550c16`.
  This is a captured binary at that HEAD, not evidence of a clean current
  worktree or a hermetic rebuild from that commit.
- Per-run logs record cwd (`ab-suite` for BASE, `ab-suite-current` for
  historical CURRENT), HEAD, and `sha256sum build/pico_fido2` before pytest.
  Both sides use the same Python executable and `ab-runtime` TMPDIR.
- The suite provenance records
  an unchanged 192-file suite copy, suite repository HEAD
  `dbd7e229ab0986b4c2d6d1f2fa653b48015e95e3`, and `pip freeze` (including
  fido2 2.2.1, pytest 9.1.1, cryptography 50.0.1, pyscard 2.3.1).
  `pico-fido/test_000_getinfo.py` SHA-256 is
  `5834a0e9c9723e2bbae736ee2500ba2e892a6f70fce46afd5a9b143817fc5760`.
  Package versions were recorded; the venv itself was not hash-verified.
- By 16:57:44Z the throwaway worktree no longer existed. The logs, not that
  temporary directory, are the retained evidence.

## Reproduction commands (not run for this documentation task)

The original worktree/build commands were:

```bash
git -C "$HOME/Projects/git/pico/fapico2" worktree add /tmp/fapico2-ab-base-837d5a1 837d5a1 --detach
cd /tmp/fapico2-ab-base-837d5a1
CARGO_TARGET_DIR=/tmp/fapico2-ab-base-837d5a1/target cargo build --manifest-path /tmp/fapico2-ab-base-837d5a1/Cargo.toml --bin fapico2-emulation --no-default-features --features emulation --target x86_64-unknown-linux-gnu
```

For a future rerun, use an unused throwaway path and an isolated emulator
bench. The following is reconstructed staging, not a verbatim historical
setup transcript. It copies the local test harness, not an upstream firmware
implementation. Verify suite hashes and package versions against the archived
provenance first; the local suite/venv may have changed.

```bash
BASE=/tmp/fapico2-ab-base-837d5a1
SUITE="$HOME/Projects/git/pico/pico-fido2/tests"
mkdir -p "$BASE/ab-suite" "$BASE/ab-suite-current" "$BASE/ab-runtime"
cp -a "$SUITE/." "$BASE/ab-suite/"
cp -a "$SUITE/." "$BASE/ab-suite-current/"
mkdir -p "$BASE/ab-suite/build" "$BASE/ab-suite-current/build"
cp "$BASE/target/x86_64-unknown-linux-gnu/debug/fapico2-emulation" "$BASE/ab-suite/build/pico_fido2"
# Candidate binary: record HEAD, dirty state, build command and SHA-256.
# Today's candidate is NOT automatically the historical e274a0d binary.
cp "$HOME/Projects/git/pico/fapico2/target/x86_64-unknown-linux-gnu/debug/fapico2-emulation" "$BASE/ab-suite-current/build/pico_fido2"
```

Run sequentially from each staged suite cwd; the existing suite harness
locates the binary as `build/pico_fido2`. Record its SHA-256 before each run.
The exact historical focused commands (same on both sides) were:

```bash
cd /tmp/fapico2-ab-base-837d5a1/ab-suite
sha256sum build/pico_fido2
TMPDIR=/tmp/fapico2-ab-base-837d5a1/ab-runtime PYTHONDONTWRITEBYTECODE=1 timeout 180 "$HOME/Projects/git/pico/pico-fido2/.test-venv/bin/python" -m pytest pico-fido/test_000_getinfo.py::test_get_info_ctap_23_fields_are_well_formed -q
TMPDIR=/tmp/fapico2-ab-base-837d5a1/ab-runtime PYTHONDONTWRITEBYTECODE=1 timeout 180 "$HOME/Projects/git/pico/pico-fido2/.test-venv/bin/python" -m pytest pico-fido/test_000_getinfo.py::test_enc_cred_store_state_changes_with_resident_credentials -q
# Repeat those commands after changing cwd to:
# /tmp/fapico2-ab-base-837d5a1/ab-suite-current
```

Each recorded focused run failed; do not hide pytest exit 1 with a wrapper's
exit 0. The exact historical BASE full-suite command, from `ab-suite`, was:

```bash
TMPDIR=/tmp/fapico2-ab-base-837d5a1/ab-runtime PYTHONDONTWRITEBYTECODE=1 timeout 600 "$HOME/Projects/git/pico/pico-fido2/.test-venv/bin/python" -m pytest pico-fido/ -q
```

## Current required diff-stat check

Run on 2026-09-17 in the fapico2 checkout at HEAD
`7ca35022d9017b30bf003783dabbc9b4f2f3e449`, branch `feature/phase7`.
Command and output, verbatim:

```text
$ git diff 837d5a1 --stat -- apps/fido/ firmware/
 firmware/fapico2.uf2  | Bin 740864 -> 797696 bytes
 firmware/src/boot.rs  | 116 ++++++++++++++++++++++++++++++++++++++++++++++++--
 firmware/src/main.rs  |  37 ++++++++++------
 firmware/src/tasks.rs |  16 +++----
 4 files changed, 144 insertions(+), 25 deletions(-)
```

This compares BASE to the **tracked working tree**, not just HEAD, and does
not show untracked files. The accompanying `git status --porcelain` showed
no entries under `apps/fido/` or `firmware/`. There are **zero `apps/fido/`
rows**, demonstrating no application-source change in that scope.

There are nevertheless **four firmware changes**: boot/main/tasks wrapper
sources and the UF2 artifact. In particular, tasks includes the `DeviceStore`
store-type change. This is not an empty firmware diff or proof that wrapper,
platform, or dependency changes cannot affect FIDO. The historical baseline
classification rests on direct A/B assertions, not diff-stat alone.

At historical CURRENT `e274a0d`, the archived stat had the same four paths
and text counts but UF2 `740864 -> 790016 bytes`. The current quote above
uses `797696`, not that older value. No suite was rerun at `7ca3502` during
this task; later HEAD and uncommitted WIP remain outside the historical A/B
validation.

## Durable evidence and limits

The eight original extracted logs (87,474 bytes total) are retained in the
local archive; all eight were byte-compared with the baseline evidence. No
bulk gate logs or binaries were added.

This task runs documentation checks only: no test suites, firmware/code
changes, hardware sign-off, or commits. Existing WIP is preserved.
The [FIDO report](fido-suite-report.md) retains its history with an appended
reference. The S-721-4 acceptance is the verdict of record
under the user-approved 2026-09-17 substitutions recorded in the introduction.

---

# gpg generate GENERAL — verdict (S-723-A1, 2026-09-19)

**Verdict: candidate C1 confirmed.** The failing layer is **opcard reply sizing /
the fapico2 dispatcher seam** — the card returns the full GET DATA 0x6E response
(270 B data + SW 9000) regardless of the request's Le, with no `61XX`/GET
RESPONSE chaining. gpg 2.4.4's scd reads 0x6E with short Le = 256 and allocates
exactly `le + 2` = 258 bytes (`/tmp/gnupg-2.4.4/scd/apdu.c:2927`:
`result_buffer_size = le < 0? 4096 : (le + 2)`), so the 272-byte reply is
truncated mid-TLV and the SW the card actually sent is discarded; the bytes at
offset 256..257 of the response body are read as the SW (`sw=0300`). scd's
`does_key_exist` (`scd/app-openpgp.c:3669-3672`) maps that read failure to
`GPG_ERR_GENERAL` — "error reading application data" — which g10 prints as the
user's `key generation failed: General error` (EPIC F3).

The C firmware's 0x6E body fits in 256 B (~243 B: RSA-2k 6-byte attrs, DE
directly under 6E), so gpg never trips this on C hardware. The Rust tree's 0x6E
is 270 B (Ed255/X255 attrs, 7F74 GFM, DE inside 73) — over the boundary by 14 B.

## Verbatim scd log excerpt (fresh scdaemon session, first command = GENKEY)

```
2026-09-19 11:22:08 scdaemon[1390831] DBG: chan_9 <- GENKEY --force OPENPGP.1
2026-09-19 11:22:08 scdaemon[1390831] DBG: send apdu: c=00 i=CA p1=00 p2=6E lc=-1 le=256 em=0
2026-09-19 11:22:08 scdaemon[1390831] DBG: PCSC_data: 00ca006e00
2026-09-19 11:22:08 scdaemon[1390831] DBG:  response: sw=0300  datalen=256
2026-09-19 11:22:08 scdaemon[1390831] error reading application data
2026-09-19 11:22:08 scdaemon[1390831] operation genkey result: General error
2026-09-19 11:22:08 scdaemon[1390831] DBG: chan_9 -> ERR 100663297 General error <SCD>
```

Every other DO read in the same session succeeded with `sw=9000`
(4F, 5F52, C4, C0, C1, C2, C3, 7F74, 5E); **only 0x6E fails**, and it fails
identically on every read (6 occurrences in the session) — the truncation is
deterministic, size-driven, not state-dependent.

## Candidate outcomes

| # | Candidate | Outcome | Evidence |
|---|---|---|---|
| C1 | Response-size / GET RESPONSE mechanics on 0x6E | **CONFIRMED** | 0x6E reply is 270 B data + SW (272 B) vs Le=256; scd's `le+2` buffer truncates at 258 → `sw=0300` (payload bytes misread as SW) → `does_key_exist` fails → `error reading application data` → `GPG_ERR_GENERAL` (log above). `apps/openpgp/src/device_shell.rs` hands opcard's reply straight to the dispatcher: opcard's `Reply::expand` (`vendor/opcard/src/card/reply.rs:24-34`) documents that "the MoreAvailable and GET RESPONSE mechanisms are handled by apdu_dispatch" — the upstream `apdu-dispatch`/`vpicc` layer opcard normally runs under (which does 61XX splitting at `vendor/opcard/src/vpicc.rs:151`) is exactly the layer the fapico2 shell replaces and does not implement it |
| C2 | GENKEY reply → scd parse failure | Not reached (masked by C1); reply shape verified correct at dispatcher level | `gpg_generate_sequence_roundtrip` (host, `apps/openpgp/tests/dispatch.rs`) asserts GENERATE `00 47 80 00 02 B6 00` → 9000 + `7F 49 22 86 20 <32 B>` on both keyless and P7-C5-shaped cards — green |
| C3 | Host-side stale card/reader state | **RULED OUT** | The GENERAL reproduces on a completely fresh chain every run: fresh relay + fresh emulation process (keystore deleted) + freshly spawned scdaemon, first command GENKEY. `gpg-connect-agent killscd`/pcscd restarts are therefore not the fix |
| C4 | PW3/admin-verify path divergence | Not reached; no evidence of involvement | does_key_exist runs before verify_chv3 and fails first; C4 would surface as 6982/63CX, not GENERAL (EPIC F3) |

## How the reproduction was driven (host, no hardware)

The emulation binary's CCID is a TCP client (`127.0.0.1:35963`, C-emulation
framing). To let host gpg 2.4.4's scdaemon reach it without a real USB reader
(this host has no libccid card-driver DB — S-721-2 note) a minimal PC/SC shim
library was built and pointed at via `scdaemon.conf`:

```
disable-ccid
pcsc-driver /tmp/s723/libfapico2pcsc.so
reader-port fapico2-emul
debug-level expert
log-file /tmp/s723/scd-run.log
```

The shim (`/tmp/s723/pcsc-shim.c`) implements the SCard* surface scd's
`apdu.c` resolves (SCardEstablishContext/Connect/Reconnect/Status/
GetStatusChange/BeginTransaction/EndTransaction/Transmit/…), bridges each
SCardTransmit 1:1 to the length-prefixed CCID socket (reset byte `0x04` → ATR
`3B DA 18 FF 81 B1 FE 75 1F 03 00 31 F5 73 C0 01 60 00 90 00 1C`), and reports
protocol T=1. It caps replies at the recvlen scd passes — which is precisely
`le + 2` for short-Le GET DATA, faithfully reproducing scd's buffer contract
(a real reader/pcscd would either truncate the same way or error; no
standards-conformant card sends 272 bytes for Le=256). Transport chain:
`scdaemon` → shim → `tests/harness/ccid_relay.py` (pico-fido2 harness, port
35970↔35963) → `fapico2-emulation` → platform `Dispatcher` → `OpenPgpApp` →
opcard.

Commands (GNUPGHOME=/tmp/s723/gnupg):
`cargo build --bin fapico2-emulation --no-default-features --features emulation --target x86_64-unknown-linux-gnu`,
then `scdaemon --multi-server` (standalone, fresh each run) +
`gpg-connect-agent -S <scd socket> 'GENKEY --force OPENPGP.1'`.

`gpg --card-status`/LEARN fails the same way on this host path (every 0x6E read
truncates), which also predicts the hardware symptom: after the >64 B CCID
reply chunking fix reaches the board, scd's LEARN will still fail until C1 is
fixed at the card side — LEARN reads 0x6E too.

## Fix direction for S-723-A2 (recorded, not implemented)

Either (a) the platform layer (`apps/openpgp/src/device_shell.rs` or
`fapico2_platform::dispatch`) caps non-SELECT responses at Le and emits the
residue via `61XX`/GET RESPONSE (INS 0xC0) chunking — matching what the
upstream apdu-dispatch/vpicc layer opcard expects (`vpicc.rs:151`) — or (b)
opcard honors Le in `get_constructed_data`. (a) is the layer that owns the
contract per opcard's own comment; either fix must keep GENERATE's 37 B reply
intact (37 ≤ 256, no chunking needed).

# C-firmware vs opcard parity table (transcribed from EPIC S723-REPAIR, spot-checked 2026-09-19)

| Topic | C firmware (`pico-fido2/src/openpgp/`) | opcard (`fapico2/vendor/opcard/src/`) | Impact |
|---|---|---|---|
| Empty-card attribute DOs | Factory default **RSA-2048** `01 08 00 00 20 00` always returned (do.c:282-288 `algorithm_attr_rsa2k`, do.c:433-438 fallback `parse_algo`) | Defaults **Ed255/X255/Ed255**, always returned (types.rs:321-325/381-385/441-445; data.rs:614-645 fallback) | gpg generates per the advertised alg (F1) — C drives gpg into RSA (the US-413 wedge); fapico2 drives gpg into ECC. **Spot-check: verified verbatim.** |
| PUT DATA attribute validation | Validated against supported algorithms (`openpgp_algorithm_attr_supported`, cmd_put_data.c:69-76 → `SW_WRONG_DATA` 6700) | Parse-only (closed-list); accepts RSA-2048 though generation is compiled out (data.rs:1144-1189) | Real gap → S-723-A3 (fail-closed gate; C uses 6700, A3 fixes with 6A80 — divergence recorded). **Spot-check: verified verbatim.** |
| Unknown GET DATA tag | `SW_WRONG_P1P2` **6B00** (cmd_get_data.c:28-32) | `KeyReferenceNotFound` **6A88** (data.rs:459-461) | Probe-tolerance risk, low → divergence register |
| 25519/Ed255 GENKEY reply | N/A — C has no 25519; always uncompressed-`04` EC point (openpgp.c:1514-1531) | `7F 49 22 86 20 <32 raw>` (gen.rs:362-369) — spec-correct for djb curves | gpg handles both (F2); C-shaped readers will not. A1: reply verified 9000 + 37 B at dispatcher level |
| INTERNAL AUTH gating | 6982 unless `has_pw2` (P2≠0x81) **or `has_pw3`** (cmd_internal_aut.c:25-27, openpgp.c:1129-1135) | 6982 unless P2=0x82 verify; no PW3 bypass (pso.rs:246-249) | P7-C6's 6982 is expected behavior in both; only the PW3 bypass diverges. **Spot-check: verified verbatim.** |
| Key Information (DE) placement | Directly under 6E (do.c:463, EF_KEY_INFO in the 6E fids list) | Inside 73 (data.rs:294-307) | Cosmetic for gpg — but contributes to the 0x6E size delta below |
| **0x6E response size** | **~243 B** (fits short Le=256): 16 B AID, 6-byte RSA-2k attrs | **270 B** (Ed255 10 B + X255 11 B attrs, 7F66, 7F74, DE inside 73) → **over gpg's short-Le buffer by 14 B** | **THE S-723-A1 defect (C1)** — see verdict above. New row surfaced by A1's reproduction |
| Empty-card `47 81` read | 6A88 (cmd_keypair_gen.c:142-145) | 6A88 (gen.rs:247-252) | None — identical. **Spot-check: C side verified verbatim.** |
| C keygen architecture | Blocking `mbedtls_rsa_gen_key` inline in the superloop, no timeout (cmd_keypair_gen.c:77, SDK main.c:142-154) — the US-413 wedge | trussed-delegated, async executor | Rust avoids the wedge for curves; RSA compiled out entirely (F7) |
| gpg POST-GENKEY fingerprint write-back | C accepts PUT DATA C7/C8/C9 (20 B) + CE/CF/D0 (4 B) | opcard PUT DATA accepts C7/C8/C9 and CE/CF/D0 (PutDataObject list, data.rs:815-841) but **rejects the composite C5/CD with 6A88** | A1 note: scd's `store_fpr` writes per-key tags only (app-openpgp.c:926-933), so gpg's flow does not hit this; raw-APDU scripts writing C5 will. Low risk → register |

## Fix (S-723-A2, 2026-09-19) — Le-honoring + 61XX/GET RESPONSE at the app seam

The upstream `vpicc` `ResponseBuffer` semantics were ported to the layer the
shell replaces: `apps/openpgp/src/device_shell.rs` now stages opcard's full
composed reply in the existing scratch buffer and serves it per exchange —
at most the request's Le bytes, `61XX` (remaining count) while more is
pending, GET RESPONSE (INS 0xC0) drains the rest (`run`/`serve`; the staged
reply is dropped on `deselect`/`mark_dirty`). ISO parses short Le `0x00` and
an absent Le alike as 0; both are served as max-256 (gpg's GENERATE is a
case-3 APDU — CRT `B6 00` is Lc data, no Le — whose 37-byte reply is expected
in full, and scd reads `6100` as Le = 256). Behavior is otherwise
byte-identical to the pre-fix card for every reply that fits Le. Tests:
`oversized_6e_chunks_per_le`, `fitting_reply_answers_9000_in_one_exchange`,
and the `apdu_read`-driven `gpg_generate_sequence_roundtrip{,_keyed_card}`
(`apps/openpgp/tests/dispatch.rs`). End-to-end: host gpg 2.4.4 GENKEY against
the emulation binary completes — "key generation completed" (see the A2
report). OpenPGP pytest failure set unchanged (186, byte-identical).

## Fix (S-723-A3, 2026-09-19) — fail-closed algorithm-attribute gate (PUT DATA)

opcard's `put_alg_attributes_sign/dec/aut` (`vendor/opcard/src/command/data.rs`,
local vendor patch per locked decision 3) now check the parsed algorithm against
`ctx.options.allowed_generation` (`ensure_alg_allowed`, after parse, **before any
state write**) and reject a non-allowed algorithm with
`Status::IncorrectDataParameter` (**6A80**) — locked decision 2. This mirrors the
C reference's `openpgp_algorithm_attr_supported` gate (cmd_put_data.c:69-76),
which answers **6700**; the SW-code difference is a recorded divergence (this
row), not a defect — 6A80 is the ISO-correct "incorrect data parameter" for a
malformed/un-servable DO value. The device build has zero opcard RSA features,
so with the ECC-only generation contract (locked decision 1) the card can no
longer be driven into the C-firmware RSA wedge class (US-413) via `gpg
--card-edit` keyattr or any raw PUT DATA. Tests (`apps/openpgp/tests/dispatch.rs`,
no-rsa feature set): `put_rsa_attr_rejected_6a80` (6A80 + stored C1 unchanged —
fail closed), `put_ecc_attr_still_accepted`, `read_pubkey_never_6a81_without_key`
(READ PUBLIC KEY contract, F7: attrs say X ⇒ INS 47 P1=81 returns 9000 or 6A88,
never 6A81 without a key).

**Consequence for the C pytest suite (supersedes "failure set unchanged" above):**
the historical 186-failure baseline (`.superpowers/sdd/
pytest-failed-postatr-2026-09-15.txt`) is **no longer byte-identical** — the
delta is the deliberate contract change, not a regression. New baseline:
`.superpowers/sdd/pytest-failed-postatr-2026-09-19-s723a3.txt`
(206 failed / 310 passed / 566 skipped):

- **31 newly failing** — all RSA-attribute contract tests (`test_keyattr_set_*`,
  `test_keyattr_change_*`, RSA2k import/keygen personalization, and their
  in-suite cascades, e.g. `test_ds_counter_0`, `test_kdf_put_none`): the C-suite
  harness `cmd_put_data` PUTs the C-firmware RSA-2k attribute (`01 08 00 00 20
  00`) and now correctly receives 6A80 instead of the pre-A3 9000 (F8 gap).
- **11 baseline failures now passing** (`test_keygen_1/2/3` in 014/016 kdfnone,
  `test_ds_counter_1`, rsa2k keygen variants): previously the suite set RSA
  attrs (accepted, F8) and generation then answered 6A81 — with the gate the
  attrs stay ECC and generation succeeds, so the keygen rows turn green. The
  6A80-vs-6700 SW difference does not affect gpg (scd maps both to a keyattr
  failure).

**UPDATE 2026-09-20 (S-731-2 review adjudication, DARK-BOOT-1 fix wave):**
baseline **212 failed / 304 passed / 566 skipped** supersedes
`pytest-failed-postatr-2026-09-19-s723a3.txt` (206/310/566) — verbatim
capture at HEAD `7f4959c`. The delta is exactly 6 flipped tests
(`test_000_initial_card::test_key_attributes_1/2/3`,
`test_091_reset_attr::Test_Reset_ATTRS::test_keyattr_reset_1/2/3`) and is
**environmental, not a firmware regression**: the emulator card fixture is
session-scoped and the keyattr tests themselves mutate the C1/C2/C3
algorithm attributes, so the initial-check/finalize rows drift with
in-suite state; no OpenPGP-path code changed since the s723a3 image
(`9ad16bb..7f4959c` touches only platform `secure_store.rs`, firmware
`tasks.rs` and python), and the failure set was verified byte-identical at
clean HEAD `409642f` (full-suite run after `git stash`, per
`.superpowers/sdd/fix2-report.md`), reproduces identically across runs
with cleared `/tmp` emulator state, and is invocation-order dependent
(root-of-repo vs `tests/` cwd shifts the cascade set). Canonical gate
invocation for future captures: `pytest openpgp/ -q` from
`pico-fido2/tests` (the CI pytest-gate cwd), fresh `/tmp/fapico2_*` state.

---

# P7-C6 script artifacts + standing instructions (S-723-B1, 2026-09-19)

The P7-C6 ceremony script (`tests/scripts/p7_c6_openpgp.py`) shipped three
defects that contaminated the cycle's recorded evidence (phase-7 ladder P7-C6,
hardware-matrix Row 1, the S-721-5 acceptance — all marked superseded,
append-only). The script is repaired; the rows below are the durable
mechanism notes and standing instructions for future scripts.

## S-723-B1-1 — INTERNAL AUTHENTICATE P2 semantics + the missing `has_pw3` bypass

**Error signature / mechanism:** INTERNAL AUTHENTICATE (INS 0x88) returned
`6982` after a successful PW1 verify and was mis-recorded as an "EdDSA
limitation". Root cause: the card tracks the two PW1 verification contexts
independently — P2=0x81 is PW1-for-signing (gates PSO:SIGN), P2=0x82 is
PW1-for-authentication/decryption (gates INTERNAL AUTHENTICATE and PSO:DEC).
A P2=0x81 verify does not satisfy INS 0x88. Parity note on top of that: the C
firmware (`pico-fido2/src/openpgp/cmd_internal_aut.c:25-27`) additionally
accepts a PW3 (admin) verification as a bypass (`has_pw3`); opcard
(`vendor/opcard/src/command/pso.rs:246-249`) requires the P2=0x82 verify only
and has no PW3 bypass.

**Standing instruction:** every future script/gpg flow must VERIFY PW1 with
P2=0x82 before INTERNAL AUTHENTICATE (and P2=0x81 before PSO:SIGN). The
opcard `has_pw3` bypass absence is a recorded divergence, not a defect to fix
in this epic.

## S-723-B1-2 — GET DATA tag byte-order trap (P1 = high byte)

**Error signature / mechanism:** `00 CA C1 00 FE` (tag in P1) addresses tag
`0xC100` — unknown → `6A88` regardless of card state — and one P7-C6
observation read that as "empty card". opcard composes the tag big-endian
from the P1/P2 pair: `Tag = u16::from_be_bytes([p1, p2])`
(`vendor/opcard/src/types.rs:581-585`), so tag 0xC1 must be sent as
P1=0x00, P2=0xC1; with Le=254 the literal APDU is `00 CA 00 C1 FE`.

**Standing instruction:** GET DATA helpers take the tag as P2 (single-byte
tags) or P1=tag-high/P2=tag-low (multi-byte); never pass a bare tag byte in
P1. The repaired script pins the literal bytes in its `--self-test`.

## S-723-B1-3 — Unknown GET DATA tag SW: C answers 6B00, opcard answers 6A88

**Error signature / mechanism:** for an unknown tag the C firmware returns
`SW_WRONG_P1P2` 6B00 (`cmd_get_data.c:28-32`) while opcard returns
`KeyReferenceNotFound` 6A88 (`vendor/opcard/src/command/data.rs:459-461`).
Scripts written against C semantics misread opcard's 6A88 (and vice versa)
as "wrong P1/P2" instead of "unknown tag", and — as P7-C6 shows — a 6A88 on
a *key-dependent* DO read can be mistaken for "no key".

**Standing instruction:** probe scripts must not infer card state from an
unknown-tag SW: 6A88/6B00 on a probe only means the tag bytes were wrong or
the DO is absent. Attribute DOs (C1/C2/C3) are NOT key-dependent and always
return 9000 + attribute bytes; treat any 6A88 on them as a script bug.

## S-723-B1-4 — 25519/Ed255 GENKEY reply shape (no C-firmware precedent)

**Error signature / mechanism:** opcard's GENERATE reply for 25519/Ed255 is
`7F 49 22 86 20 <32 raw bytes>` (`vendor/opcard/src/command/gen.rs:362-369`)
— spec-correct for djb curves. The C firmware has no 25519 support and
always emits uncompressed `04`-prefixed EC points
(`pico-fido2/src/openpgp/openpgp.c:1514-1531`), so C-shaped readers will not
parse the raw form.

**Standing instruction:** new tooling that parses GENERATE replies must
accept the raw-32-byte form for djb curves; do not "fix" opcard toward the
C shape (gpg 2.4.4's scd handles both). Pin the shape in dispatcher-level
tests (`gpg_generate_sequence_roundtrip`).

## S-723-B1-5 — Key Information (DE) placement: under 6E (C) vs inside 73 (opcard)

**Error signature / mechanism:** the C firmware places the Key Information
DO directly under the 6E response (`do.c:463`); opcard embeds it inside the
73 construction (`vendor/opcard/src/command/data.rs:294-307`). Cosmetic for
gpg, but it changes the 0x6E body size (one input to the S-723-A1/C1
response-size defect) and breaks byte-diff tooling written against C
transcripts.

**Standing instruction:** raw-APDU scripts must navigate the TLV tree rather
than hard-coding offsets into the 6E response; size-sensitive readers
(gpg's `le + 2` buffer) are covered by the A2 Le-honoring/61XX fix at the
app seam.

## S-723-B3-1 — fingerprint DO packing: all three fprs in C5; C6 zeros; C7 6A88

**As-read on hardware (P7-C7, 2026-09-19):** opcard answers GET DATA **C5**
with **all three** fingerprints packed in the 60-byte DO (sign/enc/auth,
20 B each — keyless it is 60 zero bytes); **C6** answers 60 zero bytes;
**C7** answers `6A88` **even with keys present**. The C reference
distributes the fingerprints over C5(=C7 alt)/C6/C7 (`do.c` per-key DOs),
so scripts written against C semantics expect one fingerprint per tag and
will misread opcard's answers. gpg 2.4.4 reads **C5** only — no functional
impact (verified: `--card-status` renders all three keys + keygrips from
the C5-packed DO).

**Standing instruction:** future scripts read C5 for fingerprints (all
three, 20 B each, in sign/enc/auth order); do **not** infer key presence
from C6 (always zeros) or C7 (`6A88` with keys present). Key presence is
observable via C5's non-zero bytes or READ PUBLIC KEY (`00 47 00 81`).

## P7-D2-1 — U2F/CTAP1 register attestation signature fails python-fido2 client verify

**As-read on hardware (P7-D2, 2026-09-20, image `53ba915e…`, Device 106):**
the CTAP1 U2F register **succeeds on device** (key_handle 32 B, public_key
65 B, sig 71 B, cert 319 B; one store slot consumed), but python-fido2
1.2.0's `RegistrationData.verify()` raises
`fido2.attestation.base.InvalidSignature` — the attestation self-signature
over app_param‖challenge‖key_handle‖user_public_key does not verify against
the response certificate's public key. This is an **interop gap in the
CTAP1 path**, first exercised in P7-D2 (`tests/scripts/p7_d2_fido.py`); no
earlier evidence cycle ran the CTAP1 attestation verify. **CTAP2 paths are
unaffected**
(P7-C2/C3 makeCredential/getAssertion signatures verify with python-fido2).
**The soak leg is unaffected** (`tests/scripts/soak_24h.py` checks the UP
bit + counter and the credential-key signature, never the attestation).
The row-2 re-pin verdict therefore rests on strict `get_info()` PASS +
register-on-device evidence (no corrective re-register — one-register-max;
the U2F `authenticate` leg was not re-run this cycle). This reinforces the
**stateless-U2F key-handle follow-up** (C parity: `derive_key(appId)`,
`pico-fido2/src/fido/cmd_register.c:74`), at which point the attestation
path gets rewritten anyway.

**Standing instruction:** do not add `reg.verify()` (attestation check) to
U2F acceptance bars on this firmware; verify U2F via the authenticate
response (UP bit, counter, credential-key signature) as the soak does. If
CTAP1 attestation interop matters later, fix the signing data / cert in the
firmware's U2F register path and re-verify with python-fido2.

## P7-D2-2 — OpenPGP C4 middle byte (RC retries) reads 0; gpg shows "PIN retry counter : 3 0 3"

**As-read on hardware (P7-D2, 2026-09-20, image `53ba915e…`, factory-fresh
nuked+reflashed board):** GET DATA C4 → `00 7f 7f 7f 03 00 03` — PW1
retries 3, **RC (reset-code) retries 0**, PW3 retries 3; `gpg --card-status`
renders `PIN retry counter : 3 0 3`. The C firmware's as-read factory value
was `03 03 03` (P7-C7) — the RC-retry accounting differs from C. **Nothing
gated:** no ceremony step exercises the RC path (passwd uses PW1/PW3; RESET
RETRY COUNTER uses the PW3 + P1=02 route), and every PIN op behaved
correctly across the whole P7-D2 cycle (generate, sign ×2, passwd ×2, wrong
probe `63C2`, reset-retry `9000`), before AND after the replug. Recorded as
a divergence, not a defect gate; revisit against the nuke path if RC
support is ever added.

**Standing instruction:** scripts asserting factory C4 expect `03 0X 03`
with the RC byte as-read (0 on this image family); never gate on the RC
byte, and never probe the RC path to "test" it — one wrong-PIN probe max
remains the rule for PW1 only.

## P7-D1-1 — sticky FIDO `0x34 PIN_AUTH_BLOCKED` survives power cycles

**As-read on hardware (P7-D1, 2026-09-19, image `f8d92bd5…`):** the FIDO PIN
probe answered CTAP2 **`0x34 PIN_AUTH_BLOCKED`** (not a wrong-PIN `0x32`)
on **Device 091 pre-cycle** and **again on Device 092 post-cycle** after the
plain replug — the block **survives a power cycle**. This contradicts the
CTAP2.1 model in which `PIN_AUTH_BLOCKED` clears on power cycle; it
interacts with the **persisted `pin_state.blocked` field**
(`apps/fido/src/device_keystore.rs:387`, part of the durable keystore
snapshot), which is the prime suspect for the stickiness. **Nothing else
gated:** row-2 PIN-gated re-verification (setPIN/token, credMgmt,
largeBlobs, authnrCfg) is blocked by this row and stands deferred — the
P7-C2/C3 evidence for those ceremonies remains the record; FIDO state was
left untouched (one probe, no retries).

**Standing instruction:** treat `0x34` as a persistent device state, not a
session state — do not script "replug to clear the PIN block" recovery
steps, and do not re-probe the PIN expecting the power cycle to clear it.
Root cause is **open**, ledgered as an S-731-1 follow-up (determine whether
`pin_state.blocked` persistence is correct CTAP2.1 behavior for this block
class or a set/clear-path defect); revisit before any PIN-gated
re-verification cycle.

---

# ADR — ECC-only generation contract (S-723-C1)

**Decision:** on-card RSA generation stays **out of scope** for fapico2.
Enabling `rsa2048-gen` would require trusted-rs/trussed RSA mechanism
support in the fapico2 backend plus mbedtls/RSA flash+RAM math against the
3,670,016 B size gate — and would re-open the US-413 wedge history (the C
firmware's blocking `mbedtls_rsa_gen_key` inline in the superloop is the
documented cause of that wedge).

**Consequence (the contract):** generation is ECC-only (Ed25519/CV25519) by
decision, not omission. With ECC attributes advertised, gpg generates
whatever the card advertises (F1 — verified end-to-end on hardware,
P7-C7: three-key ECC `gpg --card-edit generate` PASS). RSA requests arrive
only via explicit keyattr changes (PUT DATA attribute DOs), which the
S-723-A3 fail-closed gate now rejects with `6A80` before any state write.
Recorded here rather than re-litigated; a future RSA epic would carry its
own size-gate evidence.

**Evidence anchors (what a future RSA proposal must supersede — verified
2026-09-19, S-723-C1):**
- **Mechanism support:** the device build enables opcard with **zero**
  features (`apps/openpgp/Cargo.toml:17` optional dep, `:49`
  `device = ["dep:opcard", …]`); `AllowedAlgorithms::default_gen()`
  includes RSA_2048 only under `#[cfg(feature = "rsa2048-gen")]`
  (`vendor/opcard/src/card.rs:362-379`), and the no-`rsa`
  `gen_rsa_key`/`read_rsa_key` stubs answer `FunctionNotSupported` (6A81)
  (`vendor/opcard/src/command/gen.rs:201-209, 425-432`). There is no
  trusted-rs/trussed RSA mechanism wired into the fapico2 backend — the
  feature flag alone would not make generation work.
- **Size-gate context:** post-S-723 text segment is 426,660 B against the
  3,670,016 B ceiling (recorded in the S-723-A3 note of the EPIC); the
  gate is policy headroom, not imminent exhaustion — but mbedtls RSA-2048
  keygen is the most flash+RAM-expensive operation in this stack, and its
  cost profile is exactly what wedged US-413.
- **Wedge history:** the C firmware ran `mbedtls_rsa_gen_key` blocking,
  inline in its superloop with no timeout
  (`pico-openpgp/src/openpgp/cmd_keypair_gen.c:77`),
  producing the CCID T1 timeout documented in
  [`fapico2/docs/tasks/us413-hardware-e2e.md`](us413-hardware-e2e.md). A
  future RSA epic must bring: a trussed RSA mechanism design, a measured
  size-gate delta (`check_size_report.py` before/after), a non-blocking
  keygen shape, and its own hardware re-run evidence.

This ADR is referenced from the S-723 EPIC's root-cause section and the
C-vs-Rust parity table (both in
[`EPIC-s723-gpg-keygen-repair.md`](../../../docs/tasks/EPIC-s723-gpg-keygen-repair.md)).

---

# SF-1 — device keystore capacity + durable-ack latch (SOAK-FINDING-1, S-731-2, 2026-09-19)

**Identity:** the 24-h soak (round 4 of 288, log `soak_20260919_d1.log`) — every
CTAPHID reply of the FIDO app, CBOR *and* MSG including read-only `getInfo`,
answered `CTAPHID ERROR 0x01 INVALID_COMMAND` persistently across fresh CIDs;
CCID apps unaffected.

**Mechanism (verified on host, `apps/fido/tests/soak_finding_1.rs`):** the
device keystore snapshot (`fido.keystore.v1`) rides the chunked layer
(`platform/src/secure_store.rs::chunked`), so the binding constraint is the
`Rp2350SecureStore` **16-entry slot cap** under the chunked rewrite's
transient old+new generation (`other_slots + old_parts + new_parts ≤ 16`;
each part is ≤ 512 B, the store's per-slot value cap — a U2F register costs
251 snapshot bytes). With the soak board's occupancy (9 slots: `fido.hkey`
+ OATH/OpenPGP/migration) the **6th U2F register exactly exhausts the bound
(16/16) and the 7th cannot be made durable**. The push was nonetheless
accepted (`DeviceKeystore::store_credential` had no capacity check), the
failing persist left `dirty` latched forever, and the US-425/427
durable-before-ack gate answered every command — reads included — with
`ERROR/INVALID_COMMAND` instead of a real response.

**Fix (rounds 1–3, capacity layer reverted per DARK-BOOT-1):** three layers,
all host-tested:

1. **Capacity stays 16 (DARK-BOOT-1):** the review-round-2 store-headroom
   bump (`DEV_MAX_ENTRIES` 16 → 32) was **hardware-rejected** and reverted:
   its +36,288 B bss growth (three `PARTITION_IMAGE_MAX`-sized image
   buffers growing 9,100 → 18,188 B each + the `[Slot; 32]` store static)
   moved `MSPLIM` — which the bootrom lays out at the bss end — up by
   exactly that delta and shrank the main stack region from ~127 KiB to
   ~85 KiB; the boot path overflowed it (STKOF) and the board dark-locked
   (LED solid ON, no USB enumeration, on a freshly nuked flash). Verified
   discriminator chain: the pre-fix image boots; the identical fix code
   with 16 entries boots (Device 104, 2026-09-19); only the 32-entry image
   dark-boots. RAM is the binding constraint (statics 439 KiB of the
   520 KiB — no room to buy the stack back), so **16 entries is a
   hardware-pinned ceiling** and capacity is owned entirely by layers 2+3
   below. Flash-downgrade consequence: a partition image with more than 16
   entries (e.g. written by the rejected 32-entry build) is all-or-nothing
   RESET by this build (`from_partition_image` refuses
   `n > DEV_MAX_ENTRIES`) — moot after a factory reset, but
   flash-downgrade flows lose every secret rather than restoring partially.
2. **Transactional mutations (round 1 + round 2):** every growth mutation
   (`store_credential`, largeBlobs commit, config RP-id lists, vault
   enroll) and the U2F-auth / getAssertion **signature-counter bumps**
   verify the resulting snapshot still persists **before** committing
   (`store_credential_checked` / `grow_checked` /
   `bump_credential_counter_checked`, serialize-ahead against the actual
   store); on persist failure the mutation rolls back and no un-persistable
   dirty state survives. U2F-register overflow answers clean `WrongData`
   (6A80), CTAP2 makeCredential overflow answers `KeyStoreFull` — **0x28
   per the CTAP2 error table** (the task brief's "0x05" is a spec slip;
   0x05 is CTAP1_ERR_TIMEOUT_NOT_SUPPORTED). A reverted counter bump means
   the reply signs the durable counter — the per-credential counter never
   regresses after a reboot. The persist gate itself is untouched.
3. **Self-cleaning rewrite (round 2):** `write_chunked` deletes the parts
   it wrote when a part write fails (best effort). Part keys are
   generation-independent (`<key>.p<b><NN>`, gen lives in the value), so
   pre-existing behavior on ANY write failure was to leave orphaned parts
   that every retry overwrites in place while part 0 (the commit marker,
   written last) permanently needed a fresh slot the orphans denied it —
   one transient-occupancy failure made the logical slot unwritable
   forever. The cleanup returns the store to its pre-write occupancy; the
   previous complete generation in the other buffer is never touched.

**Established capacity (host tests, 16-entry store):** every durable
keystore persist is a chunked rewrite, and a chunked rewrite transiently
holds BOTH generations (`write_chunked` writes the new generation into the
other buffer, part-0 commit marker last), so the rewrite-time constraint is
`other_slots + old_parts + new_parts ≤ 16`; steady state afterwards is
`other_slots + parts ≤ 16`. This applies to **counter bumps too** — they
rewrite the snapshot like any other mutation (an in-place same-buffer
rewrite is forbidden by the double-buffer commit-marker discipline: a torn
one would destroy the last complete generation). When the transient does
not fit, failures are clean and retryable, never a latch: growth mutations
reject (U2F WrongData 6A80 / CTAP2 makeCredential `KeyStoreFull` 0x28) with
no orphans and a normal getInfo afterwards; counter bumps revert and sign
the durable counter (never regresses). Measured points: at 8 other slots a
7-credential keystore is 4 parts — steady state 12/16, the counter bump's
transient is exactly 16/16 and stays durable, and the 8th register (needing
a 5th part, 17 > 16) rejects cleanly
(`authenticate_counter_bump_stays_durable_at_soak_occupancy`); at 11 other
slots the 5th register is already the overflow
(`u2f_register_overflow_rejected_cleanly_and_does_not_latch`,
`mc_occupancy_limited_overflow_maps_key_store_full`). Soak relevance
(register-once, DARK-BOOT-1): one U2F credential is 1 part, so the soak
occupancy is 10/16 and every round's counter-bump transient is 11/16 —
headroom for the whole 288-round run. A per-round-register soak is
impossible at ANY capacity (288 leaked non-resident credentials ≈ 73
parts).

**Standing instruction / known limits:** U2F registrations are stored
`resident: false` (`apps/fido/src/u2f.rs` "finding 8") — they are invisible
to credMgmt, so slots consumed by U2F registers can never be freed by a
client; the only recovery is CTAP2 Reset (or reboot-wipe of the slot
family). The practical capacity is therefore a **handful of U2F
registrations**; at capacity a register answers U2F WrongData (6A80) and
makeCredential answers CTAP2 0x28 — clean, never a latch. The durable fix
that removes U2F slot consumption entirely is **stateless U2F key
handles** — the C reference derives the key handle from the master key and
the appId (`derive_key(appId)`,
`pico-fido2/src/fido/cmd_register.c:74`), storing no per-credential state
— recorded as the future firmware fix; the soak's register-once +
authenticate-only leg (`tests/scripts/soak_24h.py`) is the operational
workaround. Other apps' slot growth after a FIDO register narrows the
transient bound further; growth mutations re-verify against the actual
store at mutation time, so they reject cleanly rather than latch.
Residual, stated precisely: the pin-lifecycle mutations (the pin-blocked
flag, setPIN/retry/minPin-length changes), vault UNENROLL and some credMgmt
paths still mark dirty plainly and rely on the gate's rewrite, so a persist
failure there CAN still latch the gate — the latch window is
`other_slots + 2·parts > 16` (e.g. 9 other slots + a 4-part keystore,
reachable on a U2F-register-heavy board), and the checked growth/counter
paths never enter it; the store itself never degrades (self-cleaning
rewrite). The dispatcher bridge path (`App::process`, store not
bound) keeps
the legacy mutate-and-mark-dirty behavior and relies on the platform
persist gate after dispatch — FIDO over CCID is not an exposed surface in
this firmware. Tests:
`authenticate_counter_bump_stays_durable_at_soak_occupancy`,
`u2f_register_overflow_rejected_cleanly_and_does_not_latch`,
`mc_occupancy_limited_overflow_maps_key_store_full`,
`mc_rk_overflow_maps_key_store_full`,
`registrations_below_capacity_persist_and_round_trip`.

## US-1010 amendment (2026-09-29) — the `≤ 16` arithmetic above is superseded

Everything above is a record of the 16-entry store and is **kept as the
history it is**. It is not the current arithmetic, and reading it as current
is what this amendment exists to prevent. Three numbers moved:

| | as written above | now | why |
|---|---:|---:|---|
| `DEV_MAX_ENTRIES` | 16 | **24** | US-715 final raise, hardware-verified 2026-09-21 (16 → 32 dark-booted; 24 is the hardware-pinned ceiling) |
| `chunked::MAX_PARTS` | not stated | **12** | US-1010 |
| chunked logical bound | not stated | **5,952 B** (12 × 496) | US-1010 — **not** the 8,432 B (17 × 496) the code and docs carried |

**The defect US-1010 found.** `MAX_PARTS` and `DEV_MAX_ENTRIES` were
independent literals and nothing anywhere compared them. A chunked rewrite
writes the new generation into the buffer *not* holding the current set and
retires the old buffer's parts only afterwards, so the rewrite-time
constraint is `other_slots + old_parts + new_parts ≤ DEV_MAX_ENTRIES`. With the
values the tree actually carried — `MAX_PARTS = 17`, `DEV_MAX_ENTRIES = 24` —
the maximum-width rewrite needed `2 × 17 = 34` entries against 24 and returned
`SecureStoreError::Full`. The `MAX_LOGICAL_LEN` of 8,432 B quoted in
`secure_store.rs`, the OATH module docs, the FIDO keystore docs, the README
and this file's own neighbourhood was therefore **a documented capacity the
device never served**. `platform/src/secure_store.rs` now carries
`const _: () = assert!(2 * MAX_PARTS <= DEV_MAX_ENTRIES, …)`, and
`platform/tests/chunked_store.rs` asserts it at runtime against the real
constants (it names `rp2350::DEV_MAX_ENTRIES`; it does not restate `24`).

**`MAX_PARTS` is now 12, not lower, and `DEV_MAX_ENTRIES` was NOT raised.**
12 is the *largest* value that satisfies `2 × MAX_PARTS ≤ 24`, and it is free:
the store static is `[Slot; DEV_MAX_ENTRIES]` and `MAX_PARTS` is not a type
parameter anywhere, so lowering it changes no allocation and no image byte
(measured: `bss` 420,476 B before and after; `text` −20 B). Raising
`DEV_MAX_ENTRIES` instead would cost 568 B of sealed partition image **and**
~580 B of bss *per entry*, on a build with **zero unallocated RAM** — which is
the same MSPLIM constraint that hardware-rejected the 32-entry build. The
capacity consequence is therefore owned by the layers above, exactly as
DARK-BOOT-1 concluded, and the `grow_checked` / `store_credential_checked` /
`bump_credential_counter_checked` discipline described above still holds with
`16` replaced by `24`.

**What the ceiling actually is, measured.** The rewrite *peak* binds before the
byte count does, which is why byte arithmetic gets this wrong twice.
`apps/oath/tests/oath_capacity.rs` measures the OATH table end to end
on the real `Rp2350SecureStore`: a maximal record is 182 B, 30 of them are
5,460 B = 12 parts (11 × 496 = 5,456 is 4 B short). The 31st is 5,642 B, which
**fits** the 5,952 B byte bound and is **still 12 parts** — it does not need a
13th. What stops it is the peak of the double-buffered rewrite, which holds the
live generation and the one being written at once, plus the one entry this app
keeps outside the chunked table (the US-1030 seal high-water mark). The 30th is
reachable because it is the first credential to reach 12 parts and reaching
them rewrites *from* 11: `11 + 12 + 1 = 24 ≤ 24`. The 31st is a same-width
`12 → 12` rewrite: `12 + 12 + 1 = 25 > 24`.

**Current capacity, stated once:**

- **OATH: 30 maximal credentials** (measured; the `MAX_CREDS = 68` in
  `oath_core.rs` is a `heapless` table bound, never a capacity claim). Less
  whatever the other resident slots take from the same 24 — boot entropy,
  `fido.hkey`, the FIDO keystore, the OpenPGP stream.
- **FIDO resident: `DEVICE_MAX_CREDS = 12`**, unchanged — its own keystore is
  ~4.1 KB worst case (12 credentials + a 1,024 B large-blob array) = 9 parts,
  which still fits 12.
- **The latch window** quoted above as `other_slots + 2·parts > 16` is
  `other_slots + 2·parts > 24` today. The *mechanism* — plain
  `mark_dirty` paths relying on the gate's rewrite, versus the checked growth
  and counter-bump paths — is unchanged and still exactly the right
  description of what is and is not latched.

Tests added: `chunked_rewrite_peak_occupancy_fits_the_device_store`,
`max_width_chunked_rewrite_succeeds_on_the_device_store`
(`platform/tests/chunked_store.rs`); `the_documented_credential_ceiling_is_the_
measured_one`, `the_ceiling_is_the_double_buffered_rewrite_peak_not_the_steady_
state`, `the_ceiling_is_a_property_of_the_device_store`
(`apps/oath/tests/oath_capacity.rs`).

---

# US-713 (POLISH-PUB) — OATH SEND_REMAINING decision points (2026-09-21)

## OpenPGP vendor INSes 0xCE / 0xF1 / 0xF2 — documented divergence, no port

**Decision:** the C OpenPGP app's vendor-specific INSes
(`pico-fido2/src/openpgp/`, INS 0xCE/0xF1/0xF2) are **not** ported to the Rust
OpenPGP app. gpg/scd never sends them (vendor probes only), so porting expands
the APDU surface for no interoperability gain. Raw-APDU scripts probing them on
fapico2 get `6D00` (INS not supported) — the correct "no such command" answer,
not a misparse. Default disposition: documented divergence.

## OATH 0xA5 with nothing pending — 6985, not the C transport's silent empty 9000

The C registers `cmd_send_remaining` (`src/fido/oath.c:1150`) as a stub: the
61xx chunking lives in the SDK transport (`pico-keys-sdk/src/apdu.c`
`apdu_next`/`apdu_limit_response`; chunk cap `USB_BUFFER_SIZE(2048) −
CCID_MSG_DATA_OFFSET(10) − 2` = 2036 B; SW2 = remaining count when < 256,
`0x00` at 256 or more; any non-continuation command resets
`response_pending`). A 0xA5 reaching the C app answers an empty `9000` and
silently kills the stream. US-713 implements the mechanism at the app seam
(the CALC ALL body is re-derived per 0xA5 from the slot table — a pure
function of table + P2 + challenge; ~272 B static state, no response buffer)
and answers **6985** for 0xA5 with nothing pending: an explicit protocol
error for YKOATH hosts instead of the C's empty-OK. OATH LIST keeps the
US-705 overflow error SW (0x6A84) for oversized bodies — that contract is
pinned by `oversized_list_reports_error_sw_not_truncation` — while CALC ALL
chunks (the story-scoped flow).

## Physical-button user presence (US-702) — fail-closed on hardware; read path hardware-pending

US-702 (owner-decided) gates management WRITE_CONFIG and the device-wide
RESET (US-711) on a physical button press, C parity. The C reads the
BOOTSEL button via the QSPI-CS trick (`pico-keys-sdk/src/button.c`
`picok_get_bootsel_button`: Hi-Z the QSPI SS pad, sample, restore). The
first Rust wiring polled SIO GPIO1 (an unconnected header pin) — hardware
verified 2026-09-21 as always-6985. The committed read performs the C's
trick with the **RP2350** pad-CTRL layout (OEOVER at bits 14:15 — the
RP2040 layout, 12:13, is a different field, and `embassy-rp` 0.10's own
`bootsel` magic `0x2000` also encodes the RP2040 layout). Even with the
corrected offset, hardware presses were still not detected on the Pico 2
(2026-09-21, multiple press loops) — per owner decision this is **super-low
priority and left for future work**. Consequences until it lands:

- WRITE_CONFIG / INS 0x1E factory reset answer `6985` on hardware (fail
  closed — no host process can reconfigure or wipe the token silently).
  Host/emulation flows are unaffected (presence auto-ack via `#[cfg]`).
- Hardware evidence that writes config (e.g. the hardware-matrix row-5
  marker flow) cannot run until the button read works; the boot/persist
  path itself is hardware-verified (READ_CONFIG serves the persisted
  marker verbatim on the US-715 24-entry image).

## US-919 manifest slot — dedicated secure-store record, not a v3 header field

US-919 (EPIC `security-hardening`) words the last-known-good firmware-manifest
hash as persisted "at every successful boot" in a "store header". The
implementation stores it as a **dedicated secure-store slot**
(`boot.fwmanifest.v1`, `platform/src/fw_manifest.rs::SLOT_FW_MANIFEST`), the
same deviation US-918 took for `boot.entropy.v1` (commit `757dab3`): the
record rides the sealed format-v3 store image, so it is authenticated by the
v3 AEAD tag (an attacker re-flashing the slot region cannot forge it — the
unseal refuses), it is stamped through the same compare-then-program persist
gate as every other slot, and the store-image format never churns. Same
property the header field wanted, at no format cost.

Related documented choices on the same story:

- The manifest region covers the running image from `0x10000000` through
  `__sidata + (__edata - __sdata)` (cortex-m-rt 0.7.6 `link.x` layout
  symbols) — vector table, PICOBIN IMAGE_DEF, `.text`, `.rodata`, and the
  `.data` init image — capped structurally at the secure-partition origin
  (`0x103F0000`, `memory.x SECURE`), whose content is boot-mutable store
  data and must never enter the hash. Verified in the built ELF
  (2026-09-24): region end `0x100677FC`, 414 KiB.
- The wipe execution is the compile-time knob `foreign-image-wipe`
  (`firmware/Cargo.toml`): release/device default builds wipe; dev and
  emulation builds (`--no-default-features`) run the decision + hash + log
  only. The decision function itself
  (`fapico2_platform::fw_manifest::foreign_image_decision`) and the
  `SecureStore::wipe_all` primitive are unconditional.

## US-944 — Brainpool P-512r1 not implemented; offline-premise deviation (bp256/bp384 fetched with network)

Date: 2026-09-26. Two divergences from the epic's and US-944's stated
premises, recorded per the story's scope decision (controller + laya
consultation; user unavailable):

1. **Brainpool P-512r1: no `bp512` crate exists in the Rust ecosystem
   (checked 2026-09-26, crates.io API: "crate `bp512` does not exist").**
   Hand-rolling P-512r1 field/point arithmetic was rejected on
   security-conservatism grounds. `Mechanism::BrainpoolP512R1` is therefore
   not implemented and will not be advertised — US-945/946 gate
   `AllowedAlgorithms` accordingly, and P-512r1 requests fall through the
   backend to Core and error. P-256r1 and P-384r1 are fully served by the
   new `vendor/trussed-brainpool` crate (`bp256`/`bp384` 0.14.0).
   **US-945 update (2026-09-26):** `BRAINPOOL_P256R1` and
   `BRAINPOOL_P384R1` joined the `AllowedAlgorithms` defaults
   (`default_gen()`/`default_import()`, behind the `brainpool-backend`
   feature), so the P-512r1 carve-out is now *enforced by the defaults*,
   not just by backend absence: `BRAINPOOL_P512R1` is never in the default
   set, and a PUT DATA of a P-512r1 attribute (ECDSA or ECDH spelling, any
   slot) is refused with 6A80 by `ensure_alg_allowed` before any state
   write. Pinned by `put_brainpool_p512r1_and_unknown_oid_rejected`
   (virt) and `put_brainpool_attr_device_path` (device path) in
   `apps/openpgp/tests/`.

   > **US-966 update (2026-09-27) — P-384r1 has joined P-512r1, so the
   > "P-256r1 and P-384r1 are fully served" sentence above is now historical.**
   > It is left in place so a reader can see exactly what shipped between
   > US-944 and US-966. P-384r1 is **deferred to a follow-up release**; the
   > "US-966 — Brainpool P-384r1 deferred" entry below is the current
   > statement. P-256r1 remains fully served.
   >
   > One test name moved: the virt test
   > `put_brainpool_p512r1_and_unknown_oid_rejected` was renamed
   > `put_never_served_brainpool_curves_and_unknown_oid_rejected` in US-966,
   > because it now refuses both never-served curves rather than one.
2. **The epic's "no network" gate premise did not hold.** Network was
   available, and `cargo fetch` pulled `bp256 0.14.0` and `bp384 0.14.0`
   into the cargo cache in a single sanctioned deviation (2026-09-26, via a
   throwaway scratch project; the cache already carried
   `trussed-core 0.2.3`). Every repo build/test after that fetch ran with
   `--offline`. The brief's alternative branch ("divergence recorded, no
   partial backend lands") therefore did not trigger — the backend landed
   with the P-512r1 carve-out above.

## US-950 — advertisement-vs-reality sweep: P-521 prehash length, GET CHALLENGE cap, PSO:ENCIPHER factory-PIN asymmetry

Date: 2026-09-26. The US-950 honesty pass fixed the headline mismatch
(`GET DATA FA` listed every algorithm of every slot, including ones the
card refuses with 6A80). The story's requirement 4 asked for a focused
sweep for the rest: three further items were examined and all three are
recorded below, none of them fixed in this story. (The two things US-950
did fix belong to requirements 1 and 3, not to the sweep — the `GET DATA
FA` filter and the stale mechanism-scope comment in
`platform/src/trusted_backend/mod.rs`. An earlier draft of this paragraph
said "four items ... two fixed, two recorded", which did not match the
three items below.)

> **Amended 2026-09-26.** Item 1 below (P-521) was re-investigated and the
> finding is **withdrawn** — it was not a defect. Items 2 and 3 stand as
> written.
>
> **⚠ Amended 2026-09-27 (US-970) — the sweep found a fourth item, and
> requirement 4 was not met until now.** The paragraph above says "three
> further items were examined and all three are recorded below". That was
> true of what US-950 examined, and it is kept. But US-950 requirement 4
> asked for a sweep of this class to be **fixed or recorded**, and a fourth
> item — `PSO:CDS` returning raw `r‖s` rather than DER for ECDSA — was found
> later, during the US-969 hardware run, recorded only in
> `docs/tasks/evidence/us969-publish/item2-4-ecc-curves.{py,txt}` and
> `docs/tasks/us953-publish-acceptance.md`, and **never entered this
> register**. It is now **item 4** below. **Four in-code comments** across two
> files — `platform/src/trusted_backend/mod.rs` (the mechanism-scope and
> factory-card paragraphs) and `platform/src/trusted_backend/dispatch.rs`
> (the `BACKENDS` doc comment and the `Backend::Brainpool` variant doc) —
> still claimed Brainpool P-384r1 was served, which US-966 made false; those
> were corrected by US-970 in the same pass. With both done, US-950
> requirement 4 is met on its "**fix or document**" branch, and the honest
> reading is that it was **not fully met at the time the epic closed** — the
> sweep was incomplete, not wrong.

### 1. P-521 PSO DSI length — INVESTIGATED, CLAIM WITHDRAWN (not a defect)

**Status: the original finding in this section was wrong and is withdrawn
(2026-09-26).** No follow-up story is needed. The reasoning and the
measurement that disprove it are kept below so the claim is not
accidentally re-raised.

`AllowedAlgorithms::default_gen()` includes `P_521`, and since US-950
`GET DATA FA` advertises `P-521` (both the ECDSA and ECDH spelling),
`PUT DATA` of a P-521 attribute is accepted on C1/C2/C3 with 9000, and
GENERATE on the SIG slot answers 9000. That much of the original entry
was right.

**What was wrong.** The original entry claimed:

> A P-521 field element is 66 bytes, and a conformant OpenPGP host does not
> send 64 (521 is not a multiple of 8, so GnuPG additionally prefixes the
> leftmost-bits count). **So a host driving a P-521 key exactly as the spec
> requires gets 6985 on every PSO operation.**

Both halves of that are wrong.

**(1) The 64-byte gate is a *digest-length* table, not a field-element
gate.** `vendor/opcard/src/command/pso.rs:100-141` gates on the length of
the hash paired with each curve, and every constant is exactly that hash's
length:

| arm | gate | hash paired with the curve |
|---|---|---|
| `EcDsaP256` / `EcDsaBrainpoolP256R1` / `EcDsaSecp256k1` | 32 | SHA-256 |
| `EcDsaP384` / `EcDsaBrainpoolP384R1` | 48 | SHA-384 |
| `EcDsaP521` / `EcDsaBrainpoolP512R1` | 64 | SHA-512 |

The PSO:DECIPHER / INTERNAL AUTHENTICATE arms
(`decipher_key_mecha_uif` / `int_auth_key_mecha_uif`, `(Mechanism::P521Prehashed, 64)`,
`pso.rs:~262`) use the same digest-length constant.

**(2) The spec says the *host* sends the hash and the *card* pads.** OpenPGP
card spec V3.4.1 §7.2.10 (PSO: computational data, DSI):

> The DSI consists of the hash value which was calculated (32, 48 or 64
> bytes, dec.). If the required DSI for the computation is longer than the
> hash value, then the DSI is filled with leading zero bits by the card.

So a conformant host pairing P-521 with SHA-512 sends a **64-byte** digest
and the card zero-pads it to 66 internally. A 66-byte DSI is not a legal
input at all. The card's gate is the conformant one; widening it to 66
(and 67) would *break* every conformant host.

**(3) The "leftmost-bits" rationale conflated two different things.** The
MPI bit-count prefix GnuPG emits belongs to the OpenPGP *signature packet*
(`r`/`s` as MPIs), not to the PSO:SIGN DSI field, which is a fixed-size
byte string. It has no bearing on what a host puts in the PSO command data.

**Measurement** (re-run 2026-09-26 on the virt path, scratch probe, not
committed; personalized PINs, P-521 SIG attribute, key generated by
GENERATE on CRT B6, public key read back with READ PUBLIC KEY and used
host-side as the `p521` ECDSA verifying key):

| PSO:SIGN DSI input | SW | signature length | verifies as `ECDSA(Prehashed)` against the card's own read-back public key |
|---|---|---|---|
| 63 B | 6985 | — | — |
| **64 B** | **9000** | **132 (raw `r ‖ s`)** | **yes, 6/6 (1 + 5 further signings over distinct digests)** |
| 65 B | 6985 | — | — |
| 66 B | 6985 | — | — |
| 67 B | 6985 | — | — |

The 64-byte path produces genuine, cryptographically valid P-521
signatures over exactly the digest the host sent. 66 bytes — the field
element width the original entry wanted the gate widened to — is refused.

**One deliberate, non-actionable narrowing remains**, and it is not the
defect the original entry described: the card is **hash-agnostic**. It
enforces the digest length but does not check *which* hash was used, so a
host that paired P-521 with a hash other than SHA-512 (say SHA-256, 32
bytes) would be refused with 6985. That is not a legal P-521 configuration
— P-521 is defined over SHA-512 — so there is nothing to fix and nothing to
advertise differently.

### 2. Extended Capabilities advertises a 1024-byte GET CHALLENGE; the card accepts 4096 (under-advertising — safe, left alone)

`EXTENDED_CAPABILITIES` (`vendor/opcard/src/command/data.rs`) declares
`0x04 0x00` = "Max GET CHALLENGE: 1024", but `get_challenge` guards on
`MAX_GENERIC_LENGTH` (`vendor/opcard/src/state.rs`) = 4096. This is the
safe direction — a host that believes the advertisement never asks for more
than the card promised — so it is recorded, not changed. Changing the DO
would alter a wire value gpg reads, which is a bigger call than this story
should make.

**The feature bits, re-audited against the spec text (US-957).** The earlier
pass took the "every bit is backed by an implemented command" claim from the
C firmware's *comment* (`../pico-openpgp/src/openpgp/files.c:49-60`), which is
not evidence. US-957 re-derived each bit from **OpenPGP card specification
v3.4.1 §4.4.3.7 "Coding of byte 1 of Extended Capabilities"** (page 32 — the
"Extended Capabilities / Coding of byte 1" table was read out of the spec
PDF, not paraphrased from another implementation) and checked each against
opcard. `0x7F` = `0b0111_1111`, so `b8` is clear and `b7..b1` are set:

| bit | mask | v3.4.1 §4.4.3.7 meaning | opcard evidence | verdict |
|---|---|---|---|---|
| b8 | `0x80` | Secure Messaging supported | `GET DATA 7F66` byte is `00` = "no SM or proprietary implementation" | **honest** (clear = unsupported) |
| b7 | `0x40` | Support for GET CHALLENGE | `command.rs:87` dispatches `GetChallenge(length)` → `get_challenge` | **honest** |
| b6 | `0x20` | Support for Key Import | `command/private_key_template.rs` `put_private_key_template` (PUT KEY, INS DB); exercised by the RSA/ECC import tests | **honest** |
| b5 | `0x10` | PW Status changeable (DO C4 available for PUT DATA) | `command/data.rs:965` `Self::PwStatusBytes => put_status_bytes(...)` | **honest** |
| b4 | `0x08` | Support for Private use DOs (0101-0104) | `command/data.rs:181-184` `PrivateUse1..4`; GET at `:372-378`, PUT at `:935-936` (0101/0102) | **honest** |
| b3 | `0x04` | Algorithm attributes changeable with PUT DATA | `put_alg_attributes_sign/dec/aut` (`data.rs:960-962`), C1/C2/C3 | **honest** |
| b2 | `0x02` | PSO:DEC/ENC with AES | `command/pso.rs:517` `decipher_aes` (AES-CBC, zero IV, no padding) and the encipher arm at `:537`; pinned by the US-950 AES roundtrip tests | **honest** |
| b1 | `0x01` | KDF-DO (F9) and related functionality available | `command/kdf.rs` `validate` (PUT F9), `data.rs:371` GET F9; pinned by `kdf_do_put_validation_and_roundtrip_virt` | **honest** |

**All seven set bits are honest under v3.4.1.** The byte is therefore *not*
changed — it is also the C-reference value, and changing it is a
compatibility decision for the maintainer, not an honesty pass.

**One correction to the review brief.** The review asserted that `0x08` (bit 3)
is "FN/FC forgotten by D PIN and KDF algorithm not supported", and that this is
the unsatisfied bit. That wording is from the **OpenPGP card 2.0** Extended
Capabilities definition, not v3.4.1. In v2.0 that bit meant FN/FC + KDF; in
v3.4.1 the bit was reassigned to "Support for Private use DOs (0101-0104)"
and a *new* `b1` was given to "KDF-DO (F9) and related functionality
available". Verified against the spec text, not from memory: opcard has no
FN/FC concept at all (no C3/C4 *name* DOs — in 3.4.1 C3/C4 are the
authentication algorithm-attribute and PW-status DOs, and the name DO is
`5B`; no `forget` / `fn_status` / `fc_status` anywhere in `vendor/opcard/src/`),
but that absence is **irrelevant to this byte**, because under 3.4.1 no bit
advertises FN/FC. The `b1` KDF bit is honest on its own terms: after the
US-947 revert the card still stores, validates and returns the KDF-DO
(`command/kdf.rs`), which is exactly "KDF-DO (F9) and related functionality
available"; what it deliberately does *not* do is derive with it, because gpg
derives the KEK client-side (see the `kdf.rs` module comment).

**Two real comment defects (values left alone).** The per-byte comments in
`vendor/opcard/src/command/data.rs` are the C firmware's labels and two of
them do not match the spec's own field names:

- `0x07, 0xF4` is labelled "Max command DO: 2036". Under v3.4.1 §4.4.3.7,
  bytes **05-06** are "Maximum length of Cardholder Certificates (DO 7F21,
  each for AUT, DEC and SIG)".
- the second `0x07, 0xF4` is labelled "Max response DO: 2036". Bytes **07-08**
  are "Maximum length of special DOs with no precise length information given
  in the definition (Private Use, Login data, URL, Algorithm attributes, KDF
  etc.)".

The values themselves are unchanged (the brief forbids touching the byte), and
`0x07F4` = 2036 is a plausible bound for both fields. The labels are recorded
here so the next reader does not propagate them.

**One more comment defect.** `0x00, // Pin block format 2 supported` reads as
an assertion that the card *does* support PIN block format 2. Byte `09` in
v3.4.1 is a **0/1 flag where 0 = not supported**, and opcard implements no
digit-only PIN block format 2 (§4.3.3 is optional), so `0x00` is the correct
*value* and the comment states the opposite. `0x01, // Manage security
environment (MSE) Command supported` is correct: byte `0A` is "MSE command
for key numbers 2 (DEC) and 3 (AUT)", `0`/`1`, and `0x01` matches
`command.rs:89` dispatching to `manage_security_environment`.

### 3. PSO:ENCIPHER is not covered by the US-912 factory-PIN gate (security posture, out of scope)

The US-912 factory-default gate refuses PSO:SIGN, PSO:DECIPHER, GENERATE
and TERMINATE DF while the factory PINs are in force, but there is no
equivalent gate in `pso::encipher`. On a card that has never been
personalized no AES key exists, so PSO:ENCIPHER already refuses with 6985
(the wrapped-key load has nothing to unwrap — pinned by the negative
assertion in `aes_encipher_decipher_roundtrip_virt`); after
personalization the PW1s are no longer factory defaults. So there is no
exposure today, but the asymmetry is real and a future story that imports
an AES key before PIN personalization would open it. Noted, not changed:
adding an authorization gate is a security-behavior change, well outside an
honesty pass.

### 4. `PSO:CDS` returns raw `r‖s` for ECDSA, not DER (found US-969, recorded here by US-970)

**Status: open, recorded, not fixed.** Added to this section on 2026-09-27
because it is in the class US-950 requirement 4 named — *sweep for other
advertisement-vs-reality mismatches and **fix or document them*** — and it was
found in evidence during the US-969 hardware run but **never reached the
register**, which is where this epic's own constraint puts divergences. US-950
requirement 4 was therefore not fully met at the time the epic closed; the
"documented" branch of that requirement is now discharged.

**What is on the wire.** `vendor/opcard/src/command/pso.rs:167` passes
`SignatureSerialization::Raw` to the backend's `client_mut().sign(...)` for
the ECDSA arms. The card therefore returns the signature as the fixed-width
concatenation `r ‖ s` and **not** as a DER `SEQUENCE { INTEGER r, INTEGER s }`.
For a P-256 key that is 64 bytes; a DER encoding of the same signature is
~70–72 bytes. A host that DER-decodes the `PSO:CDS` response fails to parse
it.

**Scope of the deviation.**

| mechanism | returned | affected |
|---|---|---|
| ECDSA — NIST P-256/384/521, secp256k1, Brainpool P-256r1 | **raw `r ‖ s`** | **yes** — every ECDSA curve |
| EdDSA — Ed25519 | raw 64-byte `R ‖ S` | **no** — the OpenPGP card spec mandates the fixed-width form for EdDSA, so `Raw` is the conformant serialization here |
| RSA — PKCS#1 v1.5 | backend-encoded, PKCS#1 `DigestInfo` | no |

The distinction matters: for EdDSA the spec *requires* the concatenated form,
so the same `SignatureSerialization::Raw` call is correct on that arm and
wrong on the ECDSA arms. This is a serialization choice made per-mechanism in
`pso.rs`, not a global one.

**Evidence.** Found and measured on hardware in the US-969 publish run:
`docs/tasks/evidence/us969-publish/item2-4-ecc-curves.{py,txt}` records
`PSO:CDS` returning 64 bytes for both secp256k1 and Brainpool P-256r1, each
signature verified against the card's own public key — the **crypto** is
correct and non-vacuously so; the **encoding** is the deviation. Also named
in `docs/tasks/us953-publish-acceptance.md`.

**Impact.** Any client that DER-decodes `PSO:CDS` fails on every ECDSA curve.
GnuPG is unaffected: `g10/pubkey-enc.c` / `g10/ecdsa.c` read the fixed-width
`r‖s` form for these curves, which is why the US-969 gpg legs pass. This is
the same shape as the full-AID SELECT entry above — gpg interoperates, a
conformant other client does not.

**Fix direction (not implemented; no story has claimed it).** Select the
serialization per mechanism in `pso.rs` — `SignatureSerialization::Der` for
the ECDSA arms, `Raw` for EdDSA — and pin both directions: an ECDSA response
that parses as DER and a tampered one that does not. This is a
wire-behaviour change on a shipped path, which is why it is recorded rather
than done inside a documentation-only story.

## SELECT AID: full 16-byte AID rejected (found 2026-09-27, US-952 hardware)

The platform dispatcher selects apps by **exact byte equality**
(`platform/src/dispatch.rs:139`: `app.aid() == aid`) against the OpenPGP
app's 6-byte registered AID `D27600012401`. Measured on hardware
(`docs/tasks/evidence/us952-boot-hardware/us952-aid-matching.txt`):

| AID presented | SW |
|---|---|
| `D2760001240103040000CA03BAC80000` (full 16, real serial) | `6A82` |
| `D2760001240103040000000000000000` (full 16, zero serial) | `6A82` |
| `D27600012401` (RID+PIX, 6 bytes) | `9000` |
| `D276000124` (RID, 5 bytes) | `6A82` |
| bogus AID | `6A82` |

**Impact.** gpg/scdaemon interoperates because it sends the 6-byte
prefix. A client that SELECTs the full 16-byte AID defined by OpenPGP card
spec 3.4 §4.2.1 — Kleopatra, YubiKey tooling, and anything matching on
the AID the card reports back — receives `6A82` and sees no OpenPGP
application at all.

**Fix direction (deferred, maintainer decision 2026-09-27).** Prefix
matching in `find_app`: a presented AID that starts with a registered
AID should match, with the shorter-registered/longer-presented direction
being the intended one, and unknown AIDs still returning `6A82`. Care
needed that this does not make one app shadow another (e.g. a future
6-byte AID that is a prefix of another app's AID).

## On-card RSA-2048 key generation does not complete; the "RSA keygen proven" evidence is mislabelled (US-958, 2026-09-27)

**Claim being corrected.** Earlier US-953 reporting stated "RSA-2048
on-card keygen: repeated *key generation completed*, sw=9000", citing
`docs/tasks/evidence/us953-gpg-scdaemon-trace-rsa2048-generate.log`. **That
log contains no RSA generation at all**, and the filename is misleading:

- The only GENERATE ASYMMETRIC KEY PAIR CRT identifiers in it are
  `00 47 80 00 02 A4 00` (Ed25519 auth), `00 47 80 00 02 B6 00` (Ed25519
  sign) and `00 47 80 00 02 B8 00` (Curve25519 encryption) — the set is
  exactly `{A4, B6, B8}`. RSA generation would first require the
  algorithm attribute `01 08 00 00 20 00` to be written to `C2`; that byte
  sequence appears **zero** times in the file.
- Every `key generation completed (0 seconds) / sw=9000` line in it has
  `datalen=37` or `datalen=70`, i.e. `7F 49 43 86 41 04 <32|64 bytes>` —
  Ed25519 (37 B) and secp256k1 (70 B). An RSA-2048 modulus is 256 bytes
  and arrives as `7F 49 47 86 41 01 00 …` (~270 B). **37 and 70 bytes
  cannot be an RSA-2048 key.**

**What actually happens on hardware.** With `C2` set to RSA-2048,
`00 47 80 00 02 B8 00` does not return a status word at all: the PC/SC
transaction fails with `0x80100016` (`SCARD_E_TRANSACTION_FAILED`), the
reader's transaction timeout, after ~1750 s in the first attempt. The same
slot with X25519 returns `9000` in 0.09 s (US-958 re-confirmation,
`docs/tasks/evidence/us958-key-slots.txt`). On a 133 MHz Cortex-M33,
on-card RSA-2048 prime generation does not fit in a PC/SC transaction.

**Consistency with the standing ADR.** The S-723-C1 ADR above ("ECC-only
generation contract") already records on-card RSA generation as **out of
scope by decision**, not by omission. This entry does not reopen that
decision; it removes a false positive that implied the capability had
already been demonstrated. **No RSA key has ever been shown to generate on
this hardware.**

> **⚠ SUPERSEDED 2026-09-27 (US-968, then US-969) — measured, not argued.**
> The headline claim of this entry, **"No RSA key has ever been shown to
> generate on this hardware," is false**, and so is the `0x80100016` reading
> underneath it. Re-measured on a *different, freshly nuked* card
> (serial `88B0BD40`, post-deferral build `b639432c`):
>
> | | import | `PSO:DECIPHER` | `PSO:SIGN` | on-card generation |
> |---|---|---|---|---|
> | RSA-2048 | 0.22 s ✅ | 0.615 s ✅ byte-exact | 0.658 s ✅ verified | **90.5 s**, valid key |
> | RSA-4096 | 0.34 s ✅ | 3.861 s ✅ byte-exact | 3.896 s ✅ verified | no result in ~17 min |
>
> US-969 re-measured RSA-2048 independently and agrees to within 0.03 s on
> all three operations (import 0.152 s, decipher 0.621 s, sign 0.637 s).
>
> **The two failure figures above are host-side artefacts.**
>
> * **~1750 s** is `cardedit.py`'s own `overall_timeout` argument. That
>   driver `os.kill(pid, 9)`s its own child, so the number is the harness's
>   patience, not a property of the card.
> * **14.47 s** is a host PC/SC transaction deadline. It recurs *identically*
>   across **two RSA sizes and two curves** — a card-side stall would not
>   reproduce the same figure four times.
>
> Cross-check on the same silicon: `RS-Key/docs/limitations.md:44-63` measures
> RSA-2048 keygen at ~9.7 s on a Waveshare RP2350-Zero.
>
> **What survives from this entry:** the protocol facts, which are correct and
> are the reason the numbers above are reproducible — the PUT KEY extended
> header is `<crt> <ber-length>`; an RSA `READ PUBLIC KEY` is `81`/`82`, not
> `86`; and RSA replies arrive as `61xx` + `GET RESPONSE`. Treating `61` as
> terminal is the most likely origin of the epic's repeated `0x80100016`, and
> is why a working card read as a failing one.
>
> **What does not survive:** the conclusion, and this entry's implicit claim
> that the capability was never demonstrated. It is demonstrated — by import,
> for both use cases, on hardware. Per laya (2026-09-27) `rsa2048-gen` stays
> advertised and the timing is documented rather than the feature set shrunk.
> The S-723-C1 ADR's "out of scope by decision" is a *policy* statement and
> is not reopened by this measurement; what is corrected is the false
> positive this entry was written to remove.
>
> Evidence: `docs/tasks/evidence/us968-rsa-import/`,
> `docs/tasks/evidence/us969-publish/item3-rsa2048-import.txt`.

**This does not contradict US-942.** `docs/tasks/us942-rsa4096-heap.md` found
that RSA-4096 generation *fits the device RAM budget*, with a measured peak of
24,792 B inside the (then 128 KiB) heap. US-942 measured **allocation, not
time**: it asked whether the operation fits in SRAM, and the answer was yes.
This entry measures the other axis — a 133 MHz Cortex-M33 cannot finish
RSA-2048 prime generation inside a PC/SC transaction. Both are true at once,
and a reader must not use US-942 to argue the capability works. A memory fit
is not a timing fit; the second constraint is what this entry reports.
(US-942 is in turn superseded on the *memory* axis by US-956, which re-derived
the heap from 128 KiB to 48 KiB against a measured worst case, and by US-957,
which armed the two workloads US-942 never measured.)

**Consequence for the storyboard.** Any US-9xx acceptance item phrased
"on-card RSA-2048 key generation" is **FAIL**, not "already proven", and
must cite this entry rather than the `rsa2048-generate` log. This includes
the `Scenario: RSA keygen and use via gpg` block in
`docs/tasks/EPIC-crypto-completion.md` (US-953), which was written against
the plan and does not describe what happened.

## A reflash does not clear the flash-resident persistent store; a stale store hangs the boot before USB enumerates (US-952/953, 2026-09-27)

**Observed.** The OpenPGP card state lives in the RP2350's **NOR flash**
(`boot::SECURE_PARTITION` and the secure-store partitions at `0x103f0000`),
not in RAM. A `.uf2` reflash rewrites the firmware image and **does not**
touch it. A store left behind by an earlier session therefore survives the
reflash intact, and a card carrying a stale store **hangs during boot before
USB ever enumerates**: LED steady on, device absent from the USB bus, so
`pcscd` never lists the reader and there is no shell to probe. The same
binary, flashed a second time over that same card, **boots reliably only
after a nuke** (`nuke_universal.uf2`).

**Why this is worth its own entry.** The failure mode is indistinguishable
from the RAM bug US-956 fixed. Both present as "the board dark-locks", both
present as "a green build that will not boot", and a reflash appears to fix
one of them. The distinguishing observation is the **order**: the RAM bug
fails on a *factory-fresh* card as well, whereas the stale-store hang
disappears with a nuke. Diagnosing this in the wrong order wastes a
hardware cycle per attempt.

**Consistent with** `docs/tasks/openpgp-pw3-change-rootcause.md:254` — the
same operator log records it from the other direction: *"Reflash / power-cycle
did **not** wipe card state; only the nuke did. A 'fresh-looking' card after
reflash is not a factory card."* That earlier observation was made while
chasing a PW3 failure and was attributed there to stale probe artifacts; it is
the same flash-residency property, and this entry names the boot-hang symptom
that was not yet known then.

**Operational rule.** After any session that writes card state, or after any
"it won't boot" report, **nuke before flashing** and treat a
reflash-then-boot as unproven. A boot observed on a reflashed-but-not-nuked
card is not evidence that reflashing preserves the store; it may simply be
evidence that this particular store happened to be bootable.

**Not fixed.** This is a property of the flash-resident store, not a defect in
a specific build, and the epic's hardware phase does not change it. Whether a
reflash-time store wipe is even desirable is a design question (it would
destroy card state on every firmware update, which the spec's card-reset
model does not contemplate) — recorded, not decided.

## PSO:DECIPHER X25519: opcard does not strip the RFC 6637 `0x40` format tag (US-958, 2026-09-27) — **CLOSED by US-959**

> **Resolved 2026-09-27 by US-959.** `decrypt_ec` now accepts both the
> RFC 6637 compact form (`40 ‖ X`, 33 B) and the bare 32-byte point, and
> refuses any other length. Full derivation, including why the **reply must
> stay raw** (gpg's scdaemon prepends the tag itself, so a card that tagged
> its own reply would hand `extract_secret_x` 34 bytes and trip its
> `point_nbytes < nshared` guard), which curves are and are not affected, and
> the reproduction on the emulation binary:
> `docs/tasks/us959-x25519-format-tag.md`. The entry below is kept verbatim as
> the record of how the defect was found.
>
> **One correction to the diagnosis above**, found while fixing it: the
> "AES-wrapped-session-key form RFC 6637 mandates" is not a form on the
> OpenPGP path at all. gpg's scdaemon (`scd/app-openpgp.c` `do_decipher`)
> emits only `A6 xx 7F49 xx 86 xx <external public key>` — no session-key DO —
> because the card is an ECDH peer and gpg does the AES keyunwrap in software.
> The US-958 probes that put `wrapped` inside DO `86` were therefore
> exercising a *harness* framing error alongside the real tag defect, and their
> `6A80` does not on its own isolate the tag. The tag defect is real and is
> pinned by `x25519_decipher_accepts_rfc6637_format_tag_{virt,device_path}`
> and by `evidence/us959/x25519-tag-probe-{prefix,postfix}.txt`, which send
> gpg's exact shape.

Found while settling US-958. Distinct from, and much later than, the `6D00`
harness-framing question: with a correctly framed APDU the command
reaches opcard and answers **`6A80`**, so the ECDH cipher-text form gpg
actually sends cannot be deciphered.

`vendor/opcard/src/command/pso.rs:448-455` (`decrypt_ec`):

```rust
let serialized_key = if matches!(mechanism, Mechanism::X255) {
    // There is no format specifier for x25519
    data                     // 86-DO content, format tag still attached
} else {
    if data[0] != 0x04 { ...reject... }
    &data[1..]               // strips the 0x04 tag
};
```

`trussed-0.2.0 src/mechanisms/x255.rs:174` requires exactly 32 bytes:

```rust
if request.serialized_key.len() != 32 {
    return Err(Error::InvalidSerializedKey);
}
```

**Measured on hardware** (RP2350, card `CA03BAC8`, `us958-decipher-plain-ecdh.txt`
and `us958-decipher-0x40-probe.txt`), same X25519 card key, same request,
only the `0x40` tag differing:

| `86` DO content | SW | reply |
|---|---|---|
| `40 <32-byte point>` (RFC 6637 / gpg / opcard's own `tlv.rs:89` test vector) | `6A80` | 0 B |
| `<32-byte point>` (no tag) | **`9000`** | 32 B, **byte-exact** X25519 shared secret |

So the working path is *plain* ECDH; the AES-wrapped-session-key form
RFC 6637 mandates is not implemented. **gpg decryption will fail on this
firmware for this reason** — it is a real interoperability defect, not a
harness artefact. Not fixed here: US-958 is scoped to the `6D00` question
and the brief forbids a firmware fix without a maintainer decision.
Likely fix: drop the format tag in the `X255` branch the same way the
non-X255 branch does (and decide separately whether the wrapped-key form
should be supported at all).

## Pre-boot allocation: partially enforced (US-961, 2026-09-27)

**The invariant.** `platform/src/rsa_heap.rs` installs the one sanctioned
global allocator on the device (a 48 KiB `linked_list_allocator::LockedHeap`
over the fixed `RSA_HEAP` static, backing `trussed_rsa_alloc::SoftwareRsa`).
`rsa`/`num-bigint-dig` allocate with **infallible** `Vec`, so the heap must be
live before the software-RSA path can run, and the only place it goes live is
`crate::rsa_heap::init()` inside `DeviceBackend::boot`
(`platform/src/trusted_backend/device.rs:590-594`).

**What changed.** Before US-938 added that allocator the device build could
not allocate at all, so "nothing allocates before `init()`" was enforced by the
*linker*. Adding a `#[global_allocator]` removed that enforcement: the
invariant was left as a comment. A pre-init allocation is a
`LockedHeap::empty()` → `handle_alloc_error` → `panic = "abort"` — i.e. a dark
boot, with no USB enumeration, indistinguishable on the bench from the
stale-store hang recorded above. `tests/scripts/check_heap_gate.py` (US-961)
now enforces it from source:

1. `rsa_heap::init()` has exactly **one** call site in device source, and it
   is inside `DeviceBackend::boot`;
2. the region of `DeviceBackend::boot` before that call contains nothing but
   non-allocating `assert!`s, attributes and comments — so no constructor call
   can creep above it;
3. `DeviceBackend::boot` has exactly **one** device-path call site
   (`firmware/src/main.rs`), so there is no second boot path that skips the
   init;
4. the heap is actually linked into the release image (`rsa-backend` is in
   `fapico2-platform`'s default feature set and `firmware` does not opt out).

**What is still unenforced — stated, not left ambiguous.** The region of
`async fn main` that runs *before* `DeviceBackend::boot` is not statically
analysed by the gate: it constructs the secure store, decides the boot slot,
derives the store key, checks the firmware manifest, and runs the first-boot
migration, all with a live allocator that is not yet initialised. Any
allocation-capable code added there is a dark boot and CI will not catch it.
The runtime failure mode is also unchanged: an exhausted or not-yet-initialised
heap aborts rather than reporting a recoverable error, and there is no
allocation counter on the device to make it diagnosable.

Closing this properly needs one of: (a) initialising the heap as the first
statement of `#[main]` (before `embassy_rp::init`) and shrinking the
guaranteed-uninitialised window to nothing, or (b) a `#[global_allocator]`
wrapper that reports a *distinct* pre-init signature (an STKOF-style fault or a
defmt record in the RTT ring) instead of aborting anonymously. Both change
device code and neither was in scope for a host-only story, so they are
recorded here as a known gap rather than silently accepted.

## US-962 — the two honesty defects the whole-branch review returned, and what closed them

Both are the class US-950 was chartered to eliminate: **the card advertises
something it cannot deliver.** They were found together because each one makes
the other invisible.

### I1 — a keyless card saying RSA-2048 was left advertising a GENERATE that times out

**Closed by US-962: the S-723 scrub is restored.** Recorded here because the
divergence register is where the measurement already lives, and because S-724's
deletion of the scrub left a comment asserting the opposite of what was
measured.

- **What S-724 claimed.** `7fb66b4` removed the "legacy RSA defaults" scrub
  from `Persistent::load` on the grounds that "RSA generation is served again
  (software-RSA backend) […] GENERATE on it works and must not be silently
  reverted to the ECC defaults."
- **What is measured.** On the RP2350, on-card RSA-2048 `GENERATE` runs into a
  PC/SC transaction timeout — `0x80100016`, `SCARD_E_TRANSACTION_FAILED` —
  after ~1750 s (see the scd log excerpt above). X25519 returns `9000` in
  0.09 s on the same card. The host-side RSA path is fine; the *on-card* one
  is not, and the difference is the whole point.

  > **⚠ SUPERSEDED 2026-09-27 (US-968, re-measured by US-969; recorded here
  > 2026-09-27 by US-970).** The two sentences above are **measured false**
  > and are superseded by the `⚠ SUPERSEDED` blockquote on the entry
  >  *"On-card RSA-2048 key generation does not complete…"* (US-958) in this
  > same file, which the US-968/US-969 measurements already retract. Restated
  >  here so the correction sits beside the claim a reader lands on:
  >  * **On-card RSA-2048 `GENERATE` completes in 90.47 s** on a freshly
  >    nuked card, serial `88B0BD40`, post-deferral build `b639432c`, and
  >    returns a valid key. US-969 re-measured independently and agrees to
  >    within 0.03 s on import, decipher and sign.
  >  * **The ~1750 s figure is not the card.** It is `cardedit.py`'s own
  >    `overall_timeout` argument; that driver `os.kill(pid, 9)`s its own
  >    child, so the number measures the harness's patience. The `0x80100016`
  >    it produced is the **host** PC/SC transaction deadline, the same one
  >    that shows as 14.47 s elsewhere in this register.
  >  * **Therefore "the on-card one is not [fine], and the difference is the
  >    whole point" does not hold.** The difference that is real is between
  >    90 s and 0.09 s — a card that is slow, not a card that cannot deliver.
  >
  > **What survives from this subsection, and why the scrub stays.** The
  > protocol facts, and the *defect class*, not the timing claim. `61xx` + GET
  > RESPONSE handling is the most likely origin of this epic's repeated
  > `0x80100016`; a host that treats `61` as terminal reads a working card as
  > a failing one. The S-723 scrub that US-962 restored remains correct: a
  > keyless card that advertises RSA-2048 is asking a host to attempt a
  > ~90 s transaction the host's own deadline will not survive. The blast
  > radius is unchanged and bounded — the scrub fires only on all-empty slots
  > with `sign_count == 0`, and `rsa_attributes_with_a_key_survive_a_reflash`
  > pins it. **The defect was in the record, not in the behaviour.**
  >
  > Cross-check on the same silicon: `RS-Key/docs/limitations.md:44-63`
  > measures RSA-2048 keygen at ~9.7 s on a Waveshare RP2350-Zero.
  > Evidence: `docs/tasks/evidence/us968-rsa-import/`,
  > `docs/tasks/evidence/us969-publish/item3-rsa2048-import.txt`.

- **Why the false comment was a trap, not a typo.** The fail-closed
  allow-list still accepts the attribute, because `RSA_2048 ∈
  allowed_generation`. So the card kept *accepting* the attribute with `9000`
  while being unable to honour it. A card flashed by the C firmware or by any
  S-724-era image holds `C1/C2/C3 = RSA-2048` with no keys; a host reads that
  as "the card can do RSA", `gpg --card-edit generate` blocks for about half an
  hour and fails, and the only escape is a flash erase that destroys card
  state. Acceptance kept working — which is exactly why the defect was
  invisible to a test that only checks acceptance.

  > **⚠ CORRECTED 2026-09-27 (US-970) — "blocks for about half an hour" is
  > the harness, and "fails" is the host's deadline.** Per the `⚠ SUPERSEDED`
  > blockquote above, the ~1750 s the reader sees here is
  > `cardedit.py`'s own `overall_timeout` argument — the driver kills its own
  > child at that point — and the operation it is describing **completes on
  > the card in 90.47 s**. What a `gpg --card-edit generate` sees from a host
  > with a ~14.5 s PC/SC transaction deadline is a failure at **14.47 s**, not
  > at half an hour. The sentence above is kept because the *shape* of the
  > trap is right and worth keeping: the card accepts an attribute with
  > `9000` and cannot then satisfy what it implies within a typical host's
  > patience. The numbers in it are not.

- **The fix, and its deliberate limit.** The scrub (all three key slots empty
  **and** `sign_count == 0` **and** all three attributes RSA-2048) reverts the
  attributes to the factory ECC defaults and writes the revert back to flash.
  RSA is *not* withdrawn from the allow-list: an operator can still select it
  at run time. A card that holds a key is never touched, so no working key is
  reinterpreted — and that guard is load-bearing rather than decorative,
  because PUT DATA of a usage's algorithm attribute *deletes that usage's key*
  (spec §4.4.3: after the PUT, `READ PUBLIC KEY` on the same Crt answers
  `6A88`), so "all three attributes say RSA and some key is still present" is
  reachable only by importing the key after setting the attributes. That is
  exactly what the C-firmware migration path does, and it is what
  `rsa_attributes_with_a_key_survive_a_reflash` pins.
- **Cost and evidence.** +108 B of `text`, no RAM figure moved
  (`docs/size-report.md`, US-962 table). Covered on both client stacks by
  `apps/openpgp/tests/rsa_attr_scrub.rs`.

### I2 — FA and the dispatch's backend table were wired to different switches

**Closed by US-962: one switch per algorithm group.**

- **What was divergent.** `AllowedAlgorithms::default_gen()`
  (`vendor/opcard/src/card.rs`) is what FA advertises and what `ensure_alg_allowed`
  accepts against. The mechanisms are served by whatever is in front of trussed
  Core in `platform/src/trusted_backend/dispatch.rs`'s `BACKENDS`. Only the two
  Brainpool bits were gated, and they were gated on *opcard's* feature, while
  the backend is wired on *the platform's* — two switches, neither able to see
  the other. SECP256K1, and RSA through the always-on `rsa4096-gen` on the
  opcard dependency edge, were not gated at all.
- **Failure shape.** A build with a platform backend off dropped the variant
  from `BACKENDS` while FA still named the algorithm and the PUT DATA gate
  still answered `9000` (it consults the same allow-list). Every request then
  fell through to trussed Core, which has no such mechanism. US-950's FA test
  could not catch it: it runs on the default feature set, where the two sides
  agree by construction.
- **The mechanism, and why this one.** opcard is a vendored crate and cannot
  read the platform's features, so the coupling has to live in the one crate
  that depends on both — `fapico2-openpgp`. Each of `rsa-backend`,
  `secp256k1-backend` and `brainpool-backend` there enables the platform
  feature (the serving backend) **and** the opcard feature (the advertising
  allow-list bit) together, opcard's `virt` no longer smuggles a backend in on
  the side, and `firmware` selects the groups through the app's switches
  rather than the platform's. P-256/P-384/P-521, Ed25519 and X25519 stay
  unconditional because they are served by trussed Core, which both manifests
  enable unconditionally — there is no configuration in which they could be
  advertised unserved, so there is nothing to couple.
- **Evidence, in both directions.**
  `tests/scripts/check_advertise_serve_coupling.py` builds the production
  configuration *and* a backend-free one and requires FA to match `BACKENDS` in
  each. Measured: production 30 FA records over 10 groups with 6 backends in
  the table; backend-free 12 records over the 4 trussed-Core groups with 3
  backends. The gate was mutation-checked in both directions — restoring
  `Self::SECP256K1` unconditionally turns the backend-free build red with
  `FA advertises=true but the dispatch serves=false`, and dropping
  `secp256k1-backend` from the app's `default` turns the production build red
  for losing a capability. The residual blind spot is recorded rather than
  glossed: nothing stops a *new* algorithm from being added to `default_gen`
  without a backend, only the "no untracked FA record" assertion in
  `advertise_serve.rs`, which fails until that new group is given a row in the
  test's table.

  > **⚠ CORRECTED 2026-09-27 (US-970) — the production figures above belong
  > to the pre-US-966 build and no longer measure.** Re-run of
  > `tests/scripts/check_advertise_serve_coupling.py` on the shipped tree
  > (`fix/openpgp` at `256b8fc`, UF2 `b639432c`, 2,904 blocks) returns:
  >
  > | configuration | FA records | groups | rows in `BACKENDS` |
  > |---|---:|---:|---:|
  > | **default (shipped, post-US-966)** | **27** | **9** | 6 |
  > | reduced (no backends) | 12 | 4 | 3 |
  >
  > The reduced row is unchanged and still correct. The default row moved
  > from **30 over 10** to **27 over 9** because **US-966 removed Brainpool
  > P-384r1** (`f09bc02`), which removed exactly one FA record and one
  > advertised group. Both deferred groups now also **measure** as
  > unadvertised off the parsed reply in both configurations —
  > `BRAINPOOL_P384R1: False`, `BRAINPOOL_P512R1: False` — which is the
  > `DEFERRED_GROUPS` category US-966 added to this gate. The gate is still
  > measuring: it builds two real configurations and both are green, so
  > nothing here has gone vacuous.

## Brainpool and RSA-4096 hardware verdicts; a ~14.5 s host transaction ceiling; `C5` never populated (US-954, 2026-09-27)

> **Adds the hardware-verified status of the two conditionals the US-954
> story's own earlier version left *hardware-unverified*.** The record of
> that deferral is kept in `docs/tasks/us954-brainpool-rsa4096-hardware.md`
> at the foot; nothing above this line is edited. Full derivation and
> evidence index: that document and
> `docs/tasks/evidence/us954-brainpool-rsa4096/`.

### The two conditionals, now measured on the part

| Subject | Hardware verdict | Measured |
|---|---|---|
| **Brainpool P-256r1** | **PASS** — `PUT DATA C1` `9000`, `GENERATE` `9000`, public point read back, `PSO:SIGN` `9000` returning a 64-byte raw `r‖s` signature, **verified against the card's own public key** | gen **0.71 s**, sign **1.15 s** |
| **Brainpool P-384r1** | **PARTIAL** — attributes `9000`, `GENERATE` `9000`, public point read back (97 bytes); **`PSO:SIGN` TIMEOUT** | gen **8.19 s**, sign **TIMEOUT @ 14.47 s** |
| **RSA-4096** | **PARTIAL** — attributes accepted (`GET DATA C1` → `011000002000`); **`GENERATE` TIMEOUT** | attr 0.13 s, gen **TIMEOUT @ 14.47 s** |

This **closes the "hardware-unverified" conditional on both sides** of the
US-954 acceptance criterion: each conditional capability now has a hardware
verdict, and the honest one for two of the three subjects is "generates
(or accepts attributes), and the operation that would prove the crypto times
out on the host".

### A ~14.5 s host-side PC/SC transaction ceiling — hypothesis, unconfirmed

```
Brainpool P-384r1 GENERATE   8.19 s   9000        <- longer, succeeds
Brainpool P-384r1 PSO:SIGN  14.47 s   0x80100016  <- shorter, times out
RSA-4096        GENERATE   14.47 s   0x80100016  <- same value, different algorithm
```

**14.47 s appears identically for two unrelated operations, while a longer
operation on one of them completes.** No per-algorithm slowness explanation
can produce that pattern, because it requires a *slower* operation to succeed
where a faster one on the same card fails. The reading consistent with the
data is a **host-side transaction timeout near 14.5 s**, not the card's
compute.

**Not confirmed, and stated as a hypothesis here.** What would settle it:
raise the PC/SC transaction timeout above 15 s, change nothing else, and
re-run P-384r1 `PSO:SIGN` and RSA-4096 `GENERATE`. Both completing confirms
it; both failing at the same elapsed time refutes it. Until then, **the
card's RSA-4096 and P-384r1 signing performance is unmeasured** — neither
"too slow for the device" nor "fits the device" is established.

> **This reframes, and does not overwrite, the ~1750 s figure in the US-958
> entry above.** Two different failures, and the difference is the evidence:
> the 14.47 s figure recurs across two operations and sits at a plausible
> host timeout, whereas **~1750 s is three orders of magnitude longer on a
> *smaller* key** (RSA-2048 vs RSA-4096), which is what a card-side stall
> looks like rather than a host timeout. The US-958 entry's operational
> conclusion — **no RSA key has ever been shown to generate on this
> hardware** — is unchanged and still stands. A reader should hold both
> records.
>
> **⚠ Standing entry added 2026-09-27 (US-970) — `rsa4096-gen` is
> advertised and has never been observed to complete on the RP2350.** The
> table above records `RSA-4096 GENERATE` as `TIMEOUT @ 14.47 s`, and US-968
> later ran it for **~17 minutes** on a different card with the card never
> becoming reachable again. It is nevertheless **still advertised** —
> confirmed in the FA reply by
> `tests/scripts/check_advertise_serve_coupling.py`, which reports
> `RSA_4096` in C1's advertised set (27 records) with 6 rows in the serving
> table — and per laya (2026-09-27) it **stays** advertised, with the timing
> documented rather than the feature set shrunk. Signing and verification for
> RSA-4096 were achieved by **import** (0.34 s import, `PSO:DECIPHER` byte-exact
> at 3.861 s, `PSO:SIGN` verified at 3.896 s, US-968/US-969), not by
> generation. This is the same asymmetry as `rsa2048-gen` — advertised,
> real, slow — and the residual is the host's transaction deadline, not the
> card. Recorded here as a standing entry because it was previously carried
> only by a Goal blockquote in `EPIC-crypto-completion.md`, and this epic's
> own constraint is that divergences live in this file.

### `GENERATE` never populates the `C5` fingerprint DO — new

**Observed.** After a successful on-card key generation, `GET DATA C5`
returns **60 zero bytes**, and `GET DATA 7F51` answers `6D00`. Measured in
**both** US-953 runs on hardware — including the one where gpg encrypt/decrypt
round-tripped byte-exactly
(`evidence/us953-hw2-kdf-set-vs-unset.txt` step [3] and
`us953-hw2-kdf-result.json`, `"fp20": "0000000000000000000000000000000000000000"`).

**Cause, in code.** `vendor/opcard/src/command/gen.rs` contains no
fingerprint write. The only writer of the fingerprint DO is the host-facing
`put_fingerprint` behind `PUT DATA` on `SignFingerprint`/`DecFingerprint`/
`AuthFingerprint` (`vendor/opcard/src/command/data.rs:952-954, 1291-1305`).
A conformant card computes and stores the fingerprint itself on generation;
this one cannot, and a host that trusts `C5` will read zeros.

**Why gpg is unaffected.** gpg 2.4.4 / scdaemon derived the fingerprints it
displayed host-side, from the `7F49` extended public-key blob that
`GENERATE` returns. That is why a `C5`-less card still works with gpg and
why this gap is invisible to the epic's named acceptance client.

**This corrects a causal claim, and the correction matters.** US-953's first
run attributed gpg's inability to bind a card key (every slot `[none]`) to
this gap. It was not: the gap was present, unchanged, in the later run where
gpg bound a key and round-tripped. What actually differed between the two runs
is whether gpg's own `--edit-card generate` had completed — it had not in the
first run (host-side pinentry/Assuan plumbing stopped it before the `GENKEY`
APDU). Derivation with the evidence: `docs/tasks/us954-brainpool-rsa4096-hardware.md`.

**Not fixed.** Writing the fingerprint on generation is a firmware change
outside the scope of the two stories that found it. Until it exists, treat
`C5` on this firmware as always-zero and derive the fingerprint from the
returned public key.

> **⚠ SHARPENED 2026-09-27 (US-969), on a freshly nuked card — serial
> `88B0BD40`, retry counter `3 0 3` throughout.** This entry's core claim
> **is confirmed**, and the clean store is what makes it provable. Two
> refinements follow, and the second **corrects a statement above**.
>
> **A clean baseline is what this needed.** Before any key existed, the card
> read `C5`/`C6`/`CD` = 60/60/12 **all-zero bytes** and all three slots
> answered `6A88` — an honest "no key here". That zero state is what makes
> the post-generate reading unambiguous
> (`evidence/us969-publish/part1a-c5-baseline.txt`).
>
> **Refinement 1 — `C5` is not *always* zero; it is zero only when no host
> writes it.** `set_key` (`vendor/opcard/src/state.rs:518-602`) writes the
> key, resets the signature counter and saves, and never touches
> `persistent.fingerprints`. But **gpg writes `C5` itself**, deriving the
> fingerprint from the `7F49` blob and issuing a `PUT DATA`. After a
> *gpg-driven* generate, all three slots were correct and matched gpg's own
> report byte-for-byte:
>
> ```
> C5 = 0D9427BD68B0026455106FD5BD559BD712FD0156   (SIG)  == gpg 0D9427BD…FD0156
>      1E9F3A91F250D5D0C45FEF245E8CC8261CA23BDC   (DEC)  == gpg 1E9F3A91…A23BDC
>      8E96A20A1F0990A209F53DE3BEAB6F889FA592EA   (AUT)  == gpg 8E96A20A…92EA
> ```
>
> So the **trigger is precisely "a key was generated without a host
> fingerprint `PUT`"** — a raw `GENERATE` (this story's harness), or any
> migration path that does not re-`PUT`. It is not universal, and it is not
> the `gpg`-driven path.
>
> **Refinement 2 — CORRECTS "Why gpg is unaffected" above. gpg *does* read
> `C5`, and it believes it.** The paragraph above claims gpg "derived the
> fingerprints it displayed host-side, from the `7F49` blob". Measurement
> contradicts that. After a **raw** `GENERATE` in the AUT slot:
>
> ```
> AUT public point before = D419DB95F6287B72BF0DB2E155B57CE4E25BF9081716ACB5DAA78F50F8982D8A
> AUT public point after  = 64D01FA57090665769A06B444D5DDA1600D37FB998A233C7D36B1C5494751B44   <- changed
> C5[40:60] (AUT)         = 8E96A20A1F0990A209F53DE3BEAB6F889FA592EA                            <- UNCHANGED
> gpg --card-status       -> Authentication key: 8E96 A20A 1F09 90A2 09F5  3DE3 BEAB 6F88 9FA5 92EA
> ```
>
> gpg printed the **stale** fingerprint for a key it could not possibly have
> derived from `64D01FA5…`. Worse, once the card's slots had been regenerated
> raw, gpg reproduced the epic's original symptom exactly — on a card whose
> slots demonstrably held keys (`part1c-gpg-card-status-raw-generated.txt`):
>
> ```
> Signature key ....: [none]
> Encryption key....: [none]
> Authentication key: 8E96 A20A …   (stale, and believed)
> ```
>
> This also **resolves the `[none]` mystery** the entry above deferred: the
> `[none]` readings were never store corruption. They are this defect, and
> the two explanations that could not be told apart on the previous card are
> not equally likely — (a) is the real one, and it reproduces on a clean
> card on demand.
>
> **Fix location: `set_key`** (`vendor/opcard/src/state.rs:518-602`), which
> must write `persistent.fingerprints.key_part_mut(ty)` and
> `persistent.keygen_dates` on the `(Some(..), None)` and
> `(Some(..), Some(..))` arms — the two arms that install a new key. Both
> removal paths already clear them (`set_key`'s own `(None, Some(..))` arm at
> `state.rs:534-541`, and `remove_key` at `state.rs:1731`), so the write is
> the only missing half. The write needs the OpenPGP fingerprint of the new
> public key, which is host-side derivable from the `7F49` blob the card
> already has. **Not implemented here** — a firmware change needs its own
> review.
>
> Evidence: `docs/tasks/evidence/us969-publish/part1a-c5-baseline.txt`,
> `part1b-c5-after-generate.txt`, `part1c-gpg-card-status-raw-generated.txt`.

> **✅ FIXED 2026-09-27 (US-972), on the same card — serial `88B0BD40`.** The
> defect above is confirmed, reproduced and closed. Two of the entry's own
> conclusions need correcting, and the second is the interesting one.
>
> **The defect, reproduced first-hand.** Both PINs were confirmed over raw
> APDU in-session before any gpg traffic (`00 20 00 81/82/83` → `9000`,
> retry counter `3 0 3` before and after). A raw `00 47 80 00 02 B6 00`
> returned a fresh point and `C5` did not move:
>
> ```
> GENERATE sign (Ed25519) -> 9000, 37 B: 7F49 22 86 20 3583F585…D34DB39   <- new key
> C5 before : A1CC759D…FA7CEB8C 1825B0F6…522295 92E3845F…18973221
> C5 after  : A1CC759D…FA7CEB8C 1825B0F6…522295 92E3845F…18973221        <- UNCHANGED
> ```
>
> **Correction 1 — "Fix location: `set_key`" is right about the *symptom* and
> wrong about the *placement*.** The refinement above proposes writing
> `key_part_mut(ty)` on the `(Some, None)` and `(Some, Some)` arms. A v4
> fingerprint is `SHA-1( 0x99 ‖ u16be(len) ‖ body )` and the body carries the
> **creation timestamp**, so the card needs it. US-972 measured that it does
> not have it at that moment:
>
> ```
> CD (key generation dates) before = 6AB942F8 6AB942F8 6AB942F8
> CD after a raw GENERATE         = 6AB942F8 6AB942F8 6AB942F8   <- card did NOT set it
> ```
>
> The card sets no date at GENERATE; the *host* supplies it afterwards with
> `PUT DATA CE/CF/D0`. A fingerprint computed inside `set_key` would hash a
> creation date of zero and be **plausible and wrong** — the outcome this
> file has repeatedly called worse than none. So the shipped fix splits the
> work: `set_key` **clears** the slot (a new key can never inherit the
> previous one's fingerprint — the honest intermediate state is "none"), and
> the value is computed in `set_keygen_date`, which runs when the date
> arrives. The card's value and gpg's are then identical by construction,
> whichever arrives first.
>
> **Correction 2 — the packet format is not "host-side derivable from the
> `7F49` blob", and two plausible guesses about it are wrong.** US-972 took
> the ground truth from gpg rather than from the spec draft: generate on the
> card, let gpg `PUT DATA C7/C8/C9`, read `C5` back, and compare against the
> packet in gpg's own keyring. gpg 2.4.4 emits the **RFC 9580** forms.
> Ed25519 is *neither* candidate form — not the historical 34-byte
> `99 22 <32>` and not the 37-byte draft form — but an explicit curve OID
> followed by a `0x40`-prefixed MPI:
>
> ```
> 04 || 6AB942F8 || 16 || 09 2B06010401DA470F01 || 0107 || 40 || <32>   (Ed25519, 51 B)
> 04 || 6AB942F8 || 12 || 0A 2B060104019755010501 || 0107 || 40 || <32> || 03 01 08 07
> ```
>
> And **every ECDSA curve is uncompressed**, `04 ‖ X ‖ Y` — Brainpool P-256r1
> included, measured on the card, so the "compressed for Brainpool and
> secp256k1" guess is disproved rather than merely untested. The
> `03 01 08 07` tail on X25519 is the KDF parameter, present because this card
> advertises no KDF (DO `F1` → `6A88`).
>
> **What shipped.** `vendor/opcard/src/fingerprint.rs` (new): a `no_std`
> SHA-1 and the per-algorithm packet assembler, pinned by ten vectors — four
> **hardware-confirmed** (Ed25519 sign, cv25519 dec, Ed25519 aut, Brainpool
> P-256r1 sign, all read back out of `C5` on `88B0BD40`) and the rest
> **derived** from the same gpg off-card. `state.rs`: `set_key` clears the
> slot; new `set_keygen_date` recomputes it and fails closed when the
> algorithm cannot be reproduced exactly — **RSA is the one that fails
> closed** (`RsaParts` + `trussed_rsa_types` are behind the `rsa` feature, and
> widening a vendored crate's feature surface for it was not worth it), so
> RSA keeps whatever the host wrote. Cost: `+1,532 B` of `text`, **no RAM
> figure moves** (`docs/size-report.md`).
>
> **Not exercised on hardware, and therefore not claimed:** the end-to-end
> behaviour of the *shipped* firmware. The ground truth above was measured on
> the running card, which predates this change; confirming the fix itself
> needs a reflash, which US-972 did not do. The host-side suite is green
> (`apps/openpgp/tests/do_c5_fingerprint.rs`, RED before the fix).
>
> Evidence: `docs/tasks/evidence/us972-c5/`. Story:
> `docs/tasks/us972-do-c5-fingerprint.md`.

> **✅ CONFIRMED FIXED ON HARDWARE 2026-09-27 (US-973), same card — serial
> `88B0BD40`, firmware sha256 `d33f8a92…5aa2b9`.** The paragraph immediately
> above closed the *defect* and left the *shipped firmware* unexercised
> ("Not exercised on hardware, and therefore not claimed"). That reservation
> is now discharged, and the entry moves from open divergence to
> **hardware-confirmed fix**. Four measurements, all over raw APDU with both
> PINs confirmed in-session beforehand and `PIN retry counter` `3 0 3` at the
> start and end of every leg — no PIN attempt was refused anywhere in the
> run, and no flash, BOOTSEL, nuke or factory reset was performed.
>
> **(1) The card computes C5 on its own, and lands on the ground truth.** With
> the card still holding the US-972 Brainpool P-256r1 key, a single
> `PUT DATA CE` carrying **the date the card already held** — so the only
> thing that changes is the recompute — produced:
>
> ```
> US-972 hardware-confirmed Brainpool P-256r1 : 2E1158CA9300E8B72FAE776A2292D775448208A5
> card, recomputing that same key, no host PUT  : 2E1158CA9300E8B72FAE776A2292D775448208A5
> ```
>
> That is the entry's own ground truth, produced a second time by a
> completely different mechanism, and the agreement is exact.
>
> **(2) All three algorithm encodings, from a raw `GENERATE` with no host
> fingerprint `PUT` at all.** Each leg: raw `GENERATE`, read C5, `PUT DATA`
> the date, read C5 again, and compare against a value computed off-card from
> the point the card itself returned.
>
> | slot | algorithm | after GENERATE | after date `PUT` | expected (off-card) |
> |---|---|---|---|---|
> | dec | cv25519 | `0000…0000` | `5DFAC3A8D0729702B6BAFCC1C6F3F02B965B7817` | identical ✅ |
> | aut | Ed25519 | `0000…0000` | `AD8D0051761294FBA03D4E735B7AF40FC1059BA7` | identical ✅ |
> | sign | Brainpool P-256r1 | `0000…0000` | `E1665CCBBC769CEF632425C5C59519759B206EB9` | identical ✅ |
>
> The first column is the entry's own design claim, now measured: **an
> all-zero slot straight after `GENERATE` is correct behaviour, not a
> regression.** `CD` is provably unchanged by the `GENERATE` in all three
> legs, so the date is genuinely absent at that moment and "none" is the only
> honest value. Anyone reading the zeros as a failure would be reading a fix
> that works as designed.
>
> **(3) The migrated-stale case — the worst symptom — is resolved, and gpg
> believes the correction.** The `6C1E238E…/980331B3…/CB0B128F…` value was
> overwritten by gpg's own `PUT` in the last leg of US-972, so the case was
> **reproduced deliberately** rather than inherited: the exact historical
> bytes were written back through `PUT DATA C7/C8/C9` (the same path a
> migration import uses; `PUT DATA C5` itself answers `6A88` on this card),
> and a real GnuPG was asked to read the result.
>
> ```
> after installing the migrated value -- gpg --card-edit list ->
>   Signature key ....: 6C1E 238E D08E 4B06 9256  B634 94DF DA6A 72E8 4CE1
>   Encryption key....: 9803 31B3 6A5D 1575 2610  2197 815B 251A 5AFC 4EFF
>   Authentication key: CB0B 128F 6DEA 635B F5A5  302E E0D0 C263 0946 AD71
>
> after three PUT DATA date commands (dates unchanged; no GENERATE, no PIN) ->
>   Signature key ....: E166 5CCB BC76 9CEF 6324  25C5 C595 1975 9B20 6EB9
>   Encryption key....: 5DFA C3A8 D072 9702 B6BA  FCC1 C6F3 F02B 965B 7817
>   Authentication key: AD8D 0051 7612 94FB A03D  4E73 5B7A F40F C105 9BA7
> ```
>
> Before, a host was displaying a fingerprint that is not the key's. After, it
> displays the true one.
>
> **(4) The strongest form: the card reproduces gpg's bytes after gpg's copies
> are destroyed.** GnuPG generated a fresh Ed25519/cv25519/Ed25519 set and
> wrote its own fingerprints. Those were then **overwritten with `20 × AB`**,
> and the dates the card already held were re-`PUT`:
>
> ```
> C5 as gpg wrote it : 1666bc5c…c5da77 f8201fb4…f5f066 80e739b9…d3a1f
> C5 after 20xAB wipe: abababab…ababab abababab…ababab abababab…ababab
> C5 after recompute : 1666bc5c…c5da77 f8201fb4…f5f066 80e739b9…d3a1f   <- all three AGREE
> ```
>
> Not a copy: the value reproduced was deleted two commands earlier.
>
> **Non-vacuity, because a test that passes against a stale value proves
> nothing.** Three independent ways the comparison could have failed. The
> value moves with its inputs — the sign date set to `DEADBEEF` yields
> `C574A2994BE4E0068BBF7F6273B77E94994240AA`, and restoring the real date
> returns `E1665CCB…`. The host's copy is not what is being read — point (4).
> And every plausible-but-wrong encoding of the *same* key produces a
> *different* fingerprint: hashing a creation date of zero (precisely the
> mistake the fix's design exists to avoid) gives
> `2E7918CBDBD617A6A830C4368D52D9DF10FDF824`; a compressed point gives
> `4A16A884…`; `X` without `Y`, a v3 body, SHA-256, or a missing MPI
> bit-count each give their own distinct value. The test discriminates.
>
> **What is still not claimed.** The four vectors US-972 marked *derived*
> rather than hardware-confirmed (NIST P-256/P-384/P-521, secp256k1,
> RSA-2048) were **not** exercised here; this run covered Ed25519, cv25519 and
> Brainpool P-256r1, the three the card serves and the three US-972 settled
> on hardware. **RSA still fails closed**, unchanged. The X25519 KDF-tail
> caveat US-972 named is also unchanged: the `03 01 08 07` tail is what
> GnuPG writes when the card advertises no KDF, which is this card's state,
> and a host that negotiated one via `PUT DATA F9` would diverge.
>
> **Three false `MATCH: False` results in this run were bugs in this story's
> own off-card reference, not divergences** — a wrong MPI bit count, a
> doubled `0x04` point prefix, and DO CD sliced with DO C5's offsets. All
> three are written up with the arithmetic that settles them in
> `docs/tasks/evidence/us973-c5-verify/00-harness-corrections.md`. No
> firmware change was made in response to any of them, and no comparison was
> relaxed; each was resolved by computing both sides and showing which one
> moves.
>
> **Card left working:** signing attribute restored to Ed25519
> (`16 2b06010401da470f01ff`), all three keys freshly generated, and
> `GOODSIG`/`VALIDSIG 1666BC5C…` plus `DECRYPTION_OKAY`/`GOODMDC`
> re-confirmed end to end.
>
> Evidence: `docs/tasks/evidence/us973-c5-verify/`.

### Carry-forward: the signing slot's algorithm attribute is left on Brainpool P-384r1

US-954's harness set `C1` to the P-384r1 attribute and its restore step sits
after the statement that raised the 14.47 s timeout, so it never ran.
`GET DATA C1` is therefore expected to read `13 2b240303020801010bff`, and
`gpg --sign` will not work until `C1` is written back to
`16 2b06010401da470f01ff`. Read from the harness control flow, **not**
re-read from the card. **Check `GET DATA C1` before concluding anything from a
gpg signing failure** — this is the advertise-vs-reality class US-962 closed
on the firmware side, reintroduced here by a raw harness rather than by the
card lying.

> **US-966 (2026-09-27) — this carry-forward is now a hard blocker, not a
> nuisance.** P-384r1 is no longer served, so `13 2b240303020801010bff` on `C1`
> now names an algorithm the firmware will refuse. The situation US-954
> described ("`gpg --sign` will not work until `C1` is written back") has
> stopped being a stale-attribute problem that a restore step would fix: after
> the next flash, **`C1` cannot be written back to Brainpool P-384r1 at all**,
> because PUT DATA of a deferred curve is refused `6A80`.
>
> **Required before the next flash, one or the other:**
>
> 1. a **factory reset of the card** (`factory-wipe` / `gpg --card-edit
>    factory-reset`, which drops the flash-resident persistent store as well as
>    the attributes), or
> 2. `C1` **written back to a supported algorithm** *while the current
>    (pre-US-966) image is still flashed* — i.e. `16 2b06010401da470f01ff`
>    (Ed255) or any curve the old build serves.
>
> US-966 deliberately did **not** do either: the story is host-only, and
> flashing, BOOTSEL, a factory reset and any PIN-state change are all out of
> scope. See `docs/tasks/us966-defer-bp384.md`.
>
> **`gpg --sign` failing on the card today is a pre-existing device-state
> artifact, not a US-966 regression.** Before US-966 the card already held a
> P-384r1 attribute with no `C5` and no usable signing path; after US-966 the
> cause is different but the symptom is the same. Nobody should attribute a
> `gpg --sign` failure observed on a *pre-US-966 flash* to this change, and
> nobody should conclude the new firmware is broken from a failure observed
> before it was ever flashed.

> **⚠ SUPERSEDED 2026-09-27 (US-974) — both this carry-forward and the
> US-966 blockquote above it are stale. `C1` is already Ed25519.**
>
> **What the two say, and why neither is actionable any more.** This section
> tells a reader to **check `GET DATA C1` before concluding anything from a
> gpg signing failure**, expecting `13 2b240303020801010bff` (Brainpool
> P-384r1). The US-966 blockquote then escalates it to a **hard blocker with
> a pre-flash requirement** — factory-reset the card, or write `C1` back to
> a supported algorithm while the pre-US-966 image is still flashed, because
> after the next flash a deferred curve can no longer be `PUT` at all
> (`6A80`).
>
> **The current truth.** US-973's own final state on serial `88B0BD40` (the
> `DO C5` entry above, US-973 blockquote) records the signing attribute
> **restored to Ed25519, `16 2b06010401da470f01ff`**, all three keys freshly
> generated, with `GOODSIG` / `VALIDSIG 1666BC5C…` and `DECRYPTION_OKAY` /
> `GOODMDC` re-confirmed end to end. US-971 reached the same resting state
> independently. **So the check this section prescribes now passes** — a
> reader who follows it reads Ed25519, sees it is not the expected value, and
> draws exactly the wrong conclusion.
>
> **The pre-flash requirement is discharged, not pending.** US-968/US-969
> worked on a **freshly nuked** card (serial `88B0BD40`), which is option 1
> of the two the US-966 note offered. The card has been flashed and run
> since. The "required before the next flash" framing is spent.
>
> **Two knock-on corrections this makes, stated so neither is rediscovered:**
>
> * The `## US-966` section's closing **"Device state — not touched"** note
>   ("the card is still flashed with the pre-US-966 image and its `C1` still
>   holds the P-384r1 attribute, so `gpg --sign` fails today") is **false as
>   of US-969**. That was true when US-966 was written and is kept as the
>   record of what was true then.
> * `EPIC-crypto-completion.md`'s divergence **2** ("Brainpool P-384r1
>   generates but does not sign on hardware") poses a live timing question
>   about a curve **US-966 stopped serving**. US-974 adds the same dated
>   correction beside that row; the two documents should not disagree.
>
> **What survives** is the *shape* of the warning — a `gpg --sign` failure on
> this firmware should still be read against the card's actual attribute
> state rather than assumed — and the 14.47 s host-ceiling reading, which is
> still the live explanation for **RSA-4096 `GENERATE`**, a capability still
> advertised. What does not survive is this instance's premise: the attribute
> it tells you to look for is gone, and the pre-flash action it demands has
> been taken.
>
> **Nothing above this line is edited.**

## US-966 — Brainpool P-384r1 deferred to a follow-up release; P-256r1 kept

Date: 2026-09-27. This is a **post-close change to
`EPIC-crypto-completion`**: that epic's 28 stories closed as
`Done-with-divergences` on `fix/openpgp` with P-256r1 *and* P-384r1 served,
and US-966 then removed the P-384r1 half. The US-944/945/946 entries above
are therefore not wrong — they record what was true when they were written.
This entry is the current statement.

**What is not served, in any configuration of this workspace:**

| group | attribute (ECDSA / ECDH) | since | why |
|---|---|---|---|
| `BRAINPOOL_P512R1` | `…2b240303020801010d` | US-944 | no `bp512` crate exists in the Rust ecosystem |
| `BRAINPOOL_P384R1` | `…2b240303020801010b` | US-966 | deferred; see below |

Both are refused `6A80` at PUT DATA on every usage tag and neither appears in
`GET DATA FA`. This is the *absence* direction of the US-962 defect class, and
it is now pinned from both sides rather than left implicit.

**Why P-384r1, on the evidence:**

1. **The spec sets a floor, not a menu.** OpenPGP card spec v3.4 §4.4.3.10
   *recommends* the Brainpool curves but requires only that "at least one of
   this curves shall be supported". NIST P-256/384/521 already satisfies that,
   and P-384r1 is never singled out in the document.
2. **The IETF deprecated the family.** RFC 8734 deprecated Brainpool for TLS
   1.3 "because they had little usage … not endorsed by the IETF"; every
   Brainpool row in the IANA TLS registry is `Recommended = N`.
3. **No OpenPGP-card user was found, and the host stacks disagree.** GnuPG's
   curve table carries Brainpool; OpenSC has no Brainpool occurrence in its
   card drivers. No vendor documentation was reachable, so **no vendor
   negative is claimed** — but also no positive.

**Why P-256r1 stays:** it is the curve demonstrably working on the part —
generate 0.71 s, sign 1.15 s, signature verified against the card's own public
key (US-954).

**What P-384r1 is NOT deferred for.** Two claims circulated before this
story and are both wrong; neither may appear in the commit or the docs:

* **"P-384r1 signing is broken."** Not established. The 14.47 s US-954
  failure is a **host-side PC/SC transaction ceiling** — it recurs identically
  for RSA-4096 GENERATE while a *longer* 8.19 s NIST-P-384 GENERATE
  succeeds. P-384r1 signing is **unmeasured, not broken**. It is deferred for
  want of users.
* **"This saves ~258 KB / a quarter of the image."** The `19.7 %` `.text`
  row in `docs/size-report.md` is labelled *"`p384` + `bp384`"*, and `p384`
  is the **NIST** P-384 crate — independently advertised, still served by
  trussed Core, and untouched by this change. The 258 KB figure is US-944's
  whole two-curve Brainpool band, not P-384r1's share.
* **"…or ~20–25 KB (~2 %), which is what replacing the 258 KB claim with a
  per-crate number would suggest."** Also wrong, in the other direction. The
  **measured** saving is **166,056 B of `text` (17.6 %)**, and only 114,072 B
  of that is `bp384`'s own named symbols; the rest is fiat-crypto 384-bit
  field arithmetic and 512-bit limb machinery instantiated for Brainpool
  P-384r1 under v0-mangled generic names that no per-crate name match can
  attribute. Per-crate numbers, and the full arithmetic, are in the US-966
  section of `docs/size-report.md`.

**How the removal was made honest.** The curve went out of *both* sides at
once and unconditionally — not behind a feature — so there is no build in
which the mechanism is served and no build in which the card advertises it.
A `brainpool-p384r1` switch was considered and rejected: it would put a fourth
switch next to the three `tests/scripts/check_advertise_serve_coupling.py`
already reasons about, guarding a curve with no identified user, and it would
recreate exactly the advertise/serve split US-962 spent two stories closing.
Restoring P-384r1 later is the same edit in the other direction; if it is
ever to be *optional*, route it through a switch the way SECP256K1 is.

**Pinned by:**

| what | where |
|---|---|
| attribute refused `6A80` on C1/C2/C3, stored DOs untouched | `apps/openpgp/tests/dispatch.rs::put_never_served_brainpool_curves_and_unknown_oid_rejected`, `device_pso.rs::put_brainpool_attr_device_path` |
| not in `GET DATA FA`, and PUT refused, on the **device** dispatch | `apps/openpgp/tests/advertise_serve.rs` (`DEFERRED`) |
| 48-byte prehash is now a wrong-size digest (`6985`); P-256r1 still signs | `apps/openpgp/tests/dispatch.rs::brainpool_p384r1_is_refused_virt`, `device_pso.rs::brainpool_p384r1_is_refused_device_path` |
| the backend classifier and its `MECHANISMS` list both refuse it | `vendor/trussed-brainpool/src/lib.rs` (`selection_rejects_unserved_mechanisms`, `mechanisms_exclude_deferred_curves`) |
| the **gate** requires both deferred groups to measure as unadvertised, in the default *and* the reduced build | `tests/scripts/check_advertise_serve_coupling.py` (`DEFERRED_GROUPS`) |

**The gate was made stronger, not relaxed.** `check_advertise_serve_coupling.py`
previously would have failed outright on the removed group (it is listed in
`SWITCHED_GROUPS`), and the lazy accommodation — deleting the name — would
have left the gate with no opinion about the curve at all. Instead the gate
gained a third category: `DEFERRED_GROUPS`, whose absence is *measured* off
the parsed FA records by the test and *reported* on a line the gate parses.
The reported booleans are read from the reply, not printed as constants — a
report line that printed `advertised:false` regardless would be this epic's
recurring failure mode (US-961, US-964) in new clothes. The gate also now
requires the advertised set to be **exactly** the expected set in each
configuration, so a group cannot quietly drop out of FA either.

**Hardware coverage:** the two `tests/openpgp/card_test_*_brainpoolp384r1.py`
modules read the card's own FA DO and will skip by themselves once this image
is flashed — the same mechanism that has always skipped the P-512r1 modules.
They are kept (as the P-512r1 ones are) so a release that re-admits P-384r1
has its hardware coverage in place. **They were not run for this story**,
which is host-only.

**Device state — not touched.** See the dated note under the US-954
carry-forward above: the card is still flashed with the pre-US-966 image and
its `C1` still holds the P-384r1 attribute, so `gpg --sign` fails today for
reasons that predate this change and are not its regression. Flashing,
BOOTSEL, factory reset and PIN state were all out of scope.

## US-971 — gpg 2.4.4's `key-attr` curve menu does not offer secp256k1

Date: 2026-09-27. Card serial `88B0BD40`, firmware `b639432c…`. **No
firmware change** — this is a limitation of the named client, measured, and
it is the reason N2 could only be closed unevenly.

**The menu, as observed.** `gpg --card-edit`, `admin`, `key-attr 1`
(signature key), answer `2` (ECC). GnuPG 2.4.4 then prints exactly:

```
Please select which elliptic curve you want:
   (1) Curve 25519 *default*
   (4) NIST P-384
   (6) Brainpool P-256
```

Three entries, non-contiguous numbering, **no secp256k1** and no NIST P-256.
This is not a truncated terminal capture: the list is complete on the pty,
and the same three-entry list was seen in the earlier US-953 session
(`docs/tasks/evidence/us953-partial/ka-probe.txt:49-58`, card `76BD7BDD`) —
so it is a property of the client, not of this card or this run. GnuPG's
curve *table* does carry secp256k1 (`common/openpgp-oid.c`); what is missing
is the **menu entry** that would let a user select it for a card key.

**What this costs the epic.** The completion audit's N2 (US-953 req 2 /
US-954 req 2) asked for secp256k1 and Brainpool **through gpg** on
hardware. Brainpool is reachable and was done end to end through gpg. For
secp256k1 the *selection* step is the one leg that cannot be gpg-driven, so
the key attribute was written by raw APDU (`PUT DATA C1` with
`13 2B 81 04 00 0A FF`) and gpg did everything after it — the on-card
GENERATE, the public-key import, the `gpg --sign` (`GOODSIG` + `VALIDSIG`,
algo 19) and the `gpg --verify`, with `BADSIG` on a tampered copy of the
message. Evidence: `docs/tasks/evidence/us971-gpg-curves/`.

**What this is NOT.** It is not a card defect, not a firmware gap, and not a
claim that secp256k1 is unavailable. The card advertises and serves
secp256k1 today: `GET DATA FA` carries `C107 132B8104000AFF`, PUT DATA C1
accepts it, and the card generates and signs with it. A different client, or
a newer GnuPG with the entry present, closes the gap with no device work.

**Card state — left as found.** `ed25519 cv25519 ed25519`, all three slots
holding keys, `PIN retry counter : 3 0 3` throughout, `gpg --sign`/`--verify`
and `gpg -e`/`-d` re-confirmed working after the restore. See
`docs/tasks/us971-gpg-curve-acceptance.md`.

---

## US-121: credMgmt pinUvAuth message has no `0xFF×32 ‖ 0x0A` prefix (deliberate, pre-existing)

**Found 2026-09-27 while implementing US-121. Not a defect, not a
regression, and deliberately not fixed.**

CTAP 2.1 §6.1.5 defines the credMgmt `pinUvAuth` message as
`0xFF×32 ‖ 0x0A ‖ subCommand ‖ subCommandParams`. fapico2 does **not**
implement that form. It signs:

```
HMAC-SHA-256(pinToken, subCommand ‖ CBOR(subCommandParams))
```

with **no** `0xFF×32` prefix and **no** `0x0A` command byte. The same
non-conformance exists on both twins:

| Path | Code | Signed message |
|---|---|---|
| Host | `apps/fido/src/app.rs:1798` | `vec![req.subcommand]`, then the re-encoded params appended only for `0x04`/`0x06`/`0x07` (`app.rs:1799`, `_ => None` at `app.rs:1847`) |
| Device | `apps/fido/src/device_core.rs:2174-2176` | `auth_msg.push(subcommand)`, then the **raw** `subCommandParams` bytes appended if the client sent any |
| PicoForge | `picoforge/src/hal/fido/ops.rs:1671-1694` | `vec![sub_cmd]`, then params appended **unless** `sub_cmd` is `GetCredsMetadata (0x01)` or `EnumerateRpsBegin (0x02)` |

`0xFF×32`-prefixed messages *do* exist elsewhere in this firmware, so
"the prefix is a thing this codebase does" is true — just not on credMgmt.
The three places that build one:

| Channel | Site | Prefix |
|---|---|---|
| authenticatorConfig / vault, `0x0D` | `apps/fido/src/vault.rs:158-164` (`auth_message`) — **`#[cfg(feature = "host")]` only**, called from `app.rs:674` | `0xFF×32 ‖ 0x0D` |
| authenticatorConfig fragment, `0x0C` | `apps/fido/src/app.rs:887-888` | `0xFF×32 ‖ 0x0C ‖ 0x00` |
| vendor `0x41` | `apps/fido/src/vendor41.rs:2789-2792` | `0xFF×32 ‖ 0x41` |

Note the `host`-only gate on `vault::auth_message`: it is not available to
the device path, so it is not a template you can call from `device_core.rs`
without an `#ifdef`. credMgmt has its own construction on each twin anyway.

### Why this is not a compatibility bug

For the three sub-commands PicoForge actually calls, fapico2 and PicoForge
produce **byte-identical** signed messages:

| Sub-command | PicoForge call site | Params | Signed message on both sides |
|---|---|---|---|
| `0x02` enumerateRPsBegin | `ops.rs:1092` | `None` | `02` |
| `0x04` enumerateCredentialsBegin | `ops.rs:1244` | `{1: rpIdHash}` | `04 ‖ A1 01 58 20 …` |
| `0x06` deleteCredential | `ops.rs:1419` | `{2: {type, id}}` | `06 ‖ A1 02 A2 …` |

PicoForge's 16-byte truncation (`ops.rs:1693`, `sig.as_ref()[0..16]`) is
`pinUvAuthProtocol` 1. fapico2 accepts protocol 1 or 2 on both paths
(`app.rs:1778`, `device_core.rs:2163`) and `crypto::pin_verify_auth`
(`apps/fido/src/crypto.rs:389-390`) uses the protocol only to select 16- vs
32-byte MAC length. So the truncation is already accommodated with no
build-time switch.

**Consequence for US-121:** the story as written in the EPIC asked for a
Cargo feature gating a "PicoForge form" of the MAC, on the premise that
fapico2 computed the spec form and PicoForge did not. That premise is
false — both compute the same non-spec form. A feature gating it would
select behaviour identical to the default, i.e. dead code. **No feature
was added and no release-gate script was added**, deliberately.

### Security posture: a real spec deviation, currently inert

The deviation from CTAP 2.1 is real: the signed message omits the
`0xFF×32 ‖ 0x0A` prefix that would bind the command.

**Current exploitability is nil, and it is worth being precise about why
rather than implying a live risk.** Because `0x01` and `0x02` sign only the
sub-command byte, a captured MAC for those two carries no commitment to any
parameter — in principle replayable with different `subCommandParams`. But
neither twin *acts* on params for those two:

* the host yields `_ => None` (`app.rs:1847`), so params are excluded from
  its signed message entirely; and
* the device's `0x01` and `0x02` arms never read `raw_params` — the `0x01`
  arm (`device_core.rs:2188-2199`) just pushes the three metadata counters,
  and `0x02` similarly.

So a replay with arbitrary attached params gets **byte-identical
behaviour**: same response, no state change, nothing gained. Reporting this
as an accepted live risk would overstate it.

The reason to still care is **conformance plus future-proofing**. The
unsigned-scope property is latent, not absent: the moment a future `0x01`
or `0x02` starts honouring a parameter, that parameter is silently outside
the MAC unless the scheme is fixed at the same time. That is the actual
hazard — an unsigned scope that a future change can widen into without
anyone noticing — and it is a reason to land the spec form deliberately,
with a client migration, rather than to treat the current state as risky.

### The one real cross-twin divergence: host re-derives, device signs raw

**The host reconstructs the MAC from parsed, re-encoded fields; the device
signs the client's raw bytes.** `CmRequest` (`app.rs:130-136`) keeps only
`rp_id_hash`, `cred_id` and `user`. Anything else a client puts in
`subCommandParams` is **dropped from the host's signed message** but is
**signed by the device**.

Measured example — a `deleteCredential` carrying `rpIdHash` (key `0x01`,
which the spec does define) alongside the descriptor, with the client
signing the full params it sent:

| Twin | Result |
|---|---|
| Device | `0x00` — accepted |
| Host | `0x33 PIN_AUTH_INVALID` — refused |

That is the divergence a maintainer can actually hit. It is latent for
PicoForge only because PicoForge happens to send exactly the fields the
host re-derives, and nothing else.

**Descriptor key ordering is NOT an instance of this**, despite being the
obvious thing to suspect, and an earlier draft of this section got it
backwards. `cbor::encode` re-sorts map keys by encoded representation
(`apps/fido/src/cbor.rs:441-446`), so the `Vec` order written at
`app.rs:1812-1815` is source order only and the encoder discards it:
`62 69 64` ("id") sorts before `64 74 79 70 65` ("type"), so both sides
emit **`id` first** regardless of how the literal is written. PicoForge
agrees: it builds the descriptor in a `BTreeMap<Value>`
(`picoforge/src/hal/fido/mod.rs:570-572`) whose `Ord` for `Text` compares
by length, so "id" (2) precedes "type" (4). Measured: encoding the same
descriptor `type`-first and `id`-first yields identical bytes
(`a1 02 a2 62 69 64 … 64 74 79 70 65 …`), and both are accepted
end-to-end. Do not "fix" `app.rs:1812-1815` to match a client's literal
order — the encoder makes that a no-op.

### A second, smaller host/device split: `0x01`/`0x02` MAC scope

For `0x01`/`0x02` the host signs the sub-command byte alone regardless of
params, while the device includes raw params when sent. The same request is
therefore accepted by one twin and refused by the other:

| Client signs | Host | Device |
|---|---|---|
| PicoForge's way (params excluded) | `0x00` | `0x33` |
| Device's way (params included) | `0x33` | `0x00` |

Not an interop bug, because PicoForge sends no params for `0x01`/`0x02`.
Both halves are pinned by tests (below).

### Regression guards

| Test | Twin | Asserts |
|---|---|---|
| `apps/fido/tests/credmgmt.rs::picoforge_mac_scheme_is_accepted` | host | `0x02`/`0x04`/`0x06` in PicoForge's exact form (protocol 1, 16-byte MAC, params excluded for `0x02`) are accepted |
| `apps/fido/tests/credmgmt.rs::host_accepts_picoforge_mac_with_params_omitted_from_scope` | host | the **accepting** half of the second split above |
| `apps/fido/tests/device_full_set.rs::device_twin_credmgmt_mac_scope_differs_from_host_for_0x01_and_0x02` | device | the **refusing** half, and that the device accepts the same sub-commands when params are inside the signed scope |

**Overlap, stated plainly:** the pre-existing
`device_full_set.rs::cred_mgmt_largeblobs_u2f_device_path` already builds
credMgmt requests in exactly PicoForge's scheme — `cred_mgmt` there uses
`pinUvAuthProtocol` 1, a 16-byte `pin_auth`, and
`auth_msg = vec![sub] ‖ params` — and already covers `0x01`/`0x02`/`0x04`/
`0x06`. The new device test is therefore **not** a second copy of that
coverage: it deliberately covers only the params-present case, which the
sibling never reaches.

**Mutation evidence, honestly scoped.** Five mutations that change the
credMgmt MAC were tried. Three are **not discriminating** — forcing a
32-byte-only `pin_verify_auth`, adding the `0xFF×32 ‖ 0x0A` spec prefix, and
appending a byte to the host `0x01`/`0x02` message — because the
pre-existing `cred_mgmt_largeblobs_u2f_device_path` already exercises the
same scheme and goes red too. A reader deciding whether to delete the new
tests should know that: they are *not* the only thing holding the scheme in
place, and these three mutations do not distinguish them.

The two **discriminating** mutations, where the pre-existing tests stay green
and only the new ones go red:

| Mutation | Pre-existing | New test | Result |
|---|---|---|---|
| Device: skip `raw_params` in the credMgmt message for `0x01`/`0x02` | green | red | `left: 51 (0x33) / right: 0 (0x00)` |
| Host: sign `rpIdHash` for `0x02` when present | green | red | `left: 51 (0x33) / right: 0 (0x00)` |

Both were reverted; `apps/fido/src/` is byte-identical to the pre-story
commit.

**Standing instruction:** the credMgmt `pinUvAuth` message is
`subCommand ‖ params` with **no** `0xFF×32 ‖ 0x0A` prefix, and that is
intentional and matches PicoForge — do **not** "correct" credMgmt to the
CTAP 2.1 form (it would break PicoForge interop, the only consumer), and do
**not** add a build-time compat feature for it (it would gate behaviour
identical to the default). For `getCredsMetadata (0x01)` and
`enumerateRpsBegin (0x02)` the signed message omits any parameter; that is
**not currently exploitable**, because neither twin acts on params for
those two sub-commands — treat it as a conformance and future-proofing
debt, not a live risk, and land the spec form (with a client migration) if
and when a `0x01`/`0x02` ever starts honouring a parameter.

## D-7 — the PIV pytest suite is red for unimplemented features (2026-09-27)

**`17 failed, 13 passed`** on `tests/piv/`, measured against the Phase G–J
tip with a fresh store and the shared relay/emulator.

**Pre-existing, and proved so rather than argued.** Reverting only
`apps/piv/src/lib.rs` to the Phase F tip (`f23d5ec`) and re-running gives the
**identical** `17 failed, 13 passed`. US-181 is the only Phase G–J change to
that file, so it is not the cause. The failures are `0x6D00` on `IMPORT`
(INS `0xFE`) and its dependents: `apps/piv/src/lib.rs` has no `0xFE` arm at
`f23d5ec` either, and the `0xFE` at that commit's line 683 is the
`TOUCHPOLICY_ALWAYS` constant, not an instruction byte.

**Not attributed to the D-5 emulator-death root cause** — the D-5 failures
are 128 `TimeoutError`s after the card panics mid-suite; these are ordinary
`6D00` mismatches against features this firmware has never implemented.

**Why it matters that it is recorded.** `run_tests.sh` — the project's own gate
entry point — is unusable for two unrelated reasons (two pre-existing clippy
errors in `platform/src/ckey.rs`, and this), so a reader who runs the PIV
suite for the first time has no baseline to compare against and may read 17
failures as a regression from whatever they just changed. US-182's status-word
sweep bounds the reachable set precisely, so these words are *expected* until
the features land.


## D-8 — the TRNG wait budget is a datasheet average × 10, not a measured maximum (US-1005)

**Date:** 2026-09-28 (written). **Revised:** 2026-09-28, after review — the
original text of this entry described a *poll-count* ceiling, and that
ceiling has been replaced. **Story:** RS-KEY-ADOPT US-1005 / US-1006
(Phase 1). **Class:** unproven without hardware, not a test failure.

### What the original entry said, and why it is superseded

The first version of D-8 recorded that the device's entropy wait was bounded
by `MAX_ENTROPY_POLLS = 64` **status reads** per 24-byte EHR block, and that
a poll is not a unit of time. That was true as written and misleading as
implied: a 64-iteration no-delay loop over a register read is roughly 4 µs on
a 150 MHz core, while the RP2350 datasheet's own figure for one *healthy*
generation under the configuration this probe is calibrated against is
**~2 ms**. Sixty-four polls is therefore two to three orders of magnitude too
few to cover a single healthy draw.

The failure mode is worse than the infinite hang it replaced, and it runs the
*opposite* direction from what D-8 originally recorded: the device would
report `Stalled` on good silicon, `FuseSeedSource::seed` would return
`SeedError::Trng(Stalled)`, and `boot::init_drbg` is **fatal by design** — so
the unit would not boot. A budget that refuses roughly half of all healthy
draws is a worse outcome than no budget at all, because it is also silent.

### The claim now, stated exactly

The wait is bounded by a **wall-clock budget**, `MAX_ENTROPY_WAIT`
(`platform::trng`), of **20 ms**, expressed in ticks of an
`EntropyClock`, and independently by a **hard poll cap**. Whichever expires
first produces `TrngError::Stalled`.

> **AMENDED 2026-09-29 by D-12.** Two things changed in this paragraph's
> subject and one in its *meaning*, and this entry was not rewritten because
> its own reasoning about the 20 ms figure is unaffected:
>
> * The cap is now `MAX_ENTROPY_POLLS = 2^19` (was `2^18`), re-derived in
>   D-12. Its role also changed: it no longer catches a dead clock, because
>   the new `CLOCK_LIVENESS_SPINS` bound does, in ~0.5 ms instead of ~0.5 s.
>   It now catches a clock that is *counting* but too slowly to reach 20 ms
>   of ticks in a sane number of spins.
> * There is now a **third** bound ahead of both, and it is a different kind
>   of failure: if the clock has not moved at all across
>   `CLOCK_LIVENESS_SPINS` consecutive reads, the wait returns
>   `TrngError::ClockStalled`, not `Stalled`. That distinction did not exist
>   when this entry was written, and without it the claim "whichever expires
>   first produces `Stalled`" was not merely incomplete — it was the defect.
> * **The budget is conditional, and was not before.** `MAX_ENTROPY_WAIT` is
>   20 ms only if the clock behind it is counting. D-12's checks make that a
>   verified precondition rather than an assumption, but the *size* of the
>   20 ms remains, exactly as this entry says, a datasheet average × 10 and
>   not a measured maximum.
>
> The 1–2 µs per-loop-iteration figure this entry's cap discussion rests on
> is reasoned, not measured, and that caveat now applies to D-12's
> re-derivation too.

* **Where 20 ms comes from.** RP2350 §12.12.2, quoted verbatim in
  `embassy-rp-0.10.0/src/trng.rs:78-83`: *"For acceptable results with an
  average generation time of about 2 milliseconds, use ROSC chain length
  settings of 0 or 1 and sample count settings of 20-25."* `Config::default()`
  is exactly that (sample count 25, all three health tests enabled), so 2 ms
  is the datasheet's **average** for this configuration. 20 ms is a **10×
  safety factor** on it, chosen because the same passage warns that
  *"results occasionally take an especially long time to generate"* — the
  datasheet itself declines to bound the tail.
* **The clock.** `rp2350::Rp2350Timer` reads the RP2350 hardware `TIMER`
  directly through `rp-pac`, at the 1 MHz convention `embassy-time` already
  assumes for every `Duration` in this firmware. (`embassy-rp` 0.10.0 has no
  `timer::CycleCounter` — there is no `timer` module in the crate at all; the
  brief's suggested type does not exist in this version.) The clock sits
  behind the `EntropyClock` trait so the budget arithmetic is host-testable:
  `platform/tests/trng_wedge.rs` drives a fake clock and pins both edges of
  the deadline.
* **The hard cap.** A second, much larger bound, so a broken or absent clock
  cannot turn the budget back into an infinite loop. 2^18 register reads is
  tens of milliseconds of pure spinning and is never the binding constraint on
  a healthy peripheral.
* **What is now bounded that was not.** A *healthy-but-slow* peripheral is now
  refused in bounded time, which the poll-count version did not do. That was
  the point of the change.

### What is deliberately **not** claimed

* **That 20 ms is sufficient.** It is derived from a datasheet **average**,
  not from a measured **maximum**, and **no board was attached**. A silicon
  part slower than 10× the datasheet average would return `Stalled` and,
  because `init_drbg` is fatal, **refuse to boot**. That is the correct
  fail-closed direction — a bounded, reportable refusal beats an unbounded
  hang and beats a generator fed a constant — but it is possible, and an
  operator should know it is.
* Not that entropy starvation is survivable on hardware. That is US-1007,
  outstanding, and its hardware leg is a separate story with a separate gate.
* Not that the peripheral was observed to reach the stalled state, or to
  produce a block inside 20 ms. Neither was observed.

### The assumptions that would fail the claim

1. **Calibration.** The budget is sized for the configuration
   `embassy-rp`'s `initialize_rng` writes (`sample_count = 25`, all three
   health tests enabled — `trng.rs:110-121`). `Rp2350Probe` deliberately does
   **not** write `trng_debug_control`, leaving the health-test bypass bits to
   `Trng::new`'s initialization, precisely so it cannot disable a test. A
   future change that routes construction away from
   `embassy_rp::trng::Trng::new` would leave the peripheral on power-on
   defaults, and the budget would be calibrated against a
   differently-configured block — which the datasheet says is *slower*, so
   the budget would be too tight. **Re-check this before trusting the bound.**
2. **The tick rate.** `MAX_ENTROPY_WAIT` assumes the RP2350 `TIMER` ticks at
   1 MHz. If a future change reconfigures `clk_ref`, the budget's real
   duration changes proportionally. That assumption is not new — every
   `Duration` in this firmware already rests on it — but it is load-bearing
   here too.

### Related

`check_rng_path.py` (US-1005) is the gate that keeps callers on the DRBG.
Its allowlist is per-flag **and count-capped**, and every declared entry
prints on every run whether or not it currently has a hit.

*(Correction to the original D-8 "Related" note, which claimed the allowlist
reasons are "printed on every run": until this revision the script only
appended an entry to its report when the file had hits, so entries with no
hits never printed. The claim was false; the script now prints them all.)*

### AMENDMENT (2026-09-29, I-1 fix) — assumption (1) had a second trigger, and it has been closed

**Assumption (1) above says the budget is "sized for the config
`embassy-rp`'s `initialize_rng` writes (sample_count 25, all three health
tests enabled)" and that "a future change routing construction away from
`embassy_rp::trng::Trng::new` leaves power-on defaults, which the datasheet
says are *slower*." That was written as a *future* risk. It was also, at the
time, a present one nobody had connected to the code: `Rp2350Probe::soft_reset`
re-armed on `autocorr_err` **without** re-running `initialize_rng`.**

The omission looked deliberate — the doc justified it as "the health test is
not bypassed by this type, so there is no configuration to restore" — and
that sentence is true of `trng_debug_control`, the one register the probe
never touches. It is silent about the other two `initialize_rng` writes:
`trng_config.rnd_src_sel` and `sample_cnt1`
(`embassy-rp-0.10.0/src/trng.rs:190-201`). A TRNG soft reset returns both to
their power-on values, so after **one** `autocorr_err` the probe re-armed on
`rnd_src_sel = 0, sample_cnt1 = 0` — outside the datasheet's own 20-25
sample band, the band its 2 ms generation figure is quoted for.

**The consequence, stated as the epic's rationale states it.** The budget
does not become a slightly-worse generator; it becomes a **deadline
calibrated for a different peripheral**. A healthy part can then miss
`MAX_ENTROPY_WAIT_MS`, return `Stalled`, and — `init_drbg` being fatal by
design — leave the device refusing to seed. One autocorrelation error was
enough to turn a booting device into a dark one. This is the same class of
void as assumption (1) and assumption (2), reached by a route the register
list in this entry did not mention.

**Fixed** in `34d574d`. `platform::trng::TrngConfig` names the pair of values
the budget is valid for and lives *outside* the `device` block so the host
suite can reach the data even though the register write is device-only;
`Rp2350Probe` carries the config it was built with (the same
`Config::default()` the driver was built with, from the same constant at the
call site) and re-applies it after every soft reset, through one named
`apply_config`. `rng_imr` is still not written and that is now stated as a
decision — it masks an interrupt this bounded-poll probe never enables, so
it is a genuine no-op rather than a third apparent omission.

**Divergence delta: 0.** This amendment *closes* a void condition this entry
recorded, and it adds none: the four host tests in `platform/src/trng.rs`
are ordinary Rust and the register write is still unverified on silicon,
which this entry already said. The residual below is unchanged and is still
open.

**What remains unproven, restated.** Nothing here has been run on a board. The
restored values are transcribed from `embassy-rp`'s own `Config::default()`
(`InverterChainLength::One = 1`, `sample_count = 25`), not measured. The
datasheet band is transcribed from §12.12.2 as quoted in that same
`Config`'s documentation. US-1007's hardware leg still owns this.

## D-9 — `RngCore::fill_bytes` is infallible by contract, and two device caller classes depend on that (US-1006)

**Date:** 2026-09-28 (the second consequence added by the RS-KEY-ADOPT final
review). **Story:** RS-KEY-ADOPT US-1006. **Class:** residual API footgun,
deliberately not redesigned in this story.
**Amended 2026-09-29 (US-1007 defect fix):** the *predicted symptom* below was
wrong and is corrected in place — see "AMENDMENT" after The exposure. What
the device can actually reach is also wider than this entry claimed.

### The exposure

`rand_core::RngCore` requires `fill_bytes`, and it returns `()`. US-1006 made
`Rp2350Rng::try_fill_bytes` genuinely fallible, and established that
`Rp2350Rng::fill_bytes` is **unreachable from trussed entirely** — the only
`Platform::rng()` call in `trussed-0.2.0` is `service.rs:743-745` and it
uses `try_fill_bytes`; every other consumer goes through
`ServiceResources::rng()`, which re-mixes. So the request path is clean.

**The same infallible seam has two device consumer classes, and they fail
differently.** Both are fed the same `drbg`, so a single starved generator
reaches both.

1. **The persistent FIDO `hkey`.** `firmware/src/main.rs` hands `&mut *drbg`
   to `boot_fido`, and `apps/fido/src/device_app.rs:360` does
   `p256::SecretKey::random(&mut TrngAdapter(trng))` for the device's
   *persistent* `hkey`. `crypto::TrngAdapter::fill_bytes` forwards to
   `platform::trng::Trng::random_bytes`, which on a starved generator leaves
   the buffer untouched — so the key would be all zeros, and that key is then
   **persisted to the secure store**. A zero `hkey` fails *loudly*: the
   credential MACs it produces are all wrong and every assertion using it
   breaks.

2. **The two boot RNG pools — the worse of the two.** `fill_rng_pool`, in
   `apps/fido/src/device_app.rs:267` **and** `apps/oath/src/oath_core.rs:1016`
   (the OATH one since this branch's I-1 fix), is a plain generic
   `&mut R: Trng` caller of the same infallible method, filling a
   zero-initialized local:

   ```rust
   let mut chunk = [0u8; 64];
   for _ in 0..8 {
       trng.random_bytes(&mut chunk);   // starved: `chunk` is left UNTOUCHED
       /* extend into the pool */
   }
   ```

   "Left untouched" here does not mean "left as whatever was in it". The local
   is zero-initialized, so **the whole 512-byte pool is all zeros**, and
   `draw_random` then serves those zeros as the CTAP/U2F challenge
   (`FidoApp::new_in_place`) and as the OATH SELECT and SET_CODE challenges
   (`OathApp::new_in_place` and the two redraw sites). The consequence is
   not a loud failure: a zero `hkey` breaks loudly, whereas a
   **predictable challenge** is accepted silently by a conforming client. A
   repeated challenge is precisely the signal CTAP's challenge-response
   design exists to make unforgeable. **Of the two this is the worse
   outcome** — a broken key is a bug report, a predictable nonce is a
   vulnerability — even though both are unreachable for the same reason.

### AMENDMENT (2026-09-29, US-1007 defect fix) — the predicted symptom was wrong

**This entry predicted that a starved FIDO `hkey` would be "all zeros". That
is not what happens. The real behaviour is an infinite rejection loop, and
the prediction was wrong in the direction that matters: a zero key fails
loudly, an unbounded loop produces no output at all.**

`p256::SecretKey::random(&mut TrngAdapter(trng))` is not "one draw into a
buffer". It is a **rejection sampler**: it draws 32 bytes, rejects the draw
if the scalar is zero or >= the group order, and draws again. `NonZeroScalar::random`
rejects zero, and under starvation *the next draw is the same untouched
buffer*, so the sampler never resolves. The two halves of D-9's footgun
compose:

- the infallible `Trng::random_bytes` reports a refused draw as **success**
  with an untouched buffer (`TrngAdapter::try_fill_bytes` was literally
  `self.fill_bytes(dest); Ok(())`), so the caller cannot even tell; and
- the unbounded sampler on top then spins on that constant buffer forever.

Measured on the host twin (`tests/harness/test_entropy_starve.py`), the
process burned 100% CPU with no answer and never returned. This is worse
than the "all zeros" prediction on both axes the entry cares about: it is
**silent** (no error anywhere) and it is **unbounded** (no output, ever).

**Item 2 of "The exposure" (the boot RNG pools) is unaffected by this
correction** and its analysis stands: a zero-initialized `chunk` filled by a
starved draw really does become a 512-byte zero pool, and a predictable
challenge really is the worse of the two outcomes. Only the `hkey` symptom
was mispredicted.

**What the fix changed.** `Trng` gained a provided `try_random_bytes`, the
two implementations that can silently produce nothing (`HostTrng`,
`DrbgTrng`) override it, and both `crypto` adapters forward to it — so the
"succeeded with a constant buffer" half is gone. Bounding the other half is
what mattered: `crypto::try_fill_valid` / `try_fill_valid_with` cap the
rejection at the named constant `KEYGEN_MAX_ATTEMPTS` (8) and return
`KeygenError`, because `RngCore` cannot be made to fail and `p256` cannot be
made to stop retrying. The cap is the load-bearing half: a fix that only
improved the *error* would still loop against any future `RngCore` that
keeps claiming success.

**Wider device exposure than this entry claimed.** The entry's reasoning —
"`init_drbg` refuses fatally at boot, so the device is practically
unreachable" — is sound for a peripheral dead *at boot* and was the reason
the host-construction boot hang was called "an emulation artefact". It does
**not** cover a generator that seeded successfully and later failed, which is
what `RESEED_INTERVAL` and the re-seed path exist for. So the device's own
paths carry the same defect, and the fix reached them:

> **The premise itself is withdrawn (2026-09-29, I-4 fix).** "`init_drbg`
> refuses fatally at boot" is the *leading hypothesis* for this branch's
> parked dark boot (`.superpowers/sdd/progress.md`, HARDWARE FINDING
> 2026-09-29) — and it is an **unexplained** hypothesis. A register entry
> must not rest reachability on behaviour that is currently an open question:
> if the hypothesis is right, the premise is not a premise. What survives is
> the narrower claim the entry already made, and the paths that fell in that
> gap are now bounded. The *conclusion* of this entry is unchanged; only the
> argument for its scope has been withdrawn, because the argument was the
> part that was leaning on unexplained behaviour.


- **device request path** — `device_core.rs` drew credentials and re-derived
  `hkey` on reset with a bare `loop { draw_random(..); if valid { break } }`,
  i.e. the *same* unbounded sampler, on the *live request path*, reached by a
  `makeCredential` after a mid-life pool exhaustion. Both are now bounded and
  answer `Ctap2Response::Other`.
- **device boot path** — `device_app.rs` (`hkey`, both the `new` and the
  fresh-partition arm of `boot`) and `attestation::generate_from` still call
  `SecretKey::random(&mut adapter)`. `boot_in_place` calls
  `attestation::provision` **unconditionally**, so even a partition with a
  stored `hkey` draws fresh key material at boot; `init_drbg` having succeeded
  does not protect this. **These remain unbounded** and are the honest
  residue of this entry.

### Why it is not being fixed here

It is practically unreachable today: `boot::init_drbg` refuses fatally at
boot if the peripheral cannot seed, and `RESEED_INTERVAL` is 256, so a
generator that seeded successfully has a very large margin before it can
starve. Fixing it properly means either changing `RngCore::fill_bytes`'s
infallibility (not ours to change) or restructuring the boot paths to use
the fallible seam (`try_random_bytes`) — the latter is a real change to
`fill_rng_pool` in two crates, out of scope for US-1006, which the review
explicitly declined to block on.

### What was done instead, deliberately

1. **Loud, not redesigned.** `DrbgTrng::random_bytes` and
   `Rp2350Rng::fill_bytes` now carry a `debug_assertions` tripwire,
   **device-builds-only**. It cannot fire in a release build (the release
   profile has `debug-assertions = false`), so no shipped behaviour changed
   and no new production panic was introduced — US-1006 exists to remove
   panics from the *request* path, and this is the *boot* path, where a loud
   failure beats a stale key. It is gated to device builds because the host
   suite deliberately starves a generator through the same seam to prove it
   leaves the buffer alone, and a universal assert would take that coverage
   with it. Off-device there is no persistent secret at stake.
2. **Gated.** `check_rng_path.py` flags `.random_bytes(` outside a per-flag,
   count-capped allowlist, so this caller class cannot grow by accident. Both
   `fill_rng_pool` sites are now **declared entries with their own reasons** —
   the FIDO one and the OATH one — rather than the OATH pool being an
   omission the gate never saw, which is what the I-1 review found. The
   `TrngAdapter` callers are declared separately, and every entry prints on
   every run.

### Follow-up

*(Updated 2026-09-29.)* The first half is **done**: the FIDO `hkey` and
credential keygen now have a fallible, attempt-capped constructor path
(`crypto::try_fill_valid` / `try_fill_valid_with`, reached through
`Trng::try_random_bytes`) on the host request path and the device request
path. `TrngAdapter` gained a `try_random` equivalent by making
`try_fill_bytes` honest rather than adding a method beside a lie.

Still open, in severity order:

1. **Switch both `fill_rng_pool`s to `try_random_bytes`** so a refusal is an
   error rather than a zero pool. Unchanged, and still the higher-severity
   of the two: a broken key is a bug report, a predictable challenge is a
   vulnerability. (FIDO `device_app.rs:267`, OATH `oath_core.rs:1016`.)
2. **Bound the device *boot* samplers.** `device_app.rs`'s `hkey` in both
   `new` and the fresh-partition arm of `boot`, and
   `attestation::generate_from` (reached unconditionally by `boot_in_place`),
   still use `SecretKey::random`. `try_generate_p256_keypair_from_trng`
   exists and is the drop-in; what is missing is a fallible return through
   `FidoApp::boot`, which is a signature change.

That is a real story, not a note.

### CORRECTION (2026-09-29, I-4 fix) — the amendment over-corrected, and the two symptoms are both real

**The amendment above says the predicted "all zeros" symptom "is not what
happens" and that "the prediction was wrong in the direction that matters".
For the `hkey` that is right. As a statement about the seam it is wrong, and
the error is the one this register exists to prevent: a blanket "that symptom
is wrong" is a claim about a *caller shape* stated as a claim about a
*primitive*.**

The two caller shapes produce **different** symptoms from the same refusal,
and both were live in this tree:

| caller shape | starved-generator symptom | loud or silent |
|---|---|---|
| rejection sampler (`SecretKey::random`, `try_fill_valid`) | loops forever | silent, unbounded |
| **plain draw into a zero-initialised buffer** | **32 zero bytes** | **silent, and constant** |

`DeviceKeystore::fresh` and `DeviceKeystore::reset` were the second row. A
refused infallible draw leaves the buffer exactly as it was, and the buffer
was `[0u8; 32]`, so the keystore was constructed with 32 zero bytes as its
`device_random` — the HKDF `ikm` behind
`stateless::master_from_device_random`, the **per-device U2F master**. That
is not a stale value; it is a constant, so every U2F key handle the token
ever issued becomes computable by anyone who knows the input, on **every**
device that hit it. The only guard was the `debug_assert!` inside
`DrbgTrng::random_bytes`, and `debug-assertions` is off in the release
profile — the shipped image had none.

**A test cannot hang on a loop, so the loop is invisible to a suite in a way
the zeros are not.** That asymmetry is the whole reason the second row went
unfixed while the first was chased: the first symptom shows up as a CI
timeout, the second as nothing at all.

**Fixed** in `337d574`. Both `device_random` draws now go through
`try_random_bytes` and return `Result`; a refused `reset` leaves the
keystore untouched rather than wiping the table and installing a predictable
master; `boot_in_place` maps the refusal to a new
`SecureStoreError::Entropy`, deliberately not to `Corrupt` or `Flash` (which
say "the bytes I hold are untrustworthy" and are handled by a wipe, where
this says "I could not obtain bytes" and the only correct handling is to
stop). `DeviceKeystore::device_random()` is a new read-only accessor,
because the property was unobservable from outside the crate — which is a
large part of why it survived.

**Evidence** (`apps/fido/tests/device_random_fallible.rs`, 6 tests): the
all-zeros symptom is asserted **against the seam itself** rather than
against the keystore, so it survives a refactor of the draw path; the
cross-device equality that makes the constant (rather than merely-wrong)
shape explicit is asserted directly; and both the refusal and the healthy
control are pinned for each of the two sites. Mutation: reverting `fresh()`
to the infallible seam turns
`a_starved_generator_does_not_produce_a_fresh_keystore` red — 4 passed → 3
passed / 1 FAILED.

**Divergence delta: 0.** No new row: this corrects an existing entry's
characterisation of an existing defect and fixes it in the tree. The
`fill_rng_pool` analysis (item 1 above) is untouched and still open, and
still the higher-severity of the two — a broken key is a bug report, a
predictable challenge is a vulnerability.

## D-10 — `migration_nonce()` was an unbounded peripheral draw inside a CCID request (US-917, predates US-1005) — **CLOSED 2026-09-29 (US-1005)**

**Date:** 2026-09-28. **Story:** US-917; surfaced by the US-1005 review.
**Class:** pre-existing defect, declared rather than redesigned.
**Closed:** 2026-09-29, US-1005. The entry is kept in full rather than
deleted, because "closed" is a claim about a specific property and a reader
needs the property to check it against.

### The claim (as filed)

`firmware/src/boot.rs` held `MIG_TRNG` (`Rp2350Trng`) and
`migration_nonce()`, called from `DeviceMigrationHandler::complete` and
`complete_other_class` — i.e. **inside a CCID APDU request**, not on a boot
path. It drew 12 bytes per migration record through
`Rp2350Trng::random_bytes`, which is `embassy-rp`'s
`blocking_fill_bytes`: the unbounded, self-retrying wait, on the request
path, in a `no_std` busy-wait with no supervisor and no watchdog kick.

### What is bounded now, precisely

`migration_nonce()` returns `Result` and reaches the peripheral through
`platform::trng::try_migration_nonce`, which calls `TrngProbe::probe_bytes`.
That carries all three of the named bounds `await_ready` already enforced, in
the order liveness < budget < hard cap:

| bound | value | what it catches here |
|---|---|---|
| `CLOCK_LIVENESS_SPINS` | 256 frozen status reads | the wall clock stopped, so the budget was never in play — reported as `ClockStalled`, **not** `Stalled` (D-12) |
| `MAX_ENTROPY_WAIT` | 20 ms (10x the ~2 ms datasheet average) | a peripheral that does not validate a block in time |
| `MAX_ENTROPY_POLLS` | 2^19 status reads | a clock that counts but far too slowly |

A 12-byte nonce is **one** validated EHR block (`EHR_BLOCK_BYTES` = 24), so a
refused migration request spends **one** wait allowance — asserted at compile
time in `platform/src/trng.rs` and again from the host side in
`platform/tests/migration_nonce.rs`. That is half the exposure of the 32-byte
DRBG seed draw, which crosses two blocks. **The 20 ms constant was not
changed**, and the call site does not need a different one: the budget is
per *block*, not per byte, and this is the smallest draw in the tree that is
still a draw. A separate, smaller budget for a smaller request would be a
second number for the same physical fact (one generation attempt), and the
only way it could be "more correct" is by being tighter — which is the change
that turns a refusal into a boot brick, not a safety property.

### Where the bytes come from, and why not the DRBG

From the peripheral, through a second `Rp2350Probe` (`boot::MIG_PROBE`).

The DRBG was the preferred answer and is not reachable. It is moved **by
value** into the trussed platform (`boot::take_drbg` → `Rp2350Rng` →
`DevicePlatform` → `Service` → `SyscallRunner` → `Client` → `OpenPgpApp`'s
static), so by the time a migration APDU is served the generator lives inside
four layers of trussed ownership that `DeviceMigrationHandler` does not own.
Getting at it would mean threading a handle through all of them, and doing it
from inside `complete` would put a `&mut` to the same generator in play
across `app.complete_migration` — which itself draws entropy.

What the substitution costs is small and is stated rather than waved through:
a `DrbgTrng` output is a deterministic function of one validated peripheral
block, so for a **one-off, twelve-byte, at-rest** AEAD nonce the two routes
differ by an HMAC step and nothing else. This is not a per-request protocol
nonce — a CTAP challenge, a session key, an APDU nonce — where the
conditioning and the `RESEED_INTERVAL` accounting would matter. The EPIC's
Phase 1 wording ("every nonce on every transport comes from a conditioned,
reseeded generator") is therefore satisfied for every transport nonce and
*not* for this one, and the honest form of the claim is the narrow one.

### What happens on a refusal, and why no migration is left half-applied

The draw is taken **after** the OTP/chipid reads and **before**
`complete_migration` / `complete_passphrase_class` is entered, in both call
sites. Every step before it is a read or a borrow: `read_otp_key_1()`,
`get_chipid()`, `cflash::data_partition()`, `store_handle()` (which only
stores a pointer — `SharedStore::new` is `const fn` and takes no borrow until
an operation runs), and the two `MaybeUninit` slot accesses. So on refusal
there is **no store write, no scratch-buffer use, no flash program and no
buffer state** to roll back: the migration has not started. That ordering is
the whole of the atomicity argument, and it is a property of the call site
rather than a lock.

The refusal answers `ClassStatus::Error` (`0x04`) with `SW_OK`, the same shape
as the two refusals already beside it (OTP row unavailable, chipid
unavailable), plus a `defmt::error!` naming the site. A host reading a status
byte beats a host timing out on a wedged peripheral.

`try_migration_nonce` also **scrubs the caller's buffer on every refusal**.
That is deliberately not what `Trng::random_bytes` does — that method cannot
report failure, so leaving the buffer alone is the only honest signal it
has — and it is the right difference: a reported refusal can afford to
destroy the evidence, and a partially-written 12-byte AEAD nonce is the one
buffer a reader would mistake for a usable one.

### Why a second probe and not a re-borrow of the existing one

`DRBG_SEED_PROBE` is the obvious reuse and would have been a two-line change.
It cannot be: `FuseSeedSource` holds a `&'static mut` to that probe for as
long as the generator lives, so `boot.rs` would have to mint a **second**
`&mut` to the same object from a raw pointer. The two are never called at the
same time (single core, cooperative executor, and the draw completes before
`complete_migration` is entered), but "not concurrent" is an argument whereas
two `&mut` to one object is UB whether or not the argument holds. A separate
handle costs two bytes of bss and one more documented `Peri` duplication.

The handle count over the TRNG singleton is **unchanged at three**, and the
composition changed for the better: it was one `Rp2350Trng` + two
`Rp2350Trng` + no probe at the migration site, and is now one `Rp2350Trng` +
two `Rp2350Probe`. D-11's interleaving argument therefore *strengthens*: the
two request-path-capable handles are the same implementation, not two.

### What this entry does not claim

* **D-8 stands.** The 20 ms budget is a datasheet *average* × 10, reasoned and
  not measured on silicon. This change makes the migration path inherit that
  assumption rather than a hang; it does not make the assumption true.
* **No hardware was touched.** The device build compiles; the wait has not
  been observed to return `Ok` on a real part, nor to return `Stalled` within
  20 ms on a bad one.
* **The per-block claim is arithmetic, not silicon.** 12 ≤ 24 is a constant
  comparison; that a *healthy* generation completes inside 20 ms is D-8.
* **Migration is not exercised end to end by this change.** The refusal
  ordering is argued from the call site and the success path is unchanged;
  neither has been run against a card with a pending C→Rust capture.

### The follow-up this entry replaces

*"Route `migration_nonce()` through the device DRBG (or through
`Rp2350Probe`'s bounded `probe_bytes`)…"* — done, by the second option, for
the reason given above. The first option is still available and is the
better long-term shape: if the trussed client ever exposes a way to borrow
the platform's RNG, the migration nonce should move there and this entry's
"why not the DRBG" paragraph becomes the historical record of why it could
not be done sooner.

### What the gate does about it now

`check_rng_path.py`'s `firmware/src/boot.rs` entry declares **one** site, the
bootstrap-time `ensure_boot_entropy` record draw, and the count is capped at
1. `firmware/src/main.rs`'s `Rp2350Trng::from_peri` cap went 2 → 1. Both
tightenings were the RED for this story: run against the pre-fix tree the
gate reported the `MigrationTrng` type mention, the second `.random_bytes(` in
`boot.rs`, and the second `from_peri` in `main.rs`. A future session that
restores *any* second direct draw in either file — whatever it is called —
turns the gate red without needing to remember this entry.

## D-11 — `Rp2350Probe` and `embassy-rp`'s driver interleave over one TRNG singleton (US-1005 / I-1)

**Date:** 2026-09-28. **Story:** RS-KEY-ADOPT US-1005, extended by the
branch's I-1 fix, amended 2026-09-29 when D-10 closed. **Class:** recorded
assumption about a device concurrency property, unverified on silicon.

### The claim

`firmware/src/main.rs` builds three handles over the same TRNG register
block (`rp_pac::TRNG` is a `const` at `0x400f_0000`; the peripheral is a
singleton and there is exactly one):

1. `Rp2350Trng` — the boot-path driver, built with `from_peri` (US-1005's
   spelling, so this file never names `Trng::new` and the gate never sees
   it). Serves `ensure_boot_entropy` and `ensure_fw_manifest`. **As of the
   D-10 fix (2026-09-29) this is the only unbounded handle on the device,
   and it is reachable only before USB enumerates.**
2. `Rp2350Probe` — the **bounded** seed probe, which is also what the boot
   sanity draw uses. Serves `FuseSeedSource::seed` (and hence every DRBG
   re-seed).
3. `boot::MIG_PROBE` — a **second bounded `Rp2350Probe`**, serving
   `DeviceMigrationHandler`'s migration nonce. It used to be a second
   `Rp2350Trng` (the D-10 handle).

**What changed with I-1.** Before the fix, the driver and the probe already
shared the peripheral, but the probe's first draw was the DRBG seed some way
down the boot. After it, the **boot sanity draw is a probe draw**, so the
two implementations alternate within a single boot, before USB enumerates.
The review flagged this specifically: it is the first place on device where
two handles over the singleton interleave, and there is no board to test on.

**What changed with the D-10 fix.** Handle 3 is now the *same type* as
handle 2. The count is unchanged at three and the interleaving argument
below gets *narrower*, not stronger: the two handles that can be reached from
a request are now the same implementation, so "they are symmetric" is true by
construction for that pair. What is **not** improved is the driver/probe pair
— handle 1 is still `embassy-rp`'s, and it still alternates with both probes
during boot, so the symmetry argument below is still an argument rather than a
type identity. The half of this entry that was a *request-path* hazard is
gone: no request can reach an unbounded driver handle any more.

**Why a second probe object rather than a second borrow of handle 2.**
`FuseSeedSource` holds a `&'static mut` to handle 2 for the life of the
generator, so a re-borrow from `boot.rs` would be a second `&mut` to one
object — UB regardless of the non-concurrency argument. The cost is two
bytes of bss and one more documented `Peri` duplication.

### Why the arrangement is sound on paper

The two implementations are **symmetric** in the one respect that matters —
neither can leave the peripheral in a state the other inherits badly:

* `embassy-rp`'s `blocking_fill_bytes` calls `start_rng()` per fill
  (`embassy-rp-0.10.0/src/trng.rs:330-344`).
* `Rp2350Probe::read_into` performs its own `start()` before every
  `await_ready()` and its own `stop()` on **every** exit including the
  `Stalled` one — precisely so a refusal does not leave the oscillator
  running and the next draw inheriting its state.

And they never actually *concurrently* interleave, because there is no
concurrency to interleave with: the RP2350 in this firmware is single-core
with a cooperative executor, none of these calls contains an `.await`, and
every use is a synchronous stretch inside `main` or inside the CCID task's
critical section. The handles are used in **sequence**, never nested.

`Rp2350Probe` also deliberately does **not** write `trng_debug_control`
(the health-test configuration bits), leaving that to the driver's
`initialize_rng` at construction — which is why the probe is built *after*
`Rp2350Trng::from_peri` on the boot path, and why moving it earlier would
silently change the peripheral's configuration.

### What is NOT established

None of the above is a measurement. There is no board attached, no host test
can model two implementations over one peripheral, and
`platform/tests/trng_wedge.rs` exercises the wait *logic* against a fake
clock and a fake `TrngProbe` — it says nothing about register-level
interleaving. The claim is: *the two are symmetric and they are never
concurrent.* If either half stops being true, the arrangement stops being
sound, and nothing in the gate set would notice.

### What would void it

* Any of these calls becoming `async`, or a second executor appearing. That
  is what would turn "used in sequence" into "interleaved", and the symmetry
  argument is about sequential use.
* A second `Rp2350Trng` being used while a probe draw is in flight.
* `embassy-rp` changing `blocking_fill_bytes` to leave the source enabled
  across calls, which would break the symmetry the argument rests on.

### Follow-up

US-1007 is where the hardware leg belongs: boot the device and confirm that
a boot which performs a probe draw (sanity) and then driver draws
(`ensure_boot_entropy`, `ensure_fw_manifest`) and back to probe draws (the
DRBG seed) produces distinct, non-degenerate entropy. Until then this is an
argument, and it is recorded as one.

## D-12 — the entropy wait's wall clock: the precondition is now checked, but TIMER0-on-silicon is still an assumption (2026-09-29)

**Date:** 2026-09-29. **Story:** the 2026-09-29 dark-boot defect fix
(`c9975e4` and the two commits that follow it). **Class:** recorded
assumption about a device runtime property, unverified on silicon — plus a
**disputed** root cause, recorded because the disagreement matters to anyone
re-flashing the branch.

### The hardware finding this entry comes from

`feat/rskey-adopt` was flashed to a real Pico 2. The device came up **dark**:
LED solid, absent from `lsusb`, no CCID reader in pcscd. The known-good
baseline `091d324` flashed to the same board enumerated in 4 s with its store
intact, so the store is healthy and the fault is in this branch. The reported
mechanism was the entropy path: `boot::init_drbg` is fatal by design, so a
refused seed halts before USB enumerates — which is exactly the observed
symptom.

### The mechanism as reported, and why the sources do not support it

The report was: at seed time `TIMER0` is stopped, so
`MAX_ENTROPY_WAIT` (20 ms) is unreachable, the wait degenerates to
`MAX_ENTROPY_POLLS = 2^18`, and ~0.4 s later it returns `Stalled`.

**That mechanism is not supported by the code, and it is recorded here as
disputed rather than adopted.** What the sources say:

* `firmware/src/main.rs:197` is `let p = embassy_rp::init(Default::default());`
  — the second line of `main`, before any TRNG handle exists.
* `embassy_rp::init` (`embassy-rp-0.10.0/src/lib.rs:625-639`) calls
  `clocks::init(config.clocks)` as its first act, and `time_driver::init()`
  as its second.
* `clocks::init` (`src/clocks.rs:1150-1154`, the `_rp235x` arm) writes
  `TICKS.timer0_cycles = clk_ref / 1e6` and sets `TICKS.timer0_ctrl.ENABLE`.
  `Config::default()` is `ClockConfig::crystal(12e6)`, `ref_clk` = XOSC
  div 1, so `clk_ref` = 12 MHz and the `TIMER0` tick rate is **exactly
  1 MHz**. `TICKS.timer0_ctrl.ENABLE` resets to 0 — that is the bit that was
  stopped, and `clocks::init` sets it ~80 lines before the first
  `probe_bytes`.
* The claim that "embassy-rp initialises TIMER0 lazily on first use" is
  false as written: `time_driver::init()` (`time_driver.rs:154-171`) only
  initialises the alarm state and enables `TIMER0_IRQ_0`. It never gates the
  counter and is not lazy.
* `rp_pac::TIMER0` has **no enable and no clear register at all** — the block
  is `timehw`/`timelw`/`timehr`/`timelr`/`alarm`/`armed`/`timerawh`/
  `timerawl`/`dbgpause`/`pause`/`locked`/`source`/`intr`/`inte`/`intf`/
  `ints`. The counter cannot be stopped in software; only the tick
  *generator* can, and `clocks::init` turns it on.

So on the sources alone the clock should be counting at seed time, the
20 ms budget should be reachable, and a healthy ~2 ms generation should sit
well inside it. **This entry does not claim to have found the actual cause of
the dark boot.** What it does claim is that the class of bug is real, the
probe could not detect it, and the fix makes the two possibilities
distinguishable on the next flash instead of indistinguishable.

### What was actually wrong, and is now fixed

The defect that is established is not "the clock was stopped". It is:

> **A wait that could not tell "the peripheral was slow" from "I was never
> measuring time" reported both as one opaque `Stalled`.**

That is a defect whether or not it is what happened on 2026-09-29, because
the two conditions call for completely different responses (swap the ring
oscillator vs. look at the clock configuration) and the device gave an
operator neither. Three changes close it:

1. **`TrngProbe::await_ready` checks its own clock, every wait**
   (`CLOCK_LIVENESS_SPINS = 256` consecutive status reads with no movement →
   `TrngError::ClockStalled`). It is in the trait's *default body*, so no
   implementation — device or host, present or future — can reach the budget
   without passing through it. A call site is exactly what goes wrong; a
   check in three places is a check any one of which a later edit can move.
2. **`Rp2350Probe::new` takes a `ClockReady`**, an unforgeable token whose
   only source is `Rp2350Timer::require_advancing()`, which reads `TIMER0`
   until it moves. Building a probe now implies having watched the counter
   move, so the ordering is a type error rather than a convention. Removing
   the token argument is `E0061`; fabricating one is `E0308` — both verified.
3. **`tests/scripts/check_boot_clock_order.py`** asserts the source order in
   `firmware/src/main.rs` (check before HAL init, before the probe
   construction, before the first `probe_bytes`/`init_drbg`), that
   `await_ready` still contains the check and still tests `Ready` first, and
   that `ClockReady` has no public field, no `Default`. Comments are
   stripped before matching, so a comment cannot turn the gate green. It has
   an `--self-test` (11 fixtures, all behaving) and both mutation shapes were
   confirmed red against the real tree.

The `Ready` test stays **first** in the wait on purpose: a validated block is
a validated block, and refusing one because a stopwatch is not running would
turn a working device into a brick.

### `MAX_ENTROPY_POLLS` re-derived: 2^18 → 2^19

The cap is now the *third* bound, behind the liveness check, so its job
changed: it no longer catches a dead clock (the liveness bound does, in
~0.5 ms instead of ~0.5 s) — it catches a clock that is counting but so
slowly that 20 ms of its ticks would take an unreasonable number of spins.
Derivation, in full in the constant's doc: it must clear the budget's
worst-case iteration count (20,000 ticks at the cheapest plausible loop body)
and clear one healthy generation many times over (~1,000–4,000 iterations at
~2 ms per RP2350 §12.12.2). `2^19 = 524,288` is **26x** the first and
**130–520x** the second; 2^18 was only 13x the first, which is thin for a
bound whose per-iteration cost is itself uncertain by a factor of four. The
wall cost is `2^19 x 1–2 µs` = **0.5–1.0 s** of spinning, paid only in the
case where `ENTROPY_CLOCK_TICKS_PER_MS` is already wrong by >10x.

The per-iteration cost figure (1–2 µs, from three APB reads plus a compare
and a branch at 150 MHz `clk_sys`) is **reasoned, not measured**, and is
flagged as such in the constant. D-8's underlying caveat is unchanged: the
20 ms budget is a datasheet *average* × 10, not a measured maximum.

### The assumptions that would void this

* **A part where `TIMER0` does not count at 1 MHz.** `require_advancing()`
  would return `ClockStalled` and the device would boot to a `fatal_boot` —
  loud and fast (~0.5 ms) instead of dark and ambiguous, which is the whole
  improvement, but still a refusal. A part with a *slow* clock is not caught
  by the liveness check; it is caught by the cap, after 0.5–1 s.
* **`TIMER0.PAUSE` or a debug-pause bit being set** by anything else. Nothing
  in this tree writes them; a debugger that pauses the timer would trip both
  checks.
* **A clock fast enough to trip `CLOCK_LIVENESS_SPINS` spuriously** — i.e.
  below ~2 kHz. That is the same condition that makes
  `ENTROPY_CLOCK_TICKS_PER_MS` wrong by ~500x, at which point every other
  `Duration` in this firmware is already wrong, so the check cannot cost a
  healthy draw on any clock for which the rest of the arithmetic is meaningful.
* **The disagreement above being right after all** — that the dark boot has
  some other cause the checks do not cover. Nothing here rules that out. If
  the next flash is *still* dark, the new error code is the discriminator:
  `ClockStalled` means the clock (check `TICKS.timer0_ctrl` and `PAUSE`);
  plain `Stalled` with the budget properly measured points at the peripheral
  or the probe's register handling (see D-11). A third possibility — a boot
  chain or task-arena overflow on this path, given the 92,712 B of a 98,304 B
  ceiling — would halt with no entropy error at all and is not excluded by
  this entry. `python3 tests/scripts/check_boot_chain.py` is green at this
  tip, but it is a static analysis, not a measurement of a running device.

### What is NOT established

* That this fixes the 2026-09-29 dark boot. It fixes the *invisibility* that
  made the dark boot undiagnosable. Those are different claims and only the
  second one is supported here.
* That `TIMER0` counts on a real part at seed time. The runtime check exists
  and the gate orders it correctly; no board is attached to this tree and the
  reported mechanism was not reproduced from sources.
* The 1–2 µs per-iteration cost, and therefore the absolute wall-time claims
  above. Reasoned from APB access counts, never measured (D-8, extended).

### Related

* D-8 — the budget is a datasheet average × 10, not a measured maximum.
  Extended by this entry: the *loop-cost* figure behind the poll cap is
  reasoned too, and the cap has been re-derived against it.
* D-11 — `Rp2350Probe` and `embassy-rp`'s driver interleave over one TRNG
  singleton. The other candidate for a dark boot this entry does not exclude.
* `platform/tests/trng_clock_precondition.rs` — the host-testable half.
* `platform/src/trng.rs` — `CLOCK_LIVENESS_SPINS`, `MAX_ENTROPY_POLLS`,
  `Rp2350Timer::require_advancing`, `ClockReady`.
* `.superpowers/sdd/report-CLOCKFIX.md` — the full write-up.

---

## D-13 — the OTP lock register is read nowhere in this tree, and `Layout::rp2350()`'s rows all sit in the page the C reference locks (2026-09-29)

**Story:** RS-KEY-ADOPT US-1083, which its own header declares **blocks**
US-1081. **Class:** a gap that was open on the branch and is now closed in
the code; what remains is the datasheet reconciliation, which was already
open and is not made worse by this entry.

### What was missing

US-1081 shipped `platform/src/boot_key.rs` with three load-bearing guards
(presence, a blank-row pre-flight, a monotone counter) and the epic's fourth
— the lock-state precondition — was not delivered. The module contained no
reference to a lock at all. The epic's rationale for the fourth is explicit:

> Refusing to burn while the lock state is non-nominal is the difference
> between a recoverable mistake and a permanently mis-provisioned token.

The blank-row pre-flight does not close it, and the reason is a specific
property of the part rather than an oversight. `otp_hw->sw_lock[page]`
carries two 2-bit fields, `SEC` (bits 1:0) and `NSEC` (bits 3:2), each
encoded `0b00` READ_WRITE, `0b01` READ_ONLY, `0b11` INACCESSIBLE — plus an
`0b10` the RP2350 header does not name. **A READ_ONLY page lets a read
succeed.** So on such a page the pre-flight reads a virgin row, passes, the
presence grant is spent, and the failure lands at `program_row`. A read-based
guard is structurally blind to the state that matters.

### Why it was not hypothetical on this part

The C reference in this repository locks a page by writing `0b1100` to
`otp_hw->sw_lock[page]` (`pico-keys-sdk/src/otp/otp_rp2350.c:88-95`) and
calls `otp_lock_page` for the OTP-MKEK rows. `OTP_ROWS_PER_PAGE` is 64, and
every row `Layout::rp2350()` can name — `first_key_row = 0x08` through
`version_row = 0x0C` — is inside **page 0**. A device provisioned by the C
stack and then provisioned again by this one lands in precisely the
READ_ONLY shape, with the grant already spent.

### What closed it

`cb278d2`. `Otp::lock_state(row) -> LockState` (a required trait method, so
a device driver cannot be written without answering it), `LockWord` /
`LockField` transcribed from `pico-sdk`'s
`hardware/regs/otp.h`, `Provisioner::check_lock_state` covering **both**
written rows, and placement as step **1b** in `provision_key` — after the
pure argument checks and **before** the presence grant, so a locked device
costs the operator no button press. There is deliberately no `set_lock`: the
underlying register is writable and the C reference writes it, and the
precondition must not be satisfiable by first making the device non-nominal.

Gate: `tests/scripts/check_otp_provisioning_precondition.py`, mutation-proven
through `tests/scripts/test_gates.py` (baseline 0, broken 1).

### What is still unverified — and this entry does not close it

* **The bit positions and the value encodings are transcribed, not
  independently verified.** They come from `pico-sdk`'s generated header and
  are cross-checked against the C reference's `0b1100` lock write, which
  agrees on the `NSEC` field. They are not read out of a datasheet in this
  tree. A device `impl Otp` does not exist yet, so nothing in this repository
  reads the register.
* **`Layout::rp2350()`'s row numbers remain unverified** — US-1081's own
  standing caveat, unchanged by this entry. They are the numbers a burn
  would land on, and they were wrong the same way before and after.
* **The provisioning path has no reachable trigger.** It is a library with
  no caller in this tree, and the epic assigns the trigger to a later story
  (RS-Key's HIGH-1: wiring it to the unauthenticated Rescue SECURE applet).
  So the precondition is *delivered and enforced in the path that exists*,
  and it is **not** reachable on a device. That is a different thing from
  being missing, and it is the honest description.
* **The per-page reach is only exercised for a synthetic second page.** With
  48 rows everything is in page 0, so the host test's two-page case uses a
  hand-built `Layout`. If the row numbers are reconciled and move past row
  63, the precondition silently starts covering a second page — the
  behaviour it was written for, and one no current default-path test
  exercises.

### Standing

**A recorded gap that is now closed in code, with the datasheet
reconciliation outstanding and unchanged.** It is a row rather than an
amendment because the thing it records — that a shipped one-shot burn had no
lock-state precondition, in a state the epic names as its blocker — is a
fact about the branch's history that the corrected module docs no longer
show. Deleting this row would delete the record that the ordering was ever
wrong, which is the one thing the epic's "blocks" relationship is for.

---

## D-14 — the key row's "write-lock" is a runtime-only register and does not survive reset (US-918)

**Story:** US-918, which claims a hardware write-lock of the C key row
(OTP 0xE90). **Class:** a claim in shipped code and comments that the part's
own documentation contradicts. Found 2026-09-29 while investigating an
unrelated boot failure; **the code is left unchanged and the claim is
corrected in place**, because removing the write is a separate decision with
its own risk analysis and this entry does not make it.

### What is claimed

`firmware/src/boot.rs::otp_hw_write_lock_key_row()` runs on **every boot** —
in the baseline `091d324` and on this branch — and its own doc comment calls
it a "best-effort hardware write-lock of the C key row (OTP 0xE90)", applied
"at boot by [`otp_hw_write_lock_key_row`], US-918". The mechanism is a
single register write:

```rust
swlock.modify(|v| v.set_nsec(SwLockNsec::READ_ONLY));
```

### What is actually true

The register does not retain that state across a reset. `rp-pac-7.0.0`
documents `sw_lock` (verified in the vendored source at
`src/rp235x/otp.rs:17`, not recalled):

> "Software lock register for page 0. Locks are initialised from the OTP
> lock pages at reset. This register can be written to further advance the
> lock state of each page (**until next reset**), and read to check the
> current lock state of a page."

So the write is a **per-boot** lock. A device that powers down and back up
presents the lock state its **OTP lock pages** hold, not the state this
firmware left behind. US-918's stated security property — that the key row is
write-locked against later software — is therefore not met by this code. A
write-lock that evaporates on a power cycle is not a write-lock.

### The evidence, and what it rules out

* **The register's own documentation** (above). This is the primary
  evidence and it is unambiguous.
* **The C reference does two things, and this tree does one of them.**
  `otp_lock_page()` in `pico-keys-sdk/src/otp/otp_rp2350.c:88-95` first burns
  the *lock-page row* persistently —
  `otp_write_data_raw(OTP_DATA_PAGE0_LOCK0_ROW + page*2 + 1, 0x3c3c3c)`, which
  goes through `rom_func_otp_access` (the SBPI fuse path,
  `otp_rp2350.c:49-59`) — and only then writes `otp_hw->sw_lock[page] =
  0b1100` for the current boot. The persistent half is the burn; the
  `sw_lock` write is the runtime half. **This tree implements only the
  runtime half.** That is the whole finding.
* **The measured register, which exonerates the firmware and sharpens the
  gap.** On a real board `SW_LOCK[58] = 0x0000000F` for page 233 (rows
  0xE90..=0xE9F, the C key row): `SEC[1:0] = 0b11` and `NSEC[3:2] = 0b11`,
  i.e. INACCESSIBLE in **both** domains. Per the register's own
  documentation that value is what the **OTP lock pages** present at reset —
  so it was not produced by this firmware's runtime write, and it outlives
  the boot. On that unit the row is in fact strongly protected; the finding
  is that *this code* does not put it there, and a unit whose lock pages say
  `READ_WRITE` gets nothing from a boot-time write that will be forgotten.

### What would actually be required

A real lock is a **one-way OTP lock-page burn through SBPI**, and it is
irreversible. It is the same shape of decision US-1081 already faces and
US-1083 now guards. Three things are missing, none of them mechanical:

1. **The burn itself** — `rom_func_otp_access` / direct `sbpi_*` programming
   of the lock-page row, the first half of the C reference's `otp_lock_page`.
   It is not in this tree, and deliberately so: US-1081's provisioning path
   is a library with no reachable trigger, and a burn belongs there and not
   on an ordinary boot path.
2. **A provisioning-time decision about who may burn a unit.** This is the
   blocker, and it is a product question, not an engineering one. A burn on
   every boot is impossible (a fuse cannot be written twice); a burn at
   first boot is a silent, irreversible write to hardware the moment a unit
   is powered; a burn at factory provisioning is a manufacturing step. Each
   is defensible and they have completely different blast radii.
3. **Recovery semantics.** `READ_ONLY` was chosen over `INACCESSIBLE`
   precisely because the firmware reads the row every boot — a wrong choice
   here bricks the unit with no recovery short of a fuse-level erase.

### What the risk is while it is unmet

Bounded, and it should be stated in proportion rather than inflated. The
residual is **software-level write access to the key row by later code on
the same device**, not a new remote attack surface. It requires an attacker
already executing on the device, and the read half is unchanged either way:
US-924's residual risk — "the OTP row is still **readable from any code**
(no read-protect)" — is a strictly larger exposure and is tracked
separately. The write-lock's value, in full, is preventing a *persistent*
modification of the key row by later firmware. Until a lock page is burned
that property is not provided, and any comment or document saying the row is
write-locked is describing a boot-scoped fact as a standing one.

### What was done about it, and what deliberately was not

* **Corrected in place:** the function's doc comment and the call-site
  comment in `firmware/src/main.rs` no longer assert a protection this code
  does not provide; they now say the lock is runtime-only and does not
  survive reset. The `defmt::warn!` string was left alone — it is a log
  line, and changing it is not a comment.
* **Deliberately not done: removing the write.** It is defensible to keep —
  it does cost a same-boot write by a compromised image, it is
  non-fatal-by-design, and it makes a unit whose lock pages are already
  burnt behave correctly at runtime. It is equally defensible to remove as
  misleading. **That call is the owner's**; this entry does not pre-empt it.
  What is wrong is the *claim*, and the claim is now corrected.

### Standing

**A shipped claim that the part's documentation contradicts, now corrected
in code, with the real fix requiring a product decision that has not been
taken.** It is a row and not an edit away, because what is worth recording
is not the current text — it is that US-918 shipped a security property it
did not provide, and that a future reader asking "is the key row
write-locked?" will find a runtime register write and may reasonably stop
there.

---

# Acceptance criterion #8 — the divergence delta, stated (I-5, 2026-09-29)

The epic's acceptance criterion #8 reads, in substance: **no new standing
waiver is introduced to land any story.** This section is the explicit
accounting the whole-branch review asked for, because the register above has
grown and criterion #8 is the thing that growth is measured against.

## The delta, as a count

| | before this branch | after `feat/rskey-adopt` | delta |
|---|---|---|---|
| Register rows | D-1 … D-6 (6) | D-1 … D-14 (14) | **+8** |
| …of which are **test-suite** divergences (the standing waiver's class) | D-1, D-2 | D-1, D-2 | **0** |
| …of which are **device-behaviour** divergences no host test could reach | D-4, D-5, D-6 | D-4, D-5, D-6, D-8, D-9, D-10, D-11, D-12, D-13, D-14 | **+6** |
| New **standing waiver** in the sense criterion #8 names (a class of failure now waved through without attribution) | — | — | **0** |

**The standing waiver itself is unchanged.** D-1 and D-2 — the two
client-side CTAP-2.3 strictness failures — are the same two rows, with the
same reproduce-at-BASE instruction, and no story on this branch was landed
by suppressing a test-suite failure. D-4, D-5 and D-6 were already
attributed and red before this branch's first commit.

## The +6, and why they are the right kind

Each of D-8, D-9, D-10, D-11, D-12, D-13 (and now D-14) is a **device**
property: TRNG generation timing, the shape of a starved generator's failure,
an unbounded peripheral wait inside a CCID request (D-10, since fixed in
code), register interleaving on one TRNG singleton, a timer that might not be
counting, an OTP lock register nothing read, and a key-row "write-lock" that
is a runtime-only register. **Not one of them is reachable from a host
test**, and not one was suppressed to land a story. They are the kind of
divergence a ledger is for: the alternative would have been to claim they
were closed, and every one of them is a claim a host suite would have scored
green. D-14 is the sharpest example of that — a host suite can only check
that a register was written, and the property US-918 claimed lives in a fuse
that has not been burned.

Two of the +5 have since been **closed or narrowed in code** and keep their
row because the row records a fact about the branch's history that the
corrected source no longer shows:

* **D-8** — assumption (1) had a second, present trigger
  (`soft_reset` not re-applying the TRNG configuration). Fixed; the
  amendment says so and records that the budget is still unmeasured.
* **D-9** — the entry's characterisation of a starved generator was
  half-wrong, and the half that was wrong was the silent one. Corrected; the
  `fill_rng_pool` analysis is untouched and still open.

**A third is now closed outright: D-10** (2026-09-29, US-1005). The
unbounded `blocking_fill_bytes` inside a CCID request is gone, the refusal
is a card error, and the two `check_rng_path.py` count caps that let the site
exist were tightened so the regression turns the gate red on its own. The row
stays because "closed" is a claim about a named property — *no unbounded
entropy wait on a request path* — and a reader needs the property to check it
against. What D-10 did **not** close is inherited from D-8, not repeated
here: the 20 ms budget is still reasoned rather than measured, and the
device work still needs a board.

## The owner decision, recorded rather than assumed

**D-8, D-9, D-11, D-12, D-13 and D-14 remain open** and are accepted as a
named owner decision, not as an oversight; **D-10 is closed** and the
argument below is retained for the six that are not. The reasoning:

1. They are not test failures. Nothing in `cargo test` is red because of
   them, and nothing would be.
2. Each is written with what *would* settle it, who owns it, and why it
   cannot be settled here — D-8 and D-12 to US-1007's hardware leg, D-13 to
   the datasheet reconciliation, **D-14 to a provisioning/product decision
   that no amount of engineering on this branch can supply** (who may burn a
   unit, and when).
3. Reducing the count by deletion would be a lie. Reducing it by *fixing*
   the underlying device properties is the work of US-1007 and the stories
   named above, and it needs a board, which this branch does not have.

**D-14 is the one row here whose fix is not merely un-taken but
deliberately not taken in this commit.** Unlike the others, its claim has
been corrected in the code today, so the branch no longer *asserts* the
property — what remains is the property itself, and it is a product
decision plus an irreversible burn. It is listed among the open rows
because an unburned lock page is still an unburned lock page.

**What this section is not.** It is not a claim that criterion #8 was
satisfied, and not a request to waive it. It is the number, and the
reasoning, so the decision is visible to whoever owns it.
