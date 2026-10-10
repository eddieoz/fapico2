# US-1652 — Phase 1 gate evidence: red-then-green, ratchet, call chain

Recorded 2026-10-10, branch `feat/nostr`, tip `511f152`.

## Red-then-green (the §2.7.1 tests that exist at Phase 1 close)

Three of the six Phase-1 §2.7.1 tests exist at this point; the other three
(`mac_comparison_is_constant_time`, `calc_padded_len_edges`,
`peer_x_must_be_a_valid_curve_point`) are NIP-44 tests that come into being
with US-1653–US-1656 and carry their red-then-green with those stories —
a test cannot be red for the right reason against code that does not exist
yet, and the stories that create the code also create the demonstration.

Each red below was produced by reverting exactly one fix on the current tip,
capturing the failure, and restoring (`git checkout --`), then re-running
green. No red survives in the tree; the tip is the green state.

### 1. `main_rs_wires_nostr_presence_through_the_strict_builder` — the §2.6 builder call omitted

Red condition: `.with_presence_grant(fapico2_firmware::presence::request_grant)`
removed from the Nostr construction in `firmware/src/main.rs:1185`.

```
test main_rs_wires_nostr_presence_through_the_strict_builder ... FAILED
panicked at apps/nostr/tests/presence.rs:137:
the nostr applet must be wired to the strict one-shot path
(fapico2_firmware::presence::request_grant), not a windowed variant
test result: FAILED. 4 passed; 1 failed
```

Fails for the right reason: the failure names the wiring, not the test.

### 2. `sign_refused_without_presence_grant` — the touch gate neutralized

Red condition: the §2.3 gate in `apps/nostr/src/lib.rs` `user_present`
short-circuited to `true` (the §2.6 hazard the builder call exists to
prevent — a gate that answers before it is asked).

```
test sign_refused_without_presence_grant ... FAILED
panicked at apps/nostr/tests/presence.rs:98:
assertion `left == right` failed: a denied touch refuses with 6985
test result: FAILED. 0 passed; 1 failed
```

Fails for the right reason: SIGN executed what a denied touch must refuse.

### 3. `all_distinct_tags_for_distinct_idx` — the colliding draft tag encoding

Red condition: `presence_tag` reverted to the earlier draft's collapsed
space (`idx & 0x03` — the same class of collision the draft's
`0x50 | (ins & 0x0F) | (idx << 4)` encoding had, 8 identities → 2 tags).

```
test all_distinct_tags_for_distinct_idx ... FAILED
panicked at apps/nostr/tests/presence.rs:173:
assertion `left != right` failed: identities 0 and 4 collapsed onto one tag
test result: FAILED. 0 passed; 1 failed
```

Fails for the right reason: it names the two identities that collided.

### 4. `wire_fits_max_wire` — the device cap unreachable from the host

Red condition: `MAX_WIRE` removed from
`platform/src/ccid.rs` `pub mod message` — the pre-US-1644 state, where the
only cap a host test could reach was its own `MAX_RESPONSE` (4096) and no
test could assert the device's 2762 B transport limit at all.

```
error[E0432]: unresolved import `fapico2_platform::ccid::message::MAX_WIRE`
  no `MAX_WIRE` in `ccid::message`
```

Fails for the right reason: the test cannot even be *written* against the
host's idea of the transport — the device constant must exist and be
imported by name (`apps/nostr/tests/wire.rs:37`). The test asserts the
§2.2.1 response budgets against that constant, on both encoder paths, so an
over-long response is a compile/test failure rather than the device
silently dropping the frame (`firmware/src/tasks.rs`).

## Ratchet: green

```
PASS: check_flash_budget (US-1534) — budget 1703936 B (0x1a0000) ci.yml =
flashmap.rs, ends at or below every data region; headroom intact to
FIRMWARE_GROWTH_END 0x200000
```

US-1630's ADR 0004 raise (1621 → 1664 KiB) absorbs the applet's core: the
budget gate passes unmodified at the Phase 1 tip.

## Worst call chain: green

```
PASS: check_boot_chain (US-957) — worst call chain 93724 B <= 98304 B
(main stack zone 142556 B, 98304 B chain ceiling)
```

Margin 4,580 B (4.7 %) against the §8.3 ceiling. The root floor moved as
the story predicted: 28 `dispatch::App` vtable shims, of which **7** are
`App::process` (the registry's eight applets minus one non-CCID root) —
the gate verifies the floor is measured, and the Nostr applet is inside
the measurement. The task-arena stamp was re-measured after the US-1651
boot.rs edit (`measure_task_arena.py`, nightly): 21,952 B against ARENA
32,772 B (1.49×, floor 1.25×), stamp re-verified against current sources.

## Green state at recording time

- `cargo test -p fapico2-nostr` — 36 passed, 0 failed (keymgmt 18, wire 13,
  presence 5).
- Emulator suites `test_nostr_select.py` (6) + `test_nostr_keymgmt.py` (7)
  green through `run_tests.sh` with no runner edit.
- `check_boot_chain` / `check_flash_budget` / `check_rng_path` PASS.

---

# US-1680 — the §2.6 gate re-anchored: red-then-green, re-recorded (2026-10-10)

US-1658 moved the applet's construction out of `main.rs` (`NostrApp::new()`
now lives at `nostr_shared.rs:56`, behind the shared Mutex), which left this
gate's stale anchor: it split `main.rs` on the literal `NostrApp::new()`,
found nothing, and failed at the `expect` — a red caused by the *anchor*,
not by any wiring fault. The gate now asserts the property where it lives:
the `install_nostr_providers(...)` call in `main.rs`, its grant argument
`fapico2_firmware::presence::nostr_grant`, and the call site never naming
`window_grant` (the negative assertion is checked first, so a degraded
wiring fails naming the join-or-open hazard).

## Red 1 — the stale anchor (observed at the pre-US-1680 tip, `c0fffec`)

```
$ cargo test -p fapico2-nostr --target x86_64-unknown-linux-gnu --test presence

test main_rs_wires_nostr_presence_through_the_strict_builder ... FAILED

thread 'main_rs_wires_nostr_presence_through_the_strict_builder' panicked at apps/nostr/tests/presence.rs:120:10:
main.rs constructs the nostr applet

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out
```

The failure names the stale anchor (`main.rs constructs the nostr applet`),
not a wiring fault — the review's P1-2 exactly.

## Red 2 — the wiring degraded to `window_grant` (revert on the re-anchored gate)

`main.rs`'s third `install_nostr_providers` argument changed from
`fapico2_firmware::presence::nostr_grant` to
`fapico2_firmware::presence::window_grant`, then the gate re-run:

```
thread 'main_rs_wires_nostr_presence_through_the_strict_builder' panicked at apps/nostr/tests/presence.rs:
the nostr applet must never be wired to the join-or-open window_grant (§2.3.1):
a same-tag SIGN would join another SIGN's open window and inherit its press

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out
```

The gate fails for the right reason — naming the join-or-open hazard — not
by `expect`ing on a string that no longer exists. `git checkout --` restored
the strict wiring; no red survives in the tree.

## Green

```
$ cargo test -p fapico2-nostr --target x86_64-unknown-linux-gnu
keymgmt 18, wire 9, presence 5, nostr_shared's US-1658 module 13, store
suites 9+9 — 0 failed across every `-p fapico2-nostr` target.
