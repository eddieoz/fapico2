# The retail virgin-row brick: every factory-new board refused to seed (`NeverBootC`)

**Date:** 2026-11-20
**Evidence:** a third field video (`video_comprimido3.mp4`, 264×232, 30 fps,
121.2 s) from a community user running **v0.7.1** (`fapico2-v0.7.1-warm-boot.uf2.zip`,
built 02:09 from c447665, three minutes after US-1929 — the Phase 0 image),
plus the **owner's own reproduction**: a brand-new Pico 2 flashed with v0.7.1
fails the same way, and after a first boot of pico-fido *or* RS-Key the same
board works when fapico2 is flashed back.
**Predecessors:** [`2026-11-19-retail-first-boot-dark-park.md`](2026-11-19-retail-first-boot-dark-park.md)
(the two Robocore v0.7.0 units; the dwell/TRNG attribution that this audit
supersedes for the retail incidents).

## Verdict

**Not a TRNG stall at all.** Every retail incident to date — the two Robocore
v0.7.0 units, the third field unit on v0.7.1, and the owner's reproduction —
is one deterministic defect: **`ckey::derive_drbg_seed` refused the factory
zero OTP key row with `CKeyError::NeverBootC`** (`platform/src/ckey.rs:266-268`
pre-fix). `NeverBootC` is a migration-era guard — "the C firmware never
initialized this device" — and on a tree that is not a C port, *C never booted*
is the normal factory state. Every fresh board therefore reached the seed
attempt with a valid, just-drawn entropy record and then refused, in-process,
before the TRNG was ever touched — forever, pre-USB.

The dwell/TRNG attribution of the 2026-11-09/10/19 audits was a wrong model
that fit the incomplete evidence. It survives only as a *second*, independent
mechanism (US-1835's question), which the fixed firmware will finally let us
measure on a board that no longer brick-walls it.

## What the third video establishes (decoded at 30 fps, not the aliased 1 fps)

| t | pin | reading |
|---|---|---|
| 0 – 13.57 s | dark | release boot: rung ladder pulses are 25 ms (sub-frame at 30 fps), the sanity draw ~2 s, then the OTP identity reads' silent retry window (`otp_retry::DEADLINE_MS` = 20 s) consumed ~11 s of E16 settling |
| 13.57 – 14.01 s | **400 ms lit** | `entropy_draw_notice` — the record draw opens |
| 14.01 – 14.67 s | dark 0.66 s | the record draw **succeeds on its first attempt** — 2 EHR blocks of generation wall time; no blink, no bursts: the TRNG is healthy |
| 14.67 s – end of video | 80/170 ms blink + **300 ms-lit bursts at 450 ms period, K = 1 → 9 (capped), trains spaced 5.4 s early / 9.1 s late** | the **seed site** refusing every attempt, forever. The spacing arithmetic (20 × 250 ms sleep + K × 450 ms train) matches to ~10 ms; the 0.6–0.7 s "lit runs" are the capped 9-pulse trains merging at 30 fps; the constant ~0.73 s anchor offset is decode timebase drift |

No dark gap >0.7 s after t=14 s, no fatal signature, no 1 Hz heartbeat: **one
continuous boot run, parked inside US-1929's never-park loop**. The 300 ms
shape exists only in Phase 0 (`wait_blink.rs` collision test), which dates the
firmware more cheaply than any binary inspection: v0.7.1 *is* the Phase 0
image, and Phase 0's accepted residual ("waits forever, visibly") is exactly
what the pin shows.

## The root cause chain, code-pinned

1. `main.rs:786` — fresh store ⇒ `boot_needs_legacy_bringup` true.
2. `main.rs:788` → `boot.rs:1232-1267` — record drawn and persisted. Raw
   TRNG, no OTP involvement: **succeeds** (the video's 0.66 s draw).
3. `main.rs:821` → `boot.rs:1063-1083` — `read_otp_key_1` on the unfused row
   returns `Some([0u8; 32])` (ECC reads succeed; zeros are the US-1710/1711
   convention), so no `OtpKeyRow` park; the zero row enters `DRBG_OTP_KEY`.
4. `main.rs:833` → `boot.rs:1129` → `drbg_seed.rs:198-256` — record present
   and non-zero ✓ — then `ckey.rs:266-268`: `otp_key_1` all-zero ⇒
   `Err(CKeyError::NeverBootC)` **immediately, zero probe budget** (the burst
   spacing proves it: an attempt that reached the peripheral costs ≥ 2 s per
   block; measured spacing costs ~0 ms).
5. US-1929's re-arm loop (and v0.7.0's park) had no idea the refusal was
   permanent: the variant went into the retry machinery and was lost.

The host suite was green because a test pinned the brick as intended:
`platform/tests/drbg_seed.rs::an_uninitialized_device_refuses_with_its_own_error`
(US-918's migration-era ordering). US-1931 inverted that pin.

**Why pico-fido / RS-Key "initialize" the board:** their first boots burn OTP
rows (`pico-keys-sdk/src/otp/otp_rp2350.c:209-242`; RS-Key's MKEK/DEVK fuse
provisioning). A persistent burn is the only first-boot hardware difference
that survives a reflash, and it is exactly the difference the owner's A/B
repro exercises: after their first boot the row is non-zero, our derivation
passes, and the same board works. Nothing in pico-sdk, the RP2350 datasheet,
or the boot flow requires a burn for TRNG or USB to work — the non-zero-row
requirement was ours alone, and it contradicted our own documented zero-row
posture (`store_v3::derive_store_key` accepts the row; US-1030's
`kbase_c_unchecked` carries the written argument; `otp_row_unfused` /
`ENTROPY_FLAG_ROW_UNFUSED` advertise the state). Provisioning stays ADR 0002's
deferred epic; the boot must not demand it.

## The fix trio (this branch)

- **US-1931** — `derive_drbg_seed` accepts the zero row: the record refusals
  (`MissingBootEntropy`/`DepletedBootEntropy`) plus the mandatory fresh
  per-seed draw keep the seed uncomputable offline; a zero IKM row degenerates
  the *binding* (the residual the store already accepts), not the entropy.
  `derive_kbase`/`derive_kbase_c` keep their guards (migration semantics).
  The pinning test is inverted; the field symptom is a host test
  (`a_fresh_unfused_board_with_a_drawn_record_seeds`, red before, green after,
  one peripheral draw, zero before the fix).
- **US-1932** — the retry loops learn the variant split
  (`drbg_seed::refusal_is_freshness`): only `SeedError::Trng` re-arms forever
  (US-1929 intact — freshness never parks); a permanent state refusal parks
  legibly with the existing `DrbgRefused` signature, on both arms (legacy
  `seed_drbg_blocking` and the bring-up task). Halt sites 21 → 23, delta
  recorded in the gate. A board that can never seed says so on the pin.
- **US-1933** — the peripheral's *construction* config was embassy's stock
  `sample_count: 25` (the stall config RS-Key measured); US-1927's 1000
  reached `SAMPLE_CNT1` only through the soft-reset re-arm. The tuned constant
  now rides into `Trng::new` (`Config` is `#[non_exhaustive]` → assignment),
  and `check_rng_path.py` gains a structural CONFIG-PIN check so construction
  and budget cannot diverge again. Landed gate-red.

## Falsifiable predictions (the owner's leg)

1. **The board the owner just bought** — virgin row, never booted C firmware —
   flashing the post-US-1931 image boots first try: ladder → notice →
   record draw (~1 s at the tuned config) → seed (~1 s) → 1 Hz heartbeat,
   USB enumerates ~7 s. No burst anywhere (a healthy boot shows none).
2. **v0.7.1 field units** blink exactly like the video; the discriminator
   against a genuine TRNG stall is the burst **pulse length**: 300 ms (seed)
   from ~15 s onward on a v0.7.1 brick. A post-fix image on a genuinely
   stall-prone board would show 120/300 ms bursts only while the peripheral
   settles — and now, at the tuned construction config, that should be
   RS-Key's ~1.5 s, not minutes (US-1926's measurement finally measures this).
3. **A board with a genuinely broken seed** (e.g. torn record, unreadable
   store) on the post-US-1932 firmware parks with a signature within seconds
   instead of blinking forever — legible again. Post-US-1935 the record-site
   faults (slot unreadable, persist refused) carry their own `1011`
   signature, parked at the fault site; seed-state faults keep `0100`.

## Residuals

- **The bound root still refuses the zero row** (`ckey::derive_kbase:172`):
  correct for migration, and unreachable on the boot path — but it means
  bound-root-dependent operations refuse on a virgin board until provisioned.
  FIDO residents on a fresh board ride the snapshot-store fallback (the
  keyregion's zero-row posture is its own `None`-refusal, crypto.rs:72-78 —
  empty region, not a brick). A follow-up story (US-1935 candidate) should
  decide the bound-root policy with US-1030's argument in hand.
- **The forum thread** (`forums.raspberrypi.com/viewtopic.php?t=390946`) is
  behind a Cloudflare JS challenge — WebFetch and curl both get the
  interstitial; its contents were never read. The RND_SOURCE_ENABLE hint the
  owner relayed was checked against the code instead: the enable is
  unconditional and first (`trng.rs:919-927`) since the 2026-09-29 fix; the
  *configuration* init was the real gap (US-1933).
- **Mimosa false positive:** every `Edit` whose payload carried the Rust
  closure `|&b| b == 0` was blocked as "command injection" (`|&` read as a
  shell pipe). Recorded as tooling, not code: no_std, no process API; the
  owner disabled the plugin mid-session and the guard removal was applied
  via a scripted replacement, byte-identical to the blocked edit.
- **The probe was never connected.** The owner offered SWD; the mechanism was
  pinned from code + video + the A/B repro before hardware reads were needed.
  A read-only OTP dump on the virgin board remains available as confirmation
  if the owner wants it (AGENTS.md: probe to read, never to run).
- The three parallel reviewer reports (read-only explorers + confidence-
  filtered review) converged on the same root cause with evidence-backed
  rulings-out of the competing arms; their report transcripts are in the
  session, and their two additional findings (variant erasure = US-1932,
  construction config = US-1933) are both landed.
